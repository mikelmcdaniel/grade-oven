"""The executor module knows how to run stages.

A Stage consists of a main script to run, some files, and some metadata such
 as a description.  Stages, including metadata, are stored on disk.

When a Stage is run, its .output (StageOutput) contains basic information
such as STDOUT and STDERR.

A DockerExecutor uses Docker to run multiple Stages, one at a time.

See executor_test.py for examples.
"""

import collections
import errno
import fractions
import itertools
import json
import logging
import os
import re
import shlex
import shutil
import six
import subprocess
import time
from typing import Any, Callable, Dict, Iterable, IO, List, Optional, Text, Tuple
import zipfile

import escape_lib


class Error(Exception):
  pass


class SerializeError(Error):
  pass


class JSONSerializable(object):
  def serialize(self):
    raise NotImplementedError()

  @classmethod
  def deserialize(cls, data):
    if data is None:
      data = '{}'
    try:
      return cls(**json.loads(data))
    except TypeError as e:
      raise SerializeError(e)


def maybe_makedirs(path: Text) -> None:
  try:
    os.makedirs(path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise Error(e)


def join_cmd_parts(cmd_parts: Iterable[Text]) -> Text:
  escaped_parts = []
  for part in cmd_parts:
    if len(shlex.split(part)) > 1:
      escaped_parts.append('"{}"'.format(part.replace('"', '\\"')))
    else:
      escaped_parts.append(part)
  return ' '.join(escaped_parts)


def file_contents_or(file_path: Text, default_contents: Text = '') -> Text:
  try:
    with open(file_path) as f:
      return f.read()
  except IOError as e:
    if e.errno == errno.ENOENT:
      return default_contents
    else:
      raise Error(e)


class StageOutput(object):
  SCORE_RE = re.compile(r'\s*(-?\d+)\s*/\s*(-?\d+)\s*')

  def __init__(self, output_path: Text) -> None:
    score_raw = file_contents_or(os.path.join(output_path, 'score'), '')
    # This is only for backwards compatibilty, when totals were also recorded.
    if '/' in score_raw:
      score_raw = score_raw.split('/')[0]
    try:
      self.score = int(score_raw)
    except (TypeError, ValueError):
      self.score = None
    self.output_html = file_contents_or(
        os.path.join(output_path, 'output.html'), '')
    self.stdout = None  # type: Optional[Text]
    self.errors = None  # type: Optional[List[Text]]


def make_file_executable(path: Text) -> None:
  mode = os.stat(path).st_mode
  # copy read bits to executable bits
  mode |= (mode & 0o444) >> 2
  os.chmod(path, mode)


class Stage(object):
  def __init__(self, stage_name: Text, stage_path: Text,
               stages: "Stages") -> None:
    self.name = stage_name
    self.path = stage_path
    self._stages = stages
    self.output = None  # type: Optional[StageOutput]

  def _raw_stage_json(self) -> Dict[Text, Any]:
    stages = self._stages._raw_json.get('stages', ())
    for stage in stages:
      if stage['directory_name'] == self.name:
        return stage
    raise AssertionError('Stage {} not found in {}'.format(self.name, stages))

  def save_main_script(self, contents=None):
    """Save a main script to be run inside the Docker container.

    Main scripts are markes as executable and run directly. If BASH can run
    your script, then it should work.
    """
    maybe_makedirs(self.path)
    path = os.path.join(self.path, 'main')
    if contents is not None:
      with open(path, 'w') as f:
        # remove bad line-endings
        f.write(contents.replace('\r\n', '\n'))
    make_file_executable(path)

  @property
  def main_script(self) -> Text:
    return file_contents_or(os.path.join(self.path, 'main'))

  @property
  def filenames_except_meta(self) -> List[Text]:
    try:
      filenames = set(os.listdir(self.path))
    except OSError as e:
      if e.errno == errno.ENOENT:
        filenames = set()
      else:
        raise Error(e)
    filenames.discard('main')
    return sorted(filenames)

  @property
  def description(self) -> Text:
    return self._raw_stage_json().get('description', '')

  @property
  def is_trusted_stage(self) -> bool:
    # TODO: Make this default to False since it's
    # safer generally better to fail closed.
    return self._raw_stage_json().get('is_trusted_stage', True)

  def save_is_trusted_stage(self, is_trusted_stage: bool) -> None:
    self._raw_stage_json()['is_trusted_stage'] = is_trusted_stage
    self._stages._save_raw_json()

  def save_description(self, desc: Text) -> None:
    self._raw_stage_json()['description'] = desc
    self._stages._save_raw_json()

  def save_file(self, filename: Text, src_file: IO) -> None:
    maybe_makedirs(self.path)
    base_filename = os.path.basename(filename)
    base_filename = escape_lib.safe_entity_name(base_filename)
    try:
      with open(os.path.join(self.path, base_filename), 'wb') as dst_file:
        shutil.copyfileobj(src_file, dst_file)
    except (shutil.Error, OSError) as e:
      raise Error(e)

  def remove_file(self, filename: Text) -> None:
    base_filename = os.path.basename(filename)
    base_filename = escape_lib.safe_entity_name(base_filename)
    try:
      os.remove(os.path.join(self.path, base_filename))
    except OSError as e:
      raise Error(e)

  def _save_zip(self, stages_name: Text, zip_file: zipfile.ZipFile) -> None:
    zip_file.write(self.path, self.name)  # directory
    for root, dirs, files in os.walk(self.path):
      for basename in files:
        path = os.path.join(root, basename)
        zip_file.write(path, os.path.join(self.name, basename))


class Stages(object):
  def __init__(self, stages_path: Text) -> None:
    self.path = stages_path
    _, self.name = os.path.split(stages_path)
    self._raw_json = self._load_raw_json()
    self.stages = self._load_stages()

  def _save_raw_json(self) -> None:
    maybe_makedirs(self.path)
    content = json.dumps(self._raw_json)
    with open(os.path.join(self.path, 'metadata.json'), 'w') as f:
      f.write(content)

  def _load_raw_json(self) -> Dict[Text, Any]:
    path = os.path.realpath(os.path.join(self.path, 'metadata.json'))
    contents = file_contents_or(path, '{}')
    try:
      raw_json = json.loads(contents)  # type: Dict[Text, Any]
    except ValueError as e:
      raise ValueError('Corrupt metadata: {}\n{}\n{!r}'.format(
          e, path, contents))
    try:
      raw_json['stages']
    except KeyError:
      raw_json['stages'] = []
    return raw_json

  def _load_stages(self) -> Dict[Text, Stage]:
    stages = collections.OrderedDict()  # type: collections.OrderedDict
    for stage in self._raw_json.get('stages', ()):
      # TODO: sanitize names so they can't be something like '/path/from/root'
      stage_name = stage['directory_name']
      stages[stage_name] = Stage(stage_name, os.path.join(
          self.path, stage_name), self)
    return stages

  @property
  def description(self) -> Text:
    return self._raw_json.get('description', '')

  def save_description(self, desc: Text) -> None:
    self._raw_json['description'] = desc
    self._save_raw_json()

  def add_stage(self, stage_name: Text) -> Stage:
    stage_path = os.path.join(self.path, stage_name)
    self.stages[stage_name] = Stage(stage_name, self.path, self)
    self._raw_json['stages'].append({'directory_name': stage_name})
    self._save_raw_json()
    maybe_makedirs(stage_path)
    return self.stages[stage_name]

  # TODO: return errors
  def remove_stage(self, stage_name: Text) -> None:
    stage = self.stages[stage_name]
    del self.stages[stage_name]
    for j, s in enumerate(self._raw_json.get('stages', ())):
      if s['directory_name'] == stage_name:
        del self._raw_json['stages'][j]
        break
    self._save_raw_json()
    try:
      shutil.rmtree(stage.path)
    except (shutil.Error, OSError, IOError) as e:
      pass

  def save_zip(self, file_obj: IO) -> None:
    with zipfile.ZipFile(file_obj, 'a') as zf:
      zf.write(os.path.join(self.path, 'metadata.json'), 'metadata.json')
      for stage in self.stages.values():
        stage._save_zip(self.name, zf)

  @classmethod
  def from_zip(cls, file_obj: IO, stages_name: Text,
               stages_root: Text) -> "Stages":
    "Unpack zip from file_obj into os.path.join(stages_root, stages_name)."
    try:
      assignment_root = os.path.join(stages_root, stages_name)
      os.mkdir(assignment_root)
      with zipfile.ZipFile(file_obj, 'r') as zf:
        bad_filename = zf.testzip()
        if bad_filename is not None:
          raise Error('Corrupt file in zip: ' + bad_filename)
        # TODO: Handle case where zf.namelist() uses a lot of memory
        archived_files = zf.namelist()
        for af in archived_files:
          zf.extract(af, assignment_root)
        # Note: The code below is necessary because zip files do not store
        # whether a file was executable or not.
        stages = cls(assignment_root)
        for stage in stages.stages.values():
          make_file_executable(os.path.join(stage.path, 'main'))
        return stages
    except (zipfile.BadZipfile, zipfile.LargeZipFile) as e:
      raise Error(e)


def merge_tree(src: Text, dst: Text) -> List[Text]:
  "Like shutil.copytree, except it is not an error if the dst exists."
  errors = []
  src = os.path.abspath(src)
  dst = os.path.abspath(dst)
  maybe_makedirs(dst)
  for filename in os.listdir(src):
    src_filename = os.path.join(src, filename)
    dst_filename = os.path.join(dst, filename)
    if os.path.isfile(src_filename):
      try:
        shutil.copy(src_filename, dst_filename)
      except (shutil.Error, OSError, IOError) as e:
        errors.append(repr(e))
        errors.append(str(e))
    elif os.path.isdir(src_filename):
      merge_tree(src_filename, dst_filename)
    else:
      raise Error('"{}" is not a file/directory and cannot be copied.'.format(
          src_filename))
  return errors


def read_proc_summarized_stdout(proc: subprocess.Popen,
                                bufsize: int) -> Tuple[bytes, Text]:
  """Given a subprocess.Popen object, read it's stdout until the process dies
  and return a summarized version of the output and an error string or None.

  bufsize is the buffer size of the 'file' object
  (unbuffered and line buffering are not supported)
  """
  if bufsize < 2:
    raise ValueError(
        'This function does not support unbuffered or line-buffered files '
        '(bufsize must be >= 2).')
  # between 128KB and 128KB + bufsize
  output = collections.deque(
      maxlen=131072 // bufsize + 1)  # type: collections.deque
  error = None
  try:
    while True:
      partial_read = proc.stdout.read(bufsize)
      if partial_read:
        output.append(partial_read)
      else:  # else there's no data left to read and proc is done running
        break
  except EnvironmentError as e:
    error = str(e)
  return b''.join(output), error


class DockerExecutor(object):
  """Thin, Grade Oven specific, Docker wrapper.

  To use, create a DockerExecutor with
  a unique Docker safe container_id such as a hex-string, and
  a host_dir(ectory) that can be safely mounted inside of Docker.
  Then, call .init(), .docker_run(...), .cleanup().

  See executor_test.py for examples.
  """

  def __init__(self, container_id: Text, host_dir: Text) -> None:
    self.container_id = container_id
    self.host_dir = os.path.abspath(host_dir)
    self.timeout_seconds = 60
    self.max_num_files = 1000
    self.max_mem_bytes = 256 * 1024**2

  def _docker_run(
      self,
      docker_image_name: Text,
      cmd: List[Text],
      user: Text = None,
      env: Dict[Text, Text] = None) -> Tuple[int, Text, List[Text]]:
    "Runs a command and returns the return code or None if it timed out."
    errors = []
    if user not in ('grade_oven', 'root', None):
      raise ValueError(
          'User "{}" must be "grade_oven" or "root".'.format(user))
    if env is None:
      env = {}
    docker_cmd = [
        'docker',
        'run',
        '--hostname',
        'gradeoven',
        '--memory',
        str(self.max_mem_bytes),
        # TODO: figure out why I need to set nproc so high
        #  If I didn't set nproc > 500 docker wouldn't even start
        '--ulimit',
        'nproc=1000:1000',
        '--ulimit',
        'nice=19:19',
        '--ulimit',
        'nofile={}:{}'.format(self.max_num_files, self.max_num_files),
        '--name',
        self.container_id,
        '--net',
        'none',
        '--read-only=true',
        '--restart=no',
        '--detach',
        '--volume',
        u'{}/grade_oven:/grade_oven'.format(self.host_dir),
        '--volume',
        u'{}/tmp:/tmp'.format(self.host_dir),
        '--workdir',
        '/grade_oven/submission',
        '--cpu-shares',
        '128'
    ]
    # If a user is not specified, run as the effective user of this process.
    # If this code breaks, you can use 'grade_oven' in a --prod run but not
    # a --debug run.
    docker_cmd.extend(['--user', user or str(os.geteuid())])
    for key, val in env.items():
      docker_cmd.append('--env')
      docker_cmd.append('{}={}'.format(key, val))
    if user == 'root':
      docker_cmd.append('--volume')
      docker_cmd.append(u'{}/root:/root'.format(self.host_dir))
    docker_cmd.append(docker_image_name)
    docker_cmd.extend(cmd)
    logging.info('Starting Docker container: %s', docker_cmd)
    empty_env = {}  # type: Dict[Text, Text]
    proc = subprocess.Popen(
        docker_cmd,
        bufsize=-1,
        close_fds=True,
        cwd=self.host_dir,
        env=empty_env)
    proc.wait()

    logging.info('Waiting for Docker container: %s', self.container_id)
    docker_cmd = [
        'timeout',
        str(self.timeout_seconds), 'docker', 'wait', self.container_id
    ]
    proc = subprocess.Popen(
        docker_cmd,
        stdout=subprocess.PIPE,
        bufsize=-1,
        close_fds=True,
        cwd=self.host_dir,
        env=empty_env)
    return_code_raw, _ = proc.communicate()
    try:
      return_code = int(return_code_raw)
    except ValueError:
      errors.append(
          'Command "{}" did not finish in {} seconds and timed out.'.format(
              join_cmd_parts(cmd), self.timeout_seconds))
      return_code = None

    logging.info('Stopping Docker container: %s', self.container_id)
    docker_cmd = ['docker', 'stop', '--time', '5', self.container_id]
    proc = subprocess.Popen(
        docker_cmd,
        bufsize=-1,
        close_fds=True,
        cwd=self.host_dir,
        env=empty_env)
    proc.wait()

    logging.info('Reading Docker logs from container: %s', self.container_id)
    docker_cmd = ['docker', 'logs', self.container_id]
    proc = subprocess.Popen(
        docker_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=4096,
        close_fds=True,
        cwd=self.host_dir,
        env=empty_env)
    output, err = read_proc_summarized_stdout(proc, 4096)
    proc.wait()
    if err:
      errors.append(err)

    logging.info('Removing Docker container: %s', self.container_id)
    docker_cmd = ['docker', 'rm', '--force', self.container_id]
    proc = subprocess.Popen(
        docker_cmd,
        bufsize=-1,
        close_fds=True,
        cwd=self.host_dir,
        env=empty_env)
    proc.wait()

    # TODO: Refactor this function and related ones to work with bytes instead
    # of Text.
    return return_code, output.decode('utf-8'), errors

  def _extract_archive(self, archive_path: Text,
                       user: Optional[Text] = None) -> Tuple[Text, List[Text]]:
    output = ''
    errors = []
    if archive_path is not None:
      unarchive_cmd = {
          '.tar': ['/bin/tar', '-xf', '--'],
          '.zip': ['/usr/bin/unzip', '--'],
          '.gz': ['/bin/gunzip', '--'],
      }.get(os.path.splitext(archive_path)[-1])
      if unarchive_cmd is not None:
        unarchive_cmd.append(
            os.path.join('/grade_oven',
                         os.path.split(archive_path)[-1]))
        return_code, output, errs = self._docker_run(
            'grade_oven/grade_oven_base', unarchive_cmd, user=user)
        errors.extend(errs)
        if return_code:
          errors.append('Unarchiving command failed: "{}"'.format(
              output.rsplit('\n', 1)[-1]))
    return output, errors

  def _copy_and_extract_archive(
      self,
      archive_path: Text,
      dst_path: Optional[Text] = None,
      user: Optional[Text] = None) -> Tuple[Text, List[Text]]:
    output = ''
    errors = []
    if archive_path is not None:
      if dst_path is None:
        dst_path = os.path.join(self.host_dir, user or 'grade_oven')
      if os.path.isfile(archive_path):
        logging.info('Copying file "%s" to "%s"', archive_path, dst_path)
        shutil.copy(archive_path, dst_path)
        output, errs = self._extract_archive(archive_path, user=user)
        errors.extend(errs)
      elif os.path.isdir(archive_path):
        logging.info('Copying directory files "%s"/* to "%s"', archive_path,
                     dst_path)
        try:
          errs = merge_tree(archive_path, dst_path)
          errors.extend(errs)
        except Error as e:
          errors.append(repr(e))
          errors.append(str(e))
      elif not os.path.exists(archive_path):
        errors.append('archive_path does not exist: "{}"'.format(archive_path))
        logging.error(errors[-1])
      else:
        errors.append(
            'archive_path is not a file/dir: "{}"'.format(archive_path))
        logging.error(errors[-1])
    return output, errors

  def init(self) -> None:
    """Remove any contaminated contents from self.host_dir in order
    to .run_stages(...) stages safely.
    """
    for sub_dir in ('tmp', 'grade_oven', 'grade_oven/output',
                    'grade_oven/submission'):
      try:
        os.mkdir(os.path.join(self.host_dir, sub_dir))
      except OSError as e:
        if e.errno != errno.EEXIST:
          raise Error(e)
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
      os.mkdir(os.path.join(self.host_dir, sub_dir))

  def run_stages(self,
                 submission_path: Text,
                 stages: Stages,
                 stage_done_callback: Callable[[Stage], Any] = None,
                 env: Dict[Text, Text] = None) -> Tuple[Text, List[Text]]:
    """Run stages, copying submission_path to /grade_oven/submission inside the
    container.  When a stage is done running, stage_done_callback is called
    with the stage that has completed.
    """
    outputs = []
    errors = []
    output, errs = self._copy_and_extract_archive(submission_path,
                                                  os.path.join(
                                                      self.host_dir,
                                                      'grade_oven/submission'))
    outputs.append(output)
    errors.extend(errs)
    for stage in stages.stages.values():
      output, errs = self._copy_and_extract_archive(
          stage.path, os.path.join(self.host_dir, 'grade_oven', stage.name))
      outputs.append(output)
      errors.extend(errs)
      return_code, output, errs = self._docker_run(
          'grade_oven/grade_oven',
          [os.path.join('/grade_oven', stage.name, 'main')],
          env=env)
      stage.output = StageOutput(
          os.path.join(self.host_dir, 'grade_oven/output'))
      stage.output.stdout = output
      stage.output.errors = errs
      # If the stage is running untrusted code, remove the score.
      if not stage.is_trusted_stage:
        stage.output.score = None
      if stage_done_callback is not None:
        stage_done_callback(stage)
    return '\n'.join(outputs), errors

  def cleanup(self) -> None:
    for sub_dir in ('tmp', 'grade_oven'):
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
