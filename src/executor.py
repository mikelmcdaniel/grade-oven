"""The executor module knows how to build and test code.

archive: a tar, zip, gzip, or single file
code: an archive of source code
build script: a archive of files and a series of commands to run
(diff) test case: a set of 2 archives,
  input files and expected output files,
  and a series of commands to run that take the input and produce output.

A typical (error free), flow looks like:
 - copy code archive to a special directory, that is mounted in a container
 - extract code archive in that special directory in that container
 - copy and extract build script archive to that mounted directory
 - run the build script
 - remove everything in the special directory, except expected_filenames
 - copy test input archive input to that mounted directory
 - run the test script commands with the test input
 - diff the test results against the expected test output
"""

import collections
import errno
import fractions
import json
import logging
import os
import re
import shlex
import shutil
import subprocess


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


def maybe_makedirs(path):
  try:
    os.makedirs(path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise Error(e)


def join_cmd_parts(cmd_parts):
  escaped_parts = []
  for part in cmd_parts:
    if len(shlex.split(part)) > 1:
      escaped_parts.append('"{}"'.format(part.replace('"', '\\"')))
    else:
      escaped_parts.append(part)
  return ' '.join(escaped_parts)


def file_contents_or(file_path, default_contents=''):
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

  def __init__(self, output_path):
    score_raw = file_contents_or(os.path.join(output_path, 'score'), '')
    score_match = re.match(self.SCORE_RE, score_raw)
    if score_match:
      self.score = int(score_match.group(1))
      self.total = int(score_match.group(2))
    else:
      self.score = None
      self.total = None
    self.stdout = None
    self.errors = None

def make_file_executable(path):
  mode = os.stat(path).st_mode
  # copy read bits to executable bits
  mode |= (mode & 0444) >> 2
  os.chmod(path, mode)

class Stage(object):
  def __init__(self, stage_path):
    self.path = stage_path
    _, self.name = os.path.split(stage_path)
    self.output = None

  def save_main_script(self, contents):
    maybe_makedirs(self.path)
    path = os.path.join(self.path, 'main')
    with open(path, 'w') as f:
      # remove bad line-endings
      f.write(contents.replace('\r\n', '\n'))
    make_file_executable(path)

  def read_main_script(self):
    return file_contents_or(os.path.join(self.path, 'main'))

  @property
  def main_script(self):
    return self.read_main_script()

  @main_script.setter
  def main_script(self, contents):
    return self.save_main_script(contents)

  @property
  def filenames_except_meta(self):
    try:
      filenames = set(os.listdir(self.path))
    except OSError as e:
      if e.errno == errno.ENOENT:
        filenames = set()
      else:
        raise Error(e)
    filenames.discard('main')
    filenames.discard('description')
    return sorted(filenames)

  @property
  def description(self):
    return file_contents_or(os.path.join(self.path, 'description'), self.name)

  def save_description(self, desc):
    maybe_makedirs(self.path)
    with open(os.path.join(self.path, 'description'), 'w') as f:
      f.write(desc)


class Stages(object):
  def __init__(self, stages_path):
    self.path = stages_path
    _, self.name = os.path.split(stages_path)
    self._stages = None

  @property
  def stages(self):
    if self._stages is None:
      raw_names = file_contents_or(os.path.join(self.path, 'stages'))
      stage_names = [s for s in raw_names.split('\n') if s]
      stages = collections.OrderedDict()
      for stage_name in stage_names:
        # TODO: sanitize names so they can't be something like '/path/from/root'
        stages[stage_name] = Stage(os.path.join(self.path, stage_name))
      self._stages = stages
    return self._stages

  @property
  def description(self):
    return file_contents_or(os.path.join(self.path, 'description'), self.name)

  def save_description(self, desc):
    maybe_makedirs(self.path)
    with open(os.path.join(self.path, 'description'), 'w') as f:
      f.write(desc)

  def save_stages(self):
    assert self._stages is not None
    maybe_makedirs(self.path)
    with open(os.path.join(self.path, 'stages'), 'w') as f:
      f.write('\n'.join(self.stages.iterkeys()))

  def add_stage(self, stage_name):
    stage_path = os.path.join(self.path, stage_name)
    self.stages[stage_name] = Stage(stage_path)
    self.save_stages()
    return self.stages[stage_name]


def merge_tree(src, dst):
  "Like shutil.copytree, except it is not an error if the dst exists."
  src = os.path.abspath(src)
  dst = os.path.abspath(dst)
  maybe_makedirs(dst)
  for filename in os.listdir(src):
    src_filename = os.path.join(src, filename)
    dst_filename = os.path.join(dst, filename)
    if os.path.isfile(src_filename):
      try:
        shutil.copy(src_filename, dst_filename)
      except shutil.Error as e:
        raise Error(e)
    elif os.path.isdir(src_filename):
      merge_tree(src_filename, dst_filename)
    else:
      raise Error('"{}" is not a file/directory and cannot be copied.'.format(
        src_filename))


class DockerExecutor(object):
  """Thin, Grade Oven specific, Docker wrapper."""

  def __init__(self, container_id, host_dir):
    self.container_id = container_id
    self.host_dir = os.path.abspath(host_dir)
    self.timeout_seconds = 30
    self.max_num_files = 1000

  def _docker_run(self, docker_image_name, cmd, user=None):
    "Runs a command and returns the return code or None if it timed out."
    errors = []
    if user is None:
      user = 'grade_oven'
    assert user in ('grade_oven', 'root')
    docker_cmd = [
      'docker', 'run', '--hostname', 'grade_oven', '--memory', '256m',
      # TODO: figure out why I need to set nproc so high
      #  If I didn't set nproc > 500 docker wouldn't even start
      '--ulimit', 'nproc=1000:1000',
      '--ulimit', 'nice=19:19',
      '--ulimit', 'nofile={}:{}'.format(self.max_num_files, self.max_num_files),
      '--name', self.container_id, '--net', 'none', '--read-only=true',
      '--restart=no', '--user', user, '--detach',  # , '--rm=true'
      '--volume', '{}/grade_oven:/grade_oven'.format(self.host_dir),
      '--volume', '{}/tmp:/tmp'.format(self.host_dir),
      '--workdir', '/grade_oven/submission', '--cpu-shares', '128']
    if user == 'root':
      docker_cmd.append('--volume')
      docker_cmd.append('{}/root:/root'.format(self.host_dir))
    docker_cmd.append(docker_image_name)
    # docker_cmd.extend(['od', '-c']) DO NOT SUBMIT
    docker_cmd.extend(cmd)
    logging.info('Starting Docker container: %s', docker_cmd)
    proc = subprocess.Popen(
      docker_cmd, bufsize=-1, close_fds=True, cwd=self.host_dir, env={})
    proc.wait()

    logging.info('Waiting for Docker container: %s', self.container_id)
    docker_cmd = [
      'timeout', str(self.timeout_seconds), 'docker', 'wait', self.container_id]
    proc = subprocess.Popen(
      docker_cmd, stdout=subprocess.PIPE, bufsize=-1, close_fds=True,
      cwd=self.host_dir, env={})
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
      docker_cmd, bufsize=-1, close_fds=True, cwd=self.host_dir, env={})
    proc.wait()

    logging.info('Reading Docker logs from container: %s', self.container_id)
    # TODO: This is probably exploitable: If the user can cause a lot of output
    #  on the last line, then they may cause the server to OOM.
    docker_cmd = ['docker', 'logs', '--tail', '100', self.container_id]
    proc = subprocess.Popen(
      docker_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=-1,
      close_fds=True, cwd=self.host_dir, env={})
    output, _ = proc.communicate()

    logging.info('Removing Docker container: %s', self.container_id)
    docker_cmd = ['docker', 'rm', '--force', self.container_id]
    proc = subprocess.Popen(
      docker_cmd, bufsize=-1, close_fds=True, cwd=self.host_dir, env={})
    proc.wait()

    return return_code, output, errors

  def _extract_archive(self, archive_path, user=None):
    output = ''
    errors = []
    if user is None:
      user = 'grade_oven'
    if archive_path is not None:
      unarchive_cmd = {
        '.tar': ['/bin/tar', '-xf', '--'],
        '.zip': ['/usr/bin/unzip', '--'],
        '.gz': ['/bin/gunzip', '--'],
      }.get(os.path.splitext(archive_path)[-1])
      if unarchive_cmd is not None:
        unarchive_cmd.append(
          os.path.join('/grade_oven', os.path.split(archive_path)[-1]))
        return_code, output, errs = self._docker_run(
          'grade_oven/grade_oven_base', unarchive_cmd, user=user)
        errors.extend(errs)
        if return_code:
          errors.append('Unarchiving command failed: "{}"'.format(
            output.rsplit('\n', 1)[-1]))
    return output, errors

  def _copy_and_extract_archive(self, archive_path, dst_path=None, user=None):
    output = ''
    errors = []
    if user is None:
      user = 'grade_oven'
    if archive_path is not None:
      if dst_path is None:
        dst_path = os.path.join(self.host_dir, user)
      if os.path.isfile(archive_path):
        logging.info('Copying file "%s" to "%s"', archive_path, dst_path)
        shutil.copy(archive_path, dst_path)
        output, errs = self._extract_archive(archive_path, user=user)
        errors.extend(errs)
      elif os.path.isdir(archive_path):
        logging.info(
          'Copying directory files "%s"/* to "%s"', archive_path, dst_path)
        try:
          merge_tree(archive_path, dst_path)
        except Error as e:
          errors.append(repr(e))
          errors.append(str(e))
      elif not os.path.exists(archive_path):
        errors.append('archive_path does not exist: "{}"'.format(archive_path))
        logging.error(errors[-1])
      else:
        errors.append('archive_path is not a file/dir: "{}"'.format(archive_path))
        logging.error(errors[-1])
    return output, errors

  def init(self):
    for sub_dir in (
        'tmp', 'grade_oven', 'grade_oven/output',
        'grade_oven/submission'):
      try:
        os.mkdir(os.path.join(self.host_dir, sub_dir))
      except OSError as e:
        if e.errno != errno.EEXIST:
          raise Error(e)
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
      os.mkdir(os.path.join(self.host_dir, sub_dir))

  def run_stages(self, submission_path, stages, stage_done_callback=None):
    """Run stages, copying submission_path to /grade_oven/submission inside the
    container.  When a stage is done running, stage_done_callback is called
    with the stage that has completed.
    """
    outputs = []
    errors = []
    output, errs = self._copy_and_extract_archive(
      submission_path, os.path.join(self.host_dir, 'grade_oven/submission'))
    outputs.append(output)
    errors.extend(errs)
    for stage in stages.stages.itervalues():
      output, errs = self._copy_and_extract_archive(
        stage.path,
        os.path.join(self.host_dir, 'grade_oven', stage.name))
      outputs.append(output)
      errors.extend(errs)
      return_code, output, errs = self._docker_run(
        'grade_oven/grade_oven',
        [os.path.join('/grade_oven', stage.name, 'main')])
      stage.output = StageOutput(
        os.path.join(self.host_dir, 'grade_oven/output'))
      stage.output.stdout = output
      stage.output.errors = errs
      if stage_done_callback is not None:
        stage_done_callback(stage)
    return '\n'.join(outputs), errors

  def cleanup(self):
    for sub_dir in ('tmp', 'grade_oven'):
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
