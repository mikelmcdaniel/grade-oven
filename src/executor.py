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

import errno
import fractions
import json
import logging
import os
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


def join_cmd_parts(cmd_parts):
  escaped_parts = []
  for part in cmd_parts:
    if len(shlex.split(part)) > 1:
      escaped_parts.append('"{}"'.format(part.replace('"', '\\"')))
    else:
      escaped_parts.append(part)
  return ' '.join(escaped_parts)



class BuildScript(JSONSerializable):
  def __init__(self, archive_path=None, cmds=None, expected_filenames=None):
    if cmds is None:
      cmds = []
    if expected_filenames is None:
      expected_filenames = []
    assert not cmds or not isinstance(cmds[0], basestring)
    assert not isinstance(expected_filenames, basestring)
    self.archive_path = archive_path
    self.cmds = cmds
    self.expected_filenames = expected_filenames

  def serialize(self):
    return json.dumps({
      'archive_path': self.archive_path,
      'cmds': self.cmds,
      'expected_filenames': self.expected_filenames})


class TestCase(JSONSerializable):
  def __init__(self, input_archive_path=None, output_archive_path=None, cmds=None):
    if cmds is None:
      cmds = []
    assert not cmds or not isinstance(cmds[0], basestring)
    self.input_archive_path = input_archive_path
    self.output_archive_path = output_archive_path
    self.cmds = cmds

  def score(self, host_dir):
    "Return a tuple of score in [0, 1] and a list of error strings."
    pass

  def serialize(self):
    return json.dumps({
      'input_archive_path': self.input_archive_path,
      'output_archive_path': self.output_archive_path,
      'cmds': self.cmds})


class DiffTestCase(TestCase):
  def score(self, host_dir):
    total_score = 0
    errors = []
    base_filenames = os.listdir(os.path.join(host_dir, 'root'))
    for base_name in base_filenames:
      filename_expected = os.path.join(host_dir, 'root', base_name)
      filename_actual = os.path.join(host_dir, 'grade_oven', base_name)
      try:
        with open(filename_actual) as f:
          actual = f.read()
        with open(filename_expected) as f:
          expected = f.read()
        if actual.split() == expected.split():
          total_score += fractions.Fraction(1, len(base_filenames))
        else:
          errors.append('Expected output different for {}'.format(base_name))
      except IOError as e:
        errors.append('Expected output not found for {} ({})'.format(base_name, e))
    return total_score, errors


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
      # '--lxc-conf', 'lxc.cgroup.tasks.limit=30',
      # '--ulimit', 'nofile=262144:262144',
      # TODO: figure out why I need to set nproc so high
      #  If I didn't set nproc > 500 docker wouldn't even start
      '--ulimit', 'nproc=1000:1000',
      '--ulimit', 'nice=19:19',
      '--ulimit', 'nofile={}:{}'.format(self.max_num_files, self.max_num_files),
      '--name', self.container_id, '--net', 'none', '--read-only=true',
      '--restart=no', '--user', user, '--detach',  # , '--rm=true'
      '--volume', '{}/grade_oven:/grade_oven'.format(self.host_dir),
      '--volume', '{}/tmp:/tmp'.format(self.host_dir),
      '--workdir', '/grade_oven', '--cpu-shares', '128']
    if user == 'root':
      docker_cmd.append('--volume')
      docker_cmd.append('{}/root:/root'.format(self.host_dir))
    docker_cmd.append(docker_image_name)
    # Add a soft timeout with 5 extra seconds.
    docker_cmd.extend(['timeout', str(self.timeout_seconds + 5)])
    docker_cmd.extend(cmd)
    logging.info('Starting Docker container: %s', docker_cmd)
    proc = subprocess.Popen(
      docker_cmd, bufsize=-1, close_fds=True, cwd=self.host_dir, env={})
    proc.wait()

    logging.info('Waiting for Docker container : %s', self.container_id)
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
    docker_cmd = ['docker', 'stop', '--time', '10', self.container_id]
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

  def _copy_and_extract_archive(self, archive_path, user=None):
    output = ''
    errors = []
    if user is None:
      user = 'grade_oven'
    if archive_path is not None:
      dst_path = os.path.join(self.host_dir, user)
      if os.path.isfile(archive_path):
        logging.info('Copying file "%s" to "%s"', archive_path, dst_path)
        shutil.copy(archive_path, dst_path)
        output, errs = self._extract_archive(archive_path, user=user)
        errors.extend(errs)
      elif os.path.isdir(archive_path):
        logging.info(
          'Copying directory files "%s"/* to "%s"', archive_path, dst_path)
        # TODO: Make this copy the contents of a directory properly
        for f in os.listdir(archive_path):
          shutil.copy(os.path.join(archive_path, f), dst_path)
      elif not os.path.exists(archive_path):
        errors.append('archive_path does not exist: "{}"'.format(archive_path))
        logging.error(errors[-1])
      else:
        errors.append('archive_path is not a file/dir: "{}"'.format(archive_path))
        logging.error(errors[-1])
    return output, errors

  def init(self):
    for sub_dir in ('tmp', 'root', 'grade_oven'):
      try:
        os.mkdir(os.path.join(self.host_dir, sub_dir))
      except OSError as e:
        if e.errno != errno.EEXIST:
          raise Error(e)
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
      os.mkdir(os.path.join(self.host_dir, sub_dir))

  # TODO: add error checking and reporting
  # TODO: check for bad users (e.g. use os.path.isfile() on expected_filenames)
  def build(self, code_path, build_script):
    outputs = []
    errors = []
    # copy code archive to a special directory, that is mounted in a container
    # extract code archive in that special directory in that container
    output, errs = self._copy_and_extract_archive(code_path)
    errors.extend(errs)
    outputs.extend(output)
    # copy and extract build script archive to that mounted directory
    output, errs = self._copy_and_extract_archive(build_script.archive_path)
    errors.extend(errs)
    outputs.extend(output)
    # run the build script
    for cmd in build_script.cmds:
      return_code, output, errs = self._docker_run(
        'grade_oven/preheat_build', cmd)
      errors.extend(errs)
      if return_code:
        errors.append('Build command failed: {}'.format(join_cmd_parts(cmd)))
      outputs.append(output)
    # remove everything in the special directory, except expected_filenames
    cmd = ['mv'] + build_script.expected_filenames + ['/root/']
    errors.extend(self._docker_run('grade_oven/preheat_build', cmd, user='root')[2])
    cmd = ['/bin/bash', '-c', 'rm -rf /grade_oven/*']
    errors.extend(self._docker_run('grade_oven/preheat_build', cmd)[2])
    cmd = ['/bin/bash', '-c', 'mv /root/* /grade_oven/']
    errors.extend(self._docker_run('grade_oven/preheat_build', cmd, user='root')[2])
    return '\n'.join(output for output in outputs if output), errors

  def test(self, test_case):
    outputs = []
    errors = []
    # copy test input archive input to that mounted directory
    output, errs = self._copy_and_extract_archive(test_case.input_archive_path)
    errors.extend(errs)
    outputs.extend(output)
    # run the test script commands with the test input
    for cmd in test_case.cmds:
      _, output, errs = self._docker_run('grade_oven/bake_test', cmd)
      errors.extend(errs)
      outputs.extend(output)
    # diff the test results against the expected test output
    output, errs = self._copy_and_extract_archive(test_case.output_archive_path, user='root')
    errors.extend(errs)
    outputs.extend(output)
    score, errs = test_case.score(self.host_dir)
    errors.extend(errs)
    return score, '\n'.join(output), errors

  def cleanup(self):
    for sub_dir in ('tmp', 'root', 'grade_oven'):
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
