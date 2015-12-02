"""The executor module knows how to build and test code.

archive: a tar, zip, gzip, or single file
code: an archive of source code
build script: a archive of files and a series of commands to run
test: a set of 2 archives,
  input files (test cases) and expected output files,
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
import logging
import os
import shutil
import subprocess
import fractions


class Error(Exception):
  pass


class BuildScript(object):
  def __init__(self, archive_path, cmds, expected_filenames):
    assert not isinstance(cmds[0], basestring)
    assert not isinstance(expected_filenames, basestring)
    self.archive_path = archive_path
    self.cmds = cmds
    self.expected_filenames = expected_filenames


class TestScript(object):
  def __init__(self, input_archive_path, output_archive_path, cmds):
    assert not isinstance(cmds[0], basestring)
    self.input_archive_path = input_archive_path
    self.output_archive_path = output_archive_path
    self.cmds = cmds

  def score(self, host_dir):
    "Return a tuple of score in [0, 1] and a list of error strings."
    pass


class DiffTestScript(TestScript):
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
          errors.append('Output files different for {}'.format(base_name))
      except IOError as e:
        errors.append('Output file not found for {} ({})'.format(base_name, e))
    return total_score, errors


class ExecutorBase(object):
  pass


class DockerExecutor(ExecutorBase):
  """Thin, Grade Oven specific, Docker wrapper."""

  def __init__(self, container_id, host_dir):
    self.container_id = container_id
    self.host_dir = host_dir

  def init(self):
    for sub_dir in ('grade_oven', 'root', 'tmp'):
      try:
        os.mkdir(os.path.join(self.host_dir, sub_dir))
      except OSError as e:
        if e.errno == errno.EEXIST:
          pass
        else:
          raise Error(e)
      shutil.rmtree(os.path.join(self.host_dir, sub_dir))
      os.mkdir(os.path.join(self.host_dir, sub_dir))

  def _docker_run(self, docker_image_name, cmd, user=None):
    "Runs a command and returns the return code or None if it timed out."
    if user is None:
      user = 'grade_oven'
    assert user in ('grade_oven', 'root')
    docker_cmd = [
      'docker', 'run', '--hostname', 'grade_oven', '--memory', '256m',
      '--name', self.container_id, '--net', 'none', '--read-only=true',
      '--restart=no', '--user', user, '--detach',  # , '--rm=true'
      '--volume', '{}/grade_oven:/grade_oven'.format(self.host_dir),
      '--volume', '{}/tmp:/tmp'.format(self.host_dir),
      '--workdir', '/grade_oven', '--cpu-shares', '128']
    if user == 'root':
      docker_cmd.append('--volume')
      docker_cmd.append('{}/root:/root'.format(self.host_dir))
    docker_cmd.append(docker_image_name)
    docker_cmd.extend(cmd)
    logging.info('Starting Docker container: %s', docker_cmd)
    proc = subprocess.Popen(
      docker_cmd, bufsize=-1, close_fds=True,cwd=self.host_dir, env={})
    proc.wait()

    logging.info('Waiting for Docker container : %s', self.container_id)
    timeout_seconds = 30
    docker_cmd = [
      'timeout', str(timeout_seconds), 'docker', 'wait', self.container_id]
    proc = subprocess.Popen(
      docker_cmd, stdout=subprocess.PIPE, bufsize=-1, close_fds=True,
      cwd=self.host_dir, env={})
    return_code_raw, _ = proc.communicate()
    try:
      return_code = int(return_code_raw)
    except ValueError:
      return_code = None

    logging.info('Stopping Docker container: %s', self.container_id)
    docker_cmd = ['docker', 'stop', '--time', '1', self.container_id]
    proc = subprocess.Popen(
      docker_cmd, bufsize=-1, close_fds=True, cwd=self.host_dir, env={})
    proc.wait()

    logging.info('Removing Docker container: %s', self.container_id)
    docker_cmd = ['docker', 'rm', '--force', self.container_id]
    proc = subprocess.Popen(
      docker_cmd, bufsize=-1, close_fds=True, cwd=self.host_dir, env={})
    proc.wait()

    return return_code

  def _extract_archive(self, archive_path, user=None):
    if user is None:
      user = 'grade_oven'
    if archive_path is not None:
      unarchive_cmd = {
        '.tar': ['/bin/tar', '-xf', '--'],
        '.zip': ['/usr/bin/unzip', '--'],
        '.gz': ['/bin/gunzip', '--'],
      }.get(os.path.splitext(code_path)[-1], ['/bin/true', '--'])
      unarchive_cmd.append(
        os.path.join('/grade_oven', os.path.split(archive_path)[-1]))
      self._docker_run('grade_oven/grade_oven_base', unarchive_cmd, user=user)

  def _copy_and_extract_archive(self, archive_path, user=None):
    if user is None:
      user = 'grade_oven'
    if archive_path is not None:
      dst_path = os.path.join(self.host_dir, user)
      logging.info('Copying "%s" to "%s"', archive_path, dst_path)
      shutil.copy(archive_path, dst_path)
      self._extract_archive(archive_path, user=user)

  # TODO: add error checking and reporting
  # TODO: check for bad users (e.g. use os.path.isfile() on expected_filenames)
  def build(self, code_path, build_script):
    # copy code archive to a special directory, that is mounted in a container
    # extract code archive in that special directory in that container
    self._copy_and_extract_archive(code_path)
    # copy and extract build script archive to that mounted directory
    self._copy_and_extract_archive(build_script.archive_path)
    # run the build script
    for cmd in build_script.cmds:
      self._docker_run('grade_oven/preheat_build', cmd)
    # remove everything in the special directory, except expected_filenames
    cmd = ['mv'] + build_script.expected_filenames + ['/root/']
    self._docker_run('grade_oven/preheat_build', cmd, user='root')
    cmd = ['/bin/bash', '-c', 'rm -rf /grade_oven/*']
    self._docker_run('grade_oven/preheat_build', cmd)
    cmd = ['/bin/bash', '-c', 'mv /root/* /grade_oven/']
    self._docker_run('grade_oven/preheat_build', cmd, user='root')

  def test(self, test_script):
    # copy test input archive input to that mounted directory
    self._copy_and_extract_archive(test_script.input_archive_path)
    # run the test script commands with the test input
    for cmd in test_script.cmds:
      self._docker_run('grade_oven/bake_test', cmd)
    # diff the test results against the expected test output
    self._copy_and_extract_archive(test_script.output_archive_path, user='root')
    score, errors = test_script.score(self.host_dir)
    return score, errors

  def cleanup(self):
    self.init()

  # TODO: implement timeouts
  def build_test(self, code_path, build_script, test_script):
    self.build(code_path, build_script)
    return self.test(test_script)


if __name__ == '__main__':
  logging.basicConfig(
    filename='/dev/stderr',level=logging.INFO,
    format='%(levelname)s %(asctime)s %(message)s')
  code_path = 'test_host_dir/test/hello_world.cpp'
  bs = BuildScript(
    None,
    [['clang', '-std=c++11', '-Wall', '-Wextra', '-lstdc++',
      '-o', 'hello_world', 'hello_world.cpp']],
    ['hello_world'])
  ts = DiffTestScript(
    None, 'test_host_dir/test/hello_world.txt',
    [['/bin/bash', '-c', '/grade_oven/hello_world > hello_world.txt']])
  c = DockerExecutor('mikel_test', os.path.abspath('test_host_dir'))
  c.init()
  c.build(code_path, bs)
  score, errors = c.test(ts)
  # c.cleanup()
  print 'SCORE', score, '\n\n'.join(errors)
