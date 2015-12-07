import os
import unittest
import executor
import shutil


class EphemeralDir(object):
  def __init__(self, path):
    self.path = path

  def __enter__(self):
    shutil.rmtree(self.path, ignore_errors=True)
    os.makedirs(self.path)

  def __exit__(self, exc_type, exc_value, traceback):
    if exc_value is None:
      # For tests, we may NOT cleanup the directory, so that it can be debugged.
      shutil.rmtree(self.path)
    else:
      return False


class TestExecutor(unittest.TestCase):
  def test_hello_world(self):
    host_dir = 'testdata/executor/hello_world'
    code_path = 'testdata/executor/hello_world.cpp'
    expected_output_path = 'testdata/executor/hello_world.txt'
    with EphemeralDir(host_dir):
      build_script = executor.BuildScript(
        None,
        [['clang', '-std=c++11', '-Wall', '-Wextra', '-lstdc++',
          '-o', 'hello_world', 'hello_world.cpp']],
        ['hello_world'])
      test_case = executor.DiffTestCase(
        None, expected_output_path,
        [['/bin/bash', '-c', './hello_world > hello_world.txt']])
      c = executor.DockerExecutor('test_hello_world', host_dir)
      c.init()
      output, errors = c.build(code_path, build_script)
      self.assertEqual(errors, [])
      self.assertEqual(output, '')
      score, output, errors = c.test(test_case)
      self.assertEqual(output, '')
      self.assertEqual(errors, [])
      self.assertEqual(score, 1.0)

  def test_wrong_expected_output(self):
    host_dir = 'testdata/executor/wrong_expected_output'
    code_path = 'testdata/executor/hello_world.cpp'
    expected_output_path = 'testdata/executor/empty.txt'
    with EphemeralDir(host_dir):
      build_script = executor.BuildScript(
        None,
        [['clang', '-std=c++11', '-Wall', '-Wextra', '-lstdc++',
          '-o', 'hello_world', 'hello_world.cpp']],
        ['hello_world'])
      test_case = executor.DiffTestCase(
        None, expected_output_path,
        [['/bin/bash', '-c', './hello_world > empty.txt']])
      c = executor.DockerExecutor('test_hello_world', host_dir)
      c.init()
      output, errors = c.build(code_path, build_script)
      self.assertEqual(errors, [])
      self.assertEqual(output, '')
      score, output, errors = c.test(test_case)
      self.assertEqual(output, '')
      self.assertNotEqual(errors, [])
      self.assertEqual(score, 0.0)

  def test_fork_bomb(self):
    host_dir = 'testdata/executor/fork_bomb'
    code_path = 'testdata/executor/fork_bomb.cpp'
    expected_output_path = 'testdata/executor/empty.txt'
    with EphemeralDir(host_dir):
      build_script = executor.BuildScript(
        None,
        [['clang', '-std=c++11', '-Wall', '-Wextra', '-lstdc++',
          '-o', 'fork_bomb', 'fork_bomb.cpp']],
        ['fork_bomb'])
      test_case = executor.DiffTestCase(
        None, expected_output_path,
        [['/bin/bash', '-c', './fork_bomb > empty.txt']])
      c = executor.DockerExecutor('test_fork_bomb', host_dir)
      c.init()
      output, errors = c.build(code_path, build_script)
      self.assertEqual(errors, [])
      self.assertEqual(output, '')
      # Set a short timeout since this fork_bomb won't do anything productive.
      c.timeout_seconds = 5
      score, output, errors = c.test(test_case)
      self.assertEqual(output, '')
      self.assertNotEqual(errors, [])
      self.assertEqual(score, 1.0)

  def test_many_open_files(self):
    host_dir = 'testdata/executor/many_open_files'
    code_path = 'testdata/executor/many_open_files.cpp'
    expected_output_path = 'testdata/executor/empty.txt'
    with EphemeralDir(host_dir):
      build_script = executor.BuildScript(
        None,
        [['clang', '-std=c++11', '-Wall', '-Wextra', '-lstdc++',
          '-o', 'many_open_files', 'many_open_files.cpp']],
        ['many_open_files'])
      test_case = executor.DiffTestCase(
        None, expected_output_path,
        [['/bin/bash', '-c', './many_open_files > empty.txt']])
      c = executor.DockerExecutor('test_many_open_files', host_dir)
      c.init()
      output, errors = c.build(code_path, build_script)
      self.assertEqual(errors, [])
      self.assertEqual(output, '')
      # Set a short timeout since many_open_files won't do anything productive.
      c.timeout_seconds = 5
      c.max_num_files = 1000
      score, output, errors = c.test(test_case)
      self.assertEqual(output, '')
      self.assertEqual(errors, [])
      self.assertEqual(score, 1.0)
      filenames = os.listdir(os.path.join(host_dir, 'grade_oven'))
      # Don't check for 999 since stdin, stdout, etc. count as files
      self.assertIn('990', filenames)
      self.assertNotIn('1001', filenames)

  def test_failed_build(self):
    host_dir = 'testdata/executor/failed_build'
    expected_output_path = 'testdata/executor/empty.txt'
    with EphemeralDir(host_dir):
      build_script = executor.BuildScript(
        None, [['echo', 'MIKEL'], ['false']], [])
      c = executor.DockerExecutor('test_failed_build', host_dir)
      c.init()
      output, errors = c.build(None, build_script)
      self.assertEqual(output, 'MIKEL\n')
      self.assertIn('Build command failed: false', errors)


if __name__ == '__main__':
  unittest.main()
