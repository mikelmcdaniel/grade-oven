import os
import unittest
import executor
import shutil
import re


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
    host_dir = 'testdata/executor/HOST_DIR/hello_world'
    stages_dir = 'testdata/executor/hello_world'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_hello_world', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      output, errors = c.run_stages(code_path, stages)
      self.assertEqual(errors, [])
      self.assertEqual(stages.stages['stage0'].output.stdout, 'HELLO WORLD\n')

  def test_hello_world_cpp(self):
    host_dir = 'testdata/executor/HOST_DIR/hello_world_cpp'
    stages_dir = 'testdata/executor/hello_world_cpp'
    code_path = 'testdata/executor/hello_world_cpp/code/hello_world.cpp'
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_hello_world_cpp', host_dir)
      c.init()
      output, errors = c.run_stages(code_path, executor.Stages(stages_dir))
      self.assertEqual(errors, [])
      self.assertEqual(output, '')

  def test_evil_cpp(self):
    host_dir = 'testdata/executor/HOST_DIR/evil'
    stages_dir = 'testdata/executor/evil'
    code_path = None
    bash_sub_cmd_killed_re = re.compile(
      '/grade_oven/[^/]+/main: line \d+:\s+\d+ Killed\s+./[a-z_]+\n')
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_evil', host_dir)
      c.init()
      c.timeout_seconds = 5
      stages = executor.Stages(stages_dir)
      output, errors = c.run_stages(code_path, stages)
      self.assertEqual(stages.stages['fork_bomb'].output.errors, [
        'Command "/grade_oven/fork_bomb/main" did not finish in '
        '5 seconds and timed out.'])
      self.assertTrue(re.match(bash_sub_cmd_killed_re,
                               stages.stages['many_open_files'].output.stdout))
      self.assertTrue(re.match(bash_sub_cmd_killed_re,
                               stages.stages['much_ram'].output.stdout))

  def test_hello_world_cpp(self):
    host_dir = 'testdata/executor/HOST_DIR/score'
    stages_dir = 'testdata/executor/score'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_score', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      output, errors = c.run_stages(code_path, stages)
      self.assertEqual(errors, [])
      self.assertEqual(output.strip(), '')
      self.assertIn('score', stages.stages)
      self.assertEqual(stages.stages['score'].output.score, 12345)
      self.assertEqual(stages.stages['score'].output.total, 67890)


if __name__ == '__main__':
  unittest.main()
