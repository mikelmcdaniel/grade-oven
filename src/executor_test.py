# -*- coding: utf-8 -*-
import cStringIO
import errno
import executor
import os
import re
import shutil
import unittest
import zipfile


class EphemeralDir(object):
  def __init__(self, path):
    self.path = path

  def __enter__(self):
    shutil.rmtree(self.path, ignore_errors=True)
    try:
      os.makedirs(self.path)
    except OSError as e:
      if e.errno != errno.EEXIST:
        raise e

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

  def test_unicode_in_env(self):
    host_dir = 'testdata/executor/HOST_DIR/hello_world'
    stages_dir = 'testdata/executor/hello_world'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_unicode_in_env', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      env = {
        'DECODED': u'┻━┻ ︵﻿ ¯\(ツ)/¯ ︵ ┻━┻',
        'ENCODED': '┻━┻ ︵﻿ ¯\(ツ)/¯ ︵ ┻━┻',
      }
      output, errors = c.run_stages(code_path, stages, env=env)
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
      self.assertEqual(output.strip(), '')

  def test_evil_cpp(self):
    host_dir = 'testdata/executor/HOST_DIR/evil'
    stages_dir = 'testdata/executor/evil'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_evil', host_dir)
      c.init()
      c.timeout_seconds = 5
      stages = executor.Stages(stages_dir)
      output, errors = c.run_stages(code_path, stages)
      self.assertEqual(stages.stages['fork_bomb'].output.errors, [
        'Command "/grade_oven/fork_bomb/main" did not finish in '
        '5 seconds and timed out.'])
      self.assertEqual(
        stages.stages['many_open_files'].output.stdout, 'many_open_files\n')
      self.assertEqual(
        stages.stages['much_ram'].output.stdout, 'much_ram\n')

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

  def test_big_output(self):
    host_dir = 'testdata/executor/HOST_DIR/big_output'
    stages_dir = 'testdata/executor/big_output'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_big_output', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      output, errors = c.run_stages(code_path, stages)
      self.assertEqual(errors, [])
      stage_output = stages.stages['make_output'].output.stdout
      self.assertGreaterEqual(len(stage_output), 128 * 1024)  # >= than 128KB output
      self.assertLessEqual(len(stage_output), 132 * 1024)  # <= than 128KB + 4KB output

  def test_save_zip(self):
    # use the "evil" test case because it has multiple stages
    stages_dir = 'testdata/executor/evil'
    stages = executor.Stages(stages_dir)
    fake_file = cStringIO.StringIO()
    stages.save_zip(fake_file)
    expected_files = [
      'metadata.json',
      'fork_bomb/', 'fork_bomb/fork_bomb.cpp', 'fork_bomb/main',
      'many_open_files/', 'many_open_files/main',
      'many_open_files/many_open_files.cpp',
      'much_ram/', 'much_ram/much_ram.cpp', 'much_ram/main']
    with zipfile.ZipFile(fake_file, 'r') as zf:
      self.assertEqual(sorted(zf.namelist()), sorted(expected_files))

  def test_from_zip(self):
    # use the "evil" test case because it has multiple stages
    host_dir = 'testdata/executor/HOST_DIR'
    stages_dir = 'testdata/executor/evil'
    fake_file = cStringIO.StringIO()
    executor.Stages(stages_dir).save_zip(fake_file)
    stages = executor.Stages.from_zip(fake_file, 'test_from_zip', host_dir)
    fake_file2 = cStringIO.StringIO()
    executor.Stages(host_dir + '/test_from_zip').save_zip(fake_file2)
    shutil.rmtree(host_dir + '/test_from_zip')

    with zipfile.ZipFile(fake_file, 'r') as zf:
      with zipfile.ZipFile(fake_file2, 'r') as zf2:
        self.assertEqual(sorted(zf.namelist()), sorted(zf2.namelist()))

  def test_untrusted(self):
    host_dir = 'testdata/executor/HOST_DIR/untrusted'
    stages_dir = 'testdata/executor/untrusted'
    code_path = None
    score_map = {}
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_unptrusted', host_dir)
      c.init()
      output, errors = c.run_stages(
        code_path,
        executor.Stages(stages_dir),
        lambda stage: score_map.update({stage.name: stage.output.score}))
      self.assertEqual(errors, [])
      self.assertEqual(output.strip(), '')
      self.assertEqual(score_map, {'trusted': 123, 'untrusted': None})


if __name__ == '__main__':
  unittest.main()
