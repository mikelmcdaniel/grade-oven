# -*- coding: utf-8 -*-
import errno
import executor
import io
import os
import re
import shutil
import six
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
      outputs = {}
      for stage_output in c.run_stages(code_path, stages):
        outputs[stage_output.stage_name] = stage_output
        self.assertEqual(stage_output.errors, [])
      self.assertEqual(outputs['stage0'].stdout, 'HELLO WORLD\n')

  def test_unicode_in_env(self):
    host_dir = 'testdata/executor/HOST_DIR/unicode_in_env'
    stages_dir = 'testdata/executor/unicode_in_env'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_unicode_in_env', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      env = {
          'test': '🤬',
          'thumbs_up': '👍🏾👍🏿👍🏻👍🏼👍🏽',
      }
      outputs = {}
      for stage_output in c.run_stages(code_path, stages, env=env):
        outputs[stage_output.stage_name] = stage_output
        self.assertEqual(stage_output.errors, [])
      self.assertIn('test=🤬\n', outputs['print_env'].stdout)
      self.assertIn('thumbs_up=👍🏾👍🏿👍🏻👍🏼👍🏽\n', outputs['print_env'].stdout)

  def test_hello_world_cpp(self):
    host_dir = 'testdata/executor/HOST_DIR/hello_world_cpp'
    stages_dir = 'testdata/executor/hello_world_cpp'
    code_path = 'testdata/executor/hello_world_cpp/code/hello_world.cpp'
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_hello_world_cpp', host_dir)
      c.init()
      for stage_output in c.run_stages(code_path, executor.Stages(stages_dir)):
        self.assertEqual(stage_output.errors, [])
        self.assertEqual(stage_output.stdout.strip(), '')

  def test_evil_cpp(self):
    host_dir = 'testdata/executor/HOST_DIR/evil'
    stages_dir = 'testdata/executor/evil'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_evil', host_dir)
      c.init()
      c.timeout_seconds = 5
      c.max_num_files = 100
      c.max_mem_bytes = 64 * 1024**2
      stages = executor.Stages(stages_dir)
      outputs = {}
      for stage_output in c.run_stages(code_path, stages):
        outputs[stage_output.stage_name] = stage_output
      self.assertEqual(outputs['fork_bomb'].errors, [])
      self.assertEqual(outputs['sleep'].errors, [
          'Command "/grade_oven/sleep/main" did not finish in '
          '5 seconds and timed out.'
      ])
      self.assertIn('many_open_files: 80 files open',
                    outputs['many_open_files'].stdout)
      self.assertNotIn('many_open_files: 120 files open',
                       outputs['many_open_files'].stdout)
      self.assertIn('much_ram: Allocated 48MB.', outputs['much_ram'].stdout)
      self.assertNotIn('much_ram: Allocated 64MB.', outputs['much_ram'].stdout)

  def test_score(self):
    host_dir = 'testdata/executor/HOST_DIR/score'
    stages_dir = 'testdata/executor/score'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_score', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      outputs = {}
      for stage_output in c.run_stages(code_path, stages):
        outputs[stage_output.stage_name] = stage_output
        self.assertEqual(stage_output.errors, [])
        self.assertEqual(stage_output.stdout.strip(), '')
      self.assertIn('score', stages.stages)
      self.assertEqual(outputs['score'].score, 12345)

  def test_big_output(self):
    host_dir = 'testdata/executor/HOST_DIR/big_output'
    stages_dir = 'testdata/executor/big_output'
    code_path = None
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_big_output', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      for stage_output in c.run_stages(code_path, stages):
        self.assertEqual(stage_output.errors, [])
        stdout = stage_output.stdout
        # >= than 128KB output
        self.assertGreaterEqual(len(stdout), 128 * 1024)
        # <= than 128KB + 4KB output
        self.assertLessEqual(len(stdout), 132 * 1024)

  def test_save_zip(self):
    # use the "evil" test case because it has multiple stages
    stages_dir = 'testdata/executor/evil'
    stages = executor.Stages(stages_dir)
    fake_file = six.BytesIO()
    stages.save_zip(fake_file)
    expected_files = [
        'metadata.json', 'fork_bomb/', 'fork_bomb/fork_bomb.cpp',
        'fork_bomb/main', 'many_open_files/', 'many_open_files/main',
        'many_open_files/many_open_files.cpp', 'much_ram/',
        'much_ram/much_ram.cpp', 'much_ram/main'
    ]
    with zipfile.ZipFile(fake_file, 'r') as zf:
      self.assertEqual(sorted(zf.namelist()), sorted(expected_files))

  def test_from_zip(self):
    # use the "evil" test case because it has multiple stages
    host_dir = 'testdata/executor/HOST_DIR'
    stages_dir = 'testdata/executor/evil'
    fake_file = six.BytesIO()
    executor.Stages(stages_dir).save_zip(fake_file)
    stages = executor.Stages.from_zip(fake_file, 'test_from_zip', host_dir)
    fake_file2 = six.BytesIO()
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
      c = executor.DockerExecutor('test_untrusted', host_dir)
      c.init()
      for stage_output in c.run_stages(code_path, executor.Stages(stages_dir)):
        score_map.update({stage_output.stage_name: stage_output.score})
        self.assertEqual(stage_output.errors, [])
        self.assertEqual(stage_output.stdout.strip(), '')
      self.assertEqual(score_map, {'trusted': 123, 'untrusted': None})

  def test_save_and_remove_file(self):
    host_dir = 'testdata/executor/HOST_DIR/save_and_remove_files'
    stages_dir = 'testdata/executor/hello_world'
    code_path = None
    score_map = {}
    with EphemeralDir(host_dir):
      shutil.rmtree(host_dir)
      shutil.copytree(stages_dir, host_dir)
      stages = executor.Stages(host_dir)
      stage = stages.stages['stage0']
      # Test Stage.save_file
      fake_file = io.BytesIO(b'test_save_file contents')
      stage.save_file('ignored/path/test_save_file.txt', fake_file)
      test_file_path = os.path.join(stage.path, 'test_save_file.txt')
      with open(test_file_path) as f:
        contents = f.read()
      self.assertEqual(contents, 'test_save_file contents')
      # Test Stage.remove_file
      self.assertTrue(os.path.exists(test_file_path))
      stage.remove_file('ignored/path/test_save_file.txt')
      self.assertFalse(os.path.exists(test_file_path))

  def test_add_and_remove_stage(self):
    host_dir = 'testdata/executor/HOST_DIR/add_and_remove_stage'
    stages_dir = 'testdata/executor/hello_world'
    code_path = None
    score_map = {}
    with EphemeralDir(host_dir):
      shutil.rmtree(host_dir)
      shutil.copytree(stages_dir, host_dir)
      # Add the stage
      stages = executor.Stages(host_dir)
      new_stage = stages.add_stage('new_stage_test')
      self.assertEqual(new_stage, stages.stages['new_stage_test'])
      self.assertEqual(new_stage.description, '')
      new_stage.save_description('test description')
      self.assertEqual(new_stage.description, 'test description')
      del stages
      del new_stage

      # Load the stage and make sure the changes were persisted.
      stages2 = executor.Stages(host_dir)
      new_stage2 = stages2.stages['new_stage_test']
      new_stage2_path = new_stage2.path
      self.assertEqual(new_stage2.description, 'test description')
      del new_stage2

      # Remove the stage.
      self.assertTrue(os.path.isdir(new_stage2_path))
      stages2.remove_stage('new_stage_test')
      self.assertFalse(os.path.isdir(new_stage2_path))
      del stages2

      # Make sure the stage was removed (by reloading).
      stages3 = executor.Stages(host_dir)
      with self.assertRaises(KeyError):
        stages3.stages['new_stage_test']

  def test_run_stages_error(self):
    host_dir = 'testdata/executor/HOST_DIR/run_stages_error'
    stages_dir = 'testdata/executor/hello_world'
    code_path = 'testdata/executor/HOST_DIR/DOES_NOT_EXIST'
    with EphemeralDir(host_dir):
      c = executor.DockerExecutor('test_run_stages_error', host_dir)
      c.init()
      stages = executor.Stages(stages_dir)
      with self.assertRaises(executor.Error):
        for stage_output in c.run_stages(code_path, stages):
          pass


if __name__ == '__main__':
  unittest.main()
