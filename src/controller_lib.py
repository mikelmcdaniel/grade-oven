"""Module for holding business logic.

This is meant to hold business logic that is not specific to the presentation
of the data. For example, if a student submits code to a web frontend, the web
frontend would then call this library which will queue the submission and
ultimately update the datastore via data_model_lib.
"""
import collections
import errno
import logging
import os
import shutil
import threading
import time
from typing import Iterable, Generic, Optional, List, Set, Text, TypeVar

import werkzeug

import data_model_lib
import escape_lib
import executor
import executor_queue_lib

Resource = TypeVar('Resource')


class ResourcePool(Generic[Resource]):
  def __init__(self, resources: Iterable[Resource]) -> None:
    self._free_resources = collections.deque(resources)
    self._used_resources = set()  # type: Set[Resource]
    self._resources_lock = threading.Lock()

    if len(self._free_resources) != len(set(self._free_resources)):
      raise ValueError(
          'resources argument to ResourcePool includes non-unique elements.')

  def get(self) -> Optional[Resource]:
    with self._resources_lock:
      try:
        resource = self._free_resources.popleft()
      except IndexError:
        return None
      self._used_resources.add(resource)
      return resource

  def free(self, resource: Resource) -> None:
    with self._resources_lock:
      self._used_resources.remove(resource)
      self._free_resources.append(resource)

  def __len__(self) -> int:
    return len(self._free_resources)


class GradeOvenSubmissionTask(executor_queue_lib.ExecutorQueueTask):
  def __init__(self, priority, name: Text, description: Text,
               submission_dir: Text, container_id: Text,
               stages: executor.Stages,
               student_submission: data_model_lib.GradeOvenStudentSubmission,
               grade_oven: data_model_lib.GradeOven,
               temp_dirs: ResourcePool[Text]) -> None:
    super(GradeOvenSubmissionTask, self).__init__(priority, name, description)
    self._temp_dir = None  # type: Optional[Text]
    self.submission_dir = submission_dir
    self.container_id = container_id
    self.stages = stages
    self.student_submission = student_submission
    self.grade_oven = grade_oven
    self.temp_dirs = temp_dirs
    self.container = None  # type: Optional[executor.DockerExecutor]
    self.outputs = []  # type: List[Text]
    self.errors = []  # type: List[Text]

  def _process_stage_output(self, output: executor.StageOutput) -> None:
    logging.info('GradeOvenSubmissionTask._process_stage_output %s',
                 output.stage_name)
    if self.student_submission.assignment.due_date() is None or (
        self.student_submission.submit_time() <=
        self.student_submission.assignment.due_date()):
      self.student_submission.set_score(output.stage_name, output.score)
    else:
      self.student_submission.set_past_due_date_score(output.stage_name,
                                                      output.score)
    self.student_submission.set_output_html(output.stage_name,
                                            output.output_html)
    self.student_submission.set_output(output.stage_name, output.stdout or '')
    errors = '\n'.join(output.errors or '')
    self.student_submission.set_errors(output.stage_name, errors)
    self.student_submission.set_status('running (finished {})'.format(
        output.stage_name))

  def before_run(self) -> None:
    logging.info('GradeOvenSubmissionTask.before_run %s', self.description)
    self.student_submission.set_status('setting up')
    t = self.temp_dirs.get()
    if t is None:
      raise RuntimeError('No temporary directories available.')
    else:
      self._temp_dir = t

  def run(self) -> None:
    logging.info('GradeOvenSubmissionTask.run %s', self.description)
    assert self._temp_dir is not None
    self.container = executor.DockerExecutor(self.container_id, self._temp_dir)
    self.container.init()
    self.student_submission.set_status('running')
    username = self.student_submission.student_username
    user = self.grade_oven.user(username)
    env = {
        'GRADEOVEN_USERNAME': username
    }
    for stage_output in self.container.run_stages(
        self.submission_dir, self.stages, env=env):
      self._process_stage_output(stage_output)
      if stage_output.stdout is not None:
        self.outputs.append(stage_output.stdout)
      if stage_output.errors is not None:
        self.errors.extend(stage_output.errors)

  def after_run(self) -> None:
    logging.info('GradeOvenSubmissionTask.after_run %s', self.description)
    assert self.container is not None
    self.container.cleanup()
    assert self._temp_dir is not None
    self.temp_dirs.free(self._temp_dir)
    self.student_submission.set_status('finished')


def save_files_in_dir(flask_files: List[werkzeug.datastructures.FileStorage],
                      dir_path) -> List[Text]:
  errors = []
  try:
    os.makedirs(dir_path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise e
  for f in flask_files:
    base_filename = os.path.basename(f.filename or 'file')
    if base_filename:
      if escape_lib.is_safe_entity_name(base_filename):
        f.save(os.path.join(dir_path, base_filename))
      else:
        safe_base_filename = escape_lib.safe_entity_name(base_filename)
        errors.append(
            'Filename "{}" is unsafe.  File saved as "{}" instead.'.format(
                base_filename, safe_base_filename))
        logging.warning(errors[-1])
        f.save(os.path.join(dir_path, safe_base_filename))
  return errors


def _enqueue_student_submission(
    course_name: Text,
    assignment_name: Text,
    username: Text,
    grade_oven: data_model_lib.GradeOven,
    executor_queue: executor_queue_lib.ExecutorQueue,
    temp_dirs: ResourcePool[Text],
    files: Optional[List[werkzeug.datastructures.FileStorage]] = None
) -> List[Text]:
  errors = []
  user = grade_oven.user(username)
  course = grade_oven.course(course_name)
  assignment = course.assignment(assignment_name)
  student_submission = assignment.student_submission(username)
  # If this is a resubmission, but there's no original submission, skip it.
  # if student_submission.num_submissions() == 0 and not files:
  #   return
  logging.info('Student "%s" is attempting assignment "%s/%s".', username,
               course_name, assignment_name)
  submission_dir = os.path.join('../data/files/courses', course_name,
                                'assignments', assignment_name, 'submissions',
                                username)
  desc = '{}_{}_{}'.format(course_name, assignment_name, username)
  # TODO: Fix the quick hack below.  It is only in place to avoid "escaped"
  # names that are not safe docker container names.
  container_id = str(abs(hash(desc)))[:32]
  num_submissions = student_submission.num_submissions()
  submit_time = student_submission.submit_time() or 0
  cur_time = time.time()
  min_seconds_since_last_submission = min(num_submissions**3, 5.0)
  priority = (num_submissions, submit_time)
  stages = executor.Stages(
      os.path.join('../data/files/courses', course_name, 'assignments',
                   assignment_name))
  submission = GradeOvenSubmissionTask(
      priority, username, desc, submission_dir, container_id, stages,
      student_submission, grade_oven, temp_dirs)
  if submission in executor_queue:
    logging.warning(
        'Student "%s" submited assignment "%s/%s" while still in the queue.',
        username, course_name, assignment_name)
    errors.append(
        '{} cannot submit assignment {} for {} while in the queue.'.format(
            username, assignment_name, course_name))
  elif cur_time < submit_time + min_seconds_since_last_submission:
    seconds_left = min_seconds_since_last_submission - (cur_time - submit_time)
    formatted_time = time.strftime(
        '%Y-%m-%d %H:%M:%S',
        time.localtime(submit_time + min_seconds_since_last_submission))
    logging.info('Student "%s" submitted assignment "%s/%s" '
                 'but needs to wait until %s (%s seconds).', username,
                 course_name, assignment_name, formatted_time, seconds_left)
    errors.append(
        'Please wait until {} ({:.0f} seconds) to submit {} again.'.format(
            formatted_time, seconds_left, assignment_name))
  else:
    if files:
      try:
        shutil.rmtree(submission_dir)
      except OSError as e:
        if e.errno != errno.ENOENT:
          raise e
      save_files_in_dir(files, submission_dir)
      # If there are no files being uploaded, then this must be a resubmission.
      student_submission.set_submit_time()
      student_submission.set_num_submissions(
          student_submission.num_submissions() + 1)
    student_submission.set_status('queued')
    executor_queue.enqueue(submission)
  return errors
