"""Module for holding business logic.

This is meant to hold business logic that is not specific to the presentation
of the data. For example, if a student submits code to a web frontend, the web
frontend would then call this library which will queue the submission and
ultimately update the datastore via data_model_lib.
"""
import collections
import logging
import threading
from typing import Iterable, Generic, Optional, List, Set, Text, TypeVar

import data_model_lib
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
               temp_dirs: ResourcePool[Resource]) -> None:
    super(GradeOvenSubmissionTask, self).__init__(priority, name, description)
    self._temp_dir = None
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
    logging.info(u'GradeOvenSubmissionTask._process_stage_output %s',
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
    self.student_submission.set_output(output.stage_name, output.stdout)
    errors = '\n'.join(output.errors)
    self.student_submission.set_errors(output.stage_name, errors)
    self.student_submission.set_status(u'running (finished {})'.format(
        output.stage_name))

  def before_run(self) -> None:
    logging.info(u'GradeOvenSubmissionTask.before_run %s', self.description)
    self.student_submission.set_status('setting up')
    t = self.temp_dirs.get()
    if t is None:
      raise RuntimeError('No temporary directories available.')
    else:
      self._temp_dir = t  # type: ignore

  def run(self) -> None:
    logging.info(u'GradeOvenSubmissionTask.run %s', self.description)
    self.container = executor.DockerExecutor(self.container_id, self._temp_dir)
    self.container.init()
    self.student_submission.set_status('running')
    username = self.student_submission.student_username
    user = self.grade_oven.user(username)
    env = {
        'GRADEOVEN_USERNAME': username,
        'GRADEOVEN_REAL_NAME': user.real_name(),
        'GRADEOVEN_DISPLAY_NAME': user.display_name(),
        'GRADEOVEN_COURSE_NAME': self.student_submission.course_name,
        'GRADEOVEN_ASSIGNMENT_NAME': self.student_submission.assignment_name,
    }
    for stage_output in self.container.run_stages(
        self.submission_dir, self.stages, env=env):
      self._process_stage_output(stage_output)
    self.outputs.append(stage_output.stdout)
    self.errors.extend(stage_output.errors)

  def after_run(self) -> None:
    logging.info(u'GradeOvenSubmissionTask.after_run %s', self.description)
    self.container.cleanup()
    self.temp_dirs.free(self._temp_dir)
    self.student_submission.set_status('finished')
