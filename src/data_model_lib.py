""" Classes to interact with a Grade Oven data_store.DataStore() instance.

DataStore schema:
courses[]
  students
  instructors
  assignments[]
    students[]
      stages[]
        score
    due_date
users[]
  hashed_password
admins
monitors
instructors

File system schema:
../data/files
  courses/<course_name>
    assignments/<assignment_name>
      stages
      submissions/<students>
"""

# TODO: Add logging statements, especially near exceptions.

import bcrypt
import executor
import itertools
import os
import six
import time
from typing import Iterable, IO, List, Optional, Text
import zipfile

from datastore import datastore as datastore_lib


class GradeOvenUser(object):
  "Represents a logged in user, needed for flask.ext.login.LoginManager"

  def __init__(self, data_store: datastore_lib.DataStore,
               username: Text) -> None:
    self.username = username
    self._data_store = data_store

  def check_password(self, password: Text) -> bool:
    try:
      hashed_password = self._data_store['users', self.username,
                                         'hashed_password']
    except KeyError:
      return False
    try:
      hashed_bytes = hashed_password.encode('utf-8')
      password_bytes = password.encode('utf-8')
    except UnicodeDecodeError:
      return False
    return bcrypt.checkpw(password_bytes, hashed_bytes)

  @classmethod
  def load_and_authenticate_user(cls, data_store: datastore_lib.DataStore,
                                 username: Text,
                                 password: Text) -> Optional["GradeOvenUser"]:
    user = cls(data_store, username)
    if user.check_password(password):
      user.set_is_authenticated(True)
      return user
    return None

  def set_password(self, password: Text) -> None:
    hpw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    self._data_store['users', self.username, 'hashed_password'] = hpw

  def has_password(self) -> bool:
    return self._data_store.get(
        ('users', self.username, 'hashed_password')) is not None

  def is_admin(self) -> bool:
    return ('admins', self.username) in self._data_store

  def set_is_admin(self, is_admin: bool) -> None:
    if is_admin:
      self._data_store.put(('admins', self.username))
    else:
      del self._data_store['admins', self.username]

  def is_monitor(self) -> bool:
    return ('monitors', self.username) in self._data_store or self.is_admin()

  def set_is_monitor(self, is_monitor: bool) -> None:
    if is_monitor:
      self._data_store.put(('monitors', self.username))
    else:
      del self._data_store['monitors', self.username]

  def set_instructs_course(self, course: Text, instructs_course: bool) -> None:
    if instructs_course:
      self._data_store.put(('courses', course, 'instructors', self.username))
    else:
      del self._data_store['courses', course, 'instructors', self.username]

  def instructs_course(self, course: Text) -> bool:
    return ('courses', course, 'instructors',
            self.username) in self._data_store

  def set_takes_course(self, course: Text, takes_course: bool) -> None:
    if takes_course:
      self._data_store.put(('courses', course, 'students', self.username))
    else:
      del self._data_store['courses', course, 'students', self.username]

  def takes_course(self, course: Text) -> bool:
    return ('courses', course, 'students', self.username) in self._data_store

  def is_authenticated(self) -> bool:
    return self._data_store.get(('users', self.username, 'is_authenticated'),
                                False)

  def set_is_authenticated(self, value: bool) -> None:
    self._data_store.put(('users', self.username, 'is_authenticated'),
                         bool(value))

  def is_active(self) -> bool:
    return self.is_authenticated()

  def is_anonymous(self) -> bool:
    return False

  def get_id(self) -> Text:
    return self.username

  def display_name(self) -> Text:
    return self._data_store.get(('users', self.username, 'display', 'name'),
                                self.username)

  def set_display_name(self, display_name: Text) -> None:
    return self._data_store.put(('users', self.username, 'display', 'name'),
                                display_name)

  def real_name(self) -> Text:
    return self._data_store.get(('users', self.username, 'real', 'name'),
                                self.username)

  def set_real_name(self, real_name: Text) -> None:
    return self._data_store.put(('users', self.username, 'real', 'name'),
                                real_name)

  def prefers_anonymity(self) -> bool:
    return bool(
        self._data_store.get(('users', self.username, 'prefers_anonymity'),
                             False))

  def set_prefers_anonymity(self, prefers_anonymity: bool) -> None:
    self._data_store.put(('users', self.username, 'prefers_anonymity'),
                         bool(prefers_anonymity))


class GradeOvenAssignment(object):
  def __init__(self, data_store: datastore_lib.DataStore, course_name: Text,
               assignment_name: Text) -> None:
    self.course_name = course_name
    self.name = assignment_name
    self._data_store = data_store

  def root_dir(self) -> Text:
    return os.path.join('../data/files/courses', self.course_name,
                        'assignments', self.name)

  def stages_dir(self) -> Text:
    return os.path.join(self.root_dir(), 'stages')

  def submissions_dir(self) -> Text:
    return os.path.join(self.root_dir(), 'submissions')

  def save_submissions_zip(self, file_obj: IO) -> None:
    with zipfile.ZipFile(file_obj, 'a') as zf:
      sub_root_dir = self.submissions_dir()
      for root, dirs, files in os.walk(sub_root_dir):
        if root != sub_root_dir:
          zf.write(root, root[len(sub_root_dir):])
        for basename in files:
          path = os.path.join(root, basename)
          zf.write(path, path[len(sub_root_dir):])

  def due_date(self) -> float:
    # float unix epoch (same format as time.time())
    return self._data_store.get(
        ('courses', self.course_name, 'assignments', self.name, 'due_date'),
        None)

  def set_due_date(self, due_date: float) -> None:
    # float unix epoch (same format as time.time())
    return self._data_store.put(
        ('courses', self.course_name, 'assignments', self.name, 'due_date'),
        due_date)

  def student_submission(
      self, student_username: Text) -> "GradeOvenStudentSubmission":
    return GradeOvenStudentSubmission(self._data_store, self.course_name,
                                      self.name, student_username)


class GradeOvenStudentSubmission(object):
  def __init__(self, data_store: datastore_lib.DataStore, course_name: Text,
               assignment_name: Text, student_username: Text) -> None:
    self.course_name = course_name
    self.assignment_name = assignment_name
    self.student_username = student_username
    self._data_store = data_store
    self.assignment = GradeOvenAssignment(self._data_store, course_name,
                                          assignment_name)
    self._student_user = None

  def student_user(self) -> GradeOvenUser:
    if self._student_user is None:
      self._student_user = GradeOvenUser(self._data_store, self.student_username)
    return self._student_user

  def clear_all_outputs(self):
    for stage_name in self.stage_names():
      self.set_output(stage_name, '')
      self.set_output_html(stage_name, '')
      self.set_errors(stage_name, '')

  def stage_names(self) -> List[Text]:
    return self._data_store.get_all(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'stages'))

  def score(self) -> int:
    return sum(
        int(
            self._data_store.get(('courses', self.course_name, 'assignments',
                                  self.assignment_name, 'students',
                                  self.student_username, 'stages', stage_name,
                                  'score'), 0) or 0)
        for stage_name in self.stage_names())

  def set_score(self, stage_name: Text, score: Optional[int]) -> None:
    if score is None:
      score = 0
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'stages', stage_name, 'score'),
        score)

  def past_due_date_score(self) -> int:
    return sum(
        int(
            self._data_store.get(('courses', self.course_name, 'assignments',
                                  self.assignment_name, 'students',
                                  self.student_username, 'stages', stage_name,
                                  'past_due_date_score'), 0) or 0)
        for stage_name in self.stage_names())

  def set_past_due_date_score(self, stage_name: Text,
                              past_due_date_score: Optional[int]) -> None:
    if past_due_date_score is None:
      past_due_date_score = 0
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'stages', stage_name,
         'past_due_date_score'), past_due_date_score)

  def set_manual_score_portion(self, manual_score: int) -> None:
    due_date = self.assignment.due_date()
    if not due_date or self.submit_time() <= due_date:
      self.set_score('__manual__', manual_score)
    else:
      self.set_past_due_date_score('__manual__', manual_score)

  def output_html(self) -> Text:
    return '\n'.join(
        filter(bool, (six.text_type(
            self._data_store.get(
                ('courses', self.course_name, 'assignments',
                 self.assignment_name, 'students', self.student_username,
                 'stages', stage_name, 'output_html'), ''))
                      for stage_name in self.stage_names())))

  def set_output_html(self, stage_name: Text, output_html: Text) -> None:
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'stages', stage_name,
         'output_html'), output_html)

  def output(self) -> Text:
    return '\n'.join(
        six.text_type(
            self._data_store.get(('courses', self.course_name, 'assignments',
                                  self.assignment_name, 'students',
                                  self.student_username, 'stages', stage_name,
                                  'output'), '') or '')
        for stage_name in self.stage_names())

  def set_output(self, stage_name: Text, output: Text) -> None:
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'stages', stage_name, 'output'),
        output)

  def errors(self) -> Text:
    return '\n'.join(
        six.text_type(
            self._data_store.get(('courses', self.course_name, 'assignments',
                                  self.assignment_name, 'students',
                                  self.student_username, 'stages', stage_name,
                                  'errors'), '') or '')
        for stage_name in self.stage_names())

  def set_errors(self, stage_name: Text, errors: Text) -> None:
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'stages', stage_name, 'errors'),
        errors)

  def status(self) -> Text:
    return str(
        self._data_store.get(
            ('courses', self.course_name, 'assignments', self.assignment_name,
             'students', self.student_username, 'status'), 'never run'))

  def set_status(self, status: Text):
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'status'), str(status))

  def submit_time(self) -> float:
    return float(
        self._data_store.get(
            ('courses', self.course_name, 'assignments', self.assignment_name,
             'students', self.student_username, 'submit_time'), 0.0))

  def set_submit_time(self) -> None:
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'submit_time'), float(time.time()))

  def num_submissions(self) -> int:
    return int(
        self._data_store.get(
            ('courses', self.course_name, 'assignments', self.assignment_name,
             'students', self.student_username, 'num_submissions'), 0))

  def set_num_submissions(self, num_submissions: int) -> None:
    self._data_store.put(
        ('courses', self.course_name, 'assignments', self.assignment_name,
         'students', self.student_username, 'num_submissions'),
        int(num_submissions))

  def save_submissions_zip(self, file_obj: IO) -> None:
    with zipfile.ZipFile(file_obj, 'a') as zf:
      submission_dir = os.path.join(self.assignment.submissions_dir(),
                                    self.student_username)
      for root, dirs, files in os.walk(submission_dir):
        if root != submission_dir:
          zf.write(root, root[len(submission_dir):])
        for basename in files:
          path = os.path.join(root, basename)
          zf.write(path, path[len(submission_dir):])


class GradeOvenCourse(object):
  "Represents a course"

  def __init__(self, data_store: datastore_lib.DataStore,
               course_name: Text) -> None:
    self.name = course_name
    self._data_store = data_store

  def student_usernames(self) -> List[Text]:
    return self._data_store.get_all(('courses', self.name, 'students'))

  def instructor_usernames(self) -> List[Text]:
    return self._data_store.get_all(('courses', self.name, 'instructors'))

  def assignment_names(self) -> List[Text]:
    return self._data_store.get_all(('courses', self.name, 'assignments'))

  def assignment(self, assignment_name: Text) -> GradeOvenAssignment:
    return GradeOvenAssignment(self._data_store, self.name, assignment_name)

  def add_assignment(self, assignment_name: Text) -> None:
    self._data_store.put(('courses', self.name, 'assignments',
                          assignment_name))

  def add_assignment_from_zip(self, file_obj: IO, stages_name: Text,
                              stages_root: Text) -> None:
    stages = executor.Stages.from_zip(file_obj, stages_name, stages_root)
    self.add_assignment(stages.name)

  def add_students(self, student_usernames: Iterable[Text]) -> None:
    for username in student_usernames:
      self._data_store.put(('courses', self.name, 'students', username))

  def remove_students(self, student_usernames: Iterable[Text]) -> None:
    for username in student_usernames:
      self._data_store.remove(('courses', self.name, 'students', username))


class GradeOven(object):
  def __init__(self, data_store: datastore_lib.DataStore) -> None:
    self._data_store = data_store

  def course_names(self) -> List[Text]:
    return self._data_store.get_all(('courses', ))

  def user(self, username: Text) -> GradeOvenUser:
    return GradeOvenUser(self._data_store, username)

  def course(self, course_name: Text) -> GradeOvenCourse:
    return GradeOvenCourse(self._data_store, course_name)

  def assignment(self, course_name: Text,
                 assignment_name: Text) -> GradeOvenAssignment:
    return GradeOvenAssignment(self._data_store, course_name, assignment_name)
