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
import time
import zipfile

class GradeOvenUser(object):
  "Represents a logged in user, needed for flask.ext.login.LoginManager"
  def __init__(self, data_store, username):
    self.username = username
    self._data_store = data_store

  def check_password(self, password):
    password = password.encode('utf-8')
    try:
      hashed_password = self._data_store[
        'users', self.username, 'hashed_password']
    except KeyError:
      return False
    try:
      hashed_password = hashed_password.encode('utf-8')
      return hashed_password == bcrypt.hashpw(password, hashed_password)
    except (ValueError, TypeError) as e:
      return False

  @classmethod
  def load_and_authenticate_user(cls, data_store, username, password):
    user = cls(data_store, username)
    if user.check_password(password):
      user.set_is_authenticated(True)
      return user
    return None

  def set_password(self, password):
    hpw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    self._data_store['users', self.username, 'hashed_password'] = hpw

  def has_password(self):
    return self._data_store.get(('users', self.username, 'hashed_password')) is not None

  def is_admin(self):
    return ('admins', self.username) in self._data_store

  def set_is_admin(self, is_admin):
    if is_admin:
      self._data_store.put(('admins', self.username))
    else:
      del self._data_store['admins', self.username]

  def is_monitor(self):
    return ('monitors', self.username) in self._data_store or self.is_admin()

  def set_is_monitor(self, is_monitor):
    if is_monitor:
      self._data_store.put(('monitors', self.username))
    else:
      del self._data_store['monitors', self.username]

  def is_instructor(self):
    return ('instructors', self.username) in self._data_store

  def set_is_instructor(self, is_instructor):
    if is_instructor:
      self._data_store.put(('instructors', self.username))
    else:
      del self._data_store['instructors', self.username]

  def is_instructor(self):
    return ('instructors', self.username) in self._data_store

  def set_instructs_course(self, course, instructs_course):
    if instructs_course:
      self._data_store.put(('courses', course, 'instructors', self.username))
    else:
      del self._data_store['courses', course, 'instructors', self.username]

  def instructs_course(self, course):
    return ('courses', course, 'instructors', self.username) in self._data_store

  def set_takes_course(self, course, takes_course):
    if takes_course:
      self._data_store.put(('courses', course, 'students', self.username))
    else:
      del self._data_store['courses', course, 'students', self.username]

  def takes_course(self, course):
    return ('courses', course, 'students', self.username) in self._data_store

  def is_authenticated(self):
    return self._data_store.get(('users', self.username, 'is_authenticated'), False)

  def set_is_authenticated(self, value):
    self._data_store.put(('users', self.username, 'is_authenticated'), bool(value))

  def is_active(self):
    return self.is_authenticated()

  def is_anonymous(self):
    return False

  def get_id(self):
    return self.username

  def display_name(self):
    return self._data_store.get(('users', self.username, 'display', 'name'), self.username)

  def set_display_name(self, display_name):
    return self._data_store.put(('users', self.username, 'display', 'name'), display_name)

  def real_name(self):
    return self._data_store.get(('users', self.username, 'real', 'name'), self.username)

  def set_real_name(self, real_name):
    return self._data_store.put(('users', self.username, 'real', 'name'), real_name)

  def prefers_anonymity(self):
    return bool(self._data_store.get(
      ('users', self.username, 'prefers_anonymity'), False))

  def set_prefers_anonymity(self, prefers_anonymity):
    return self._data_store.put(('users', self.username, 'prefers_anonymity'),
                                bool(prefers_anonymity))


class GradeOvenAssignment(object):
  def __init__(self, data_store, course_name, assignment_name):
    self.course_name = course_name
    self.name = assignment_name
    self._data_store = data_store

  def root_dir(self):
    return os.path.join(
      '../data/files/courses', self.course_name, 'assignments', self.name)

  def stages_dir(self):
    return os.path.join(self.root_dir(), 'stages')

  def submissions_dir(self):
    return os.path.join(self.root_dir(), 'submissions')

  def save_submissions_zip(self, file_obj):
    with zipfile.ZipFile(file_obj, 'a') as zf:
      sub_root_dir = self.submissions_dir()
      for root, dirs, files in os.walk(sub_root_dir):
        if root != sub_root_dir:
          zf.write(root, root[len(sub_root_dir):])
        for basename in files:
          path = os.path.join(root, basename)
          zf.write(path, path[len(sub_root_dir):])

  def due_date(self):
    # float unix epoch (same format as time.time())
    return self._data_store.get(
      ('courses', self.course_name, 'assignments', self.name, 'due_date'), None)

  def set_due_date(self, due_date):
    # float unix epoch (same format as time.time())
    return self._data_store.put(
      ('courses', self.course_name, 'assignments', self.name, 'due_date'),
      due_date)

  def student_submission(self, student_username):
    return GradeOvenStudentSubmission(self._data_store, self.course_name,
                                      self.name, student_username)


class GradeOvenStudentSubmission(object):
  def __init__(self, data_store, course_name, assignment_name, student_username):
    self.course_name = course_name
    self.assignment_name = assignment_name
    self.student_username = student_username
    self._data_store = data_store
    self.assignment = GradeOvenAssignment(
      self._data_store, course_name, assignment_name)


  def stage_names(self):
    return self._data_store.get_all(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages'))

  def score(self):
    return sum(int(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'score'), 0) or 0)
                   for stage_name in self.stage_names())

  def set_score(self, stage_name, score):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'score'), score)

  def __past_due_date_score(self):
    return sum(int(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'past_due_date_score'), 0) or 0)
                   for stage_name in self.stage_names())

  def past_due_date_score(self):
    return max(self.__past_due_date_score(), self.score())

  def set_past_due_date_score(self, stage_name, past_due_date_score):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'past_due_date_score'),
      past_due_date_score)

  def output_html(self):
    return '\n'.join(itertools.ifilter(bool, (unicode(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'output_html'), ''))
                   for stage_name in self.stage_names())))

  def set_output_html(self, stage_name, output_html):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'output_html'), output_html)

  def output(self):
    return '\n'.join(unicode(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'output'), '') or '')
                   for stage_name in self.stage_names())

  def set_output(self, stage_name, output):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'output'), output)

  def errors(self):
    return '\n'.join(unicode(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'errors'), '') or '')
                   for stage_name in self.stage_names())

  def set_errors(self, stage_name, errors):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'errors'), errors)

  def status(self):
    return str(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'status'), 'never run'))

  def set_status(self, status):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'status'), str(status))

  def submit_time(self):
    return float(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'submit_time'), 0.0))

  def set_submit_time(self, submit_time=None):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'submit_time'), float(time.time()))

  def num_submissions(self):
    return int(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'num_submissions'), 0))

  def set_num_submissions(self, num_submissions):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'num_submissions'), int(num_submissions))

  def save_submissions_zip(self, file_obj):
    with zipfile.ZipFile(file_obj, 'a') as zf:
      submission_dir = os.path.join(
        self.assignment.submissions_dir(), self.student_username)
      for root, dirs, files in os.walk(submission_dir):
        if root != submission_dir:
          zf.write(root, root[len(submission_dir):])
        for basename in files:
          path = os.path.join(root, basename)
          zf.write(path, path[len(submission_dir):])


class GradeOvenCourse(object):
  "Represents a course"
  def __init__(self, data_store, course_name):
    self.name = course_name
    self._data_store = data_store

  def student_usernames(self):
    return self._data_store.get_all(('courses', self.name, 'students'))

  def instructor_usernames(self):
    return self._data_store.get_all(('courses', self.name, 'instructors'))

  def assignment_names(self):
    return self._data_store.get_all(('courses', self.name, 'assignments'))

  def assignment(self, assignment_name):
    return GradeOvenAssignment(self._data_store, self.name, assignment_name)

  def add_assignment(self, assignment_name):
    self._data_store.put(('courses', self.name, 'assignments', assignment_name))

  def add_assignment_from_zip(self, file_obj, stages_name, stages_root):
    stages = executor.Stages.from_zip(file_obj, stages_name, stages_root)
    self.add_assignment(stages.name)

  def add_students(self, student_usernames):
    for username in student_usernames:
      self._data_store.put(('courses', self.name, 'students', username))

  def remove_students(self, student_usernames):
    for username in student_usernames:
      self._data_store.remove(('courses', self.name, 'students', username))


class GradeOven(object):
  def __init__(self, data_store):
    self._data_store = data_store

  def course_names(self):
    return self._data_store.get_all(('courses',))

  def user(self, username):
    return GradeOvenUser(self._data_store, username)

  def course(self, course_name):
    return GradeOvenCourse(self._data_store, course_name)

  def assignment(self, course_name, assignment_name):
    return GradeOvenAssignment(self._data_store, course_name, assignment_name)
