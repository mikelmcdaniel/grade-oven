import bcrypt
import executor
import os
import time
""" Classes to interact with a Grade Oven data_store.DataStore() instance.

DataStore schema:
courses[]
  students
  instructors
  assignments[]
    students[]
      stages[]
        score
        total
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

class GradeOvenUser(object):
  "Represents a logged in user, needed for flask.ext.login.LoginManager"
  def __init__(self, data_store, username):
    self.username = username
    self._data_store = data_store

  def check_password(self, password):
    try:
      hashed_password = self._data_store['users', self.username, 'hashed_password']
    except KeyError:
      return False
    try:
      return bcrypt.checkpw(password, hashed_password)
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
    hpw = bcrypt.hashpw(password, bcrypt.gensalt())
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

  def avatar_name(self):
    return self._data_store.get(('users', self.username, 'avatar', 'name'), self.username)

  def set_avatar_name(self, avatar_name):
    return self._data_store.put(('users', self.username, 'avatar', 'name'), avatar_name)


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

  def student_submission(self, student_username):
    return GradeOvenStudentSubmission(self._data_store, self.course_name,
                                      self.name, student_username)


class GradeOvenStudentSubmission(object):
  def __init__(self, data_store, course_name, assignment_name, student_username):
    self.course_name = course_name
    self.assignment_name = assignment_name
    self.student_username = student_username
    self._data_store = data_store

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

  def total(self):
    return sum(int(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'total'), 0) or 0)
                   for stage_name in self.stage_names())

  def set_total(self, stage_name, total):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'total'), total)

  def output(self):
    return '\n'.join(str(self._data_store.get(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'output'), '') or '')
                   for stage_name in self.stage_names())

  def set_output(self, stage_name, output):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.assignment_name,
       'students', self.student_username, 'stages', stage_name, 'output'), output)

  def errors(self):
    return '\n'.join(str(self._data_store.get(
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
