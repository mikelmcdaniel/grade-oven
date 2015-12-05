import executor
import os
import bcrypt
""" Classes to interact with a Grade Oven data_store.DataStore() instance.

DataStore schema:
courses[]
  students
  instructors
  assignments[]
    students[]
      score
    due_date
    build_script
    test_case
users[]
  hashed_password
admins
instructors
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

  def is_admin(self):
    return ('admins', self.username) in self._data_store

  def set_is_admin(self, is_admin):
    if is_admin:
      self._data_store.put(('admins', self.username))
    else:
      del self._data_store['admins', self.username]

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


class GradeOvenAssignment(object):
  def __init__(self, data_store, course_name, assignment_name):
    self.course_name = course_name
    self.name = assignment_name
    self._data_store = data_store

  def description(self):
    return self._data_store.get(
      ('courses', self.course_name, 'assignments', self.name, 'description'),
      self.name)

  def set_description(self, assignment_desc):
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.name, 'description'),
      assignment_desc)

  def get_build_script(self):
    serialized = self._data_store.get(
      ('courses', self.course_name, 'assignments', self.name, 'build_script'))
    return executor.BuildScript.deserialize(serialized)

  def set_build_script(self, build_script):
    serialized = build_script.serialize()
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.name, 'build_script'),
      serialized)

  def get_test_case(self):
    serialized = self._data_store.get(
      ('courses', self.course_name, 'assignments', self.name, 'test_case'))
    return executor.DiffTestCase.deserialize(serialized)

  def set_test_case(self, test_case):
    serialized = test_case.serialize()
    self._data_store.put(
      ('courses', self.course_name, 'assignments', self.name, 'test_case'),
      serialized)

  def root_dir(self):
    return os.path.join(
      'data/files/courses', self.course_name, 'assignments', self.name)

  def build_script_archive_dir(self):
    return os.path.join(self.root_dir(), 'build_script/archive')

  def test_case_input_archive_dir(self):
    return os.path.join(self.root_dir(), 'test_case/input')

  def test_case_output_archive_dir(self):
    return os.path.join(self.root_dir(), 'test_case/output')


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
