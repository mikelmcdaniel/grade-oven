# TODO: Validate course and assignment names
# TODO: Restrict which users can see which pages more
#   e.g. onlyy admins, instructors, and enrolled students should see courses
import errno
import cgi
import os
import functools
import shlex
import time

import bcrypt
import flask
from flask.ext import login
from OpenSSL import SSL

import datastore as datastore_lib
import executor

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = open('data/secret_key.txt').read()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
login_manager = login.LoginManager()
login_manager.init_app(app)
data_store = datastore_lib.DataStore(os.path.abspath('data/db'))

"""
datastore schema:
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
      hashed_password = data_store['users', self.username, 'hashed_password']
    except KeyError:
      return False
    try:
      return bcrypt.checkpw(password, hashed_password)
    except (ValueError, TypeError) as e:
      return False

  @classmethod
  def load_and_authenticate_user(cls, data_store, username, password):
    user = cls.load_user(data_store, username)
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
    return data_store.get(('users', self.username, 'is_authenticated'), False)

  def set_is_authenticated(self, value):
    data_store.put(('users', self.username, 'is_authenticated'), bool(value))

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

  def add_edit_assignment(self, assignment_name):
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




def admin_required(func):
  @functools.wraps(func)
  def admin_required_func(*args, **kwargs):
    if login.current_user.is_authenticated() and login.current_user.is_admin():
      return func(*args, **kwargs)
    else:
      return flask.abort(403)  # forbidden
  return login.login_required(admin_required_func)


@login_manager.user_loader
def load_user(username):
  return GradeOvenUser(data_store, username)


@app.route('/admin/add_user')
@admin_required
def admin_add_user():
  return flask.redirect('/admin/edit_user')

@app.route('/admin/edit_user', methods=['GET', 'POST'])
@admin_required
def admin_edit_user():
  def _select_to_bool(value):
    if value == 'set':
      return True
    elif value == 'unset':
      return False
    return None
  form = flask.request.form
  username = form.get('username')
  password = form.get('password')
  password2 = form.get('password2')
  is_admin = _select_to_bool(form.get('is_admin'))
  is_instructor = _select_to_bool(form.get('is_instructor'))
  course = form.get('course')
  instructs_course = _select_to_bool(form.get('instructs_course'))
  takes_course = _select_to_bool(form.get('takes_course'))
  errors = []
  msgs = []
  if (password is None or password2 is None) and password != password2:
    errors.append('Password and password confirmation do not match.')
  if username is not None:
    user = GradeOvenUser.load_user(data_store, username)
    msgs.append('Loaded user {!r}'.format(username))
    if password is not None:
      user.set_password(password)
      msgs.append('Set password')
    if is_admin is not None:
      user.set_is_admin(is_admin)
      msgs.append('Set is_admin == {!r}'.format(is_admin))
    if is_instructor is not None:
      user.set_is_instructor(is_instructor)
      msgs.append('Set is_instructor == {!r}'.format(is_instructor))
    if course is not None:
      if instructs_course:
        user.set_instructs_course(course, instructs_course)
        msgs.append('Set instructs_course {!r} == {!r}'.format(course, instructs_course))
      if takes_course:
        user.set_takes_course(course, takes_course)
        msgs.append('Set takes_course {!r} == {!r}'.format(course, takes_course))
  else:
    errors.append('Username must be set.')
  return flask.render_template('admin_edit_user.html', errors=errors, msgs=msgs)

@app.route('/admin/db/get/<path:key>')
@admin_required
def admin_db_get(key):
  return cgi.escape(repr(data_store.get(key.split('/'))))

@app.route('/admin/db/get_all/<path:key>')
@admin_required
def admin_db_get_all(key):
  return '<br>'.join(cgi.escape(repr(v))
                     for v in data_store.get_all(key.split('/')))

@app.route('/debug/logged_in')
@login.login_required
def debug_logged_in():
  return 'Logged in as {}.'.format(cgi.escape(login.current_user.get_id()))

@app.route('/courses')
@login.login_required
def courses():
  return flask.render_template(
    'courses.html', courses=GradeOven(data_store).course_names())

BASE_FILENAME_CHARS = frozenset(
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.()')
def base_filename_is_safe(filename):
  return not (set(filename) - BASE_FILENAME_CHARS) and filename

# TODO: handle/return errors
def save_files_in_dir(dir_path, flask_files):
  try:
    os.makedirs(dir_path)
  except OSError as e:
    if e.errno != errno.EEXIST:  # If dir_path exists, ignore this error.
      raise e
  for f in flask_files:
    base_filename = os.path.basename(f.filename)
    if base_filename_is_safe(base_filename):
      f.save(os.path.join(dir_path, base_filename))

@app.route('/courses/<string:course_name>', methods=['GET', 'POST'])
@login.login_required
def courses_x(course_name):
  user = login.current_user
  course = GradeOvenCourse(data_store, course_name)
  instructs_course = user.instructs_course(course.name)
  takes_course = user.takes_course(course.name)
  if instructs_course:
    form = flask.request.form
    # Add/Edit assignment
    assignment_name = form.get('assignment_name')
    if assignment_name:
      course.add_edit_assignment(assignment_name)
      assignment = course.assignment(assignment_name)
      # build_script
      build_script = assignment.get_build_script()
      # TODO (here and below): check if any files were uploaded
      #   also remove old files
      #   also have some way to garbage collect old files
      #   also show the files that already exist
      save_files_in_dir(
        assignment.build_script_archive_dir(),
        flask.request.files.getlist('build_archive[]'))
      build_script.archive_path = assignment.build_script_archive_dir()
      cmds = form.get('build_script_cmds')
      if cmds:
        build_script.cmds = map(shlex.split, cmds.split('\n'))
      expected_filenames = form.get('expected_filenames')
      if expected_filenames:
        build_script.expected_filenames = expected_filenames.split('\n')
      assignment.set_build_script(build_script)
      # test_case
      test_case = assignment.get_test_case()
      save_files_in_dir(
        assignment.test_case_input_archive_dir(),
        flask.request.files.getlist('input_archive[]'))
      test_case.input_archive_path = assignment.test_case_input_archive_dir()
      save_files_in_dir(
        assignment.test_case_output_archive_dir(),
        flask.request.files.getlist('output_archive[]'))
      test_case.output_archive_path = assignment.test_case_output_archive_dir()
      cmds = form.get('test_case_cmds')
      if cmds:
        test_case.cmds = map(shlex.split, cmds.split('\n'))
      assignment.set_test_case(test_case)
    # Enroll students
    add_students = form.get('add_students')
    if add_students:
      course.add_students(add_students.split())
    # Unenroll students
    remove_students = form.get('remove_students')
    if remove_students:
      course.remove_students(remove_students.split())
    student_usernames = course.student_usernames()
  else:
    student_usernames = None
  assignment_names = course.assignment_names()
  return flask.render_template(
    'courses_x.html', instructs_course=instructs_course,
    takes_course=takes_course, students=student_usernames,
    assignments=assignment_names, course_name=course.name)

@app.route('/courses/<string:course_name>/assignments/<string:assignment_name>', methods=['GET', 'POST'])
@login.login_required
def courses_x_assignment_x(course_name, assignment_name):
  user = login.current_user
  course = GradeOvenCourse(data_store, course_name)
  assignment = course.assignment(assignment_name)
  instructs_course = user.instructs_course(course.name)
  takes_course = user.takes_course(course.name)
  if takes_course:
    temp_hack_dir = os.path.join(assignment.root_dir(), 'TEMPORARY_HACK')
    save_files_in_dir(
      temp_hack_dir,
      flask.request.files.getlist('code_archive[]'))
    bs = assignment.get_build_script()
    tc = assignment.get_test_case()
    # bs = executor.BuildScript(
    #   None,
    #   [['clang', '-std=c++11', '-Wall', '-Wextra', '-lstdc++',
    #     '-o', 'hello_world', 'hello_world.cpp']],
    #   ['hello_world'])
    # tc = executor.DiffTestCase(
    #   None, 'test_host_dir/test/hello_world.txt',
    #   [['/bin/bash', '-c', '/grade_oven/hello_world > hello_world.txt']])
    c = executor.DockerExecutor('temp_hack', 'test_host_dir')
    c.init()
    c.build(temp_hack_dir, bs)
    score, errors = c.test(tc)
    c.cleanup()
  return flask.render_template(
    'courses_x_assignments_x.html', instructs_course=instructs_course,
    takes_course=takes_course, course_name=course.name,
    assignment_name=assignment.name, score=score, errors=errors)

@app.route('/')
def index():
  if login.current_user.is_authenticated():
    return flask.redirect('/debug/logged_in')
  else:
    return flask.redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login_():
  form = flask.request.form
  username = form.get('username')
  password = form.get('password')
  if username and password:
    user = GradeOvenUser.load_and_authenticate_user(
      data_store, username, password)
    if user is None:
      return flask.abort(400)
    else:
      login.login_user(user, remember=True)
      return flask.redirect('/')
  return flask.render_template('login.html')

@app.route("/logout")
@login.login_required
def logout():
    login.logout_user()
    return flask.redirect('/')



if __name__ == '__main__':
  if not data_store.get_all(('admins',)):
    user = GradeOvenUser(data_store, 'admin')
    user.set_password('admin')
    user.set_is_admin(True)

  context = SSL.Context(SSL.TLSv1_METHOD)
  # TODO: generate a legitimate server key and certificate
  context.use_privatekey_file('data/ssl/server.key')
  context.use_certificate_file('data/ssl/server.crt')

  # TODO: add logging
  app.run(
    host='0.0.0.0', port=4321, debug=True, use_reloader=False,
    use_debugger=False, ssl_context=context, use_evalex=False, threaded=True)
