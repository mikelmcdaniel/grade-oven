# login -> dashboard
# * -> logout
# dashboard -> settings, course[]
# settings -> update_avatar
# course -> assignment[]
# assignment -> submit
# logout -> login

import cgi
import os
import functools
import time

import bcrypt
import flask
from flask.ext import login
from OpenSSL import SSL

import datastore as datastore_lib

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = open('data/secret_key.txt').read()
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
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


class GradeOvenCourse(object):
  "Represents a course"
  def __init__(self, data_store, course_name):
    self.name = course_name
    self._data_store = data_store

  def students(self):
    return data_store.get_all(('courses', self.name, 'students'))

  def instructors(self):
    return data_store.get_all(('courses', self.name, 'instructors'))

  def assignments(self):
    return data_store.get_all(('courses', self.name, 'assignments'))


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
  return 'You are logged in as {}'.format(login.current_user.get_id())

@app.route('/courses/<string:course_name>')
@login.login_required
def courses_x(course_name):
  user = login.current_user
  course = GradeOvenCourse(data_store, course_name)
  instructs_course = user.instructs_course(course.name)
  takes_course = user.takes_course(course.name)
  if instructs_course:
    students = course.students()
  else:
    students = None
  assignments = course.assignments()
  return flask.render_template(
    'courses_x.html', instructs_course=instructs_course,
    takes_course=takes_course, students=students, assignments=assignments,
    course_name=course.name)

@app.route('/courses/<string:course_name>/assignments/<string:assignment_name>')
@login.login_required
def courses_x_assignment_x(course_name, assignment_name):
  return cgi.escape('TODO: /courses/{}/assignments/{}'.format(course_name, assignment_name))

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
