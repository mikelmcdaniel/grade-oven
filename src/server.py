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
app.config['SECRET_KEY'] = ''.join(bcrypt.gensalt()[7:] for _ in xrange(10))
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024
login_manager = login.LoginManager()
login_manager.init_app(app)
data_store = datastore_lib.DataStore(os.path.abspath('data/db'))

"""
datastore schema:
courses[]
  students
  instructors
users[]
  hashed_password
admins[]
"""


class GradeOvenUser(object):
  "Represents a logged in user, needed for flask.ext.login.LoginManager"
  def __init__(self, data_store, username):
    self.username = username
    self._data_store = data_store

  @classmethod
  def load_user(cls, data_store, username):
    return cls(data_store, username)

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
  return GradeOvenUser.load_user(data_store, username)

@app.route('/admin/add_user')
@admin_required
def admin_add_user():
  return flask.redirect('/admin/edit_user')

@app.route('/admin/edit_user', methods=['GET', 'POST'])
@admin_required
def admin_edit_user():
  form = flask.request.form
  username = form.get('username')
  password = form.get('password')
  password2 = form.get('password2')
  errors = []
  if password != password2:
    errors.append('Password and password confirmation do not match.')
  if username and password and password2:
    if password == password2:
      user = GradeOvenUser.load_user(data_store, username)
      user.set_password(password)
  elif username or password or password2:
    errors.append('Username and password must both be set.')
  return flask.render_template('admin_edit_user.html', errors=errors)

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
  return 'You are logged in.'

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




if __name__ == '__main__':
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
