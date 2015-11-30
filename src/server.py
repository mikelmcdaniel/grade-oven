# login -> dashboard
# * -> logout
# dashboard -> settings, course[]
# settings -> update_avatar
# course -> assignment[]
# assignment -> submit
# logout -> login

import os
import functools
import bcrypt
import flask
from flask.ext import login
from OpenSSL import SSL

import datastore as datastore_lib

app = flask.Flask(__name__)
app.config['SECRET_KEY'] = ''.join(bcrypt.gensalt()[7:] for _ in xrange(20))
login_manager = login.LoginManager()
login_manager.init_app(app)
data_store = datastore_lib.DataStore(os.path.abspath('data/'))

"""
datastore schema:
courses[]
  students
  instructors
users[]
  hashed_password
"""


class GradeOvenUser(object):
  "Represents a logged in user, needed for flask.ext.login.LoginManager"
  def __init__(self, data_store, username):
    self.username = username
    self._data_store = data_store

  @classmethod
  def load_user(cls, data_store, username):
    return cls(data_store, username)

  @classmethod
  def load_and_authenticate_user(cls, data_store, username, password):
    hashed_password = data_store.get(('users', username, 'hashed_password'))
    try:
      is_valid_password = bcrypt.checkpw(password, hashed_password)
    except (ValueError, TypeError) as e:
      is_valid_password = False
    if is_valid_password:
      user = cls.load_user(data_store, username)
      user.set_is_authenticated(True)
      return user
    return None

  def set_password(self, password):
    hpw = bcrypt.hashpw(password, bcrypt.gensalt())
    self._data_store.put(('users', self.username, 'hashed_password'), hpw)

  def is_authenticated(self):
    return data_store.get(('users', self.username, 'is_authenticated'))

  def set_is_authenticated(self, value):
    data_store.put(('users', self.username, 'is_authenticated'), bool(value))

  def is_active(self):
    return self.is_authenticated()

  def is_anonymous(self):
    return False

  def get_id(self):
    return self.username


@login_manager.user_loader
def load_user(username):
  return GradeOvenUser.load_user(data_store, username)


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

@app.route('/login', methods=['POST', 'GET'])
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

  context = SSL.Context(SSL.TLSv1_METHOD)
  # TODO: generate a legitimate server key and certificate
  context.use_privatekey_file('data/server.key')
  context.use_certificate_file('data/server.crt')

  # TODO: add logging
  app.run(
    host='0.0.0.0', port=4321, debug=True, use_reloader=False,
    use_debugger=False, ssl_context=context, use_evalex=False)
