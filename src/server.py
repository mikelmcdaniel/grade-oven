# TODO: Validate course and assignment names
# TODO: Restrict which users can see which pages more
#   e.g. only admins, instructors, and enrolled students should see courses
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
import grade_oven_lib
import executor

# globals
app = flask.Flask(__name__)
app.config['SECRET_KEY'] = open('data/secret_key.txt').read()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
login_manager = login.LoginManager()
login_manager.init_app(app)
data_store = datastore_lib.DataStore(os.path.abspath('data/db'))
grade_oven = grade_oven_lib.GradeOven(data_store)


def admin_required(func):
  @functools.wraps(func)
  def admin_required_func(*args, **kwargs):
    if login.current_user.is_authenticated() and login.current_user.is_admin():
      return func(*args, **kwargs)
    else:
      return flask.abort(403)  # forbidden
  return login.login_required(admin_required_func)


# Set function to load a user
login_manager.user_loader(grade_oven.user)


# Prevent cross-site scripting attacks
@app.before_request
def csrf_protect():
  if flask.request.method != 'GET':
    token = flask.session.pop('_csrf_token', None)
    if not token or token != flask.request.form.get('_csrf_token'):
      abort(403)

def generate_csrf_token():
  if '_csrf_token' not in flask.session:
    # TODO: Verify that bcrypt.gensalt() is sufficient
    flask.session['_csrf_token'] = bcrypt.gensalt()[7:]
  return flask.session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


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
    user = grade_oven.user(username)
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
    'courses.html', courses=grade_oven.course_names())

BASE_FILENAME_CHARS = frozenset(
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.()')
def base_filename_is_safe(filename):
  return not (set(filename) - BASE_FILENAME_CHARS) and filename

# TODO: handle/return errors
def save_files_in_dir(dir_path, flask_files):
  try:
    os.makedirs(dir_path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise e
  for f in flask_files:
    base_filename = os.path.basename(f.filename)
    if base_filename_is_safe(base_filename):
      f.save(os.path.join(dir_path, base_filename))

@app.route('/courses/<string:course_name>', methods=['GET', 'POST'])
@login.login_required
def courses_x(course_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  instructs_course = user.instructs_course(course_name)
  takes_course = user.takes_course(course_name)
  if instructs_course:
    form = flask.request.form
    # Add/Edit assignment
    assignment_name = form.get('assignment_name')
    if assignment_name:
      course.add_assignment(assignment_name)
      return flask.redirect(
        '/courses/{}/assignments/{}'.format(course_name, assignment_name))
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

@app.route('/courses/<string:course_name>/assignments', methods=['GET', 'POST'])
@login.login_required
def courses_x_assignments(course_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  instructs_course = user.instructs_course(course_name)
  takes_course = user.takes_course(course_name)
  # Add/Edit assignment
  if instructs_course:
    form = flask.request.form
    assignment_name = form.get('assignment_name')
    if assignment_name:
      course.add_assignment(assignment_name)
      return flask.redirect(
        '/courses/{}/assignments/{}'.format(course_name, assignment_name))
  assignment_names = course.assignment_names()
  return flask.render_template(
    'courses_x_assignments.html', instructs_course=instructs_course,
    takes_course=takes_course, assignments=assignment_names,
    course_name=course.name)

def _edit_assignment(form, course_name, assignment_name):
  course = grade_oven.course(course_name)
  course.add_assignment(assignment_name)
  assignment = course.assignment(assignment_name)
  assignment_desc = form.get('assignment_desc')
  if assignment_desc:
    assignment.set_description(assignment_desc)
  # build_script
  build_script = assignment.get_build_script()
  # TODO (here and below): check if any files were uploaded
  #   also remove old files
  #   also have some way to garbage collect old files
  #   also show the files that already exist
  files = flask.request.files.getlist('build_archive[]')
  if files:
    save_files_in_dir(assignment.build_script_archive_dir(), files)
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
  files = flask.request.files.getlist('input_archive[]')
  if files:
    save_files_in_dir(assignment.test_case_input_archive_dir(), files)
    test_case.input_archive_path = assignment.test_case_input_archive_dir()
  files = flask.request.files.getlist('output_archive[]')
  if files:
    save_files_in_dir(assignment.test_case_output_archive_dir(), files)
    test_case.output_archive_path = assignment.test_case_output_archive_dir()
  cmds = form.get('test_case_cmds')
  if cmds:
    test_case.cmds = map(shlex.split, cmds.split('\n'))
  assignment.set_test_case(test_case)

@app.route('/courses/<string:course_name>/assignments/<string:assignment_name>', methods=['GET', 'POST'])
@login.login_required
def courses_x_assignments_x(course_name, assignment_name):
  errors = []
  user = login.current_user
  course = grade_oven.course(course_name)
  assignment = course.assignment(assignment_name)
  instructs_course = user.instructs_course(course.name)
  takes_course = user.takes_course(course.name)
  build_script_cmds = None
  test_case_cmds = None
  score = None
  build_output = None
  test_output = None
  if instructs_course:
    form = flask.request.form
    _edit_assignment(form, course_name, assignment_name)
    build_script = assignment.get_build_script()
    build_script_cmds = '\n'.join(executor.join_cmd_parts(c)
                                  for c in build_script.cmds)
    test_case = assignment.get_test_case()
    test_case_cmds = '\n'.join(executor.join_cmd_parts(c)
                               for c in test_case.cmds)
  if takes_course:
    temp_hack_dir = os.path.join(assignment.root_dir(), 'TEMPORARY_HACK')
    files = flask.request.files.getlist('code_archive[]')
    if files:
      save_files_in_dir(temp_hack_dir, files)
      build_script = assignment.get_build_script()
      test_case = assignment.get_test_case()
      c = executor.DockerExecutor('temp_hack', 'test_host_dir')
      c.init()
      build_output, errs = c.build(temp_hack_dir, build_script)
      errors.extend(errs)
      score, test_output, errs = c.test(test_case)
      errors.extend(errs)
      c.cleanup()
  assignment_desc = assignment.description()
  return flask.render_template(
    'courses_x_assignments_x.html', instructs_course=instructs_course,
    takes_course=takes_course, course_name=course.name,
    assignment_name=assignment.name, score=score, errors=errors,
    build_script_cmds=build_script_cmds, test_case_cmds=test_case_cmds,
    assignment_desc=assignment_desc, build_output=build_output,
    test_output=test_output)

@app.route('/')
def index():
  if login.current_user.is_authenticated():
    return flask.redirect('/courses')
  else:
    return flask.redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login_():
  form = flask.request.form
  username = form.get('username')
  password = form.get('password')
  if username and password:
    user = grade_oven_lib.GradeOvenUser.load_and_authenticate_user(
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
    user = grade_oven.user('admin')
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
