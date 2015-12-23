# TODO: Validate course and assignment names
# TODO: Restrict which users can see which pages more
#   e.g. only admins, instructors, and enrolled students should see courses
import errno
import cgi
import collections
import os
import functools
import glob
import shlex
import shutil
import time
import tempfile
import threading
import logging

import bcrypt
import flask
from flask.ext import login
from OpenSSL import SSL

import datastore as datastore_lib
import grade_oven_lib
import executor
import executor_queue_lib

# globals
app = flask.Flask(__name__)
app.config['SECRET_KEY'] = open('../data/secret_key.txt').read()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
login_manager = login.LoginManager()
login_manager.init_app(app)
data_store = datastore_lib.DataStore(os.path.abspath('../data/db'))
grade_oven = grade_oven_lib.GradeOven(data_store)
executor_queue = executor_queue_lib.ExecutorQueue()


class ResourcePool(object):
  def __init__(self, resources):
    self._free_resources = collections.deque(resources)
    self._used_resources = set()
    self._resources_lock = threading.Lock()

  def get(self):
    with self._resources_lock:
      try:
        resource = self._free_resources.popleft()
      except IndexError:
        return None
      self._used_resources.add(resource)
      return resource

  def free(self, resource):
    with self._resources_lock:
      self._used_resources.remove(resource)
      self._free_resources.append(resource)


temp_dirs = ResourcePool(
  os.path.abspath(p) for p in glob.glob('../data/host_dirs/?'))


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
  return flask.render_template(
    'admin_edit_user.html', username=login.current_user.get_id(), errors=errors, msgs=msgs)

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
    'courses.html', username=login.current_user.get_id(),
    courses=grade_oven.course_names())

BASE_FILENAME_CHARS = frozenset(
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -_.()')
def base_filename_is_safe(filename):
  return not (set(filename) - BASE_FILENAME_CHARS) and filename

def safe_base_filename(filename):
  if base_filename_is_safe(filename):
    return filename
  elif not filename:
    return '_'
  else:
    return ''.join(c if c in BASE_FILENAME_CHARS else '%{!x}'.format(ord(c))
                   for c in filename)

# TODO: handle/return errors
def save_files_in_dir(flask_files, dir_path):
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
    'courses_x.html', username=login.current_user.get_id(),
    instructs_course=instructs_course,
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
    'courses_x_assignments.html', username=login.current_user.get_id(),
    instructs_course=instructs_course,
    takes_course=takes_course, assignments=assignment_names,
    course_name=course.name)

def _edit_assignment(form, course_name, assignment_name, stages):
  logging.info('Editing assignment "%s" in course "%s"',
               assignment_name, course_name)
  course = grade_oven.course(course_name)
  course.add_assignment(assignment_name)
  assignment = course.assignment(assignment_name)
  new_stage_name = form.get('new_stage_name')
  if new_stage_name:
    new_stage_name = safe_base_filename(new_stage_name)
    stages.add_stage(new_stage_name)
  description = form.get('description')
  if description:
    stages.save_description(description)
  delete_files = form.getlist('delete_files')
  for delete_file in delete_files:
    parts = delete_file.split('/', 1)
    if len(parts) == 2:
      df_stage_name, df_filename = parts
      df_stage_name = safe_base_filename(df_stage_name)
      df_filename = safe_base_filename(df_filename)
      try:
        df_stage = stages.stages[df_stage_name]
        try:
          os.remove(os.path.join(df_stage.path, df_filename))
        except OSError as e:
          logging.warning('OSError when deleting "%s": %s', delete_file, e)
      except KeyError as e:
        logging.warning('Could not find stage "%s" to delete "%s": %s',
                        df_stage_name, delete_file, e)
    else:
      logging.warning('Could not split "%s" to delete it.', delete_file)
  for stage in stages.stages.itervalues():
    description = form.get('description_{}'.format(stage.name))
    if description:
      stage.save_description(description)
    main_cmds = form.get('main_cmds_{}'.format(stage.name))
    if main_cmds:
      stage.save_main_script(main_cmds)
    files = flask.request.files.getlist('files_{}[]'.format(stage.name))
    if files:
      save_files_in_dir(files, stage.path)


class GradeOvenSubmission(executor_queue_lib.Submission):
  def __init__(
      self, priority, name, description, submission_dir, container_id, stages,
      student_submission):
    super(GradeOvenSubmission, self).__init__(priority, name, description)
    self._temp_dir = None
    self.submission_dir = submission_dir
    self.container_id = container_id
    self.stages = stages
    self.student_submission = student_submission
    self.container = None

  def _run_stages_callback(self, stage):
    logging.info('GradeOvenSubmission._run_stages_callback %s', stage.name)
    self.student_submission.set_score(stage.name, stage.output.score)
    self.student_submission.set_total(stage.name, stage.output.total)
    self.student_submission.set_output(stage.name, stage.output.stdout)
    errors = '\n'.join(stage.output.errors)
    self.student_submission.set_errors(stage.name, errors)
    self.student_submission.set_status(
      'running (finished {})'.format(stage.name))

  def before_run(self):
    logging.info('GradeOvenSubmission.before_run %s', self.description)
    self.student_submission.set_status('setting up')
    self._temp_dir = temp_dirs.get()
    assert self._temp_dir is not None

  def run(self):
    logging.info('GradeOvenSubmission.run %s', self.description)
    self.container = executor.DockerExecutor(self.container_id, self._temp_dir)
    self.container.init()
    outputs = []
    errors = []
    self.student_submission.set_status('running')
    output, errs = self.container.run_stages(self.submission_dir, self.stages,
                                             self._run_stages_callback)
    outputs.append(output)
    errors.extend(errs)

  def after_run(self):
    logging.info('GradeOvenSubmission.after_run %s', self.description)
    self.container.cleanup()
    temp_dirs.free(self._temp_dir)
    self.student_submission.set_status('finished')


def _make_grade_table(course, assignment):
  header_row = ['Avatar Name', 'Score', 'Submission Status',
                'Submit Time', 'Attempts']
  table = []
  for username in course.student_usernames():
    row = []
    user = grade_oven.user(username)
    row.append(user.avatar_name())
    submission = assignment.student_submission(username)
    row.append(submission.score())
    row.append(submission.status())
    row.append(time.strftime('%Y-%m-%d %H:%M:%S',
                             time.localtime(submission.submit_time())))
    row.append(submission.num_submissions())
    table.append(row)
  table = sorted(table, key=lambda row: (-row[1], row[3], row[4]))
  return header_row, table

@app.route('/courses/<string:course_name>/assignments/<string:assignment_name>',
           methods=['GET', 'POST'])
@login.login_required
def courses_x_assignments_x(course_name, assignment_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  assignment = course.assignment(assignment_name)
  student_submission = assignment.student_submission(user.username)
  instructs_course = user.instructs_course(course.name)
  takes_course = user.takes_course(course.name)
  stages = executor.Stages(os.path.join(
    '../data/files/courses', course.name, 'assignments', assignment.name))
  if instructs_course:
    form = flask.request.form
    _edit_assignment(form, course_name, assignment_name, stages)
  if takes_course:
    files = flask.request.files.getlist('submission_files[]')
    if files:
      logging.info('Student "%s" is attempting assignment "%s/%s".',
                   user.username, course_name, assignment_name)
      submission_dir = os.path.join(
        '../data/files/courses', course_name, 'assignments', assignment_name,
        'submissions', user.username)
      desc = '{}_{}_{}'.format(course_name, assignment_name, user.username)
      container_id = desc
      submission = GradeOvenSubmission(
        'priority', user.username, desc, submission_dir, container_id, stages,
        student_submission)
      if submission in executor_queue:
        logging.warning(
          'Student "%s" submited assignment "%s/%s" while still in the queue.',
          user.username, course_name, assignment_name)
      else:
        try:
          shutil.rmtree(submission_dir)
        except OSError as e:
          if e.errno != errno.ENOENT:
            raise e
        save_files_in_dir(files, submission_dir)
        executor_queue.enqueue(submission)
        student_submission.set_status('queued')
        student_submission.set_submit_time()
        student_submission.set_num_submissions(
          student_submission.num_submissions() + 1)
    output = student_submission.output()
    errors = student_submission.errors()
  else:
    output, errors = None, None
  header_row, table = _make_grade_table(course, assignment)
  return flask.render_template(
    'courses_x_assignments_x.html', username=login.current_user.get_id(),
    instructs_course=instructs_course,
    takes_course=takes_course, course_name=course.name,
    assignment_name=assignment.name,
    stages=stages.stages.values(), output=output, errors=errors,
    stages_desc=stages.description, header_row=header_row, table=table)

@app.route('/settings', methods=['GET', 'POST'])
@login.login_required
def settings():
  user = login.current_user
  errors = []

  form = flask.request.form
  avatar_name = form.get('avatar_name')
  if avatar_name:
    user.set_avatar_name(avatar_name)
  password = form.get('password')
  password2 = form.get('password2')
  if password or password2:
    if password == password2:
      user.set_password(password)
    else:
      errors.append('Passwords do not match.')

  return flask.render_template(
    'settings.html', username=login.current_user.get_id(),
    avatar_name=user.avatar_name(), errors=errors)

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
  return flask.render_template(
    'login.html', username=login.current_user.get_id())

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
  context.use_privatekey_file('../data/ssl/server.key')
  context.use_certificate_file('../data/ssl/server.crt')

  # logging.basicConfig(filename='../data/server.log', level=logging.DEBUG)
  logging.basicConfig(level=logging.DEBUG)

  # TODO: add logging
  app.run(
    host='0.0.0.0', port=4321, debug=True, use_reloader=False,
    use_debugger=False, ssl_context=context, use_evalex=False, threaded=True)
