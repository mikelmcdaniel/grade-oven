"""This is the server modules which imports everything and handles requests.

All UI is controlled via this module.

This server enforces most of the security that isn't related to actually running
code, such as input sanitazation (via escape_lib).
"""

# TODO: Validate course and assignment names
# TODO: Restrict which users can see which pages more
#   e.g. only admins, instructors, and enrolled students should see courses
import cgi
import collections
import csv
import errno
import functools
import glob
import itertools
import json
import logging
import math
import optparse
import os
import re
import shlex
import shutil
import signal
import six
import tempfile
import threading
import time
from typing import Dict, Text
import zipfile

import flask_login as login
import bcrypt
import flask

from datastore import datastore as datastore_lib
import escape_lib
import executor
import executor_queue_lib
import grade_oven_lib
import random_display_name_lib

SECONDS_PER_DAY = 24 * 60 * 60

# globals
app = flask.Flask(__name__)
with open('../data/secret_key.txt') as f:
  app.config['SECRET_KEY'] = f.read()
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
login_manager = login.LoginManager()
login_manager.init_app(app)
data_store = datastore_lib.DataStore(os.path.abspath('../data/db'))
grade_oven = grade_oven_lib.GradeOven(data_store)
executor_queue = executor_queue_lib.ExecutorQueue()
monitor_variables = collections.defaultdict(int)  # type: Dict[Text, int]


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

  def __len__(self):
    return len(self._free_resources)


temp_dirs = ResourcePool(
    os.path.abspath(p) for p in glob.glob('../data/host_dirs/?'))
assert len(temp_dirs) > 0


def nothing_required(func):
  @functools.wraps(func)
  def nothing_required_func(*args, **kwargs):
    logging.info(u'User "%s" accessed public page "%s"',
                 login.current_user.get_id(), flask.request.url)
    return func(*args, **kwargs)

  return nothing_required_func


def login_required(func):
  @functools.wraps(func)
  def login_required_func(*args, **kwargs):
    if login.current_user.is_authenticated:
      logging.info(u'User "%s" accessed "%s"', login.current_user.get_id(),
                   flask.request.url)
      return func(*args, **kwargs)
    else:
      logging.info(u'Unknown user "%s" tried to access "%s"',
                   login.current_user.get_id(), flask.request.url)
      return flask.redirect(
          u'/login?redirect={}'.format(flask.request.path), code=303)

  return login_required_func


def admin_required(func):
  @functools.wraps(func)
  def admin_required_func(*args, **kwargs):
    if login.current_user.is_authenticated and login.current_user.is_admin():
      logging.info(u'Admin "%s" accessed "%s"', login.current_user.get_id(),
                   flask.request.url)
      return func(*args, **kwargs)
    else:
      logging.warning(u'Unknown user "%s" tried to access admin page "%s"',
                      login.current_user.get_id(), flask.request.url)
      return flask.abort(403)  # forbidden

  return admin_required_func


def monitor_required(func):
  @functools.wraps(func)
  def monitor_required_func(*args, **kwargs):
    if login.current_user.is_authenticated and login.current_user.is_monitor():
      if login.current_user.get_id() != 'monitor':
        logging.info(u'Monitor "%s" accessed "%s"',
                     login.current_user.get_id(), flask.request.url)
      return func(*args, **kwargs)
    else:
      logging.warning(u'Unknown user "%s" tried to access monitor page "%s"',
                      login.current_user.get_id(), flask.request.url)
      return flask.abort(403)  # forbidden

  return monitor_required_func


# Set function to load a user
login_manager.user_loader(grade_oven.user)


# Prevent cross-site scripting attacks
@app.before_request
def csrf_protect():
  if flask.request.method != 'GET' and flask.request.path != '/login':
    expected_token = flask.session.pop('_csrf_token', None)
    received_token = flask.request.form.get('_csrf_token')
    if expected_token != received_token:
      logging.warning(
          u'Invalid _csrf_token "%s" for "%s". Expected token "%s".',
          expected_token, flask.request.url, received_token)
      flask.abort(403)


def generate_csrf_token():
  if '_csrf_token' not in flask.session:
    # TODO: Verify that bcrypt.gensalt() is sufficient
    flask.session['_csrf_token'] = bcrypt.gensalt()[7:].decode('utf-8')
  return flask.session['_csrf_token']


app.jinja_env.globals['csrf_token'] = generate_csrf_token

SIGNALS = dict(
    (signal_name, getattr(signal, signal_name)) for signal_name in dir(signal))


@app.route('/favicon.ico')
@nothing_required
def favicon():
  return flask.send_file('static/favicon.ico', mimetype='image/x-icon')


@app.route('/about')
@nothing_required
def about():
  return flask.render_template(
      'about.html', username=login.current_user.get_id())


@app.route('/admin')
@admin_required
def admin():
  return flask.render_template(
      'admin.html', username=login.current_user.get_id())


@app.route('/admin/kill/<string:sig>')
@admin_required
def admin_kill_x(sig):
  self_pid = os.getpid()
  logging.warning('Sending signal (%s) to self (pid %s).', sig, self_pid)
  sig = SIGNALS.get(sig, sig)
  try:
    sig = int(sig)
  except ValueError:
    pass
  os.kill(self_pid, sig)


@app.route('/admin/add_user')
@admin_required
def admin_add_user():
  return flask.redirect('/admin/edit_user')


def _select_to_bool(value):
  if value == 'set':
    return True
  elif value == 'unset':
    return False
  return None


def _add_edit_user(username, password, is_admin, is_monitor, is_instructor,
                   course, instructs_course, takes_course, add_defaults, msgs):
  user = grade_oven.user(username)
  msgs.append(u'Loaded user {!r}'.format(username))
  if password is not None:
    user.set_password(password)
    msgs.append('Set password')
  if is_admin is not None:
    user.set_is_admin(is_admin)
    msgs.append('Set is_admin == {!r}'.format(is_admin))
  if is_monitor is not None:
    user.set_is_monitor(is_monitor)
    msgs.append('Set is_monitor == {!r}'.format(is_monitor))
  if is_instructor is not None:
    user.set_is_instructor(is_instructor)
    msgs.append('Set is_instructor == {!r}'.format(is_instructor))
  if course is not None:
    if instructs_course:
      user.set_instructs_course(course, instructs_course)
      msgs.append('Set instructs_course {!r} == {!r}'.format(
          course, instructs_course))
    if takes_course:
      user.set_takes_course(course, takes_course)
      msgs.append('Set takes_course {!r} == {!r}'.format(course, takes_course))
  if add_defaults:
    name = random_display_name_lib.random_name()
    user.set_display_name(name)
    user.set_real_name(name)


@app.route('/admin/edit_user', methods=['GET', 'POST'])
@admin_required
def admin_edit_user():
  form = flask.request.form
  usernames = form.get('usernames')
  if usernames:
    usernames = [
        escape_lib.safe_entity_name(u) for u in re.split('\s|,|;', usernames)
        if u
    ]
  else:
    usernames = []
  password = form.get('password')
  password2 = form.get('password2')
  is_admin = _select_to_bool(form.get('is_admin'))
  is_monitor = _select_to_bool(form.get('is_monitor'))
  is_instructor = _select_to_bool(form.get('is_instructor'))
  course = form.get('course')
  instructs_course = _select_to_bool(form.get('instructs_course'))
  takes_course = _select_to_bool(form.get('takes_course'))
  errors = []
  msgs = []
  passwords = []
  if not password and not password2:
    if usernames:
      msgs.append('"Username","Generated Password"')
    for username in usernames:
      user = grade_oven.user(username)
      if not user.has_password():
        generated_password = bcrypt.gensalt()[7:]
        passwords.append(generated_password)
        msgs.append('"{}","{}"'.format(username, generated_password))
      else:
        passwords.append(None)
  elif password != password2:
    errors.append('Password and password confirmation do not match.')
  else:  # password == password2:
    passwords = [password for _ in xrange(len(usernames))]
  for username, password_ in zip(usernames, passwords):
    _add_edit_user(username, password_, is_admin, is_monitor, is_instructor,
                   course, instructs_course, takes_course, True, msgs)
  return flask.render_template(
      'admin_edit_user.html',
      username=login.current_user.get_id(),
      errors=errors,
      msgs=msgs)


@app.route('/admin/db/<path:key>')
@admin_required
def admin_db(key):
  key = key.split('/')
  key_parts = []
  parts_so_far = []
  for part in key:
    parts_so_far.append(part)
    key_parts.append(('/'.join(parts_so_far), part))
  data = repr(data_store.get(key))
  sub_dirs = data_store.get_all(key)
  return flask.render_template(
      'admin_db.html',
      username=login.current_user.get_id(),
      key=key_parts,
      data=data,
      sub_dirs=sub_dirs)


@app.route('/monitor/variables')
@monitor_required
def monitor_variables_():
  monitor_variables['monitor_vars_gets'] += 1
  return json.dumps(
      monitor_variables, sort_keys=True, indent=2, separators=(',', ': '))


@app.route('/monitor/logs')
@monitor_required
def monitor_logs():
  log_names = os.listdir('../data/logs')
  return flask.render_template(
      'monitor_logs.html',
      username=login.current_user.get_id(),
      log_names=log_names)


@app.route('/monitor/logs/<string:log_name>')
@monitor_required
def monitor_logs_x(log_name):
  errors = []
  safe_log_name = escape_lib.safe_entity_name(log_name)
  if safe_log_name != log_name:
    logging.error(u'User "%s" requsted bad log name "%s".',
                  login.current_user.get_id(), log_name)
    return flask.redirect('/monitor/logs/' + safe_log_name)

  log_data = '<COULD NOT READ LOG>'
  max_bytes = flask.request.args.get('max_bytes', 100 * 1024)
  try:
    max_bytes = int(max_bytes)
  except ValueError as e:
    errors.append(u'max_bytes "{}" is not an int: {}'.fomrat(max_bytes, e))
    logging.error(errors[-1])
    max_bytes = 100 * 1024
  line_regex = flask.request.args.get('line_regex', '')
  try:
    with open(os.path.join('../data/logs', log_name)) as f:
      f.seek(0, os.SEEK_END)
      f_size = f.tell()
      f.seek(max(0, f_size - max_bytes), os.SEEK_SET)
      log_data = f.read(max_bytes)
      if line_regex:
        compiled_line_regex = re.compile(
            line_regex)  # This may raise an exception.
        log_data = '\n'.join(
            line for line in log_data.split('\n')
            if compiled_line_regex.match(line))
  except (OSError, IOError) as e:
    errors.append(u'Could not read log:\n{!r}\n{}'.format(e, e))
    log_data = ''
  return flask.render_template(
      'monitor_logs_x.html',
      username=login.current_user.get_id(),
      log_name=log_name,
      log_data=log_data,
      errors=errors,
      max_bytes=max_bytes,
      line_regex=line_regex)


@app.route('/debug/logged_in')
@login_required
def debug_logged_in():
  return u'Logged in as {}.'.format(cgi.escape(login.current_user.get_id()))


@app.route('/debug/ping')
@nothing_required
def debug_ping():
  return 'pong'


@app.route('/courses')
@login_required
def courses():
  return flask.render_template(
      'courses.html',
      username=login.current_user.get_id(),
      courses=grade_oven.course_names())


def save_files_in_dir(flask_files, dir_path):
  errors = []
  try:
    os.makedirs(dir_path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise e
  for f in flask_files:
    base_filename = os.path.basename(f.filename)
    if base_filename:
      if escape_lib.is_safe_entity_name(base_filename):
        f.save(os.path.join(dir_path, base_filename))
      else:
        safe_base_filename = escape_lib.safe_entity_name(base_filename)
        errors.append(
            u'Filename "{}" is unsafe.  File saved as "{}" instead.'.format(
                base_filename, safe_base_filename))
        logging.warning(errors[-1])
        f.save(os.path.join(dir_path, safe_base_filename))
  return errors


@app.route('/courses/<string:course_name>/download_grades', methods=['GET'])
@login_required
def courses_x_download_grades(course_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  instructs_course = user.instructs_course(course_name)
  takes_course = user.takes_course(course_name)
  if instructs_course:
    header_row, table = _make_grades_table(course, instructs_course)
    buf = six.BytesIO()
    writer = csv.writer(buf)
    writer.writerow(header_row)
    for row in table:
      writer.writerow([x.encode('utf-8') for x in row])
    response = flask.make_response(buf.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=grades.csv'
    return response
  else:
    return flask.redirect(u'/courses/{}'.format(course_name), code=303)


@app.route('/courses/<string:course_name>', methods=['GET', 'POST'])
@login_required
def courses_x(course_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  instructs_course = user.instructs_course(course_name)
  takes_course = user.takes_course(course_name)
  if instructs_course:
    form = flask.request.form
    # Add/Edit assignment
    assignment_name = escape_lib.safe_entity_name(form.get('assignment_name'))
    if assignment_name:
      assignment_zips = flask.request.files.getlist('assignment_zips[]')
      if assignment_zips:
        for file_obj in assignment_zips:
          course.add_assignment_from_zip(
              file_obj, assignment_name,
              '../data/files/courses/{}/assignments'.format(course_name))
      else:
        course.add_assignment(assignment_name)
      return flask.redirect(u'/courses/{}/assignments/{}'.format(
          course_name, assignment_name))
    # Enroll students
    add_students = escape_lib.safe_entity_name(form.get('add_students'))
    if add_students:
      course.add_students(add_students.split())
    # Unenroll students
    remove_students = escape_lib.safe_entity_name(form.get('remove_students'))
    if remove_students:
      course.remove_students(remove_students.split())
    student_usernames = course.student_usernames()
    psuedo_usernames = []
    for student_username in student_usernames:
      u = grade_oven.user(student_username)
      psuedo_usernames.append(u'{} ({})'.format(student_username,
                                                u.display_name()))
    student_usernames = psuedo_usernames
  else:
    student_usernames = None
  grades_header_row, grades_table = _make_grades_table(
      course, show_real_names=instructs_course)
  assignment_names = course.assignment_names()
  return flask.render_template(
      'courses_x.html',
      username=login.current_user.get_id(),
      instructs_course=instructs_course,
      takes_course=takes_course,
      assignments=assignment_names,
      course_name=course.name,
      grades_header_row=grades_header_row,
      grades_table=grades_table)


def _make_grades_table(course, show_real_names=False):
  header_row = []
  if show_real_names:
    header_row.append('Username')
    header_row.append('Real Name')
  header_row.append('Display Name')
  assignment_names = course.assignment_names()
  student_names = sorted(course.student_usernames())
  for assignment_name in assignment_names:
    header_row.append(assignment_name)
    header_row.append(assignment_name + ' (after due date)')
  assignments = [course.assignment(an) for an in assignment_names]
  table = []
  for student_name in student_names:
    user = grade_oven.user(student_name)
    if not show_real_names and user.prefers_anonymity():
      continue
    row = []
    if show_real_names:
      row.append(user.username)
      row.append(user.real_name())
    row.append(user.display_name())
    for assignment in assignments:
      submission = assignment.student_submission(student_name)
      row.append(six.text_type(submission.score()))
      row.append(six.text_type(submission.past_due_date_score()))
    table.append(row)
  table = sorted(table)
  return header_row, table


@app.route(
    '/courses/<string:course_name>/assignments', methods=['GET', 'POST'])
@login_required
def courses_x_assignments(course_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  instructs_course = user.instructs_course(course_name)
  takes_course = user.takes_course(course_name)
  assignment_names = course.assignment_names()
  return flask.render_template(
      'courses_x_assignments.html',
      username=login.current_user.get_id(),
      instructs_course=instructs_course,
      takes_course=takes_course,
      assignments=assignment_names,
      course_name=course.name)


def _edit_assignment(form, course_name, assignment_name, stages):
  errors = []
  logging.info(u'Editing assignment "%s" in course "%s"', assignment_name,
               course_name)
  course = grade_oven.course(course_name)
  course.add_assignment(assignment_name)
  assignment = course.assignment(assignment_name)
  new_stage_name = form.get('new_stage_name')
  if new_stage_name:
    new_stage_name = escape_lib.safe_entity_name(new_stage_name)
    stages.add_stage(new_stage_name)
  description = form.get('description')
  if description:
    stages.save_description(description)
  due_date = form.get('due_date')
  try:
    assignment.set_due_date(
        time.mktime(time.strptime(due_date, '%Y-%m-%d %H:%M')))
  except TypeError:
    pass  # None passed in (no date)
  except ValueError:
    if due_date:
      errors.append(
          'Due date "{}" not formatted like "YYYY-MM-DD HH:MM".'.format(
              due_date))
  delete_files = form.getlist('delete_files')
  for delete_file in delete_files:
    parts = delete_file.split('/', 1)
    if len(parts) == 2:
      df_stage_name, df_filename = parts
      df_stage_name = escape_lib.safe_entity_name(df_stage_name)
      df_filename = escape_lib.safe_entity_name(df_filename)
      try:
        df_stage = stages.stages[df_stage_name]
        try:
          os.remove(os.path.join(df_stage.path, df_filename))
        except OSError as e:
          errors.append(u'Could not delete "{}": {}'.format(delete_file, e))
          logging.warning(errors[-1])
      except KeyError as e:
        errors.append(u'Could not find stage "{}" to delete "{}": {}'.format(
            df_stage_name, delete_file, e))
        logging.warning(errors[-1])
    else:
      errors.append(u'Could not split "{}" to delete it.'.format(delete_file))
      logging.warning(errors[-1])
  for stage in stages.stages.values():
    description = form.get(u'description_{}'.format(stage.name))
    if description:
      stage.save_description(description)
    main_cmds = form.get(u'main_cmds_{}'.format(stage.name))
    if main_cmds:
      stage.save_main_script(main_cmds)
    is_trusted_stage = form.get(u'is_trusted_stage_{}'.format(
        stage.name)) is not None
    stage.save_is_trusted_stage(is_trusted_stage)
    files = flask.request.files.getlist(u'files_{}[]'.format(stage.name))
    if files:
      save_files_in_dir(files, stage.path)
  delete_stages = form.getlist('delete_stages'.format(stage.name))
  for delete_stage in delete_stages:
    stages.remove_stage(delete_stage)
  return errors


class GradeOvenSubmission(executor_queue_lib.ExecutorQueueTask):
  def __init__(self, priority, name, description, submission_dir, container_id,
               stages, student_submission):
    super(GradeOvenSubmission, self).__init__(priority, name, description)
    self._temp_dir = None
    self.submission_dir = submission_dir
    self.container_id = container_id
    self.stages = stages
    self.student_submission = student_submission
    self.container = None
    self.outputs = []
    self.errors = []

  def _run_stages_callback(self, stage):
    logging.info(u'GradeOvenSubmission._run_stages_callback %s', stage.name)
    if self.student_submission.assignment.due_date() is None or (
        self.student_submission.submit_time() <=
        self.student_submission.assignment.due_date()):
      self.student_submission.set_score(stage.name, stage.output.score)
    else:
      self.student_submission.set_past_due_date_score(stage.name,
                                                      stage.output.score)
    self.student_submission.set_output_html(stage.name,
                                            stage.output.output_html)
    self.student_submission.set_output(stage.name, stage.output.stdout)
    errors = '\n'.join(stage.output.errors)
    self.student_submission.set_errors(stage.name, errors)
    self.student_submission.set_status(u'running (finished {})'.format(
        stage.name))

  def before_run(self):
    logging.info(u'GradeOvenSubmission.before_run %s', self.description)
    self.student_submission.set_status('setting up')
    self._temp_dir = temp_dirs.get()
    if self._temp_dir is None:
      raise RuntimeError('No temporary directories available.')

  def run(self):
    logging.info(u'GradeOvenSubmission.run %s', self.description)
    self.container = executor.DockerExecutor(self.container_id, self._temp_dir)
    self.container.init()
    self.student_submission.set_status('running')
    username = self.student_submission.student_username
    user = grade_oven.user(username)
    env = {
        'GRADEOVEN_USERNAME': username,
        'GRADEOVEN_REAL_NAME': user.real_name(),
        'GRADEOVEN_DISPLAY_NAME': user.display_name(),
        'GRADEOVEN_COURSE_NAME': self.student_submission.course_name,
        'GRADEOVEN_ASSIGNMENT_NAME': self.student_submission.assignment_name,
    }
    output, errs = self.container.run_stages(
        self.submission_dir, self.stages, self._run_stages_callback, env=env)
    self.outputs.append(output)
    self.errors.extend(errs)

  def after_run(self):
    logging.info(u'GradeOvenSubmission.after_run %s', self.description)
    self.container.cleanup()
    temp_dirs.free(self._temp_dir)
    self.student_submission.set_status('finished')


def _int_or_0(x):
  try:
    return int(x)
  except ValueError:
    return 0


def _make_grade_table(course, assignment, show_real_names=False):
  header_row = [
      'Display Name', 'Score', 'Score (after due date)', 'Days Late',
      'Submit Time', 'Attempts'
  ]
  table = []
  due_date = assignment.due_date()
  if not due_date:
    header_row.remove('Score (after due date)')
    header_row.remove('Days Late')
  for username in course.student_usernames():
    row = []
    user = grade_oven.user(username)
    if not show_real_names and user.prefers_anonymity():
      continue
    if show_real_names:
      row.append(u'{} ({})'.format(user.display_name(), user.real_name()))
    else:
      row.append(user.display_name())
    submission = assignment.student_submission(username)
    submission_status = submission.status()
    if submission_status and submission_status not in ('finished',
                                                       'never run'):
      row.append(submission_status)
    else:
      row.append(submission.score())
    submit_time = submission.submit_time()
    if due_date:
      row.append(submission.past_due_date_score() or '')
      if submit_time and due_date:
        days_late = max(0, (submit_time - due_date) / SECONDS_PER_DAY)
        row.append('{:.0f}'.format(math.floor(days_late)))
      else:
        row.append('')
    if submit_time:
      row.append(
          time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(submit_time)))
    else:
      row.append('')
    row.append(submission.num_submissions())
    table.append(row)
  table = sorted(
      table, key=lambda row: (-_int_or_0(row[1]), row[-2], row[-1], row[0]))
  return header_row, table


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/download'
)
@login_required
def courses_x_assignments_x_download(course_name, assignment_name):
  user = login.current_user
  instructs_course = user.instructs_course(course_name)
  if instructs_course:
    stages = executor.Stages(
        os.path.join('../data/files/courses', course_name, 'assignments',
                     assignment_name))
    buf = six.BytesIO()
    stages.save_zip(buf)
    response = flask.make_response(buf.getvalue())
    response.headers['Content-Disposition'] = (
        'attachment; filename={}.zip'.format(assignment_name))
    return response
  else:
    return flask.redirect(
        u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
        code=303)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/download_submissions'
)
@login_required
def courses_x_assignments_x_download_submissions(course_name, assignment_name):
  user = login.current_user
  instructs_course = user.instructs_course(course_name)
  if instructs_course:
    course = grade_oven.course(course_name)
    assignment = course.assignment(assignment_name)
    buf = six.BytesIO()
    assignment.save_submissions_zip(buf)
    response = flask.make_response(buf.getvalue())
    response.headers['Content-Disposition'] = (
        'attachment; filename={} submissions.zip'.format(assignment_name))
    return response
  else:
    return flask.redirect(
        u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
        code=303)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/download_previous_submission'
)
@login_required
def courses_x_assignments_x_download_previous_submission(
    course_name, assignment_name):
  user = login.current_user
  takes_course = user.takes_course(course_name)
  if takes_course:
    course = grade_oven.course(course_name)
    assignment = course.assignment(assignment_name)
    buf = six.BytesIO()
    submission = assignment.student_submission(user.username)
    submission.save_submissions_zip(buf)
    response = flask.make_response(buf.getvalue())
    response.headers['Content-Disposition'] = (
        'attachment; filename={} submission.zip'.format(assignment_name))
    return response
  else:
    return flask.redirect(
        u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
        code=303)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/edit',
    methods=['POST'])
@login_required
def courses_x_assignments_x_edit(course_name, assignment_name):
  user = login.current_user
  instructs_course = user.instructs_course(course_name)
  if instructs_course:
    stages = executor.Stages(
        os.path.join('../data/files/courses', course_name, 'assignments',
                     assignment_name))
    form = flask.request.form
    for error in _edit_assignment(form, course_name, assignment_name, stages):
      flask.flash(error)
  return flask.redirect(
      u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
      code=303)


def _enqueue_student_submission(course_name, assignment_name, username, files):
  user = grade_oven.user(username)
  course = grade_oven.course(course_name)
  assignment = course.assignment(assignment_name)
  student_submission = assignment.student_submission(username)
  # If this is a resubmission, but there's no original submission, skip it.
  # if student_submission.num_submissions() == 0 and not files:
  #   return
  monitor_variables['assignment_attempts'] += 1
  logging.info(u'Student "%s" is attempting assignment "%s/%s".', username,
               course_name, assignment_name)
  submission_dir = os.path.join('../data/files/courses', course_name,
                                'assignments', assignment_name, 'submissions',
                                username)
  desc = u'{}_{}_{}'.format(course_name, assignment_name, username)
  # TODO: Fix the quick hack below.  It is only in place to avoid "escaped"
  # names that are not safe docker container names.
  container_id = str(abs(hash(desc)))[:32]
  num_submissions = student_submission.num_submissions()
  submit_time = student_submission.submit_time() or 0
  cur_time = time.time()
  min_seconds_since_last_submission = min(num_submissions**3, 5.0)
  priority = (num_submissions, submit_time)
  stages = executor.Stages(
      os.path.join('../data/files/courses', course_name, 'assignments',
                   assignment_name))
  submission = GradeOvenSubmission(priority, username, desc, submission_dir,
                                   container_id, stages, student_submission)
  if submission in executor_queue:
    logging.warning(
        u'Student "%s" submited assignment "%s/%s" while still in the queue.',
        username, course_name, assignment_name)
    flask.flash(
        u'{} cannot submit assignment {} for {} while in the queue.'.format(
            username, assignment_name, course_name))
  elif cur_time < submit_time + min_seconds_since_last_submission:
    seconds_left = min_seconds_since_last_submission - (cur_time - submit_time)
    formatted_time = time.strftime(
        '%Y-%m-%d %H:%M:%S',
        time.localtime(submit_time + min_seconds_since_last_submission))
    logging.info(u'Student "%s" submitted assignment "%s/%s" '
                 'but needs to wait until %s (%s seconds).', username,
                 course_name, assignment_name, formatted_time, seconds_left)
    flask.flash(
        u'Please wait until {} ({:.0f} seconds) to submit {} again.'.format(
            formatted_time, seconds_left, assignment_name))
  else:
    if files:
      try:
        shutil.rmtree(submission_dir)
      except OSError as e:
        if e.errno != errno.ENOENT:
          raise e
      save_files_in_dir(files, submission_dir)
      # If there are no files being uploaded, then this must be a resubmission.
      student_submission.set_submit_time()
      student_submission.set_num_submissions(
          student_submission.num_submissions() + 1)
    student_submission.set_status('queued')
    executor_queue.enqueue(submission)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/submit',
    methods=['POST'])
@login_required
def courses_x_assignments_x_submit(course_name, assignment_name):
  user = login.current_user
  takes_course = user.takes_course(course_name)
  if takes_course:
    files = flask.request.files.getlist('submission_files[]')
    if files:
      _enqueue_student_submission(course_name, assignment_name, user.username,
                                  files)
  return flask.redirect(
      u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
      code=303)


# TODO: This is very specific to Canvas as of 2017-03. Make it generic.
# TODO: This function exposes too many internals. Encapsulate them.
# TODO: This function reimplements logic that is elsewhere. Reuse code.
@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/submit_all',
    methods=['POST'])
@login_required
def courses_x_assignments_x_submit_all(course_name, assignment_name):
  user = login.current_user
  instructs_course = user.instructs_course(course_name)
  files = None
  if instructs_course:
    student_usernames = frozenset(
        grade_oven.course(course_name).student_usernames())
    # Build map of normalized_student_real_names to potential student_usernames
    normalized_student_real_names = collections.defaultdict(set)
    for student_username in student_usernames:
      student_user = grade_oven.user(student_username)
      real_name = student_user.real_name()
      normalized_student_real_names[real_name].add(student_username)
      real_name_parts = real_name.lower().split()
      for name_parts in itertools.permutations(real_name_parts,
                                               min(4, len(real_name_parts))):
        normalized_student_real_names[''.join(name_parts)].add(
            student_username)
    files = flask.request.files.getlist('all_submission_files[]')
    temp_dirname = tempfile.mkdtemp()
    if 1:
      for f in files:
        with zipfile.ZipFile(f.stream, 'r') as zf:
          for filename in zf.namelist():
            normalized_real_name = filename.split('_', 1)[0]
            student_usernames = normalized_student_real_names[
                normalized_real_name]
            if len(student_usernames) == 0:
              flask.flash(
                  'Zipped file "{}" could not be associated with any student.'.
                  format(filename))
            elif len(student_usernames) > 1:
              flask.flash(
                  'Zipped file "{}" associated with multiple students: {}.'.
                  format(filename, ', '.join(student_usernames)))
            else:
              student_username = student_usernames.pop()
              submission_dir = os.path.join(
                  '../data/files/courses', course_name, 'assignments',
                  assignment_name, 'submissions', student_username)
              try:
                shutil.rmtree(submission_dir)
              except OSError as e:
                if e.errno != errno.ENOENT:
                  raise e
              try:
                os.makedirs(submission_dir)
              except OSError as e:
                if e.errno != errno.EEXIST:
                  raise e
              _enqueue_student_submission(course_name, assignment_name,
                                          student_username, None)
    shutil.rmtree(temp_dirname)
  return flask.redirect(
      u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
      code=303)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/resubmit_all',
    methods=['POST'])
@login_required
def courses_x_assignments_x_resubmit_all(course_name, assignment_name):
  user = login.current_user
  instructs_course = user.instructs_course(course_name)
  files = None
  if instructs_course:
    for username in grade_oven.course(course_name).student_usernames():
      _enqueue_student_submission(course_name, assignment_name, username,
                                  files)
  return flask.redirect(
      u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
      code=303)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>')
@login_required
def courses_x_assignments_x(course_name, assignment_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  assignment = course.assignment(assignment_name)
  student_submission = assignment.student_submission(user.username)
  instructs_course = user.instructs_course(course.name)
  takes_course = user.takes_course(course.name)
  stages = executor.Stages(
      os.path.join('../data/files/courses', course.name, 'assignments',
                   assignment.name))
  if takes_course:
    due_date = assignment.due_date()
    if due_date is None:
      formatted_due_date = ''
    else:
      formatted_due_date = time.strftime('%Y-%m-%d %H:%M',
                                         time.localtime(due_date))
    submission_output = student_submission.output()
    submission_has_output_html = bool(student_submission.output_html())
    submission_errors = student_submission.errors().strip()
  else:
    formatted_due_date = ''
    submission_output, submission_errors = '', ''
    submission_has_output_html = False
  header_row, table = _make_grade_table(
      course, assignment, show_real_names=instructs_course)
  return flask.render_template(
      'courses_x_assignments_x.html',
      username=login.current_user.get_id(),
      instructs_course=instructs_course,
      takes_course=takes_course,
      course_name=course.name,
      assignment_name=assignment.name,
      formatted_due_date=formatted_due_date,
      stages=stages.stages.values(),
      submission_output=submission_output,
      submission_has_output_html=submission_has_output_html,
      submission_errors=submission_errors,
      stages_desc=stages.description,
      header_row=header_row,
      table=table)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/output_html/<string:username>'
)
@login_required
def courses_x_assignments_x_output_html_x(course_name,
                                          assignment_name,
                                          username=None):
  user = login.current_user if username is None else grade_oven.user(username)
  if user.instructs_course(course_name) or user.takes_course(course_name):
    course = grade_oven.course(course_name)
    assignment = course.assignment(assignment_name)
    student_submission = assignment.student_submission(user.username)
    submission_output_html = student_submission.output_html()
    return flask.render_template(
        'courses_x_assignments_x_output_html.html',
        username=login.current_user.get_id(),
        submission_output_html=submission_output_html)
  else:
    return flask.redirect(
        u'/courses/{}/assignments/{}'.format(course_name, assignment_name),
        code=303)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/output_html'
)
@login_required
def courses_x_assignments_x_output_html(course_name, assignment_name):
  return courses_x_assignments_x_output_html_x(course_name, assignment_name)


@app.route(
    '/courses/<string:course_name>/assignments/<string:assignment_name>/submissions',
    methods=['GET', 'POST'])
@login_required
def courses_x_assignments_x_submissions(course_name, assignment_name):
  user = login.current_user
  course = grade_oven.course(course_name)
  assignment = course.assignment(assignment_name)
  instructs_course = user.instructs_course(course.name)
  student_submissions = []
  if instructs_course:
    form = flask.request.form
    student_username = form.get('_student_username')
    manual_score = form.get('manual_score')
    if student_username and manual_score is not None:
      submission = assignment.student_submission(student_username)
      try:
        submission.set_manual_score_portion(int(manual_score))
      except ValueError:
        flask.flash(
            'Manual score "{}" is not an integer.'.format(manual_score))
    for student_username in course.student_usernames():
      student_submissions.append(
          assignment.student_submission(student_username))
  return flask.render_template(
      'courses_x_assignments_x_submissions.html',
      username=login.current_user.get_id(),
      instructs_course=instructs_course,
      course_name=course.name,
      assignment_name=assignment.name,
      student_submissions=student_submissions)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
  user = login.current_user
  errors = []

  form = flask.request.form
  real_name = form.get('real_name')
  if real_name:
    real_name = real_name[:256]
    user.set_real_name(real_name)
  display_name = form.get('display_name')
  if display_name:
    display_name = display_name[:30]
    user.set_display_name(display_name)
  prefers_anonymity = form.get('prefers_anonymity')
  if prefers_anonymity:
    user.set_prefers_anonymity(True)
  else:
    user.set_prefers_anonymity(False)
  password = form.get('password')
  password2 = form.get('password2')
  if password or password2:
    if password == password2:
      user.set_password(password)
    else:
      errors.append('Passwords do not match.')

  return flask.render_template(
      'settings.html',
      username=login.current_user.get_id(),
      real_name=user.real_name(),
      display_name=user.display_name(),
      prefers_anonymity=user.prefers_anonymity(),
      errors=errors)


@app.route('/')
@nothing_required
def index():
  if login.current_user.is_authenticated:
    if login.current_user.is_admin():
      return flask.redirect('/admin')
    else:
      return flask.redirect('/courses')
  else:
    return flask.redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
@nothing_required
def login_():
  form = flask.request.form
  username = escape_lib.safe_entity_name(form.get('username'))
  password = form.get('password')
  if username and password:
    user = grade_oven_lib.GradeOvenUser.load_and_authenticate_user(
        data_store, username, password)
    if user is None:
      monitor_variables['login_failures'] += 1
      return flask.abort(401)
    else:
      monitor_variables['login_successes'] += 1
      login.login_user(user, remember=True)
      redirect = flask.request.args.get('redirect', '/')
      return flask.redirect(redirect, code=303)
  return flask.render_template(
      'login.html', username=login.current_user.get_id())


@app.route('/logout')
@login_required
def logout():
  monitor_variables['logouts'] += 1
  login.logout_user()
  return flask.redirect('/')


def get_command_line_options():
  parser = optparse.OptionParser()
  parser.add_option(
      '--debug',
      action='store_true',
      dest='debug',
      default=True,
      help='Run in debug mode (instead of production mode).')
  parser.add_option(
      '--prod',
      action='store_false',
      dest='debug',
      default=True,
      help='Run in production mode (instead of debug mode).')
  parser.add_option(
      '--port',
      action='store',
      dest='port',
      type='int',
      default=None,
      help='Port to listen to.')
  parser.add_option(
      '--host',
      action='store',
      dest='host',
      type='string',
      default=None,
      help='Host name to listen to.')

  options, _ = parser.parse_args()
  return options


def main():
  options = get_command_line_options()
  if not data_store.get_all(('admins', )):
    user = grade_oven.user('admin')
    user.set_password('admin')
    user.set_is_admin(True)
  if not data_store.get_all(('monitors', )):
    user = grade_oven.user('monitor')
    with open('../data/secret_key.txt') as f:
      user.set_password(f.read())
    user.set_is_monitor(True)

  context = ('../data/ssl/server.crt', '../data/ssl/server.key')

  # logging.basicConfig(filename='../data/server.log', level=logging.DEBUG)
  logging.basicConfig(level=logging.DEBUG)

  # TODO: add logging
  if options.port is None:
    options.port = 4321 if options.debug else 443
  if options.host is None:
    options.host = 'localhost' if options.debug else '0.0.0.0'
  app.run(
      host=options.host,
      port=options.port,
      debug=options.debug,
      use_reloader=False,
      use_debugger=options.debug,
      ssl_context=context,
      use_evalex=False,
      threaded=True)


if __name__ == '__main__':
  main()
