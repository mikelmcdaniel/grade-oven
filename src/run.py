"""This script performs minimal setup, then starts the server and monitor.

This script can run in --debug or --prod mode.
The server and monitor are automatically restarted when the corresponding
processes die and their STDOUT/STDERR are written out to .txt logs in
../data/logs.
"""

import errno
import logging
import optparse
import os
import random
import time
from typing import Dict, Text
import subprocess

import monitor


def maybe_makedirs(path: Text) -> None:
  try:
    os.makedirs(path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise e


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

  options, _ = parser.parse_args()
  return options


def main() -> None:
  options = get_command_line_options()
  prod_debug_flag = '--debug' if options.debug else '--prod'

  if options.debug:
    prod_debug_flag = '--debug'
    port = 4321
    host = 'localhost'
  else:
    prod_debug_flag = '--prod'
    port = 443
    host = '0.0.0.0'

  server_address = 'https://localhost:{}'.format(port)

  maybe_makedirs('../data/logs')

  def run_server() -> subprocess.Popen:
    env = {}  # type: Dict[Text, Text]
    return subprocess.Popen(
        [
            'authbind', 'python2', 'server.py', prod_debug_flag, '--host',
            host, '--port',
            str(port)
        ],
        stdout=open('../data/logs/server-stdout.txt', 'a'),
        stderr=open('../data/logs/server-stderr.txt', 'a'),
        close_fds=True,
        shell=False,
        env=env)

  def run_monitor() -> subprocess.Popen:
    env = {}  # type: Dict[Text, Text]
    return subprocess.Popen(
        [
            'python2', 'monitor.py', '--server_address', server_address,
            '--log_file', '../data/logs/monitor-scrapes.txt'
        ],
        stdout=open('../data/logs/monitor-stdout.txt', 'a'),
        stderr=open('../data/logs/monitor-stderr.txt', 'a'),
        close_fds=True,
        shell=False,
        env=env)

  server_proc = run_server()
  monitor_proc = run_monitor()
  time.sleep(3)

  while True:
    # Poll the processes frequently and do a proper ping infrequently.
    for j in range(10):
      if server_proc.poll() is not None:
        logging.warning('Restarting server')
        server_proc = run_server()
      if monitor_proc.poll() is not None:
        logging.warning('Restarting monitor')
        monitor_proc = run_monitor()
      time.sleep(1 + random.random())
    if not monitor.server_is_up(server_address):
      logging.error('Server is not up. Killing server...')
      server_proc.kill()
      logging.error('Server killed.')


if __name__ == '__main__':
  main()
