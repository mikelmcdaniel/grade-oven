import errno
import optparse
import os
import random
import time
import subprocess


def maybe_makedirs(path):
  try:
    os.makedirs(path)
  except OSError as e:
    if e.errno != errno.EEXIST:
      raise Error(e)


def get_command_line_options():
  parser = optparse.OptionParser()
  parser.add_option('--debug',
                    action='store_true', dest='debug', default=True,
                    help='Run in debug mode (instead of production mode).')
  parser.add_option('--prod',
                    action='store_false', dest='debug', default=True,
                    help='Run in production mode (instead of debug mode).')

  options, _ = parser.parse_args()
  return options


def main():
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

  def run_server():
    return subprocess.Popen(
      ['authbind', 'python2', 'server.py', prod_debug_flag,
       '--host', host, '--port', str(port)],
      stdout=open('../data/logs/server-stdout.txt', 'a'),
      stderr=open('../data/logs/server-stderr.txt', 'a'),
      close_fds=True, shell=False, env={})

  def run_monitor():
    return subprocess.Popen(
      ['python2', 'monitor.py', '--server_address', server_address,
       '--log_file', '../data/logs/monitor-scrapes.txt'],
      stdout=open('../data/logs/monitor-stdout.txt', 'a'),
      stderr=open('../data/logs/monitor-stderr.txt', 'a'),
      close_fds=True, shell=False, env={})

  server_proc = run_server()
  monitor_proc = run_monitor()
  while True:
    if server_proc.poll() is not None:
      time.sleep(1)
      server_proc = run_server()
    if monitor_proc.poll() is not None:
      time.sleep(1)
      monitor_proc = run_monitor()
    time.sleep(1 + random.random())

if __name__ == '__main__':
  main()