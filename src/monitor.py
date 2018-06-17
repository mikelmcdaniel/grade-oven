"""A simple program which probes the GradeOven --server_address
and writes the results to --log_file.

It's an incredibly simple and weak way to collect data for debugging.
"""

import collections
import cookielib
import io
import json
import logging
import mechanize
import optparse
import random
import ssl
import time
from typing import IO, Text
import urllib2
import urlparse

# Attempt to make Python to not verify SSL
# Ideally, this would check that the certificate from Grade Oven matches
# what's expected instead of ignoring it altogether.
try:
  _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
  # We're running a legacy Python version that doesn't verify HTTPS certificates
  pass
else:
  ssl._create_default_https_context = _create_unverified_https_context


def ping(url: Text, expected_response: Text = None) -> bool:
  'Open a URL, with some retrying, and check the response.'
  resp = None
  for j in range(3):
    try:
      resp = urllib2.urlopen(url, timeout=3.0)
      break
    except urllib2.URLError as e:
      logging.error(e)
      time.sleep(2**j)
  return resp is not None and (expected_response is None
                               or resp.read() == expected_response)


def server_is_up(host: Text) -> bool:
  return ping(urlparse.urljoin(host, '/debug/ping'), 'pong')


def scrape_variables(host: Text, logs_file: IO) -> None:
  br = mechanize.Browser()
  cj = cookielib.LWPCookieJar()
  br.set_cookiejar(cj)
  br.set_handle_equiv(True)
  # br.set_handle_gzip(True)
  br.set_handle_redirect(True)
  br.set_handle_referer(True)
  br.set_handle_robots(False)

  login_url = urlparse.urljoin(host, '/login')
  logging.info('Starting login into %s', login_url)
  response = br.open(login_url)
  br.form = next(iter(br.forms()))
  br.form['username'] = 'monitor'
  with open('../data/secret_key.txt') as f:
    br.form['password'] = f.read()
  br.method = 'POST'
  br.submit()
  br.method = 'GET'
  logging.info('Successfully logged into %s', login_url)

  variables_url = urlparse.urljoin(host, '/monitor/variables')
  while True:
    try:
      response = br.open(variables_url)
    except urllib2.URLError as e:
      logging.error('Could not open "%s": %s', variables_url, e)
      time.sleep(59 + random.random())
      continue
    raw_vars = response.read()
    logs_file.write(raw_vars)
    logs_file.write('\n')
    # variables = json.loads(raw_vars)
    time.sleep(59 + random.random())


def get_command_line_options():
  parser = optparse.OptionParser()
  parser.add_option(
      '--server_address',
      action='store',
      dest='server_address',
      type='string',
      default='https://localhost:4321',
      help='Server URL to send requests to.')
  parser.add_option(
      '--log_file',
      action='store',
      dest='log_file',
      type='string',
      default='scrape_logs.txt',
      help='File to save raw scrape logs to.')

  options, _ = parser.parse_args()
  return options


def main() -> None:
  options = get_command_line_options()
  with open(options.log_file, 'a') as log_file:
    scrape_variables(options.server_address, log_file)


if __name__ == '__main__':
  main()
