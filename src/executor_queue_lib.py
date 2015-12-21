"""An ExecutorQueue runs in a separate thread and is used to queue
and run stages against student submissions in separate Python threads.
Unlike the Executor class, ExecutorQueue is tightly coupled with Grade Oven.

Note that because executor mostly uses subprocess to run code, it is
not necessary to use multiprocessing to get good parallism.
"""

import collections
import functools
import threading
import Queue as queue
import logging

import executor

@functools.total_ordering
class Submission(object):
  def __init__(self, closure, priority, short_desc, long_desc=None):
    if long_desc is None:
      long_desc = short_desc
    self.closure = closure
    self.priority = priority
    self.short_description = short_desc
    self.description = long_desc

  def __ne__(self, other):
    return not self == other

  def __eq__(self, other):
    return self.priority == other

  def __le__(self, other):
    return self.priority < other


class ExecutorThread(threading.Thread):
  def __init__(self, submission, release_func):
    super(ExecutorThread, self).__init__()
    self.daemon = False
    self.submission = submission
    self.name = 'ExecutorThread {}'.format(self.submission.short_description)
    self._release_func = release_func

  def run(self):
    try:
      self.submission.closure()
    finally:
      self._release_func()


class ExecutorQueue(object):
  def __init__(self, max_threads=3):
    # priority queue picks things with a lesser value first
    self._submission_queue = queue.PriorityQueue()
    self._threads_semaphore = threading.BoundedSemaphore(max_threads)
    self._running_threads = collections.deque()

  def enqueue(self, submission):
    self._submission_queue.put(submission)
    self.maybe_execute()

  def _maybe_cleanup_threads(self):
    threads_to_remove = 0
    for t in self._running_threads:
      if t.is_alive():
        break
      threads_to_remove += 1
    for _ in xrange(threads_to_remove):
      self._running_threads.popleft()

  def join(self):
    while True:
      try:
        t = self._running_threads.popleft()
      except IndexError:  # no threads are running
        break
      t.join()
      self._maybe_cleanup_threads()

  def _release_func(self):
    self._submission_queue.task_done()
    self._threads_semaphore.release()
    self.maybe_execute()

  def maybe_execute(self):
    if self._threads_semaphore.acquire(blocking=False):
      try:
        submission = self._submission_queue.get(block=False)
      except queue.Empty:
        submission = None
        self._threads_semaphore.release()
      if submission is not None:
        t = ExecutorThread(submission, self._release_func)
        t.start()
        self._running_threads.append(t)


