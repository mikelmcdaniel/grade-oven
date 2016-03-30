"""An ExecutorQueue runs in a separate thread and is used to queue
and run stages against student submissions in separate Python threads.

Note that because executor mostly uses subprocess to run code, it is
not necessary to use multiprocessing to get good parallism.

See executor_queue_lib_test.py for example usage.
"""

import collections
import functools
import threading
import Queue as queue
import logging

@functools.total_ordering
class Submission(object):
  # Possible stages:
  QUEUED = 'queued'
  RUNNING = 'running'
  DONE = 'done'
  def __init__(self, priority, name, description, closure=None):
    self.closure = closure
    self.priority = priority
    self.name = name
    self.description = description
    self.status = self.QUEUED

  def before_run(self):
    pass

  def run(self):
    self.closure()

  def after_run(self):
    pass

  def __hash__(self):
    return hash(self.name)

  def __ne__(self, other):
    return not self == other

  def __eq__(self, other):
    return self.name == other

  def __le__(self, other):
    return self.name < other


class ExecutorThread(threading.Thread):
  def __init__(self, submission, release_func):
    super(ExecutorThread, self).__init__()
    self.daemon = False
    self.submission = submission
    self.name = 'ExecutorThread {}:{}'.format(self.submission.name,
                                              self.submission.description)
    self._release_func = release_func

  def run(self):
    self.submission.status = Submission.RUNNING
    try:
      self.submission.before_run()
      self.submission.run()
    finally:
      self.submission.status = Submission.DONE
      self.submission.after_run()
      self._release_func()


class ExecutorQueue(object):
  def __init__(self, max_threads=3):
    # priority queue picks things with a lesser value first
    self._submission_queue = queue.PriorityQueue()
    self._submission_set = set()
    self._threads_semaphore = threading.BoundedSemaphore(max_threads)
    self._running_threads = collections.deque()
    self._running_threads_lock = threading.Lock()

  def __contains__(self, submission):
    return submission in self._submission_set

  def enqueue(self, submission):
    if submission not in self._submission_set:
      self._submission_set.add(submission)
      self._submission_queue.put((submission.priority, submission))
      self.maybe_execute()
      return True
    else:
      return False

  def _maybe_cleanup_threads(self):
    threads_to_remove = 0
    with self._running_threads_lock:
      for t in self._running_threads:
        if t.is_alive():
          break
        threads_to_remove += 1
      for _ in xrange(threads_to_remove):
        self._running_threads.popleft()

  def join(self):
    while True:
      with self._running_threads_lock:
        try:
          t = self._running_threads[0]
        except IndexError:  # no threads are running
          break
          t.join()
      self._maybe_cleanup_threads()

  def _release_func(self, submission):
    self._submission_set.discard(submission)
    self._submission_queue.task_done()
    self._threads_semaphore.release()
    self.maybe_execute()

  def maybe_execute(self):
    if self._threads_semaphore.acquire(blocking=False):
      try:
        _, submission = self._submission_queue.get(block=False)
      except queue.Empty:
        submission = None
        self._threads_semaphore.release()
      if submission is not None:
        t = ExecutorThread(
          submission, functools.partial(self._release_func, submission))
        t.start()
        with self._running_threads_lock:
          self._running_threads.append(t)


