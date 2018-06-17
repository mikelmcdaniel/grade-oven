"""An ExecutorQueue runs in a separate thread and is used to queue
and run stages against student submissions in separate Python threads.

Note that because executor mostly uses subprocess to run code, it is
not necessary to use multiprocessing to get good parallism.

See executor_queue_lib_test.py for example usage.
"""

import collections
import functools
import threading
from typing import Any, Callable, Set, Text
from six.moves import queue
import logging

@functools.total_ordering
class Submission(object):
  # Possible stages:
  QUEUED = 'queued'
  RUNNING = 'running'
  DONE = 'done'
  def __init__(
      self, priority, name: Text, description: Text,
      closure: Callable[[], Any]=None) -> None:
    self.closure = closure
    self.priority = priority
    self.name = name
    self.description = description
    self.status = self.QUEUED

  def before_run(self) -> None:
    pass

  def run(self) -> None:
    self.closure()

  def after_run(self) -> None:
    pass

  def __hash__(self):
    return hash(self.name)

  def __ne__(self, other):
    return not self == other

  def __eq__(self, other):
    return self.name == other.name

  def __le__(self, other):
    return self.name < other.name


class ExecutorThread(threading.Thread):
  def __init__(
      self, submission: Submission, release_func: Callable[[], Any]) -> None:
    super(ExecutorThread, self).__init__()
    self.daemon = False
    self.submission = submission
    self.name = 'ExecutorThread {}:{}'.format(self.submission.name,
                                              self.submission.description)
    self._release_func = release_func

  def run(self) -> None:
    self.submission.status = Submission.RUNNING
    try:
      self.submission.before_run()
      self.submission.run()
    except Exception as e:
      logging.error('Submission failed to run: {!r}'.format(e))
    finally:
      self.submission.status = Submission.DONE
      self.submission.after_run()
      self._release_func()

class ExecutorQueue(object):
  def __init__(self, max_threads=3):
    # priority queue picks things with a lesser value first
    self._submission_queue = queue.PriorityQueue()
    self._submission_set = set()  # type: Set[Submission]
    self._threads_semaphore = threading.BoundedSemaphore(max_threads)
    self._thread = threading.Thread(None, self.__run, 'ExecutorQueue.__run')
    self._thread.daemon = True
    self._thread.start()

  def __run(self) -> None:
    while True:
      self._threads_semaphore.acquire()
      _, submission = self._submission_queue.get()
      t = ExecutorThread(submission,
                         functools.partial(self.__release_func, submission))
      t.start()

  def __release_func(self, submission: Submission) -> None:
    self._submission_set.discard(submission)
    self._submission_queue.task_done()
    self._threads_semaphore.release()

  def __contains__(self, submission: Submission) -> bool:
    return submission in self._submission_set

  def enqueue(self, submission: Submission) -> bool:
    if submission not in self._submission_set:
      self._submission_set.add(submission)
      self._submission_queue.put((submission.priority, submission))
      return True
    else:
      return False

  def join(self) -> None:
    self._submission_queue.join()
