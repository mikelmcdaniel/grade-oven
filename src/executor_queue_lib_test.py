import itertools
import threading
import unittest
import random

import executor_queue_lib

class TestExecutor(unittest.TestCase):
  def test_one_submission(self):
    nonce = []
    def closure():
      nonce.append('nonce')
    executor_queue = executor_queue_lib.ExecutorQueue()
    submission = executor_queue_lib.Submission(
      closure, 'arbitrary priority', 'short description')
    executor_queue.enqueue(submission)
    executor_queue.join()
    self.assertEqual(nonce, ['nonce'])

  def test_multiple_submissions(self):
    nonce = set()
    def closure1():
      nonce.add('one')
    def closure2():
      nonce.add('two')
    def closure3():
      nonce.add('three')
    submission1 = executor_queue_lib.Submission(
      closure1, 'arbitrary priority', 'first description')
    submission2 = executor_queue_lib.Submission(
      closure2, 'arbitrary priority', 'second description')
    submission3 = executor_queue_lib.Submission(
      closure3, 'arbitrary priority', 'third description')
    executor_queue = executor_queue_lib.ExecutorQueue()
    executor_queue.enqueue(submission1)
    executor_queue.enqueue(submission2)
    executor_queue.enqueue(submission3)
    executor_queue.join()
    self.assertEqual(nonce, set(['one', 'two', 'three']))

  def test_submission_ordering(self):
    sorted_submissions = [
      executor_queue_lib.Submission(lambda: None, j, str(j))
      for j in xrange(10)]
    shuffled_submissions = [
      executor_queue_lib.Submission(lambda: None, j, str(j))
      for j in xrange(10)]
    random.shuffle(shuffled_submissions)
    self.assertEqual(sorted_submissions, sorted(shuffled_submissions))

    submission1 = sorted_submissions[1]
    submission2 = sorted_submissions[2]
    self.assertLess(submission1, submission2)
    self.assertNotEqual(submission1, submission2)

  def test_priorities(self):
    nonce = []
    nonce_lock = threading.Lock()
    def null_closure():
      nonce_lock.acquire()
      nonce_lock.release()
    def closure1():
      nonce_lock.acquire()
      nonce_lock.release()
      nonce.append('first')
    def closure2():
      nonce_lock.acquire()
      nonce_lock.release()
      nonce.append('second')
    def closure3():
      nonce_lock.acquire()
      nonce_lock.release()
      nonce.append('third')
    # The null submission is necessary since as soon as it's queued, it will
    # be started since nothing else is in the queue and max_threads == 1.
    null_submission = executor_queue_lib.Submission(
      null_closure, 1000, 'null submission')
    submission1 = executor_queue_lib.Submission(
      closure1, 1, 'most important')
    submission2 = executor_queue_lib.Submission(
      closure2, 2, 'meh')
    submission3 = executor_queue_lib.Submission(
      closure3, 3, 'least important')
    executor_queue = executor_queue_lib.ExecutorQueue(max_threads=1)
    nonce_lock.acquire()
    executor_queue.enqueue(null_submission)
    executor_queue.enqueue(submission3)
    executor_queue.enqueue(submission1)
    executor_queue.enqueue(submission2)
    nonce_lock.release()
    executor_queue.join()
    self.assertEqual(nonce, ['first', 'second', 'third'])

    # Test all permutations of length 3, just to be safe
    for s1, s2, s3 in itertools.permutations(
        (submission1, submission2, submission3)):
      del nonce[:]
      self.assertEqual(nonce, [])
      nonce_lock.acquire()
      executor_queue.enqueue(null_submission)
      executor_queue.enqueue(s1)
      executor_queue.enqueue(s2)
      executor_queue.enqueue(s3)
      nonce_lock.release()
      executor_queue.join()
      self.assertEqual(nonce, ['first', 'second', 'third'])



if __name__ == '__main__':
  unittest.main()
