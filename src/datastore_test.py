import six
import shutil
import tempfile
import unittest

import datastore


class TestDataStore(unittest.TestCase):

  def test_DataStore(self):
    key1 = ('courses', six.unichr(9835), 'assignments', 'homework 1')
    key2 = ('courses', six.unichr(9835), 'assignments', 'homework 2' + six.unichr(9835))
    key3 = ('courses', 'python', 'assignments', 'homework 1')
    temp_dir = tempfile.mkdtemp()
    try:
      store = datastore.DataStore(temp_dir)
      store.put(key1, b'c++ 1')
      store.put(key2, u'c++ 2')
      store[key3] = 'python 1'
      self.assertEqual(set(store.get_all(('courses',))),
                       set([six.unichr(9835), 'python']))
      self.assertEqual(store.get(key1), 'c++ 1')
      self.assertEqual(store[key3], 'python 1')
      store.remove(('courses', six.unichr(9835)))
      self.assertEqual(set(store.get_all(('courses',))), set(['python']))
      self.assertIn(('courses',), store)
      self.assertIn(('courses', 'python'), store)
      self.assertIn(('courses', 'python', 'assignments', 'homework 1'), store)
      del store[('courses', 'python', 'assignments', 'homework 1')]
      self.assertNotIn(
        ('courses', 'python', 'assignments', 'homework 1'), store)
      self.assertEqual(set(store.get_all(('courses', 'nothing'))), set())
      self.assertEqual(
        store.get(('does', 'not', 'exist' + six.unichr(9835)), 'DEFAULT VAL'),
        'DEFAULT VAL')
    finally:
      shutil.rmtree(temp_dir)


if __name__ == '__main__':
  unittest.main()
