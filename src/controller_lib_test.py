import unittest

import controller_lib


class TestExecutor(unittest.TestCase):
  def test_ResourcePool(self):
    with self.assertRaises(ValueError):
      controller_lib.ResourcePool(['baz', 'foo', 'bar', 'baz'])
    pool = controller_lib.ResourcePool(['foo', 'bar', 'baz'])
    self.assertEqual(3, len(pool))
    found_resources = set()
    for _ in ['foo', 'bar', 'baz']:
      found_resources.add(pool.get())
    self.assertEqual(set(['foo', 'bar', 'baz']), found_resources)
    self.assertEqual(None, pool.get())
    self.assertEqual(0, len(pool))
    pool.free('bar')
    self.assertEqual(1, len(pool))
    with self.assertRaises(KeyError):
      pool.free('bar')
    with self.assertRaises(KeyError):
      pool.free('not-a-resource')
    pool.free('foo')
    self.assertEqual(2, len(pool))
    pool.free('baz')
    self.assertEqual(3, len(pool))


if __name__ == '__main__':
  unittest.main()
