"""This module provides a simple hierarchical DataStore where keys are tuples
of ASCII strings and values are basic Python types (e.g. int, str, None).

See the example at the bottom of datastore.py for an example of
how to use it or look at this simple example:

  key = ('courses', 'c++', 'assignments')
  store = DataStore(temp_dir)
  store.put(key, 'homework 1')
  store.put(key, 'homework 2')
  store[key3] = 'python 1'  # same as .put(...)
  del store[('courses', 'c++')]  # same as .remove(...)
  assert set(store.get_all(('courses',))) == set(['python'])
"""

import json
import os
import shutil
import six
import tempfile

import leveldb

_JSON_NULL = bytes(json.dumps(None).encode('utf-8'))

# TODO: Allow keys to be arbitrary
# TODO: Make concurrent deletions/puts atomic with respect to eachother
class DataStore(object):
  def __init__(self, dir_path=None):
    if dir_path is None:
      dir_path = tempfile.mkdtemp()
    self.db = leveldb.LevelDB(dir_path, paranoid_checks=True)

  def put(self, key, value=None):
    # TODO: Before moving to Python3, decoding bytes was not necessary.
    # Add proper support for writing bytes.
    if isinstance(value, bytes):
      value = value.decode('utf-8')

    mods = leveldb.WriteBatch()
    partial_key = []
    for j, key_part in enumerate(key, 1):
      partial_key.append('\x00')
      partial_key[0] = six.unichr(j)
      partial_key.append(key_part)
      pk = bytearray(''.join(partial_key), 'utf-8')
      mods.Put(pk, _JSON_NULL)
    mods.Put(pk, bytes(json.dumps(value).encode('utf-8')))
    self.db.Write(mods)

  def __setitem__(self, key, value):
    return self.put(key, value)

  def __getitem__(self, key):
    real_key = []
    for key_part in key:
      real_key.append('\x00')
      real_key.append(key_part)
    real_key[0] = six.unichr(len(key))
    raw_value = self.db.Get(bytearray(''.join(real_key), 'utf-8'))
    value = json.loads(raw_value)
    return value

  def get(self, key, default_value=None):
    try:
      return self[key]
    except KeyError:
      return default_value

  def __contains__(self, key):
    try:
      self[key]
      return True
    except KeyError:
      return False

  def get_all(self, key):
    real_key = []
    real_key.append(chr(len(key) + 1))
    real_key.append('\x00'.join(key))
    start_key = ''.join(real_key)
    real_key.append('\x01')
    end_key = ''.join(real_key)
    sub_keys = []
    for sub_key in self.db.RangeIter(
        bytearray(start_key, 'utf-8'), bytearray(end_key, 'utf-8'),
        include_value=False):
      sub_keys.append(sub_key[sub_key.rfind(b'\x00') + 1:].decode('utf-8'))
    return sub_keys

  def remove(self, key):
    real_key = []
    real_key.append(six.unichr(len(key)))
    real_key.append('\x00'.join(key))
    mods = leveldb.WriteBatch()
    for j in six.moves.xrange(len(key), 256):
      real_key[0] = six.unichr(j)
      start_key = ''.join(real_key)
      end_key = start_key + '\x01'
      found_keys = False
      for k in self.db.RangeIter(
          bytearray(start_key, 'utf-8'), bytearray(end_key, 'utf-8'),
          include_value=False):
        mods.Delete(k)
        found_keys = True
      if not found_keys:
        break
    self.db.Write(mods)

  def __delitem__(self, key):
    return self.remove(key)


if __name__ == '__main__':
  key1 = ('courses', six.unichr(9835), 'assignments', 'homework 1')
  key2 = ('courses', six.unichr(9835), 'assignments', 'homework 2' + six.unichr(9835))
  key3 = ('courses', 'python', 'assignments', 'homework 1')
  temp_dir = tempfile.mkdtemp()
  try:
    store = DataStore(temp_dir)
    store.put(key1, b'c++ 1')
    store.put(key2, u'c++ 2')
    store[key3] = 'python 1'
    assert set(store.get_all(('courses',))) == set([six.unichr(9835), 'python'])
    assert store.get(key1) == 'c++ 1'
    assert store[key3] == 'python 1'
    store.remove(('courses', six.unichr(9835)))
    assert set(store.get_all(('courses',))) == set(['python'])
    assert ('courses',) in store
    assert ('courses', 'python') in store
    assert ('courses', 'python', 'assignments', 'homework 1') in store
    del store[('courses', 'python', 'assignments', 'homework 1')]
    assert ('courses', 'python', 'assignments', 'homework 1') not in store
    assert set(store.get_all(('courses', 'nothing'))) == set()
    assert store.get(
      ('does', 'not', 'exist' + six.unichr(9835)), 'DEFAULT VAL') == 'DEFAULT VAL'
  finally:
    shutil.rmtree(temp_dir)
