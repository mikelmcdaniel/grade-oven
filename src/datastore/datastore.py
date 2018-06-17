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

import abc
import json
import six
import tempfile
from typing import Any, List, Text, Tuple, TypeVar

import leveldb

DataStoreKey = Tuple[Text]
DataStoreValue = TypeVar('DataStoreValue', Text, int, float)

_JSON_NULL = bytes(json.dumps(None).encode('utf-8'))


class AbstractDataStore(object):
  @abc.abstractmethod
  def put(self, key: DataStoreKey, value: DataStoreValue = None) -> None:
    self[key] = value

  @abc.abstractmethod
  def __getitem__(self, key: DataStoreKey) -> DataStoreValue:
    pass

  @abc.abstractmethod
  def get_all(self, key: DataStoreKey) -> List[Text]:
    pass

  @abc.abstractmethod
  def remove(self, key: DataStoreKey) -> None:
    pass

  # Methods below do not need to be overriden
  def __setitem__(self, key: DataStoreKey, value: DataStoreValue) -> None:
    self.put(key, value)

  def get(self, key: DataStoreKey, default_value: Any = None) -> Any:
    try:
      return self[key]
    except KeyError:
      return default_value

  def __contains__(self, key: DataStoreKey) -> bool:
    try:
      self[key]
      return True
    except KeyError:
      return False

  def __delitem__(self, key: DataStoreKey) -> None:
    self.remove(key)


# TODO: Allow keys to be arbitrary
# TODO: Make concurrent deletions/puts atomic with respect to eachother
class DataStore(AbstractDataStore):
  def __init__(self, dir_path: Text = None) -> None:
    if dir_path is None:
      dir_path = tempfile.mkdtemp()
    self.db = leveldb.LevelDB(dir_path, paranoid_checks=True)

  def put(self, key: DataStoreKey, value: DataStoreValue = None) -> None:
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

  def __getitem__(self, key: DataStoreKey) -> DataStoreValue:
    real_key = []
    for key_part in key:
      real_key.append('\x00')
      real_key.append(key_part)
    real_key[0] = six.unichr(len(key))
    raw_value = self.db.Get(bytearray(''.join(real_key), 'utf-8'))
    value = json.loads(raw_value)
    return value

  def get_all(self, key: DataStoreKey) -> List[Text]:
    real_key = []
    real_key.append(chr(len(key) + 1))
    real_key.append('\x00'.join(key))
    start_key = ''.join(real_key)
    real_key.append('\x01')
    end_key = ''.join(real_key)
    sub_keys = []
    for sub_key in self.db.RangeIter(
        bytearray(start_key, 'utf-8'),
        bytearray(end_key, 'utf-8'),
        include_value=False):
      sub_keys.append(sub_key[sub_key.rfind(b'\x00') + 1:].decode('utf-8'))
    return sub_keys

  def remove(self, key: DataStoreKey) -> None:
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
          bytearray(start_key, 'utf-8'),
          bytearray(end_key, 'utf-8'),
          include_value=False):
        mods.Delete(k)
        found_keys = True
      if not found_keys:
        break
    self.db.Write(mods)
