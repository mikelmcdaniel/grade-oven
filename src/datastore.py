import json
import os
import shutil


class DataStore(object):
  def __init__(self, dir_path):
    self.dir_path = dir_path
    self._data = {}

  def load(self):
    with open(os.path.join(self.dir_path, 'db.json')) as f:
      self._data = json.load(f)

  def save(self):
    with open(os.path.join(self.dir_path, 'db_new.json'), 'w') as f:
      json.dump(self._data, f)
    shutil.move('db_new.json', 'db.json')

  def put(self, key, value):
    sub_tree = value
    cur = self._data
    for j, key_part in enumerate(key):
      if key_part not in cur:
        for k in xrange(len(key) - 1, j, -1):
          sub_tree = {key[k]: sub_tree}
        break
      else:
        cur = cur[key_part]
    cur[key_part] = sub_tree

  def get(self, key):
    cur = self._data
    for sub_key in key:
      cur = cur[sub_key]
    return cur

  def get_all(self, key):
    return tuple(self.get(key))

  def remove(self, key):
    cur = self._data
    for sub_key in key[:-1:]:
      cur = cur[sub_key]
    del cur[key[-1]]


if __name__ == '__main__':
  key1 = ('courses', 'c++',    'assignments', 'homework 1')
  key2 = ('courses', 'c++',    'assignments', 'homework 2')
  key3 = ('courses', 'python', 'assignments', 'homework 1')
  store = DataStore(os.getcwd())
  store.put(key1, 'c++ 1')
  store.put(key2, 'c++ 2')
  store.put(key3, 'python 1')
  assert set(store.get_all(('courses',))) == set(['c++', 'python'])
  assert store.get(key1) == 'c++ 1'
  assert store.get(key3) == 'python 1'
  store.remove(('courses', 'c++'))
  assert set(store.get_all(('courses',))) == set(['python'])


