"""A simple library for checking and sanitizing strings.

A safe entity is something that should be able to safely appear in a
URI or HTML without being escaped.
"""
from typing import Text

# Note that '.' is ok becuase '/' is not
SAFE_ENTITY_CHARS = frozenset(
  'abcdefghijklmnopqrstuvwxyz'
  'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  '0123456789 -_.()[]%=+,')

BAD_ENTITY_NAMES = frozenset(['', ' ', '.', '..'])


def is_safe_entity_name(entity: Text) -> bool:
  return (entity not in BAD_ENTITY_NAMES and
          not frozenset(entity) - SAFE_ENTITY_CHARS)

def safe_entity_name(entity: Text) -> Text:
  if entity is None:
    return None
  if entity == '':
    return '_'
  elif entity in BAD_ENTITY_NAMES:
    return ''.join('{:02x}'.format(ord(c)) for c in entity)
  elif is_safe_entity_name(entity):
    return entity
  return ''.join(
    c if c in SAFE_ENTITY_CHARS else '{:02x}'.format(ord(c))
    for c in entity)
