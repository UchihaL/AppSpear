#!/usr/bin/env python2
#
# Copyright (C) 2012 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generates default implementations of operator<< for enum types."""

import codecs
import os
import re
import string
import sys


_ENUM_START_RE = re.compile(r'\benum\b\s+(class\s+)?(\S+)\s+:?.*\{(\s+// private)?')
_ENUM_VALUE_RE = re.compile(r'([A-Za-z0-9_]+)(.*)')
_ENUM_END_RE = re.compile(r'^\s*\};$')
_ENUMS = {}
_NAMESPACES = {}
_ENUM_CLASSES = {}

def Confused(filename, line_number, line):
  sys.stderr.write('%s:%d: confused by:\n%s\n' % (filename, line_number, line))
  raise Exception("giving up!")
  sys.exit(1)


def ProcessFile(filename):
  lines = codecs.open(filename, 'r', 'utf8', 'replace').read().split('\n')
  in_enum = False
  is_enum_class = False
  line_number = 0
  

  namespaces = []
  enclosing_classes = []

  for raw_line in lines:
    line_number += 1

    if not in_enum:
      # Is this the start of a new enum?
      m = _ENUM_START_RE.search(raw_line)
      if m:
        # Yes, so add an empty entry to _ENUMS for this enum.
        
        # Except when it's private
        if m.group(3) is not None:
          continue
        
        is_enum_class = m.group(1) is not None
        enum_name = m.group(2)
        if len(enclosing_classes) > 0:
          enum_name = '::'.join(enclosing_classes) + '::' + enum_name
        _ENUMS[enum_name] = []
        _NAMESPACES[enum_name] = '::'.join(namespaces)
        _ENUM_CLASSES[enum_name] = is_enum_class
        in_enum = True
        continue

      # Is this the start or end of a namespace?
      m = re.compile(r'^namespace (\S+) \{').search(raw_line)
      if m:
        namespaces.append(m.group(1))
        continue
      m = re.compile(r'^\}\s+// namespace').search(raw_line)
      if m:
        namespaces = namespaces[0:len(namespaces) - 1]
        continue

      # Is this the start or end of an enclosing class or struct?
      m = re.compile(r'^(?:class|struct)(?: MANAGED)? (\S+).* \{').search(raw_line)
      if m:
        enclosing_classes.append(m.group(1))
        continue
      m = re.compile(r'^\};').search(raw_line)
      if m:
        enclosing_classes = enclosing_classes[0:len(enclosing_classes) - 1]
        continue

      continue

    # Is this the end of the current enum?
    m = _ENUM_END_RE.search(raw_line)
    if m:
      if not in_enum:
        Confused(filename, line_number, raw_line)
      in_enum = False
      continue

    # The only useful thing in comments is the <<alternate text>> syntax for
    # overriding the default enum value names. Pull that out...
    enum_text = None
    m_comment = re.compile(r'// <<(.*?)>>').search(raw_line)
    if m_comment:
      enum_text = m_comment.group(1)
    # ...and then strip // comments.
    line = re.sub(r'//.*', '', raw_line)

    # Strip whitespace.
    line = line.strip()

    # Skip blank lines.
    if len(line) == 0:
      continue

    # Since we know we're in an enum type, and we're not looking at a comment
    # or a blank line, this line should be the next enum value...
    m = _ENUM_VALUE_RE.search(line)
    if not m:
      Confused(filename, line_number, raw_line)
    enum_value = m.group(1)

    # By default, we turn "kSomeValue" into "SomeValue".
    if enum_text == None:
      enum_text = enum_value
      if enum_text.startswith('k'):
        enum_text = enum_text[1:]

    # Lose literal values because we don't care; turn "= 123, // blah" into ", // blah".
    rest = m.group(2).strip()
    m_literal = re.compile(r'= (0x[0-9a-f]+|-?[0-9]+|\'.\')').search(rest)
    if m_literal:
      rest = rest[(len(m_literal.group(0))):]

    # With "kSomeValue = kOtherValue," we take the original and skip later synonyms.
    # TODO: check that the rhs is actually an existing value.
    if rest.startswith('= k'):
      continue

    # Remove any trailing comma and whitespace
    if rest.startswith(','):
      rest = rest[1:]
    rest = rest.strip()

    # There shouldn't be anything left.
    if len(rest):
      Confused(filename, line_number, raw_line)

    if len(enclosing_classes) > 0:
      if is_enum_class:
        enum_value = enum_name + '::' + enum_value
      else:
        enum_value = '::'.join(enclosing_classes) + '::' + enum_value

    _ENUMS[enum_name].append((enum_value, enum_text))

def main():
  local_path = sys.argv[1]
  header_files = []
  for header_file in sys.argv[2:]:
    header_files.append(header_file)
    ProcessFile(header_file)

  print('#include <iostream>')
  print('')

  for header_file in header_files:
    header_file = header_file.replace(local_path + '/', '')
    print('#include "%s"' % header_file)

  print('')

  for enum_name in _ENUMS:
    print('// This was automatically generated by %s --- do not edit!' % sys.argv[0])

    namespaces = _NAMESPACES[enum_name].split('::')
    for namespace in namespaces:
      print('namespace %s {' % namespace)

    print('std::ostream& operator<<(std::ostream& os, const %s& rhs) {' % enum_name)
    print('  switch (rhs) {')
    for (enum_value, enum_text) in _ENUMS[enum_name]:
      print('    case %s: os << "%s"; break;' % (enum_value, enum_text))
    if not _ENUM_CLASSES[enum_name]:
      print('    default: os << "%s[" << static_cast<int>(rhs) << "]"; break;' % enum_name)
    print('  }')
    print('  return os;')
    print('}')

    for namespace in reversed(namespaces):
      print('}  // namespace %s' % namespace)
    print('')

  sys.exit(0)


if __name__ == '__main__':
  main()
