#!/usr/bin/env python
#
# This script reads system launch daemons and agents.
#
# Python 3.4 is required to read binary plists, or convert them first with,
# find /System/Library/Launch* -type f -exec sudo plutil -convert xml1 {} \;

import glob
import hashlib
import os
import plistlib

header ='filename,label,program,sha256,runatload,comment'
location = '/System/Library/Launch%s/*.plist'


def LoadPlist(filename):
  """Plists can be read with plistlib."""
  try:
    return plistlib.readPlist(filename)
  except:
    print('python3.4 is required to read binary plist %s, skipping' % filename)
    return None


def GetStatus(plist):
  """Plists may have a RunAtLoad key."""
  try:
    return plist['RunAtLoad']
  except KeyError:
    return 'False'


def GetLabel(plist):
  """Plists have a label."""
  return plist['Label']


def GetProgram(plist):
  """Plists have either a Program or ProgramArguments key,
     if the executable requires command line options.
  """
  try:
    p = plist['Program']
  except KeyError:
    p = plist['ProgramArguments']
  return (p, HashFile(p))


def HashFile(f):
  """Returns SHA-256 hash of a given file."""
  if type(f) is list:
    f = f[0]
  try:
    return hashlib.sha256(open(f,'rb').read()).hexdigest()
  except:
    return 'UNKNOWN'


def main():
  """Main function."""
  print(header)

  for kind in ['Daemons', 'Agents']:
    for filename in glob.glob(location % kind):
      p = LoadPlist(filename)
      if p:
        e = (filename, GetLabel(p), '"%s",%s' % GetProgram(p), GetStatus(p))
        print('%s,%s,%s,%s,' % e)
      else:
        print('Could not load %s' % filename)


if __name__ == '__main__':
  main()
