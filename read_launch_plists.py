#!/usr/bin/env python
#
# This script reads system launch daemon and agent plists.

import glob
import hashlib
import os
import plistlib
import subprocess
import csv

header ='filename,label,program,sha256,runatload,comment'
location = '/System/Library/Launch%s/*.plist'
comments = {}

def LoadPlist(filename):
  """Plists can be read with plistlib."""
  # creating our own data
  data = None
  
  try:
    p = subprocess.Popen(
        ['/usr/bin/plutil', '-convert', 'xml1', '-o', '-', filename],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out_data, err_data = p.communicate()
  except IOError as e:
    # file could not be found
    print e
      
  if(p.returncode == 0):
      data = plistlib.readPlistFromString(out_data)
  
  return data


def GetStatus(plist):
  """Plists may have a RunAtLoad key."""
  try:
    return plist['RunAtLoad']
  except KeyError:
    return 'False'


def GetLabel(plist):
  """Plists have a label."""
  try:
    return plist['Label']
  except KeyError:
    return 'False'


def GetProgram(plist):
  """Plists have either a Program or ProgramArguments key,
     if the executable requires command line options.
  """
  try:
    return "['%s']" % plist['Program'], HashFile(plist['Program'])
  except KeyError:
    return plist['ProgramArguments'], HashFile(plist['ProgramArguments'])


def HashFile(f):
  """Returns SHA-256 hash of a given file."""
  if type(f) is list:
    f = f[0]
  try:
    return hashlib.sha256(open(f,'rb').read()).hexdigest()
  except:
    return 'UNKNOWN'


def GetComment(plist):
  """docstring for GetComment"""
  global comments
  label = plist['Label']
  comment = None
  if label in comments:
    comment = comments[label]
  return comment


def main():
  """Main function."""
  print(header)
  
  global comments

  csvfile = os.path.join(os.path.dirname(
      os.path.realpath(__file__)), 'comments.csv')

  with open(csvfile, 'rb') as f:
      reader = csv.reader(f)
      comments = {rows[0]:rows[1] for rows in reader}
  
  for kind in ['Daemons', 'Agents']:
    for filename in glob.glob(location % kind):
      if not filename.endswith('com.apple.jetsamproperties.Mac.plist'):
        p = LoadPlist(filename)
        if p:
          e = (filename, GetLabel(p), '"%s",%s' % GetProgram(p), GetStatus(p), '"%s"' % GetComment(p))
          print('%s,%s,%s,%s,%s' % e)
        else:
          print('Could not load %s' % filename)


if __name__ == '__main__':
  main()
