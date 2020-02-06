"""
https://github.com/drduh/macOS-Security-and-Privacy-Guide/blob/master/launchd/read_launch_plists.py

Reads macOS system launch daemon and agent property lists.
"""

import glob
import hashlib
import os
import plistlib
import subprocess
import csv

HEADER = "filename,label,program,sha256,runatload,comment"
PLIST_LOCATION = "/System/Library/Launch%s/*.plist"
PLIST_TYPES = ["Daemons", "Agents"]


def LoadPlist(filename):
    """Returns plists read with plistlib."""
    try:
        proc = subprocess.Popen(
            ["/usr/bin/plutil", "-convert", "xml1", "-o", "-", filename],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_data, err_data = proc.communicate()
    except IOError as io_error:
        print(io_error, err_data)

    if proc.returncode == 0:
        return plistlib.readPlistFromString(out_data)

    return None


def GetPlistValue(plist, value):
    """Returns the value of a plist dictionary, or False."""
    try:
        return plist[value]
    except KeyError:
        return False


def GetProgram(plist):
    """Returns a plist's Program or ProgramArguments key and hash."""
    try:
        return "['%s']" % plist["Program"], HashFile(plist["Program"])
    except KeyError:
        try:
            return plist["ProgramArguments"], HashFile(plist["ProgramArguments"])
        except KeyError:
            return ("NO PROGRAM DEFINED", "UNKNOWN FILE HASH")
    return None


def HashFile(filename):
    """Returns SHA-256 hash of a given file."""
    if isinstance(filename, list):
        filename = filename[0]
    try:
        return hashlib.sha256(
            open(filename, "rb").read()).hexdigest()
    except IOError:
        return "UNKNOWN FILE HASH"


def GetComment(plist, comments):
    """Get comment for a given property list."""
    try:
        label = plist["Label"]
    except KeyError:
        return None

    if label in comments:
        return comments[label]
    return None


def main():
    """Main function."""
    print(HEADER)

    comments_file = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "comments.csv")

    with open(comments_file, "rb") as c_file:
        reader = csv.reader(c_file)
        comments = {rows[0]:rows[1] for rows in reader}

    for ptype in PLIST_TYPES:
        for filename in glob.glob(PLIST_LOCATION % ptype):
            prop = LoadPlist(filename)
            if prop:
                print("%s,%s,%s,%s,%s" % (
                    filename,
                    GetPlistValue(prop, "Label"),
                    '"%s",%s' % GetProgram(prop),
                    GetPlistValue(prop, "RunAtLoad"),
                    '"%s"' % GetComment(prop, comments)))
            else:
                print("Could not load %s" % filename)


if __name__ == "__main__":
    main()
