"""
Scan handlers package. get() must return a fully initialized scan handler.
A scan handler is any object with a getSigInfo() call taking no arguments
and an scan() call taking a single filename argument and returning (malicious, siginfo).

SigInfo should be the namedtuple from socialscan.util or compatible.

ie:

def getSigInfo():
    return SigInfo("scannervv", "sigversion", datetime.datetime.now())

def scan(filename):
    f = open(filename, "rb")
    for line in f:
        if line.startswith("evil"):
            return True, getSigInfo()
    return False, getSigInfo()
"""
import os
from datetime import datetime

_cache = {}
def get(handler):
    try:
        module = _cache[handler]
        return module
    except KeyError:
        module = __import__(handler, globals(), {}, 0)
        _cache[handler] = module
        return module


# Some generic functions for determining the signature date from signature files.
def getMostRecent(dirname, searchstring='', filterfunction=None):
    """
    Generic function to get the most recently modified file from a directory, optionally
    searching only files matching searchstring.
    """
    most_recent_path = ''
    most_recent_mtime = 0
    getmtime = os.path.getmtime
    path_join = os.path.join
    names = os.listdir(dirname)
    if searchstring:
        if not filterfunction:
            filterfunction = lambda x, y: x.find(y) >= 0
        names[:] = [n for n in names if filterfunction(n, searchstring)]
    for name in names:
        filepath = path_join(dirname, name)
        mtime = getmtime(filepath)
        if mtime > most_recent_mtime:
            most_recent_path = filepath
            most_recent_mtime = mtime
    return most_recent_path, most_recent_mtime


def getSigDate(sigdir, search='', filterfn=None):
    'Get a datetime.datetime object from the most recent signature file in sigdir.'
    sigfile, mtime = getMostRecent(sigdir, searchstring=search, filterfunction=filterfn)
    return datetime.fromtimestamp(mtime)
