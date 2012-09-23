#!/usr/bin/python2

import urllib
import pickle
import sys

def urlretrieve(url, filepath):
    try:
        filepath, headers = urllib.urlretrieve(url, filepath)
    except IOError:
        headers = ''
    return [filepath, headers]


print pickle.dumps(urlretrieve(sys.argv[1], sys.argv[2]))
