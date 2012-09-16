#!/usr/bin/python

import os
import pickle
import sys

# Modify the path to include the socialscan modules.
# __file__ is <socialscan source>/socialscan/filehash.py
pdn = os.path.dirname
projectdir = pdn(pdn(os.path.abspath(__file__)))
if projectdir not in sys.path:
    sys.path.append(projectdir)

from socialscan.sethash import hasher

class FileIter(object):
    """
    A simple iterator allowing iteration of a file in blocks
    """
    def __init__(self, f, blocksize=4096):
        self.f = f

    def __iter__(self):
        return self

    def next(self):
        r = self.f.read()
        if not len(r):
            raise StopIteration
        return r


def filehash(filename):
    f = open(filename, "rb")
    print("opened")
    sum = hasher()
    for block in FileIter(f):
        sum.update(block)
    return sum.hexdigest()


print pickle.dumps(filehash(sys.argv[1]))

