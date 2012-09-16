"""
Utility for dumping data from an anydbm-style database.
"""

import anydbm
import os
import shutil
import sys
import traceback

from os import path

def main():
    names = [n for n in os.listdir('.') if n.endswith('.log')]
    for name in names:
        dbpath = path.join('.', name)
        db = anydbm.open(dbpath, 'c')
        print 'found in %s:' % dbpath 
        for k, v in db.items():
            print '\tk, v: %s, %s' % (k, v)
        db.close()


if __name__ == "__main__":
    main()
