#!/usr/bin/env python
"""
Run all unit tests for socialscan
Run tests by executing on the command line: python runtests.py
    -v flag for verbose output
"""

import unittest
import sys
import os
import re
import getopt

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <projectdir>/test/runtests.py

global projectdir
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'),
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)
os.chdir(projectdir)

# import test suite modules
import test_cnc_table
import test_filehash
import test_keymanager
import test_model
import test_scanhandlers_dummy
import test_scanhandlers_mcafee
import test_scanhandlers_msseccli
import test_scandigest
import test_scanlog
import test_containermanagers
import test_searchutil
import test_sethash
import test_util


# setup a complete test suite
tests = unittest.TestSuite()
tests.addTests(test_cnc_table.suite())
tests.addTests(test_filehash.suite())
tests.addTests(test_keymanager.suite())
tests.addTests(test_model.suite())
tests.addTests(test_scanhandlers_dummy.suite())

# TODO: add these test handlers based on availablility of scanners.
#tests.addTests(test_scanhandlers_mcafee.suite())
#tests.addTests(test_scanhandlers_msseccli.suite())

tests.addTests(test_scandigest.suite())
tests.addTests(test_scanlog.suite())
tests.addTests(test_containermanagers.suite())
tests.addTests(test_searchutil.suite())
tests.addTests(test_sethash.suite())
tests.addTests(test_util.suite())


def run(v=1):
    unittest.TextTestRunner(verbosity=v).run(tests)


if __name__ == "__main__":
    v = 1
    optlist, args = getopt.getopt(sys.argv[1:], 'vl:')
    options = dict(optlist)
    if '-v' in options or '-v' in args:
        v += 1
    if '-l' in options or '-l' in args:
        try: a = int(options['-l'])
        except: pass
        else: v = a
    run(v=v)

