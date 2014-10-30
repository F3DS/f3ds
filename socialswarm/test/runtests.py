#!/usr/bin/env python
"""
Run all unit tests for social swarm
Run tests by executing on the command line: python runtests.py
    -v flag for verbose output

"""

import unittest
import sys
import os
import re
import cStringIO

from os import path

global projectdir
# modify the path to see the source we are testing,
# and to make the relative paths work correctly.
# this makes it easy to run the unit test from its own directory
# __file__ is <projectdir>/test/runtests.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'src'), path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)
os.chdir(projectdir)

# import test suite modules
import test_models

# setup a complete test suite
sswarm_tests = unittest.TestSuite()
sswarm_tests.addTests(test_models.suite())

def run(v=1):
    # For now, output is just extra stuff, so comment it out and use the simple form.
    unittest.TextTestRunner(verbosity=v).run(sswarm_tests)
    #output = cStringIO.StringIO()
    #unittest.TextTestRunner(stream=output, verbosity=v).run(sswarm_tests)
    #lines = output.getvalue()
    #output.close()
    #print lines


if __name__ == '__main__':
    # check for verbose flag
    v = 1
    if len(sys.argv) >= 2 and sys.argv[1] == '-v':
        v += 1
        if len(sys.argv) > 2:
            try: a = int(sys.argv[2])
            except: pass
            else: v = a
    run(v=v)
