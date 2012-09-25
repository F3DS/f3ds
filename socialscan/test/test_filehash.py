"""
Unit test module for sethash module
Run tests by executing on the command line: python test_sethash.py
"""

import hashlib
import sys
import unittest

from os import path
from unittest import skipUnless

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_filehash.py
pdn = path.dirname
thisfile = path.abspath(__file__)
projectdir = pdn(pdn(thisfile))
f3dsdir = pdn(projectdir)
for d in [projectdir,
          f3dsdir,
          path.join(projectdir, 'socialscan'),
          path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

# Import will fail if argv is not just one file.
tmp_argv = []
tmp_argv.extend(sys.argv)
sys.argv = [sys.argv[0], thisfile]

from f3ds.framework import filehash
from f3ds.framework import sethash

# Restore argv
sys.argv = []
sys.argv.extend(tmp_argv)


class FilehashTest(unittest.TestCase):

    @skipUnless(sethash.hasher == hashlib.sha512, 'Expected value requires sha512')
    def testFilehash(self):
        'Test calling filehash on this file.'
        filehash_path = path.join(projectdir, 'f3ds', 'framework', 'filehash.py')
        expected = """\
077def2303208e3825d52102ccba667e\
6367602e3f45149ac982f68427fdb30f\
02ac80c99c8a64cf8eee3551a0915b96\
b1df49c13f5ca0961392c908ddca9076"""
        actual = filehash.filehash(filehash_path)
        msg = "'%s' != '%s'\nfilehash.py may have changed since this test was written"
        self.assertEqual(expected, actual, msg % (expected, actual))

def suite():
    filehash_suite = unittest.makeSuite(FilehashTest)
    suite = unittest.TestSuite((filehash_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
