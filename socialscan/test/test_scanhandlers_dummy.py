"""
Unit test module for dummy module
Run tests by executing on the command line: python test_scanhandlers_dummy.py
"""

import unittest
import sys
import os
import datetime
import time

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scanhandlers_dummy.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.scanhandlers import dummy
from unittestutils import trim_microseconds

class DummyTest(unittest.TestCase):
    timestamp = time.time()
    curtime = datetime.datetime.fromtimestamp(timestamp)
    scannerfile = 'data/dummy'
    benignfile = 'data/good'
    maliciousfile = 'data/mal'
    version = '1.0'

    def setUp(self):
        sf = open(self.scannerfile, 'w')
        sf.write('%s\n%s\n%s\n' % (self.scannerfile, self.version, self.timestamp))
        sf.close()
        bf = open(self.benignfile, 'w')
        bf.write('This file is good.\nYou will find no non-good thing here.\nNot even NT lovers')
        bf.close()
        mf = open(self.maliciousfile, 'w')
        mf.write('This file is not good.\nin fact it is pure\nevil.')
        mf.close()

    def tearDown(self):
        for f in [self.scannerfile, self.benignfile, self.maliciousfile]:
            try: os.remove(f)
            except: pass

    def testGetSigInfo(self):
        "Should return a SigInfo object"
        si = dummy.getSigInfo()
        actual = (si.scannervv, si.sigversion, trim_microseconds(si.sigdate))
        expected = (self.scannerfile, self.version, trim_microseconds(self.curtime))
        self.assertEqual(expected, actual)

    def testScanBenign(self):
        "Tests the dummy scanner's scan method."
        malicious, si = dummy.scan(self.benignfile)
        self.assertFalse(malicious)
        expected = (self.scannerfile, self.version, trim_microseconds(self.curtime))
        actual = (si.scannervv, si.sigversion, trim_microseconds(si.sigdate))
        self.assertEquals(expected, actual)

    def testScanMalicious(self):
        "Tests the dummy scanner's scan method with an evil file."
        malicious, si = dummy.scan(self.maliciousfile)
        self.assertTrue(malicious)
        expected = (self.scannerfile, self.version, trim_microseconds(self.curtime))
        actual = (si.scannervv, si.sigversion, trim_microseconds(si.sigdate))
        self.assertEquals(expected, actual)


def suite():
    dummy_suite = unittest.makeSuite(DummyTest)
    suite = unittest.TestSuite((dummy_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
