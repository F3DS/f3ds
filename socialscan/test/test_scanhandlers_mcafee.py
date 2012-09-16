"""
Unit test module for mcafee module
Run tests by executing on the command line: python test_scanhandlers_mcafee.py
"""

import unittest
import sys
import os
import datetime

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scanhandlers_mcafee.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.scanhandlers import mcafee

class McafeeTest(unittest.TestCase):
    sigdate =  datetime.datetime(2012, 3, 10, 0, 0)
    scannervv = 'mcafee 5400.1158 for Win32.'
    benignfile = 'data/good'
    maliciousfile = 'data/badfile_for_unit_tests'
    version = '6645'

    def setUp(self):
        bf = open(self.benignfile, 'w+')
        bf.write('This file is good.\nYou will find no non-good thing here.\nNot even NT lovers')
        bf.close()

    def tearDown(self):
        for f in [self.benignfile]:
            try: os.remove(f)
            except: pass

    def testGetSigInfo(self):
        "Should return a SigInfo object"
        si = mcafee.getSigInfo()
        actual = (si.scannervv, si.sigversion, si.sigdate)
        expected = (self.scannervv, self.version, self.sigdate)
        self.assertEqual(expected, actual)

    def testScanBenign(self):
        "Tests the mcafee scanner's scan method."
        malicious, sigInfo = mcafee.scan(self.benignfile)
        self.assertFalse(malicious)
        expected = (self.scannervv, self.version, self.sigdate)
        actual = (sigInfo.scannervv, sigInfo.sigversion, sigInfo.sigdate)
        self.assertEquals(expected, actual)

    def testScanMalicious(self):
        "Tests the mcafee scanner's scan method with an evil file."
        malicious, sigInfo = mcafee.scan(self.maliciousfile)
        expected = (self.scannervv, self.version, self.sigdate)
        actual = (sigInfo.scannervv, sigInfo.sigversion, sigInfo.sigdate)
        self.assertEquals(expected, actual)
        # TODO: embed the data of a malicious file?  or will mcafee not like that?
        # TODO: find a file that is malicious that mcafee thinks is malicious.
        # TODO: maybe a tracking cookie?
        # For now put this assertion at the end so the other can succeed if it will.
        self.assertTrue(malicious)


def suite():
    mcafee_suite = unittest.makeSuite(McafeeTest)
    suite = unittest.TestSuite((mcafee_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
