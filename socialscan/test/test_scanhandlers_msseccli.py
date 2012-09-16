"""
Unit test module for msseccli module
Run tests by executing on the command line: python test_scanhandlers_msseccli.py
"""

import unittest
import sys
import os
import datetime

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scanhandlers_msseccli.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.scanhandlers import msseccli

class MsseccliTest(unittest.TestCase):
    sigdate =  datetime.datetime(2012, 1, 26, 0, 0)
    scannervv = u'msseccli 3.0.8402.0'
    version  = u'1.119.632.0'
    benignfile = 'data/good'
    maliciousfile = 'data/badfile_for_unit_tests'

    def setUp(self):
        bf = open(self.benignfile, 'w')
        bf.write('This file is good.\nYou will find no non-good thing here.\nNot even NT lovers')
        bf.close()

    def tearDown(self):
        for f in [self.benignfile]:
            try: os.remove(f)
            except: pass

    def testGetSigInfo(self):
        "Should return a SigInfo object"
        si = msseccli.getSigInfo()
        actual = (si.scannervv, si.sigversion, si.sigdate)
        expected = (self.scannervv, self.version, self.sigdate)
        self.assertEqual(expected, actual)

    def testScanBenign(self):
        "Tests the msseccli scanner's scan method."
        malicious, sigInfo = msseccli.scan(self.benignfile)
        self.assertFalse(malicious)
        expected = (self.scannervv, self.version, self.sigdate)
        actual = (sigInfo.scannervv, sigInfo.sigversion, sigInfo.sigdate)
        self.assertEquals(expected, actual)

    def testScanMalicious(self):
        "Tests the msseccli scanner's scan method with an evil file."
        malicious, sigInfo = msseccli.scan(self.maliciousfile)
        expected = (self.scannervv, self.version, self.sigdate)
        actual = (sigInfo.scannervv, sigInfo.sigversion, sigInfo.sigdate)
        self.assertEquals(expected, actual)
        # TODO: embed the data of a malicious file?  or will msseccli not like that?
        # TODO: find a file that is malicious that msseccli thinks is malicious.
        # TODO: maybe a tracking cookie?
        # For now put this assertion at the end so the other can succeed if it will.
        self.assertTrue(malicious)


def suite():
    msseccli_suite = unittest.makeSuite(MsseccliTest)
    suite = unittest.TestSuite((msseccli_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
