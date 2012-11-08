"""
Unit test module for util module
Run tests by executing on the command line: python test_util.py
"""

import datetime
import sys
import unittest

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_searchutil.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)


from f3ds.framework import util
from socialscan import util as scanutil


class UtilTest(unittest.TestCase):

    def testDeltaSeconds(self):
        'Should get the number of seconds represented by a timedelta.'
        td = datetime.timedelta(weeks=2, days=1, hours=1, minutes=3,
                                milliseconds=2000, microseconds=5000000)
        expected = 1299787
        actual = util.delta_seconds(td)
        self.assertEqual(expected, actual)

    def testUpdateCounts(self):
        'Test that utility function to update counts works.'
        class Dummy: pass
        scan = Dummy()
        scan.sigdate = datetime.datetime.now()
        scan.safety = scanutil.Safety.malicious
        found, malicious = (0, 0)
        found, malicious = scanutil.update_counts(found, malicious, scan)
        self.assertEqual(found, malicious)
        self.assertEqual(malicious, 1)

    def testEqualSigInfoWithMicroseconds(self):
        'SigInfo objects with microseconds are considered equal even if the usec are not.'
        # This could fail on second boundaries, so make the seconds be 0.  It could
        # also fail on other boundaries, but with much lower probability.
        n1 = datetime.datetime.now()
        d1 = datetime.datetime(n1.year, n1.month, n1.day, n1.hour, n1.minute, 0, n1.microsecond)
        n2 = datetime.datetime.now()
        d2 = datetime.datetime(n2.year, n2.month, n2.day, n2.hour, n2.minute, 0, n2.microsecond)
        s1 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', d1)
        s2 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', d2)
        self.assertEqual(s1, s2)

    def testEqualSigInfoHalfWithMicroseconds(self):
        'SigInfo objects with mixed microseconds are considered equal even if the usec are not.'
        # This could fail on second boundaries, so make the seconds be 0.  It could
        # also fail on other boundaries, but with much lower probability.
        n1 = datetime.datetime.now()
        d1 = datetime.datetime(n1.year, n1.month, n1.day, n1.hour, n1.minute, 0, n1.microsecond)
        n2 = datetime.datetime.now()
        d2 = datetime.datetime(n2.year, n2.month, n2.day, n2.hour, n2.minute, 0)
        s1 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', d1)
        s2 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', d2)
        self.assertEqual(s1, s2)

    def testEqualSigInfoWithoutMicroseconds(self):
        'SigInfo objects with no microseconds if otherwise equal should be equal.'
        # This could fail on second boundaries, so make the seconds be 0.  It could
        # also fail on other boundaries, but with much lower probability.
        n1 = datetime.datetime.now()
        now = datetime.datetime(n1.year, n1.month, n1.day, n1.hour, n1.minute, 0)
        d1 = now
        d2 = now
        s1 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', d1)
        s2 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', d2)
        self.assertEqual(s1, s2)

    def testComparingSigInfoToNoneShouldNotRaiseErrors(self):
        'SigInfo objects are not equal to None.'
        s1 = scanutil.SigInfo('Testing 1 2', 'Testing 1 2 v0.6', datetime.datetime.now())
        s2 = None
        # There is no 'assertDoesNotRaise', so compare equal.
        if s1 == s2:
            msg = 'SigInfo object %s and %s are not equal but somehow they are?'
            raise Exception(msg % (s1, s2))

    def testClassNameProperty(self):
        'Should get the name of a class as a bare string.'
        expected = 'UtilTest'
        actual = util.class_name(self)
        self.assertEqual(expected, actual)
        class InnerClass(object):
            def __init__(self):
                self.name = 'InnerClass'
        ic = InnerClass()
        self.assertEqual(ic.name, util.class_name(ic))


def suite():
    util_suite = unittest.makeSuite(UtilTest)
    suite = unittest.TestSuite((util_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
