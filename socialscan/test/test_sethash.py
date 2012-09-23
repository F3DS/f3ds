"""
Unit test module for sethash module
Run tests by executing on the command line: python test_sethash.py
"""

import hashlib
import sys
import unittest

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_sethash.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)


from f3ds.framework import sethash
from unittestutils import setConfigValue


class SethashTest(unittest.TestCase):
    saved_algorithm = ''
    setting = 'algorithm'

    @classmethod
    def setUpClass(cls):
        'Save the current algorithm setting.'
        cls.saved_algorithm = setConfigValue(cls.setting, '')

    @classmethod
    def tearDownModule(cls):
        'Restore the algorithm setting'
        setConfigValue(cls.setting, cls.saved_algorithm)

    def tearDown(self):
        'Reset the value of the configured algorithm.'
        # If this is not reset, and 'blowfish' is the
        # setting that remains, testUseHasher will fail.
        setConfigValue(self.setting, self.saved_algorithm)

    def testUseHasher(self):
        'Test accessing hasher as imported.'
        expected = eval('hashlib.' + self.saved_algorithm.strip() + '()')
        actual = sethash.hasher()
        self.assertIsInstance(actual, type(expected))

    def testSetHashConfigSha384(self):
        'Test using the default hasher from config file (sha384).'
        setConfigValue(self.setting, 'sha384')
        expected = hashlib.sha384()
        actual = sethash.set_hash_function()()
        self.assertIsInstance(actual, type(expected))

    def testSetHashConfigSha512(self):
        'Test using the default hasher from config file (sha512).'
        setConfigValue(self.setting, 'sha512')
        expected = hashlib.sha512()
        actual = sethash.set_hash_function()()
        self.assertIsInstance(actual, type(expected))

    def testSetHashConfigValueNotSupported(self):
        'Test using the default hasher when the configured value is not supported.'
        setConfigValue(self.setting, 'blowfish')
        expected = hashlib.sha256()
        actual = sethash.set_hash_function()()
        self.assertIsInstance(actual, type(expected))

    # Nota Bene: this test is the same as config value not supported, unless we
    # actually remove the algorithm configuration from the config file, and then
    # it only tests which exception is raised, but all are caught, so it matters
    # little.
    #def testSetHashConfigValueNotSet(self):

    def testSetHashPassingAlgorithmSha1(self):
        'Test passing the sha1 algorithm.'
        expected = hashlib.sha1()
        actual = sethash.set_hash_function('sha1')()
        self.assertIsInstance(actual, type(expected))
      
    def testSetHashPassingAlgorithmMd5(self):
        'Test passing the md5 algorithm.'
        expected = hashlib.md5()
        actual = sethash.set_hash_function('md5')()
        self.assertIsInstance(actual, type(expected))


def suite():
    sethash_suite = unittest.makeSuite(SethashTest)
    suite = unittest.TestSuite((sethash_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
