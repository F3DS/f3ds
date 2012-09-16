"""
Unit test module for slmanager module
Run tests by executing on the command line: python test_slmanager.py
"""

import sys
import unittest

from datetime import datetime
from os import path

# 3rd party modules
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <buildsystem>/test/test_slmanager.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.config import loadDefaultConfig
from socialscan.model.containers import ScanLogManager
from socialscan.model import Base, Peer
from unittestutils import trim_microseconds
from socialscan.util import SigInfo


class ScanLogManagerTest(unittest.TestCase):
    engine = None
    session = None
    siginfo = None
    config = None

    @classmethod
    def setUpClass(cls):
        'Initialize sqlite in-memory for use by tests.'
        cls.engine = create_engine('sqlite:///:memory:')
        Session = sessionmaker(bind=cls.engine)
        cls.session = Session()
        Base.metadata.create_all(cls.engine)
        now = trim_microseconds(datetime.utcnow())
        cls.siginfo = SigInfo('Test Model Scanner v1.0', 'Generic Signature 0.3', now)
        cls.config = loadDefaultConfig()
        owner = owner = Peer('slmgrtest-owner', 'slmgrtest-owner', 'slmgrtest-owner')
        cls.config.owner = owner

    @classmethod
    def tearDownClass(cls):
        cls.session = None
        cls.engine = None
        cls.siginfo = None

    def testInit(self):
        'Make sure we can create a ScanLogManager instance.'
        slmgr = ScanLogManager(self.config, self.session)
        self.assertEqual(slmgr.config, self.config)
        self.assertEqual(slmgr.session, self.session)
        # TODO:
        # use config to get sharedir and storedir
        # Test for creation of sharedir and storedir
        # Test that config and session members are not None
        # Test that logger is not None
        # Test that scanhandler is as configured
        # Test that loadlimit is as configured
        # Test digests and ourdigest
        # ourdigest == None will test _determineSiginfo
    # TODO: Add test coverage.  This is very minimal testing.


def suite():
    slmanager_suite = unittest.makeSuite(ScanLogManagerTest)
    suite = unittest.TestSuite((slmanager_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
