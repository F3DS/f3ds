"""
Unit test module for model module
Run tests by executing on the command line: python test_model.py
"""
# Standard Python modules
import os
import sys
import unittest

from datetime import datetime
from os import path

# 3rd party modules
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Our modules

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_model.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.model import (Base, Peer, Scan, ScanDigestFile, ScanLogFile,
                              ScanDigest, ScanLog)
from f3ds.framework.util import UrlObject
from socialscan.util import SigInfo, Safety
from unittestutils import trim_microseconds

hexes = '[\dA-Fa-f]'
UUID_PATTERN = '%s{8}-%s{4}-%s{4}-%s{4}-%s{12}' % (hexes, hexes, hexes, hexes, hexes)

class ModelTestBase(unittest.TestCase):
    engine = None
    session = None
    siginfo = None

    @classmethod
    def setUpClass(cls):
        'Initialize sqlite in-memory for use by tests.'
        cls.engine = create_engine('sqlite:///:memory:')
        Session = sessionmaker(bind=cls.engine)
        cls.session = Session()
        Base.metadata.create_all(cls.engine)
        now = trim_microseconds(datetime.utcnow())
        cls.siginfo = SigInfo('Test Model Scanner v1.0', 'Generic Signature 0.3', now)

    @classmethod
    def tearDownClass(cls):
        cls.session = None
        cls.engine = None
        cls.siginfo = None


class ScanTest(ModelTestBase):
    owner = Peer('scantest-owner', 'scantest-owner', 'scantest-owner')

    def testInitLocal(self):
        'Test that we can make a Scan instance for a local scan.'
        url = 'http://www.nachomama.ru/gimmefreestuff.jsp'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        self.assertEqual(scan.owner, self.owner)
        self.assertEqual(scan.url, url)
        self.assertFalse(scan.malicious)
        self.assertEqual(scan.type, 'local')
        actual = SigInfo(scan.scannervv, scan.sigversion, scan.sigdate)
        self.assertEqual(self.siginfo, actual)

    def testRepr(self):
        'Test that repr makes sense.'
        url = 'http://www.nachocheesy.net/bestcornchips.aspx'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        actual = scan.__repr__()
        expected = "Scan(id=None, %s, %s, %s, %s, %s, hash=None, peer=None, tainted=None)" % \
                   (self.owner, type, url, malicious, self.siginfo)
        self.assertEqual(expected, actual)

    def testToUrlObjectNoFilesizeNoHash(self):
        'Test that we can make a UrlObject out of this Scan object with no filesize or hash.'
        url = 'http://www.gourmetcheese.com/jackofalltrades.aspx'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        expected = UrlObject(url, -1, nonce=self.owner.name)
        actual = scan.to_UrlObject()
        self.assertEqual(expected, actual)

    def testToUrlObjectNoHash(self):
        'Test that we can make a UrlObject out of this Scan object withn no hash.'
        url = 'http://www.gourmetcheese.com/jackofalltrades.aspx'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        scan.filesize = 35432
        expected = UrlObject(url, 35432, nonce=self.owner.name)
        actual = scan.to_UrlObject()
        self.assertEqual(expected, actual)

    def testToUrlObjectNoFilesize(self):
        'Test that we can make a UrlObject out of this Scan object with no filesize.'
        url = 'http://www.gourmetcheese.com/jackofalltrades.aspx'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        scan.hash = 'ea46fc3db21ae'
        expected = UrlObject(url, -1, nonce=self.owner.name, hash='ea46fc3db21ae')
        actual = scan.to_UrlObject()
        self.assertEqual(expected, actual)

    def testToUrlObject(self):
        'Test that we can make a UrlObject out of this Scan object.'
        url = 'http://www.gourmetcheese.com/jackofalltrades.aspx'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        scan.filesize = 35980
        scan.hash = 'ea46fc3db21ae'
        expected = UrlObject(url, 35980, nonce=self.owner.name, hash='ea46fc3db21ae')
        actual = scan.to_UrlObject()
        self.assertEqual(expected, actual)

    def testSafety(self):
        'Test that accessing safety property gives correct result.'
        url = 'http://www.bluecornchipfanatics.com/bestnachocheese.cgi'
        type = 'local'
        malicious = False
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        expected = Safety(True, malicious)
        actual = scan.safety
        self.assertEqual(expected, actual)
        scan.malicious = True
        self.assertNotEqual(expected, scan.safety)

    def testSigInfo(self):
        'Test that accessing siginfo property gives correct result.'
        url = 'http://www.flauters.com/weflautyourlaws'
        type = 'local'
        malicious = True
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        actual = scan.siginfo
        self.assertEqual(self.siginfo, actual)

    def testMarkTainted(self):
        'With no peer, markTainted should raise a NotImplementedError.'
        url = 'http://www.flauters.com/meanspirited'
        type = 'social-aggregate'
        malicious = True
        scan = Scan(self.owner, type, url, malicious, self.siginfo)
        self.assertRaises(NotImplementedError, scan.markTainted, (self.session, 2.0))
    #TODO: write test for markTainted with a peer.


class ScanDigestFileTest(ModelTestBase):
    name = 'scandigestfiletest'
    owner = Peer('scandigestfiletest-owner', 'scandigestfiletest-owner', 'scandigestfiletest-owner')
    bindhost = '127.0.0.1'
    port = '8123'
    url = 'http://%s:%s/shared/digests/{uuid}' % (bindhost, port)
    location = 'data/shared/digests/{uuid}'

    def testInit(self):
        'Test that we can make a ScanDigestFile instance.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location,
                                siginfo=self.siginfo)
        self.assertRegexpMatches(sdfile.filename,
                                 self.location.replace('{uuid}', UUID_PATTERN))
        self.assertRegexpMatches(sdfile.url,
                                 self.url.replace('{uuid}', UUID_PATTERN))
        self.assertEqual(sdfile.creator, self.owner)
        actual = SigInfo(sdfile.scannervv, sdfile.sigversion, sdfile.sigdate)
        self.assertEqual(self.siginfo, actual)

    def testRepr(self):
        'Test that ScanDigestFile repr makes sense.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
        actual = sdfile.__repr__()
        expected = 'ScanDigestFile(id=None, ScanDigest, %r, %r)' % (self.owner, sdfile.filename)
        self.assertEqual(expected, actual)

    def testUsefulnessNoHitsNoDateAttribute(self):
        'Test that accessing usefulness gives correct result when hits and date are missing.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
        if hasattr(sdfile, 'date'):
            delattr(sdfile, 'date')
        expected = 0.0
        actual = sdfile.usefulness
        self.assertEqual(expected, actual)

    def testUsefulnessNoHitsAttribute(self):
        'Test that accessing usefulness gives correct result when hits is missing.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
        sdfile.date = datetime.utcnow() # .now() is used in property.
        expected = 0.0
        actual = sdfile.usefulness
        self.assertEqual(expected, actual)

    def testUsefulness(self):
        'Test that accessing usefulness gives correct result.  Fails every DST change.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
        now = datetime.now()
        utcnow = datetime.utcnow()
        seconds_diff = utcnow - now
        sdfile.hits = abs(seconds_diff.total_seconds() * 10)
        sdfile.date = utcnow
        actual = sdfile.usefulness
        expected = 10.0
        self.assertAlmostEqual(expected, actual, places=5)

    def testCreate(self):
        'Test that a ScanDigest object is created when we call create.'
        max = 25
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
        sdfile.create(max)
        self.assertIsNotNone(sdfile._container)
        self.assertIsInstance(sdfile._container, ScanDigest)
        self.assertEqual(sdfile._container.maxcapacity, max)

    def testSigInfo(self):
        'Test that we get the right SigInfo back when accessing siginfo property.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location,
                                siginfo=self.siginfo)
        actual = sdfile.siginfo
        self.assertEqual(self.siginfo, actual)

    def testMarkTainted(self):
        'Test that a peerless digest raises a NotImplementedError.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
        self.assertRaises(NotImplementedError, sdfile.markTainted, (self.session, 3.0))
    # TODO: write test for markTainted with a peer

    def testCreateAddSaveLoadGet(self):
        'Test that we can create, add to, save, unload, load, and get from a ScanDigestFile.'
        max = 25
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location,
                                siginfo=self.siginfo)
        # Create
        sdfile.create(max)
        self.assertIsNotNone(sdfile._container)
        self.assertIsInstance(sdfile._container, ScanDigest)
        self.assertEqual(sdfile._container.maxcapacity, max)
        url = 'http://www.bluecornchipfanatics.com/bestnachocheese.cgi'
        size = 3452
        uo = UrlObject(url, size, nonce=self.name, hash='ea463b2cd1')
        # Add/Get
        sdfile.add(uo)
        self.assertTrue(sdfile.get(uo))
        # Save
        sdfile.save()
        self.assertTrue(os.path.isfile(sdfile.filename))
        # Unload
        sdfile.unload()
        self.assertFalse(sdfile._container)
        # Load
        loaded_file = sdfile.load()
        self.assertTrue(sdfile._container)
        self.assertEqual(sdfile, loaded_file)
        # Get
        self.assertTrue(sdfile.get(uo))

    def testLoadingEmptyFile(self):
        'If we try to load an empty file, ScanDigest should not catch the exception.'
        sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location,
                                siginfo=self.siginfo)
        # Make sure the file exists but is empty
        f = open(sdfile.filename, 'wb')
        f.write('')
        f.close()
        # Load
        self.assertRaises(ValueError, sdfile.load)
        try:
            os.remove(sdfile.filename)
        except:
            pass


class ScanLogFileTest(ModelTestBase):
    name = 'scanlogfiletest'
    owner = Peer('scanlogfiletest-owner', 'scanlogfiletest-owner', 'scanlogfiletest-owner')
    bindhost = '127.0.0.1'
    port = '8123'
    url = 'http://%s:%s/shared/logs/{uuid}' % (bindhost, port)
    location = 'data/shared/logs/{uuid}'

    def testInit(self):
        'Test that we can make a ScanLogFile instance.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location,
                             siginfo=self.siginfo)
        filename = self.location + '.log'
        url = self.url + '.log'
        self.assertRegexpMatches(slfile.filename, filename.replace('{uuid}', UUID_PATTERN))
        self.assertRegexpMatches(slfile.url, url.replace('{uuid}', UUID_PATTERN))
        self.assertEqual(slfile.creator, self.owner)
        actual = SigInfo(slfile.scannervv, slfile.sigversion, slfile.sigdate)
        self.assertEqual(self.siginfo, actual)

    def testRepr(self):
        'Test that ScanLogFile repr makes sense.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location)
        actual = slfile.__repr__()
        expected = 'ScanLogFile(id=None, ScanLog, %r, %r)' % (self.owner, slfile.filename)
        self.assertEqual(expected, actual)

    def testUsefulnessNoHitsNoDateAttribute(self):
        'Test that accessing usefulness gives correct result when hits and date are missing.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location)
        if hasattr(slfile, 'date'):
            delattr(slfile, 'date')
        expected = 0.0
        actual = slfile.usefulness
        self.assertEqual(expected, actual)

    def testUsefulnessNoHitsAttribute(self):
        'Test that accessing usefulness gives correct result when hits is missing.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location)
        slfile.date = datetime.utcnow() # .now() is used in property.
        expected = 0.0
        actual = slfile.usefulness
        self.assertEqual(expected, actual)

    def testUsefulness(self):
        'Test that accessing usefulness gives correct result.  Fails every DST change.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location,
                             siginfo=self.siginfo)
        now = datetime.now()
        utcnow = datetime.utcnow()
        seconds_diff = utcnow - now
        slfile.hits = abs(seconds_diff.total_seconds() * 10)
        slfile.date = utcnow
        actual = slfile.usefulness
        expected = 10.0
        self.assertAlmostEqual(expected, actual, places=5)

    def testCreate(self):
        'Test that a ScanDigest object is created when we call create.'
        max = 25
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location)
        slfile.create(max)
        self.assertIsNotNone(slfile._container)
        self.assertIsInstance(slfile._container, ScanLog)
        self.assertEqual(slfile._container.maxcapacity, max)

    def testSigInfo(self):
        'Test that we get the right SigInfo back when accessing siginfo property.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location,
                             siginfo=self.siginfo)
        actual = slfile.siginfo
        self.assertEqual(self.siginfo, actual)

    def testMarkTainted(self):
        'Test that a peerless log raises a NotImplementedError.'
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location)
        self.assertRaises(NotImplementedError, slfile.markTainted, (self.session, 3.0))
    # TODO: write test for markTainted with a peer

    def testLoadSetsMaxCapacity(self):
        'Test that load sets the maxcapacity member of the ScanLogFile.'
        max = 52
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location,
                             siginfo=self.siginfo)
        # Create
        slfile.create(max)
        self.assertIsNotNone(slfile._container)
        self.assertIsInstance(slfile._container, ScanLog)
        self.assertEqual(slfile._container.maxcapacity, max)
        # Save
        slfile.save()
        self.assertTrue(os.path.isfile(slfile.filename))
        # Unload
        slfile.unload()
        self.assertFalse(slfile._container)
        # Load
        slfile.load()
        self.assertIsNotNone(slfile._container)
        self.assertEqual(slfile._container.maxcapacity, max)

    def testCreateAddSaveLoadGet(self):
        'Test that we can create, add to, save, unload, load, and get from a ScanLogFile.'
        max = 25
        slfile = ScanLogFile(self.owner, url=self.url, location=self.location,
                             siginfo=self.siginfo)
        # Create
        slfile.create(max)
        self.assertIsNotNone(slfile._container)
        self.assertIsInstance(slfile._container, ScanLog)
        self.assertEqual(slfile._container.maxcapacity, max)
        url = 'http://www.bluecornchipfanatics.com/bestnachocheese.cgi'
        size = 3452
        uo = UrlObject(url, size, nonce=self.name, hash='ea463b2cd1')
        safety = Safety(True, False)
        # Add/Get
        slfile.add(uo, safety)
        self.assertTrue(slfile.get(uo))
        # Save
        slfile.save()
        self.assertTrue(os.path.isfile(slfile.filename))
        # Unload
        slfile.unload()
        self.assertFalse(slfile._container)
        # Load
        loaded_file = slfile.load()
        self.assertTrue(slfile._container)
        self.assertEqual(slfile, loaded_file)
        # Get
        self.assertTrue(slfile.get(uo))


#TODO: write tests for QueuedRequest class
#TODO: write tests for SentScanRequest class
#TODO: write tests for SocialRelationship class
#TODO: write tests for Peer class


def suite():
    scan_suite = unittest.makeSuite(ScanTest)
    scandigestfile_suite = unittest.makeSuite(ScanDigestFileTest)
    scanlogfile_suite = unittest.makeSuite(ScanLogFileTest)
    suite = unittest.TestSuite((scan_suite, scandigestfile_suite, scanlogfile_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
