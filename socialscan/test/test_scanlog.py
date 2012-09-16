"""
Unit test module for scanlog module
Run tests by executing on the command line: python test_scanlog.py
"""

import anydbm
import os
import shutil
import sys
import traceback
import unittest

from datetime import datetime
from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scanlog.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.exceptions import ContainerFullError
from socialscan.model import scanlog
from socialscan.searchutil import UrlObject
from socialscan.util import SigInfo, Safety
from unittestutils import trim_microseconds


DEBUG = False

class ScanLogTest(unittest.TestCase):
    name = 'Testbox'
    db = None

    @classmethod
    def setUpClass(cls):
        'Setup paths, create dirs.'
        cls.datadir = path.abspath(path.join('.', 'data'))
        cls.sldir = path.join(cls.datadir, 'log')
        cls.slpath = path.join(cls.sldir, 'dbfile')
        if not os.path.isdir(cls.sldir):
            os.makedirs(cls.sldir)

    @classmethod
    def tearDownClass(cls):
        'Clean up dirs.'
        try:
            shutil.rmtree(cls.sldir)
        except (IOError, WindowsError):
            if DEBUG:
                print traceback.format_exc(sys.exc_info()[2])

    def setUp(self):
        'Make sure we have a db object'
        self.db = anydbm.open(self.slpath, 'c')

    def tearDown(self):
        'Track calls to setUp/tearDown, when they equal the number of tests, clean up.'
        try:
            if self.db:
                for k in self.db.keys():
                    del self.db[k]
                self.db.close()
        except (anydbm.error, TypeError):
            pass
        self.db = None

    def testInit(self):
        'After init, saved should be True, others as assigned.'
        si = SigInfo('Unit Test Sig Info', '0.12345', datetime.utcnow())
        sl = scanlog.ScanLog(15, si, self.slpath)
        self.assertTrue(sl.saved)
        self.assertEqual(sl.maxcapacity, 15)
        self.assertEqual(sl.siginfo, si)

    def testLoadFreshDb(self):
        'Starting off with a fresh db.'
        si = SigInfo('Unknown Scanner Version', 'Unknown Signature Version',
                     trim_microseconds(datetime.utcnow()))
        sl = scanlog.ScanLog.load(self.slpath + '_newdb')
        self.assertTrue(sl.saved)
        self.assertEqual(sl.maxcapacity, 300)
        self.assertEqual(sl.siginfo, si)

    def testLoadExistingDb(self):
        'Create a db, save using normal db interface, then load from it using scanlog.'
        # setUp creates.  Now we populate the db.
        now = trim_microseconds(datetime.utcnow())
        self.db['maxcapacity'] = '%s' % (23)
        self.db['scannervv'] = '%s' % 'Test Scanner Version 0.14'
        self.db['sigversion'] = '%s' % 'signature version 9.12.10'
        self.db['sigtimestamp'] = '%s' % now
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        # Save the data.
        self.db.close()
        # Load a ScanLog from the db.
        sl = scanlog.ScanLog.load(self.slpath)
        self.assertTrue(sl.saved)
        self.assertEqual(sl.maxcapacity, 23)
        self.assertEqual(sl.siginfo, si)

    def testSaveLoadHits(self):
        'If there were hits on this log, preserve them.'
        vases = ('http://allyourvases.rblong.to.us', 1234, '', Safety.possibly_benign)
        data = [vases]
        now = trim_microseconds(datetime.utcnow())
        capacity = 45
        scannervv = 'Unit Test Sig Info'
        sigversion = '0.12345'
        si = SigInfo(scannervv, sigversion, now)
        # Create ScanLog
        sl = scanlog.ScanLog(capacity, si, self.slpath)
        # Add data to ScanLog
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sl.add(uo, safety))
        sl.hits = 35
        sl.save()
        del sl
        # Load
        sl = scanlog.ScanLog.load(self.slpath)
        # Get items.
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            value = sl.get(uo)
            self.assertEqual(safety.ismalicious, value.ismalicious)
        self.assertEqual(int(sl.hits), 35)


    def testInitAddSaveLoadGet(self):
        'Create a new ScanLog object, save items to it, save it, load it.'
        # We need data in an object to test get, so we'll test add.  In order to test
        # add we need to load an object or create a new one.  In order to load one, we
        # need to save one, so we might as well test all of them.
        # Initialize data.
        bases = ('http://allyourbases.rblong.to.us', 2345, '', Safety.possibly_malicious)
        vases = ('http://allyourvases.rblong.to.us', 1234, '', Safety.possibly_benign)
        empty0 = ('', 0, '', Safety.benign)
        empty1 = ('', 235, '', Safety.malicious)
        empty2 = ('', 3342, '', Safety.possibly_malicious)
        empty3 = ('', 0, '', Safety.possibly_benign)
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d', Safety.benign), 
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a', Safety.malicious),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56', Safety.benign),
                ('', 22434, '8eaf73dac9d0b083cadefa34', Safety.benign),
                ('', 66575, '8caf73dac9d0e183cadefa32', Safety.malicious),
                ('http://youhavebeenpowned.cz', 0, '', Safety.malicious),
                ('http://reallysafe.com', 136, '', Safety.benign),
                bases,
                vases]
        empty = [empty0, empty1, empty2, empty3]
        now = trim_microseconds(datetime.utcnow())
        capacity = 45
        scannervv = 'Unit Test Sig Info'
        sigversion = '0.12345'
        si = SigInfo(scannervv, sigversion, now)
        # Create ScanLog
        sl = scanlog.ScanLog(capacity, si, self.slpath)
        # Add data to ScanLog
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sl.add(uo, safety))
        for url, size, hash, safety in empty:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertFalse(sl.add(uo, safety))
        sl.save()
        del sl
        # Load
        sl = scanlog.ScanLog.load(self.slpath)
        # Get items.
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            value = sl.get(uo)
            self.assertEqual(safety.ismalicious, value.ismalicious)
        for url, size, hash, safety in empty:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            value = sl.get(uo)
            self.assertIsNone(value)

    def testFillBeyondCapacity(self):
        'Create a new ScanLog object, save items to it, save it, load it, stuff it full.'
        bases = ('http://allyourbases.rblong.to.us', 2345, '', Safety.possibly_malicious)
        vases = ('http://allyourvases.rblong.to.us', 1234, '', Safety.possibly_benign)
        cases = ('http://allyourcases.rblong.to.us', 6358, '', Safety.possibly_malicious)
        faces = ('http://allyourfaces.rblong.to.us', 39217, '', Safety.possibly_benign)
        empty0 = ('', 0, '', Safety.benign)
        empty1 = ('', 235, '', Safety.malicious)
        empty2 = ('', 3342, '', Safety.possibly_malicious)
        empty3 = ('', 0, '', Safety.possibly_benign)
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d', Safety.benign), 
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a', Safety.malicious),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56', Safety.benign),
                ('', 22434, '8eaf73dac9d0b083cadefa34', Safety.benign),
                ('', 66575, '8caf73dac9d0e183cadefa32', Safety.malicious),
                ('http://youhavebeenpowned.cz', 0, '', Safety.malicious),
                ('http://reallysafe.com', 136, '', Safety.benign),
                bases,
                vases,
                cases]
        empty = [empty0, empty1, empty2, empty3]
        now = trim_microseconds(datetime.utcnow())
        capacity = 10 # Capacity is based on number of urls added.
        scannervv = 'Unit Test Sig Info'
        sigversion = '0.12345'
        si = SigInfo(scannervv, sigversion, now)
        # Create ScanLog
        sl = scanlog.ScanLog(capacity, si, self.slpath)
        # Add data to ScanLog
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sl.add(uo, safety))
        for url, size, hash, safety in empty:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertFalse(sl.add(uo, safety))
        sl.save()
        del sl
        # Load
        sl = scanlog.ScanLog.load(self.slpath)
        # Get items.
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            value = sl.get(uo)
            self.assertEqual(safety.ismalicious, value.ismalicious)
        for url, size, hash, safety in empty:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            value = sl.get(uo)
            self.assertIsNone(value)
        with self.assertRaises(ContainerFullError):
            face_uo = UrlObject(faces[0], faces[1], hash=faces[2], nonce=self.name)
            sl.add(face_uo, faces[3])

    def testLengthAccountingForMetadataWithHits(self):
        'If there is metadata incl. hits, it should not be included in the length reported.'
        bases = ('http://allyourbases.rblong.to.us', 2345, '', Safety.possibly_malicious)
        vases = ('http://allyourvases.rblong.to.us', 1234, '', Safety.possibly_benign)
        cases = ('http://allyourcases.rblong.to.us', 6358, '', Safety.possibly_malicious)
        faces = ('http://allyourfaces.rblong.to.us', 39217, '', Safety.possibly_benign)
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d', Safety.benign), 
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a', Safety.malicious),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56', Safety.benign),
                ('', 22434, '8eaf73dac9d0b083cadefa34', Safety.benign),
                ('', 66575, '8caf73dac9d0e183cadefa32', Safety.malicious),
                ('http://youhavebeenpowned.cz', 0, '', Safety.malicious),
                ('http://reallysafe.com', 136, '', Safety.benign),
                bases,
                vases,
                cases,
                faces]
        now = trim_microseconds(datetime.utcnow())
        self.db['maxcapacity'] = '%s' % (23)
        self.db['scannervv'] = '%s' % 'Test Scanner Version 0.14'
        self.db['sigversion'] = '%s' % 'signature version 9.12.10'
        self.db['sigtimestamp'] = '%s' % now
        self.db['hits'] = '%s' % (25)
        self.db.close()
        # Now open as ScanLog
        sl = scanlog.ScanLog.load(self.slpath)
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sl.add(uo, safety))
        self.assertEqual(len(sl), len(data))

    def testLengthAccountingForMetadataNoHits(self):
        'If there is metadata, it should not be included in the length reported.'
        bases = ('http://allyourbases.rblong.to.us', 2345, '', Safety.possibly_malicious)
        vases = ('http://allyourvases.rblong.to.us', 1234, '', Safety.possibly_benign)
        cases = ('http://allyourcases.rblong.to.us', 6358, '', Safety.possibly_malicious)
        faces = ('http://allyourfaces.rblong.to.us', 39217, '', Safety.possibly_benign)
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d', Safety.benign), 
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a', Safety.malicious),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56', Safety.benign),
                ('', 22434, '8eaf73dac9d0b083cadefa34', Safety.benign),
                ('', 66575, '8caf73dac9d0e183cadefa32', Safety.malicious),
                ('http://youhavebeenpowned.cz', 0, '', Safety.malicious),
                ('http://reallysafe.com', 136, '', Safety.benign),
                bases,
                vases,
                cases,
                faces]
        now = trim_microseconds(datetime.utcnow())
        self.db['maxcapacity'] = '%s' % (23)
        self.db['scannervv'] = '%s' % 'Test Scanner Version 0.14'
        self.db['sigversion'] = '%s' % 'signature version 9.12.10'
        self.db['sigtimestamp'] = '%s' % now
        self.db.close()
        # Now open as ScanLog
        sl = scanlog.ScanLog.load(self.slpath)
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sl.add(uo, safety))
        self.assertEqual(len(sl), len(data))

    def testLengthCorrespondsToUrlsAdded(self):
        'The length of a ScanDigest should equal the number of urls added.'
        bases = ('http://allyourbases.rblong.to.us', 2345, '', Safety.possibly_malicious)
        vases = ('http://allyourvases.rblong.to.us', 1234, '', Safety.possibly_benign)
        cases = ('http://allyourcases.rblong.to.us', 6358, '', Safety.possibly_malicious)
        faces = ('http://allyourfaces.rblong.to.us', 39217, '', Safety.possibly_benign)
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d', Safety.benign), 
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a', Safety.malicious),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56', Safety.benign),
                ('', 22434, '8eaf73dac9d0b083cadefa34', Safety.benign),
                ('', 66575, '8caf73dac9d0e183cadefa32', Safety.malicious),
                ('http://youhavebeenpowned.cz', 0, '', Safety.malicious),
                ('http://reallysafe.com', 136, '', Safety.benign),
                bases,
                vases,
                cases,
                faces]
        now = trim_microseconds(datetime.utcnow())
        self.db['maxcapacity'] = '%s' % (23)
        self.db['scannervv'] = '%s' % 'Test Scanner Version 0.14'
        self.db['sigversion'] = '%s' % 'signature version 9.12.10'
        self.db['sigtimestamp'] = '%s' % now
        self.db['hits'] = '%s' % (25)
        self.db.close()
        # Now open as ScanLog
        sl = scanlog.ScanLog.load(self.slpath)
        for url, size, hash, safety in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sl.add(uo, safety))
        self.assertEqual(len(sl), len(data))

    def testMicrosecondsDoNotRainOnTheParade(self):
        'If the sigtimestamp has microseconds, ignore them.'
        now = datetime.utcnow()
        now_sans_micro = trim_microseconds(now)
        self.db['maxcapacity'] = '%s' % (23)
        self.db['scannervv'] = '%s' % 'Test Scanner Version 0.14'
        self.db['sigversion'] = '%s' % 'signature version 9.12.10'
        self.db['sigtimestamp'] = '%s' % now
        self.db.close()
        # Now open as ScanLog
        sl = scanlog.ScanLog.load(self.slpath)
        self.assertEqual(sl.siginfo.sigdate, now_sans_micro)


def suite():
    scanlog_suite = unittest.makeSuite(ScanLogTest)
    suite = unittest.TestSuite((scanlog_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
