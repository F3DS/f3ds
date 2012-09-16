"""
Unit test module for scandigest module
Run tests by executing on the command line: python test_scandigest.py
"""

import os
import shutil
import StringIO
import sys
import tempfile
import time
import traceback
import unittest

from datetime import datetime
from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scandigest.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.exceptions import ContainerFullError, ZeroSizedDigestError, DigestModifiedTimeError
from socialscan.model import scandigest
from socialscan.searchutil import UrlObject
from socialscan.util import SigInfo
from unittestutils import trim_microseconds


DEBUG = False

class ScanDigestTest(unittest.TestCase):
    name = 'Testbox'
    db = None

    @classmethod
    def setUpClass(cls):
        'Setup paths, create dirs.'
        cls.datadir = path.abspath(path.join('.', 'data'))
        cls.sddir = path.join(cls.datadir, 'shared')
        cls.sdpath = path.join(cls.sddir, 'sdfile')
        if not path.isdir(cls.sddir):
            os.makedirs(cls.sddir)

    @classmethod
    def tearDownClass(cls):
        'Clean up dirs.'
        try:
            shutil.rmtree(cls.sddir)
        except (IOError, WindowsError):
            if DEBUG:
                print traceback.format_exc(sys.exc_info()[2])

    def removeTempFile(self, filename):
        'Clean up a temporary file.'
        try:
            os.remove(filename)
        except:
            pass
        
    def testInit(self):
        'After init, saved should be True, others as assigned.'
        si = SigInfo('Unit Test Sig Info', '0.12345', datetime.utcnow())
        sd = scandigest.ScanDigest(15, si, self.sdpath)
        self.assertTrue(sd.saved)
        self.assertEqual(sd.maxcapacity, 15)
        self.assertEqual(sd.siginfo, si)
        self.assertTrue(0 <= sd.nonce <= 0xffffffff)

    def testInitNonce(self):
        'After init, saved should be True, others as assigned, including nonce.'
        si = SigInfo('Unit Test Sig Info', '0.12345', datetime.utcnow())
        sd = scandigest.ScanDigest(15, si, self.sdpath, nonce=12345)
        self.assertTrue(sd.saved)
        self.assertEqual(sd.maxcapacity, 15)
        self.assertEqual(sd.siginfo, si)
        self.assertEqual(sd.nonce, 12345)

    def testSaveDigest(self):
        'Create a digest, save, then load from it using ScanDigest.load.'
        name = 'Testbox'
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        urlbase = 'http://www.froogly.com/iownyour%sbase.aspx'
        bases = ['first', 'second', 'third', 'home']
        urlobjects = []
        for base in bases:
            uo = UrlObject(urlbase % base, 3425, nonce=name, hash='e0dbc25fdb98a7e3')
            urlobjects.append(uo)
            sd.add(uo)
        sd.save()
        # Load from file.
        sd = scandigest.ScanDigest.load(self.sdpath)
        self.assertTrue(sd.saved)
        self.assertEqual(sd.maxcapacity, 23)
        self.assertEqual(sd.siginfo, si)
        for uo in urlobjects:
            self.assertTrue(sd.get(uo))

    def testInitAddSaveLoadGet(self):
        'Create a digest, save, then load from it using ScanDigest.load.'
        name = 'Testbox'
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        urlbase = 'http://www.froogly.com/iownyour%sbase.aspx'
        bases = ['first', 'second', 'third', 'home']
        urlobjects = []
        for base in bases:
            uo = UrlObject(urlbase % base, 3425, nonce=name, hash='e0dbc25fdb98a7e3')
            urlobjects.append(uo)
            sd.add(uo)
        sd.save()
        # Load from file now.
        sd = scandigest.ScanDigest.load(self.sdpath)
        self.assertTrue(sd.saved)
        self.assertEqual(sd.maxcapacity, 23)
        self.assertEqual(sd.siginfo, si)
        for uo in urlobjects:
            self.assertTrue(sd.get(uo))

    def testInitAddSaveLoadGetNoIncludeContent(self):
        'Test that two different urls with the same content are found with only one added.'
        name = 'Testbox'
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        urlbase = 'http://www.froogly.com/iownyour%sbase.aspx'
        bases = ['first', 'second', 'third', 'home']
        urlobjects = []
        for base in bases:
            uo = UrlObject(urlbase % base, 3425, nonce=name, hash='e0dbc25fdb98a7e3')
            urlobjects.append(uo)
            sd.add(uo)
        sd.save()
        # Load from file now.
        sd = scandigest.ScanDigest.load(self.sdpath)
        self.assertTrue(sd.saved)
        self.assertEqual(sd.maxcapacity, 23)
        self.assertEqual(sd.siginfo, si)
        # Change the urls, but keep the hash.  The urls should still be
        # found because their hashes were stored.
        altered_urlobjects = []
        for base in bases:
            url = urlbase % base
            uo = UrlObject(url + 'altered', 3425, nonce=name, hash='e0dbc25fdb98a7e3')
            altered_urlobjects.append(uo)
        for uo in altered_urlobjects:
            self.assertTrue(sd.get(uo))

    def testCreateLoadToCapacityLoadThenOverflow(self):
        'Create a ScanDigest object, stuff it to overflowing.'
        bases = ('http://allyourbases.rblong.to.us', 2345, '')
        vases = ('http://allyourvases.rblong.to.us', 1234, '')
        cases = ('http://allyourcases.rblong.to.us', 4262, '')
        faces = ('http://allyourfaces.rblong.to.us', 9013, '')
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d'), 
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a'),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56'),
                ('', 22434, '8eaf73dac9d0b083cadefa34'),
                ('', 66575, '8caf73dac9d0e183cadefa32'),
                ('http://youhavebeenpowned.cz', 0, ''),
                ('http://reallysafe.com', 136, ''),
                bases,
                vases,
                cases]
        now = trim_microseconds(datetime.utcnow())
        capacity = 10 # Capacity is based on number of urls added.
        scannervv = 'Unit Test Sig Info'
        sigversion = '0.12345'
        si = SigInfo(scannervv, sigversion, now)
        # Create ScanDigest
        sd = scandigest.ScanDigest(capacity, si, self.sdpath)
        # Add data to ScanDigest
        for url, size, hash in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sd.add(uo))
        sd.save()
        del sd
        # Load and get items.
        sd = scandigest.ScanDigest.load(self.sdpath)
        for url, size, hash in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            value = sd.get(uo)
            self.assertTrue(value)
        # Try to add and save faces.
        face_uo = UrlObject(faces[0], faces[1], nonce=self.name, hash=faces[2])
        self.assertRaises(ContainerFullError, sd.add, face_uo)

    def testSizeMatchesUrlsAdded(self):
        'Add urls to a ScanDigest, some with contents hashes, size is number of urls added.'
        bases = ('http://allyourbases.rblong.to.us', 2345, '')
        vases = ('http://allyourvases.rblong.to.us', 1234, '')
        cases = ('http://allyourcases.rblong.to.us', 4262, '')
        faces = ('http://allyourfaces.rblong.to.us', 9013, '')
        data = [('http://www.google.com', 1546, 'e60f0c7b96e7ca2f0948ab1c31d'),
                ('http://westealyourpasswd.com', 9823, 'b849b8e3a659f8d4cac675a'),
                ('http://www.mit.edu', 12309, '6aedc8dcf2ca3efe938d9268c40ae56'),
                ('', 22434, '8eaf73dac9d0b083cadefa34'),
                ('', 66575, '8caf73dac9d0e183cadefa32'),
                ('http://youhavebeenpowned.cz', 0, ''),
                ('http://reallysafe.com', 136, ''),
                bases,
                vases,
                cases]
        now = trim_microseconds(datetime.utcnow())
        capacity = 25
        scannervv = 'Unit Test Sig Info'
        sigversion = '0.12345'
        si = SigInfo(scannervv, sigversion, now)
        # Create ScanDigest
        sd = scandigest.ScanDigest(capacity, si, self.sdpath)
        # Add data to ScanDigest
        for url, size, hash in data:
            uo = UrlObject(url, size, nonce=self.name, hash=hash)
            self.assertTrue(sd.add(uo))
        self.assertEqual(len(sd), len(data))
        sd.save()
        self.assertEqual(len(sd), len(data))
        del sd
        # Load and get items.
        sd = scandigest.ScanDigest.load(self.sdpath)
        self.assertEqual(len(sd), len(data))

    # Because load requires a file object, testing load from a non-existent file makes no
    # sense.  However, testing with an empty file, or a file that does not match
    # expectations (not big enough, only has metadata, wrong packing format) does make
    # sense, as well as None instead of a file object.
    def testLoadFromEmptyFile(self):
        'Loading from an empty file should result in a ValueError not a struct.error'
        fd, tmp = tempfile.mkstemp(dir=path.dirname(self.sdpath))
        os.close(fd)
        self.assertRaises(ValueError, scandigest.ScanDigest.load, (tmp))
        self.removeTempFile(tmp)

    def testLoadEmptyFileName(self):
        'Loading from and empty filename should cause an IOError.'
        fd, tmp = tempfile.mkstemp(dir=path.dirname(self.sdpath))
        os.write(fd, '')
        os.close(fd)
        self.assertRaises(IOError, scandigest.ScanDigest.load, (''))
        self.removeTempFile(tmp)

    def testLoadFromNone(self):
        'Opening filename None should cause a TypeError.'
        nothing = None
        self.assertRaises(TypeError, scandigest.ScanDigest.load, (nothing))
    # TODO: test loading from other error conditions mentioned above testLoadFromEmptyFile.

    def testVerifySaveZeroBytes(self):
        'A zero-sized scandigest should raise ZeroSizedDigestError.'
        fd, tmp = tempfile.mkstemp(dir=path.dirname(self.sdpath))
        os.write(fd, '')
        os.close(fd)
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        sd.filename = tmp
        self.assertRaises(ZeroSizedDigestError, sd.verify_save)
        self.removeTempFile(tmp)

    def testVerifySaveNonzeroBytes(self):
        'A non-zero sized scandigest should not raise an error.'
        fd, tmp = tempfile.mkstemp(dir=path.dirname(self.sdpath))
        os.write(fd, 'The brown lazy fox held on for dear life while the cow jumped over the moon.')
        os.close(fd)
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        sd.filename = tmp
        sd.verify_save()
        # No assertion, as verify_save should run without raising an error in this case.
        self.removeTempFile(tmp)

    def testVerifySaveStaleFile(self):
        'A scandigest that is older than expected should raise a DigestModifiedTimeError.'
        fd, tmp = tempfile.mkstemp(dir=path.dirname(self.sdpath))
        os.write(fd, 'The brown lazy fox held on for dear life while the cow jumped over the moon.')
        os.close(fd)
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        sd.filename = tmp
        self.assertRaises(DigestModifiedTimeError, sd.verify_save, (time.time() + 1000))
        self.removeTempFile(tmp)

    def testVerifySaveRecentFile(self):
        before_write = time.time()
        fd, tmp = tempfile.mkstemp(dir=path.dirname(self.sdpath))
        os.write(fd, 'The brown lazy fox held on for dear life while the cow jumped over the moon.')
        os.close(fd)
        now = trim_microseconds(datetime.utcnow())
        si = SigInfo('Test Scanner Version 0.14', 'signature version 9.12.10', now)
        sd = scandigest.ScanDigest(23, si, self.sdpath, nonce=12345)
        sd.filename = tmp
        # No assertion, as verify_save should run without raising an error in this case.
        sd.verify_save(age=before_write)
        self.removeTempFile(tmp)


def suite():
    scandigest_suite = unittest.makeSuite(ScanDigestTest)
    suite = unittest.TestSuite((scandigest_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
