"""
Unit test module for keymanager module
Run tests by executing on the command line: python test_keymanager.py
"""

import os
import re
import shutil
import sys
import traceback
import unittest

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_keymanager.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

try:
    from socialscan import keymanager
    skip = False
except:
    skip = True

@unittest.skipIf(skip, 'keymanager could not be imported, so skip keymanager tests.')
class KeymanagerTest(unittest.TestCase):
    gpg = None
    gpgdir = path.join('.', 'data', 'gpg')
    keydir = path.join(gpgdir, 'keys')
    name = 'Test Gpg User'
    email = 'testgpg@example.com'
    fingerprint = None
    uids = None
    key_to_import = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.9 (Cygwin)

mI0ETyo58AEEAK6+spbAHit6pGgpFNtFgdmSirJdveRO1bX3/MlmQ+4CY59ZBLEf
5+hyGJ1Za3RUq8vtFdP0RcVfF1N0V/sqTMWOAbfsfXcRmox2WDQ748jB/c/7XfKR
IA21ghmlxIhQ9cizuQpg4XK5M9HAhlxykE0XqAsbaWvPhwmfv1p3SmAVABEBAAG0
OWNvbXB1dGVyIGlwYWRkcmVzcyAoR2VuZXJhdGVkIGJ5IGdudXBnLnB5KSA8ZGV2
QHNzY2FuLnVzPoi2BBMBAgAgBQJPKjnwAhsvBgsJCAcDAgQVAggDBBYCAwECHgEC
F4AACgkQVXXGnj8BE6PeugP+PRt7zIGFTQsDhRneEbyooEstKEAbnYYOd7BhHTsW
ad7CO+wmQyDcfuEA5HKKVtZiuPkVsALZlsLdWtPDPnanmeKqWq1RB+RiCcwos97h
XtOQbMYnpoEsYXXFJpfsMvaqylg5Khsk+UBMc+6T8Z8Clpxng42dEuFyCrxT1ced
TRY=
=MmCa
-----END PGP PUBLIC KEY BLOCK-----
"""

    @classmethod
    def setUpClass(cls):
        'Setup paths, create dirs.'
        cls.gpgdir = path.join('.', 'data', 'gpg')
        cls.keydir = path.join(cls.gpgdir, 'keys')
        if not path.isdir(cls.keydir):
            os.makedirs(cls.keydir)

    @classmethod
    def tearDownClass(cls):
        'Clean up dirs.'
        try:
            shutil.rmtree(cls.gpgdir)
        except:
            print traceback.format_exc(sys.exc_info()[2])

    def setUp(self):
        'Make sure we have a gpg wrapper object; test accessing own_fingerprint.'
        self.uids = ['Henry Longmore (Some Comment) <user@example.com>', 
                     'Henry S Longmore (Other comment) <user2@example.com>',
                     'Hank K Longmore (Third comment) <user3@example.com>',
                     'H. K. Longmore (The Fourth) <user4@example.com>']

        if not self.gpg:
            self.gpg = keymanager.GpgWrapper(self.keydir, self.name, self.email)
        if not self.fingerprint:
            self.fingerprint = self.gpg.own_fingerprint
        # Above we exercise one code path for own_fingerprint, below another.
        self.assertEquals(self.fingerprint, self.gpg.own_fingerprint)

    def tearDown(self):
        'Track calls to setUp/tearDown, when they equal the number of tests, clean up.'
        self.fingerprint = None

    def testInit(self):
        'Should have our own public key fingerprint.'
        self.assertEqual(self.fingerprint, self.gpg.own_fingerprint)

    ip_pattern = re.compile('(\d{1,3}\.){3}(\d{1,3})')

    def testInitUseIpAddressAsName(self):
        'Passing no name to GpgWrapper should result in ip address as name.'
        # Nota Bene: this is susceptible to failure if we specify an exact
        # expected IP address, so test against it being *an* IP address.
        gpg = keymanager.GpgWrapper(self.keydir, '', self.email)
        match = self.ip_pattern.search(gpg.name_real)
        if match:
            ip_string = match.group(0)
            octets = ip_string.split('.')
            for octet in octets:
                d = int(octet)
                # Not knowing the subnet mask, we'll assume 0 is valid.
                self.assertTrue(0 <= d <= 255)
        else:
            msg = 'IPv4 Address pattern (%s) not matched by %s'
            self.fail(msg % (self.ip_pattern.pattern, gpg.name_real))

    def testOwnFingerprint(self):
        'Accessing own_fingerprint when one already exists should get the existing fingerprint.'
        # Nota Bene: this test requires that the key directory not get deleted in tearDown
        gpg = keymanager.GpgWrapper(self.keydir, self.name, self.email)
        self.assertEquals(self.fingerprint, self.gpg.own_fingerprint)

    # testGenerateOwnKey is tested by accessing own_fingerprint in setUp.
    # testFindFingerprint is tested by accessing own_fingerprint in testOwnFingerprint.

    def testSearchUidsEmailFound(self):
        'Test find_uid for email address.'
        test_string = 'Test User (Silly Comment Not) <%s>' % self.email
        self.uids.append(test_string)
        email = '<%s>' % self.email
        expected = 'Test User (Silly Comment Not) <testgpg@example.com>'
        self.assertEquals(expected, self.gpg.find_uid(email, self.uids))

    def testSearchUidsEmailNotFound(self):
        'Test find_uid for email address that is not there.'
        test_string = 'Test User (Silly Comment Not) <%s>' % self.email
        self.uids.append(test_string)
        email = '<%s>' % self.email
        expected = 'Test User (Silly Comment Not) <testgpg@example.com>'
        self.assertEquals(expected, self.gpg.find_uid(email, self.uids))

    # testSearchUidsNameFound is performed elsewhere by accessing own_fingerprint.
    def testSearchUidsNameNotFound(self):
        'Test find_uid for a name that is not there.'
        self.assertEquals(self.gpg.find_uid('Henry K Longmore', self.uids), None)

    def testGetAsciiKey(self):
        'Test getting ascii public key by accessing own_public_ascii_key'
        lines = self.key_to_import.splitlines()
        expected_first = lines[0]
        expected_last = lines[-1]
        ascii = self.gpg.own_public_ascii_key
        lines = ascii.splitlines()
        actual_first = lines[0]
        actual_last = lines[-1]
        self.assertEquals(expected_first, actual_first)
        self.assertEquals(expected_last, actual_last)

    def testGetPrivateFingerprint(self):
        'Test getting private key fingerprint by accessing own_private_fingerprint'
        fingerprint = self.gpg.own_private_fingerprint
        expected = self.gpg.find_fingerprint(self.name, self.email, private=True)
        self.assertEquals(expected, fingerprint) 
        
    def testGetAsciiKeyPrivate(self):
        'Test getting ascii private key by accessing own_private_fingerprint'
        lines = self.key_to_import.splitlines()
        expected_first = lines[0].replace('PUBLIC', 'PRIVATE')
        expected_last = lines[-1].replace('PUBLIC', 'PRIVATE')
        ascii = self.gpg.own_private_ascii_key()
        lines = ascii.splitlines()
        actual_first = lines[0]
        actual_last = lines[-1]
        self.assertEquals(expected_first, actual_first)
        self.assertEquals(expected_last, actual_last)

    def testEncrypt(self):
        'Test that we get a PGP MESSAGE block when encrypting data.'
        lines = self.key_to_import.splitlines()
        expected_first = lines[0].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        expected_last = lines[-1].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        secret = 'Susan kissed Tommy on the playground by the swings.'
        crypt = self.gpg.encrypt(secret, name='', email=self.email)
        crypt_ascii = '%s' % crypt
        lines = crypt_ascii.splitlines()
        actual_first = lines[0].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        actual_last = lines[-1].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        self.assertEquals(expected_first, actual_first)
        self.assertEquals(expected_last, actual_last)

    def testEncryptHaveFingerprint(self):
        'We should get a PGP MESSAGE block when encrypting data, using fingerprint.'
        lines = self.key_to_import.splitlines()
        expected_first = lines[0].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        expected_last = lines[-1].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        secret = 'Susan kissed Tommy on the playground by the swings.'
        crypt = self.gpg.encrypt(secret, fingerprint=self.fingerprint)
        crypt_ascii = '%s' % crypt
        lines = crypt_ascii.splitlines()
        actual_first = lines[0].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        actual_last = lines[-1].replace('PUBLIC KEY BLOCK', 'MESSAGE')
        self.assertEquals(expected_first, actual_first)
        self.assertEquals(expected_last, actual_last)

    def testImportPublicKey(self):
        'Test that we can import a key and then find its fingerprint.'
        result = self.gpg.import_public_key(self.key_to_import)
        expected = result.fingerprints
        actual = [self.gpg.find_fingerprint('computer ipaddress')]
        self.assertEqual(expected, actual)
    

def suite():
    keymanager_suite = unittest.makeSuite(KeymanagerTest)
    suite = unittest.TestSuite((keymanager_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
