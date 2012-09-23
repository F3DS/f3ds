"""
Unit test module for searchutil module
Run tests by executing on the command line: python test_searchutil.py
"""

import hashlib
import sys
import unittest

from os import path
from unittest import skipUnless

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_searchutil.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)


from socialscan import searchutil
from socialscan.model import Peer, ScanDigestFile
from f3ds.framework import sethash
from socialscan.util import Safety


class UrlObjectTest(unittest.TestCase):
    name = 'testbox'

    def testInit(self):
        'Test that creating a new UrlObject results in a url hash and a content hash'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name)
        self.assertNotEqual(uo.url, plain_url)
        self.assertEqual(uo.filesize, filesize)
        self.assertEqual(uo.nonce, self.name)
        self.assertEqual(uo.contenthash, '')
        self.assertFalse(uo.plain)
        self.assertFalse(uo.objecthash)
        with self.assertRaises(AttributeError):
            if self.is_hashed:
                pass

    def testInitHashedUrl(self):
        'Test creating a new UrlObject with an already-hashed url'
        hashed_url = 'https://amason.com/buywarez'
        filesize = 6433
        uo = searchutil.UrlObject(hashed_url, filesize, nonce=self.name, is_hashed=True)
        self.assertEqual(uo.url, hashed_url)
        self.assertEqual(uo.filesize, filesize)
        self.assertEqual(uo.nonce, self.name)
        self.assertEqual(uo.contenthash, '')
        self.assertFalse(uo.plain)
        self.assertFalse(uo.objecthash)
        with self.assertRaises(AttributeError):
            if self.is_hashed:
                pass

    def testInitContentHash(self):
        'Test that creating a new UrlObject gives url hash and content hash updated with nonce'
        plain_url = 'https://worstbuy.com/buyflops'
        filesize = 7431
        hash = 'a3e8cd964bafe231aebacef43fea7a98bfc1de64facebaceacebeefdeaddeaf'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        self.assertNotEqual(uo.url, plain_url)
        self.assertEqual(uo.filesize, filesize)
        self.assertEqual(uo.nonce, self.name)
        self.assertNotEqual(uo.contenthash, uo._makehash(self.name).hexdigest())
        self.assertNotEqual(uo.contenthash, '')
        self.assertFalse(uo.plain)
        self.assertFalse(uo.objecthash)
        with self.assertRaises(AttributeError):
            if self.is_hashed:
                pass
        self.assertNotEqual(uo.contenthash, hash)

    def testInitHashedUrlAndContentHash(self):
        'Test creating UrlObject with existing url hash and content hash'
        hashed_url = 'https://amason.com/buywarez'
        filesize = 27436
        hash = 'a3e8cd964bafe231aebacef43fea7a98bfc1de64facebaceacebeefdeaddeaf'
        uo = searchutil.UrlObject(hashed_url, filesize, nonce=self.name, hash=hash, is_hashed=True)
        self.assertEqual(uo.url, hashed_url)
        self.assertEqual(uo.filesize, filesize)
        self.assertEqual(uo.nonce, self.name)
        self.assertNotEqual(uo.contenthash, uo._makehash(self.name).hexdigest())
        self.assertEqual(uo.contenthash, hash)
        self.assertFalse(uo.plain)
        self.assertFalse(uo.objecthash)
        with self.assertRaises(AttributeError):
            if self.is_hashed:
                pass

    def testMakeHash(self):
        'Test _makehash works as expected'
        plain_url = 'http://www.barnesandnible.com/u/Evil-Mook/374213414'
        filesize = 94382673
        hash = 'aceabeaaddbasebeefbeebecadecafecabcaddeafdeaddabfacefadefeedfae'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        self.assertEqual(uo.contenthash, uo._makehash(self.name, hash).hexdigest())
      
    def testUrlProperty(self):
        'Test that accessing url property does not change it'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name)
        current = uo.url
        self.assertEqual(current, uo.url)
      
    def testContentHashProperty(self):
        'Test that accessing contenthash property does not change it'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name)
        current = uo.contenthash
        self.assertEqual(current, uo.contenthash)

    @skipUnless(sethash.hasher == hashlib.sha512, 'Expected value requires sha512')
    def testRepr(self):
        'Test repr makes sense'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name)
        actual = uo.__repr__()
        expected = """UrlObject('\
cbf16c0096270ebc5de04a4a32f60694\
2672476ba3966ebe7ed8e4e54241933f\
2fdc168b71fa6e0b1aa1bfac8f589a86\
aa671bbf7cc781825435501ecafdb417\
', 5433, nonce='testbox', hash='', is_hashed=True)"""
        self.assertEqual(expected, actual)

    @skipUnless(sethash.hasher == hashlib.sha512, 'Expected value requires sha512')
    def testStr(self):
        'Test str looks good'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name)
        actual = uo.__str__()
        expected = """(\
cbf16c0096270ebc5de04a4a32f60694\
2672476ba3966ebe7ed8e4e54241933f\
2fdc168b71fa6e0b1aa1bfac8f589a86\
aa671bbf7cc781825435501ecafdb417\
, )"""
        self.assertEqual(expected, actual)

    @skipUnless(sethash.hasher == hashlib.sha512, 'Expected value requires sha512')
    def testStrHashContents(self):
        'Test str looks good'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        actual = uo.__str__()
        expected = """(\
cbf16c0096270ebc5de04a4a32f60694\
2672476ba3966ebe7ed8e4e54241933f\
2fdc168b71fa6e0b1aa1bfac8f589a86\
aa671bbf7cc781825435501ecafdb417\
, \
5232f54390ce5bc545e211a7e13410b4\
4e32630fa0ee4c76ce0b90efd1658c36\
0a72f213a75d11ff8f899e69fd90b436\
278d2ee32558ef0084c27f657606e942\
)"""
        self.assertEqual(expected, actual)

    def testEmptyUrl(self):
        'Test that an empty url will be False in a boolean context'
        plain_url = ''
        filesize = 4332
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name)
        self.assertFalse(uo.url)

    def testEmptyHash(self):
        'Test that an empty content hash will be False in a boolean context'
        plain_url = 'https://offacemix.com/stilurcc.jsp'
        filesize = 5433
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash='')
        self.assertFalse(uo.contenthash)

    def testEmptyUrlEmptyHash(self):
        'Test that an empty url and empty content hash will be False in a boolean context'
        plain_url = ''
        filesize = 4332
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash='')
        self.assertFalse(uo.url)
        self.assertFalse(uo.contenthash)
        self.assertFalse(uo)

    def testEqual(self):
        'Test that two equivalent UrlObjects are equal.'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo1 = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        uo2 = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        self.assertEqual(uo1, uo2)

    def testNotEqualUrl(self):
        'If the urls are different, two UrlObjects are not equal.'
        plain_url1 = 'https://amason.com/buywarez'
        plain_url2 = 'http://amason.com/buywarez'
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo1 = searchutil.UrlObject(plain_url1, filesize, nonce=self.name, hash=hash)
        uo2 = searchutil.UrlObject(plain_url2, filesize, nonce=self.name, hash=hash)
        self.assertNotEqual(uo1, uo2)

    def testNotEqualContenthash(self):
        'If the contenthashes are different, two UrlObjects are not equal.'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash1 = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        hash2 = 'afa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo1 = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash1)
        uo2 = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash2)
        self.assertNotEqual(uo1, uo2)

    def testNotEqualNonce(self):
        'Two UrlObjects are not equal if their nonces are not, even if other parts are equal.'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        nonce1 = self.name
        nonce2 = self.name + 'ed'
        uo1 = searchutil.UrlObject(plain_url, filesize, nonce=nonce1, hash=hash)
        uo2 = searchutil.UrlObject(plain_url, filesize, nonce=nonce2, hash=hash)
        self.assertNotEqual(uo1, uo2)

    def testNoErrorOnHashNone(self):
        'Test that giving a hash of None will not result in an error.'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash = None
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)

    def testNoErrorOnUrlNone(self):
        'Test that giving a url of None will not result in an error.'
        plain_url = None
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)

    def testNoErrorOnHashNonString(self):
        'Test that giving a non-string for the hash will not result in an error.'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash = list(set('supercalifragilisticexpialadocious?'))
        hash.sort()
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)

    def testNoErrorOnUrlNonString(self):
        'Test that giving a non-string for the url will not result in an error.'
        plain_url = list(set('http://www.zippity.com/someurlshavemorelettersinthemthanothers'))
        plain_url.sort()
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)

    def testNotEmptyIfUrlIsUnicode(self):
        'Test that if the url is unicode it will still work.'
        plain_url = u'https://amason.com/buywarez'
        filesize = 5433
        hash = '9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        self.assertTrue(uo.url)
        self.assertTrue(uo.contenthash)
        self.assertTrue(uo)

    def testNotEmptyIfHashIsUnicode(self):
        'Test that it still works if the content hash is unicode.'
        plain_url = 'https://amason.com/buywarez'
        filesize = 5433
        hash = u'9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        self.assertTrue(uo.url)
        self.assertTrue(uo.contenthash)
        self.assertTrue(uo)

    def testNotEmptyIfUrlAndHashAreUnicode(self):
        'Test that if the url and the hash are unicode it is still good.'
        plain_url = u'https://amason.com/buywarez'
        filesize = 5433
        hash = u'9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        self.assertTrue(uo.url)
        self.assertTrue(uo.contenthash)
        self.assertTrue(uo)

    def testUrlObjectComparedWithNone(self):
        'None and a UrlObject are not equivalent.'
        plain_url = u'https://seasemestret.com/piedpiper'
        filesize = 5433
        hash = u'9fa3ce1ba6ce2de7af3de8ad4be1e4f0'
        uo1 = searchutil.UrlObject(plain_url, filesize, nonce=self.name, hash=hash)
        uo2 = None
        if uo1 == uo2:
            msg = 'UrlObject %s and %s are not equal, but yet they are?'
            raise Exception(msg % (uo1, uo2))


class SearchResultTest(unittest.TestCase):
    name = 'testbox'
    owner = Peer('test-owner', 'test-owner', 'test-owner')
    bindhost = '127.0.0.1'
    port = '8123'
    url = 'http://%s:%s/shared/digests/{uuid}' % (bindhost, port)
    location = 'data/shared/digests/{uuid}'
    sdfile = None

    def setUp(self):
        self.sdfile = ScanDigestFile(self.owner, url=self.url, location=self.location)
    
    def testInit(self):
        'Testing SearchResult initialization.'
        plain_url = 'http://facebool.com/pownership.aspx'
        uo = searchutil.UrlObject(plain_url, 2343, nonce=self.name)
        expected_safety = Safety(True, True)
        sr = searchutil.SearchResult(uo, self.sdfile, expected_safety)
        self.assertEqual(sr.filesize, uo.filesize)
        self.assertEqual(sr.hash, uo.contenthash)
        self.assertEqual(sr.url, uo.url)
        self.assertNotEqual(sr.url, plain_url)
        self.assertEqual(sr.malicious, expected_safety.ismalicious)
        self.assertEqual(sr.safety, expected_safety)
        self.assertEqual(sr.digest, self.sdfile)
        self.assertEqual(sr.siginfo, self.sdfile.siginfo)
        self.assertEqual(sr.scannervv, self.sdfile.scannervv)
        self.assertEqual(sr.sigversion, self.sdfile.sigversion)
        self.assertEqual(sr.sigdate, self.sdfile.sigdate)
        self.assertEqual(sr.timestamp, self.sdfile.date)

    def testMarkTaintedNoPeer(self):
        'Testing markTainted with no peer defined.'
        plain_url = 'http://googke.com/pownership.aspx'
        uo = searchutil.UrlObject(plain_url, 2343, nonce=self.name)
        expected_safety = Safety(True, True)
        sr = searchutil.SearchResult(uo, self.sdfile, expected_safety)
        self.assertRaises(NotImplementedError, sr.markTainted, (None,)) 


def suite():
    urlobject_suite = unittest.makeSuite(UrlObjectTest)
    searchresult_suite = unittest.makeSuite(SearchResultTest)
    suite = unittest.TestSuite((urlobject_suite, searchresult_suite))
    return suite


if __name__ == "__main__":
    unittest.main()
