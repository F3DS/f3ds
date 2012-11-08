#!/usr/bin/python
"""
Code to handle innards of scan digests.
"""

# Standard python modules
import datetime
import os
import random
# see http://docs.python.org/library/struct.html for struct documentation
# particularly of the format strings
import struct
import time

# 3rd party modules
from pybloom import ScalableBloomFilter

# Our modules
from f3ds.framework.log import Logger
from f3ds.framework.exceptions import (ContainerFullError, ZeroSizedDigestError,
                                       DigestModifiedTimeError)
from f3ds.framework.util import UrlObject
from socialscan.util import SigInfo


class Digest(object):
    """
    IMPORTANT:

    Represents a digest, which stores urls using a bloomfilter.

    @ivar nonce: random salt stored with the digest file to make the hashes unpredictable.
                  ranged C{0} to C{0xffffffff-1}.
    @type nonce: C{int}

    @ivar filterS: Bloom filter
    @type filterS: C{ScalableBloomFilter}

    @ivar maxcapacity: maximum number of items to store in this digest.
    @type maxcapacity: C{int}

    @ivar meta: Meta data about what items can be stored in this digest. Type will be
    determined by subclasses.

    @ivar saved: whether this digest has been saved since items were added.
    @type saved: C{bool}
    """
    # Compile just one format string, just once for the class
    # Packing is for int: self.nonce
    #                int: self.maxcapacity
    #                int: self.urlcount
    #                str: self.meta
    transformer = struct.Struct('<III150p')

    def __init__(self, maxcapacity, meta, filename, filterS=None, nonce=None):
        """
        @param filterS: object to use as filterS if not None. if None, a new filter will be created.
        @type filterS: C{ScalableBloomFilter} or C{None}

        @param nonce: if not None, the nonce to use. When None, a new one will be generated.
        @type nonce: C{int}
        """
        self.saved = True  # nothing to save until add is called.
        if nonce != None:
            self.nonce = nonce
        else:
            self.nonce = random.randint(0, 0xffffffff)
        self.filterS = filterS or ScalableBloomFilter()
        self.maxcapacity = maxcapacity
        self.meta = meta
        self.urlcount = 0
        self.filename = filename

    def get(self, obj):
        """
        Get the information about a UrlObject.  The UrlObject will have a url property
        and a contenthash property.  These represent a hexdigest of a hash of the actual
        url and the contents located at the url respectively.

        @param obj: object to search for
        @type obj: L{UrlObject}
        """
        found = False
        try:
            contenthash = obj.contenthash
        except AttributeError:
            pass
        else:
            if contenthash:
                found = contenthash.decode("hex") in self.filterS
        return found or obj.url.decode('hex') in self.filterS

    def __len__(self):
        """
        Determine the length of the confidence filter
        """
        return self.urlcount

    def _addkey(self, key):
        # If the last one added filled this digest to capacity, don't add another.
        if len(self) >= self.maxcapacity:
            raise ContainerFullError
        self.saved = False
        return self.filterS.add(key)

    def add(self, item, extra=None):
        """
        Param extra is deliberately unused; it exists for the interface.
        """
        # Refuse to add an empty url hash and empty contents hash.
        added = False
        if not item:
            return added
        try:
            contenthash = item.contenthash
        except AttributeError:
            pass
        else:
            if contenthash:
                added = not self._addkey(contenthash.decode('hex'))
        if item.url:
            added = not self._addkey(item.url.decode('hex')) or added
        if added:
            self.urlcount += 1
        return added

    def makedirs(self):
        filedir = os.path.dirname(self.filename)
        try:
            if not os.path.isdir(filedir):
                os.makedirs(filedir)
        except:
            return False
        else:
            return True

    # TODO: should we be saving self.hits as well?
    def save(self):
        """
        Write the filters for this digest to a seekable file-like object.
        Based off of the equivalent method in ScalableBloomFilter.
        """
        if not self.saved:
            now = time.time()
            with open(self.filename, "wb") as f:
                f.write(self.transformer.pack(self.nonce, self.maxcapacity,
                                              self.urlcount, str(self.meta)))
                self.filterS.tofile(f)
            self.saved = True
            self.verify_save(now)

    def verify_save(self, age=0):
        """
        If a digest is written with 0 bytes, there was a problem.  Stop the system so
        it can be found.  Double-check the last modification time.
        """
        size = os.path.getsize(self.filename)
        if not size > 0:
            msg = 'file %s has size %s bytes' % (self.filename, size)
            raise ZeroSizedDigestError(msg)
        newer = os.path.getmtime(self.filename)
        if not newer >= age:
            msg = 'file %s age in seconds since the epoch is %s, but expected something >= %s'
            raise DigestModifiedTimeError(msg % (self.filename, newer, age))

    def close(self):
        """
        Make sure digest changes are written.
        """
        try:
            self.save()
        except IOError:
            pass

    @classmethod
    def load(cls, filename):
        #import pdb; pdb.set_trace()
        t = cls.transformer
        size = t.size
        with open(filename, "rb") as serialized_digest:
            readdata = serialized_digest.read(size)
            if len(readdata) != size:
                msg = 'invalid amount read from file for format %r: %r (should have been %d)'
                Logger("digest.load").log(msg % (t.format, readdata, size))
                raise ValueError
            nonce, maxcapacity, urlcount, meta = t.unpack(readdata)

            # If meta has a conversion from string repr, use it.
            if hasattr(self, 'meta_from_string'):
                meta = self.meta_from_string()
            filterS = ScalableBloomFilter.fromfile(serialized_digest)
        digest = cls(maxcapacity, meta, filename, filterS=filterS, nonce=nonce)
        digest.urlcount = urlcount
        return digest


