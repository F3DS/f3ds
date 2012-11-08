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
from f3ds.framework.model.digest import Digest
from f3ds.framework.util import UrlObject
from socialscan.util import SigInfo


class ScanDigest(Digest):
    """
    IMPORTANT:
    this class should be considered an implementation detail of the higher level
    C{socialscan.model.ScanDigestFile}!

    Represents a scan digest, which stores urls that have been scanned using a bloomfilter.

    @ivar nonce: random salt stored with the digest file to make the hashes unpredictable.
                  ranged C{0} to C{0xffffffff-1}.
    @type nonce: C{int}

    @ivar filterS: Bloom filter representing "scanned" portion of data.
    @type filterS: C{ScalableBloomFilter}

    @ivar maxcapacity: maximum number of scans to store in this digest.
    @type maxcapacity: C{int}

    @ivar siginfo: Signature information about what scans can be stored in this digest.
    @type siginfo: L{SigInfo}

    @ivar saved: whether this digest has been saved since scans were added.
    @type saved: C{bool}
    """
    # Compile just one format string, just once for the class
    # Packing is for int: self.nonce
    #                int: self.maxcapacity
    #                int: self.urlcount
    #                str: self.siginfo.scannervv
    #                str: self.siginfo.sigversion
    #                int: time.mktime(self.siginfo.sigdate.timetuple())
    transformer = struct.Struct('<III50p50pI')

    def __init__(self, maxcapacity, siginfo, filename, filterS=None, nonce=None):
        """
        @param filterS: object to use as filterS if not None. if None, a new filter will be created.
        @type filterS: C{ScalableBloomFilter} or C{None}

        @param nonce: if not None, the nonce to use. When None, a new one will be generated.
        @type nonce: C{int}
        """
        super(ScanDigest, self).__init__(maxcapacity, siginfo, filename, filterS, nonce)
        self.siginfo = siginfo


    # TODO: should we be saving self.hits as well?
    def save(self):
        """
        Write the filters for this digest to a seekable file-like object.
        Based off of the equivalent method in ScalableBloomFilter.  This
        overrides the base class method so the packing can use the siginfo.
        """
        if not self.saved:
            now = time.time()
            with open(self.filename, "wb") as f:
                f.write(self.transformer.pack(self.nonce, self.maxcapacity,
                                              self.urlcount,
                                              str(self.siginfo.scannervv),
                                              str(self.siginfo.sigversion),
                                              int(time.mktime(self.siginfo.sigdate.timetuple()))))
                self.filterS.tofile(f)
            self.saved = True
            self.verify_save(now)


    @classmethod
    def load(cls, filename):
        """
        This overrides the base class method to unpack using the siginfo.
        """
        #import pdb; pdb.set_trace()
        t = cls.transformer
        size = t.size
        with open(filename, "rb") as serialized_digest:
            readdata = serialized_digest.read(size)
            if len(readdata) != size:
                msg = 'invalid amount read from file for format %r: %r (should have been %d)'
                Logger("scandigest.load").log(msg % (t.format, readdata, size))
                raise ValueError
            nonce, maxcapacity, urlcount, scannervv, sigversion, sigtimestamp = t.unpack(readdata)

            # Read the datetime as non-utc, since that's how we wrote it with mktime.
            siginfo = SigInfo(scannervv, sigversion,
                              datetime.datetime.fromtimestamp(sigtimestamp))
            filterS = ScalableBloomFilter.fromfile(serialized_digest)
        scandigest = cls(maxcapacity, siginfo, filename, filterS=filterS, nonce=nonce)
        scandigest.urlcount = urlcount
        return scandigest

