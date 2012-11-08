#!/usr/bin/python

import traceback

from f3ds.framework.sethash import hasher


class SearchResult(object):
    """
    Represents an individual result from a digest. Intended to appear to be a L{Scan}.

    @ivar malicious: Indicates whether the safety represented is malicious or not.
    @type malicious: C{bool}

    @ivar safety: safety object that this result represents
    @type safety: L{Safety}

    @ivar digest: Digest that this result came from
    @type digest: L{ScanDigestFile}
    """
    def __init__(self, parent, digest, safety):
        self.filesize = parent.filesize
        self.hash = parent.contenthash
        self.url = parent.url

        self.malicious = safety.ismalicious
        self.safety = safety
        self.digest = digest

        self.siginfo = digest.siginfo
        self.scannervv = digest.scannervv
        self.sigversion = digest.sigversion
        self.sigdate = digest.sigdate
        self.peer = digest.creator
        self.timestamp = digest.date

    def markTainted(self, session, punishment=1.5):
        """
        @see: L{socialscan.model.ScanDigestFile.markTainted}
        """
        self.digest.markTainted(session, punishment)
 
