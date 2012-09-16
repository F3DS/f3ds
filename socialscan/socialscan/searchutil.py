#!/usr/bin/python

import traceback

from socialscan.sethash import hasher


class UrlObject(object):
    """
    Represents a url and the file at the url.

    @ivar url: the url to represent.
    @type url: C{str}

    @ivar filesize: the filesize in bytes of the file at the url.
    @type filesize: C{int}

    @ivar hash: hexdigest of a hash of the content of the file at the url. May be C{None}.
    @type hash: C{str} or C{None}
    """
    def __init__(self, url, filesize, nonce='', hash='', is_hashed=False):
        """
        @param url: the url to represent.
        @param filesize: the filesize in bytes of the file at the url.
        @param hash: optional; if provided, the hexdigest of a hash of the file at the url.
        """
        self.hash = ''
        self.filehash = ''
        self.filesize = filesize 
        self.objecthash = hash if hash and isinstance(hash, basestring) else ''
        self.nonce = nonce
        noncehash = self._makehash(self.nonce)
        self.empty_contenthash = noncehash.hexdigest()
        noncehash.update(str(self.filesize))
        self.empty_url = noncehash.hexdigest()
        self.prehashed = False
        if is_hashed:
            self.hash = url
            self.filehash = hash
            self.plain = ''
            self.objecthash = ''
            self.prehashed = True
        else:
            self.plain = url if url and isinstance(url, basestring) else ''
            trash = self.url if self.plain else ''
            refuse = self.contenthash if self.objecthash else ''

    @property 
    def url(self):
        if not self.hash:
            #self.hash = self._makehash(self.nonce, self.plain, str(self.filesize))
            self.hash = self._makehash(self.plain)
            #self.plain = ''
        return self._extracthash(self.hash, self.empty_url)

    @property
    def contenthash(self):
        if not self.filehash:
            #self.filehash = self._makehash(self.nonce, self.objecthash)
            self.filehash = self._makehash(self.objecthash)
            #self.objecthash = ''
        return self._extracthash(self.filehash, self.empty_contenthash)

    def _makehash(self, *values):
        hash = hasher()
        for value in values:
            hash.update(value)
        return hash

    def _extracthash(self, hashobj, empty):
        try:
            digest = hashobj.hexdigest()
        except AttributeError:
            return hashobj
        else:
            #if digest == empty:
            #    return ''
            return digest

    def __repr__(self):
        repr_string = 'UrlObject(%r, %r' % (self.url, self.filesize)
        if self.nonce:
            repr_string += ', nonce=%r' % (self.nonce)
        if self.hash:
            repr_string += ', hash=%r' % (self.filehash)
        repr_string += ', is_hashed=True)' 
        return repr_string

    def __str__(self):
        return '(%s, %s)' % (self.url, self.contenthash)

    def __nonzero__(self):
        if not self.url and not self.contenthash:
            return False
        return True

    def __eq__(self, other):
        'Two UrlObjects are equal if they have the same url, contenthash, and nonce.'
        if other == None: return False
        if self.url != other.url: return False
        if self.contenthash != other.contenthash: return False
        if self.nonce != other.nonce: return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


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
 
