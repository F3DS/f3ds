#!/usr/bin/python

"""
scanning.py: Scanning Library

Classes: ScannableRequest
"""

__author__ = 'Jun Park and Matt Probst'
__version__ = '0.1'

# Python standard library modules
import httplib
import os
import pickle
import subprocess
import sys
import time
import traceback
import urllib
import urlparse
import uuid
import xmlrpclib

from datetime import datetime

# 3rd party modules
from twisted.internet import defer, reactor

# Our modules
from socialscan import scanhandlers
from socialscan.exceptions import IncompleteScanError
from socialscan.log import Logger
from socialscan.model import Peer, Scan, SentScanRequest, ScanDigestFile, SocialRelationship
from socialscan.util import Safety, cached, TimeMeasurer

# __file__ is <source dir>/socialscan/socialscan/scanning.py
# F3DS dir is <source dir>/f3ds/framework/
dn = os.path.dirname
f3dsdir = os.path.realpath(dn(dn(dn(__file__))))


class ScannableRequest(object):
    """
    State object representing the state of a request. Includes most code required to do scanning of a url.

    @type url: C{str}
    @ivar url: url that was requested

    @type filesize: C{int}
    @ivar filesize: size of the file at the requested url
    
    @type hash: C{str} (empty string for not available)
    @ivar hash: the hash of the file, if the file has been retrieved and hashed. use L{getHash} to
                ensure this happens. L{dolocalscan} performs a download and hash, if one has not
                already been done.

    @type fileid: C{str}
    @ivar fileid: the UUID of the file downloaded.
                  C{config.scanning.download_location.format(id=fileid)} will give the path to the
                  downloaded file, and C{config.scanning.local_server_url.format(id=fileid)} will
                  give an http url to the same file.

    @type timeout: C{float}
    @ivar timeout: timeout to schedule when sleep() is called
    """
    def __init__(self, config, session, url=None, parentrequest=None,
                 digestmanager=None, scanlogmanager=None):
        self.logger = Logger("Scanner")
        self.config = config
        self.session = session
        self.handler = scanhandlers.get(config.scanning.handler)

        if not url and not parentrequest:
            raise Exception("url or parentrequest must be provided!")
        elif not url:
            self.url = parentrequest.url
        else:
            self.url = url

        self.fileid = None
        self.parentrequest = parentrequest
        self.digestmanager = digestmanager
        self.scanlogmanager = scanlogmanager
        try:
            self.timeout = float(self.config.scanning.timeout)
        except:
            self.timeout = 0.1
        self.headers = {}
        self.downloaded_filepath = ''
        self.downloaded_filesize = -1 # an invalid size and can safely be used for "unknown"
        self.objectage = None
        self.contenthash = ''
        self.scan = None
        self.closepeers = []

    def sleep(self):
        """
        @return: a twisted Deferred that will be called L{timeout} seconds after
        this method is called
        @rtype: C{twisted.internet.defer.Deferred}
        """
        d = defer.Deferred()
        reactor.callLater(self.timeout, d.callback, None)
        return d

    #@cached
    def retrieve(self):
        """
        Retrieve the url via http and store it.
        urllib warning: When opening HTTPS URLs, does not attempt to validate the server certificate.
        """
        self.logger.log('ScannableRequest.retrieve called')
        with TimeMeasurer() as retrieve_timer:
            id = str(uuid.uuid4())
            filepath = self.config.scanning.download_location.format(id=id)
            if not os.path.exists(os.path.dirname(filepath)):
                os.makedirs(os.path.dirname(filepath))
            self.fileid = id
            # grab file with a subprocess...
            script_name = 'urlretrieve.py'
            script_path = os.path.join(f3dsdir, script_name)
            proc = subprocess.Popen(["python", script_path, self.url, filepath],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            if(proc.returncode != 0):
                error = proc.stderr.readlines()
                self.logger.log("Error downloading url %s for scanning: %s " % (self.url, error))
                raise IncompleteScanError
            else:
                lines = proc.stdout.readlines()
                lines[:] = [l.strip() for l in lines]
                filepath, headers = pickle.loads('\n'.join(lines))
        self.downloaded_filepath = filepath
        self.headers = dict(headers)
        self.retrievems = int(retrieve_timer.total * 1000.0)  # time.time() uses seconds, not ms

    @property
    def filepath(self):
        """
        Ensure we have downloaded the file when trying to use filepath.
        """
        if not self.downloaded_filepath:
            self.retrieve()
        return self.downloaded_filepath

    def retrieveHeaders(self):
        """
        Retrieve the headers from the url via HTTP HEAD, if they are not already stored.
        """
        if not self.headers:
            oururl = urlparse.urlparse(self.url)
            if oururl.scheme == "http":
                conn = httplib.HTTPConnection(oururl.netloc)
            else:
                conn = httplib.HTTPSConnection(oururl.netloc)
            conn.request("HEAD", oururl.path)
            response = conn.getresponse()
            self.headers = dict(response.getheaders())
        if self.downloaded_filesize < 0:
            try:
                content_length = self.headers["content-length"]
                self.downloaded_filesize = int(content_length)
            except KeyError:
                self.logger.log("url returned no content-length: %r" % (self.url))
            except ValueError:
                self.logger.log("url returned invalid filesize: %r" % content_length)
        if not self.objectage:
            try:
                age = self.headers['last-modified']
                self.objectage = datetime.strptime(age, '%a, %d %b %Y %H:%M:%S %Z')
            except KeyError:
                self.logger.log('url returned no last-modified: %r' % (self.url))
            except ValueError:
                self.logger.log('url returned invalid last-modified: %r' % age)
        # message-length should be handled too:
        # http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.4

    @property
    def filesize(self):
        """
        Ensure we have the filesize when we try to use it.
        """
        if self.downloaded_filesize < 0:
            self.retrieveHeaders()
        # If it is still invalid, see what the os can give us
        if self.downloaded_filesize < 0:
            try:
                self.downloaded_filesize = os.path.getsize(self.filepath)
            except (IOError, WindowsError), e:
                msg = "Error while processing %s (file stats for file at %s): %s"
                self.logger.log(msg % (self.url, self.filepath, e))
                raise IncompleteScanError
        return self.downloaded_filesize

    @property
    def age(self):
        """
        Ensure we have the object's age when we try to use it.
        """
        if not self.objectage:
            self.retrieveHeaders()
        return self.objectage

    def _scansQuery(self, use_size, enforce_size, enforce_hash, owner):
        """
        Get scans from the database, possibly filtering by size or content hash.
        """
        msg = 'getting scans from db, with query params '
        msg += 'use_size: %s, enforce_size: %s, enforce_hash: %s, and owner: %s'
        self.logger.log(msg % (use_size, enforce_size, enforce_hash, owner))
        query = self.session.query(Scan)
        if owner:
            query = query.filter(Scan.owner==self.config.owner)
        query = query.filter(Scan.url==self.url).filter(Scan.tainted==False)
        if enforce_hash or self.hash:
            query = query.filter(Scan.hash==self.hash)
        if enforce_size or (use_size and self.filesize > -1):
            query = query.filter(Scan.filesize==self.filesize)
        return query

    def getRelevantScans(self, use_size=True, enforce_size=False, enforce_hash=False):
        """
        Retrieve any relevant scans from the database.
        """
        return self._scansQuery(use_size, enforce_size, enforce_hash, False).all()

    def getRelevantActiveScans(self, use_size=False, enforce_size=False, enforce_hash=False):
        """
        Retrieve any relevant scans from the database, don't enforce size as it does not
        get added to Scan objects, not here, not remotely returned results in rpccommands.
        """
        return self._scansQuery(use_size, enforce_size, enforce_hash, False).all()

    def getHash(self):
        """
        Get the hash of the file, downloading and hashing it as necessary. Cached.

        @rtype: C{str}
        @return: L{hash}
        """
        # Read file contents using a subprocess.
        script_name = 'filehash.py'
        script_path = os.path.join(f3dsdir, script_name)
        # TODO: add a Timer thread to interrupt if it takes too long.
        try:
            data = subprocess.check_output(['python', script_path, self.filepath])
        except IncompleteScanError:
            self.logger.log('Failed to download %s, unable to get hash' % (self.filepath))
            return ''
        except subprocess.CalledProcessError, e:
            self.logger.log('Non-zero return code from %s' % script_name)
            self.logger.log('Return code: %s, output: %s' % (e.returncode, e.output))
            return ''
        except Exception, e:
            self.logger.log('Unknown failure while trying to download %s' % (self.filepath))
            self.logger.log('Exception was: %s' % e)
            return ''
        self.logger.log('Waiting: %s' % self.filepath)
        self.logger.log('output of filehash.py: %s' % data)
        lines = data.split('\r\n')
        if 'opened' == lines[0]:
            if len(lines) > 1:
                lines[:] = lines[1:]
            else:
                return ''
        lines[:] = [l.strip() for l in lines]
        self.contenthash = pickle.loads('\n'.join(lines))
        self.logger.log('Got contenthash: %s' % self.contenthash)

    @property
    def hash(self):
        """
        Ensure we have the content hash when we try to access it.
        """
        if not self.contenthash:
            self.getHash()

        return self.contenthash

    #@cached
    def dolocalscan(self):
        """
        Get or perform a local scan. Performed when first called, then L{cached} for future calls.

        @rtype: L{socialscan.model.Scan}
        @return: the scan performed for this request
        """
        if self.scan:
            return self.scan

        self.session.commit()  # release the session lock for following long operation
        filepath = self.filepath
        shasum = self.hash

        if shasum == None:
            scan_timer = TimeMeasurer()
            try:
                scantime = int(scan_timer.total * 10000.0)
            except AttributeError:
                scantime = 0
            siginfo = self.handler.getSigInfo()
            malicious = True
        else:
            with TimeMeasurer() as scan_timer:
                malicious, siginfo = self.handler.scan(filepath)
            try:
                scantime = int(scan_timer.total * 1000.0)  # time.time() uses seconds
            except AttributeError:
                scantime = 0

        if self.parentrequest:
            request = self.parentrequest
            peer = request.peer
        else:
            request = None
            peer = None

        scan = Scan(self.config.owner, "local", self.url, malicious, siginfo, hash=shasum,
                    scantime=scantime, retrievems=self.retrievems, peer=peer, request=request)
        self.session.add(scan)
        self.session.commit()
        self.scan = scan

    @property
    def localscan(self):
        """
        A local scan is loaded from the database if previously scanned or scanned newly as necessary.

        @rtype: L{socialscan.model.Scan}
        """
        self.logger.log('ScannableRequest.localscan called/accessed')
        if not self.scan:
            self.logger.log('no scan found in ScannableRequest.  Checking database.')
            scan = self._scansQuery(True, True, True, True).first()
            if scan:
                self.logger.log('found scan in database.')
                self.scan = scan
            else:
                self.logger.log('calling dolocalscan()')
                self.dolocalscan()
        self.logger.log('Returning self.scan: %s' % self.scan)
        return self.scan

    def alreadySent(self):
        """
        An sqlalchemy query resulting in peers to whom scan requests have been sent,
        for use in a query's .except_() when assembling a list of peers to send scan requests to.

        @rtype: sqlalchemy.orm.query.Query
        """
        self.logger.log('ScannableRequest.alreadySent called')
        return self.session.query(Peer)\
                        .join(SentScanRequest.peer)\
                        .filter(SentScanRequest.owner==self.config.owner)\
                        .filter(SentScanRequest.url==self.url)\
                        .with_entities(Peer)

    def getPeers(self):
        """
        Returns an sqlalchemy query of peers within configured maximum distance.
        """
        maxdist = float(self.config.scanning.max_active_distance)
        peersquery = self.config.owner.queryRelated(self.session)
        return peersquery.filter(SocialRelationship.pdistance <= maxdist)

    @property
    def peers(self):
        if not self.closepeers:
            self.closepeers = self.getPeers().all()
        return self.closepeers

    def requestActiveScans(self, peers=None):
        """
        Request a scan from peers. Not @cached.

        @type peers: list of L{socialscan.model.Peer}
        @param peers: list of peers to send scan requests to; optional.  Note that
                      the default of peers=None will not request the same url of a
                      given peer more than once.
        @rtype: None
        @return: 
        """
        if not peers:
            peers = self.getPeers().except_(self.alreadySent()).all()

        retries = int(self.config.scanning.max_active_retries)
        while peers and retries > 0:
            failures = []
            for peer in peers:
                self.logger.log("Sending active scan request to peer %r" % peer)
                request = SentScanRequest(self.config.owner, self.url, peer)
                self.session.commit()  # release the database lock for following long operation
                try:
                    peer.transport.scanRequest(self.config.owner.name, self.url, request.key)
                except:
                    self.logger.exception()
                    failures.append(peer)
                else:
                    self.session.add(request)
            peers[:] = failures
            retries = 0 #-= 1 # Disable retries for now.
        self.session.commit()

    #@property
    #@cached
    def digestscans(self):
        """
        The scan information retrieved from the currently loaded digests in sdmanager.
        Lazy loaded when referenced.

        @rtype: list of L{socialscan.searchutil.SearchResult}
        """
        self.logger.log('ScannableRequest.digestscans called')
        results = []
        self.logger.log('searching digests for %r' % self.url)
        found = self.digestmanager.search(self.url, self.filesize, self.hash, aggregate=True)
        if found:
            self.logger.log('found in digest, now searching scanlog')
            results = self.scanlogmanager.search(self.url, self.filesize, self.hash)
            if results:
                self.logger.log('found in scanlog: %r' % (results))
        return results

