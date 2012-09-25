#!/usr/bin/python

# Standard Python modules
import os
import sys
import time
import traceback
import urllib
import uuid
import xmlrpclib

from datetime import datetime
from multiprocessing import Process
from SimpleXMLRPCServer import SimpleXMLRPCServer

# 3rd party modules
from sqlalchemy import and_, or_

# Our modules
from f3ds.framework.log import Logger
from socialscan import scanhandlers, scanning
from socialscan.config import loadDefaultConfig
from socialscan.db import setupDB
from socialscan.exceptions import ContainerFullError
from socialscan.model import Peer, QueuedRequest, Scan, ScanDigestFile, SocialRelationship
from socialscan.scandigest import ScanDigest
from socialscan.searchutil import SearchResult, UrlObject


def requestQuery(session, config):
    """
    Prepare a request query. This is code used in multiple places to find requests based on
    social distance, and as you can see it's quite a large query, so it gets it's own special function.
    """
    return session.query(QueuedRequest)\
              .join(QueuedRequest.peer)\
              .join((SocialRelationship,
                     and_(
                          or_(SocialRelationship.peer_id==QueuedRequest.peer_id,
                              SocialRelationship.social_peer_id==QueuedRequest.peer_id),
                          or_(SocialRelationship.peer_id==config.owner.id,
                              SocialRelationship.social_peer_id==config.owner.id))))\
              .order_by(SocialRelationship.pdistance)\
              .filter(QueuedRequest.owner==config.owner)


class DigestManager(object):
    """
    Digest manager object which stores and manages loaded digests, and runs jobs related to them.

    @ivar logger: "DigestManager" logger
    @type logger: L{Logger}

    @ivar config: socialscan configuration
    @type config: L{AttributeConfig}

    @ivar session: SQLAlchemy database session
    @type session: C{sqlalchemy.orm.session.Session}

    @ivar scanhandler: ScanHandler module, used for C{getSigInfo()}
    @type scanhandler: scanhandler module

    @ivar loadlimit: C{int} version of C{config.sdmanager.loadlimit}
    @type loadlimit: C{int}

    @ivar digests: foreign scan digests currently loaded
    @type digests: C{list} of L{ScanDigestFile}

    @ivar ourdigest: the digest that is currently being built by this digest manager
    @type ourdigest: L{ScanDigestFile}

    @ivar announcequeue: local scan digests to announce to peers
    @type announcequeue: C{list} of L{ScanDigestFile}
    """

    #Traceback (most recent call last):
    #  File "main.py", line 65, in <module>
    #    main()
    #  File "main.py", line 39, in main
    #    digestmanager = DigestManager(config, session)
    #  File "C:\cygwin\home\Administrator\socialscan\socialscan\sdmanager.py", line 98, in __init__
    #    .filter(ScanDigestFile.tainted == False)\
    #  File "<string>", line 1, in <lambda>
    #  File "build\bdist.win32\egg\sqlalchemy\orm\query.py", line 50, in generate
    #  File "build\bdist.win32\egg\sqlalchemy\orm\query.py", line 1083, in filter
    #sqlalchemy.exc.ArgumentError: filter() argument must be of type sqlalchemy.sql.ClauseElement or string 

    def __init__(self, config, session):
        self.logger = Logger("DigestManager")
        self.logger.log("initializing digest manager")
        self.config = config
        self.session = session

        sharedir = os.path.dirname(config.sdmanager.share_location)
        storedir = os.path.dirname(config.sdmanager.storage_location)
        if not os.path.exists(sharedir):
            self.logger.log("creating share dir %r" % sharedir)
            os.makedirs(sharedir)
        if not os.path.exists(storedir):
            self.logger.log("creating storage dir %r" % storedir)
            os.makedirs(storedir)

        self.scanhandler = scanhandlers.get(config.scanning.handler)

        self.loadlimit = int(config.sdmanager.loadlimit)
        self.digests = []
        alldigests = session.query(ScanDigestFile)\
                            .filter(ScanDigestFile.owner == config.owner)\
                            .filter(ScanDigestFile.creator != config.owner)\
                            .all()
                            #.filter(ScanDigestFile.tainted == False)\
                            # Removed the filter as it broke, see stacktrace above
                            # __init__
        sorteddigests = sorted(alldigests, key=lambda digest: digest.usefulness)
        for digestfile in sorteddigests[:self.loadlimit]:
            try:
                self.digests.append(digestfile.load())
            except (ValueError, AttributeError, IOError), error:
                self.logger.log('Error while loading digest %s: %s' % (digestfile, error))

        self.ourdigest = session.query(ScanDigestFile)\
                                .filter(ScanDigestFile.owner == config.owner)\
                                .filter(ScanDigestFile.creator != config.owner)\
                                .filter(ScanDigestFile.complete == False)\
                                .order_by(ScanDigestFile.date.desc())\
                                .first()
        if self.ourdigest:
            try:
                self.ourdigest.load()
            except:
                self.logger.exception()
                self.ourdigest = None

        if not self.ourdigest:
            self._newsd(self._determineSiginfo())

        self.announcequeue = []  #

    def __del__(self):
        'Attempt to preserve digest when exiting.'
        try:
            if self.ourdigest:
                self.ourdigest.save()
        except (IOError, WindowsError, AttributeError):
            pass

    def _determineSiginfo(self):
        """
        Determine the siginfo currently provided by the scanner
        """
        return self.scanhandler.getSigInfo()

    def _announceDigests(self):
        """
        Send our current scan digest out to peers.
        """
        distance = float(self.config.sdmanager.digest_distance)
        targetpeers = self.config.owner.getByDistance(self.session, distance)

        digests = self.announcequeue
        self.announcequeue = []
        self.logger.log("announcing %d digests to %d peers" % (len(digests), len(targetpeers)))

        self.session.commit()  # release the session lock for following long operations
        for digest in digests:
            self.logger.log("digest url: %s, owner: %s, name: %s" % \
                            (digest.url, self.config.owner, self.config.owner.name))
            for peer in targetpeers:
                try:
                    peer.transport.digestOffer(self.config.owner.name, digest.url)
                except Exception, e:
                    self.logger.log("Exception while sending to peer %r: %r" %
                                    (peer, e))

    def _newsd(self, siginfo):
        """
        Create a new local scan digest and, if it exists, flush the old one to disk and 
        add it to the L{announcequeue}.
        """
        self.logger.log("creating a new scan digest with siginfo %r" % (siginfo, ))
        if self.ourdigest:
            self.logger.log("freeing previously loaded digest")
            self.announcequeue.append(self.ourdigest)
            self.ourdigest.save()
            self.ourdigest.complete = True
            self.session.add(self.ourdigest)

        self.ourdigest = ScanDigestFile(self.config.owner, self.config, siginfo=siginfo)
        self.ourdigest.create(int(self.config.sdmanager.maxcapacity))
        self.ourdigest.save()
        self.logger.log("New digest's filename: %s" % self.ourdigest.filename)

    def _addScans(self, scans):
        """
        Add some scans to the currently active digest. Scans are assumed to be siginfo-compatible,
        i.e. they have the same siginfo as the digest that is being added to.

        This function will recursively create new digests if the current one fills up.

        @param scans: scans to add to the digest
        @type scans: C{list} of L{Scan}
        """
        if not len(scans):
            return
        self.logger.log("adding %d scans to currently active digest" % len(scans))
        it = iter(list(scans))  # we use an separate iterator so we
                                # can grab the uniterated objects if necessary
        lastone = None # to make sure the one that *caused* the overflow
                       #can be handled again in the new digest
        try:
            for scan in it:
                lastone = scan
                self.ourdigest.add(scan.to_UrlObject())
                scan.digested = True
                self.session.add(scan)
            self.session.add(self.ourdigest)
        except ContainerFullError:
            self.logger.log("scans overflowed")
            overflow = [lastone] + list(it)
            self._newsd(overflow[0].siginfo)
            self._addScans(overflow)

    def updateOurSD(self):
        """
        Recurring job: Update our sd with new scans
        Note: This assumes that multiple updates of the scanner's signatures cannot occur
        in the time between runs of this function. If they do, it will cause an exception.
        """
        try:
            self.logger.log("updating our scandigest")
            scans = self.session.query(Scan)\
                                .filter(Scan.owner==self.config.owner)\
                                .filter(Scan.digested!=True)\
                                .filter(Scan.type=="local")\
                                .order_by(Scan.timestamp)\
                                .all()

            self.logger.log("processing %d scans" % len(scans))

            currentsiginfo = self.ourdigest.siginfo
            newsiginfo = self._determineSiginfo()

            currentscans = []  # current scans are the scans that are
                               # sigversion-compatible with the current digest

            newscans = []  # new scans are the scans that require a new scan
                           # digest for sigversion compatibility

            discardedscans = []  # scans are discarded if they are not compatible
                                 # with the current scanner sigversion or current
                                 # digest sigversion

            for scan in scans:
                if scan.siginfo == currentsiginfo:
                    currentscans.append(scan)
                elif scan.siginfo == newsiginfo:
                    newscans.append(scan)
                else:
                    discardedscans.append(scan)

            self._addScans(currentscans)

            if newsiginfo != currentsiginfo:
                self._newsd(newsiginfo)
                self._addScans(newscans)

            if discardedscans:
                discardedinfos = [scan.siginfo for scan in discardedscans]
                deduplicated = list(set(discardedinfos))
                self.logger.log("Warning, scans were discarded when adding to scan digest "
                                "(probably due to much too long of a digest update time) "
                                "with siginfos: %r" % deduplicated)

            if self.announcequeue:
                self._announceDigests()

            self.session.commit()
            self.ourdigest.save()
            
        except:
            self.logger.exception()
            raise

    def _retrieve_progress(self, block_count, block_size, total_size):
        log_msg = '%s of %s downloaded' % (block_count * block_size, total_size)
        self.logger.log(log_msg)

    def retrieveScanDigest(self):
        """
        Recurring job: retrieve a scan digest that a peer has offered to us and, if a slot can be
        made available, load it up.
        """
        try:
            self.logger.log("retrieving a scan digest")
            request = requestQuery(self.session, self.config)\
                                .filter(QueuedRequest.type=="digest-offer")\
                                .filter(QueuedRequest.state!="done")\
                                .first()
            if not request:
                self.logger.log("no digests offers to retrieve")
                return  # no queued requests - nothing to do
            peer = request.peer
            self.logger.log("offer: %r" % request)

            digest = ScanDigestFile(self.config.owner, self.config, url=request.url,
                                    foreign=True, creator=peer)
            # do not initialize the version info yet

            self.logger.log('Downloading %s to %s' % (request.url, digest.filename))
            try:
                (fname, headers) = urllib.urlretrieve(request.url, digest.filename,
                                                      self._retrieve_progress)
            except IOError, error:
                self.logger.log("Error downloading scan digest from url %r "
                                "(offered by peer %r): %r" % (request.url, request.peer, error))
                request.state = "done"
                self.session.add(request)
                self.session.commit()
                return
            else:
                self.logger.log('Finished downloading %s to %s.' % (request.url, fname))
                self.logger.log('Headers:')
                for h in headers:
                    self.logger.log('%s: %s' % (h, headers[h]))

            # TODO: should we add a delay in here, to allow the OS more time to write the
            # file?  Or what else is causing the error where the file is empty?
            try:
                digest.load()
            except (ValueError, AttributeError, IOError), error:
                self.logger.log('Error loading digest %s: %s' % (digest, error))
                return

            # now initialize the version info that we retrieved from the digest file
            siginfo = digest._digest.siginfo
            digest.scannervv, digest.sigversion, digest.sigdate = siginfo

            request.state = "done"

            self.session.add(request)
            self.session.add(digest)
            self.session.commit()

            if len(self.digests)+1 >= self.loadlimit:
                self._unloadone()

            if len(self.digests)+1 < self.loadlimit:
                self.logger.log("digest slot available, putting digest in working digests")
                self.digests.append(digest)
            else:
                self.logger.log("no digest slot available, unloading digest")
                digest.unload()  # make extra sure that gets unloaded
        except:
            self.logger.exception()
            raise

    def _unloadone(self):
        """
        Unload the least useful digest.
        """
        self.logger.log("attempting to unload some digests [stub]")
        if not len(self.digests):
            self.logger.log("no digests loaded to unload!")
        digests = sorted(self.digests, key=lambda digest: digest.usefulness)
        tounload = digests[0]
        self.digests.remove(tounload)
        tounload.unload()
        self.logger.log("unloaded digest %r" % (digest,))

    def search(self, url, size, hash):
        """
        Search the loaded digests. 

        @param url: size of the object to search for in the digests
        @type url: C{str}

        @param size: size in bytes of the object to search for in the digests
        @type size: C{int}

        @param hash: a hexdigest of a hash of the content of the object to search for in the digests
        @type hash: C{str}

        @return: number of digests containing the url being searched for.
        @rtype: C{int}
        """
        self.logger.log("searching digests for url %r (size: %r, hash: %r)" % (url, size, hash))
        urlobject = UrlObject(url, size, hash)

        count = 0
        for digest in self.digests:
            if digest.tainted:
                # digest is no good, throw it out
                self.digests.remove(digest)
                digest.unload()
                self.logger.log("unloaded tainted digest %r" % (digest,))
                continue
            found = digest.get(urlobject)
            if found:
                # Let this digest record the hit.
                count += 1
                digest.hits += 1
                self.session.add(digest)
        self.session.commit()
        return count

    def performRequestedScan(self):
        """
        Recurring job: perform a scan that a peer has requested and return the result to them,
        as well as storing the result in our database for future reference.
        """
        self.logger.log("Performing a requested scan")
        try:
            request = requestQuery(self.session, self.config)\
                                .filter(QueuedRequest.type=="active-scan")\
                                .filter(QueuedRequest.state!="done")\
                                .first()
            if not request:
                self.logger.log("no scans requested")
                return #nothing to do
            peer = request.peer
            self.logger.log("handling request %r" % request)

            wasprocessed = request.state == "processed"

            if not wasprocessed:
                self.logger.log("request unprocessed, sending to scanner")
                scanner = scanning.ScannableRequest(self.config, self.session, parentrequest=request)
                scan = scanner.localscan
                request.state = "processed"
            else:
                self.logger.log("request already processed, not re-scanning")
                scan = request.scan
                if not scan:
                    self.logger.log("Already scanned, but scan missing! marking as done anyway.")
                    request.state = "done"
                    self.session.add(request)
                    self.session.commit()
                    return

            self.logger.log("sending result to peer who requested it")
            try:
                result = peer.transport.scanResult(self.config.owner.name, request.url, scan.hash,
                                            request.key, scan.malicious, scan.scannervv,
                                            scan.sigversion, time.mktime(scan.sigdate.timetuple()))
            except:
                self.logger.exception()
            else:
                if result == "success":
                    self.logger.log("send successful, marking request done")
                    request.state = "done"
                else:
                    self.logger.log("send unsuccessful, "
                                    "peer responded with non-success response %r" % result)

            if wasprocessed:
                request.state = "done"

            self.session.add(request)
            self.session.commit()
            self.logger.log("done")
        except:
            self.logger.exception()
            raise

    def relationshipRedemption(self):
        """
        redeem relationships of all peers
        """
        try:
            relationships = self.session.query(SocialRelationship)\
                    .join((Peer, or_(SocialRelationship.peer_id==self.config.owner.id,
                                        SocialRelationship.social_peer_id==self.config.owner.id)
                                       ))\
                    .all()
            amount = float(self.config.sdmanager.redemption_amount)
            for relationship in relationships:
                relationship.redemption(amount)
                self.session.add(relationship)
            self.session.commit()
        except:
            self.logger.exception()
            raise

    def _initJobs(self):
        """
        initialize jobs with the twisted reactor. Separate from __init__ so that
        C{DigestManager} can be instantiated by non-main code.
        """
        assert not hasattr(self, "jobs"), "_initJobs should only be called once"
        from twisted.internet.task import LoopingCall

        sdmconf = self.config.sdmanager
        self.jobs = []

        job1 = LoopingCall(self.updateOurSD)
        job1.start(float(sdmconf.updateoursd_interval))
        self.jobs.append(job1)

        job2 = LoopingCall(self.retrieveScanDigest)
        job2.start(float(sdmconf.retrievesd_interval))
        self.jobs.append(job2)

        job3 = LoopingCall(self.performRequestedScan)
        job3.start(float(sdmconf.activescan_interval))
        self.jobs.append(job3)

        job4 = LoopingCall(self.relationshipRedemption)
        job4.start(float(sdmconf.redemption_hours))
        self.jobs.append(job4)

