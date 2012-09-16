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
from socialscan import scanhandlers, scanning
from socialscan.config import loadDefaultConfig
from socialscan.db import setupDB
from socialscan.exceptions import ContainerFullError
from socialscan.log import Logger
from socialscan.model import Peer, QueuedRequest, Scan, ScanLogFile, SocialRelationship
from socialscan.scanlog import ScanLog
from socialscan.searchutil import SearchResult, UrlObject


class ScanLogManager(object):
    """
    Log manager object which stores and manages loaded scan logs, and runs jobs related to them.

    @ivar logger: "ScanLogManager" logger
    @type logger: L{Logger}

    @ivar config: socialscan configuration
    @type config: L{AttributeConfig}

    @ivar session: SQLAlchemy database session
    @type session: C{sqlalchemy.orm.session.Session}

    @ivar scanhandler: ScanHandler module, used for C{getSigInfo()}
    @type scanhandler: scanhandler module

    @ivar loadlimit: C{int} version of C{config.sdmanager.loadlimit}
    @type loadlimit: C{int}

    @ivar logs: foreign scan logs currently loaded
    @type logs: C{list} of L{ScanLogFile}

    @ivar ourlog: the log that is currently being built by this log manager
    @type ourlog: L{ScanLogFile}

    @ivar announcequeue: local scan logs to announce to peers
    @type announcequeue: C{list} of L{ScanLogFile}
    """

    def __init__(self, config, session):
        self.logger = Logger("ScanLogManager")
        self.logger.log("initializing log manager")
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
        self.logs = []
        alllogs = session.query(ScanLogFile)\
                            .filter(ScanLogFile.owner == config.owner)\
                            .filter(ScanLogFile.creator != config.owner)\
                            .all()
                            #.filter(ScanLogFile.tainted == False)\
                            # Removed the filter as it broke, see stacktrace above
                            # __init__
        sortedlogs = sorted(alllogs, key=lambda log: log.usefulness)
        for logfile in sortedlogs[:self.loadlimit]:
            try:
                self.logs.append(logfile.load())
            except (ValueError, AttributeError, IOError), error:
                self.logger.log('Error while loading scanlog %s: %s' % (logfile, error))

        self.ourlog = session.query(ScanLogFile)\
                                .filter(ScanLogFile.owner == config.owner)\
                                .filter(ScanLogFile.creator != config.owner)\
                                .filter(ScanLogFile.complete == False)\
                                .order_by(ScanLogFile.date.desc())\
                                .first()
        if self.ourlog:
            try:
                self.ourlog.load()
            except:
                self.logger.exception()
                self.ourlog = None

        if not self.ourlog:
            self._newsl(self._determineSiginfo())

        self.announcequeue = []  #

    def _determineSiginfo(self):
        """
        Determine the siginfo currently provided by the scanner
        """
        return self.scanhandler.getSigInfo()

    def _announceLogs(self):
        """
        Send our current scan log out to peers.
        """
        distance = float(self.config.sdmanager.digest_distance)
        targetpeers = self.config.owner.getByDistance(self.session, distance)

        logs = self.announcequeue
        self.announcequeue = []
        self.logger.log("announcing %d logs to %d peers" % (len(logs), len(targetpeers)))

        self.session.commit()  # release the session lock for following long operations
        for log in logs:
            self.logger.log("log url: %s, owner: %s, name: %s" % \
                            (log.url, self.config.owner, self.config.owner.name))
            for peer in targetpeers:
                try:
                    peer.transport.scanlogOffer(self.config.owner.name, log.url)
                except Exception, e:
                    self.logger.log("Exception while sending to peer %r: %r" %
                                    (peer, e))

    def _newsl(self, siginfo):
        """
        Create a new local scan log and, if it exists, flush the old one to disk and 
        add it to the L{announcequeue}.
        """
        self.logger.log("creating a new scan log with siginfo %r" % (siginfo, ))
        if self.ourlog:
            self.logger.log("freeing previously loaded log")
            self.announcequeue.append(self.ourlog)
            self.ourlog.save()
            self.ourlog.complete = True
            self.session.add(self.ourlog)

        self.ourlog = ScanLogFile(self.config.owner, self.config, siginfo=siginfo)
        self.ourlog.create(int(self.config.sdmanager.maxcapacity))
        self.ourlog.save()
        self.logger.log("New log's filename: %s" % self.ourlog.filename)

    def _addScans(self, scans):
        """
        Add some scans to the currently active log. Scans are assumed to be siginfo-compatible,
        i.e. they have the same siginfo as the log that is being added to.

        This function will recursively create new logs if the current one fills up.

        @param scans: scans to add to the log
        @type scans: C{list} of L{Scan}
        """
        if not len(scans):
            return
        self.logger.log("adding %d scans to currently active log" % len(scans))
        it = iter(list(scans))  # we use an separate iterator so we
                                # can grab the uniterated objects if necessary
        lastone = None # to make sure the one that *caused* the overflow
                       #can be handled again in the new log
        try:
            for scan in it:
                lastone = scan
                self.ourlog.add(scan.to_UrlObject(), scan.safety)
                scan.logged = True
                self.session.add(scan)
            self.session.add(self.ourlog)
        except ContainerFullError:
            self.logger.log("scans overflowed")
            overflow = [lastone] + list(it)
            self._newsl(overflow[0].siginfo)
            self._addScans(overflow)

    def updateOurSL(self):
        """
        Recurring job: Update our sl with new scans
        Note: This assumes that multiple updates of the scanner's signatures cannot occur
        in the time between runs of this function. If they do, it will cause an exception.
        """
        try:
            self.logger.log("updating our scanlog")
            scans = self.session.query(Scan)\
                                .filter(Scan.owner==self.config.owner)\
                                .filter(Scan.digested==True)\
                                .filter(Scan.logged!=True)\
                                .filter(Scan.type=="local")\
                                .order_by(Scan.timestamp)\
                                .all()

            self.logger.log("processing %d scans" % len(scans))

            currentsiginfo = self.ourlog.siginfo
            newsiginfo = self._determineSiginfo()

            currentscans = []  # current scans are the scans that are
                               # sigversion-compatible with the current log

            newscans = []  # new scans are the scans that require a new scan
                           # log for sigversion compatibility

            discardedscans = []  # scans are discarded if they are not compatible
                                 # with the current scanner sigversion or current
                                 # log sigversion

            for scan in scans:
                if scan.siginfo == currentsiginfo:
                    currentscans.append(scan)
                elif scan.siginfo == newsiginfo:
                    newscans.append(scan)
                else:
                    discardedscans.append(scan)

            self._addScans(currentscans)

            if newsiginfo != currentsiginfo:
                self._newsl(newsiginfo)
                self._addScans(newscans)

            if discardedscans:
                discardedinfos = [scan.siginfo for scan in discardedscans]
                deduplicated = list(set(discardedinfos))
                self.logger.log("Warning, scans were discarded when adding to scan log "
                                "(probably due to much too long of a log update time) "
                                "with siginfos: %r" % deduplicated)

            if self.announcequeue:
                self._announceLogs()

            self.session.commit()
            self.ourlog.save()
            
        except:
            self.logger.exception()
            raise

    def _retrieve_progress(self, block_count, block_size, total_size):
        log_msg = '%s of %s downloaded' % (block_count * block_size, total_size)
        self.logger.log(log_msg)

    def retrieveScanLog(self):
        """
        Recurring job: retrieve a scan log that a peer has offered to us and, if a slot can be
        made available, load it up.
        """
        try:
            self.logger.log("retrieving a scan log")
            request = requestQuery(self.session, self.config)\
                                .filter(QueuedRequest.type=="scanlog-offer")\
                                .filter(QueuedRequest.state!="done")\
                                .first()
            if not request:
                self.logger.log("no logs offers to retrieve")
                return  # no queued requests - nothing to do
            peer = request.peer
            self.logger.log("offer: %r" % request)

            log = ScanLogFile(self.config.owner, self.config, url=request.url,
                              foreign=True, creator=peer)
            # do not initialize the version info yet

            self.logger.log('Downloading %s to %s' % (request.url, log.filename))
            try:
                (fname, headers) = urllib.urlretrieve(request.url, log.filename,
                                                      self._retrieve_progress)
            except IOError, error:
                self.logger.log("Error downloading scan log from url %r "
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

            try:
                log.load()
            except (ValueError, AttributeError, IOError), error:
                self.logger.log('Error loading scanlog %s: %s' % (log, error))
                return

            # now initialize the version info that we retrieved from the log file
            siginfo = log._log.siginfo
            log.scannervv, log.sigversion, log.sigdate = siginfo

            request.state = "done"

            self.session.add(request)
            self.session.add(log)
            self.session.commit()

            if len(self.logs)+1 >= self.loadlimit:
                self._unloadone()

            if len(self.logs)+1 < self.loadlimit:
                self.logger.log("log slot available, putting log in working logs")
                self.logs.append(log)
            else:
                self.logger.log("no log slot available, unloading log")
                log.unload()  # make extra sure that gets unloaded
        except:
            self.logger.exception()
            raise

    def _unloadone(self):
        """
        Unload the least useful log.
        """
        self.logger.log("attempting to unload some logs [stub]")
        if not len(self.logs):
            self.logger.log("no logs loaded to unload!")
        logs = sorted(self.logs, key=lambda log: log.usefulness)
        tounload = logs[0]
        self.logs.remove(tounload)
        tounload.unload()
        self.logger.log("unloaded log %r" % (log,))

    def search(self, url, size, hash):
        """
        Search the loaded logs. 

        @param url: size of the object to search for in the logs
        @type url: C{str}

        @param size: size in bytes of the object to search for in the logs
        @type size: C{int}

        @param hash: a hexdigest of a hash of the content of the object to search for in the logs
        @type hash: C{str}

        @return: results of the search
        @rtype: C{list} of L{SearchResult}
        """
        self.logger.log("searching logs for url %r (size: %r, hash: %r)" % (url, size, hash))
        urlobject = UrlObject(url, size, hash)

        results = []
        for log in self.logs:
            if log.tainted:
                # log is no good, throw it out
                self.logs.remove(log)
                log.unload()
                self.logger.log("unloaded tainted log %r" % (log,))
                continue
            safety = log.get(urlobject)
            if safety:
                results.append(SearchResult(urlobject, log, safety))
                log.hits += 1
                self.session.add(log)
        self.session.commit()
        return results

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
        C{ScanLogManager} can be instantiated by non-main code.
        """
        assert not hasattr(self, "jobs"), "_initJobs should only be called once"
        from twisted.internet.task import LoopingCall

        sdmconf = self.config.sdmanager
        self.jobs = []

        job1 = LoopingCall(self.updateOurSL)
        job1.start(float(sdmconf.updateoursd_interval))
        self.jobs.append(job1)

        job2 = LoopingCall(self.retrieveScanLog)
        job2.start(float(sdmconf.retrievesd_interval))
        self.jobs.append(job2)

        job3 = LoopingCall(self.relationshipRedemption)
        job3.start(float(sdmconf.redemption_hours))
        self.jobs.append(job3)

