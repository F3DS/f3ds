#!/usr/bin/python

# Standard Python modules
import os
import sys
import tempfile
import time
import urllib
import urllib2

from datetime import datetime
from datetime import timedelta
from os import path

# Modify the path to include the f3ds framework.
# __file__ is <root>/socialscan/socialscan/model/containers.py
pdn = path.dirname
thisfile = path.abspath(__file__)
projectdir = pdn(pdn(thisfile))
for d in [projectdir,
          path.join(projectdir, 'socialscan'),
          path.join(projectdir, 'util'),]:
    if d not in sys.path:
        sys.path.append(d)

# 3rd party modules
from twisted.internet.task import LoopingCall

# Our modules
from f3ds.framework.log import Logger
from f3ds.framework.model.containers import ContainerManager
from socialscan import scanhandlers, scanning
from socialscan import util
from socialscan.exceptions import ContainerFullError
from socialscan.model import (QueuedRequest, relationshipsQuery, requestQuery,
                              Scan, ScanDigestFile, ScanLogFile)
from socialscan.model.scandigest import ScanDigest
from socialscan.model.scanlog import ScanLog
from socialscan.searchutil import SearchResult, UrlObject


########## ContainerManager Implementations ##########

class ScanResultContainerManager(ContainerManager):
    """
    Container manager object which stores and manages loaded containers, and runs jobs related to them.
    For example, containers may be of type ScanLogFile or ScanDigestFile

    Variables added by this class:

    @ivar scanhandler: ScanHandler module, used for C{getSigInfo()}
    @type scanhandler: scanhandler module
    """

    def __init__(self, config, session, container_mixin):
        super(ScanResultContainerManager, self).__init__(config, session, container_mixin)
        self.scanhandler = scanhandlers.get(config.scanning.handler)
        self.added_property_name = 'contained'
        self.timeout = config.container_manager.download_timeout
        self.singlesd = config.container_manager.process_single_sd in ['True', 'true']
        if not self.loaded:
            # Discard default container from parent class; it had siginfo==None
            self.ourcontainer = None
            self._newcontainer(self._determineSiginfo())


    def _determineSiginfo(self):
        """
        Determine the siginfo currently provided by the scanner
        """
        return self.scanhandler.getSigInfo()

    def _announceContainers(self):
        """
        Send our current container out to peers.
        """
        distance = float(self.config.container_manager.announce_distance)
        targetpeers = self.config.owner.getByDistance(self.session, distance)

        containers = self.announcequeue
        self.announcequeue = []
        msg = 'announcing %d %ss to %d peers'
        self.logger.log(msg % (len(containers), self.cname, len(targetpeers)))

        self.session.commit()  # release the session lock for following long operations
        msg = '%s url: %s, owner: %s, name: %s'
        owner, name = (self.config.owner, self.config.owner.name)
        for container in containers:
            self.logger.log(msg % (self.cname, container.url, owner, name))
            for peer in targetpeers:
                try:
                    peer.transport.containerOffer(self.config.owner.name, container.url,
                                                  self.cname)
                except Exception, e:
                    self.logger.log('Exception while sending to peer %r: %r' %
                                    (peer, e))

    def _newcontainer(self, siginfo):
        """
        Create a new local container and, if it exists, flush the old one to disk and 
        add it to the L{announcequeue}.
        """
        self.logger.log('creating a new %s with siginfo %r' % (self.cname, (siginfo, )))
        if self.ourcontainer:
            self.logger.log('freeing previously loaded %s' % (self.cname))
            self.announcequeue.append(self.ourcontainer)
            self.ourcontainer.save()
            self.ourcontainer.complete = True
            self.session.add(self.ourcontainer)

        self.ourcontainer = self.container(self.config.owner, self.config, siginfo=siginfo)
        self.ourcontainer.create(int(self.config.container_manager.maxcapacity))
        self.ourcontainer.save()
        self.logger.log("New %s's filename: %s" % (self.cname, self.ourcontainer.filename))

    def _addScans(self, scans):
        """
        Add some scans to the currently active container. Scans are assumed to be siginfo-compatible,
        i.e. they have the same siginfo as the container that is being added to.

        This function will recursively create new containers if the current one fills up.

        @param scans: scans to add to the container
        @type scans: C{list} of L{Scan}
        """
        if not len(scans):
            return
        self.logger.log('adding %d scans to currently active %s' % (len(scans), self.cname))
        it = iter(list(scans))  # we use an separate iterator so we
                                # can grab the uniterated objects if necessary
        lastone = None # preserve the one that *caused* the overflow to handle in new container
        try:
            for scan in it:
                lastone = scan
                self.ourcontainer.add(scan.to_UrlObject(), scan.safety)
                setattr(scan, self.added_property_name, True)
                self.session.add(scan)
            self.session.add(self.ourcontainer)
        except ContainerFullError:
            self.logger.log('scans overflowed')
            overflow = [lastone] + list(it)
            self._newcontainer(overflow[0].siginfo)
            self._addScans(overflow)

    def _findScans(self):
        return  self.session.query(Scan)\
                            .filter(Scan.type=='local')\
                            .order_by(Scan.timestamp) \
                            .all()

    def updateOurContainer(self):
        """
        Recurring job: Update our sd with new scans
        Note: This assumes that multiple updates of the scanner's signatures cannot occur
        in the time between runs of this function. If they do, it will cause an exception.
        """
        try:
            self.logger.log('updating our %s' % self.cname)
            scans = self._findScans()
            self.logger.log('processing %d scans' % len(scans))
            currentsiginfo = self.ourcontainer.siginfo
            newsiginfo = self._determineSiginfo()
            currentscans = [] # scans that are sigversion-compatible with current container
            newscans = [] # scans that require a new container for sigversion compatibility
            discardedscans = [] # not compatible with the current scanner or container sigversion
            
            for scan in scans:
                if scan.siginfo == currentsiginfo:
                    currentscans.append(scan)
                elif scan.siginfo == newsiginfo:
                    newscans.append(scan)
                else:
                    discardedscans.append(scan)
            self._addScans(currentscans)

            if newsiginfo != currentsiginfo:
                self._newcontainer(newsiginfo)
                self._addScans(newscans)
            if discardedscans:
                discardedinfos = [scan.siginfo for scan in discardedscans]
                discardedinfos = list(set(discardedinfos))
                msg = 'Warning: scans were discarded when adding to %s' % (self.cname)
                msg += ' (probably caused by a long update time) with siginfos: %r' % (discardedinfos)
                self.logger.log(msg)
            self.ourcontainer.save()
            if self.announcequeue:
                self._announceContainers()
            self.session.commit()
        except:
            self.logger.exception()
            raise

    def _splitsuffix(self, url):
        'Split the suffix off of a url.'
        garbage, pathpart = urllib.splittype(url)
        garbage, path = urllib.splithost(pathpart or '')
        pathpart, garbage = urllib.splitquery(pathpart or '')
        pathpart, garbage = urllib.splitattr(pathpart or '')
        return os.path.splitext(pathpart)[1]

    def urlretrieve(self, url, filename=None, reporthook=None, data=None):
        """
        urllib.retrieve does not have a timeout value, but a nicer interface for getting
        at the data than urllib2.open; urllib2 does not have a retrieve function.  This
        method combines both: the signature and return values match urllib.retrieve,
        while the actual call uses urllib2.open which has a timeout.

        Note that this method does not use a cache to retain recently downloaded urls.
        """
        # Much of this comes from urllib.URLopener.retrieve
        bs = 1024*8
        size = -1
        read = 0
        blocknum = 0
        try:
            fp = urllib2.urlopen(url, data, float(self.timeout))
        except urllib2.URLError, e:
            self.logger.log('retrieval incomplete: %s' % e)
            raise

        try:
            headers = fp.info()
            if filename:
                tfp = open(filename, 'wb')
            else:
                suffix = self._splitsuffix(url)
                (fd, filename) = tempfile.mkstemp(suffix)
                # TODO: Would it be useful to store a list of retrieved containers?
                #self.__tempfiles.append(filename)
                tfp = os.fdopen(fd, 'wb')
            try:
                result = filename, headers
                #if self.tempcache is not None:
                #    self.tempcache[url] = result
                if reporthook:
                    if 'content-length' in headers:
                        size = int(headers['Content-Length'])
                    reporthook(blocknum, bs, size)
                timeout = timedelta(seconds=int(self.timeout))
                start = datetime.utcnow()
                while True:
                    block = fp.read(bs)
                    if block == '':
                        break
                    read += len(block)
                    tfp.write(block)
                    blocknum += 1
                    if reporthook:
                        reporthook(blocknum, bs, size)
                    elapsed = datetime.utcnow() - start
                    if elapsed > timeout:
                        msg = 'While downloading: %s timed out: took %s (timeout: %s)'
                        self.logger.log(msg % (util.class_name(self), elapsed, timeout))
                        break
            finally:
                tfp.close()
        finally:
            fp.close()
        # raise exception if actual size does not match content-length header
        if size >= 0 and read < size:
            msg = 'retrieval incomplete: got only %i out of %i bytes'
            raise urllib.ContentTooShortError(msg % (read, size), result)
        return result

    def retrieveContainer(self):
        """
        Recurring job: retrieve a container that a peer has offered to us and, if a slot can be
        made available, load it up.
        """
        requests = []
        self.singlesd
        try:
            self.logger.log('retrieving a %s' % (self.cname))
            query = requestQuery(self.session, self.config)
            query = query.filter(QueuedRequest.type=='%s-offer' % (self.cname.lower()))
            query = query.filter(QueuedRequest.state!='done')
            if self.singlesd:
                requests = [query.first()]
            else:
                requests = query.all()
        except Exception, e:
            self.logger.log('unable to get requests from the database: %s' % e)
            return

        requests[:] = [r for r in requests if r]
        if not requests:
            self.logger.log('no %s offers to retrieve' % (self.cname))
            return  # no queued requests - nothing to do
        for request in requests:
            try:
                peer = request.peer
                self.logger.log('offer: %r' % request)
                container = self.container(self.config.owner, self.config, url=request.url,
                                           foreign=True, creator=peer)
                # do not initialize the version info yet

                self.logger.log('Downloading %s to %s' % (request.url, container.filename))
                try:
                    (fname, headers) = self.urlretrieve(request.url, container.filename,
                                                        self._retrieve_progress)
                except IOError, error:
                    msg = 'Error downloading %s from url %r' % (self.cname, request.url)
                    msg += ' (offered by peer %r): %r' % (request.peer, error)
                    self.logger.log(msg)
                    request.state = 'done'
                    self.session.add(request)
                    self.session.commit()
                    return
                else:
                    self.logger.log('Finished downloading %s to %s.' % (request.url, fname))
                    self.logger.log('Headers:')
                    for h in headers:
                        self.logger.log('%s: %s' % (h, headers[h]))
                try:
                    container.load()
                except (ValueError, AttributeError, IOError), error:
                    self.logger.log('Error loading %s %s: %s' % (self.cname, container, error))
                    request.state = 'done'
                    self.session.add(request)
                    self.session.commit()
                    return
                # now initialize the version info that we retrieved from the container
                siginfo = container._container.siginfo
                container.scannervv, container.sigversion, container.sigdate = siginfo

                request.state = 'done'
                self.session.add(request)
                self.session.add(container)
                self.session.commit()

                if len(self.containers) + 1 >= self.loadlimit:
                    self._unloadone()

                if len(self.containers) + 1 < self.loadlimit:
                    msg = '%s slot available, putting %s in working set'
                    self.logger.log(msg % (self.cname, self.cname))
                    self.containers.append(container)
                else:
                    msg = 'no %s slot available, unloading %s'
                    self.logger.log(msg % (self.cname, self.cname))
                    container.unload()  # make extra sure that gets unloaded
            except:
                self.logger.exception()
                raise

    def search(self, url, size, contenthash, aggregate=False):
        """
        Search the loaded containers. 

        @param url: size of the object to search for in the containers
        @type url: C{str}

        @param size: size in bytes of the object to search for in the containers
        @type size: C{int}

        @param contenthash: a hexdigest of a hash of the content of the object to search for
        @type contenthash: C{str}

        @param aggregate: determines whether the actual results found will be returned, or
                          an aggregation of the results (in this class, count of results)
        @type aggregate: C{bool}

        @return: number of containers containing the url being searched for if aggregate is True,
                 otherwise a list of SearchResult objects.
        @rtype: C{int} or C{list} of L{SearchResult}
        """
        msg = 'searching %s for url %r (size: %r, hash: %r)'
        self.logger.log(msg % (self.cname, url, size, contenthash))
        urlobject = UrlObject(url, size, contenthash)

        results = []
        self.logger.log('containers to search: %s' % len(self.containers))
        for container in self.containers:
            if container.tainted:
                # container is no good, throw it out
                self.containers.remove(container)
                container.unload()
                self.logger.log('unloaded tainted %s %r' % (self.cname, (container,)))
                continue
            # TODO: maybe log the filepath?
            self.logger.log('calling container.get on urlobject %s' % urlobject)
            found = container.get(urlobject)
            # Because found might be a Safety object or a boolean, use a tuple
            # to print it to the log file.
            self.logger.log('result: found=%s' % (found,))
            if found:
                # If container is ScanDigest, found needs to become a Safety object.
                # Maliciousness has no meaning at this point, and will go away with
                # the computation of the return value.
                if not isinstance(found, util.Safety):
                    if not aggregate:
                        msg = 'ERROR: need Safety object, have %s, but aggregate=%s'
                        msg += '\nCoercing to Safety(%s, True).'
                        self.logger.log(msg % (type(found), aggregate, found))
                    found = util.Safety(found, True)
                results.append(SearchResult(urlobject, container, found))
                container.hits += 1
                self.session.add(container)
        self.session.commit()
        rv = results
        if aggregate:
            try:
                rv = reduce(lambda x, y: x + y, map(lambda x: 1, results))
            except:
                rv = 0
        return rv

    def _initJobs(self):
        """
        initialize jobs with the twisted reactor. Separate from __init__ so that
        C{ScanResultContainerManager} can be instantiated by non-main code.
        """
        assert not hasattr(self, 'jobs'), '_initJobs should only be called once'

        conf = self.config.container_manager
        self.jobs = []

        job1 = LoopingCall(self.updateOurContainer)
        job1.start(float(conf.updateoursd_interval))
        self.jobs.append(job1)

        job2 = LoopingCall(self.retrieveContainer)
        job2.start(float(conf.retrievesd_interval))
        self.jobs.append(job2)

        job3 = LoopingCall(self.relationshipRedemption)
        job3.start(float(conf.redemption_hours))
        self.jobs.append(job3)


########## ScanResultContainerManager Implementations ##########

class DigestManager(ScanResultContainerManager):
    """
    Manage scan results using a ScanDigestFile container.

    Adds the ability to perform a scan requested by a peer, storing the result
    in our database.
    """
    def __init__(self, config, session):
        """
        Use a ScanDigestFile as the underlying container type.
        """
        super(DigestManager, self).__init__(config, session, ScanDigestFile)
        self.added_property_name = 'digested'

    def _findScans(self):
        # Nota Bene: this query does not go in with the others in model/__init__.py b/c
        # it needs specific values for digested and type, different from the other Scans
        # query.
        # TODO: learn enough about the return value to see if it can be filtered
        # yet again, and add required filtering.
        return self.session.query(Scan)\
                           .filter(Scan.owner==self.config.owner)\
                           .filter(Scan.digested!=True)\
                           .filter(Scan.type=='local')\
                           .order_by(Scan.timestamp)\
                           .all()

    def performRequestedScan(self):
        """
        Recurring job: perform a scan that a peer has requested and return the result to them,
        as well as storing the result in our database for future reference.
        """
        try:
            request = requestQuery(self.session, self.config)\
                                .filter(QueuedRequest.type=='active-scan')\
                                .filter(QueuedRequest.state!='done')\
                                .first()
            if not request:
                #self.logger.log('no scans requested')
                return #nothing to do
            self.logger.log('Performing a requested scan')
            peer = request.peer
            self.logger.log('handling request %r' % request)

            wasprocessed = request.state == 'processed'
            done = request.state == 'done'

            if not wasprocessed and not done:
                self.logger.log('request unprocessed, sending to scanner')
                scanner = scanning.ScannableRequest(self.config, self.session, parentrequest=request)
                scan = scanner.localscan
                request.scan = scan
                request.state = 'processed'
            else:
                self.logger.log('request already processed, not re-scanning')
                scan = request.scan
                if not scan:
                    self.logger.log('Already scanned, but scan missing! marking as done anyway.')
                    request.state = 'done'
                    self.session.add(request)
                    self.session.commit()
                    return

            self.logger.log('sending result to peer who requested it')
            #retries = int(self.config.scanning.max_active_retries)
            successful = False
            #while retries > 0 and not successful:
            try:
                result = peer.transport.scanResult(self.config.owner.name, request.url,
                                        scan.hash, request.key, scan.malicious, scan.scannervv,
                                        scan.sigversion, time.mktime(scan.sigdate.timetuple()))
            except:
                self.logger.exception()
            else:
                if result == 'success':
                    self.logger.log('send successful, marking request done')
                    request.state = 'done'
                    successful = True
                else:
                    msg = 'send unsuccessful, peer responded with non-success response %r'
                    self.logger.log(msg % result)
            #    retries -= 1

            if wasprocessed and successful:
                request.state = 'done'

            self.session.add(request)
            self.session.commit()
            self.logger.log('done')
        except:
            self.logger.exception()
            raise

    def _initJobs(self):
        """
        initialize jobs with the twisted reactor. Separate from __init__ so that
        C{ScanResultContainerManager} can be instantiated by non-main code.
        """
        super(DigestManager, self)._initJobs()
        conf = self.config.container_manager

        job4 = LoopingCall(self.performRequestedScan)
        job4.start(float(conf.activescan_interval))
        self.jobs.append(job4)


class ScanLogManager(ScanResultContainerManager):
    """
    Manage scan results using a ScanLogFile container.

    """
    def __init__(self, config, session):
        """
        Use a ScanLogFile as the underlying container type.
        """
        super(ScanLogManager, self).__init__(config, session, ScanLogFile)
        self.added_property_name = 'logged'

    def _findScans(self):
        # Nota Bene: this query does not go in with the others in model/__init__.py b/c
        # it needs specific values for digested, type, and logged different from the other Scans
        # query.
        # TODO: learn enough about the return value to see if it can be filtered
        # yet again, and add required filtering.
        return self.session.query(Scan)\
                           .filter(Scan.owner==self.config.owner)\
                           .filter(Scan.digested==True)\
                           .filter(Scan.logged!=True)\
                           .filter(Scan.type=='local')\
                           .order_by(Scan.timestamp)\
                           .all()

