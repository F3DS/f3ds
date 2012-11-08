#!/usr/bin/python

__author__ = 'Jun Park and Matt Probst'
__version__ = '0.1'

# Standard python modules
import collections
import os
import random
import string
import sys
import traceback
import uuid
import xmlrpclib

from datetime import datetime

# 3rd party modules
from sqlalchemy import (Boolean, Column, DateTime, Enum, Float, Integer, String,
                        ForeignKey, MetaData, and_, or_)
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import mapper, relationship, backref

# Our modules
from f3ds.framework.model import (ContainerMixin, BaseQueuedRequest,
                                  BaseSentRequest, map_to_UrlObject, BasePeer,
                                  SocialRelationship, baseRelationshipsQuery,
                                  baseRequestQuery)
from f3ds.framework.util import UrlObject
from socialscan import util
from socialscan.exceptions import TaintedScanError
from socialscan.model.scandigest import ScanDigest
from socialscan.model.scanlog import ScanLog

Base = declarative_base()


# TODO: write tests (can use ScanDigestFile, ScanLogFile tests as starting point).
class SocialScanContainerMixin(ContainerMixin):
    """
    Represents a SocialScan container file and information about it.
    """
    tainted = False

    def __init__(self, container_type, owner, config=None, siginfo=None, url=None,
                 location=None, creator=None, foreign=False, usefulness=0.0):
        super(SocialScanContainerMixin, self).__init__(container_type, owner,
                                                       config, url, location,
                                                       creator, foreign,
                                                       usefulness)
        if siginfo:
            self.scannervv, self.sigversion, self.sigdate = siginfo

    @property
    def siginfo(self):
        """
        The L{util.SigInfo} version of scannervv, sigversion, and sigdate

        @rtype L{socialscan.util.SigInfo}
        """
        return util.SigInfo(self.scannervv, self.sigversion, self.sigdate)
    meta = siginfo


class Scan(Base):
    """
    Represents the local scan info of a URL.

    @type id: C{int}
    @ivar id: row identification number

    @type url: C{string}
    @ivar url: the url which was scanned

    @type hash: C{string}
    @ivar hash: a hash of the file which was scanned, if applicable; null if not

    @type filesize: C{int}
    @ivar filesize: the size of the file scanned, in bytes

    @type owner: L{Peer}
    @ivar owner: the peer which this database row belongs to (for uniqueness in multi-peer databases).

    @type timestamp: C{datetime.datetime}
    @ivar timestamp: time when the scan was completed


    @type peer: C{None} or L{Peer}
    @ivar peer: the peer who provided the active scan for us
                (in the case of type=="social-active") or the peer who requested
                the active scan from us (in the case of type=="local"); this field is now unnecessary
                due to the following two and can be removed (but see markTainted for a
                possible conflict with removing it)

    @type request: C{None} or L{QueuedRequest}
    @ivar request: the request we received which requested this active scan;
                   null if not a requested "local" scan

    @type sent_request: None or L{SentScanRequest}
    @ivar sent_request: the request we sent to a peer which this scan fulfills;
                        only used for "social-active"


    @type scannervv: C{str}
    @ivar scannervv: the scanner vendor and version, only used when "type" is
                     "social-active" or "local"

    @type sigversion: C{str}
    @ivar sigversion: the signature version used to scan, only used when "type" is
                      "social-active" or "local"

    @type sigdate: C{str}
    @ivar sigdate: the datestamp of the signatures used to scan, only used when
                   "type" is "social-active" or "local"

    @type malicious: C{bool}
    @ivar malicious: result of the scan; true if malicious, false if benign


    @type scantime: C{int}
    @ivar scantime: time that the scan took in milliseconds

    @type retrievems: C{int}
    @ivar retrievems: time that the file took to download (for logging purposes)

    @type digested: C{bool}
    @ivar digested: true if we have included this scan in a scan digest. only applicable
                    if type="local".

    @type logged: C{bool}
    @ivar logged: true if we have included this scan in a scan log. only applicable
                  if type="local".

    @type type: C{str}
    @ivar type: type of the scan; one of ["local", "social-active", "social-aggregate"].
             a fourth type, not part of the enum, is "social-passive" -
             the result of a scan using only bloom filters. However, this is never stored in the
             database, so no enum element is needed.

    """
    __tablename__ = 'scans'

    # id: priamry key, unique
    id = Column(Integer, nullable=False, primary_key=True)
    url = Column(String(1024), nullable=False)
    hash = Column(String(128))
    filesize = Column(Integer)
    owner_id = Column(Integer, ForeignKey('peers.id'))

    # timestamp is automatically generated and inserted.
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    peer_id = Column(Integer, ForeignKey('peers.id'))
    request_id = Column(Integer, ForeignKey('incomingqueue.id'))
    sent_request_id = Column(Integer, ForeignKey('sentscanrequests.id'))
    tainted = Column(Boolean, default=False, nullable=False)

    scannervv = Column(String(50))  # vendor and version
    sigversion = Column(String(50))
    sigdate = Column(DateTime, nullable=False)

    malicious = Column(Boolean)

    scantime = Column(Integer)
    retrivems = Column(Integer)

    digested = Column(Boolean, default=False, nullable=False)
    logged = Column(Boolean, default=False, nullable=False)

    type = Column(Enum("local", "social-active", "social-aggregate"))

    def __init__(self, owner, type, url, malicious, siginfo, hash=None, peer=None,
                 request=None, sentrequest=None, scantime=None, retrievems=None):
        self.owner = owner
        self.url = url
        self.malicious = malicious

        self.type = type

        self.hash = hash
        self.peer = peer
        #self.request = request
        self.scannervv, self.sigversion, self.sigdate = siginfo
        self.scantime = scantime
        self.retrievems = retrievems

    def __repr__(self):
        if self.tainted:  # need some doublechecking just in case
            traceback.print_stack()
            sys.stderr.write("WARNING: interacting with tainted scan! possible code oversight.\n")
            sys.stderr.flush()
        return "Scan(id=%r, %s, %s, %s, %s, %s, hash=%s, peer=%s, tainted=%r)" % \
            (self.id, self.owner, self.type, self.url, bool(self.malicious), self.siginfo,
                        self.hash, self.peer, self.tainted)

    to_UrlObject = map_to_UrlObject

    @property
    def safety(self):
        if self.tainted:
            raise TaintedScanError
        return util.Safety(True, self.malicious)

    @property
    def siginfo(self):
        """
        The L{util.SigInfo} version of scannervv, sigversion, and sigdate

        @rtype L{socialscan.util.SigInfo}
        """
        if self.tainted:
            raise TaintedScanError
        return util.SigInfo(self.scannervv, self.sigversion, self.sigdate)

    def markTainted(self, session, punishment=1.5):
        """
        Mark a scan as tainted (ie, a peer produced an incorrect result to intentionally confuse us).

        does not commit the session, must be committed manually
        """
        if not self.peer:
            raise NotImplementedError("marking peerless scans tainted is not implemented: %r" % self)
        relationship = self.owner.getRelationship(session, self.peer)
        relationship.punish(punishment)
        self.tainted = True
        session.add(relationship)
        session.add(self)


class ScanDigestFile(SocialScanContainerMixin, Base):
    """
    Represents a scan digest file and information about it.
    """
    __tablename__ = 'sdmeta'

    id = Column(Integer, nullable=False, primary_key=True)
    owner_id = Column(Integer, ForeignKey('peers.id'))

    creator_id = Column(Integer, ForeignKey('peers.id'))
    date = Column(DateTime, default=datetime.utcnow)
    complete = Column(Boolean, default=False)

    url = Column(String(1024))
    filename = Column(String(1024))

    hits = Column(Integer, default=0, nullable=False)

    scannervv = Column(String(50))
    sigversion = Column(String(50))
    sigdate = Column(DateTime)

    container_type_name = Column(String(128))

    def __init__(self, owner, config=None, siginfo=None, url=None,
                 location=None, creator=None, foreign=False, usefulness=0.0):
        super(ScanDigestFile, self).__init__(ScanDigest, owner, config, siginfo, url,
                                             location, creator, foreign, usefulness)
        self.container_type_name = 'ScanDigest'


class ScanLogFile(SocialScanContainerMixin, Base):
    """
    Represents a scan log file and information about it.
    """
    __tablename__ = 'slmeta'

    id = Column(Integer, nullable=False, primary_key=True)
    owner_id = Column(Integer, ForeignKey('peers.id'))

    creator_id = Column(Integer, ForeignKey('peers.id'))
    date = Column(DateTime, default=datetime.utcnow)
    complete = Column(Boolean, default=False)

    url = Column(String(1024))
    filename = Column(String(1024))

    hits = Column(Integer, default=0, nullable=False)

    scannervv = Column(String(50))
    sigversion = Column(String(50))
    sigdate = Column(DateTime)

    container_type_name = Column(String(128))

    def __init__(self, owner, config=None, siginfo=None, url=None, location=None,
                 creator=None, foreign=False, usefulness=0.0):
        super(ScanLogFile, self).__init__(ScanLog, owner, config, siginfo, url,
                                          location, creator, foreign, usefulness)
        self.filename = self.filename + '.log'
        self.url = self.url + '.log'
        self.container_type_name = 'ScanLog'


# An implementation of BaseQueuedRequest for SocialScan, an F3DS application.
class QueuedRequest(BaseQueuedRequest, Base):
    """
    A request that was received from a peer and has been queued for processing
    For type, any "offer" will be the lower-case class name, suffixed with "-offer"
    """
    __tablename__ = 'incomingqueue'
    extend_existing = True
    autoload = True
    type = Column(Enum("active-scan", "scandigestfile-offer", "scanlogfile-offer"), nullable=False)
    scan = relationship("Scan", uselist=False, backref="request")

    def __init__(self, owner, type, peer, url, key=None):
        super(QueuedRequest, self).__init__(owner, peer, url, key)
        self.type = type

    def __repr__(self):
        s = "QueuedRequest(id=%r, %r, %r, %r, %r, key=%r) from %r: %r (done at %r) - scanned as %r"
        return s % (self.id, self.owner, self.type, self.peer, self.url, self.key, 
                    self.time, self.state, self.fulfilled_time, self.scan)


# An implementation of BaseSentRequest for SocialScan, an F3DS application.
class SentScanRequest(BaseSentRequest, Base):
    """
    Table for active scan requests sent out to other peers - this is for local use only!
    """
    __tablename__ = 'sentscanrequests'
    ignored = Column(Boolean, nullable=True)
    scan = relationship(Scan, backref='sent_request', uselist=False)

    def __init__(self, owner, url, peer):
        super(SentScanRequest, self).__init__(owner, url, peer)


class Peer(BasePeer, Base):
    """
    An implementation of BasePeer for SocialScan, an F3DS application.
    """
    __tablename__ = 'peers'
    digests = relationship(ScanDigestFile,
                           backref='creator',
                           primaryjoin="Peer.id==ScanDigestFile.creator_id and Scan.tainted==False")
    scanlogs = relationship(ScanLogFile,
                           backref='creator',
                           primaryjoin="Peer.id==ScanLogFile.creator_id and Scan.tainted==False")
    requests = relationship(QueuedRequest,
                            backref='peer',
                            primaryjoin="Peer.id==QueuedRequest.peer_id")
    scans = relationship(Scan,
                         backref='peer',
                         primaryjoin="Peer.id==Scan.peer_id and Scan.tainted==False")
    sentscanrequests = relationship(SentScanRequest,
                                    backref='peer',
                                    primaryjoin="Peer.id==SentScanRequest.peer_id")
    _owned_digests = relationship(ScanDigestFile,
                                  backref='owner',
                                   primaryjoin="Peer.id==ScanDigestFile.owner_id")
    _owned_scanlogs = relationship(ScanLogFile,
                                  backref='owner',
                                   primaryjoin="Peer.id==ScanLogFile.owner_id")
    _owned_requests = relationship(QueuedRequest,
                                   backref='owner',
                                    primaryjoin="Peer.id==QueuedRequest.owner_id")
    _owned_scans = relationship(Scan,
                                backref='owner',
                                primaryjoin="Peer.id==Scan.owner_id")
    _owned_sentscanrequests = relationship(SentScanRequest,
                                           backref='owner',
                                           primaryjoin="Peer.id==SentScanRequest.owner_id")

    def __init__(self, username, password, url):
        super(Peer, self).__init__(username, password, url)
        # Override f3ds default network timeout if set in socialscan config.
        try:
            from socialscan.config import loadDefaultConfig
            self.timeout = loadDefaultConfig().core.network_timeout
        except:
            pass


######################## Queries #############################
#                                                            #
# Putting frequently used or unweildy queries here will also #
# reduce the potental for circular dependencies              #
#                                                            #
##############################################################

def relationshipsQuery(session, config):
    """
    Get all the peer relationships.
    """
    return baseRelationshipsQuery(session, config, peertype=Peer)


def requestQuery(session, config):
    """
    Prepare a request query using a QueuedRequest.  Find requests based on
    social distance.
    """
    return baseRequestQuery(session, config, queued_request_type=QueuedRequest)

###################### End Queries ###########################

