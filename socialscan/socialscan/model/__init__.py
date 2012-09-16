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
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapper, relationship, backref

# Our modules
from socialscan import util
from socialscan.exceptions import TaintedScanError
from socialscan.model.scandigest import ScanDigest
from socialscan.model.scanlog import ScanLog
from socialscan.searchutil import UrlObject

Base = declarative_base()


# TODO: write tests (can use ScanDigestFile, ScanLogFile tests as starting point).
class ContainerMixin(object):
    """
    Represents a container file and information about it.
    """
    tainted = False

    def __init__(self, container_type, owner, config=None, siginfo=None, url=None,
                 location=None, creator=None, foreign=False, usefulness=0.0):
        self.container_type = container_type
        self.owner = owner

        name = str(uuid.uuid4())
        if not location:
            if foreign:
                location = config.container_manager.storage_location
            else:
                location = config.container_manager.share_location
        self.filename = location.format(uuid=name)

        if not url:
            url = config.container_manager.share_url.format(bindhost=config.sharing.bindhost,
                                                    port=config.sharing.port,
                                                    uuid=name)
        self.url = url.format(uuid=name)

        if creator == None:
            self.creator = owner
        else:
            self.creator = creator

        if siginfo:
            self.scannervv, self.sigversion, self.sigdate = siginfo

    def __repr__(self):
        rv = '%s(id=%r, %s, %r, %r)'
        return rv % (self.__name__, self.id, self.container_type.__name__, self.owner, self.filename)

    # TODO: use class_name as a decorator?
    @property
    def __name__(self):
        return util.class_name(self)

    @property
    def usefulness(self):
        now = datetime.now()
        if not hasattr(self, 'date') or not self.date:
            self.date = now
        agesecs = util.delta_seconds(self.date - now)
        try:
            return float(self.hits) / agesecs
        except:
            return float(0)

    def create(self, maxcapacity):
        """
        Create a container.
        """
        self.maxcapacity = maxcapacity
        self._container = self.container_type(self.maxcapacity, self.siginfo, self.filename)

    def load(self):
        """
        Load a container from self.filename; return this ContainerMixin.
        """
        self._container = self.container_type.load(self.filename)
        self.maxcapacity = self._container.maxcapacity
        return self

    def save(self):
        """
        Save a container to file.
        """
        if hasattr(self._container, 'makedirs'):
            self._container.makedirs()
        if hasattr(self._container, 'set_metadata'):
            self._container.set_metadata(self.maxcapacity, self.siginfo)
        self._container.save()

    def unload(self):
        """
        Unload the current container.
        """
        self._container.close()
        self._container = None

    def get(self, item):
        try:
            get = self._container.get  # on a separate line for ease of error handling
        except AttributeError:
            msg = "Attempted to access %r of %r which is not loaded. "
            msg += "call %r.load() before using!" % (self.__name__, self, self._container.__name__)
            raise AttributeError(msg)
        return get(item)

    def add(self, item, extra=None):
        """
        Add an item to the container.
        """
        try:
            add = self._container.add # on a separate line for ease of error handling
        except AttributeError:
            msg = "Attempted to access %r of %r which is not loaded. "
            msg += "call %r.load() before using!" % (self.__name__, self, self._container.__name__)
            raise AttributeError(msg)
        return add(item, extra)

    @property
    def siginfo(self):
        """
        The L{util.SigInfo} version of scannervv, sigversion, and sigdate

        @rtype L{socialscan.util.SigInfo}
        """
        return util.SigInfo(self.scannervv, self.sigversion, self.sigdate)

    def markTainted(self, session, punishment=1.5):
        """
        Mark container as tainted (ie, a peer produced an incorrect result to intentionally confuse us).

        does not commit the session, must be committed manually
        """
        if not self.creator or self.creator == self.owner:
            raise NotImplementedError("marking peerless container tainted is not implemented: %r" % self)
        relationship = self.owner.getRelationship(session, self.creator)
        relationship.punish(punishment)
        self.tainted = True
        session.add(relationship)
        session.add(self)


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

    # TODO: naming convention?
    def to_UrlObject(self):
        'Convert Scan to UrlObject.'
        filesize = -1
        if hasattr(self, 'filesize') and self.filesize:
            filesize = self.filesize
        hash = self.hash if self.hash else ''
        uo = UrlObject(self.url, filesize, nonce=self.owner.name, hash=hash)
        return uo

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


class ScanDigestFile(ContainerMixin, Base):
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


class ScanLogFile(ContainerMixin, Base):
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


class QueuedRequest(Base):
    """
    A request that was received from a peer and has been queued for processing
    For type, any "offer" will be the lower-case class name, suffixed with "-offer"
    """
    __tablename__ = 'incomingqueue'

    id = Column(Integer, nullable=False, primary_key=True)
    owner_id = Column(Integer, ForeignKey('peers.id'), nullable=False)

    peer_id = Column(Integer, ForeignKey('peers.id'), nullable=False)
    type = Column(Enum("active-scan", "scandigestfile-offer", "scanlogfile-offer"), nullable=False)
    time = Column(DateTime, default=datetime.utcnow, nullable=False)

    url = Column(String(1024), nullable=False)
    fulfilled_time = Column(DateTime, nullable=True)

    key = Column(String(16))

    state = Column(Enum("received", "processed", "done"), default="received", nullable=False)

    scan = relationship("Scan", uselist=False, backref="request")

    def __init__(self, owner, type, peer, url, key=None):
        self.owner = owner
        self.type = type
        self.peer = peer
        self.url = url
        if key:
            self.key = key

        self.state = "received"

    def __repr__(self):
        return "QueuedRequest(id=%r, %r, %r, %r, %r, key=%r) from %r: %r (done at %r) - scanned as %r" %\
                    (self.id, self.owner, self.type, self.peer, self.url, self.key,\
                     self.time, self.state, self.fulfilled_time, self.scan)


class SentScanRequest(Base):
    """
    Table for active scan requests sent out to other peers - this is for local use only!
    """
    __tablename__ = 'sentscanrequests'

    id = Column(Integer, nullable=False, primary_key=True)
    owner_id = Column(Integer, ForeignKey('peers.id'), nullable=False)

    peer_id = Column(Integer, ForeignKey('peers.id'), nullable=False)
    url = Column(String(1024), nullable=False)
    key = Column(String(16), nullable=False)
    ignored = Column(Boolean, nullable=True)

    scan = relationship(Scan, backref='sent_request', uselist=False)

    @classmethod
    def generate_key(cls):
        key = []  # TODO XXX FIXME this key generation is not cryptographically strong, and
        for i in range(16):  # in a real environment may need to be improved
            key.append(random.choice(string.letters + string.digits + string.punctuation))
        return "".join(key)

    def __init__(self, owner, url, peer):
        self.key = self.generate_key()

        self.owner = owner
        self.url = url
        self.peer = peer


class SocialRelationship(Base):
    """
    """
    __tablename__ = 'socialrelationship'
    peer_id = Column(Integer, ForeignKey('peers.id'), primary_key=True)
    social_peer_id = Column(Integer, ForeignKey('peers.id'), primary_key=True)

    pdistance = Column(Float, nullable=False)
    realdistance = Column(Float, nullable=False)

    def __init__(self, peer_a, peer_b, distance, perceiveddistance=None):
        self.peer_id = peer_a
        self.social_peer_id = peer_b
        self.realdistance = distance
        if perceiveddistance != None:
            self.pdistance = perceiveddistance
        else:
            self.pdistance = distance

    def __repr__(self):
        return "SocialRelationship(%d, %d, %f, perceiveddistance=%f)" % \
                (self.peer_id, self.social_peer_id, self.realdistance, self.pdistance)

    def __str__(self):
        return "SocialRelationship(peer_id=%d, social_peer_id=%d, realdistance=%f, pdistance=%f)" % \
                (self.peer_id, self.social_peer_id, self.realdistance, self.pdistance)

    @property
    def distance(self):
        return self.pdistance

    def punish(self, punishment):
        self.pdistance *= punishment

    def redemption(self, multiplier):
        self.pdistance = ((multiplier * self.realdistance) +
                                 ((1.0 - multiplier) * self.pdistance))


class Peer(Base):
    """
    """
    __tablename__ = 'peers'

    id = Column(Integer, nullable=False, primary_key=True)
    username = Column(String(80), nullable=False)
    password = Column(String(80), nullable=False)
    ss_url = Column(String(128), nullable=False)
    timeout = Column(Integer)

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
        self.username = username
        self.password = password
        self.ss_url = url
        try:
            from socialscan.config import loadDefaultConfig
            self.timeout = loadDefaultConfig().core.network_timeout
        except:
            self.timeout = 10

    def __repr__(self):
        return "Peer(id=%r, %r, %r, %r)" % (self.id, self.username, self.password, self.ss_url)

    @property
    def transport(self):
        """
        Return a call proxy to this peer's rpccommands, currently using xmlrpc
        """
        transport_with_timeout = util.TimeoutedTransport()
        transport_with_timeout.set_timeout(self.timeout)
        return xmlrpclib.ServerProxy(self.ss_url+"RPC2", allow_none=True,
                                     transport=transport_with_timeout)

    def getRelationship(self, session, peer):
        """
        Get the relationship between this peer and another peer from a session.
        Result is None if no relationship exists.
        """
        return session.query(SocialRelationship)\
                .join((Peer, and_(
                                    or_(SocialRelationship.peer_id==self.id,
                                        SocialRelationship.social_peer_id==self.id),
                                    or_(SocialRelationship.peer_id==peer.id,
                                        SocialRelationship.social_peer_id==peer.id)
                                   )))\
                .order_by(SocialRelationship.pdistance)\
                .first()

    def queryRelated(self, session):
        right = session.query(Peer)\
                .join(SocialRelationship, SocialRelationship.peer_id==Peer.id)\
                .filter(SocialRelationship.social_peer_id==self.id)\
                .add_entity(SocialRelationship)
        left = session.query(Peer)\
                .join(SocialRelationship, SocialRelationship.social_peer_id==Peer.id)\
                .filter(SocialRelationship.peer_id==self.id)\
                .add_entity(SocialRelationship)
        return right.union(left).with_entities(Peer)

    @property
    def name(self):
        """
        a proxy to whatever attribute happens to be the peer name, to allow easy changing
        of what is treated as the name
        """
        return self.username

    @classmethod
    def getByName(cls, session, name):
        return session.query(Peer).filter(Peer.username == name).one()

    def getByDistance(self, session, distance):
        return self.queryRelated(session)\
                        .filter(SocialRelationship.pdistance <= distance)\
                        .all()


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
    return session.query(SocialRelationship)\
              .join((Peer,
                     or_(SocialRelationship.peer_id==config.owner.id,
                         SocialRelationship.social_peer_id==config.owner.id)
                   ))\
              .all()


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

###################### End Queries ###########################

