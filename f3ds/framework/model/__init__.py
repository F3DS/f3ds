#!/usr/bin/python

__author__ = 'Jun Park, Matt Probst, Henry Longmore'
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
from f3ds.framework import util
from f3ds.framework.util import UrlObject, class_name, delta_seconds, TimeoutedTransport

Base = declarative_base()


# TODO: write tests (can use ScanDigestFile, ScanLogFile tests as starting point).
class ContainerMixin(object):
    """
    Represents a container file and information about it.
    """
    tainted = False

    def __init__(self, container_type, owner, config=None, url=None,
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
        self._container = self.container_type(self.maxcapacity, self.meta, self.filename)

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
            self._container.set_metadata(self.maxcapacity, self.meta)
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
    def meta(self):
        """
        Some meta information about the container.  To be defined by subclasses.
        """
        return None

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


    # TODO: naming convention?
def map_to_UrlObject(self):
    'Convert an object with required parameters for a UrlObject to the same.'
    filesize = -1
    if hasattr(self, 'filesize') and self.filesize:
        filesize = self.filesize
    hash = self.hash if self.hash else ''
    uo = UrlObject(self.url, filesize, nonce=self.owner.name, hash=hash)
    return uo


class BaseQueuedRequest(object):
    """
    A queued request for extension by F3DS applications.
    """
    #__tablename__ = 'incomingqueue' # Set the tablename in an implementation of BaseQueuedRequest.
    id = Column(Integer, nullable=False, primary_key=True)
    @declared_attr
    def owner_id(cls):
        return Column(Integer, ForeignKey('peers.id'), nullable=False)
    @declared_attr
    def peer_id(cls):
        return Column(Integer, ForeignKey('peers.id'), nullable=False)
    time = Column(DateTime, default=datetime.utcnow, nullable=False)
    url = Column(String(1024), nullable=False)
    fulfilled_time = Column(DateTime, nullable=True)
    key = Column(String(16))
    state = Column(Enum("received", "processed", "done"), default="received", nullable=False)

    def __init__(self, owner, peer, url, key=None):
        self.owner = owner
        self.peer = peer
        self.url = url
        if key:
            self.key = key
        self.state = "received"

    def __repr__(self):
        s = "BaseQueuedRequest(id=%r, %r, %r, %r, key=%r) from %r: %r (done at %r)"
        return s % (self.id, self.owner, self.peer, self.url, self.key,
                    self.time, self.state, self.fulfilled_time)


class BaseSentRequest(object):
    """
    A sent request for extension by F3DS applications.
    """
    #__tablename__ = 'basesentrequests' # Set the table name in an implementation of BaseSentRequest.
    id = Column(Integer, nullable=False, primary_key=True)
    @declared_attr
    def owner_id(cls):
        return Column(Integer, ForeignKey('peers.id'), nullable=False)
    @declared_attr
    def peer_id(cls):
        return Column(Integer, ForeignKey('peers.id'), nullable=False)
    url = Column(String(1024), nullable=False)
    key = Column(String(16), nullable=False)

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


class BasePeer(object):
    """
    Peer class for extension by F3DS applications.
    """
    #__tablename__ = 'basepeers' # Set the table name in an implementation of BasePeer.
    id = Column(Integer, nullable=False, primary_key=True)
    username = Column(String(80), nullable=False)
    password = Column(String(80), nullable=False)
    rpc_url = Column(String(128), nullable=False)
    timeout = Column(Integer)
 
    def __init__(self, username, password, url):
        self.username = username
        self.password = password
        self.rpc_url = url
        try:
            # TODO: create f3ds.config; use it here.
            from f3ds.config import loadDefaultConfig
            self.timeout = loadDefaultConfig().core.network_timeout
        except:
            self.timeout = 10

    def __repr__(self):
        return "Peer(id=%r, %r, %r, %r)" % (self.id, self.username, self.password, self.rpc_url)

    @property
    def transport(self):
        """
        Return a call proxy to this peer's rpccommands, currently using xmlrpc
        """
        transport_with_timeout = util.TimeoutedTransport()
        transport_with_timeout.set_timeout(self.timeout)
        return xmlrpclib.ServerProxy(self.rpc_url+"RPC2", allow_none=True,
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

def baseRelationshipsQuery(session, config, peertype=BasePeer):
    """
    Get all the peer relationships.
    """
    return session.query(SocialRelationship)\
              .join((peertype,
                     or_(SocialRelationship.peer_id==config.owner.id,
                         SocialRelationship.social_peer_id==config.owner.id)
                   ))\
              .all()


def baseRequestQuery(session, config, queued_request_type=BaseQueuedRequest):
    """
    Prepare a request query. This is code used in multiple places to find requests based on
    social distance, and as you can see it's quite a large query, so it gets it's own special function.
    """
    return session.query(queued_request_type)\
              .join(queued_request_type.peer)\
              .join((SocialRelationship,
                     and_(
                          or_(SocialRelationship.peer_id==queued_request_type.peer_id,
                              SocialRelationship.social_peer_id==queued_request_type.peer_id),
                          or_(SocialRelationship.peer_id==config.owner.id,
                              SocialRelationship.social_peer_id==config.owner.id))))\
              .order_by(SocialRelationship.pdistance)\
              .filter(queued_request_type.owner==config.owner)

###################### End Queries ###########################


