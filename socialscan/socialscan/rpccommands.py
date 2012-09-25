#!/usr/bin/python

# Python standard library modules
import datetime

# 3rd party modules
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from twisted.web import xmlrpc

# Our modules
from f3ds.framework.log import Logger
from socialscan.model import (Peer, BaseQueuedRequest, QueuedRequest, Scan,
                              BaseSentRequest, SentScanRequest)
from socialscan.util import SigInfo

class BaseRPCCommands(xmlrpc.XMLRPC):
    """
    RPC functions that are offered to other peers.
    """
    allowNone = True
    useDateTime = True
    def __init__(self, config, session):
        self.session = session
        self.config = config
        self.logger = Logger("BaseRPCFunctions")

    def _getpeer(self, peername, action):
        """
        Attempt to retrieve a peer
        """
        try:
            return Peer.getByName(self.session, peername)
        except MultipleResultsFound, e:
            self.logger.log("A Peer %r %s but we have multiple peers by that name: %r"
                                   % (peername, action, e))
        except NoResultFound, e:
            self.logger.log("A Peer %r %s but we have no peers by that name: %r"
                                  % (peername, action, e))

    def xmlrpc_containerOffer(self, peername, url, name):
        """
        Called by a peer to offer a container.  Stores the offer so that a worker
        can retrieve it later.
        """
        try:
            peer = self._getpeer(peername, "offered a %s on url %s" % (name, url))
            if not peer:
                return "peer not known"

            request = QueuedRequest(self.config.owner, "%s-offer" % (name), peer, url)

            self.session.add(request)
            self.session.commit()
            self.logger.log("%s offer: %r" % (name, (request,)))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_digestOffer(self, peername, url):
        """
        Called by a peer to offer a digest. Stores the offer so that a worker
        can retrieve it later (due to the large size digests often reach).
        """
        try:
            peer = self._getpeer(peername, "offered a digest on url %s" % url)
            if not peer:
                return "peer not known"

            request = QueuedRequest(self.config.owner, "digest-offer", peer, url)

            self.session.add(request)
            self.session.commit()
            self.logger.log("digest offer: %r" % (request,))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_logOffer(self, peername, url, logtype=''):
        """
        Called by a peer to offer a log. Stores the offer so that a worker
        can retrieve it later (due to the large size logs can reach).
        """
        try:
            peer = self._getpeer(peername, "offered a %slog on url %s" % (logtype, url))
            if not peer:
                return "peer not known"

            request = QueuedRequest(self.config.owner, "%slog-offer" % (logtype), peer, url)

            self.session.add(request)
            self.session.commit()
            self.logger.log("%slog offer: %r" % (logtype, request,))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_request(self, peername, url, key, requesttype=''):
        try:
            peer = self._getpeer(peername, "requested a %s on url %s" % (requesttype, url))
            if not peer:
                return "peer not known"

            request = BaseQueuedRequest(self.config.owner, peer, url, key=key)
            self.session.add(request)
            self.session.commit()

            self.logger.log("request %r: %r" % (key, request))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_result(self, peername, url, key):
        try:
            peer = self._getpeer(peername, "returned a %s on url %s" % (resulttype, url))
            if not peer:
                return "peer not known"

            request = self.session.query(BaseSentRequest).\
                        filter(BaseSentRequest.owner == self.config.owner).\
                        filter(BaseSentRequest.key == key).\
                        filter(BaseSentRequest.peer == peer).\
                        filter(BaseSentRequest.url == url).first()
            if not request:
                msg = "Peer %r attempted to return a result for url %r"
                msg += " with key %r, but no such result was requested"
                self.log(msg % (peer, url, key))
                return "no such request"
            self.session.add(request)
            self.session.commit()
            self.logger.log("Result %r: %r" % (key, scan))
            return "success"
        except:
            self.logger.exception()
            return "exception"


class SocialScanRPCCommands(BaseRPCCommands):
    """
    SocialScan RPC functions that are offered to other peers.
    """
    def __init__(self, config, session):
        super(SocialScanRPCCommands, self).__init__(config, session)
        self.logger = Logger("RPCFunctions")

    def xmlrpc_scanlogOffer(self, peername, url):
        """
        Called by a peer to offer a scanlog. Stores the offer so that a worker
        can retrieve it later (due to the large size scanlogs often reach).
        """
        self.xmlrpc_logOffer(peername, url, logtype='scan')

    def xmlrpc_scanRequest(self, peername, url, key):
        try:
            peer = self._getpeer(peername, "requested a scan on url %s" % url)
            if not peer:
                return "peer not known"

            request = QueuedRequest(self.config.owner, "active-scan", peer,
                                    url, key=key)
            self.session.add(request)
            self.session.commit()

            self.logger.log("Scan request %r: %r" % (key, request))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_scanResult(self, peername, url, hash, key, malicious,
                          scannervv, sigversion, sigdatestr):
        try:
            peer = self._getpeer(peername, "returned a scan on url %s" % url)
            if not peer:
                return "peer not known"

            request = self.session.query(SentScanRequest).\
                        filter(SentScanRequest.owner == self.config.owner).\
                        filter(SentScanRequest.key == key).\
                        filter(SentScanRequest.peer == peer).\
                        filter(SentScanRequest.url == url).first()
            if not request:
                self.log("Peer %r attempted to return a scan result for "
                            "url %r with key %r, but no such scan was requested"
                            % (peer, url, key))
                return "no such request"

            sigdate = datetime.datetime.utcfromtimestamp(int(sigdatestr))

            hash = hash or None  # if the hash is empty or similar, replace with None

            scan = Scan(self.config.owner, "social-active", url, malicious,
                        siginfo=SigInfo(scannervv, sigversion, sigdate),
                        hash=hash, sentrequest=request, peer=peer)
            self.session.add(scan)
            self.session.commit()
            self.logger.log("Scan result %r: %r" % (key, scan))
            return "success"
        except:
            self.logger.exception()
            return "exception"

