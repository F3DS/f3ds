#!/usr/bin/python

# Python standard library modules
import datetime

# 3rd party modules
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
from twisted.web import xmlrpc

# Our modules
from socialscan.model import Peer, QueuedRequest, QueuedRequest, Scan, SentScanRequest
from socialscan.log import Logger
from socialscan.util import SigInfo

class RPCCommands(xmlrpc.XMLRPC):
    """
    RPC functions that are offered to other peers.

    todo: This class could use a more descriptive name
    """
    allowNone = True
    useDateTime = True
    def __init__(self, config, session):
        self.session = session
        self.config = config
        self.logger = Logger("RPCFunctions")

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

    def xmlrpc_scanlogOffer(self, peername, url):
        """
        Called by a peer to offer a scanlog. Stores the offer so that a worker
        can retrieve it later (due to the large size scanlogs often reach).
        """
        try:
            peer = self._getpeer(peername, "offered a scanlog on url %s" % url)
            if not peer:
                return "peer not known"

            request = QueuedRequest(self.config.owner, "scanlog-offer", peer, url)

            self.session.add(request)
            self.session.commit()
            self.logger.log("scanlog offer: %r" % (request,))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_scanRequest(self, peername, url, key):
        try:
            peer = self._getpeer(peername, "requested a scan on url %s" % url)
            if not peer:
                return "peer not known"

            request = QueuedRequest(self.config.owner, "active-scan",
                        peer, url, key=key)
            self.session.add(request)
            self.session.commit()

            self.logger.log("Scan request %r: %r" % (key, request))
            return "success"
        except:
            self.logger.exception()
            return "exception"

    def xmlrpc_scanResult(self, peername, url, hash, key, malicious, scannervv,
                        sigversion, sigdatestr):
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

