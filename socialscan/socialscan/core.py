# Standard Python modules
import json
import datetime

# 3rd party modules
from twisted.internet import defer, reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint

# Our modules
from f3ds.framework.log import Logger
from f3ds.framework.core import (Core, CoreRequest, CoreClientRequest,
                                 CoreClientFactory, BaseHandlerProxy)
from socialscan import decisionhandlers
from socialscan import scanning
from socialscan.config import loadDefaultConfig
from socialscan.db import setupDB
from socialscan.model import Peer, Scan
from socialscan.util import Safety, WeightedAverager

class DecisionHandlerProxy(BaseHandlerProxy):
    """
    Decision Handler proxy.  Contains default implementations which will be
    used if something is missing from the handler implementation.
    """
    def __init__(self, handler):
        super(DecisionHandlerProxy, self).__init__(handler)
        # If desired, set a different default for self.port
        #self.port = 8123
        self.not_implemented = 'decision_' + self.not_implemented

    def deny(self, core, request):
        "Determine what string should be returned to squid to deny this url"
        core.logger.log("denying url %s" % request.url)
        return "http://localhost:%s/malicious.html" % self.port

    def allow(self, core, request):
        "Determine what string should be returned to squid to allow this url"
        core.logger.log("allowing url %s" % request.url)
        return ""

    def isUrlExempt(self, core, request):
        """
        Determine whether url should be exempt from scanning.
        Returning True will immediately allow the url.
        """
        #placeholder code - nothing is exempt
        return False

    def process(self, core, request):
        """
        Determine the safety status of a url.
        Overridden to provide documentation for decision_handler writers.
        
        @type request: L{socialscan.scanning.ScannableRequest}
        @param request: Request object 

        @rtype: L{socialscan.util.Safety}
        @return: Computed Safety value of the request
        """
        raise NotImplementedError(self.not_implemented)


class SocialScanCoreRequest(CoreRequest):
    def __init__(self, core):
        super(SocialScanCoreRequest, self).__init__(core, logger_name='SocialScan Request')

    @defer.inlineCallbacks
    def handle_url(self, url):
        """
        Run the loop for an individual url
        """
        try:
            self.logger.log("handling url %r" % url)
            request = scanning.ScannableRequest(self.core.config, self.core.session, url,
                                                digestmanager=self.core.digestmanager,
                                                scanlogmanager=self.core.scanlogmanager)

            if self.handler.isUrlExempt(self.core, request):
                self.logger.log("url exempt from scanning")
                self.reply(self.handler.allow(self.core, request))
                return

            start = datetime.datetime.utcnow()
            confident = False
            while not confident:
                status = self.handler.process(self.core, request)
                elapsed = datetime.datetime.utcnow() - start
                self.logger.log('handle_url: elapsed time: %s' % elapsed)
                confident = status.isconfident
                if elapsed > self.timeout:
                    msg = 'timed out: took %s (timeout: %s) (confident?: %s)'
                    self.logger.log(msg % (elapsed, self.timeout, confident))
                    break
                yield request.sleep()

            if status.ismalicious:
                self.reply(self.handler.deny(self.core, request))
            else:
                self.reply(self.handler.allow(self.core, request))
        except:
            self.logger.exception()
            self.transport.loseConnection()


class SocialScanCore(Core):
    def __init__(self, config, session, digestmanager, scanlogmanager):
        super(SocialScanCore, self).__init__(config, session, digestmanager,
                                             scanlogmanager, logname='SocialScan')
        self.confidence_threshold = float(config.core.confidence_threshold)
        self.logger.log("confidence threshold: %f" % self.confidence_threshold)
        self.handler = DecisionHandlerProxy(decisionhandlers.get(config.core.decision_handler))
        self.handler.port = config.sharing.port

    def buildProtocol(self, addr):
        return SocialScanCoreRequest(self)
