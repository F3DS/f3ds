# Standard Python modules
import json
import datetime

# 3rd party modules
from twisted.internet import defer, reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint

# Our modules
from socialscan import decisionhandlers
from socialscan import scanning
from socialscan.config import loadDefaultConfig
from socialscan.db import setupDB
from socialscan.log import Logger
from socialscan.model import Peer, Scan
from socialscan.util import Safety, WeightedAverager

class HandlerProxy(object):
    """
    Handler proxy. contains default implementations which will be used if something is missing from the
    handler implementation.
    """
    def __init__(self, handler):
        self._handler = handler
        self.port = 8123

    def __getattribute__(self, attribute):
        """
        Custom implementation of __getattribute__ to retrieve attributes from the provided
        handler first, then from the class if they cannot be found in the handler.
        """
        try:
            return getattr(object.__getattribute__(self, "_handler"), attribute)
        except AttributeError:
            return object.__getattribute__(self, attribute)

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
        
        @type request: L{socialscan.scanning.ScannableRequest}
        @param request: Request object 

        @rtype: L{socialscan.util.Safety}
        @return: Computed Safety value of the request
        """
        msg = 'decision_handler module must contain a function matching "process(core, request)"'
        raise NotImplementedError(msg)


class CoreRequest(Protocol):
    def __init__(self, core):
        self.core = core
        self.handler = core.handler
        self.logger = Logger('SocialScan Request')
        self.input = []
        self.timeout = core.handle_timeout

    def dataReceived(self, data):
        if "\x04" in data:
            self.input.append(data.partition("\x04")[0])
            url = json.loads("".join(self.input))
            self.handle_url(url)
        else:
            self.input.append(data)

    def reply(self, result):
        self.transport.write(json.dumps(result))
        self.transport.loseConnection()

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


class Core(Factory):
    def __init__(self, config, session, digestmanager, scanlogmanager):
        self.logger = Logger('SocialScan')
        self.config = config
        self.session = session
        self.timeout = datetime.timedelta(seconds=int(config.core.network_timeout))
        self.handle_timeout = datetime.timedelta(seconds=int(config.core.system_timeout))
        self.confidence_threshold = float(config.core.confidence_threshold)
        self.logger.log("confidence threshold: %f" % self.confidence_threshold)
        self.handler = HandlerProxy(decisionhandlers.get(config.core.decision_handler))
        self.handler.port = config.sharing.port
        self.digestmanager = digestmanager
        self.scanlogmanager = scanlogmanager

    def buildProtocol(self, addr):
        return CoreRequest(self)


class CoreClientRequest(Protocol):
    def __init__(self, url, callback):
        self.url = url
        self.callback = callback
        self.input = []

    def connectionMade(self):
        self.transport.write(json.dumps(self.url))
        self.transport.write("\x04")

    def dataReceived(self, data):
        self.input.append(data)

    def connectionLost(self, reason):
        self.callback(json.loads("".join(self.input)).encode("utf-8"))


class CoreClientFactory(Factory):
    def __init__(self, url, callback):
        self.url = url
        self.callback = callback

    def buildProtocol(self, addr):
        return CoreClientRequest(self.url, self.callback)

