# Standard Python modules
import json
import datetime

# 3rd party modules
from twisted.internet import defer, reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.internet.endpoints import TCP4ClientEndpoint

# Our modules
from f3ds.framework.log import Logger
from socialscan import decisionhandlers
from socialscan import scanning
from socialscan.config import loadDefaultConfig
from socialscan.db import setupDB
from socialscan.model import Peer, Scan
from socialscan.util import Safety, WeightedAverager

class BaseHandlerProxy(object):
    """
    Handler proxy. contains default implementations which will be used if something is missing from the
    handler implementation.
    """
    def __init__(self, handler):
        self._handler = handler
        self.port = 8123
        self.not_implemented = 'handler module must contain a function matching "process(core, request)"'

    def __getattribute__(self, attribute):
        """
        Custom implementation of __getattribute__ to retrieve attributes from the provided
        handler first, then from the class if they cannot be found in the handler.
        """
        try:
            return getattr(object.__getattribute__(self, "_handler"), attribute)
        except AttributeError:
            return object.__getattribute__(self, attribute)

    def process(self, core, request):
        """
        Process a request.
        """
        raise NotImplementedError(self.not_implemented)


class CoreRequest(Protocol):
    def __init__(self, core, logger_name='Core Request'):
        self.core = core
        self.handler = core.handler
        self.logger = Logger(logger_name)
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
        raise NotImplementedError('Derived classes must implement handle_url.')

# TODO: refactor Core to reflect F3DS framework.
class Core(Factory):
    def __init__(self, config, session, digestmanager, scanlogmanager, logname='CoreBase'):
        # Do we need digestmanager, scanlogmanager?
        self.logger = Logger(logname)
        self.config = config
        self.session = session
        self.timeout = datetime.timedelta(seconds=int(config.core.network_timeout))
        self.handle_timeout = datetime.timedelta(seconds=int(config.core.system_timeout))
        self.handler = BaseHandlerProxy(None)
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

