#!/usr/bin/python

"""
SocialScan Squid Redirector
Is run as __main__ as a squid redirector
see http://wiki.squid-cache.org/Features/Redirectors
"""

__author__ = 'Christian "lahwran" Horne, Matt Probst, and Jun Park'

# Python standard library imports
import os

from datetime import datetime, timedelta

# 3rd party imports
from twisted.internet import stdio, reactor
from twisted.protocols import basic
from twisted.internet.endpoints import TCP4ClientEndpoint

# Our imports
from socialscan.config import loadDefaultConfig
from socialscan.log import Logger
from socialscan.core import CoreClientFactory


class Redirector(basic.LineOnlyReceiver):
    """
    Redirector protocol class. Implements the squid redirector protocol, agnostic of where
    it is used from. Currently only uses the url field from the squid redirector protocol,
    so leaving out the other fields will have no effect.

    @ivar logger: 'Redirector' logger
    @type logger: L{Logger}

    @ivar config: config instance
    @type config: L{AttributeConfig}

    @ivar endpoint: endpoint location of Core server on localhost
    @type endpoint: C{twisted.internet.endpoints.TCP4ClientEndpoint}
    """
    begin = None
    end = None
    delimiter = "\n"
    def __init__(self, config):
        self.logger = Logger('Redirector')
        self.config = config
        self.endpoint = TCP4ClientEndpoint(reactor, "127.0.0.1", int(config.scanning._core_port))

    def parseLine(self, line):
        """
        Parse a line from squid
        @param line: line received from squid
        @type line: C{str}
        @return: url from the line
        @rtype: C{str}
        """
        # IDnum URLstr ip/fqdn ident method key=value key=value
        # or
        # URLstr ip/fqdn ident method key=value key=value
        # E.g., http://www.google.com 192.168.100.1/- user2 GET myip=192.168.100.1 myport=3128

        split = line.split(" ")
        fields = iter(split)

        # the following block deals with the ID number being optional
        first = fields.next()
        try:
            channelid = int(first)
        except ValueError:
            url = first
        else:
            url = fields.next()

        return url

    def stop(self):
        """
        Stop running; provided in case this protocol is subclassed.
        Stops the reactor.
        """
        reactor.stop()

    @property
    def totaltime(self):
        if self.begin and self.end:
            return self.end - self.begin
        elif self.begin:
            return datetime.now() - self.begin
        else:
            return timedelta(0)

    def callback(self, result):
        """
        Callback provided to CoreClientFactory.
        @param result: url to redirect to, or C{""}.
        @type result: C{str}
        """
        self.end = datetime.now()
        msg = 'Decision took %s seconds; URL result: %s'
        self.logger.log(msg % (self.totaltime.total_seconds(), result))
        self.transport.write("%s\n" % result)

    def dataReceived(self, data):
        """
        A hack to make sure this protocol will work regardless of whether it is fed
        \\r\\n newlines or \\n newlines.
        """
        basic.LineOnlyReceiver.dataReceived(self, data.replace("\r", ""))

    def lineReceived(self, line):
        """
        Handle a received line.
        @type line: C{str}
        @param line: line received
        """
        self.begin = datetime.now()
        self.logger.log("Got a new request: [%s]" % line.replace("\n", ""))
        if not line:
            self.logger.log("Line empty, exiting: %r" % line)
            self.stop()

        url = self.parseLine(line)
        if not url:
            self.logger.log("URL empty, ignoring: %r" % url)
            return

        factory = CoreClientFactory(url, self.callback)
        self.endpoint.connect(factory)


def main(config):
    """
    Run the redirector. Uses Twisted's StandardIO to run L{Redirector} as squid expects.
    @param config: initialized config.
    @type config: L{AttributeConfig}
    """
    redirector = Redirector(config)
    stdio.StandardIO(redirector)

    from twisted.internet import reactor
    reactor.run()

    redirector.logger.log("SocialScan Redirector is exiting...\n")


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    config = loadDefaultConfig()
    main(config)
