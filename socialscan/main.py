#!/usr/bin/python
"""
Main code to initialize the system. Does not daemonize.
Run with:

    python main.py
"""
# Standard Python modules
import os
import shutil

# 3rd party modules
from twisted.web.static import File
from twisted.web.server import Site
from twisted.web import resource
from twisted.internet.endpoints import TCP4ServerEndpoint

# Our modules
from f3ds.framework import log
from socialscan.config import loadDefaultConfig
from socialscan.core import SocialScanCore
from socialscan.db import setupDB
from socialscan.model import Peer
from socialscan.rpccommands import SocialScanRPCCommands
from socialscan.model.containers import DigestManager, ScanLogManager


def main():
    """
    Start the system and twisted reactor.
    """
    from twisted.internet import reactor

    log.stdoutlog = True
    logger = log.Logger("Main")

    logger.log("Loading configuration")
    config = loadDefaultConfig()
    logger.log("Setting up DB")
    session, engine = setupDB(config.database.url)

    owner = Peer.getByName(session, config.general.localpeer)
    config.owner = owner

    # start the digest manager
    logger.log("Start digest manager")
    digestmanager = DigestManager(config, session)
    digestmanager._initJobs()

    # start the scanlog manager
    logger.log("Start scan log manager")
    scanlogmanager = ScanLogManager(config, session)
    scanlogmanager._initJobs()

    # construct the sharing system that other peers can download from and talk to
    logger.log("Initialize sharing system")
    root = resource.Resource()
    root.putChild('RPC2', SocialScanRPCCommands(config, session))

    # add the local static content under shared/ that other peers can download digests and such from
    sharedir = os.path.realpath("data/shared/")
    #root.putChild('shared', File(sharedir))
    if not os.path.exists(sharedir):
        os.makedirs(sharedir)
    dn = os.path.dirname
    sourcedir = dn(dn(sharedir))
    shutil.copy2(os.path.join(sourcedir, 'url_malicious.html'),
                 os.path.join(sourcedir, 'data', 'malicious.html'))
    #root.putChild('malicious', File("url_malicious.html"))

    logger.log("Initializing TCP listening")
    reactor.listenTCP(port=int(config.sharing.rpcport), interface=config.sharing.bindhost,
                        factory=Site(root))

    endpoint = TCP4ServerEndpoint(reactor, int(config.scanning._core_port), interface="127.0.0.1")
    endpoint.listen(SocialScanCore(config, session, digestmanager, scanlogmanager))

    logger.log("Running reactor")
    reactor.run()


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    main()
