#!/usr/bin/python
"""Minor utilities for testing the system.

Usage:
    python testutils.py <command> <args...>

Available commands:
    makepeers [IP...] - generate some peers, relationships, and names
    db                - start a python interactive interpreter with the db environment loaded
"""

import sys

from socialscan.model import *
from socialscan import db
from socialscan.config import loadDefaultConfig
from socialscan import util

from collections import deque
import random

import ConfigParser


initdists = (0.5, 0.7, 1.1, 1.5)
rollingdists = []
peercount = 4
def nextDistance():
    global rollingdists
    if not len(rollingdists):
        rollingdists = list(initdists)
    dist = random.choice(rollingdists)
    rollingdists.remove(dist)
    return dist


def makepeers():
    """
    Generate a list of peers with random relationships, for testing
    """
    random.seed(0)
    addresses = deque(sys.argv[2:])
    if not len(addresses):
        print makepeers.__doc__
        return

    if "127.0.0.1" in addresses:
        ouraddress = "127.0.0.1"
    else:
        ouraddress = util.getIP()
    ourname = None

    peercount = len(addresses)

    names = """
    bebo    boidoc  merodoc friabo
    bodoc   sabo    sobo    merido
    merom   sigrin  bidoc   budoc
    sodo    froigrin    merem   bado
    subo    sabo    budo    perigo
    budoc   driam   bigrin  sebo
    bebo    bubo    sido    bigo
    bedoc   bebo    bugo    perubo""".split()[:peercount]
    names = list(set(names))
    random.shuffle(names)

    session.query(Peer).delete()
    session.query(SocialRelationship).delete()
    peers = []

    config = loadDefaultConfig()

    for name in names:
        address = addresses.pop()
        peers.append(Peer(name, "", "http://%s:%s/" % (address, config.sharing.rpcport)))
        print "making peer %s (%s)" % (name, address)
        if address == ouraddress:
            ourname = name
    session.add_all(peers)
    session.commit()
    for peer in peers:
        print "peer %s relationships:" % peer.name
        for otherpeer in peers:
            if peer.getRelationship(session, otherpeer) != None or peer == otherpeer:
                continue
            distance = 0.9 # nextDistance()
            relationship = SocialRelationship(peer.id, otherpeer.id, distance)
            session.add(relationship)
            print "    %f -> %s" % (distance, otherpeer.name)
    session.commit()

    if ourname:
        print "assigned name %r to local peer" % ourname
        parser = ConfigParser.ConfigParser()
        f = os.path.join(os.path.dirname(__file__), "socialscan.config")
        parser.readfp(open(f, "r"))
        parser.set("general", "localpeer", ourname)
        try:
            parser.add_section("sharing")
        except ConfigParser.DuplicateSectionError:
            pass
        parser.set("sharing", "bindhost", ouraddress)
        parser.set("sharing", "port", config.sharing.port)
        parser.set("sharing", "rpcport", config.sharing.rpcport)
        parser.write(open(f, "w"))



if __name__ == "__main__":
    command = sys.argv[1]
    config = loadDefaultConfig()
    session, engine = db.setupDB(config.database.url)
    if command == "makepeers":
        makepeers()
    elif command == "db":
        #owner = Peer.getByName(session, config.general.localpeer)
        #config.owner = owner
        import code
        code.interact(local=globals())
    else:
        print __doc__
