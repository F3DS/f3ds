#!/usr/bin/python

import ConfigParser
import sys

def editor(shandler,dhandler, previous, path):
    
    f=open(path, 'w')
    
    config=ConfigParser.SafeConfigParser()

    general=previous[0]
    sharing=previous[1]
    
    config.add_section("core")
    config.set("core", "decision_handler", dhandler)

    config.add_section(sharing[0])
    config.set("sharing", "bindhost", sharing[1])
    config.set("sharing", "port", sharing[2])
    
    config.add_section("scanning")
    config.set("scanning", "handler", shandler)

    # set a number of parameters
    config.add_section(general[0])
    config.set("general","localpeer",general[1])
    config.set("general","localip",general[2])

    # write to socialscan.config
    config.write(f)

    f.close()

def getInfo(path):
    config=ConfigParser.ConfigParser()
    config.read(path)

    #first get general
    first=config.get("general","localpeer",1)
    second=config.get("general","localip",1)
    general=("general",first, second)

    #Now get sharing
    bind=config.get("sharing", "bindhost", 1)
    port=config.get("sharing", "port", 1)
    sharing=("sharing",bind, port)

    #returns a tuple of tuples
    return general,sharing

##if __name__ == '__main__':
##    a=str(sys.argv[1])
##    b=str(sys.argv[2])
##    editor('mcafee', 'local', 'socialscan.config')

