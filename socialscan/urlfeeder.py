#!/usr/bin/env python

import os
import sys
import getopt

from os import path

import UserAgent
import dbutils

thisdir, scriptname = path.split(path.abspath(__file__))

def print_usage():
    usage = """
    usage: %s -u <urlfile> -d <description> [-m <number>] [-M <number>] [-s <number>] [-i]

        -u urlfile      path to file containing urls to feed to the squid proxy
        -d description  description of experiment to help name output
        -m number       minimum amount of sleep * scale [200]
        -M number       maximum amount of sleep * scale [800]
        -s number       scale to use to change min, max sleep possible [1000]
        -i              interactive
    """
    print usage % (scriptname)

def main():
    minnap = 200
    maxnap = 800
    scale = 1000.0
    prefix = ''

    if len(sys.argv) < 2:
        with open(path.join(thisdir, 'args.txt'), 'rU') as argslist:
            lines = argslist.readlines()
            lines[:] = [line.replace('\r', ' ').replace('\n', ' ') for line in lines]
            argline = ''.join(lines)
            sys.argv = [sys.argv[0]] + argline.split()

    optlist, args = getopt.getopt(sys.argv[1:], 'u:d:m:M:s:i')
    options = dict(optlist)

    if '-u' not in options:
        print_usage()
        return
    nap = False
    if '-m' in options or '-M' in options or '-s' in options:
        nap = True
    UserAgent.retrieve(options['-u'], nap=nap, minnap=minnap, maxnap=maxnap,
                       napscale=scale, interactive='-i' in options)
    dbutils.export_csv(dbutils.dump(), description=options['-d'])


if __name__ == "__main__":
    main()

