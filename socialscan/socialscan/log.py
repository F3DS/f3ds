#!/usr/bin/python

__author__ = 'Jun Park and Matt Probst'
__version__ = '0.1'

import os
from datetime import datetime
import sys
import traceback
from xmlrpclib import ServerProxy
import json

process_writer = None

process_start = datetime.now()

def formatname(logdir, name, fmt='{name}_%Y-%m-%d_%H%M.log'):
    """
    Format a logfile name
    """
    logfile = fmt.format(name=name)
    logfile = process_start.strftime(logfile)
    logfile = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", logdir, logfile))
    return logfile

def uniqify(logdir, name):
    """
    Make sure the name used by this process is unique, so we don't dump our logs in
    with the logs from other processes
    """
    logfile = formatname(logdir, name)
    inc = 0
    while os.path.exists(logfile):
        logfile = formatname(logdir, name, '{name}_%Y-%m-%d_%H%M' + ('_%d.log' % inc))
        inc += 1
    return logfile

stdoutlog = False

class Logger(object):
    def __init__(self, name):
        global process_writer
        self.logging = True
        self.name = name


        logdir = "data/log/"
        if not os.path.exists(logdir):
            os.makedirs(logdir)

        if not process_writer:
            logfile = uniqify(logdir, name)
            self.logger = open(logfile, "w")
            process_writer = self.logger
        else:
            self.logger = process_writer

    def log(self, message):
        if self.logging:
            now = datetime.utcnow()
            self.logger.write("[%s %s] %s\n" % (self.name, now, message))
            self.logger.flush()

            if stdoutlog:
                msg = "\033[02m[%s.%d %s] %s\033[00m\n" % (self.name, os.getpid(), now, message)
                sys.stdout.write(msg)
                sys.stderr.flush()
                sys.stdout.flush() #just to be helpful

    def exception(self):
        exc = traceback.format_exc()
        for line in exc.split("\n"):
            self.log(line)
