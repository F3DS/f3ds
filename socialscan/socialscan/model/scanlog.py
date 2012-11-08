#!/usr/bin/python
"""
ScanLog implementation details.
"""

# Python standard libraries
import anydbm
import os

from datetime import datetime
from os import path

# 3rd party modules

# Our modules
from f3ds.framework.log import Logger
from f3ds.framework.exceptions import ContainerFullError
from f3ds.framework.model.log import Log
from socialscan.config import loadDefaultConfig
from socialscan.util import Safety, SigInfo


class ScanLog(Log):
    """
    IMPORTANT:
    this class should be considered an implementation detail of the higher level
    C{socialscan.model.ScanLogFile}!

    Represents a scan log, which stores three pieces of information about an object:
        1) a hash of the url of the object
        2) a hash of the object at the url, if available
        3) whether the object was deemed to be malicious (0 = benign, 1 = malicious)
        1 & 2 are used as keys for two distinct entries, with 3 as the data for both

    @ivar maxcapacity: maximum number of scans to store in this log.
    @type maxcapacity: C{int}

    @ivar siginfo: Signature information about what scans can be stored in this log.
    @type siginfo: L{SigInfo}

    @ivar saved: whether this log has been saved since scans were added.
    @type saved: C{bool}
    """
    logger = Logger('ScanLog')
    bool_string_map = {'1': True, '0': False}

    def __init__(self, maxcapacity, siginfo, dbpath):
        """
        @param maxcapacity: maximum capacity of ScanLog.  Should be the same as the
                            corresponding ScanDigest's maxcapacity.
        @type maxcapacity: int

        @param siginfo: signature info for scanner.  Should match the corresponding
                        ScanDigest's siginfo.
        @type siginfo: L{SigInfo}

        @param db: database containing url/content hash keys and maliciousness values
        @type db: L{anydbm} database
        """
        super(ScanLog, self).__init__(maxcapacity, siginfo, dbpath)
        self.siginfo = siginfo
        self.metadata_keys = ['maxcapacity', 'scannervv', 'sigversion', 'sigtimestamp', 'urlcount']
        # Save metadata after setting it.
        self.saved = False
        self.save()

    def get(self, urlobject):
        """
        Get the information about an attribute of interest for an object. 
        @param urlobject: object with url hash and/or content hash to search for
        """
        confident = False
        malicious = True
        if not urlobject:
            return None
        for key in [urlobject.url, urlobject.contenthash]:
            if key in self.db:
                (confident, malicious) = (True, self.bool_string_map[self.db[key]])
            if confident:
                break
        return Safety(confident, malicious) if confident else None


    def add(self, urlobject, safety):
        # UrlObject is False if url hash and content hash are both empty.
        added = False
        if not urlobject:
            return added
        if len(self) >= self.maxcapacity:
            raise ContainerFullError

        self.saved = False
        for key in [urlobject.url, urlobject.contenthash]:
            if not key:
                continue
            self.db[key] = '1' if safety.ismalicious else '0'
            added = True
        if added:
            self.urlcount += 1
        return added

    def _set_metadata(self):
        self.db['maxcapacity'] = '%s' % self.maxcapacity
        try:
            self.db['scannervv'] = '%s' % self.siginfo.scannervv
            self.db['sigversion'] = '%s' % self.siginfo.sigversion
            if not self.siginfo.sigdate:
                # self.siginfo is a property; assign to self.sigdate instead.
                self.sigdate = datetime.utcnow()
                self.db['utc'] = 'True'
            self.db['sigtimestamp'] = self._ignore_microseconds('%s' % self.siginfo.sigdate)
        except:
            self.db['scannervv'] = ''
            self.db['sigversion'] = ''
            # self.siginfo is a property; assign to self.sigdate instead.
            self.sigdate = datetime.utcnow()
            self.db['utc'] = 'True'
            self.db['sigtimestamp'] = self._ignore_microseconds('%s' % self.sigdate)
        self.db['urlcount'] = '%s' % self.urlcount
        if hasattr(self, 'hits'):
            self.db['hits'] = '%s' % self.hits
        self.saved = False

    def set_metadata(self, maxcapacity=None, siginfo=None):
        'Allow the metadata to be set after initialization.'
        if maxcapacity:
            self.maxcapacity = maxcapacity
            saved = False
        if siginfo:
            self.siginfo = siginfo
            saved = False

    @classmethod
    def load(cls, filepath):
        try:
            db = anydbm.open(filepath, 'c')
        except anydbm.error, e:
            ScanLog.logger.log(e)

        now = datetime.utcnow()
        now = datetime(now.year, now.month, now.day, now.hour, now.minute, now.second, tzinfo=None)
        defaults = {'maxcapacity': loadDefaultConfig().container_manager.maxcapacity,
                    'scannervv': 'Unknown Scanner Version',
                    'sigversion': 'Unknown Signature Version',
                    'sigtimestamp': '%s' % datetime.strftime(now, '%Y-%m-%d %H:%M:%S'),
                    'urlcount': 0}

        for k in defaults:
            if k in db:
                defaults[k] = db[k]
        if 'utc' in db:
            dtconversion = datetime.utcfromtimestamp
        else:
            dtconversion = datetime.fromtimestamp
        db.close()
        # Make sure types are as expected.
        defaults['maxcapacity'] = int(defaults['maxcapacity'])
        defaults['urlcount'] = int(defaults['urlcount'])
        # one last check of the timestamp, in case the loaded version was bad.
        try:
            if not defaults['sigtimestamp']:
                defaults['sigtimestamp'] =  '%s' % datetime.strftime(now, '%Y-%m-%d %H:%M:%S')
            sigtimestamp = datetime.strptime(cls._ignore_microseconds(defaults['sigtimestamp']),
                                             '%Y-%m-%d %H:%M:%S')
        except:
            ScanLog.logger.log('Error getting the sigtimestamp from %s' % filepath)
            ScanLog.logger.log('sigtimestamp before conversion: %s' % defaults['sigtimestamp'])
            sigtimestamp = datetime(now.year, now.month, now.day, now.hour, now.minute, now.second)
        siginfo = SigInfo(defaults['scannervv'], defaults['sigversion'], sigtimestamp)
        scanlog = cls(defaults['maxcapacity'], siginfo, filepath)
        scanlog.urlcount = defaults['urlcount']
        return scanlog

