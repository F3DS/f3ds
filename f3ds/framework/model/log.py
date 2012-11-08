#!/usr/bin/python
"""
Log implementation details. (Not to be confused with the logging module called log).
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
from f3ds.framework.util import Present


class Log(object):
    """
    Represents a log, which stores three pieces of information about an object:
        1) a hash of the url of the object
        2) a hash of the object at the url, if available
        3) whether the object an attribute of interest is present. (0 = does not have the
        attribute, 1 = does have the attribute)
        1 & 2 are used as keys for two distinct entries, with 3 as the data for both

    @ivar maxcapacity: maximum number of items to store in this log.
    @type maxcapacity: C{int}

    @ivar meta: meta data about what items can be stored in this log.  The type will be
    determined by subclasses.

    @ivar saved: whether this log has been saved since items were added.
    @type saved: C{bool}
    """
    logger = Logger('Log')
    bool_string_map = {'1': True, '0': False}

    def __init__(self, maxcapacity, meta, dbpath):
        """
        @param maxcapacity: maximum capacity of Log.  Should be the same as the
                            corresponding ScanDigest's maxcapacity.
        @type maxcapacity: int

        @param meta: meta data about what items are stored in this Log.  Type will be
        determined by subclasses.

        @param db: database containing url/content hash keys and attribute present values
        @type db: L{anydbm} database
        """
        self.maxcapacity = maxcapacity
        self.meta = meta
        self.dbpath = dbpath
        dbdir = path.dirname(self.dbpath)
        self.metadata_keys = ['maxcapacity', 'meta', 'urlcount']
        if not path.isdir(dbdir):
            os.makedirs(dbdir)
        self.db = anydbm.open(self.dbpath, 'c')
        if 'hits' in self.db:
            self.hits = self.db['hits']
        self.urlcount = 0
        # Save metadata after setting it.
        self.saved = False
        self.save()

    def get(self, urlobject):
        """
        Get the information about an object. 
        @param urlobject: object with url hash and/or content hash to search for
        """
        confident = False
        present = True
        if not urlobject:
            return None
        for key in [urlobject.url, urlobject.contenthash]:
            if key in self.db:
                (confident, present) = (True, self.bool_string_map[self.db[key]])
            if confident:
                break
        return Present(confident, present) if confident else None

    def __len__(self):
        """ Get the number of urls in this scanlog. """
        return self.urlcount

    def add(self, urlobject, present):
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
            self.db[key] = '1' if present.ispresent else '0'
            added = True
        if added:
            self.urlcount += 1
        return added

    def save(self):
        """
        Make sure db changes are written.
        """
        if not self.saved:
            self._set_metadata()
            self.db.sync()
            self.saved = True

    def close(self):
        try:
            if self.db:
                self.db.close()
        except anydbm.error:
            pass

    @classmethod
    def _ignore_microseconds(cls, dtstring):
        decimal = dtstring.find('.')
        if decimal > 0:
            dtstring = dtstring[:decimal]
        return dtstring

    def _set_metadata(self):
        self.db['meta'] = '%s' % self.meta
        self.db['urlcount'] = '%s' % self.urlcount
        if hasattr(self, 'hits'):
            self.db['hits'] = '%s' % self.hits
        self.saved = False

    def set_metadata(self, maxcapacity=None, meta=None):
        'Allow the metadata to be set after initialization.'
        if maxcapacity:
            self.maxcapacity = maxcapacity
            saved = False
        if meta:
            self.meta = meta
            saved = False

    @classmethod
    def load(cls, filepath):
        try:
            db = anydbm.open(filepath, 'c')
        except anydbm.error, e:
            Log.logger.log(e)

        now = datetime.utcnow()
        now = datetime(now.year, now.month, now.day, now.hour, now.minute, now.second, tzinfo=None)
        try:
            from f3ds.framework.config import loadDefaultConfig
            maxcapacity = loadDefaultConfig().container_manager.maxcapacity
        except:
            maxcapacity = 500
        defaults = {'maxcapacity': maxcapacity, 'meta': '', 'urlcount': 0}

        for k in defaults:
            if k in db:
                defaults[k] = db[k]
        db.close()
        # Make sure types are as expected.
        defaults['maxcapacity'] = int(defaults['maxcapacity'])
        defaults['urlcount'] = int(defaults['urlcount'])
        defaults['meta'] = str(defaults['meta'])
        log = cls(defaults['maxcapacity'], meta, filepath)
        log.urlcount = defaults['urlcount']
        return log

