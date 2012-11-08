#!/usr/bin/python

"""
Utilities used by various parts of socialscan.
"""

__author__ = 'Jun Park, Matt Probst, Henry Longmore'
__version__ = '0.1'

import collections
import os
import re
import subprocess
import xmlrpclib


from f3ds.framework.sethash import hasher


def delta_seconds(td):
    """
    Determine the total seconds that have elapsed in a datetime.timedelta.
    """
    return float(td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / float(10**6)


class UrlObject(object):
    """
    Represents a url and the file at the url.

    @ivar url: the url to represent.
    @type url: C{str}

    @ivar filesize: the filesize in bytes of the file at the url.
    @type filesize: C{int}

    @ivar hash: hexdigest of a hash of the content of the file at the url. May be C{None}.
    @type hash: C{str} or C{None}
    """
    def __init__(self, url, filesize, nonce='', hash='', is_hashed=False):
        """
        @param url: the url to represent.
        @param filesize: the filesize in bytes of the file at the url.
        @param hash: optional; if provided, the hexdigest of a hash of the file at the url.
        """
        self.hash = ''
        self.filehash = ''
        self.filesize = filesize 
        self.objecthash = hash if hash and isinstance(hash, basestring) else ''
        self.nonce = nonce
        noncehash = self._makehash(self.nonce)
        self.empty_contenthash = noncehash.hexdigest()
        noncehash.update(str(self.filesize))
        self.empty_url = noncehash.hexdigest()
        self.prehashed = False
        if is_hashed:
            self.hash = url
            self.filehash = hash
            self.plain = ''
            self.objecthash = ''
            self.prehashed = True
        else:
            self.plain = url if url and isinstance(url, basestring) else ''
            trash = self.url if self.plain else ''
            refuse = self.contenthash if self.objecthash else ''

    @property 
    def url(self):
        if not self.hash:
            #self.hash = self._makehash(self.nonce, self.plain, str(self.filesize))
            self.hash = self._makehash(self.plain)
            #self.plain = ''
        return self._extracthash(self.hash, self.empty_url)

    @property
    def contenthash(self):
        if not self.filehash:
            #self.filehash = self._makehash(self.nonce, self.objecthash)
            self.filehash = self._makehash(self.objecthash)
            #self.objecthash = ''
        return self._extracthash(self.filehash, self.empty_contenthash)

    def _makehash(self, *values):
        hash = hasher()
        for value in values:
            hash.update(value)
        return hash

    def _extracthash(self, hashobj, empty):
        try:
            digest = hashobj.hexdigest()
        except AttributeError:
            return hashobj
        else:
            #if digest == empty:
            #    return ''
            return digest

    def __repr__(self):
        repr_string = 'UrlObject(%r, %r' % (self.url, self.filesize)
        if self.nonce:
            repr_string += ', nonce=%r' % (self.nonce)
        if self.hash:
            repr_string += ', hash=%r' % (self.filehash)
        repr_string += ', is_hashed=True)' 
        return repr_string

    def __str__(self):
        return '(%s, %s)' % (self.url, self.contenthash)

    def __nonzero__(self):
        if not self.url and not self.contenthash:
            return False
        return True

    def __eq__(self, other):
        'Two UrlObjects are equal if they have the same url, contenthash, and nonce.'
        if other == None: return False
        if self.url != other.url: return False
        if self.contenthash != other.contenthash: return False
        if self.nonce != other.nonce: return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


class TimeoutedTransport(xmlrpclib.Transport):
    """
    Timeouted xmlrpclib transport used in model.Peer.transport.
    """
    timeout = 10

    def set_timeout(self, timeout):
        self.timeout = timeout

    def make_connection(self, host):
        """
        Slightly modified version of the same method from the original xmlrpclib.Transport
        Added timeout to httpconnection.
        """
        if self._connection and host == self._connection[0]:
            return self._connection[1]
        chost, self._extra_headers, x509 = self.get_host_info(host)
        self._connection = host, httplib.HTTPConnection(chost, timeout=self.timeout)
        return self._connection[1]


class WeightedAverager(object):
    """
    Class used to average a series of values, with different weights on each value. The
    influcene of each value on the average is determined by the weight, where the weight
    is multiplied by the value to determine the influence.
    """
    def __init__(self):
        self.elements = []
        self.totalweight = 0.0
        self.total = 0.0

    @property
    def average(self):
        """
        The current average.
        """
        if self.totalweight == 0.0:
            return 0.0
        return self.total / self.totalweight

    def add(self, item, weight=1.0):
        """
        Add an item to the average.
        @param item: value to be added to the average
        @type item: C{float()}able

        @param weight: influence of the value on the average
        @type weight: C{float}
        """
        self.elements.append((item, weight))
        self.total += weight * float(item)
        self.totalweight += weight

################## Decorators ##################

def cached(method, cache_name="_{0}_cache"):
    """
    Decorator to cache the result of a method in the instance the method is called on,
    and return the cached value for susequent calls of the method. Does not work on
    non-method functions.

    This is a very simple memoizing decorator - it completely ignores arguments to the
    method to determine what cache to use.

    @param method: function to decorate.
    @type method: C{function}

    @param cache_name: the name of the attribute to cache the method result on.
    @type cache_name: C{str}
    """
    cache_name = cache_name.format(method.__name__)

    @functools.wraps(method)
    def cacher(self, *args, **kwargs):
        try:
            return getattr(self, cache_name)
        except AttributeError:
            result = method(self, *args, **kwargs)
            setattr(self, cache_name, result)
            return result

    return cacher

def cached_as(name):
    """
    Wraps @cached decorator to allow use of the cache_name argument. Returns the actual decorator.
    @param name: name to pass to cached()
    @type name: C{str}
    """
    def decorate(method):
        return cached(method, name)
    return decorate


def class_name(class_instance):
    """
    'Decorator' to get the name of a class from an instance of the class.
    """
    rv = '%s' % class_instance.__class__
    rv = rv.strip('<>')
    rv = rv.split('.')[-1]
    rv = rv.strip("'")
    return rv

################ End Decorators ################

class TimeMeasurer(object):
    """
    Measure how long a piece of code takes to run.
    usage:

    with TimeMeasurer() as time_measurement:
        #run your code
    time_it_took = time_measurement.total
    """
    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, type, value, traceback):
        self.end = time.time()
        self.total = self.end - self.start


lin_addr_re=re.compile("inet addr: ?([0-9.]+) ")
win_addr_re=re.compile("IPv4 Address[ .]*: ?([0-9.]+)[\n\r]*$")
def getIP():
    """
    Determine the IP of a network interface on the local machine.
    Returns None if no IP was found. Should work on both windows and linux.
    """

    if os.name == "posix":
        args = ["ifconfig", interface]
        child = subprocess.Popen(args, stdout=subprocess.PIPE)
        output, error = child.communicate()

        match = lin_addr_re.search(output)
        if match:
            return match.group(1)
    elif os.name == "nt":
        args = ["ipconfig"]
        child = subprocess.Popen(args, stdout=subprocess.PIPE)
        for line in child.stdout:
            match = win_addr_re.search(line)
            if match:
                return match.group(1)

class Present(collections.namedtuple("Present", ["isconfident", "ispresent"])):
    """
    Container for status constants regarding the presence or absence of an attribute of
    interest. Evaluates to True when C{isconfident} is true.
    Create an instance with Present(isconfident, ispresent).

    @cvar absent: isconfident=True, ispresent=False
    @type absent: C{Present}

    @cvar possibly_absent: isconfident=False, ispresent=False
    @type possibly_absent: C{Present}

    @cvar possibly_present: isconfident=False, ispresent=True
    @type possibly_present: C{Present}

    @cvar present: isconfident=True, ispresent=True
    @type present: C{Present}

    @ivar isconfident: Indicates whether the system is confident in the ispresent value.
    @type isconfident: C{bool}

    @ivar ispresent: Indicates whether the item of interest is present or not.
    @type ispresent: C{bool}
    """
    def __nonzero__(self):
        return self.isconfident

Present.absent = Present(True, False)
Present.possibly_absent = Present(False, False)
Present.possibly_present = Present(False, True)
Present.present = Present(True, True)

