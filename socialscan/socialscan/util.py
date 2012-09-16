#!/usr/bin/python

"""
Utilities used by various parts of socialscan.
"""

__author__ = 'Jun Park and Matt Probst'
__version__ = '0.1'

import time
import sys
import os
from datetime import datetime
import subprocess
import re
import collections
import xmlrpclib
import httplib
import functools

class SigInfo(collections.namedtuple("SigInfo", ["scannervv", "sigversion", "sigdate"])):
    """
    Scanner signature information container.
    @ivar scannervv: The name of the scanner. Is usually provided as a constant in the scanhandler.
    @type scannervv: C{str}
    @ivar sigversion: The version of the signatures currently in use by the scanner.
    @type sigversion: C{str}
    @ivar sigdate: The date which the signatures currently in use by the scanner were updated
    @type sigdate: C{datetime.datetime}
    """
    def __eq__(self, other):
        if other == None: return False
        if self.scannervv != other.scannervv: return False
        if self.sigversion != other.sigversion: return False
        if self.sigdate != other.sigdate:
            s = self.sigdate
            o = other.sigdate
            ssd = datetime(s.year, s.month, s.day, s.hour, s.minute, s.second)
            osd = datetime(o.year, o.month, o.day, o.hour, o.minute, o.second)
            if ssd != osd:
                return False
        return True


def delta_seconds(td):
    """
    Determine the total seconds that have elapsed in a datetime.timedelta.
    """
    return float(td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / float(10**6)


def update_counts(scanned_count, malicious_count, scan, days=10):
    """ Update counts for number of scans found and number of malicious scans found. """
    if (datetime.now() - scan.sigdate).days <= days:
        scanned_count += 1
        if scan.safety == Safety.malicious:
            malicious_count += 1
    return scanned_count, malicious_count


def paranoid_update_counts(scans, days=2):
    scanned = 0
    malicious = 0
    scanners_with_results = {}
    # Aggregate scans by scanner.
    for scan in scans:
        recent_scan = (datetime.now() - scan.sigdate).days <= days
        scanner = scan.scannervv
        if recent_scan:
            if scanner not in scanners_with_results or scan.safety == Safety.malicious:
                scanners_with_results[scanner] = scan
    # Get count of results by scanner
    scanned = len(scanners_with_results)
    # Get count of malicious reports, using first scan for each scanner
    for scanner in scanners_with_results:
        scan = scanners_with_results[scanner]
        if scan.safety == Safety.malicious:
            malicious += 1
    return scanned, malicious


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


class Safety(collections.namedtuple("Safety", ["isconfident", "ismalicious"])):
    """
    Container for safety status constants. Evaluates to True when C{isconfident} is true.
    Create an instance with Safety(isconfident, ismalicious).

    @cvar benign: isconfident=True, ismalicious=False
    @type benign: C{Safety}

    @cvar possibly_benign: isconfident=False, ismalicious=False
    @type possibly_benign: C{Safety}

    @cvar possibly_malicious: isconfident=False, ismalicious=True
    @type possibly_malicious: C{Safety}

    @cvar malicious: isconfident=True, ismalicious=True
    @type malicious: C{Safety}


    @ivar isconfident: Indicates whether the safety represented is confident in the ismalicious value.
    @type isconfident: C{bool}

    @ivar ismalicious: Indicates whether the safety represented is malicious or not.
    @type ismalicious: C{bool}
    """
    def __nonzero__(self):
        return self.isconfident

Safety.benign = Safety(True, False)
Safety.possibly_benign = Safety(False, False)
Safety.possibly_malicious = Safety(False, True)
Safety.malicious = Safety(True, True)


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

