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

