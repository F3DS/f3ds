#!/usr/bin/python

"""
Collection of socialscan exceptions.

"""

__author__ = 'Henry Longmore and Matt Probst'
__version__ = '0.1'


class IncompleteScanError(Exception):
    pass


class TaintedScanError(Exception):
    pass


class ContainerFullError(Exception):
    """
    Exception raised when a container has no more room.
    """
    pass

class ZeroSizedDigestError(Exception):
    """
    Exception raised when a ScanDigest is written with 0 bytes.
    """
    pass

class DigestModifiedTimeError(Exception):
    """
    Exception raised when the mtime of a ScanDigest is older than expected.
    """
    pass
