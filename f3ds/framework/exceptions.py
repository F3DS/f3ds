#!/usr/bin/python

"""
Collection of f3ds framework exceptions.

"""

__author__ = 'Henry Longmore and Matt Probst'
__version__ = '0.1'


class ContainerFullError(Exception):
    """
    Exception raised when a container has no more room.
    """
    pass

class ZeroSizedDigestError(Exception):
    """
    Exception raised when a Digest is written with 0 bytes.
    """
    pass

class DigestModifiedTimeError(Exception):
    """
    Exception raised when the mtime of a Digest is older than expected.
    """
    pass
