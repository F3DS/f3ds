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
