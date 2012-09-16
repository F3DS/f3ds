#!/usr/bin/python

import hashlib
import os
import sys

# Modify the path to include the socialscan modules.
# __file__ is <socialscan source>/socialscan/sethash.py
pdn = os.path.dirname
projectdir = pdn(pdn(os.path.abspath(__file__)))
if projectdir not in sys.path:
    sys.path.append(projectdir)


from socialscan.config import loadDefaultConfig

global hasher

def set_hash_function(algorithm=''):
    'Choose a hashlib algorithm from those always supported. Default is sha256.'
    local_supported = {'md5': hashlib.md5,
                       'sha1': hashlib.sha1,
                       'sha224': hashlib.sha224,
                       'sha256': hashlib.sha256,
                       'sha384': hashlib.sha384,
                       'sha512': hashlib.sha512}
    try:
        if not algorithm:
            algorithm = loadDefaultConfig().sethash.algorithm
        return local_supported[algorithm]
    except:
        return local_supported['sha256']

hasher = set_hash_function()

