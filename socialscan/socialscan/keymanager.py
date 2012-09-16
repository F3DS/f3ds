#!/usr/bin/python

"""
Manage public/private key generation, storage, retrieval, encryption, decryption, etc.
for use with socialscan.
"""

__author__ = 'Henry Longmore and Matt Probst'
__version__ = '0.1'

# Python standard library modules
import os
import sys

# 3rd party modules
import gnupg

# Our modules
from socialscan import util

global gpg
gpg = None


class GpgWrapper(object):
    
    def __init__(self, home='', name='', email=''):
        if not home:
            home = os.path.join('.', 'socialscan', 'gnupg')
        self.gnupghome = os.path.realpath(home)
        self.name_real = name if name else '%s' % (util.getIP())
        self.name_email = email if email else 'dev@sscan.us'
        self.gpg = gnupg.GPG(gnupghome=self.gnupghome)
        self.own_public_key_fingerprint = None
        self.own_public_ascii_armored_key = None
        self.own_private_key_fingerprint = None

    @property
    def own_fingerprint(self):
        'Return our own public key fingerprint, generate one if needed.'
        if not self.own_public_key_fingerprint:
            fingerprint = self.find_fingerprint(self.name_real, self.name_email)
            if not fingerprint:
                self.generate_own_key()
            else:
                self.own_public_key_fingerprint = fingerprint
        return self.own_public_key_fingerprint

    def generate_own_key(self):
        cmd = self.gpg.gen_key_input(name_real=self.name_real, name_email=self.name_email)
        key = self.gpg.gen_key(cmd)
        self.own_public_key_fingerprint = key.fingerprint
    
    def find_fingerprint(self, name='', email='', private=False):
        """
        Find a fingerprint by name if specified, or by email. Use "private=True"
        to search for private key fingerprints.
        """
        if not name and not email:
            return False
        keys = self.gpg.list_keys(private)
        for pk in keys:
            uids = pk['uids']
            token = name if name else '<%s>' % email
            if self.find_uid(token, uids):
                return pk['fingerprint']
        return ''

    def find_uid(self, token, uids):
        'Return uid containing token, if one exists.'
        token_parts = token.split()
        sys.stdout.flush()
        for uid in uids:
            parts = uid.split()
            possible = True
            for p in token_parts:
                if not p in parts:
                    possible = False
                    break
            if not possible:
                continue
            return uid
        return None

    def get_ascii_key(self, fingerprint='', name='', email='', private=False):
        if not fingerprint:
            fingerprint = self.find_fingerprint(name, email)
        ascii = self.gpg.export_keys(fingerprint, secret=private)
        return ascii

    @property
    def own_public_ascii_key(self):
        if not self.own_public_ascii_armored_key:
            key = self.get_ascii_key(self.own_fingerprint, self.name_real, self.name_email)
            if not key:
                self.generate_own_key()
                key = self.get_ascii_key(self.own_fingerprint, self.name_real, self.name_email)
            self.own_public_ascii_armored_key = key
        return self.own_public_ascii_armored_key

    @property
    def own_private_fingerprint(self):
        if not self.own_private_key_fingerprint:
            key = self.find_fingerprint(self.name_real, self.name_email, private=True)
            if not key:
                self.generate_own_key()
                key = self.find_fingerprint(self.name_real, self.name_email, private=True)
            self.own_private_key_fingerprint = key
        return self.own_private_key_fingerprint

    def own_private_ascii_key(self):
        key = self.get_ascii_key(self.own_private_fingerprint, private=True)
        return key

    def import_public_key(self, key):
        'Wrap self.gpg.import_keys'
        return self.gpg.import_keys(key)

    def encrypt(self, data, name='', email='', fingerprint=''):
        if not fingerprint:
            fingerprint = self.find_fingerprint(name, email)
        if not fingerprint:
            return 'public key not found for (%s, %s)' % (name, email)
        encrypted = self.gpg.encrypt(data, fingerprint, always_trust=True)
        return encrypted


if not gpg:
    # TODO: configure defaults, use them here.
    gpgdir = os.path.join('.', 'data', 'gpg')
    keydir = os.path.join(gpgdir, 'keys')
    name = 'Test Gpg User'
    email = 'testgpg@example.com'
    gpg = GpgWrapper(home=keydir, name=name, email=email)

