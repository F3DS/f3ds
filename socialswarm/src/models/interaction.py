"""
Model interactions for social swarm.

Authored by Henry Longmore.
"""

# Standard python library imports
import time

from datetime import datetime, timedelta
from email.utils import parsedate_tz

# 3rd party imports

# Our code
from models import TimeFormatNotRecognized

class Interaction(object):

    time_formats = {'slashes': {'us': '%m/%d/%Y %H:%M:%S', 'nonus': '%d/%m/%Y %H:%M:%S',
                                'utc_tz': '%Y/%m/%dT%H:%M:%S%z'},
                    'dashes': {'us': '%m-%d-%Y %H:%M:%S', 'nonus': '%d-%m-%Y %H:%M:%S',
                               'utc_tz': '%Y-%m-%dT%H:%M:%S%z'},
                    'spaces': {'us': '%m %d %Y %H:%M:%S', 'nonus': '%d %m %Y %H:%M:%S',
                               'utc_tz': '%Y %m %dT%H:%M:%S%z'}}

    def __init__(self, formatted_dtstamp='', actor='', direct_object=''):
        super(Interaction, self).__init__()
        if formatted_dtstamp:
            self.set_dtstamp(formatted_dtstamp)
        if direct_object:
            self.set_direct_object(direct_object)
        if actor:
            self.set_actor(actor)

    def set_dtstamp(self, s):
        probable_format = ''
        if s.find('/') > 0:
            probable_format = 'slashes'
        elif s.find('-') > 0:
            probable_format = 'dashes'
        else:
            probable_format = 'spaces'
        t = None
        utc_offset = 0
        for subformat in self.time_formats[probable_format]:
            try:
                t = datetime.strptime(s, self.time_formats[probable_format][subformat])
            except ValueError, e:
                msg = '%s' % (e)
                if subformat == 'utc_tz' and msg.find("'z' is a bad directive in format ") >= 0:
                    try:
                        dts, utc_offset = (s[:-5], s[-5:])
                        format = self.time_formats[probable_format][subformat][:-2]
                        t = datetime.strptime(dts, format)
                    except:
                        pass
            if t:
                break
        if not t:
            raise TimeFormatNotRecognized
        self.dtstamp = t
        if utc_offset:
            try:
                utco_seconds = int('%s%s' % (utc_offset[0], (60*int(utc_offset[-2:]) + 3600*int(utc_offset[1:-2]))))
                self.dtstamp = self.dtstamp + timedelta(seconds=utco_seconds)
            except:
                pass

    def set_actor(self, actor):
        'from should be unique id (sha1 hash?)'
        self.actor = actor

    def set_direct_object(self, direct_object):
        'to should be unique id (sha1 hash?)'
        self.direct_object = direct_object

    def __cmp__(self, other):
        if self.dtstamp < other.dtstamp:
            return -1
        elif self.dtstamp == other.dtstamp:
            return 0
        else:
            return 1

    def reciprocal(self, other):
        if not self.actor == other.direct_object:
            return False
        if not self.direct_object == other.actor:
            return False
        return True
