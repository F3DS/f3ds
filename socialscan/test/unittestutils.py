"""
Utilities to aid in unit testing.
"""

import datetime
import os
import sys

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scanhandlers_dummy.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'), 
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

def trim_microseconds(dt):
    return datetime.datetime(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)


def setConfigValue(setting, value, configfile='socialscan.defaults.config'):
    old_setting = None
    configpath = path.join(projectdir, configfile)
    lines = []
    with open(configpath, 'rU') as config:
        for line in config:
            if not line.startswith(setting):
                lines.append(line)
                continue
            parts = line.split('=')
            if len(parts) > 2:
                raise Exception('Expected lvalue = rvalue:\n%s->%s' % (line, parts))
            if not value:
                value = parts[1]
            (old_setting, parts[1]) = (parts[1], value)
            lines.append('='.join(parts))
    lines[:] = [line.replace('\r', '') for line in lines]
    with open(configpath, 'w+b') as config:
        config.writelines(lines)
    return old_setting
