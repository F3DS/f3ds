"""
Avira scanhandler
"""
# Python standard library imports
import re
import subprocess
import os
import tempfile

from datetime import datetime, timedelta

# 3rd party imports

# Our imports
from socialscan.scanhandlers import getSigDate
from socialscan.util import SigInfo


module_name = os.path.splitext(os.path.basename(__file__))[0]
cursiginfo = None
siginfotime = None
expiry = timedelta(hours=1)

avira_dir = os.path.join('C:' + os.sep, 'Program Files (x86)', 'Avira', 'AntiVir Desktop')
avira_bin = os.path.join(avira_dir, 'scancl')

scannervv_re = re.compile("Avira / Windows Version (.*)")
engineversion_re = re.compile("engine set: (.*)")
vdfversion_re = re.compile("VDF Version: (.*)")

sigdate = getSigDate(avira_dir, search='.vdf')

def scan(filename):
    global cursiginfo
    global siginfotime

    process = subprocess.Popen([avira_bin, filename], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    lines = output.replace('\r\n', '\n').split('\n')

    malicious = False

    for line in lines:
        split = line.split()
        if not split:
            continue
        name = split[0].replace('.', '')
        if name in ['Infected', 'Warnings', 'Suspicious', 'Infections'] and int(split[-1]) > 0:
            malicious = True
            break
    return malicious, cursiginfo


def getVersionInfo():
    global cursiginfo
    global siginfotime

    process = subprocess.Popen([avira_bin, '--version'], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    lines = output.replace('\r\n', '\n').split('\n')
    scannervv = '%s' % (module_name)
    engineversion = 'Unknown engine version'
    vdfversion = 'Unknown signature version'

    for line in lines:
        match = scannervv_re.search(line)
        if match:
            scannervv = '%s %s' % (module_name, match.group(1))
            continue
        match = engineversion_re.search(line)
        if match:
            engineversion = match.group(1)
            continue
        match = vdfversion_re.search(line)
        if match:
            vdfversion = match.group(1)
    sigversion = '%s (engine: %s)' % (vdfversion.strip(), engineversion.strip())
    return scannervv, sigversion


def getSigInfo():
    global cursiginfo
    global siginfotime
    now = datetime.now()
    if cursiginfo == None or now - siginfotime > expiry:
        scannervv, sigversion = getVersionInfo()
        sigdate = getSigDate(avira_dir, search='.vdf')
        cursiginfo = SigInfo(scannervv, sigversion, sigdate)
        siginfotime = now
    return cursiginfo

