"""
Scanhandler for Kaspersky Small Office Security
"""

# Standard Python modules
import os
import re
import subprocess
import tempfile

from datetime import datetime, timedelta
from os import path
# 3rd party modules

# Our modules
from socialscan.scanhandlers import getMostRecent
from socialscan.util import SigInfo

dn = os.path.dirname
project_dir = os.path.realpath(dn(dn(dn(__file__))))
module_name = os.path.splitext(os.path.basename(__file__))[0]

info = SigInfo("kaspersky", "signature-version", datetime.fromtimestamp(1323576595))

kaspersky_bin = "C:/Program Files (x86)/Kaspersky Lab/Kaspersky Small Office Security/avp.exe"
kaspersky_data = "C:/ProgramData/Kaspersky Lab/AVP9/Data"
cursiginfo = None
siginfotime = None
expiry = timedelta(hours=1)


def scan(filename):
    global cursiginfo
    filename = filename.replace('/', '\\')
    filepath = os.path.join(project_dir, filename)

    process = subprocess.Popen([kaspersky_bin, 'scan', '/i0', filepath], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    lines = output.replace('\r', '').split('\n')

    malicious = False
    for line in lines:
        split = line.split()
        if not len(split):
            continue
        # Yes, they misspelled "Threats" as "Treats" in their output.
        if split[1] in ["Total", "Detected", "Suspicions:", "Treats"] and int(split[-1]) > 0:
            malicious = True
            break
    if not cursiginfo:
        getSigInfo()
    return malicious, cursiginfo


def getProductVersion():
    scanner_version = '%s unknown version' % module_name
    process = subprocess.Popen([kaspersky_bin, 'help'], stdout=subprocess.PIPE)
    output = process.communicate()[0]
    lines = output.replace('\r', '').split('\n')

    for line in lines:
        parts = line.split()
        if parts[0] == 'Kaspersky' and parts[1] == 'Anti-Virus':
            scanner_version = '%s %s' % (module_name, parts[3])
            break
    return scanner_version


def getSigVersionDate():
    """
    Use the update file to get the signature date and what as best I can tell is
    the signature version.
    """
    xmlish_filter = lambda x, y: x.lower().startswith('u') and x.lower().endswith(y)
    filepath, mtime = getMostRecent(kaspersky_data, 'g.xml', xmlish_filter)
    barename = path.splitext(path.basename(filepath))[0]
    sigversion = barename[1:-1]
    sigdate = getSigDate(filepath)
    return [sigversion, sigdate]


def getSigDate(filepath):
    update_date_re = re.compile('UpdateDate\s*=\s*"(.*?)"')
    sigdate = datetime.now()
    with open(filepath, 'rU') as input:
        for line in input:
            match = update_date_re.search(line)
            if match:
                possible_sigdate = match.group(1)
                possible_sigdate = datetime.strptime(possible_sigdate, '%d%m%Y %H%M')
                if isinstance(possible_sigdate, datetime):
                    sigdate = possible_sigdate
                    break
    return sigdate


def getSigInfo():
    'Gather the info we want from various sources.'
    global cursiginfo
    global siginfotime
    now = datetime.utcnow()
    if cursiginfo == None or now - siginfotime > expiry:
        # Unlike other scanners, we get no information from doing a scan.
        # Instead we run the help command, and parse an update xml log file.
        scannervv = getProductVersion()
        sigversion, sigdate = getSigVersionDate()
        cursiginfo = SigInfo('%s' % scannervv, '%s' % sigversion, sigdate)
        siginfotime = now
    return cursiginfo

