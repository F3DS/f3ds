"""
Scanhandler for AVG Business Edition.
"""
# Standard Python modules
import os
import re
import subprocess
import tempfile
import traceback

from datetime import datetime, timedelta

# Our modules
from socialscan.util import SigInfo

dn = os.path.dirname
project_dir = os.path.realpath(dn(dn(dn(__file__))))
module_name = os.path.splitext(os.path.basename(__file__))[0]

cursiginfo = None
siginfotime = None
expiry = timedelta(hours=1)

scannervv_re = re.compile('Program version (.*?),')
siginfo_sigdate_re = re.compile('Virus Database: Version (.*) (.*)$')


def scan(filename):
    global cursiginfo
    global siginfotime
    filename = filename.replace('/', '\\')
    filepath = os.path.join(project_dir, filename)
    avg_be = '"C:\program files (x86)\\avg\\avg2012\\avgscanx" /scan="%s"' % filepath

    process = subprocess.Popen(avg_be, stdout=subprocess.PIPE)
    output = process.communicate()[0]
    lines = output.replace('\r\n', '\n').split('\n')

    malicious = False
    scanned = False
    scannervv = '%s' % module_name
    sigversion = "undetermined"
    sigdate = datetime.now()

    for line in lines:
        split = line.split()
        if not split:
            continue
        if line.startswith('Found infections') and int(split[-1]) != 0:
            malicious = True
            continue
        elif line.startswith('Objects scanned') and int(split[-1]) != 0:
            scanned = True
            continue
        match = scannervv_re.search(line)
        if match:
            scannervv = '%s %s' % (module_name, match.group(1))
            continue
        match = siginfo_sigdate_re.search(line)
        if match:
            sigversion = match.group(1)
            possible_sigdate = match.group(2)
            possible_sigdate = datetime.strptime(possible_sigdate, '%Y-%m-%d')
            if isinstance(possible_sigdate, datetime):
                sigdate = possible_sigdate
    if scanned:
        cursiginfo = SigInfo(scannervv, sigversion, sigdate)
        siginfotime = datetime.now()

    return malicious, cursiginfo


def getSigInfo():
    global cursiginfo
    global siginfotime
    now = datetime.now()
    if cursiginfo == None or now - siginfotime > expiry:
        i = None
        info = SigInfo('%s Unknown Version' % ''.join(module_name),
                       '%s Unknown Signature Version' % ''.join(module_name), now)
        with tempfile.NamedTemporaryFile() as tmp:
            try:
                r, i = scan(tmp.name)
            except:
                traceback.print_exc()
                pass
        cursiginfo = i if i else info
        siginfotime = now
    return cursiginfo

