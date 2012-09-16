# Standard python modules
import os
import re
import subprocess
import tempfile

from datetime import datetime, timedelta

# 3rd party modules

# Our modules
from socialscan.scanhandlers import getMostRecent
from socialscan.util import SigInfo

module_name = os.path.splitext(os.path.basename(__file__))[0]
cursiginfo = None
siginfotime = None
expiry = timedelta(hours=1)

sigversion_re = re.compile("^# Virus database: (.*)$")
scan_status_re = re.compile("^(.*)OK$")
sigdate = None
sigversion = None


def scan(filename):
    global cursiginfo
    global siginfotime
    global sigversion
    global sigdate

    avast_params = ['--console', '--dontpanic', '--soundoff']
    avast_bin = r"C:\Program Files\AVAST Software\Avast Business\ashCmd.exe"
    avast = r"%s %s %s" % (avast_bin, ' '.join(avast_params), filename)

    process = subprocess.Popen(avast, stdout=subprocess.PIPE)
    output = process.communicate()[0]

    malicious = False
    scannervv = "avast"
    # TODO: get scanner version (available in UI or in exe properties)
    malicious_re = re.compile("%s\t(.*)" % filename.replace('\\','/'))

    for line in output.replace("\r\n","\n").split("\n"):
        # Is this file OK?
        match = scan_status_re.match(line)
        if match:
            break
        # Is this file malicious?
        # Use re.search to avoid having to know the full path
        match = malicious_re.search(line.replace('\\', '/'))
        if match:
            malicious = True
            break
    if not sigversion or not sigdate:
        sigversion, sigdate = getSigVersionAndDate()
    cursiginfo = SigInfo(scannervv, sigversion, sigdate)
    siginfotime = datetime.now()
    return malicious, cursiginfo


def isdir(name, dirname):
    #Filter out files, we only want to examine directories in avast_defs
    if os.path.isdir(os.path.realpath(os.path.join(dirname, name))):
        return True
    return False


def getSigVersionAndDate():
    avast_defs = r'C:\Program Files\AVAST Software\Avast Business\defs'
    most_recent_path, mtime = getMostRecent(avast_defs,
                                            searchstring=avast_defs,
                                            filterfunction=isdir)
    sigversion = os.path.basename(most_recent_path)
    sigdate = datetime.fromtimestamp(mtime)
    return sigversion, sigdate


def getSigInfo():
    global cursiginfo
    global siginfotime
    global sigversion
    global sigdate

    now = datetime.now()
    if cursiginfo == None or now - siginfotime > expiry:
        i = None
        sigversion, sigdate = getSigVersionAndDate()
        info = SigInfo('%s Unknown Version' % ''.join(module_name), '%s' % sigversion, sigdate)
        with tempfile.NamedTemporaryFile() as tmp:
            try:
                r, i = scan(tmp.name)
            except:
                pass
        cursiginfo = i if i else info
        siginfotime = now
    return cursiginfo

