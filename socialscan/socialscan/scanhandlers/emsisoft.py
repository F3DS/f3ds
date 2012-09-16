"""
interface to http://www.emsisoft.de/en/software/cmd/
"""

import subprocess
import re
from socialscan.util import SigInfo
import datetime
import os
import tempfile


module_name = os.path.splitext(os.path.basename(__file__))[0]
cursiginfo = None
siginfotime = None
expiry = datetime.timedelta(hours=1)


emisoft = "C:/Program Files (x86)/Emsisoft Anti-Malware/a2cmd.exe"

scannervv_re = re.compile("^(Emsisoft Commandline Scanner v.*)$")
siginfo_re = re.compile("^Last update: (.*)$")


def scan(filename):
    global cursiginfo
    global siginfotime

    result = subprocess.Popen([emisoft, "/a", "/s", "/f=%s" % filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    infoundblock = False
    malicious = False


    scannervv = "emsisoft"
    sigversion = "undetermined"
    sigdate = datetime.datetime.fromtimestamp(0)


    for line in result.stdout:
        if not infoundblock:
            if line.strip().lower() == "found":
                infoundblock = True
            match = scannervv_re.match(line)
            if match:
                scannervv = match.group(1)
                continue
            match = siginfo_re.match(line)
            if match:
                sigversion = match.group(1)
                sigdate = datetime.datetime.strptime(sigversion, "%m/%d/%Y %I:%M:%S %p")
        elif infoundblock:
            split = line.split()
            if not len(split):
                continue
            if split[0] in ["Objects:", "Traces:", "Cookies:", "Processes:"] and int(split[1]) > 0:
                malicious = True

    cursiginfo = SigInfo(scannervv, sigversion, sigdate)
    siginfotime = datetime.datetime.now()

    return malicious, cursiginfo



def getSigInfo():
    global cursiginfo
    global siginfotime
    now = datetime.datetime.now()
    if cursiginfo == None or now - siginfotime > expiry:
        i = None
        info = SigInfo('%s Unknown Version' % ''.join(module_name),
                       '%s Unknown Signature Version' % ''.join(module_name), now)
        with tempfile.NamedTemporaryFile() as tmp:
            try:
                r, i = scan(tmp.name)
            except:
                pass
        cursiginfo = i if i else info
        siginfotime = now
    return cursiginfo

