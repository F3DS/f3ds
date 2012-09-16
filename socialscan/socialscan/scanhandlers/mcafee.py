
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


mcafee = "C:/vscl/scan.exe"


scannervv_re = re.compile("^AV Engine version: (.*)$")
siginfo_re = re.compile("^Dat set version: (.*) created (.*)$")


def scan(filename):
    global cursiginfo
    global siginfotime

    process = subprocess.Popen([mcafee, filename], stdout=subprocess.PIPE)
    output = process.communicate()[0]

    malicious = False

    scannervv = "mcafee"
    sigversion = "undetermined"
    sigdate = datetime.datetime.now()

    for line in output.replace("\r\n","\n").split("\n"):
        split = line.split()
        if not len(split):
            continue
        elif split[0].lower().startswith("possibly") and int(split[-1]) != 0:
            malicious = True
            continue

        match = scannervv_re.match(line)
        if match:
            scannervv = "mcafee %s" % match.group(1)
            continue

        match = siginfo_re.match(line)
        if match:
            sigversion = match.group(1)
            sigdate = datetime.datetime.strptime(match.group(2), "%b %d %Y")

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

