"""
Scanhandler for ClamWin AV
"""
# Standard python modules
import os
import re
import subprocess
import tempfile

from datetime import datetime, timedelta

# 3rd party modules

# Our modules
from socialscan.scanhandlers import getSigDate
from socialscan.util import SigInfo


module_name = os.path.splitext(os.path.basename(__file__))[0]
cursiginfo = None
siginfotime = None
expiry = timedelta(hours=1)
sigdate = None
sigversion = None

scannervv_re = re.compile("^Engine version: (.*)$")

clamwin_bin = r'C:\Program Files (x86)\ClamWin\bin\clamscan.exe'
clamwin_db = r'C:\ProgramData\.clamwin\db'

def scan(filename):
    global cursiginfo
    global siginfotime
    global sigdate
    global sigversion

    clamwin_cmd = '"%s" --database="%s" "%s"' % (clamwin_bin, clamwin_db, filename)
    process = subprocess.Popen(clamwin_cmd, stdout=subprocess.PIPE)
    output = process.communicate()[0]

    malicious = False
    scannervv = "clamwin"
    for line in output.replace("\r\n","\n").split("\n"):
        split = line.split()
        if not split:
            continue
        elif line.lower().startswith("infected files") and int(split[-1]) != 0:
            malicious = True
            continue
        match = scannervv_re.match(line)
        if match:
            scannervv = "clamwin %s" % match.group(1)
            continue
    cursiginfo = SigInfo(scannervv, sigversion, sigdate)
    siginfotime = datetime.now()
    return malicious, cursiginfo


def getSigVersion():
    'Parse the update log file for signature version info'
    def extract_version(line):
        'This needs to be done for each version info portion'
        version = 0
        version_re = re.compile('version: (.*?),')
        match = version_re.search(line)
        if match:
            version = match.group(1)
        return version
    # Main function
    main_cvd = 0
    daily_cld = 0
    bytecode_cld = 0
    update_log = os.path.join(clamwin_db, '..', 'log', 'ClamUpdateLog.txt')
    try:
        ul = open(update_log, 'rU')
        lines = ul.readlines()
        lines.reverse()
        for line in lines:
            if line.startswith('main.cvd'):
                main_cvd = extract_version(line)
            elif line.startswith('daily.cld'):
                daily_cld = extract_version(line)
            elif line.startswith('bytecode.cld'):
                bytecode_cld = extract_version(line)
            if main_cvd and daily_cld and bytecode_cld:
                break
    except Exception, e:
        pass
    return '%s.%s.%s' % (main_cvd, daily_cld, bytecode_cld)


def getSigInfo():
    global cursiginfo
    global siginfotime
    global sigdate
    global sigversion

    now = datetime.now()
    if cursiginfo == None or now - siginfotime > expiry:
        i = None
        sigdate = getSigDate(clamwin_db)
        sigversion = getSigVersion()
        info = SigInfo('%s Unknown Version' % ''.join(module_name), sigversion, sigdate)
        with tempfile.NamedTemporaryFile() as tmp:
            try:
                r, i = scan(tmp.name)
            except:
                pass
        cursiginfo = i if i else info
        siginfotime = now
    return cursiginfo

