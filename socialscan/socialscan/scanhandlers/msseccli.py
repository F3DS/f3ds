# Standard python library modules
import codecs
import os
import re
import subprocess
import tempfile

from datetime import datetime, timedelta

# Our modules
from socialscan.scanhandlers import getMostRecent, getSigDate
from socialscan.util import SigInfo

dn = os.path.dirname
project_dir = os.path.realpath(dn(dn(dn(__file__))))
module_name = os.path.splitext(os.path.basename(__file__))[0]

cursiginfo = None
siginfotime = None
expiry = timedelta(hours=1)

msseccli_data_dir = r'C:\ProgramData\Microsoft\Microsoft Antimalware\Support'
msseccli_update_dir = r'C:\ProgramData\Microsoft\Microsoft Antimalware\Definition Updates'
msseccli_bin_dir = ''
msseccli_bin = ''


def get_binary():
    global msseccli_bin
    global msseccli_bin_dir
    filename = 'MpCmdRun'
    if not msseccli_bin_dir:
        base = r'C:\Program Files\Microsoft Security Client'
        for root, dirs, files in os.walk(base):
            bin = [f for f in files if f.lower().find(filename.lower()) == 0]
            if bin:
                msseccli_bin_dir = root
                break
    msseccli_bin = os.path.join(msseccli_bin_dir, filename)


def analyzeLog(filename):
    sigversion = None
    scannervv = None
    file_confirm = False
    malicious = False
    line_count = 0
    most_recent, mtime = getMostRecent(msseccli_data_dir, 'MPDetection')
    # Look for signature info
    if most_recent:
        lines = []
        with codecs.open(most_recent, 'r', 'utf-16le') as data:
            lines = data.readlines()
        lines.reverse()
        for line in lines:
            parts = line.split()
            if not scannervv and 'Version:' in parts:
                scannervv = '%s %s' % (module_name, parts[3])
                sigversion = parts[11]
            elif not file_confirm and 'DETECTION' in parts:
                if parts[3].find(filename) > len('file:'):
                    malicious = True
                    file_confirm = True
            line_count += 1
            if line_count > 1000:
                break
            if scannervv and sigversion and file_confirm:
                break
    sigdate = getSigDate(msseccli_update_dir)
    return [malicious, scannervv, sigversion, sigdate]


def scan(filename):
    global cursiginfo
    global siginfotime
    filename = filename.replace('/', '\\')
    filepath = os.path.join(project_dir, filename)
    if not msseccli_bin:
        get_binary()
    # subprocess.Popen will treat a string surrounded by double quotes as a single
    # argument regardless of white space contained within.
    msseccli = [msseccli_bin, '-Scan', '-Scantype', '3', '-Trace', '-Grouping', '0x2',
                '-Level', '0x10', '-GetFiles', '-DisableRemediation', '-File', "%s" % filepath]
    process = subprocess.Popen(msseccli, stdout=subprocess.PIPE)
    process.wait()
    output = process.communicate()[0]

    malicious = False
    scannervv = "msseccli"
    sigversion = "undetermined"
    sigdate = datetime.now()
    [malicious, scannervv, sigversion, sigdate] = analyzeLog(filename)
    malicious = process.returncode != 0 or malicious
    cursiginfo = SigInfo(scannervv, sigversion, sigdate)
    siginfotime = datetime.now()
    return malicious, cursiginfo


def getSigInfo():
    global cursiginfo
    global siginfotime
    now = datetime.now()
    if cursiginfo == None or now - siginfotime > expiry:
        i = None
        garbage, scanver, sigver, sigdate = analyzeLog('')
        info = SigInfo(scanver, sigver, sigdate)
        with tempfile.NamedTemporaryFile() as tmp:
            try:
                r, i = scan(tmp.name)
            except:
                # We already got a decent default with getSigInfoFromDetectionLog
                pass
        cursiginfo = i if i else info
        siginfotime = now
    return cursiginfo

# Find the binary when loading instead of scanning to reduce impact on latency data
get_binary()
