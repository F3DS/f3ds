
import subprocess
import re
from socialscan.util import SigInfo
import datetime
import os
import tempfile
from datetime import date
dt = date.today()


module_name = os.path.splitext(os.path.basename(__file__))[0]
cursiginfo = None
siginfotime = None
expiry = datetime.timedelta(hours=1)

#C:\Program Files (x86)\Symantec\Symantec Endpoint Protection>doscan /scanfile <full filename> 
#Results go to text doc at - C:\ProgramData\Symantec\Symantec Endpoint Protection\12.1.1000.157.105\Data\Logs\AV\<date>
endpoint = r"C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\doscan"
endpointLog = r"C:\ProgramData\Symantec\Symantec Endpoint Protection\12.1.1000.157.105\Data\Logs\AV\%s.Log" % dt.strftime("%m%d%Y")

# Log file column header discriptions can be found: http://www.symantec.com/business/support/index?page=content&id=TECH100099
# Sample infected log entry:
#2A000C043A25,3,2,1,IP-0AD233EF,Administrator,,,,,,,16777216,"Scan started on selected drives and folders and all extensions.",1326341812,,0,,,,,0,,,,,,,,,,,{3AAC7133-2AA9-4AFC-B5C5-630640FDC09A},,,,WORKGROUP,12:31:39:09:2C:01,12.1.1000.157,,,,,,,,,,,,,,,,0,,,,,,,,,,,,,,,,,,,
#2A000C05001C,51,1,1,IP-0AD233EF,Administrator,Trojan.Pidief,c:\users\administrator\documents\touch5.txt,5,1,19,256,33554436,"",1326341812,,0,101	{0916EFF6-2FD7-41C3-AAFF-6BF7F3E95D92}	1	2				Trojan.Pidief	1;0	0	0		0,0,39861,0,0,0,,,0,,0,0,4,0,,{3AAC7133-2AA9-4AFC-B5C5-630640FDC09A},,,,WORKGROUP,12:31:39:09:2C:01,12.1.1000.157,,,,,,,,,,,,,,,,999,,cca1edaa-88eb-44dc-8c90-4078f733e515,0,,501		134928	2	000A5F646B4C678241F5B309BCF21757FEB8CE285DFECA9EE9EB61476963A1A5		127	127		0	0	0	touch5.txt	1,,1,0,1,127,0,0,0,,,0,127,0,
#2A000C05001D,2,2,1,IP-0AD233EF,Administrator,,,,,,,16777216,"Scan Complete:  Risks: 1   Scanned: 2   Files/Folders/Drives Omitted: 0 Trusted Files Skipped: 0",1326341812,,0,1:1:2:0:0,,,,0,,,,,,,,,,,{3AAC7133-2AA9-4AFC-B5C5-630640FDC09A},,,,WORKGROUP,12:31:39:09:2C:01,12.1.1000.157,,,,,,,,,,,,,,,,0,,,,,,,,,,,,,,,,,,,
def analyizeEndPointLog(filename):
    log = open(endpointLog,"r")
    entries = log.readlines();
    # Iterate from the bottom of the list
    entries.reverse()
    if "Scan Complete:  Risks: 0" in entries[0]:
        return [False,0,0]
    else:
        for e in entries:
            if filename.lower() in e:
                es = e.split(',')
                scanner_ver = es[38] + ':' + es[6]
                sig_id = es[19]
                return [True, sig_id, scanner_ver]
        return [False,0,0]


def scan(filename):
    global cursiginfo
    global siginfotime

    process = subprocess.Popen([endpoint, filename], stdout=subprocess.PIPE)
    process.wait()

    malicious = False

    scannervv = "endpoint"
    sigversion = "undetermined"
    sigdate = datetime.datetime.now()

    [malicious, sigversion, scannervv ] = analyizeEndPointLog(filename)

    if malicious:
        cursiginfo = SigInfo("endpoint %s" % scannervv, sigversion, sigdate)
    else:
        cursiginfo = SigInfo("endpoint", sigversion, sigdate)

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

