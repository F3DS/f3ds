import datetime
import time

from socialscan.util import SigInfo


def getSigInfo():
    try:
        reader = open("data/dummy")
        name, version, date = [x for x in reader.readlines() if x]
    except IOError, e:
        if e.errno == 2:
            thetuple = ("data/dummy", "1.0", str(time.time()))
            name, version, date = thetuple
            open("data/dummy", "w").write("\n".join(thetuple))

    return SigInfo(name.replace("\n", ""), version.replace("\n", ""),
                   datetime.datetime.fromtimestamp(float(date)))

def scan(filename):
    f = open(filename, "rb")
    for line in f:
        if line.startswith("evil"):
            return True, getSigInfo()
    return False, getSigInfo()
