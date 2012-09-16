"""
Profile mcafee scan handler.
Run tests by executing on the command line: python test_scanhandlers_mcafee.py
"""

import sys
import os
import cProfile

from os import path

# Modify the path to include the source under test
# Then we can run the unit tests from the test directory
# __file__ is <root>/test/test_scanhandlers_mcafee.py
pdn = path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util'),
          path.join(projectdir, 'test')]:
    if d not in sys.path:
        sys.path.append(d)

from socialscan.scanhandlers import mcafee

class McafeeProfile(object):
    malwares = []

    def __init__(self, malwares_dir):
        names = os.listdir(malwares_dir)
        for name in names:
            filepath = path.join(malwares_dir, name)
            self.malwares.append(filepath)
            if len(self.malwares) > 15:
                break

    def runScanner(self):
        "Profiles the mcafee scanhandler."
        for malware in self.malwares:
            print 'file:%s' % malware
            sys.stdout.flush()
            malicious, sigInfo = mcafee.scan(malware)
            print 'malicious:%s\nsigInfo:%s' % (malicious, str(sigInfo))
            sys.stdout.flush()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        malware_path = sys.argv[1]
    if len(sys.argv) > 2:
        logfile = sys.argv[2]
    else:
        logfile = path.join('.', 'mcafee_profiling.log')
    profiler = McafeeProfile(malware_path)
    cProfile.run('profiler.runScanner()', logfile)

## To view the stats, do
#import pstats
#p = pstats.Stats(logfile)

