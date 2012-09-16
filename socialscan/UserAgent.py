#UserAgent.py
import sys
import urllib2
import os
import time
import random

from os import path
from time import sleep

proxy_handler=urllib2.ProxyHandler({'http':'http://127.0.0.1:3128'})
opener=urllib2.build_opener(proxy_handler)

def retrieve(urlfile, nap=False, minnap=200, maxnap=800, napscale=1000.0, interactive=False):
    global opener
    f=open(urlfile, 'r').readlines()
    progress_log = path.join('..', 'Progress.txt')
    fo=open(progress_log, 'w')
    for line in f:
        if not line.strip():
            continue
        retry = True
        quit = False
        while retry:
            try:
                opener.open(line)
            except (urllib2.HTTPError, urllib2.URLError):
                # 503 Service unavailable error, Forcibly closed connection error
                print 'Rebuilding opener'
                opener=urllib2.build_opener(proxy_handler)
            if nap:
                sleep(random.randrange(minnap, maxnap)/float(napscale))
            if interactive:
                choice = raw_input('Press enter to proceed to next url, q to quit.')
                choice = choice.strip().lower()
                if choice == 'q':
                    quit = True
                elif choice == 'r':
                    retry = True
                else:
                    retry = False
            else:
                retry = False
        if quit:
            break
    fo.write('$##DONE')
    fo.close()

if __name__=='__main__':
    retrieve(str(sys.argv[1]))
