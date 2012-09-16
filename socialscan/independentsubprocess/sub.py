#!/usr/bin/python2

import sys
import pickle
import independentsubprocess

communicator = independentsubprocess.ChildProcess()

def code_to_run(params):
    # open
    # many AVs stop the file from being opened; immediately print that this portion has succeeded
    communicator.send_ok()
    
#    from time import sleep
#    raise Exception("doom")
#    sleep(7)
    # continue
    return ["sub.py returning", "ooook","", None]



# write return value
communicator.send_results(code_to_run(communicator.get_params()))

