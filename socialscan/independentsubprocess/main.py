#!/usr/bin/python2



import independentsubprocess
communicator = independentsubprocess.ParentProcess(["python2", "sub.py"],
                                                   ["a thing", 1, True, {'a': 'ok'}])

if not communicator.is_ok(timeout=.0):
    print "no response within timeout period!"

if communicator.is_ok(timeout=.2):
    print "got ok w/ timeout!"

print communicator.get_results()
