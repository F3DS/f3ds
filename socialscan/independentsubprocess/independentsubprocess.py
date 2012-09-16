#!/usr/bin/python

import pickle
import sys
import subprocess


# from http://mail.python.org/pipermail/python-list/2009-July/187344.html
import select
import sys
DEBUG=False
def DPRINT(format_str, *args, **kwargs):
    '''Conditionally print formatted output based on DEBUG'''
    if DEBUG:
        print(format_str % (args or kwargs))

def non_blocking_readline(f_read=sys.stdin, timeout_select=0.0):
    """to readline non blocking from the file object 'f_read'
    for 'timeout_select' see module 'select'
    """
    text_lines = ''  # for result accumulation
    while True: # as long as there are bytes to read
        rlist, wlist, xlist = select.select([f_read],   [], [],
                                            timeout_select)
        DPRINT("rlist=%r, wlist=%r, xlist=%r",
               rlist, wlist, xlist)
        if rlist:
            text_read = f_read.readline() # get a line
            DPRINT("after read/readline text_read:%r, len=%s",
                   text_read, len(text_read))
            if text_read:       # there were some bytes
                text_lines += text_read
                DPRINT("text_lines:%r", text_lines)
                continue # Got some chars, keep going.
        break  # Nothing new found, let's get out.
    return text_lines or None
# end http://mail.python.org/pipermail/python-list/2009-July/187344.html

non_blocking_read = non_blocking_readline
class buffered_non_blocking_reader:
    def __init__(self, f_read):
        self.f_read = f_read
        self.buf = []

    def readline(self, timeout_select=0.0):
        '''adds some buffering so each time you do a read you should get a single line or nothing
        this code is not perfect - the non_blocking_read is not guaranteed to end with a 
        newline, which this code doesn't account for.
        Also, '\r' is not considered at all.'''
        # get the data
        data = non_blocking_read(self.f_read, timeout_select)
        try:
            # add the data, if it exists
            data = data.split("\n")
            self.buf.extend(data)
        except:
            # no data...
            pass
        if(self.has_data()):
            return self.buf.pop(0)
        else:
            return ""

    def has_data(self):
        if(len(self.buf)>0):
            return True
        return False


class ParentProcess:
    def __init__(self, command, parameter):
        '''command is formated for Popen; ["cmd", "param"]
        parameter is one variable, but can be complex (array, dictionary, etc)'''
        self.cmd_fds = subprocess.Popen(command, 
                                        stdout=subprocess.PIPE, 
                                        stderr=subprocess.PIPE, 
                                        stdin=subprocess.PIPE)

        self.stdout = buffered_non_blocking_reader(self.cmd_fds.stdout)

        # send data...
        pickle.dump(parameter, self.cmd_fds.stdin)


    def is_ok(self, timeout=.1):
        '''returns true if ok; 1 to 1 correspondence with ChildProcess.send_ok - 
        other code doesn't automatically chomp any extra OKs'''
        # put in non_blocking_readline
        data = self.stdout.readline(timeout).rstrip()
        if(data != "ok"):
            return False
        return True


    def get_results(self, timeout=5):
        '''returns the final results, or raises an exception if there are none'''
        # put in non_blocking_readline
        try:
            results = []
            while self.stdout.has_data():
                results.append(self.stdout.readline(timeout))
            
            if(results[0]==""):
                raise Exception("no data collected in timeout period")

            converted = pickle.loads("\n".join(results))
            
        except Exception as e:
            stderr = non_blocking_read(self.cmd_fds.stderr)
            if(stderr):
                raise Exception("something bad happened in subprocess: %s" % stderr)
            else:
                raise# Exception("something bad happened: %s" % e)
        return converted




class ChildProcess:
    def __init__(self):
        '''child process cannot use stdout without disrupting parent processes expected input - this could be changed by adding an expect-type call to ParentProcess'''
        self.params = pickle.load(sys.stdin)
        
    def get_params(self):
        return self.params

    def send_ok(self):
        print("ok")
        sys.stdout.flush()

    def send_results(self, results):
        '''can only be run once, but can be a complex variable'''
        pickle.dump(results, sys.stdout)
        exit(0)

