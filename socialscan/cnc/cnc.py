# Python Standard library modules
import os
import subprocess
import sys
import time
import traceback

from os import path
basename = path.basename
splitext = path.splitext

# Modify the path to include the main socialscan directories
# so we can use the config module
# __file__ is <root>/cnc/cnc.py
pdn = os.path.dirname
projectdir = pdn(pdn(path.abspath(__file__)))
for d in [projectdir, path.join(projectdir, 'socialscan'), path.join(projectdir, 'util')]:
    if d not in sys.path:
        sys.path.append(d)

# 3rd party modules
import paramiko
from fabric.api import *

# Our modules
import ccadjust
import control
import create_peers
import scanname
import spotcontrol
import table
import tablev2

from socialscan.config import loadConfig


inst_address = None
personality = ''
done = False
table_names = ['TABLE1', 'TABLE2']
inst_dns_file = 'instdns.txt'
args_feeder_file='args.txt'
passwrd='t9XJv*qU%2'


def quit():
    global done
    print 'Warning: you will lose the ability to control individual instance processes.'
    choice = raw_input('Are you sure you want to continue? (y/Y for yes, all others are no):')
    if choice.strip() in ['y', 'Y']:
        print 'Bye!'
        done = True


def destroy(config=None):
    global table_names
    ccadjust.adjust('Null', 'All', table_names[0])
    spotcontrol.main(table_names[0])


def retrieve(config=None):
    subprocess.call(['fab live retrieve'], shell=True)


def initdb(config=None):
    global table_names
    use_default_table = False
    try:
        table_name = config.database.table_name
    except:
        table_name = ''
    if not table_name:
        choice = raw_input('\tUse alternate table name? y or Y for yes, all others for no: ')
        if choice.strip() in ['y', 'Y']:
            choice = raw_input('\tEnter alternate table name (blank to change revert to default): ')
            if choice.strip() != '':
                choice = choice.replace("'", '')
                table_names = [choice + '1', choice + '2']
                print '\tnew table names: %s' % table_names
    else:
        table_names = [table_name + '1', table_name + '2']
        print 'using config, table names are now %s' % table_names
    try:
        create = config.database.create
    except:
        create = 'True'
    if create.lower() == 'true':
        tablev2.main(table_names[1])
        try:
            n = int(config.database.num_peers.strip())
        except:
            n = 0
        while not n:
            choice = raw_input('\tHow many peers? ')
            try:
                n = int(choice.strip())
            except:
                n = 0
                print 'Invalid selection:%s' % (choice)
        try:
            table.ami_populate(config=config, num_peers=n, table_name=table_names[0])
        except:
            traceback.print_exc()
            print """
Perhaps you just wanted to populate the table names?  If so, you can ignore
this error message.  Otherwise, you should probably quit and try again.
"""


def launch(config=None):
    global inst_address
    try:
        name = config.launch.name
    except:
        name = ''
    if not name:
        name= raw_input('\tWhat would you like to name your experiment? ')
    try:
        inst_address=spotcontrol.main(table_names[0], name.strip())
    except KeyboardInterrupt:
        print '\n\tKeyboardInterrupt received.  Aborting launch, destroying instances.\n'
        destroy()


def updates(config=None):
    #Makes the sqlite table and database of peer_ids relationships
    print 'Creating peers table...'
    try:
        create_peers.main()
    except:
        traceback.print_exc()
    db_path = 'tempPeers'
    pymysql_path = '/root/Temp/petehunt-PyMySQL-a4d2ead/'
    # TODO: is the 'Put new sqlite db in socialscan dir' necessary?  How is it used, and why?
    data = {
        'Updating source code': ['fab live update -P'],
        'Put new sqlite db in socialscan dir': ['fab live putdb:' + db_path + ' -P'],
        'Installing pyMySQL module to instances': ['fab live putsql:' + pymysql_path + ' -P'],
    }
    for action in data:
        print action + '...'
        try:
            subprocess.call(data[action], shell=True)
        except:
            traceback.print_exc()
    # Now clean up (TODO: is this needed?  Seems related to 'Put new sqlite db in
    # socialscan dir'.  If it can be removed, the next one can be added to the data dict
    # above.
    print 'cleaning up...'
    try:
        create_peers.cleanup()
    except:
        traceback.print_exc()
    # This function sets up the peers and saves a copy of the database as 'bdatabase.db'
    # for retesting with different personalities
    try:
        subprocess.call(['fab live setup -P'], shell=True)
    except:
        traceback.print_exc()


def start(config=None):
    global personality
    # Get whether to use the same url list for all nodes.
    try:
        mode = config.start.mode.strip()
    except:
        mode = ''
    modes = ['same', 'diff']
    while not mode or mode not in modes:
        print('\tWill you be using the same URL list for all nodes or a different one for each?')
        mode = raw_input("'Type in same or diff':  ")
        mode = mode.strip()
        if mode not in modes: print 'Not an option'
    # Get personality.
    try:
        personality = config.start.personality.strip()
    except:
        personality = ''
    pyfiles = [n for n in os.listdir(projectdir + '/socialscan/decisionhandlers') if n.endswith('.py')]
    personalities = [splitext(basename(p))[0] for p in pyfiles if p != '__init__.py']
    message=str(personalities).strip('"').lstrip('[').rstrip(']')
    while not personality or personality not in personalities:
        print('\tWhat personality will you be using: '+message)
        personality = raw_input("'Type in "+message+":  ")
        if personality not in personalities: print 'Not an option'

    fo = open(inst_dns_file, 'r').readlines()
    print fo

    #Generates one file for all the nodes or a file for each node depending on the fab function called
    if mode == 'same': 
        path = getList()
        subprocess.call(['fab live putfile:'+path+' -P'], shell=True)
    elif mode == 'diff':
        subprocess.call(['fab live putfiles'], shell=True)

    for server in fo:
        arg = server.strip('\n')+':'+personality
        print arg
        subprocess.call(['fab begin:%s,hosts="%s"'%(arg,server.strip('\n'))], shell=True) #MADE A CHANGE HERE
        print 'I finished begin function for '+server

    for server in fo:
        host=server.strip('\n')
        user='Administrator'
        subprocess.call(["ssh -i ~/.ssh/id_rsa_sscan "+user+"@"+host+" -f  'nohup /cygdrive/c/squid/sbin/squid.exe &'"], shell=True)
        subprocess.call(['ssh -i ~/.ssh/id_rsa_sscan '+user+'@'+host+' -f  "nohup /cygdrive/c/Python27/python.exe socialscan/main.py >> /dev/null &"'], shell=True)
        subprocess.call(['ssh -i ~/.ssh/id_rsa_sscan '+user+'@'+host+' -f "exit"'], shell=True)
        print 'finished turning on squid and main.py for '+server


def beginclient():
    global personality
    fo=open(inst_dns_file, 'r').readlines()
    name='New_urltests.txt'

    for server in fo:
        print server, personality
        #fname=open(args_feeder_file,'w')
        ami=scanname.getName(server, table_names[1])
        descript=personality+'_'+ami
        print descript
        fname=open('args.txt','w+')
        fname.write('-u '+name+' -d '+descript)
        test=fname.read()
        fname.close()
        print test

        subprocess.call(['fab putfeeder:%s,hosts="%s"'%(args_feeder_file,server.strip('\n'))],shell=True)
        #subprocess.call(['rm args.txt'],shell=True)

    for server in fo:
        subprocess.call(['ssh -i ~/.ssh/id_rsa_sscan Administrator@'+server.strip('\n')+' -f "nohup /cygdrive/c/Python27/python.exe socialscan/urlfeeder.py &"'], shell=True)
        subprocess.call(['ssh -i ~/.ssh/id_rsa_sscan Administrator@'+server.strip('\n')+' -f "exit"'], shell=True)
        print 'finished starting urlfeeder.py in '+server
  

def getList():
    num_benign = 80
    generator_dir = '/home/malwarerepo/malwarerepo.trustproxy.org/util'
    generator_name = 'url_gen.sh'
    urllist = '/root/testurls'
    local('cd %s && ./%s %s %s' % (generator_dir, generator_name, num_benign, ulrlist))
    return urllist


def getTableName(n=0):
    if len(table_names) > n:
        return table_names[n]
    return table_names[0]


def checker():
    global inst_address
    addresses = inst_address
    done_key='$##DONE'
    local='/root/experiments/tmp/checker.txt'
    finished=list()
    while len(finished)!=len(addresses):
        for host in addresses:
            if host not in finished:
                subprocess.call(['fab progress,hosts="'+host+'"'], shell=True)
                feedback = ''
                with open(local,'r') as feedback_file:
                    feedback = feedback_file.read()
                if done_key in feedback:
                    finished.append(host)
                    #The following call will terminate main.py and squid in the finished host
                    subprocess.call(['fab stopclient,hosts="'+host+'"'], shell=True)
                    try:
                        os.remove(local)
                    except:
                        # Try truncating the file if we can't remove it.
                        f = open(local, 'w+')
                        f.close()
                else:
                    print 'Scanning not finished, %d left'%(len(addresses)-len(finished))
    print 'Scans in every instance have stopped'


def process_config(config_path):
    """
    Run most or all of an experiment from a config file.
    """
    config = loadConfig(config_path)
    # TODO: add config for control operations
    section_function_map = [
        ('database', initdb),
        ('launch', launch),
        ('updates', updates),
        ('start', start),
        ('sclient', beginclient),
        ('stop', checker),
        ('retrieve', retrieve),
        ('destroy', destroy),
    ]
    for section, operation in section_function_map:
        try:
            config_section = eval('config.' + section)
            if config_section:
                operation(config)
        except:
            pass
    return config.general.run_main == 'True'


def print_usage():
    usage = """
%s [config file]
\tTo run non-interactively, pass a config file specifying experiment parameters.
\tTo run interactively, pass no arguments.
\tTo run non-interactively, then switch to interactive, set
\t\trun_main=True
\tin the [general] section of the config file
"""
    print usage % (os.path.splitext(basename(__file__))[0])


def print_config_help():
    config_help = """
\tConfig Sections and Options:
\t\tgeneral
\t\t\trun_main: True or False -- if True, switch to interactive after processing config
\t\t\tdebug: True or False -- if True, print debug statements

\t\tdatabase
\t\t\tnum_peers: integer > 0 -- number of peers for this experiment
\t\t\ttable_name: string -- base string for tables for this experiment

\t\tlaunch
\t\t\tname: string -- experiment name

\t\tstart
\t\t\tmode: 'same' or 'diff' -- if same, all peers will get the same url list,
                                otherwise they will all get different lists
\t\t\tpersonality: any of the decisionhandlers available in the decisionhandlers
                   directory, do not include .py

\t\tupdates
\t\t\tany_option_here: any value -- if the updates section exists, the
                                    updates function will be called

\t\tretrieve
\t\t\tany_option_here: any value -- if the retrieve section exists, the
                                    retrieve function will be called

\t\tdestroy
\t\t\tany_option_here: any value -- if the destroy section exists, the
                                    destroy function will be called
"""
    print config_help


def print_menu():
    print '\nControl System, please enter command one of the following commands'
    print '\t1)initdb -- runs scripts to initialize db with AMIs to launch'
    print '\t2)launch -- starts up instances from central db'
    print '\t3)update -- updates code (mainly socialscan)'
    print '\t4)start -- starts socialscan'
    print '\t5)sclient-- starts client'
    print '\t6)stop -- stops socialscan'
    print '\t7)retrieve -- retrieve results from sqlite db and clear out all results to run new test'
    print '\t8)destroy-- terminates all instances launched'
    print '\t9)quit -- ends command and control script\n'


def main():

    global inst_address
    global personality
    global done

    command_map = { 'initdb': initdb, 'launch': launch, 'update': updates,
                    'start': start, 'sclient': beginclient, 'stop': checker,
                    'retrieve': retrieve, 'destroy': destroy, 'quit': quit, 
                    '1': initdb, '2': launch, '3': updates, '4': start, '5': beginclient,
                    '6': checker, '7': retrieve, '8': destroy, '9': quit}

    try:
        while not done:
            print_menu()
            command = raw_input("$ ")
            command = command.strip()
            if command in command_map:
                command_map[command]()
            else:
                print 'Sorry, that is not a command.  Try again.'
    finally:
        for name in ['tempPeers', inst_dns_file]:
            try:
                os.remove(name)
            except:
                # See if we can truncate it
                f = open(name, 'w+')
                f.close()


if __name__ == '__main__':
    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    run_main = True
    config_path = ''
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    if config_path:
        if os.path.isfile(config_path):
            run_main = process_config(config_path)
        else:
            print_usage()
            if config_path in ['-h', '--help']:
                print_config_help()
            sys.exit()
    if run_main:
        main()

