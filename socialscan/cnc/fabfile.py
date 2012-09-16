# Import standard python modules
import subprocess

# Import 3rd party modules
import boto
import paramiko
import MySQLdb as mdb

from fabric.api import *

# Import our modules
import cnc
import editor
import scanname


table="TABLE1"
my_Db='testcc'
my_Host='localhost'
my_User='root'
my_Passwd='b12kj3as201n'
column_a="Unique_Id"
column_b="Instance_Id"
column_c="Instance_type"
column_d="AMI_Id"
column_e="Private_IP_Address"
column_f="Current_VMState"
column_g="Target_VMState"
column_h="Peer_Id"

env.user='Administrator'
env.password='t9XJv*qU%2'
env.key_filename='/root/.ssh/id_rsa_sscan'
output_all='output.txt'


def live(host=None):
    if host==None:
        global table
        table = cnc.getTableName()
        list1=list()
        con_db = mdb.connect(host=my_Host, user=my_User, passwd=my_Passwd, db=my_Db)
        with con_db:
            cur=con_db.cursor(mdb.cursors.DictCursor)
            cur.execute("SELECT "+column_b+" FROM "+table+" WHERE NOT "+column_b+" <=> '' AND "+column_f+"='Online'")
            rows=cur.fetchall()
            for row in rows:
                list1.append(row[column_b])
        conn=boto.connect_ec2()
        reservations=conn.get_all_instances(instance_ids=list1)
        list2=[inst.public_dns_name for reserv in reservations for inst in reserv.instances]
        env.hosts=list2 #this is really all we want from this
    else:
        env.hosts=[host]
    

def update():
    combine_stderr=False
    code_dir = '/home/Administrator/socialscan'
    with settings(warn_only=True):
        if run("test -d %s" % code_dir).failed:
            run("git clone git@coredev.sscan.us:socialscan %s" % code_dir)
    with cd('socialscan'):
        run('pwd')
        run('git pull git@coredev.sscan.us:socialscan >> errorfile.txt')
        

def putsql(filename):
    combine_stderr=False
    fileName = filename
    dirName = '/home/Administrator/'
    with settings(warn_only=True):
        if run("test -d /home/Administrator/petehunt-PyMySQL-a4d2ead").failed:
            put(fileName, dirName)
    with cd('petehunt-PyMySQL-a4d2ead'):
        run('python setup.py install >> errorfile.txt')

def putfile(filename):
    fileName = filename
    dirName = '/home/Administrator/socialscan/New_urltests.txt'
    #with cd('socialscan'):
    put(fileName, dirName)

def putfiles():
    # TODO: to have repeatable experiments, we need the same url list.
    # This function is inadequate, and will need some serious overhaul, or
    # we may need to have a way to specify the url list to use.
    fileName=cnc.getList()
    dirName = '/home/Administrator/socialscan/New_urltests.txt'
    put(fileName,dirName)
    
def putdb(filename):
    combine_stderr=False
    fileName = filename
    dirName = '/home/Administrator/socialscan/tempPeers'
    put(fileName, dirName)

def putfeeder(filename):
    combine_stderr=False
    with cd('socialscan'):
        put(filename,'.')

def progress():
    remote='/home/Administrator/Progress.txt'
    local='/root/experiments/tmp/checker.txt'
    get(remote,local)

def retrieve():
    local='/root/experiments/'
    with cd('socialscan'):
        get('*.csv', local)

def setup():
    global table
    table = cnc.getTableName()
    list1=list()
    lives=''
    #tempPath="/root/socialscan.config"
    con_db = mdb.connect(host=my_Host, user=my_User, passwd=my_Passwd, db=my_Db)
    with con_db:
        cur=con_db.cursor(mdb.cursors.DictCursor)
        cur.execute("SELECT "+column_e+" FROM "+table+" WHERE NOT "+column_e+" <=> ''")
        rows=cur.fetchall()
        for row in rows:
            list1.append(row[column_e])
    for k in list1:
        lives=lives+str(k)+' '
    with cd('socialscan'):
        #run('git pull')
        run('rm database.db >> errorfile.txt')
        run('python testutils.py makepeers '+lives+' >> errorfile.txt')
        run('cp database.db bdatabase.db >> errorfile.txt')

def begin(arg):
    print arg
    with cd('socialscan'):
        ipaddress,personality=str(arg).split(':')
        print ipaddress, personality
        path=str(ipaddress)+'socialscan.config'
        get('socialscan.config',path)
        print 'Transferred socialscan.config file from server to localhost for editing'
        sharing=editor.getInfo(path)
        shandler=scanname.getName(ipaddress)
        print sharing
        print shandler
        editor.editor(shandler,personality,sharing,path)
        put(path,'socialscan.config')
        #run('cp bdatabase.db database.db') #Restores original database.db to use for new testing

def stopclient():
    #first we need to get the pids
    with cd('socialscan'):
        put('pid.py','.') 
        run('python pid.py >> errorfile.txt')
        get('pid.txt', '/socialscan/cnc/pid.txt')
        temp=[k.lstrip().split()[0] for k in open('pid.txt','r').readlines()]
        pid1,pid2=temp
        run('kill '+pid1+' >> errorfile.txt')
        run('kill '+pid2+' >> errorfile.txt')
        run('rm pid.py')
        run('rm pid.txt')
    subprocess.call(['rm pid.txt'], shell=True)


