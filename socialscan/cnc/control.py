#!/usr/bin/python
#-*- coding: utf-8 -*-

'''
#####Program Assumes the following:
        boto has been installed and credentials setup
        MySQLdb has been installed
        Values for Current VMState= Off, Online, Booting, Null are all hard coded
        Values for Target VMState= Off, Null, Online are hardcoded
##### How it works:
        Program will begin by seperating the rows that have CurrentVMState<>TargetVMState
        Once that has happened it will futher divide rows depending on whether instance is
        going from online to off, online to null, off to online, null to online.  For off or
        null to online, it will keep a list with both of these since it will need to launch
        the instances regardless.  For those being created it will then seperate them further
        into first AMI ID's and then by the instance_type.  So far only five different
        instance_types are covered thus far: t1.micro, m1.small, m1.large, m1.xlarge, c1.medium.
        Then it will launch a 'batch' per reservation. And from there it go through each of the
        instances and get the private ip address and check that the instance is online.  Once
        all instances are online, it will then go through the other rows and either stop them,
        start them or destroy them as a whole.
'''
# Import standard python modules
import copy
import os
import sys
import time
import traceback

# Import 3rd party modules
import boto
import MySQLdb as mdb

# Import our modules
#import spots

#######Data Variables##########
my_Host='localhost'
my_User='root'
my_Passwd='b12kj3as201n'
my_Db='testcc'
column_a="Unique_Id"
column_b="Instance_Id"
column_c="Instance_type"
column_d="AMI_Id"
column_e="Private_IP_Address"
column_f="Current_VMState"
column_g="Target_VMState"
column_h="Peer_Id"
table="TABLE1"
scrgrp='ScanAgent'
inst_dns_file = 'instdns.txt'
online=list()


def control(table_name='TABLE1', exp_name='testcc'):
    global table
    table = table_name
    start_time=time.time()
    #Connect to mysql database used as root
    con_db = mdb.connect(host=my_Host, user=my_User, passwd=my_Passwd, db=my_Db)

    with con_db:
        cur=con_db.cursor(mdb.cursors.DictCursor)
        """Check that the column names are correctly named within the table
        and that the table name is also correct."""
        cur.execute("SELECT * FROM "+table+" WHERE NOT "+column_f+" <=> "+column_g)
        rows=cur.fetchall()
        
        crows=list()
        term_ids=list()
        term=list()
        for row in rows:
            if row[column_g]=='Null':
                # The Current State is either 'off' or 'online and soon-to-be terminated'
                term.append(row)
                term_ids.append(row[column_b])
            else:
                crows.append(row)
        start_ids=list()
        start=list()
        stop_ids=list()
        stop=list()
        create=list()
        create_off=list()
        create_off_ids=list()
        for x in crows:                 #Target state is either off or online
            if x[column_f]=='Off':      #Go from off state to online: start instances
                start.append(x)
                start_ids.append(x[column_b])
            elif x[column_f]=='Online': #Go from online to off
                stop.append(x)
                stop_ids.append(x[column_b])
            elif x[column_f]=='Null':   #Go from null to either off or online
                create.append(x)
                if x[column_g]=='Off':  # Stop instances that went from Null to Off
                    create_off.append(x)
                    create_off_ids.append(x[column_b])

        #Now we need to seperate and group the remaining rows in create list into the different AMI
        #First we find all the differing AMI ID's in the create list and place them into
        #a list called the amilist
        amilist=list()
        for s in create:
            if s[column_d] not in amilist:
                amilist.append(s[column_d])
        amilist=list(set(amilist))
        
        #Now that we have however many differing AMI ID's are in the create list, we go
        #through the create list again and append the rows that belong to a matching ami id
        #into a temporary list.  Once we have all the rows for that id we place the ami id
        #as a key and the list containing all matching rows as the value in the temp dictionary
        temp=dict()
        temporary=list()
        for x in amilist:
            for y in create:
                if y[column_d]==x:
                    temporary.append(y)
            temp[x]=temporary           #now this holds a list of rows
            temporary=list()

        #Now we further divide up the same ami id rows by their differing instance types
        #and assign them temporary lists.  Once we have filtered the ami id and instance type
        #we launch the instances by calling the Filter4 function
        for z in temp.keys():
            row1=temp[z]
            row2=list();row3=list();row4=list();row5=list();row6=list()
            for w in row1:
                if w[column_c]=='t1.micro':
                    row2.append(w)
                elif w[column_c]=='m1.small':
                    row3.append(w)
                elif w[column_c]=='m1.large':
                    row4.append(w)
                elif w[column_c]=='c1.medium':
                    row5.append(w)
                elif w[column_c]=='m1.xlarge':
                    row6.append(w)
            if len(row2) != 0:
                Filter4(z,row2,cur)
            if len(row3) !=0:
                Filter4(z,row3,cur)
            if len(row4) != 0:
                Filter4(z,row4,cur)
            if len(row5) !=0:
                Filter4(z,row5,cur)
            if len(row6) != 0:
                Filter4(z,row6,cur)

        spot_instances = False
        conn = boto.connect_ec2()
        # Check whether there are instances to be launched; verify they are done booting up.
        if create:
            bring_online(len(create), online, cur)
        # Start, stop, terminate other instances
        if start:
            Filter2(start, start_ids, cur)
        if stop:
            Filter3(stop, stop_ids, cur)
        if term:
            Filter1(term, term_ids, cur)
        if create_off:
            Filter3(create_off, create_off_ids, cur)

        # Check for all the running instances at any given point by querying the table
        cur.execute("SELECT * FROM "+table+" WHERE "+column_f+" <=> 'Online'")
        rows=cur.fetchall()
        online_Ids=[row[column_b] for row in rows]
        reservations = conn.get_all_instances(instance_ids=online_Ids)
        running=[inst.public_dns_name for reserv in reservations for inst in reserv.instances
                                       if inst.update() == 'running']
        with open(inst_dns_file, 'w') as instance_dns:
            for address in running:
                instance_dns.write('%s\n' % address)
        print running

        end_time=time.time()
        print 'Took: ',(end_time-start_time)
        return running


# This function terminates any row that has a target vm state of Null
def Filter1(list1,list2,cur):
    destroy_inst(list2)    #calls the destroy function and gives the instance id list as a parameter
    for xrow in list1:
        cur.execute("UPDATE "+table+" SET "+column_b+"='',"+column_e+"='',"+column_f+"='Null' WHERE \
                "+column_g+"='Null'")
    print 'All Necessary instances have been terminated'

# This function starts any rows that have current state 'off' and target state 'online'
# It checks that the instances are online and not just booting
def Filter2(list1, list2, cur):
    start_inst(list2)
    conn = boto.connect_ec2()
    reservations=conn.get_all_instances(list2)
    for xrow in list1:
        cur.execute("UPDATE "+table+" SET "+column_f+"='Booting' WHERE "+column_b+"='"+str(xrow[column_b])+"'")
    print 'All Necessary Instances have been launched, but are still booting'
    bring_online(len(list1),reservations,cur)

# This function stops all rows that have target state as off
def Filter3(list1,list2,cur):
    stop_inst(list2)
    for xrow in list1:
        cur.execute("UPDATE "+table+" SET "+column_e+"='', "+column_f+"='Off' WHERE "+column_b+"='"+str(xrow[column_b])+"'")
    print 'All necessary instances have been stopped'

# This function creates and launches all instances that are going
# online from a current state of off or null
def Filter4(amid,list1,cur):
    reservation=create_inst(list1,amid,list1[0][column_c])
    n=0
    for xrow in list1:
        a=str(reservation.instances[n].id)
        print 'Launching Instance: '+a
        cur.execute("UPDATE "+table+" SET "+column_b+"='"+str(a)+"', "+column_f+"='Booting' \
            WHERE "+column_a+"="+str(xrow[column_a]))
        n+=1
    online.append(reservation)

#This functions is responsible for placing the private ip addresses as soon as possible to the table
#and for checking that the instance is done booting up by pinging it.
def bring_online(t, reservations, cur):
    try:
        while t > 0:
            for reservation in reservations:
                for instance in reservation.instances:
                    #Now just wait till the instances are done booting
                    cur.execute("SELECT * FROM "+table+" WHERE "+column_b+"='"+str(instance.id)+"'")
                    xrow=cur.fetchall()
                    if xrow[0][column_f]=='Booting':
                        if instance.update()=='running':
                            if xrow[0][column_e]=='':
                                cur.execute("UPDATE "+table+" SET "+column_e+"='"+str(instance.private_ip_address)+"'\
                                    WHERE "+column_b+"='"+str(instance.id)+"'")
                            if ping(instance)==True:
                                print instance.private_ip_address
                                cur.execute("UPDATE "+table+" SET "+column_f+"='Online' \
                                    WHERE "+column_b+"='"+str(instance.id)+"'")
                                print instance, instance.ip_address, 'is now up'
                                t-=1
    except:
        print 'error has occurred', t
        time.sleep(2)
        bring_online(t, reservations, cur)
    print 'All launched instances are now running.\n'

#The following functions just call the run, stop, start, and terminate instances
#on batches given by a list.
    #Regular instance
##def create_inst(list1,imgid,instype):
##    conn = boto.connect_ec2()
##    reservation=conn.run_instances(image_id=imgid, min_count=len(list1), max_count=len(list1), security_groups=[scrgrp], instance_type=instype)
##    return reservation

#SpotInstance
def create_inst(list1,imgid,instype):
    conn = boto.connect_ec2()
    reservation=conn.run_instances(image_id=imgid, security_groups=[scrgrp], instance_type=instype)
    return reservation

def destroy_inst(inst_ids):
    conn = boto.connect_ec2()
    check=conn.terminate_instances(inst_ids)
    for ids in check:
        r,n=str(ids).split(':')
        if str(n) not in inst_ids:
            print '%s could not be destroyed'%str(n)
        
def stop_inst(inst_id):
    conn = boto.connect_ec2()
    check=conn.stop_instances(inst_id)
    for ids in check:
        r,n=str(ids).split(':')
        if str(n) not in inst_id:
            print '%s could not be stopped'%str(n)
        
def start_inst(start_ids):
    conn = boto.connect_ec2()
    check=conn.start_instances(start_ids)
    for ids in check:
        r,n=str(ids).split(':')
        if str(n) not in start_ids:
            print '%s could not be started'%str(n)

#Sees if the given instance is online by checking that the console output states its ready.
def ping(inst):
    message= 'Windows is Ready to use'
    output= inst.get_console_output()
    if message in output.output: return True
    else: return False


def main():
    if len(sys.argv) > 1:
        table_name = sys.argv[1]
    control(table_name)


if __name__ == '__main__':
    main()

