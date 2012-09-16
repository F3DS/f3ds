#!/usr/bin/python
#-*- coding: utf-8 -*-
# Import standard python modules
import sys
import random

# Import 3rd party modules
import MySQLdb as mdb

# Import our modules
from tablev2 import amis

functional_scanhandlers = ['avgbe', 'avast', 'avira', 'kaspersky', 'mcafee', 'msseccli']
functional_amis = []
ami_list = []
engine="MyISAM"
small_experiment_threshold = 24

def ami_populate(config=None, num_peers=50, table_name='TABLE1'):
    table_name = table_name.replace("'",'')
    size = 't1.micro'
    con = mdb.connect('localhost', 'testuser', 'test623', 'testcc');
    table_name_tuple = (table_name,)
    create_table_sql = "CREATE TABLE IF NOT EXISTS " + table_name
    create_table_sql += "(Unique_Id INT PRIMARY KEY AUTO_INCREMENT, Instance_Id VARCHAR(25),\
            Instance_type VARCHAR(25), AMI_Id VARCHAR(25), Private_IP_Address\
            VARCHAR(25), Current_VMState ENUM('Null','Booting','Off','Online'),\
            Target_VMState ENUM('Null','Off','Online'), Peer_Id VARCHAR(25))"
    with con:
        cur=con.cursor()
        cur.execute(create_table_sql)
##        cur.execute("CREATE TABLE IF NOT EXITS \
##            TABLE2(AMI_Id VARCHAR(25) PRIMARY KEY, ScannerName VARCHAR(300)) ENGINGE="+engine)

        # Insert the data
        for n in xrange(0, num_peers):
            insert_sql= "INSERT INTO %s VALUES(%s, '', '%s', '%s', '', 'Null', 'Online', '')"
            insert_sql = insert_sql % (table_name, n + 1, size, get_ami(num_peers, config))
            cur.execute(insert_sql)


# TODO: unit tests for generate, get functions.
def generate_ami_list(config):
    global ami_list
    global functional_amis
    if ami_list:
        return
    generate_functional_amis_list()
    for ami in functional_amis:
        try:
            n = int(eval('config.amis.' + amis[ami]))
        except:
            n = 0
        ami_list.extend([ami] * n)


def generate_functional_amis_list():
    global functional_amis
    if functional_amis:
        return
    functional_amis = [ami for ami in amis if amis[ami] in functional_scanhandlers]


def get_ami(num_peers, config=None):
    global functional_amis
    global ami_list
    generate_functional_amis_list()
    if config:
        generate_ami_list(config)
        ami = random.choice(ami_list)
        ami_list.remove(ami)
    else:
        ami = random.choice(functional_amis)
        if num_peers < small_experiment_threshold:
            functional_amis.remove(ami)
    return ami


def main():
    table_name = 'TABLE1'
    if len(sys.argv) > 1:
        try:
            num_peers = int(sys.argv[1])
        except:
            num_peers = 50
    if len(sys.argv) > 2:
        table_name = sys.argv[2]
    ami_populate(num_peers, table_name)
        
if __name__ == '__main__':
    main()
