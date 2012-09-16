#!/usr/bin/python
#-*- coding: utf-8 -*-
# Import standard python modules
import sys

# Import 3rd party modules
import MySQLdb as mdb

amis = {
        'ami-d6ff20bf': 'avast',
        'ami-2eff2047': 'avgbe',
        'ami-ddae7eb4': 'avira', 
        'ami-c5ae7eac': 'clamwin',
        'ami-c1ae7ea8': 'kaspersky',
        'ami-f6ff209f': 'mcafee',
        'ami-dfae7eb6': 'msseccli',
        'ami-cdae7ea4': 'symantec'}

def main(table_name='TABLE2'):
    table_name = table_name.replace("'", '')
    con = mdb.connect('localhost', 'testuser', 'test623', 'testcc');
    create_table_sql = "CREATE TABLE IF NOT EXISTS " + table_name
    create_table_sql += "(AMI_Id VARCHAR(25), Scanner VARCHAR(25))"
    with con:
        cur=con.cursor()
        cur.execute(create_table_sql)

        # Now we insert all the data
        for ami, scanner in amis.items():
            insert_sql = "INSERT INTO %s VALUES('%s', '%s')" % (table_name, ami, scanner)
            cur.execute(insert_sql)

if __name__ == '__main__':
    table_name = 'TABLE2'
    if len(sys.argv) > 1:
        table_name = sys.argv[1]
    main(table_name)

