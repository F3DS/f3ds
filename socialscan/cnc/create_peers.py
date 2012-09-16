# Standard python imports
import sqlite3
import sys

# Third-party imports
import MySQLdb as mdb

column_a="Unique_Id"
column_b="Instance_Id"
column_c="Instance_type"
column_d="AMI_Id"
column_e="Private_IP_Address"
column_f="Current_VMState"
column_g="Target_VMState"
column_h="Peer_Id"
table="TABLE1"

# TODO: instead of using a temporary db to store the peers, perhaps it would be better to
# store the private ip along with the other instance data in the table represented by
# 'table'.  Then the 'testutils.py makepeers' command could be run just using the info
# from the database.
def main(num_peers=50, table_name='TABLE1'):
    global table
    table = table_name
    result = None
    c = None
    conn = sqlite3.connect('tempPeers')
    try:
        con = mdb.connect('localhost', 'root', 'b12kj3as201n', 'testcc')
        with con:
        #with mdb.connect('localhost', 'root', 'b12kj3as201n', 'testcc') as con:
            cur = con.cursor(mdb.cursors.DictCursor)
            #this creates the 1st temp table PeersTable with a uniqe id and the private address as columns
            cur.execute("CREATE TABLE IF NOT EXISTS \
                PeersTable(Unique_Id INT PRIMARY KEY AUTO_INCREMENT, \
                PeerIds VARCHAR(25), peers_id INT)")
            #This inserts private_ip_addresses from TABLE1 into PeersTable
            cur.execute("INSERT INTO PeersTable (PeerIds) \
                SELECT " + table + "." + column_e + " \
                FROM " + table + " WHERE NOT " + table + "." + column_e + "<=>''")
            #Now we do the 1:1 relationship
            min_range = 10
            max_range = num_peers + min_range
            rows = [x for x in xrange(min_range, max_range)]

            n = 1
            for row in rows:
                cur.execute("UPDATE PeersTable SET peers_id=%s WHERE Unique_Id=%s"%(int(row), n))
                n += 1
            cur.execute("SELECT PeerIds, peers_id FROM PeersTable")   
            result=cur.fetchall()
            cur.execute("DROP TABLE PeersTable")

        #Sqlite3 commnads
        c = conn.cursor()
        # Create table in sql database
        c.execute('''create table PeersTable (peer_ids int, PeerIds text)''')
        for k in result:
            s=(int(k['peers_id']), k['PeerIds'])
            c.execute('''insert into PeersTable values (?,?)''', s)
        
        c.execute('select * from PeersTable order by peer_ids')
        for row in c:
            print row

    finally:
        conn.commit()
        if c: c.close()


def cleanup():
    conn = sqlite3.connect('tempPeers')
    c = conn.cursor()
    c.executescript('''drop table if exists PeersTable;''')
    conn.commit()
    c.close()

'''if __name__ == '__main__':
    if len(sys.argv)==2:
        main(int(sys.argv[1]))
    else:
        main()'''


