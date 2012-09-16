import MySQLdb as mdb

table="TABLE1"
my_User='root'
my_Host='localhost'
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

#what is a string that tells the new state you want [Online, Off, Null]
#whom is either a list of instances or 'All' which indicates all
#instances to whom you want to convert to the new state

def adjust(what, whom, table_name='TABLE1'):
    global table
    if table_name:
        table = table_name
    con_db = mdb.connect(host=my_Host, user=my_User, passwd=my_Passwd, db=my_Db)
    with con_db:
        cur=con_db.cursor(mdb.cursors.DictCursor)
        if type(whom) is list:
            for inst in whom:
                cur.execute("UPDATE "+table+" SET "+column_g+"='"+what+"' \
                    WHERE "+column_b+"='"+inst)
        elif type(whom) is str and whom=='All':
            cur.execute("UPDATE "+table+" SET "+column_g+"='"+what+"'")
            
