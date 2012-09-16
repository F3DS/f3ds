#scanname.py
import MySQLdb as mdb
import boto

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

def getName(ipaddress, table2='TABLE2'):
    k=dict()
    k['dns-name']=str(ipaddress).strip('\n')
    print k.items()
    conn=boto.connect_ec2()
    result=conn.get_all_instances(filters=k)
    print result[0].instances[0].private_ip_address
    ami=result[0].instances[0].image_id
    
    con_db = mdb.connect(host=my_Host, user=my_User, passwd=my_Passwd, db=my_Db)
    with con_db:
        cur=con_db.cursor(mdb.cursors.DictCursor)
        cur.execute("SELECT * FROM "+table2+" WHERE "+column_d+"='"+ami+"'")
        row=cur.fetchall()
        print row[0]
        return row[0]['Scanner']
