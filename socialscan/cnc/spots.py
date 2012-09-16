#spots.py

import boto, time, traceback

def launch(requests):
    conn=boto.connect_ec2()

    try:
        start_time=time.time()
        #print requests
        list1=[result.id for results in requests for result in results]
        #print list1
        list1=list(set(list1))
        temp=list()
        print'Beginning requests...'
        #Loops till all the requests are active
        #print len(list1)
    
        while len(temp)!=len(list1):
            #print 'while loop',
            info=conn.get_all_spot_instance_requests(request_ids=list1)
            for k in info:
                print '.',
                time.sleep(3)
                if k.state=='active' and k.instance_id not in temp:
                    #print 'if', k.instance_id,
                    print 'Now Active: ',k.instance_id
                    temp.append(k.instance_id)
                    break
        #print temp
        #Using the list of instance ids requested, we will now get a list
        #of reservations pertaining to them
        reservations=conn.get_all_instances(instance_ids=temp)
        end_time=time.time()
        print 'Time: ', end_time-start_time
        return reservations

        
    finally:
        print 'Now that requests are active, lets make sure they are online'
        end=conn.cancel_spot_instance_requests(request_ids=list1)
        
    
if __name__=='__main__':
    launch()
