#pids.py
#gets the pids for the main.py and squid processes
import subprocess

def get_ids():
    
    subprocess.call(['ps -a | grep -i python >> pid.txt'],shell=True)
    subprocess.call(['ps -a | grep -i tsclient >> pid.txt'],shell=True)
    
if __name__ == '__main__':
    get_ids()
