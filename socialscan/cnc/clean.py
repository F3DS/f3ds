#clean.py
from fabric.api import local

def main():
    fo=open('cleanup.txt', 'r').readlines()
    for line in fo:
        local('cd /home/malwarerepo/malwarerepo.trustproxy.org/util/ && rm '+line)
    print 'Cleanup is complete'
    local('rm cleanup.txt')

if __name__=='__main__':
    main()
