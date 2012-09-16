setting up a vm
---------------


1. use latest **cygwin** installer to install **git** (latest cygwin installer: http://cygwin.com/setup.exe )
2. install **python 2.7** from http://python.org/ftp/python/2.7.2/python-2.7.2.msi
3. download **ez_install.py** to C:/Documents\ and\ Settings/Adminstrator/Downloads/ez_setup.py
   from http://peak.telecommunity.com/dist/ez_setup.py
4. download **twisted** from http://twistedmatrix.com/Releases/Twisted/11.1/Twisted-11.1.0.win-amd64-py2.7.msi and install it
5. download the **pywin32** integration layer from http://sourceforge.net/projects/pywin32/files/pywin32/Build216/pywin32-216.win32-py2.7.exe/download and install it
5. download **squid** from http://squid.acmeconsulting.it/download/squid-3.0.STABLE23-BZR-bin.zip and extract to C:/squid/
6. extract **squid** such that there is a C:/squid/
7. get the **instance private key** installed on the vm. Download it to C:/cygwin/home/Administrator/.ssh/id_rsa
8. put the **squid config** from the squid.conf in this repo in C:/squid/etc/squid.conf
9. add port 8123 in windows firewall 

in the cygwin shell (if an easy_install fails, try it again):

    echo 'PATH="/cygdrive/c/Python27:$PATH"' > /etc/profile
    source /etc/profile
    rm /usr/bin/python # IMPORTANT - if you don't do this, it might not use the correct version!
    
    python C:/Documents\ and\ Settings/Adminstrator/Downloads/ez_setup.py
    
    /cygdrive/c/Python27/Scripts/easy_install sqlalchemy
    /cygdrive/c/Python27/Scripts/easy_install zope.interface

    cd /cygdrive/c/Python27/Lib/site-packages
    wget http://dl.dropbox.com/u/16327181/site-packages.tar.gz
    tar -xzf site-packages.tar.gz
    rm site-packages.tar.gz
    cd ~
    
    chmod 0600 ~/.ssh/id_rsa
    git clone git@coredev.sscan.us:socialscan
    
    cp C:/squid/etc/mime.conf.default C:/squid/etc/mime.conf
    mkdir -p C:/squid/var/spool/squid
    C:/squid/sbin/squid.exe -z # to create the squid cache directories


To run the system, cd to ~/socialscan/ and run ./master.sh. to shut it down, press enter. It should be run once to ensure that it is correctly set up.
