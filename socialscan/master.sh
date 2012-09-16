#!/bin/bash

if [ `uname -o` = "Cygwin" ]
then

    /cygdrive/c/Python27/python.exe main.py &
    /cygdrive/c/squid/sbin/squid.exe &

    echo "processes started. hit enter to shut them down"
    read

    taskkill /F /IM squid.exe /T
    taskkill /F /IM python.exe /T

else

    echo "this doesn't work on linux at the moment"

fi
