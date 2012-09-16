#!/bin/bash

if [ `uname -o` = "Cygwin" ]
then

    taskkill /F /IM squid.exe /T
    taskkill /F /IM python.exe /T

else

    echo "this doesn't work on linux at the moment"

fi
