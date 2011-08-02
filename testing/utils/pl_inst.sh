#!/bin/bash

if [ -z "$MYBOX" ]
then
    if [ ../../umlsetup.sh ]
    then
	MYBOX=`cd ../..; pwd`
    fi
fi
source ${MYBOX}/umlsetup.sh

for host in ${OPENSWANHOSTS}
do
    make DESTDIR=$POOLSPACE/$host/root install
done
