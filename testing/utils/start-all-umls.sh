#!/bin/bash 
#
# configuration for this file has moved to $LIBRESWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at
# umlsetup-sample.sh
# in this directory. Copy it to $LIBRESWANSRCDIR and edit it.
#
cd `dirname $0`
LIBRESWANSRCDIR=${LIBRESWANSRCDIR-../..}
if [ ! -f ${LIBRESWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in umlsetup-sample.sh.
    exit 1
fi
	
export LIBRESWANSRCDIR
. $LIBRESWANSRCDIR/umlsetup.sh

for i in $REGULARHOSTS $FREESWANHOSTS
do
	ln -sfn bootuml.sh $i
	sh $i
done
