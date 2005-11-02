#!/bin/sh 
#
# configuration for this file has moved to $FREESWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at
# umlsetup-sample.sh
# in this directory. Copy it to $FREESWANSRCDIR and edit it.
#
cd `dirname $0`
FREESWANSRCDIR=${FREESWANSRCDIR-../..}
if [ ! -f ${FREESWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in umlsetup-sample.sh.
    exit 1
fi
	
export FREESWANSRCDIR
. $FREESWANSRCDIR/umlsetup.sh

for i in $REGULARHOSTS $FREESWANHOSTS
do
	ln -sfn bootuml.sh $i
	sh $i
done
