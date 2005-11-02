#!/bin/sh

. CONFIG

both --name isakmp-aggr-psk --psk --aggrmode $EASTHOST $TO $WESTHOST $TIMES2 ;
me --name isakmp-aggr-psk --initiate 

$DOWHACK shutdown 

if [ -f pluto/west/core ];
then
	echo CORE west
	echo CORE west
	echo CORE west
fi

if [ -f pluto/east/core ];
then
        echo CORE east
	echo CORE east
	echo CORE east
fi

