#!/bin/sh

# assumes that 
#          ROOTDIR=    set to root of source code.
#          OBJDIRTOP=  set to location of object files
#

args="--rootdir=$ROOTDIR/testing/baseconfigs/all --verbose --verbose"
config="--config $ROOTDIR/testing/pluto/ikev2-01/west.conf"
args="$args $config"
#args="$args --verbose --verbose"
echo "file $ROOTDIR/OBJ.linux.i386/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args $args >OUTPUT/ikev2-west.conf-out" >>.gdbinit

eval ${OBJDIRTOP}/programs/readwriteconf/readwriteconf $args 2>&1

