#!/bin/sh

rootdir=`cd ../../..; pwd`
mkdir -p OUTPUT
exe=$rootdir/OBJ.linux.i386/programs/readwriteconf/readwriteconf
args="--rootdir=$rootdir/testing/baseconfigs/all --config $rootdir/testing/pluto/mast-pluto-01/east.conf"
echo "file $exe" >.gdbinit
echo "set args $args >OUTPUT/west-flat.conf-out" >>.gdbinit

eval $exe $args >OUTPUT/east-flat.conf-out

diff -u east-flat.conf OUTPUT/east-flat.conf-out
