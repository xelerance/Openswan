#!/bin/sh

rootdir=`cd ../../..; pwd`
mkdir -p OUTPUT
echo "file $rootdir/OBJ.linux.i386/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args --rootdir=$rootdir/testing/baseconfigs/all --config $rootdir/testing/baseconfigs/west/etc/ipsec.conf >OUTPUT/west-flat.conf-out" >>.gdbinit

$rootdir/OBJ.linux.i386/programs/readwriteconf/readwriteconf --rootdir=$rootdir/testing/baseconfigs/all --config $rootdir/testing/baseconfigs/west/etc/ipsec.conf >OUTPUT/west-flat.conf-out

diff -u west-flat.conf OUTPUT/west-flat.conf-out
