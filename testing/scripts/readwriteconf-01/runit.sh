#!/bin/sh

rootdir=`cd ../../..; pwd`
mkdir -p OUTPUT
$rootdir/OBJ.linux.i386/programs/readwriteconf/readwriteconf --rootdir=$rootdir/testing/baseconfigs/all --config $rootdir/testing/baseconfigs/west/etc/ipsec.conf >OUTPUT/west-flat.conf-out

diff -u west-flat.conf OUTPUT/west-flat.conf-out
