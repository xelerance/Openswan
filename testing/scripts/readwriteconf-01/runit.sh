#!/bin/sh

MAKE=${MAKE-make}

rootdir=`cd ../../..; pwd`
mkdir -p OUTPUT
echo "file $rootdir/OBJ.linux.i386/programs/readwriteconf/readwriteconf" >.gdbinit
echo "set args --rootdir=$rootdir/testing/baseconfigs/all --config $rootdir/testing/baseconfigs/west/etc/ipsec.conf >OUTPUT/west-flat.conf-out" >>.gdbinit

(cd $rootdir/programs/readwriteconf && ${MAKE} programs )

$rootdir/OBJ.linux.i386/programs/readwriteconf/readwriteconf --rootdir=$rootdir/testing/baseconfigs/all --config $rootdir/testing/baseconfigs/west/etc/ipsec.conf >OUTPUT/west-flat.conf-out

sed -f ../fixups/confwritesanity.sed OUTPUT/west-flat.conf-out >OUTPUT/west-flat.fixed

if diff -u west-flat.conf OUTPUT/west-flat.fixed >OUTPUT/west-flat.diff
then
	echo Success
else
	echo Failed
	exit 30
fi
