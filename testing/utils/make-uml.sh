#!/bin/sh
#
# 
# $Id: make-uml.sh,v 1.31 2003/04/10 02:41:15 mcr Exp $
#

# show me
#set -x

# fail if any command fails
set -e

case $# in
    1) FREESWANSRCDIR=$1; shift;;
esac
    
#
# configuration for this file has moved to $FREESWANSRCDIR/umlsetup.sh
# By default, that file does not exist. A sample is at umlsetup-sample.sh
# in this directory. Copy it to $FREESWANSRCDIR and edit it.
#
FREESWANSRCDIR=${FREESWANSRCDIR-../..}
if [ ! -f ${FREESWANSRCDIR}/umlsetup.sh ]
then
    echo No umlsetup.sh. Please read instructions in doc/umltesting.html and testing/utils/umlsetup-sample.sh.
    exit 1
fi

. ${FREESWANSRCDIR}/umlsetup.sh
. ${FREESWANSRCDIR}/testing/utils/uml-functions.sh

# make absolute so that we can reference it from POOLSPACE
FREESWANSRCDIR=`cd $FREESWANSRCDIR && pwd`;export FREESWANSRCDIR

# what this script does is create some Makefile
#  (if they do not already exist)
# that will copy everything where it needs to go.

if [ -d $FREESWANSRCDIR/testing/kernelconfigs ]
then
    TESTINGROOT=$FREESWANSRCDIR/testing
fi
TESTINGROOT=${TESTINGROOT-/c2/freeswan/sandbox/testing}

if [ -z "$NONINTPATCH" ]
then
    if [ -f ${TESTINGROOT}/kernelconfigs/linux-2.4.0-nonintconfig.patch ]
    then
	NONINTPATCH=${TESTINGROOT}/kernelconfigs/linux-2.4.0-nonintconfig.patch
    fi
fi

# hack for version specific stuff
UMLVERSION=`basename $UMLPATCH .bz2 | sed -e 's/uml-patch-//'`
EXTRAPATCH=${TESTINGROOT}/kernelconfigs/extras.$UMLVERSION.patch

# dig the kernel revision out.
KERNEL_MAJ_VERSION=`${FREESWANSRCDIR}/packaging/utils/kernelversion-short $KERNPOOL/Makefile`


echo -n Looking for Extra patch at $EXTRAPATCH..
if [ -f "${EXTRAPATCH}" ]
then
    echo found it.
else
    echo none.
    EXTRAPATCH=
fi

mkdir -p $POOLSPACE
UMLMAKE=$POOLSPACE/Makefile
NOW=`date`
USER=${USER-`id -un`}
echo '#' built by $0 on $NOW by $USER >|$UMLMAKE
echo '#' >>$UMLMAKE

setup_make >>$UMLMAKE

# now, setup up root dir
for host in $REGULARHOSTS
do
    setup_host_make $host plain/linux regular >>$UMLMAKE
done


# okay, copy the kernel, apply the UML patches, and build a plain kernel.
UMLPLAIN=$POOLSPACE/plain
mkdir -p $UMLPLAIN

if [ ! -x $UMLPLAIN/linux ]
then
    cd $UMLPLAIN
    lndir -silent $KERNPOOL .
    
    if [ ! -d arch/um ] 
    then
	bzcat $UMLPATCH | patch -p1 
	if [ -n "$NONINTPATCH" ]
	then
	    echo Applying non-interactive config patch
	    cat $NONINTPATCH | patch -p1
	else
		echo Can not find +$NONINTPATCH+
	exit 1
	fi
	if [ -n "$EXTRAPATCH" ]
	then
	    echo Applying other version specific stuff
	    cat $EXTRAPATCH | patch -p1
	fi
	for patch in ${TESTINGROOT}/kernelconfigs/local_${KERNEL_MAJ_VERSION}_*.patch
	do
	    if [ -f $patch ] 
	    then
		echo Applying local patch $patch
		cat $patch | patch -p1
	    fi
	done
    fi

    if [ ! -f .config ] 
    then
	cp ${TESTINGROOT}/kernelconfigs/umlplain.config .config
    fi
    (make ARCH=um oldconfig_nonint && make ARCH=um dep && make ARCH=um linux ) || exit 1 </dev/null 
fi

# now, execute the Makefile that we have created!
cd $POOLSPACE && make $REGULARHOSTS 

# now, copy the kernel, apply the UML patches.
# then, make FreeSWAN patches as well.
#
UMLSWAN=$POOLSPACE/swan

# we could copy the UMLPLAIN to make this tree. This would be faster, as we
# already built most everything. We could also just use a FreeSWAN-enabled
# kernel on sunrise/sunset. We avoid this as we actually want them to always
# work.

# where to install FreeSWAN tools
DESTDIR=$POOLSPACE/root

# do not generate .depend by default
KERNDEP=''

mkdir -p $UMLSWAN

if [ ! -x $UMLSWAN/linux ]
then
    cd $UMLSWAN
    lndir -silent $KERNPOOL .
    
    if [ ! -d arch/um ] 
    then
	bzcat $UMLPATCH | patch -p1 
	if [ -n "$NONINTPATCH" ]
	then
	    echo Applying non-interactive config patch
	    cat $NONINTPATCH | patch -p1
	else
		echo Can not find +$NONINTPATCH+
	fi
	if [ -n "$EXTRAPATCH" ]
	then
	    echo Applying other version specific stuff
	    cat $EXTRAPATCH | patch -p1
	fi
	for patch in ${TESTINGROOT}/kernelconfigs/local_${KERNEL_MAJ_VERSION}_*.patch
	do
	    if [ -f $patch ] 
	    then
		echo Applying local patch $patch
		cat $patch | patch -p1
	    fi
	done
    fi
    
    # copy the config file
    rm -f .config
    cp ${TESTINGROOT}/kernelconfigs/umlswan.config .config

    # make the kernel here for good luck
    make ARCH=um oldconfig_nonint
    if [ ! -f .depend ]
    then
      make ARCH=um dep >umlswan.make.dep.out
    fi 
    #make ARCH=um linux >umlswan.make.plain.out

    # we have to copy it again, because "make oldconfig" above, blew
    # away options that it didn't know about.

    cp ${TESTINGROOT}/kernelconfigs/umlswan.config .config

    # nuke final executable here since we will do FreeSWAN in a moment.
    rm -f linux .depend
    KERNDEP=dep
fi

grep CONFIG_IPSEC $UMLSWAN/.config || exit 1

if [ ! -x $UMLSWAN/linux ]
then
    cd $FREESWANSRCDIR || exit 1

    make KERNMAKEOPTS='ARCH=um' KERNELSRC=$UMLSWAN KERNCLEAN='' KERNDEP=$KERNDEP KERNEL=linux DESTDIR=$DESTDIR nopromptgo || exit 1 </dev/null 
fi

cd $FREESWANSRCDIR || exit 1

make programs

# now, setup up root dir
for host in $FREESWANHOSTS
do
    setup_host_make $host $UMLSWAN/linux freeswan >>$UMLMAKE
done

# now, execute the Makefile that we have created!
cd $POOLSPACE && make $FREESWANHOSTS 

    
#
# $Log: make-uml.sh,v $
# Revision 1.31  2003/04/10 02:41:15  mcr
# 	fix location of </dev/null redirects.
#
# Revision 1.30  2003/04/09 04:21:52  build
# 	make sure that stdin is /dev/null when building kernels to
# 	keep "rm" from thinking it should prompt!
#
# Revision 1.29  2003/04/03 23:41:46  mcr
# 	note if we couldn't find a patch we were told exists
#
# Revision 1.28  2002/12/18 17:33:33  mcr
# 	apply local patches, if any are found.
#
# Revision 1.27  2002/11/11 02:44:25  mcr
# 	add ability to provide per-UML-patch patches in case we need
# 	to use a particular iteration of UML, but there are still
# 	problems with it.
#
# Revision 1.26  2002/08/26 15:37:27  mcr
# 	used wrong sense when looking for NONINTPATCH, -z is needed.
#
# Revision 1.25  2002/08/25 19:39:15  mcr
# 	added missing "then" to NONINTPATCH test.
#
# Revision 1.24  2002/08/25 17:39:45  mcr
# 	apply the RH nonint-config patch if we can find it
# 	either in $TESTINGROOT, or via $NONINTPATCH.
#
# Revision 1.23  2002/08/05 00:27:43  mcr
# 	do not install FreeSWAN for "regular hosts"
#
# Revision 1.22  2002/08/02 22:33:30  mcr
# 	call setup_make for common makefile portions.
#
# Revision 1.21  2002/07/29 02:46:09  mcr
# 	move setting of TESTINGROOT to before setup_host_make where it
# 	is in fact used.
# 	make the regular hosts after making their kernel.
#
# Revision 1.20  2002/07/29 01:02:20  mcr
# 	instead of actually doing all the operations, build
# 	a makefile in $POOLSPACE that will do it whenever necessary.
#
# Revision 1.18  2002/06/17 04:23:13  mcr
# 	make-uml.sh is mature enough to not need set -x now.
#
# Revision 1.17  2002/06/03 01:23:36  mcr
# 	added "nopromptgo" and "rcf" to provide documented "oldgo" and "ocf"
# 	functionality.
# 	"oldgo" and "ocf" now will permit interaction with the user as
# 	permitted (and undocumented) by many users.
#
# Revision 1.16  2002/04/24 07:55:32  mcr
# 	#include patches and Makefiles for post-reorg compilation.
#
# Revision 1.15  2002/04/05 01:21:39  mcr
# 	make-uml script was building statically linked FreeSWAN kernels
# 	only by fluke - turns out that "make oldconfig" blows away
# 	any options in .config that weren't defined. Thus, the initial
# 	build of a non-SWAN kernel before building FreeSWAN would
# 	blow away the CONFIG_IPSEC options- specifically the CONFIG_IPSEC=y
# 	(vs =m). This worked before because "make insert" put the
# 	options back in, but now that the default has changed to modules,
# 	the it defaults the wrong way.
# 	Solution: copy the .config file in again after the plain build.
#
# Revision 1.14  2002/04/03 23:42:18  mcr
# 	force copy of swan kernel config file to get right IPSEC=y options.
# 	redirect some build output to a local file.
#
# Revision 1.13  2002/02/16 20:56:06  rgb
# Force make programs so UML does not depend on top level make programs.
#
# Revision 1.12  2002/02/13 21:39:16  mcr
# 	change to use uml*.config files instead.
# 	uml*.config files have been updated for 2.4.7-10 UML patch.
#
# Revision 1.11  2002/01/11 05:26:03  rgb
# Fixed missing semicolon bug.
#
# Revision 1.10  2001/11/27 05:36:30  mcr
# 	just look for a kernel in build directory. This
# 	type of "optomization" is dumb - it should be a makefile.
#
# Revision 1.9  2001/11/23 00:36:01  mcr
# 	take $FREESWANDIR as command line argument.
# 	use HS's "devready" instead of fudging our own.
#
# Revision 1.8  2001/11/22 05:46:07  henry
# new version stuff makes version.c obsolete
#
# Revision 1.7  2001/11/07 20:10:20  mcr
# 	revised setup comments after RGB consultation.
# 	removed all non-variables from umlsetup-sample.sh.
#
# Revision 1.6  2001/11/07 19:25:17  mcr
# 	split out some functions from make-uml.
#
# Revision 1.5  2001/10/28 23:52:22  mcr
# 	pathnames need to be fully qualified.
#
# Revision 1.4  2001/10/23 16:32:08  mcr
# 	make log files unique to each UML.
#
# Revision 1.3  2001/10/15 05:41:46  mcr
# 	moved variables for UML setup to common file.
# 	provided sample of this file.
#
# Revision 1.2  2001/09/25 01:09:53  mcr
# 	some minor changes to whether to run "KERNDEP"
#
# Revision 1.1  2001/09/25 00:52:16  mcr
# 	a script to build a UML+FreeSWAN testing environment.
#
#    
