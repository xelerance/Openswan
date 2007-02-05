#! /bin/sh 
#
# 
# $Id: uml-functions.sh,v 1.45 2005/11/21 08:44:57 mcr Exp $
#

setup_make() {
    domodules=$1

    TAB="	@"
    depends=""

    echo "# RULES for making module"

    # figure out our base architecture, as we'll need in the Makefiles.
    SUBARCH=${ARCH-`uname -m`}
    case $SUBARCH in
	i?86) SUBARCH=i386;;
    esac

    echo "IPSECDIR=${OPENSWANSRCDIR}/linux/net/ipsec"
    echo "USE_OBJDIR=${USE_OBJDIR}"
    echo "OPENSWANSRCDIR=${OPENSWANSRCDIR}"
    echo "include ${OPENSWANSRCDIR}/Makefile.inc"
    echo "include ${OPENSWANSRCDIR}/Makefile.ver"
    echo 
    
    echo "all: "
    echo "$TAB echo Default make called"
    echo "$TAB exit 1"
    echo

    if $domodules
    then
	echo "module/ipsec.o: ${OPENSWANSRCDIR}/packaging/makefiles/module.make \${IPSECDIR}/*.c"
	echo "$TAB mkdir -p module"
	echo "$TAB make -C ${OPENSWANSRCDIR} OPENSWANSRCDIR=${OPENSWANSRCDIR} MODBUILDDIR=$POOLSPACE/module MODBUILDDIR=$POOLSPACE/module KERNELSRC=$UMLPLAIN ARCH=um SUBARCH=${SUBARCH} module "
	echo

	echo "module26/ipsec.ko: ${OPENSWANSRCDIR}/packaging/makefiles/module26.make \${IPSECDIR}/*.c"
	echo "$TAB mkdir -p module26"
	echo "$TAB make -C ${OPENSWANSRCDIR} OPENSWANSRCDIR=${OPENSWANSRCDIR} MODBUILDDIR=$POOLSPACE/module MOD26BUILDDIR=$POOLSPACE/module26 KERNELSRC=$UMLPLAIN ARCH=um SUBARCH=${SUBARCH} module26 "
	echo
    fi

    # now describe how to build the initrd.
    echo "initrd.uml: ${OPENSWANSRCDIR}/testing/utils/initrd.list"
    echo "$TAB fakeroot ${OPENSWANSRCDIR}/testing/utils/buildinitrd ${OPENSWANSRCDIR}/testing/utils/initrd.list ${OPENSWANSRCDIR} ${BASICROOT}" 
}

# output should directed to a Makefile
setup_host_make() {
    host=$1
    KERNEL=$2
    HOSTTYPE=$3
    KERNVER=$4
    domodules=$5          # true or false
    KERNDIR=`dirname $KERNEL`
    TAB="	@"
    hostroot=$host/root
    depends=""

    echo "# RULES for host $host"
    echo 

    echo "$hostroot:"
    echo "$TAB mkdir -p $host $hostroot"
    echo
    depends="$depends $host/root"

    echo "# make a hard link copy of the ROOT, but"
    echo "# make private copy of /var."
    echo "$hostroot/sbin/init : ${BASICROOT}/sbin/init"
    echo "$TAB -(cd ${BASICROOT} && find . -print | cpio -pld $POOLSPACE/$hostroot 2>/dev/null )"
    echo "$TAB rm -rf $hostroot/var"

    echo "$TAB (cd ${BASICROOT} && find var -print | cpio -pd $POOLSPACE/$hostroot 2>/dev/null )"

    # make sure that we have /dev, /tmp and /var/run
    echo "$TAB mkdir -p $hostroot/dev $hostroot/tmp $hostroot/var/run $hostroot/usr/share $hostroot/proc $hostroot/var/log/pluto/peer"
    echo "$TAB rm -f $hostroot/dev/console $hostroot/dev/null"
    echo "$TAB touch $hostroot/dev/console $hostroot/dev/null"

    # root image may be debian, but we expect rh-style /etc/rc.d
    echo "$TAB mkdir -p $hostroot/etc/rc.d"
    echo "$TAB mkdir -p $hostroot/testing $hostroot/usr/src $hostroot/usr/obj"
    echo "$TAB if [ ! -d $hostroot/etc/rc.d/init.d ]; then (cd $hostroot/etc/rc.d && ln -fs ../init.d ../rc?.d . ); fi"

    # nuke certain other files that get in the way of booting
    echo "$TAB rm -f $hostroot/etc/mtab $hostroot/sbin/hwclock"

    # set up the timezone
    echo "$TAB rm -f $hostroot/etc/localtime "

    # dummy out fsck.
    echo "$TAB ln -f $hostroot/bin/true $hostroot/sbin/fsck.hostfs"

    # force it to GMT, otherwise (RH7.1) use host's zoneinfo.
    if [ -f /usr/share/zoneinfo/GMT ] 
    then
      echo "$TAB cp /usr/share/zoneinfo/GMT $hostroot/etc/localtime"
    else
      echo "$TAB cp /etc/localtime $hostroot/etc/localtime"
    fi

    # now remove any files that we shouldn't have copied.
    echo "$TAB (cd ${TESTINGROOT}/baseconfigs/all && find . -type f -print) | (cd $hostroot && xargs rm -f)"
    echo "$TAB (cd ${TESTINGROOT}/baseconfigs/$host && find . -type f -print) | (cd $hostroot && xargs rm -f)"
    # okay, that's all the stock stuff
    echo 
    depends="$depends $hostroot/sbin/init"

    # copy global configuration files, and make sure that they are up-to-date.
    (cd ${TESTINGROOT}/baseconfigs/all && find . -type f -print) | sed -e 's,^\./,,' >makeuml.$$
    echo -n >makeuml2.$$
    cat makeuml.$$ | while read file
    do
        case $file in
	    *~) ;;
	    *CVS/*);;
	    */.\#*);;
	    etc/fstab);;
	    *) echo "$hostroot/$file : ${TESTINGROOT}/baseconfigs/all/$file $hostroot"
	       echo "$TAB rm -f $hostroot/$file && mkdir -p `dirname $hostroot/$file` && cp ${TESTINGROOT}/baseconfigs/all/$file $hostroot/$file"
	       echo
	       echo -n $hostroot/$file ' ' >>makeuml2.$$
	esac
    done	 
    nicelists=`cat makeuml2.$$`
    depends="$depends $nicelists"
    rm -f makeuml.$$ makeuml2.$$

    # copy configuration files, but make sure that they are up-to-date.
    (cd ${TESTINGROOT}/baseconfigs/$host && find . -type f -print) | sed -e 's,^\./,,'  >makeuml.$$
    echo -n >makeuml2.$$
    cat makeuml.$$ | while read file
    do
        case $file in
	    *~) ;;
	    *CVS/*);;
	    etc/fstab);;
	    */.\#*);;
	    *) echo "$hostroot/$file : ${TESTINGROOT}/baseconfigs/$host/$file $hostroot"
	       echo "$TAB rm -f $hostroot/$file && mkdir -p `dirname $hostroot/$file` && cp ${TESTINGROOT}/baseconfigs/$host/$file $hostroot/$file"
	       echo
	       echo -n $hostroot/$file ' ' >>makeuml2.$$
	esac
    done	 
 
    nicelists=`cat makeuml2.$$`
    depends="$depends $nicelists"
    rm -f makeuml.$$ makeuml2.$$

    # setup the mount of /usr/share
    echo "$hostroot/etc/fstab : ${TESTINGROOT}/baseconfigs/$host/etc/fstab"
    echo "$TAB cp ${TESTINGROOT}/baseconfigs/$host/etc/fstab $hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/share		     hostfs   defaults,ro,$SHAREROOT 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /testing		     hostfs   defaults,ro,${TESTINGROOT} 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/src		     hostfs   defaults,ro,${OPENSWANSRCDIR} 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/obj		     hostfs   defaults,ro,\${OBJDIRTOP} 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /usr/local		     hostfs   defaults,rw,${POOLSPACE}/${hostroot}/usr/local 0 0 >>$hostroot/etc/fstab"
    echo "$TAB echo none	   /var/tmp		     hostfs   defaults,rw,${POOLSPACE}/${hostroot}/var/tmp 0 0 >>$hostroot/etc/fstab"
    depends="$depends $hostroot/etc/fstab"

    # split Debian "interfaces" file into RH ifcfg-* file
    echo "$hostroot/etc/sysconfig/network-scripts/ifcfg-eth0: $hostroot/etc/network/interfaces"
    echo "$TAB mkdir -p $hostroot/etc/sysconfig/network-scripts"
    echo "$TAB ${TESTINGROOT}/utils/interfaces2ifcfg.pl $hostroot/etc/network/interfaces $hostroot/etc/sysconfig/network-scripts"
    echo
    depends="$depends $hostroot/etc/sysconfig/network-scripts/ifcfg-eth0"

    if [ "X$HOSTTYPE" == "Xopenswan" ]
    then
	# install FreeSWAN if appropriate.
        
	echo "$hostroot/usr/local/sbin/ipsec : ${OPENSWANSRCDIR}/Makefile.inc ${OPENSWANSRCDIR}/Makefile.ver"
	echo "$TAB cd ${OPENSWANSRCDIR} && make DESTDIR=$POOLSPACE/$hostroot USE_OBJDIR=true install"
	echo
	depends="$depends $hostroot/usr/local/sbin/ipsec"

	case ${KERNVER} in
	    26) DOTO=".ko";;
	    *) DOTO=".o";;
	esac

	if $domodules
	then
	    # update the module, if any.
	    echo "$hostroot/ipsec.o : module${KERNVER}/ipsec${DOTO} $hostroot"
	    echo "$TAB -cp module${KERNVER}/ipsec${DOTO} $hostroot/ipsec.o"
	    echo
	    depends="$depends $hostroot/ipsec.o"

	    # make module startup script
	    startscript=$POOLSPACE/$host/startmodule.sh
	    echo "$startscript : $OPENSWANSRCDIR/umlsetup.sh $hostroot/ipsec.o initrd.uml"
	    echo "$TAB echo '#!/bin/sh' >$startscript"
	    echo "$TAB echo ''          >>$startscript"
	    echo "$TAB echo '# get $net value from baseconfig'          >>$startscript"
	    echo "$TAB echo . ${TESTINGROOT}/baseconfigs/net.$host.sh   >>$startscript"
	    echo "$TAB echo ''          >>$startscript"
	    echo "$TAB # the umlroot= is a local hack >>$startscript"
	    echo "$TAB echo '$POOLSPACE/plain${KERNVER}/linux initrd=$POOLSPACE/initrd.uml umlroot=$POOLSPACE/$hostroot root=/dev/ram0 rw ssl=pty umid=$host \$\$net \$\$UML_DEBUG_OPT \$\$UML_"${host}"_OPT  init=/linuxrc gim\$\$*' >>$startscript"
	    echo "$TAB chmod +x $startscript"
	    echo
	    depends="$depends $startscript"
	fi
    fi

    # make startup script
    startscript=$POOLSPACE/$host/start.sh
    echo "$startscript : $OPENSWANSRCDIR/umlsetup.sh initrd.uml"
    echo "$TAB echo '#!/bin/sh' >$startscript"
    echo "$TAB echo ''          >>$startscript"
    echo "$TAB echo '# get $net value from baseconfig'          >>$startscript"
    echo "$TAB echo . ${TESTINGROOT}/baseconfigs/net.$host.sh   >>$startscript"
    echo "$TAB echo ''          >>$startscript"
    echo "$TAB # the umlroot= is a local hack >>$startscript"
    echo "$TAB echo '$KERNEL initrd=$POOLSPACE/initrd.uml umlroot=$POOLSPACE/$hostroot root=/dev/ram0 rw ssl=pty umid=$host \$\$net \$\$UML_DEBUG_OPT \$\$UML_"${host}"_OPT  init=/linuxrc \$\$*' >>$startscript"
    echo "$TAB echo 'if [ -n \"\$\$UML_SLEEP\" ]; then eval \$\$UML_SLEEP; fi'  >>$startscript"
    echo "$TAB chmod +x $startscript"
    echo
    depends="$depends $startscript"

    echo "$host : $depends"
    echo "$TAB for dir in ${UML_extra_DIRS-x}; do (if [ -d \$\$dir ]; then echo installing in \$\$dir; cd \$\$dir && make DESTDIR=$POOLSPACE/$hostroot install; fi); done;"
    echo
}

setup_host() {
    host=$1
    KERNEL=$2
    KERNDIR=`dirname $KERNEL`

    hostroot=$POOLSPACE/$host/root
    mkdir -p $hostroot
    # copy (with hard links) 
    (cd ${BASICROOT} && find . -print | cpio -pld $hostroot 2>/dev/null )

    # make private copy of /var.
    rm -rf $hostroot/var
    (cd ${BASICROOT} && find var -print | cpio -pd $hostroot 2>/dev/null )

    # make sure that we have /dev, /tmp and /var/run
    mkdir -p $hostroot/dev $hostroot/tmp $hostroot/var/run $hostroot/usr/share $hostroot/proc

    # root image is debian, but FreeSWAN expects redhat
    mkdir -p $hostroot/etc/rc.d
    if [ ! -d $hostroot/etc/rc.d/init.d ]
    then
      (cd $hostroot/etc/rc.d && ln -fs ../init.d ../rc?.d . )
    fi
    
    # nuke certain other files that get in the way of booting
    rm -f $hostroot/etc/mtab
    rm -f $hostroot/sbin/hwclock

    # set up the timezone
    rm -f $hostroot/etc/localtime 

    # dummy out fsck.
    ln -f $hostroot/bin/true $hostroot/sbin/fsck.hostfs

    # force it to GMT, otherwise (RH7.1) use host's zoneinfo.
    if [ -f /usr/share/zoneinfo/GMT ] 
    then
      cp /usr/share/zoneinfo/GMT $hostroot/etc/localtime
    else
      cp /etc/localtime $hostroot/etc/localtime
    fi

    # or, you might want to force it to local
    # cp /etc/localtime $hostroot/etc/localtime

    # copy configuration files
    ### XXX this should be done with a generated Makefile.
    (cd ${TESTINGROOT}/baseconfigs/$host && tar cf - .) | (cd $hostroot && tar -x -f - --unlink-first)

    # setup the mount of /usr/share
    echo "none	   /usr/share		     hostfs   defaults,ro,$SHAREROOT 0 0" >>$hostroot/etc/fstab

    # split Debian "interfaces" file into RH ifcfg-* file
    mkdir -p $hostroot/etc/sysconfig/network-scripts
    ${TESTINGROOT}/utils/interfaces2ifcfg.pl $hostroot/etc/network/interfaces $hostroot/etc/sysconfig/network-scripts

    # make startup script
    startscript=$POOLSPACE/$host/start.sh
    if [ ! -f $startscript ]
    then
	echo '#!/bin/sh' >$startscript
	echo ''          >>$startscript
	echo '# get $net value from baseconfig'          >>$startscript
	echo ". ${TESTINGROOT}/baseconfigs/net.$host.sh" >>$startscript
	echo ''          >>$startscript
	echo "$KERNEL ubd0=$hostroot umid=$host \$net \$UML_DEBUG_OPT \$UML_$host_OPT \$*" >>$startscript
	chmod +x $startscript
    fi
}

applypatches() {
    if [ ! -d arch/um/.PATCHAPPLIED ] 
    then
	echo Applying $UMLPATCH

	if [ "$UMLPATCH" != "none" ] && [ "$UMLPATCH" != /dev/null ]
	then
	    if bzcat $UMLPATCH | patch -p1 
	    then
		:
	    else
		echo "Failed to apply UML patch: $UMLPATCH"
		exit 1;
	    fi
        fi

	if [ -n "$UMLPATCH2" ] && [ -f $UMLPATCH2 ]
	then
		echo Applying $UMLPATCH2
		if bzcat $UMLPATCH2 | patch -p1 
		then
		    :
		else
		    echo "Failed to apply UML patch: $UMLPATCH2"
		    exit 1;
		fi
	fi

	if [ -n "$NONINTPATCH" ] && [ "$NONINTPATCH" != "none" ]
	then
	    if [ -f "$NONINTPATCH" ]
	    then
		echo Applying non-interactive config patch
		cat $NONINTPATCH | patch -p1
		NONINTCONFIG=oldconfig_nonint
	    else
		echo Can not find +$NONINTPATCH+
		exit 1
	    fi
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
	mkdir -p arch/um/.PATCHAPPLIED

	if $NATTPATCH
	then
	    echo Applying the NAT-Traversal patch
	    (cd $OPENSWANSRCDIR && make nattpatch${KERNVERSION} ) | patch -p1
	else
            echo Not applying the NAT-Traversal patch
	fi
    fi
}

lndirkerndirnogit() {
    origin=$1
    dest=$2

    ( cd $dest
	stuff=`cd $origin; echo *`
	for t in $stuff; do
	  if [ -d $origin/$t ]; then
	     mkdir -p $t; (cd $t && lndir -silent $origin/$t .);
	  else
             ln -s -f $origin/$t .
          fi
        done
    )
}



