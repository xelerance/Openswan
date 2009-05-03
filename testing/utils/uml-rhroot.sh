#!/bin/sh

# don't touch below
rpmcanon() {
    rpm=$1
    for i in `eval echo $d1/$rpm*.rpm $d2/$rpm*.rpm`
    do
	if [ -r $i ]
        then
	    echo $i
	fi
    done
}

nri() {
    list=`for i; do rpmcanon $i; done`
    rpm --root=$root -i $list
}

usage() {
    echo "Usage: $0 rootdir cdimagedir" >&2
    exit 2
}

# ARG1 is space to build root image
# ARG2 is pointer to CDs images/etc.

if [ ! -w / ]
then
    echo unfortunately, you have to run me as root, since I need chroot.
fi

root=$1; shift
if [ -z "$root" ]
then
    usage;
fi

if [ -d $root/* ]
then
    echo Root space $root has stuff in it, aborting.
    exit 0
fi

uproot=`dirname $root`
if [ ! -w $uproot ]
then
    echo $uproot is not writable.
    exit 1
fi

image=$1; shift
if [ -z "$image" ] || [ ! -d $image ]
then
    usage;
fi

if [ -d $image/RedHat/RPMS ]
then
    d1=$image/RedHat/RPMS
    d2=$image/RedHat/RPMS
    echo "Assuming merged RH disc1/2 at $d1"
elif [ -d $image/disc1 ] && [ -d $image/disc2 ]
then
    d1=$image/disc1/RedHat/RPMS
    d2=$image/disc2/RedHat/RPMS
    echo "Assuming RH disc1 at $d1"
    echo "        and disc2 at $d2"
elif [ -r $image/basesystem-*.rpm ]
then
    d1=$image
    echo "Assuming download RPMS directory at $d1"
fi
    

mkdir -p $root/var/lib/rpm
mkdir -p $root/etc $root/usr/bin $root/bin $root/usr/lib $root/lib
mkdir -p $root/usr/bin $root/etc/X11/applnk/System $root/usr/include


rpm --root=$root --initdb

nri basesystem setup filesystem "glibc-[0-9.]*.i386" glibc-common- "slang-[0-9]" "newt-[0-9]" popt- 

nri info- makeinfo- mktemp- shadow-utils- ntsysv- syslinux- \
	libtermcap- bzip2- libstdc++- logrotate- \
	modutils- diffutils- fileutils- findutils- \
	grep- gzip- psmisc- readline- rootfiles- \
	console-tools- tar- textutils- \
	mount- tmpwatch- vim-common- \
	which- passwd- zlib- util-linux- \
	chkconfig- db1- "db3-[0-9]" e2fsprogs- \
	file- iputils- losetup- mingetty- \
	net-tools- pwdb- netconfig- termcap- \
	bash- crontabs- iproute- MAKEDEV- \
	"ncurses-[0-9]" cpio- ed- gawk- less- \
	procps- redhat-release- sed- sysklogd- \
	dev- time- vim-minimal- pam- \
	sh-utils- SysVinit- rpm-4 mingetty- \
	initscripts- cracklib fileutils- textutils- glib- \
	termcap- bzip2-libs info krbafs words krb5-libs-

# do one fixup, not clear why!
(cd $root/lib; ln -fs libtermcap.so.2.* libtermcap.so.2 )

# fixup password file
chroot $root pwconv

# should now chown it to yourself.
echo You should now chown it to yourself.
# now copy some UML friendly files in
#(cd umlroot; tar cf - . ) | (cd $root; tar xf - )

