#!/bin/bash

# This script downloads everything you need and sets up a UML.

HERE=`pwd`
set -e
set -u

echo I will setup UML at $HERE. I need 400Mbytes of space.

df -m . | grep -v 'Filesystem' | read device size used avail rest
if [ $avail -lt 400 ]
then
    echo there is not enough disk space here.
    df -H .
    exit 1
fi

echo -n I found enough space. Hit enter to proceed. ^C to abort.
read ans

# okay, we are read.
mkdir -p download
mkdir -p sandboxes
mkdir -p bin

# things that I need.
# XXX add UML utilities
# XXX check signatures
#
LINUX=linux-2.4.19
UMLPATCH=uml-patch-2.4.19-47.bz2
UMLROOT=umlfreeroot-15.1.tar.gz
LIBPCAPTAR=libpcap-0.7.2.tar.gz
TCPDUMPTAR=tcpdump-3.7.2.tar.gz
URLs="ftp://ftp.nrc.ca/pub/linux/kernel/v2.4/$LINUX.tar.gz
      http://ftp.nl.linux.org/uml/$UMLPATCH
      http://www.sandelman.ca/freeswan/uml/$UMLROOT
      http://www.tcpdump.org/releases/$LIBPCAPTAR
      http://www.tcpdump.org/releases/$TCPDUMPTAR
      ftp://ftp.xs4all.nl/pub/crypto/freeswan/snapshots/snapshot.tar.gz"

cd download
for file in $URLs
do
    wget -m $file
    wget -m $file.sig
done

# XXX check signatures!
pgp snapshot.tar.gz.sig

cd $HERE

# extract things
zcat download/$LINUX.tar.gz | tar xf -
zcat download/$UMLROOT | tar xf - 

# setup link
ln -f -s root-* root

# build tcpdump.
cd sandboxes
zcat ../download/$LIBPCAPTAR | tar xf -
(cd libpcap-0.7.2 && ./configure --prefix=$HERE && make && make install)

zcat ../download/$TCPDUMPTAR | tar xf -
(cd tcpdump-3.7.2 && ./configure --prefix=$HERE && make && make install)

TCPDUMP=$HERE/bin/tcpdump
if ($TCPDUMP --version | grep 'tcpdump version 3.7')
then
    :
else
    exit 1
fi

cd sandboxes
zcat ../download/snapshot.tar.gz | tar xf -
cd freeswan-*
FREESWAN=`pwd`

# now setup the umlsetup.sh

date >umlsetup.sh
echo POOLSPACE=$FREESWAN/UMLPOOL export POOLSPACE           >>umlsetup.sh
echo BUILDTOP=$FREESWAN          export BUILDTOP            >>umlsetup.sh
echo KERNPOOL=$HERE/$LINUX       export KERNPOOL            >>umlsetup.sh
echo UMLPATCH=$HERE/download/$UMLPATCH export UMLPATCH      >>umlsetup.sh
echo BASICROOT=$HERE/root        export BASICROOT           >>umlsetup.sh
echo SHAREDIR=$BASICROOT/usr/share export SHAREDIR          >>umlsetup.sh

echo REGULARHOSTS='sunrise sunset nic sec carrot beet' >>umlsetup.sh
echo FREESWANHOSTS='east west japan' >>umlsetup.sh

echo BIND9STATICLIBDIR=/usr/local/bind9 export BIND9STATICLIBDIR >>umlsetup.sh

echo 'REGRESSRESULTS=${POOLSPACE}/results' >>umlsetup.sh
echo 'FREESWANDIR=$BUILDTOP'               >>umlsetup.sh

make check






      
      

