#!/bin/sh

klips_git=/mara1/git/klips
libreswan_git=`pwd`



(cd $klips_git && find net/ipsec include/libreswan* include/pfkey* -type f | cpio -pdu $libreswan_git/linux )

cd $libreswan_git/linux/net/ipsec
if [ -f Makefile ]; then mv Makefile Makefile.fs2_6; fi
for dir in des aes alg 
do
	if [ -f $dir/Makefile ]; then mv $dir/Makefile $dir/Makefile.fs2_6; fi
done
rm version.c Makefile.ver

