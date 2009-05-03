#!/bin/sh

klips_git=/mara1/git/klips
openswan_git=`pwd`



(cd $klips_git && find net/ipsec include/openswan* include/pfkey* -type f | cpio -pdu $openswan_git/linux )

cd $openswan_git/linux/net/ipsec
if [ -f Makefile ]; then mv Makefile Makefile.fs2_6; fi
for dir in des aes alg 
do
	if [ -f $dir/Makefile ]; then mv $dir/Makefile $dir/Makefile.fs2_6; fi
done
rm version.c Makefile.ver

