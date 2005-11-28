#!/bin/sh

klips_git=/mara1/git/klips
openswan_git=/mara6/openswan/public.git

(cd $klips_git && find net/ipsec include/openswan* include/pfkey* -type f | cpio -pd $openswan_git/linux )

cd $openswan_git/linux/net/ipsec
if [ -f Makefile ]; then mv Makefile Makefile.fs2_6; fi

