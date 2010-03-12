#!/bin/sh

OPENSWANSRCDIR=/mara4/openswan-2/klips26
KERNELSRC=/mara4/openswan-2/klips26/UMLPOOL/plain26
MODULE_DEF_INCLUDE=${OPENSWANSRCDIR}/packaging/linus/config-all.h

export OPENSWANSRCDIR KERNELSRC MODULE_DEF_INCLUDE

#SUBDIRS=${OPENSWANSRCDIR}/linux/net/ipsec 

make --debug=biv -C ${KERNELSRC} V=1 BUILDDIR=`pwd` SUBDIRS=`pwd` MODULE_DEF_INCLUDE=${MODULE_DEF_INCLUDE} ARCH=um $*


