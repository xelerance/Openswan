# Openswan library
# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#

OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

srcdir?=${OPENSWANSRCDIR}/lib/liboswkeys/

LIBRARY=oswkeys
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

# just always turn on these two.
CFLAGS+=-DUSE_SHA2 -DUSE_AES

ONEFILE=x509dn.c
SRCS=asn1.c certload.c pem.c pgp.c pkcs.c x509dn.c ocsp.c
SRCS+=rsapub.c
SRCS+=x509cert.c x509lists.c oid.c x509chain.c der.c
ifeq ($(USE_LIBNSS),true)
SRCS+=signatures_nss.c
else
SRCS+=signatures.c
endif

OBJS=${SRCS:.c=.o}

include ${srcdir}../Makefile.library

