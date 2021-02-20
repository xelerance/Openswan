# Openswan library for pluto
#
# mostly contains minor support items that are placed here to make unit testing
# of pluto easier. Generally, this code can depend upon -lopenswan, and -loswlog,
# it should not depend upon anything else (ideally, including other code in this
# this library)
#
# Copyright (C) 2007 Xelerance Corporation
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


OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

srcdir?=${OPENSWANSRCDIR}/lib/libpluto/

LIBRARY=pluto
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3
CFLAGS+=-DLEAK_DETECTIVE

# for access to qcbor code, submodule of libwhack
CFLAGS+=-I${OPENSWANSRCDIR}/lib/libwhack/qcbor/inc
CFLAGS+= -DQCBOR_DISABLE_FLOAT_HW_USE
CFLAGS+= -DQCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA

ONEFILE=pluto_constants.c
SRCS=defs.c db_ops.c db2_ops.c ai2db.c spdb_print.c
SRCS+=pluto_constants.c x509support.c packet.c
SRCS+=readwhackmsg.c rnd.c rndchunk.c writewhackmsg.c orient.c spd_format.c
SRCS+=endclienttot.c setproctitle.c iface.c
SRCS+=plutoctrl_cbor.c plutoopts.c

#enable to get lots more debugging about semantics.
#CFLAGS+=-DPARSER_TYPE_DEBUG

OBJS=${SRCS:.c=.o}

include ${srcdir}../Makefile.library

