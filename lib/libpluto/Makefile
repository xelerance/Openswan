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
#
# RCSID $Id: Makefile,v 1.20 2005/09/17 21:57:45 mcr Exp $


OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

LIBRARY=pluto
LIB=lib${LIBRARY}.a
MANDIR=$(MANTREE)/man3

ONEFILE=pluto_constants.c
SRCS=pluto_constants.c x509support.c
SRCS+=

#enable to get lots more debugging about semantics.
#CFLAGS=-DPARSER_TYPE_DEBUG

OBJS=${SRCS:.c=.o} 

include ${srcdir}../Makefile.library

