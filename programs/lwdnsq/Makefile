# Makefile for the KLIPS interface utilities
# Copyright (C) 1998, 1999  Henry Spencer.
# Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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

PROGRAM:=lwdnsq

OBJS:=cmds.o lookup.o

LWRESINCL=${LWRESDIR}/include

LIBS:=${OPENSWANLIB} ${LIBLWRES} ${LIBDNS} ${LIBISC}

ifdef BIND9INCDIR
CFLAGS+=-I${BIND9INCDIR}
endif

CFLAGS+=-I../../lib/libisc/include 
CFLAGS+=-I../../lib/libdns/include 
CFLAGS+=-I../../lib/liblwres/include 

CFLAGS+=-I${srcdir}../../lib/libisc/nothreads/include 

CFLAGS+=-I${srcdir}../../lib/libisc/${ISCARCH}/include 
CFLAGS+=-I${srcdir}../../lib/libdns/${ISCARCH}/include 
CFLAGS+=-I${srcdir}../../lib/liblwres/${ISCARCH}/include 

CFLAGS+=-I${srcdir}../../lib/libisc/include 
CFLAGS+=-I${srcdir}../../lib/libdns/include 
CFLAGS+=-I${srcdir}../../lib/liblwres/include 

# for debugging
#CFLAGS+=-DEFENCE
#LIBS+=-lefence

#USERCOMPILE=-g


include ${srcdir}../Makefile.program

lwdnsq.8: lwdnsq.xml
	xmlto man lwdnsq.xml

lwdnsq.xml: lwdnsq.xml.in

TAGS: 
	etags *.[ch] ../../lib/liblwres/*.[ch] ../../lib/liblwres/include/lwres/*.h

# manually maintained dependancies
lwdnsq.o:	lwdnsq.c lwdnsq.h 
cmds.o:		cmds.c lwdnsq.h
lookup.o:	lookup.c lwdnsq.h
