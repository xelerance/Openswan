# Makefile for the ike aggressive denial of service attacker
#
# Copyright (C) 2006  Michael Richardson <mcr@xelerance.com>
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

LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
include ${LIBRESWANSRCDIR}/Makefile.inc

PROGRAM=ike-aggr-dos
OBJS=checksum.o

VPATH += ${LIBRESWANSRCDIR}/testing/kunit/libkern

#LIBS=${LIBRESWANLIB}
EXTRALIBS=-lpcap

include ${LIBRESWANSRCDIR}/programs/Makefile.program


