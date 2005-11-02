# Makefile for the KLIPS interface utilities
# Copyright (C) 2004 Michael Richardson <mcr@xelerance.com>
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
# RCSID $Id: Makefile,v 1.2 2004/04/10 03:36:10 mcr Exp $

###################################################
# Adjust SSLDIR before make ...
SSLDIR=/usr

###################################################

OPENSWANSRCDIR=../..
include ${OPENSWANSRCDIR}/Makefile.inc

PROGRAM=fswcert
CFLAGS += -DVERSION=\"$(IPSECVERSION)\" -I$(SSLDIR)/include
LDFLAGS = -L$(SSLDIR)/lib
LDLIBS = -lcrypto

fswcert.8: fswcert.pod
	pod2man fswcert.pod >fswcert.8

include ../Makefile.program

#
# $Log: Makefile,v $
# Revision 1.2  2004/04/10 03:36:10  mcr
# 	merged in BSD-compat changes.
#
#

