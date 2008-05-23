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
#
# RCSID $Id: Makefile,v 1.22 2005/07/29 21:52:52 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ..; pwd)
srcdir?=${OPENSWANSRCDIR}/programs/

include ${OPENSWANSRCDIR}/Makefile.inc

SUBDIRS=

ifeq ($(USE_KLIPS),true)
SUBDIRS+=spi eroute spigrp tncfg klipsdebug pf_key
endif

ifeq ($(USE_LWRES),true)
SUBDIRS+=lwdnsq
endif

ifeq ($(USE_IPSECPOLICY),true)
SUBDIRS+=showpolicy
endif

SUBDIRS+=proc pluto addconn 
SUBDIRS+=_confread _copyright _include _keycensor _plutoload _plutorun
SUBDIRS+=_realsetup _secretcensor _startklips _updown _updown.klips _updown.mast
SUBDIRS+=auto barf verify ipsec look newhostkey ranbits secrets
SUBDIRS+=rsasigkey setup showdefaults showhostkey 
SUBDIRS+=ikeping examples livetest
ifeq ($(USE_KLIPS),true)
SUBDIRS+= _startklips _updown.klips 
endif
ifeq ($(USE_MAST),true)
SUBDIRS+= _updown.mast 
endif
ifeq ($(USE_NETKEY),true)
SUBDIRS+= _startnetkey _updown.netkey
endif

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

# programs

cleanall distclean mostlyclean realclean install programs checkprograms check clean spotless install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${srcdir}$$d/ OPENSWANSRCDIR=$(OPENSWANSRCDIR) $@ ) || exit 1;\
	done; \

