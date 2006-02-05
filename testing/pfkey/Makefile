# FreeS/WAN subdir makefile
# Copyright (C) 1998-2001  Henry Spencer.
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
# RCSID $Id: Makefile,v 1.4 2005/05/24 00:51:44 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include $(OPENSWANSRCDIR)/Makefile.inc
include ${srcdir}Makefile.unit-settings

srcdir?=$(shell pwd)/

SUBDIRS=eroute-01

def:	check

# programs

check:	include/openswan.h include/linux/madelinks include/net/madelinks include/asm/madelinks

cleanall distclean mostlyclean realclean install programs checkprograms check clean spotless install_file_list:
	@for d in $(SUBDIRS) ; \
	do \
		(cd $$d && $(MAKE) srcdir=${srcdir}$$d/ OPENSWANSRCDIR=$(OPENSWANSRCDIR) $@ ) || exit 1;\
	done; 

# 
# Local Variables: 
# compile-command: "make"
# End: 
