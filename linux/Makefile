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
# RCSID $Id: Makefile,v 1.8 2004/04/03 19:44:41 ken Exp $

OPENSWANSRCDIR=..
#SUBDIRS=net/ipsec

include $(OPENSWANSRCDIR)/Makefile.inc

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

cleanall distclean mostlyclean realclean install programs checkprograms check clean spotless modules install_file_list:
	@true

#	@for d in $(SUBDIRS); \
#	do \
#		(cd $$d && $(MAKE) TOPDIR=${KERNELSRC} OPENSWANSRCDIR=$(OPENSWANSRCDIR)/.. $@ ) || exit 1 ; \
#	done

