# FreeS/WAN testing makefile
# Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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
# RCSID $Id: Makefile,v 1.5 2003/02/17 02:34:38 mcr Exp $

FREESWANSRCDIR=../..
export FREESWANSRCDIR
include $(FREESWANSRCDIR)/Makefile.inc

SUBDIRS=
UTILS=${FREESWANSRCDIR}/testing/utils

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check: 	${FREESWANSRCDIR}/umlsetup.sh
	source ${FREESWANSRCDIR}/umlsetup.sh; source setup.sh; source ${UTILS}/functions.sh; source TESTLIST

spotcheck:
	@source ${FREESWANSRCDIR}/umlsetup.sh; source setup.sh; source $${UTILS}/functions.sh; eval `sed -e '/^#/d' TESTLIST | perl $${UTILS}/shuffle.pl 1`

install install_file_list checkprograms programs:
	@true

clean:
	grep -v '^#' TESTLIST | while read testtype name status; \
	do\
		rm -rf $$name/OUTPUT; \
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

#
# $Log: Makefile,v $
# Revision 1.5  2003/02/17 02:34:38  mcr
# 	adjusted "make clean" target in Makefiles.
#
# Revision 1.4  2002/11/01 02:28:29  mcr
# 	added "make spotcheck" which runs a randomly selected
# 	test from the TESTLIST.
#
# Revision 1.3  2002/08/08 01:52:32  mcr
# 	the "make clean" script should ignore comments in the TESTLIST.
#
# Revision 1.2  2002/06/19 09:22:23  mcr
# 	enable pluto tests by default.
#
# Revision 1.1  2002/06/19 07:16:23  mcr
# 	first prototype of 2-UML tests for pluto.
#
# Revision 1.1  2002/06/08 17:41:22  mcr
# 	library test routines.
#
# 



