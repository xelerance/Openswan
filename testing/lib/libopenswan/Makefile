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
# RCSID $Id: Makefile,v 1.5 2005/01/24 01:13:13 mcr Exp $

OPENSWANSRCDIR=../../..
include $(OPENSWANSRCDIR)/Makefile.inc

SUBDIRS=
UTILS=${OPENSWANSRCDIR}/testing/utils

def:	check

check:
	export OPENSWANLIB=${OPENSWANLIB} REGRESSRESULTS=$${REGRESSRESULTS-../results} ; source ${UTILS}/functions.sh; source TESTLIST

one:
	export OPENSWANLIB=${OPENSWANLIB} REGRESSRESULTS=$${REGRESSRESULTS-../results} ; source ${UTILS}/functions.sh; eval `grep ${TEST} TESTLIST`

install install_file_list checkprograms programs:
	@true

clean:
	cat TESTLIST | while read testtype name status; \
	do\
		rm -rf `basename $$name .c`;\
	done

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

