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
# RCSID $Id: Makefile,v 1.5 2005/08/05 17:04:54 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/testing/lib/libpluto/
include $(OPENSWANSRCDIR)/Makefile.inc

SUBDIRS=
SRCDIR=${srcdir}
UTILS=${OPENSWANSRCDIR}/testing/utils

TESTS=$(shell awk '{print $$2;}' ${srcdir}TESTLIST)

all: ${TESTS}
	echo ${TESTS}

one:
	export OPENSWANLIB=${OPENSWANLIB} REGRESSRESULTS=$${REGRESSRESULTS-../results} ; source ${UTILS}/functions.sh; eval `grep ${TEST} TESTLIST`

refineconnection: refineconnection.c lib-refineconnection/testlist.sh OUTPUT.refineconnection.txt FLAGS.refineconnection
	source ${UTILS}/functions.sh; multilibtest `basename $< .c`

def:
	@echo "Please read doc/intro.html or INSTALL before running make"
	@false

check:
	@ECHO=: REGRESSRESULTS=$${REGRESSRESULTS-../results} ; source ${UTILS}/functions.sh; source ${srcdir}TESTLIST

install install_file_list checkprograms programs:
	@true

clean:
	cat ${srcdir}TESTLIST | while read testtype name status; \
	do\
		rm -rf `basename $$name .c`;\
	done

ike-secrets.txt: OUTPUT.parentI2.txt
	grep '../parentI2 ikev2 [IR]' OUTPUT.parentI2.txt | cut -c13- >ike-secrets.txt

cleanall: clean

distclean: clean

mostlyclean: clean

realclean: clean

depend:
	(source ${UTILS}/functions.sh; ls *.c | (while read file; do echo 'Calculating depends for '$$file >&2; ECHO=':' MOREFLAGS=-MM complibtest .Makefile.depend.$$file.${OSDEP} $$file >&2; cat .Makefile.depend.$$file.${OSDEP}; done) | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend.${OSDEP})

-include ${srcdir}Makefile.depend.${OSDEP}


east.record: ${OPENSWANSRCDIR}/programs/pluto/rcv_whack.c
	(cd ${OPENSWANSRCDIR}/programs/pluto && unset OPENSWANSRCDIR && pl_inst.sh)
	(cd ${OPENSWANSRCDIR}/testing/pluto/whackrecord-01 && ../../utils/runme.sh )
	source ${OPENSWANSRCDIR}/umlsetup.sh; cp $$POOLSPACE/east/root/var/tmp/east.record .
