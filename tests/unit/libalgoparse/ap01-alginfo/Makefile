# Openswan testing makefile
# Copyright (C) 2016 Michael Richardson <mcr@xelerance.com>
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

OPENSWANSRCDIR?=$(shell cd ../../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto/lp01-spdbtest
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE}
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRALIBS+=${PLUTOLIB} ${CRYPTOLIBS} ${WHACKLIB}
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${LIBPLUTO} ${LIBALGOPARSE} ${CRYPTOLIBS} ${WHACKLIB}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

TESTNUMBER=lo06-datatot
TESTNAME=alginfo-test
UNITTESTARGS=-r

programs ${TESTNAME}:
	@mkdir -p OUTPUT
	@echo CC alginfo_test.c -o ${TESTNAME}
	@${CC} alginfo_test.c   -o ${TESTNAME} ${EXTRAFLAGS} ${EXTRALIBS} ${EXTRALIBS}
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit

check: ${TESTNAME}
	${COREULIMIT} && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	diff OUTPUT/${TESTNAME}.txt output.txt
	@: recordresults lib-$testobj "$testexpect" "$stat" lib-$testobj false

update:
	cp OUTPUT/${TESTNAME}.txt output.txt

clean:
	-rm -f ${TESTNAME}


# Local Variables:
# compile-command: "make check"
# End:
