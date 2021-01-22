# Openswan testing makefile
# Copyright (C) 2017 Michael Richardson <mcr@xelerance.com>
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
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE}
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/crypto.o
EXTRALIBS+=${LIBPLUTO} ${LIBALGOPARSE}
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${CRYPTOLIBS} ${LIBOSWLOG} ${LIBOPENSWAN}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS} ${LIBGMP}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

include Makefile.testcase

Q=$(if ${V},,@)
${TESTNAME} programs: ${TESTSRC} ${LIBPLUTO}
	@mkdir -p OUTPUT
	@echo CC ${TESTNAME}.c
	${Q}${CC} -o ${TESTNAME} ${EXTRAFLAGS} ${TESTSRC} ${EXTRAOBJS} ${EXTRALIBS}
	@echo "file ${TESTNAME}"       >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit

check: ${TESTNAME}
	${COREULIMIT} && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	diff OUTPUT/${TESTNAME}.txt output.txt
	@: recordresults lib-$testobj "$testexpect" "$stat" lib-$testobj false

clean:
	rm -f ${TESTNAME}

update:
	cp OUTPUT/${TESTNAME}.txt output.txt

pcapupdate:
	@true



