# FreeS/WAN testing makefile
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
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto/lp01-spdbtest
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE}
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS} ${LIBALGOPARSE}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}    ${LIBGMP} ${CRYPTOLIBS}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

TESTNUMBER=ap05-ikev1toikev2
TESTNAME=ikev1toikev2
UNITTESTARGS=

programs ${TESTNAME}: ${TESTNAME}.c
	@mkdir -p OUTPUT
	@echo CC ${TESTNAME}.c
	@${CC} -o ${TESTNAME} ${EXTRAFLAGS} ${TESTNAME}.c ${EXTRALIBS} ${EXTRALIBS}
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit

check: ${TESTNAME}
	${COREULIMIT} && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	diff OUTPUT/${TESTNAME}.txt output.txt
	@: recordresults lib-$testobj "$testexpect" "$stat" lib-$testobj false

update:
	cp OUTPUT/${TESTNAME}.txt output.txt



