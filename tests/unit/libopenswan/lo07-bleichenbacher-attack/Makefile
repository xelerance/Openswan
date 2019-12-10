# OpenS/WAN testing makefile
# Copyright (C) 2018 Bart Trojanowski <bart@xelerance.com>
# Copyright (C) 2014 Michael Richardson <mcr@xelerance.com>
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

EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}    ${LIBGMP} ${CRYPTOLIBS} ${LIBPLUTO}

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_crypto.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_rsa.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/keymgmt.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/signatures.o
EXTRAOBJS+=${OBJDIRTOP}/lib/libopenswan/oswconf.o

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

TESTNUMBER=lo07-bleichenbacher-attack
TESTNAME=bleichenbacher-attack
UNITTESTARGS=

programs: ${TESTNAME}
.PHONY: programs

Q=$(if $V,,@)

check: ${TESTNAME}
	@mkdir -p OUTPUT
	${COREULIMIT} && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	diff OUTPUT/${TESTNAME}.txt output.txt
	@: recordresults lib-$testobj "$testexpect" "$stat" lib-$testobj false

${TESTNAME}: ${TESTNAME}.c
	@echo CC ${TESTNAME}.c
	$Q${CC} -Wno-pointer-sign -o ${TESTNAME} ${EXTRAFLAGS} ${TESTNAME}.c ${EXTRAOBJS} ${EXTRALIBS}
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit

update:
	cp OUTPUT/${TESTNAME}.txt output.txt


initiate:


