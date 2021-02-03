# Openswan testing makefile
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
srcdir?=${OPENSWANSRCDIR}/tests/unit/libwhack/wo03-msgstop
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE} -I..
EXTRAFLAGS+=-I../../libpluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include

EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${LIBOPENSWAN} ${LIBOSWLOG}
EXTRALIBS+=${LIBIPSECCONF} ${WHACKLIB} ${LIBOPENSWAN} ${LIBOSWKEYS} ${LIBALGOPARSE}
EXTRALIBS+=${LIBPLUTO} ${CRYPTOLIBS} ${LIBWHACK} ${LIBOSWLOG}
EXTRALIBS+=${LIBOPENSWAN} -lgmp ${LIBEFENCE} -lpcap

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}    ${HAVE_EFENCE}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

TESTNAME=decodestop
CBOROUT=OUTPUT/wm05o.bin
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

check: check1
update: update1
programs: ${TESTNAME}

OUTPUT:
	@mkdir -p OUTPUT

${TESTNAME}: ${TESTNAME}.c
	@echo CC ${TESTNAME}.c
	@${CC} -g -O0 -o ${TESTNAME} ${EXTRAFLAGS} ${TESTNAME}.c ${EXTRAOBJS} ${EXTRALIBS}

# --- test 1 ---

.gdb1init:
	@echo "file ${TESTNAME}"          >$@
	@echo "set args "${UNITTEST1ARGS} >>$@

check1: OUTPUT ${TESTNAME} .gdb1init
	@echo "## CHECK 1 :: ${UNITTEST1ARGS}"
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} 2>&1 && cborseq2diag.rb ${CBOROUT} >OUTPUT/${TESTNAME}1.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}1.txt | diff - output1.txt
	@echo "## 1 OK"

update1:
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}1.txt >output1.txt

clean:
	rm -rf OUTPUT ${TESTNAME}

pcapupdate:
	@true
