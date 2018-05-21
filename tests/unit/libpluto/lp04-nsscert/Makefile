# FreeS/WAN testing makefile
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
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto/lp02-parentI1
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE} -I..
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}

EXTRALIBS+=${LIBPLUTO} ${CRYPTOLIBS} ${WHACKLIB}
EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=-lgmp ${LIBEFENCE} -lpcap ${NSS_LIBS} ${FIPS_LIBS}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

UNITTESTARGS=CAcert.pem goodcert1.pem badcert1.pem

TESTNAME=nsscert
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

.PHONY: check update

check:	nsscert.c
	@mkdir -p OUTPUT
	@echo CC ${TESTNAME}.c
	@${CC} -g -O0 -o ${TESTNAME} ${EXTRAFLAGS} ${TESTNAME}.c ${EXTRALIBS}
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit
	ulimit -c unlimited && ./${TESTNAME} ${UNITTESTARGS} 2>&1 | tee OUTPUT/${TESTNAME}.txt | diff -B - output${NSS_LIBTOKEN}.txt

update:
	cp OUTPUT/${TESTNAME}.txt output.txt

clean:
	rm -f ${TESTNAME} *~ *.o

pcapupdate:
	@true
