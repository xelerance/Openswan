# Openswan unit testing makefile
# Copyright (C) 2014,2015 Michael Richardson <mcr@xelerance.com>
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
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include

include ../../libpluto/lp13-objectlist.make
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/keys.o

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
SAMPLEDIR=../samples
OUTPUTS=OUTPUT
WHACKFILE=${OUTPUTS}/ikev2client.record.${ARCH}
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

FILTERS=sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed -f ${TESTUTILS}/certsize.sed

include Makefile.testcase

Q=$(if ${V},,@)
programs ${TESTNAME}: ${TESTNAME}.c $(wildcard ../seam_*.c) ${EXTRAOBJS}
	@echo " CC ${TESTNAME}"
	${Q}${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@echo " LD ${TESTNAME}"
	${Q}${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRAOBJS} ${EXTRALIBS}

check: OUTPUT/R1-dump.txt
OUTPUT/R1-dump.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb1init
	@echo "set args "${UNITTEST1ARGS} >>.gdb1init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} >OUTPUT/${TESTNAME}_1.txt 2>&1
	@${FILTERS} OUTPUT/${TESTNAME}_1.txt | diff - output1.txt
	tcpdump -n -t -v -r OUTPUT/${TESTNAME}.pcap | tee OUTPUT/R1-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1-dump.txt

${WHACKFILE}: ${SAMPLEDIR}/${ENDNAME}.conf OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/${ENDNAME} --config ${SAMPLEDIR}/${ENDNAME}.conf --whackout=${WHACKFILE} ${CONNNAME}

update: update1
update1:
	${FILTERS} OUTPUT/${TESTNAME}_1.txt >output1.txt
	[ -f OUTPUT/R1-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1-dump.txt >R1-dump.txt

clean:
	rm -f OUTPUT/${TESTNAME}_*.txt ${TESTNAME} ${TESTNAME}.o ${WHACKFILE} OUTPUT/*.pcap *~ *.o

OUTPUT:
	@mkdir -p OUTPUT

