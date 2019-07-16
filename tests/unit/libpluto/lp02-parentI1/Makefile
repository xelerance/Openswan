# FreeS/WAN testing makefile
# Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
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

include ../lp13-objectlist.make
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/connections.o

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
SAMPLEDIR=../samples
OUTPUTS=OUTPUT
FILTERS=sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed -f ${TESTUTILS}/certsize.sed
EXTRAFLAGS+=-DSAMPLEDIR=\"${SAMPLEDIR}\"

include Makefile.testcase

EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

Q=$(if ${V},,@)
programs ${TESTNAME}: ${TESTNAME}.c ${EXTRAOBJS} ../seam_*.c
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit
	@echo " CC ${TESTNAME}"
	${Q}${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@echo " LD ${TESTNAME}"
	${Q}${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRAOBJS} ${EXTRALIBS}

check:	${WHACKFILE} OUTPUT ${EXTRAOBJS} ${TESTNAME}
	ulimit -c unlimited && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	@${FILTERS} OUTPUT/${TESTNAME}.txt | diff - output.txt
	@tcpdump -n -t -v -r OUTPUT/${TESTNAME}.pcap | tee OUTPUT/I1-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - I1-dump.txt

${TESTNAME}.E:
	@${CC} -E -c -g -o ${TESTNAME}.E -O0 ${TESTNAME}.c ${EXTRAFLAGS}

ifeq (${WHACKREFFILE},)
${WHACKFILE}: OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/${ENDNAME} --config ${SAMPLEDIR}/${ENDNAME}.conf --whackout=${WHACKFILE} ${CONNNAME}
else
${WHACKFILE}: ${WHACKREFFILE}
	@mkdir -p OUTPUT
	cp ${WHACKREFFILE} ${WHACKFILE}
endif

update: OUTPUT
	${FILTERS} OUTPUT/${TESTNAME}.txt >output.txt
	sed -f ${TESTUTILS}/sanity.sed OUTPUT/I1-dump.txt >I1-dump.txt

clean: OUTPUT
	rm -f OUTPUT/${TESTNAME}.txt ${TESTNAME} ${WHACKFILE} OUTPUT/${TESTNAME}.pcap *.o *~

OUTPUT:
	@mkdir -p OUTPUT

# Local Variables:
# compile-command: "make check"
# End:
#
