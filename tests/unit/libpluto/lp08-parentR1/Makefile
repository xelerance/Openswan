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

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
SAMPLEDIR=../samples
OUTPUTS=OUTPUT
WHACKFILE=${OUTPUTS}/ikev2client.record.${ARCH}
WHACKFILE3=${OUTPUTS}/any1.record.${ARCH}
UNITTEST1ARGS=${WHACKFILE} parker1--jj2 parentI1badKE.pcap OUTPUT/parentR1notify.pcap
UNITTEST2ARGS=${WHACKFILE} parker1--jj2 parentI1.pcap      OUTPUT/parentR1.pcap
UNITTEST3ARGS=${WHACKFILE3} any1--jj2 parker1.pcap       OUTPUT/parentR1parker.pcap

TESTNAME=parentR1
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

Q=$(if ${V},,@)
programs ${TESTNAME}: ${TESTNAME}.c $(wildcard ../seam_*.c)
	@echo " CC ${TESTNAME}"
	${Q}${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@echo " LD ${TESTNAME}"
	${Q}${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRAOBJS} ${EXTRALIBS}

check: OUTPUT/R1-dump.txt OUTPUT/R1notify-dump.txt OUTPUT/R1parker-dump.txt
OUTPUT/R1-dump.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb2init
	@echo "set args "${UNITTEST2ARGS} >>.gdb2init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST2ARGS} >OUTPUT/${TESTNAME}_2.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_2.txt | diff - output2.txt
	tcpdump -n -t -v -r OUTPUT/parentR1.pcap | tee OUTPUT/R1-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1-dump.txt

OUTPUT/R1notify-dump.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb1init
	@echo "set args "${UNITTEST1ARGS} >>.gdb1init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} >OUTPUT/${TESTNAME}_1.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_1.txt | diff - output1.txt
	tcpdump -n -t -v -r OUTPUT/parentR1notify.pcap | tee OUTPUT/R1notify-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1notify-dump.txt

OUTPUT/R1parker-dump.txt:	${WHACKFILE3} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"           >.gdb3init
	@echo "set args "${UNITTEST3ARGS} >>.gdb3init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST3ARGS} >OUTPUT/${TESTNAME}_3.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_3.txt | diff - output3.txt
	tcpdump -n -t -v -r OUTPUT/parentR1parker.pcap | tee OUTPUT/R1parker-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1parker-dump.txt

${WHACKFILE}: ${SAMPLEDIR}/parker.conf
	@mkdir -p OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/parker --config ${SAMPLEDIR}/parker.conf --whackout=${WHACKFILE} parker1--jj2

${WHACKFILE3}: ${SAMPLEDIR}/parker.conf
	@mkdir -p OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/parker --config ${SAMPLEDIR}/parker.conf --whackout=${WHACKFILE3} any1--jj2

update: update3 update2 update1
update1:
	-make OUTPUT/R1-dump.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_1.txt >output1.txt
	[ -f OUTPUT/R1-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1-dump.txt >R1-dump.txt

update2:
	-make OUTPUT/R1notify-dump.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_2.txt >output2.txt
	[ -f OUTPUT/R1notify-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1notify-dump.txt >R1notify-dump.txt

update3:
	-make OUTPUT/R1parker-dump.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_3.txt >output3.txt
	[ -f OUTPUT/R1parker-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1parker-dump.txt >R1parker-dump.txt

clean:
	rm -f OUTPUT/${TESTNAME}_*.txt ${TESTNAME} ${WHACKFILE} OUTPUT/*.pcap *~ *.o ${WHACKFILE3}

PCAPDEPENDENCIES = ../lp02-parentI1/OUTPUT/parentI1.pcap
include ../Makefile.pcapupdate

pcapupdate: ${PCAPDEPENDENCIES}
	# note that input parentI1badKE is magic from the network.
	cp ../lp02-parentI1/OUTPUT/parentI1.pcap parentI1.pcap

