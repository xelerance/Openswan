# Makefile for the Openswan in-tree test cases
# Copyright (C) 2014 Michael Richardson <mcr@xelerance.com>
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

OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/functional/01-confread

include ${OPENSWANSRCDIR}/Makefile.inc

PLUTOBIN=${OBJDIRTOP}/programs/pluto/pluto
ADDCONN=${OBJDIRTOP}/programs/addconn/addconn
READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
WHACKBIN=${OBJDIRTOP}/programs/whack/whack
SAMPLES=${OPENSWANSRCDIR}/tests/unit/libpluto/samples
CTLBASE=--ctlbase OUTPUT/base
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/OUTPUT
OUTPUTS=OUTPUT

step1:
	@rm -f OUTPUT/base.pid
	@echo "file ${PLUTOBIN}" >.gdbinit
	@echo "set args --nhelpers 1 ${CTLBASE} ${SOCKETS}" >.gdbinit
	@${PLUTOBIN} --nhelpers 1 ${CTLBASE} ${SOCKETS} 2>&1

step2:
	@${ADDCONN} --verbose ${CTLBASE} --config ${SAMPLES}/rw.conf --rootdir ${SAMPLES}/rw gateway--any        >&2

step2X:
	@${READWRITE} --verbose --config ${SAMPLES}/rw.conf --rootdir=${SAMPLES}/rw --whackout=${OUTPUTS}/rw.whackout gateway--any        >&2

step2b:
	@${ADDCONN} --verbose ${CTLBASE} --config ../07-sourceipv6/green.conf --rootdir ../07-sourceipv6 green   >&2

stop step3:
	@${WHACKBIN} ${CTLBASE} --shutdown

step4:
	@${WHACKBIN} ${CTLBASE} --status

check: OUTPUT
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2 step2b; sleep 1; make --no-print-directory step3)| tee ${OUTPUTS}/pluto.addconn.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ./removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.addconn.out;

OUTPUT:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p ${OUTPUTS}/cacerts ${OUTPUTS}/aacerts ${OUTPUTS}/ocspcerts ${OUTPUTS}/crls
	-rm -f OUTPUT.pid

update:
	sed -r -f ${TESTUTILS}/openswanver.sed -f ./removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.addconn.raw >pluto.addconn.out

clean:
	rm -rf OUTPUT OUTPUT.pid

