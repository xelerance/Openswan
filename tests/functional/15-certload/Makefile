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
srcdir?=${OPENSWANSRCDIR}/tests/functional/15-certload

include ${OPENSWANSRCDIR}/Makefile.inc

REMOVEHELPERS=${TESTUTILS}/removehelpers.sed
PLUTOBIN=${OBJDIRTOP}/programs/pluto/pluto
ADDCONN=${OBJDIRTOP}/programs/addconn/addconn
WHACKBIN=${OBJDIRTOP}/programs/whack/whack
SAMPLES=.
CTLBASE=--ctlbase OUTPUT/base
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/OUTPUT
OUTPUTS=OUTPUT
SAMPLE=moon

step1: ${OUTPUTS}
	@rm -f OUTPUT/base.pid
	@echo "file ${PLUTOBIN}" >.gdbinit
	@echo "set args --nofork --nhelpers 1 ${CTLBASE} ${SOCKETS}" >>.gdbinit
	@cp -r ${SAMPLE}/certs/.   ${OUTPUTS}/certs/.
	@cp -r ${SAMPLE}/cacerts/. ${OUTPUTS}/cacerts/.
	@${PLUTOBIN} --nhelpers 1 ${CTLBASE} ${SOCKETS} 2>&1

step2:
	@${ADDCONN} --verbose ${CTLBASE} --config ${SAMPLES}/${SAMPLE}.conf --rootdir ${SAMPLES}/${SAMPLE} net-net-works   >&2

step2b:
	@-${ADDCONN} --verbose ${CTLBASE} --config ${SAMPLES}/${SAMPLE}.conf --rootdir ${SAMPLES}/${SAMPLE} net-net-fails  >&2

step3:
	@${WHACKBIN} ${CTLBASE} --shutdown

step4:
	@${WHACKBIN} ${CTLBASE} --status

check: OUTPUT
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2 step2b; sleep 1; make --no-print-directory step4; make --no-print-directory step3)| tee ${OUTPUTS}/pluto.addconn.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ${REMOVEHELPERS} -f ${TESTUTILS}/randomhelper.sed -f ${TESTUTILS}/loadcertpath.sed | diff -w - pluto.addconn.out;

OUTPUT:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p ${OUTPUTS}/cacerts ${OUTPUTS}/certs ${OUTPUTS}/aacerts ${OUTPUTS}/ocspcerts ${OUTPUTS}/crls
	-rm -f OUTPUT.pid

update:
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${REMOVEHELPERS} -f ${TESTUTILS}/randomhelper.sed  -f ${TESTUTILS}/loadcertpath.sed ${OUTPUTS}/pluto.addconn.raw >pluto.addconn.out

clean:
	rm -rf OUTPUT OUTPUT.pid

