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
WHACKBIN=${OBJDIRTOP}/programs/whack/whack
CTLBASE=--ctlbase OUTPUT
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=OUTPUT
OUTPUTS=../OUTPUTS
OUTPUT=OUTPUT

check:
	@mkdir -p ${OUTPUTS}
	@mkdir -p ${OUTPUT}/cacerts ${OUTPUT}/aacerts ${OUTPUT}/ocspcerts  ${OUTPUT}/crls
	-rm -f OUTPUT.pid
	${PLUTOBIN} --help 2>&1 | tee ${OUTPUTS}/pluto.help.raw | sed -r -f ${TESTUTILS}/openswanver.sed  -f ${TESTUTILS}/randomhelper.sed | diff - pluto.help.out || (cat ${OUTPUTS}/pluto.help.raw; exit 1)
	echo ${PLUTOBIN} ${CTLBASE} ${SOCKETS}
	(${PLUTOBIN} ${CTLBASE} ${SOCKETS} 2>&1; sleep 1; ${WHACKBIN} ${CTLBASE} --shutdown)| tee ${OUTPUTS}/pluto.start.raw | sed -r -f ${TESTUTILS}/openswanver.sed  -f ${TESTUTILS}/removehelpers.sed  -f ${TESTUTILS}/randomhelper.sed | uniq | diff - pluto.start.out;
	(${PLUTOBIN} --nhelpers -1 ${CTLBASE} ${SOCKETS} 2>&1; sleep 1; ${WHACKBIN} ${CTLBASE} --shutdown)| tee ${OUTPUTS}/pluto.nhelpers.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed  -f ${TESTUTILS}/randomhelper.sed | uniq | diff - pluto.nhelpers.out;
	: make sure that nhelpers=-1 started at least one helper.
	[ $$(sed -n -f ./nhelpers.sed ${OUTPUTS}/pluto.nhelpers.raw | wc -l) -ge 1 ]
	(${PLUTOBIN} --nhelpers 5 ${CTLBASE} ${SOCKETS} 2>&1; sleep 1; ${WHACKBIN} ${CTLBASE} --shutdown)| tee ${OUTPUTS}/pluto.nhelper5.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.nhelper5.out;
	(${PLUTOBIN} --nhelpers 1 --secctx_attr_value 10 ${CTLBASE} ${SOCKETS} 2>&1; sleep 1; ${WHACKBIN} ${CTLBASE} --shutdown)| tee ${OUTPUTS}/pluto.secctx.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.secctx.out;

update:
	sed -r -f ${TESTUTILS}/openswanver.sed ${OUTPUTS}/pluto.help.raw  >pluto.help.out
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/randomhelper.sed -f ${TESTUTILS}/removehelpers.sed ${OUTPUTS}/pluto.start.raw | uniq >pluto.start.out
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/randomhelper.sed -f ${TESTUTILS}/removehelpers.sed ${OUTPUTS}/pluto.nhelpers.raw | uniq >pluto.nhelpers.out
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.nhelper5.raw >pluto.nhelper5.out
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.secctx.raw >pluto.secctx.out

stop:
	${WHACKBIN} ${CTLBASE} --shutdown

whack:
	${WHACKBIN} ${CTLBASE} ${ARGS}

start:
	${PLUTOBIN} ${CTLBASE} ${SOCKETS} 2>&1
