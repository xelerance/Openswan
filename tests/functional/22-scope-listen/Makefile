# Makefile for the Openswan in-tree test cases
# Copyright (C) 2014-2016 Michael Richardson <mcr@xelerance.com>
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
TESTNAME=scopelisten
srcdir?=${OPENSWANSRCDIR}/tests/functional/08-${TESTNAME}

include ${OPENSWANSRCDIR}/Makefile.inc

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
PLUTOBIN=${OBJDIRTOP}/programs/pluto/pluto
ADDCONN=${OBJDIRTOP}/programs/addconn/addconn
WHACKBIN=${OBJDIRTOP}/programs/whack/whack
CTLBASE=--ctlbase OUTPUT/base
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/OUTPUT
OUTPUTS=OUTPUT
CONFBASE=bob
CONFFILE=${CONFBASE}.conf
FILTERS=sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed -f ${TESTUTILS}/certsize-r.sed -f ${TESTUTILS}/pending_ddns.sed -f ${TESTUTILS}/removehelpers.sed

check: ${OUTPUTS}
	mkdir -p ${OUTPUTS}
	-rm -f OUTPUT/base.pid core
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2 step4; sleep 1; make --no-print-directory step3)| tee ${OUTPUTS}/pluto.${TESTNAME}.raw | ${FILTERS} | diff - pluto.${TESTNAME}.out;
	@if [ -f core ]; then echo CORE DUMP; exit 1; fi

update:
	${FILTERS} ${OUTPUTS}/pluto.${TESTNAME}.raw >pluto.${TESTNAME}.out

step1:
	@${PLUTOBIN} --nhelpers 1 ${CTLBASE} ${SOCKETS} --ipsecdir ${CONFBASE} --secretsfile ${CONFBASE}.secrets 2>&1

step2:
	@${WHACKBIN} ${CTLBASE} --debug-control --debug-controlmore --on-link-scope

stop step3:
	@${WHACKBIN} ${CTLBASE} --shutdown

step4:
	@${WHACKBIN} ${CTLBASE} --option-status

OUTPUT:
	@mkdir -p ${OUTPUTS}/base

clean:
	-rm -f OUTPUT/base.pid

