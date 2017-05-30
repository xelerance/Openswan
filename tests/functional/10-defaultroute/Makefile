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
TESTNAME=defaultroute
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

check: ${OUTPUTS}
	mkdir -p ${OUTPUTS}
	${READWRITE} --debug --config ${CONFFILE} | tee ${OUTPUTS}/bob.conf.raw | diff - bob.conf.out
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2 step2c step4; sleep 1; make --no-print-directory step3)| tee ${OUTPUTS}/pluto.${TESTNAME}.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ../05-addconn/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.${TESTNAME}.out;

update:
	cp ${OUTPUTS}/bob.conf.raw     bob.conf.out
	sed -r -f ${TESTUTILS}/openswanver.sed -f ../05-addconn/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.${TESTNAME}.raw >pluto.${TESTNAME}.out

step1:
	@${PLUTOBIN} --nhelpers 1 ${CTLBASE} ${SOCKETS} --ipsecdir ${CONFBASE} --secretsfile ${CONFBASE}.secrets 2>&1

step2:
	@${ADDCONN} --verbose ${CTLBASE} --config ${CONFFILE} nat-t >OUTPUT/addconn.${TESTNAME}.txt

step2b:
	@${WHACKBIN} ${CTLBASE} --debug-control --debug-controlmore

step2c:
	@${WHACKBIN} ${CTLBASE} --rereadsecrets >/dev/null

step3:
	@${WHACKBIN} ${CTLBASE} --shutdown

step4:
	@${WHACKBIN} ${CTLBASE} --status

OUTPUT:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p bob/cacerts bob/aacerts bob/ocspcerts bob/crls
	-rm -f OUTPUT/base.pid

clean:
	-rm -f OUTPUT/base.pid

