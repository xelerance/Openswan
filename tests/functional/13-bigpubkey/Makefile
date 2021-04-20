# Makefile for the Openswan in-tree test cases
# Copyright (C) 2016 Michael Richardson <mcr@xelerance.com>
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
WHACKBIN=${OBJDIRTOP}/programs/whack/whack
SAMPLES=${OPENSWANSRCDIR}/tests/unit/libpluto/samples
CTLBASE=--ctlbase OUTPUT/base
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/OUTPUT
OUTPUTS=OUTPUT

all:
	echo nothing

step1:
	@rm -f OUTPUT/base.pid
	@echo "file ${PLUTOBIN}" >.gdbinit
	@echo "set args --nhelpers 1 ${CTLBASE} --secretsfile ../../unit/libopenswan/lo02-verifysigs/key-4096.secrets ${SOCKETS} --nofork " >>.gdbinit
	@${PLUTOBIN} --nhelpers 1 ${CTLBASE} --secretsfile ../../unit/libopenswan/lo02-verifysigs/key-4096.secrets ${SOCKETS} 2>&1

step2:
	@${ADDCONN} --verbose ${CTLBASE} --config green.conf big-key-green berri-vzhost-mondev-v6 >&2

step3:
	@${WHACKBIN} ${CTLBASE} --shutdown

step4:
	@(${WHACKBIN} ${CTLBASE} --listall; ${WHACKBIN} ${CTLBASE} --listen; ${WHACKBIN} ${CTLBASE} --listall) > ${OUTPUTS}/pluto.whack.raw

check: OUTPUT
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2; sleep 1; make --no-print-directory step4; sleep 1; make --no-print-directory step3 )| tee ${OUTPUTS}/pluto.big-key-green.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.big-key-green.out;
	@sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed ${OUTPUTS}/pluto.whack.raw | diff - pluto.whack.out

OUTPUT:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p ${OUTPUTS}/cacerts ${OUTPUTS}/aacerts ${OUTPUTS}/ocspcerts ${OUTPUTS}/crls
	-rm -f OUTPUT/base.pid

update:
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.big-key-green.raw >pluto.big-key-green.out
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed OUTPUT/pluto.whack.raw >pluto.whack.out

clean:
	rm -rf OUTPUT OUTPUT/base.pid

