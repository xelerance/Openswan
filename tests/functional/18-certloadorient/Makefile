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
WHACKBIN=${OBJDIRTOP}/programs/whack/whack
SAMPLES=${OPENSWANSRCDIR}/tests/unit/libpluto/samples
CTLBASE=--ctlbase OUTPUT/base
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/OUTPUT --secretsfile=`pwd`/ipsec.secrets
OUTPUTS=OUTPUT

step1:
	@rm -f OUTPUT/base.pid
	@echo "file ${PLUTOBIN}" >.gdbinit
	@echo "set args --nhelpers 1 ${CTLBASE} ${SOCKETS}" >.gdbinit
	@${PLUTOBIN} --nhelpers 1 ${CTLBASE} ${SOCKETS} 2>&1

step2:
	@${ADDCONN} --verbose ${CTLBASE} --config certone.conf green >&2

stepX:
	@${WHACKBIN} ${CTLBASE} --debug-all

step3:
	@${WHACKBIN} ${CTLBASE} --shutdown

step4:
	@${WHACKBIN} ${CTLBASE} --status

step5:
	@${WHACKBIN} ${CTLBASE} --listen || exit 0

check: OUTPUT ${OUTPUTS}/certs/berri1.pem ${OUTPUTS}/certs/peel1.pem ${OUTPUTS}/private/peel1.key
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2; sleep 1; make --no-print-directory step5 step4 step3)| tee ${OUTPUTS}/pluto.addconn.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ./removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.addconn.out;

OUTPUT:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p ${OUTPUTS}/cacerts ${OUTPUTS}/aacerts ${OUTPUTS}/ocspcerts ${OUTPUTS}/crls ${OUTPUTS}/certs ${OUTPUTS}/private
	-rm -f OUTPUT.pid

update:
	sed -r -f ${TESTUTILS}/openswanver.sed -f ./removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.addconn.raw >pluto.addconn.out

clean:
	rm -rf OUTPUT OUTPUT.pid

berri1.pem:
	openssl genrsa -f4 -out berri1.key 2048
	openssl req -new -batch -subj "/DC=Canada/DC=Xelerance/CN=berri" -x509 -set_serial 1234 -days 1024 -key berri1.key -out berri1.pem

${OUTPUTS}/certs/berri1.pem: berri1.pem
	cp berri1.pem ${OUTPUTS}/certs

peel1.pem:
	openssl genrsa -f4 -out peel1.key 2048
	openssl req -new -batch -subj "/DC=Canada/DC=Xelerance/CN=peel" -x509 -set_serial 1234 -days 1024 -key peel1.key -out peel1.pem

${OUTPUTS}/certs/peel1.pem: peel1.pem
	cp peel1.pem ${OUTPUTS}/certs

${OUTPUTS}/private/peel1.key: peel1.key
	cp peel1.key ${OUTPUTS}/private


