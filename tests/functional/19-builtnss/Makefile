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
SAMPLES=${OPENSWANSRCDIR}/tests/unit/libpluto/samples
CTLBASE=--ctlbase OUTPUT/base
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/OUTPUT --secretsfile=`pwd`/ipsec.secrets
OUTPUTS=OUTPUT

step1:
	@rm -f OUTPUT/base.pid
	@echo "file ${PLUTOBIN}" >.gdbinit
	@echo "set args --nhelpers 1 ${CTLBASE} ${SOCKETS}" >.gdbinit
	@if ${PLUTOBIN} --built-withlibnss; then echo LIBNSS; else echo BUILTINCRYPTO; fi

check: OUTPUT
	@(make --no-print-directory step1) | tee ${OUTPUTS}/pluto.${USE_LIBNSS}.libnss.raw | sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/randomhelper.sed | diff - pluto.${USE_LIBNSS}.libnss.out;

OUTPUT:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p ${OUTPUTS}/cacerts ${OUTPUTS}/aacerts ${OUTPUTS}/ocspcerts ${OUTPUTS}/crls ${OUTPUTS}/certs ${OUTPUTS}/private
	-rm -f OUTPUT.pid

update:
	sed -r -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/pluto.${USE_LIBNSS}.libnss.raw >pluto.${USE_LIBNSS}.libnss.out

clean:
	rm -rf OUTPUT OUTPUT.pid


