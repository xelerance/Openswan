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
ifeq ($(USE_LIBNSS),true)
NSS=.nss
else
NSS=
endif
OUTPUTS=OUTPUT${NSS}
CTLBASE=--ctlbase ${OUTPUTS}/base
SECRETS=ipsec${NSS}.secrets
LOGFILE=pluto${NSS}.addconn.out
SOCKETS=--interface 127.0.0.1 --ikeport 7500 --stderrlog --use-nostack --ipsecdir=`pwd`/${OUTPUTS} --secretsfile=`pwd`/${SECRETS}

all:
	echo run make check

vars:
	@echo PLUTO: ${PLUTOBIN}
	@echo ADDCONN: ${ADDCONN}
	@echo LOGFILE: ${LOGFILE}

step1:
	@rm -f ${OUTPUTS}/base.pid
	@echo "file ${PLUTOBIN}" >.gdbinit
	@echo "set args --nofork --nhelpers 1 ${CTLBASE} ${SOCKETS}" >>.gdbinit
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
	@${WHACKBIN} ${CTLBASE} --listen >&2 || exit 0

check: ${OUTPUTS} ${OUTPUTS}/certs/berri1.pem ${OUTPUTS}/certs/peel1.pem ${OUTPUTS}/private/peel1.key
	@(make --no-print-directory step1; sleep 1; make --no-print-directory step2; sleep 1; make --no-print-directory step5 step4 step3)| tee ${OUTPUTS}/${LOGFILE} | sed -r -f certfileloc.sed -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed | diff - ${LOGFILE}

${OUTPUTS}:
	@mkdir -p ${OUTPUTS}/base
	@mkdir -p ${OUTPUTS}/cacerts ${OUTPUTS}/aacerts ${OUTPUTS}/ocspcerts ${OUTPUTS}/crls ${OUTPUTS}/certs ${OUTPUTS}/private

update:
	sed -r -f certfileloc.sed -f ${TESTUTILS}/openswanver.sed -f ${TESTUTILS}/removehelpers.sed -f ${TESTUTILS}/randomhelper.sed ${OUTPUTS}/${LOGFILE} >${LOGFILE}

clean:
	rm -rf ${OUTPUTS}

ifeq ($(USE_LIBNSS),true)
${OUTPUTS}/cert9.db:
	certutil -f password.txt -d sql:`pwd`/${OUTPUTS} -N

${OUTPUTS}/certs/berri1.pem: | ${OUTPUTS}/cert9.db
	certutil -z ${OPENSWANSRCDIR}/noise.dat -f password.txt -d sql:`pwd`/${OUTPUTS} -S -x -k rsa -n berri1.pem -t u,u,u -s "CN=berri" -v 36
	certutil -f password.txt -d sql:`pwd`/${OUTPUTS} -L -n berri1.pem -a >${OUTPUTS}/certs/berri1.pem

${OUTPUTS}/certs/peel1.pem:  | ${OUTPUTS}/cert9.db
	certutil -z ${OPENSWANSRCDIR}/noise.dat -f password.txt -d sql:`pwd`/${OUTPUTS} -S -x -k rsa -n peel1.pem -t u,u,u -s "CN=peel" -v 36
	certutil -f password.txt -d sql:`pwd`/${OUTPUTS} -L -n peel1.pem -a >${OUTPUTS}/certs/peel1.pem

${OUTPUTS}/private/peel1.key:
	@mkdir -p ${OUTPUTS}/private
	@touch ${OUTPUTS}/private/peel1.key

else
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
endif

