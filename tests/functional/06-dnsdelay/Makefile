# Makefile for the Openswan in-tree functional test cases
# Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
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
srcdir?=${OPENSWANSRCDIR}/tests/functional/06-dnsdelay

include ${OPENSWANSRCDIR}/Makefile.inc

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf

check:
	mkdir -p ../OUTPUTS
	${READWRITE} --config client.conf | tee ../OUTPUTS/client.conf.raw | diff - client.conf.out
	${READWRITE} --config client.conf --whackout=../OUTPUTS/client.conf.whack cpe

update:
	cp ../OUTPUTS/client.conf.raw     client.conf.out


# Local Variables:
# compile-command: "(cd ../../../programs/readwriteconf && make clean && make programs) && make check"
# End:
