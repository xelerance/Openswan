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
srcdir?=${OPENSWANSRCDIR}/tests/functional/11-subnets

include ${OPENSWANSRCDIR}/Makefile.inc

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
OUTPUTS=../OUTPUTS

check:
	mkdir -p ${OUTPUTS}
	@(echo "file ${READWRITE}"; echo "set args" --debug --whackout=${OUTPUTS}/dookurecord.whack --config ../../unit/libpluto/samples/alias-h2n.conf parker--dailyplanet) >.gdbinit
	${READWRITE} --debug --whackout=${OUTPUTS}/dookurecord.whack --config ../../unit/libpluto/samples/alias-h2n.conf parker--dailyplanet 2>&1 | tee ../OUTPUTS/alias-h2n.conf.raw | diff - alias-h2n.conf.out


update:
	cp ../OUTPUTS/alias-h2n.conf.raw     alias-h2n.conf.out




