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

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
OUTPUTS=../OUTPUTS
SAMPLE2DIR=../../unit/libpluto/samples

TEST1ARGS=--rootdir=${SAMPLE2DIR}/rwcert --config ${SAMPLE2DIR}/rwcert.conf --whackout=${OUTPUTS}/rwcert.whack --all --debug

# note may fail if core dumps are not named "core"

check:
	@mkdir -p ${OUTPUTS}
	@rm -f core
	@echo >.gdbinit  "file ${READWRITE} "
	@echo >>.gdbinit "set args ${TEST1ARGS}"
	@${READWRITE} ${TEST1ARGS} 2>&1 | tee ${OUTPUTS}/rwcert.out | diff - output1.txt
	@cborseq2pretty.rb ${OUTPUTS}/rwcert.whack | grep carolCert.pem    >/dev/null

update:
	cp ../OUTPUTS/rwcert.out          output1.txt



