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
SAMPLEDIR=../01-confread
SAMPLE2DIR=../../unit/libpluto/samples

check:
	@mkdir -p ${OUTPUTS}
	@echo processing ${SAMPLEDIR}/dooku.conf
	@${READWRITE} --rootdir=${SAMPLEDIR}/dooku --config ${SAMPLEDIR}/dooku.conf --whackout=${OUTPUTS}/dookurecord.whack dooku--cassidy-net | tee -a ${OUTPUTS}/dookuload.out | diff - /dev/null
	strings ${OUTPUTS}/dookurecord.whack | grep pluto-whack-file >/dev/null
	strings ${OUTPUTS}/dookurecord.whack | grep dooku--cassidy-net >/dev/null
	@echo processing ${SAMPLEDIR}/parker.conf parker1-jj0
	@echo >.gdbinit2  "file ${READWRITE} "
	@echo >>.gdbinit2 "set args --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj0 "
	${READWRITE} --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj0 2>&1 | tee ${OUTPUTS}/parker1load.out | diff - output2.txt
	@echo processing ${SAMPLEDIR}/parker.conf parker1-jj2
	@${READWRITE} --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj2 ikev2:parker--jj | tee ${OUTPUTS}/parkerload.out | diff - /dev/null
	@strings ${OUTPUTS}/parkerrecord.whack | grep pluto-whack-file >/dev/null
	@strings ${OUTPUTS}/parkerrecord.whack | grep parker1--jj2 >/dev/null
	@strings ${OUTPUTS}/parkerrecord.whack | grep ikev2:parker--jj >/dev/null

update:
	true



