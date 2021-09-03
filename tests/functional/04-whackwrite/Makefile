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

TEST3ARGS=--rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord2.whack --all

# note may fail if core dumps are not named "core"

check:
	@mkdir -p ${OUTPUTS}
	@rm -f core
	@echo processing ${SAMPLEDIR}/dooku.conf
	@echo >.gdbinit  "file ${READWRITE} "
	@echo >>.gdbinit "set args --verbose --rootdir=${SAMPLEDIR}/dooku --config ${SAMPLEDIR}/dooku.conf --whackout=${OUTPUTS}/dookurecord.whack dooku--cassidy-net"
	${READWRITE} --rootdir=${SAMPLEDIR}/dooku --config ${SAMPLEDIR}/dooku.conf --whackout=${OUTPUTS}/dookurecord.whack dooku--cassidy-net 2>&1 | tee ${OUTPUTS}/dookuload.out | diff - dookuload.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@cborseq2pretty.rb ${OUTPUTS}/dookurecord.whack | tee ${OUTPUTS}/dookurecord.out | diff - dookurecord.txt
	@echo processing ${SAMPLEDIR}/parker.conf parker1-jj0
	@echo >.gdbinit2  "file ${READWRITE} "
	@echo >>.gdbinit2 "set args --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj0 "
	@${READWRITE} --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj0 2>&1 | tee ${OUTPUTS}/parker1load.out | diff - output2.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@cborseq2pretty.rb ${OUTPUTS}/parkerrecord.whack | tee ${OUTPUTS}/parkerrecord.out | diff - parkerrecord.txt
	@echo processing ${SAMPLEDIR}/parker.conf parker1-jj2
	@echo >.gdbinit2b  "file ${READWRITE} "
	@echo >>.gdbinit2b "set args --verbose --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord.whack parker1--jj2 ikev2:parker--jj "
	@${READWRITE} --rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord3.whack parker1--jj2 ikev2:parker--jj 2>&1 | tee ${OUTPUTS}/parkerload.out | diff - parkerload.txt
	@if [ -r core ]; then echo CORE DUMP; exit 1; fi
	@echo testing ${SAMPLEDIR}/parker.conf with --all
	@echo >.gdbinit3 "file ${READWRITE} "
	@echo >>.gdbinit3 "set args ${TEST3ARGS}"
	@cborseq2pretty.rb ${OUTPUTS}/parkerrecord3.whack | tee ${OUTPUTS}/parkerrecord3.out | diff - parkerrecord3.txt
	@${READWRITE} ${TEST3ARGS} 2>&1 | tee ${OUTPUTS}/parkerload2.out | diff - parkerload2.txt
	@cborseq2pretty.rb ${OUTPUTS}/parkerrecord2.whack | tee ${OUTPUTS}/parkerrecord2.out | diff - parkerrecord2.txt

update:
	cp ../OUTPUTS/parker1load.out  output2.txt
	cp ../OUTPUTS/parkerload2.out  parkerload2.txt
	cp ../OUTPUTS/dookuload.out    dookuload.txt
	cp ../OUTPUTS/parkerload.out   parkerload.txt
	cp ${OUTPUTS}/dookurecord.out  dookurecord.txt
	cp ${OUTPUTS}/parkerrecord.out parkerrecord.txt
	cp ${OUTPUTS}/parkerrecord3.out parkerrecord3.txt
	cp ${OUTPUTS}/parkerrecord2.out parkerrecord2.txt




