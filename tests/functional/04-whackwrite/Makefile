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
export READWRITE
export OUTPUTS
SAMPLEDIR=../01-confread
SAMPLE2DIR=../../unit/libpluto/samples

TEST3ARGS=--rootdir=${SAMPLE2DIR}/parker --config ${SAMPLE2DIR}/parker.conf --whackout=${OUTPUTS}/parkerrecord2.whack --all
TEST4ARGS=--rootdir=${SAMPLE2DIR}/dooku  --config ${SAMPLE2DIR}/dooku.conf  --whackout=${OUTPUTS}/dookurecord.whack --all

# note may fail if core dumps are not named "core"


check:
	@mkdir -p ${OUTPUTS}
	@./writetest dooku  ${SAMPLEDIR}/dooku.conf ${SAMPLEDIR}/dooku "dooku--cassidy-net dooku--ipv6"
	@./writetest parker  ${SAMPLE2DIR}/parker.conf ${SAMPLE2DIR}/parker "parker1--jj0"
	@./writetest parker2 ${SAMPLE2DIR}/parker.conf ${SAMPLE2DIR}/parker "ikev2:parker--jj"
	@./writetest acppeer1 ${SAMPLE2DIR}/acppeers.conf ${SAMPLE2DIR}/acppeers "peerA--peerB"

update:
	# dooku
	cp ${OUTPUTS}/dookuload.out    dookuload.txt
	cp ${OUTPUTS}/dookurecord.out  dookurecord.txt

	# parker
	cp ${OUTPUTS}/parkerload.out   parkerload.txt
	cp ${OUTPUTS}/parkerrecord.out parkerrecord.txt

	# parker2
	cp ${OUTPUTS}/parker2load.out   parker2load.txt
	cp ${OUTPUTS}/parker2record.out parker2record.txt

	# acppeers1
	cp ${OUTPUTS}/acppeer1load.out    acppeer1load.txt
	cp ${OUTPUTS}/acppeer1record.out  acppeer1record.txt



