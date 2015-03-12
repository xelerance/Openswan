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

check:
	@mkdir -p ${OUTPUTS}
	@${READWRITE} --rootdir=${SAMPLEDIR}/dooku --config ${SAMPLEDIR}/dooku.conf --whackout=${OUTPUTS}/dookurecord.whack dooku--cassidy-net
	@strings ${OUTPUTS}/dookurecord.whack | grep pluto-whack-file >/dev/null
	@strings ${OUTPUTS}/dookurecord.whack | grep dooku--cassidy-net >/dev/null

update:
	true



