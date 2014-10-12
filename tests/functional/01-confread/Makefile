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

check:
	mkdir -p ../OUTPUTS
	${OBJDIRTOP}/programs/readwriteconf/readwriteconf --config ${OBJDIRTOP}/programs/_confread/ipsec.conf | tee ../OUTPUTS/default.ipsec.conf.raw | diff - default.ipsec.conf.out
	${OBJDIRTOP}/programs/readwriteconf/readwriteconf --config moon-base.conf | tee ../OUTPUTS/moon-base.conf.raw | diff - moon-base.conf.out

update:
	cp ../OUTPUTS/default.ipsec.conf.raw default.ipsec.conf.out
	cp ../OUTPUTS/moon-base.conf.raw     moon-base.conf.out



