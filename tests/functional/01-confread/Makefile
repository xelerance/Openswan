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

check:
	-@rm -f core
	mkdir -p ../OUTPUTS
	${READWRITE} --config ${OBJDIRTOP}/programs/_confread/ipsec.conf | tee ../OUTPUTS/default.ipsec.conf.raw | diff - default.ipsec.conf.out
	${READWRITE} --config moon-base.conf | tee ../OUTPUTS/moon-base.conf.raw | diff - moon-base.conf.out
	${READWRITE} --rootdir=dooku --config dooku.conf | tee ../OUTPUTS/dooku.conf.raw | diff - dooku.conf.out
	${READWRITE} --rootdir=cassidy --config cassidy.conf | tee ../OUTPUTS/cassidy.conf.raw | diff - cassidy.conf.out
	${READWRITE} --rootdir=dooku --config ../../unit/libpluto/samples/h2h.conf | tee ../OUTPUTS/h2h.conf.raw | diff - h2h.conf.out
	: ${READWRITE} --rootdir=dooku --config brokenspace.conf | tee ../OUTPUTS/brokenspace.conf.raw | diff - brokenspace.conf.out
	[ ! -f core ]

update:
	cp ../OUTPUTS/default.ipsec.conf.raw default.ipsec.conf.out
	cp ../OUTPUTS/moon-base.conf.raw     moon-base.conf.out
	cp ../OUTPUTS/dooku.conf.raw         dooku.conf.out
	cp ../OUTPUTS/cassidy.conf.raw       cassidy.conf.out
	cp ../OUTPUTS/h2h.conf.raw           h2h.conf.out

# Local Variables:
# compile-command: "(cd ../../../programs/readwriteconf && make clean && make programs) && make check"
# End:
