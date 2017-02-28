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

check: OUTPUT
	-@rm -f core
	../readwritetest ${READWRITE} "" default.ipsec.conf ${OBJDIRTOP}/programs/_confread/ipsec.conf
	../readwritetest ${READWRITE} "" moon-base.conf  moon-base.conf
	../readwritetest ${READWRITE} dooku dooku.conf dooku.conf
	../readwritetest ${READWRITE} cycle    cycle.conf    cycle.conf
	../readwritetest ${READWRITE} cassidy   cassidy.conf cassidy.conf
	../readwritetest ${READWRITE} dooku h2h.conf ../../unit/libpluto/samples/h2h.conf
	../readwritetest ${READWRITE} dooku certpercent.conf berri-strongswan.conf
	: ../readwritetest ${READWRITE} dooku brokenspace.conf brokenspace.conf
	[ ! -f core ]

OUTPUT:
	mkdir -p OUTPUT

update:
	cp ../OUTPUTS/default.ipsec.conf.raw default.ipsec.conf.out
	cp ../OUTPUTS/moon-base.conf.raw     moon-base.conf.out
	cp ../OUTPUTS/dooku.conf.raw         dooku.conf.out
	cp ../OUTPUTS/cassidy.conf.raw       cassidy.conf.out
	cp ../OUTPUTS/h2h.conf.raw           h2h.conf.out
	cp ../OUTPUTS/certpercent.conf.raw           certpercent.conf.out

# Local Variables:
# compile-command: "(cd ../../../programs/readwriteconf && make clean && make programs) && make check"
# End:
