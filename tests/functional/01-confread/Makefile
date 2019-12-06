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
	../readwritetest ${READWRITE} dooku n2n-transport.conf n2n-transport.conf
	: ../readwritetest ${READWRITE} dooku brokenspace.conf brokenspace.conf
	[ ! -f core ]

OUTPUT:
	mkdir -p OUTPUT

update:
	cp OUTPUT/default.ipsec.conf.out default.ipsec.conf.out
	cp OUTPUT/moon-base.conf.out     moon-base.conf.out
	cp OUTPUT/dooku.conf.out         dooku.conf.out
	cp OUTPUT/cassidy.conf.out       cassidy.conf.out
	cp OUTPUT/h2h.conf.out           h2h.conf.out
	cp OUTPUT/certpercent.conf.out   certpercent.conf.out
	cp OUTPUT/n2n-transport.conf.out n2n-transport.conf.out

# Local Variables:
# compile-command: "(cd ../../../programs/readwriteconf && make clean && make programs) && make check"
# End:
