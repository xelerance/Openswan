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
	../readwritetest ${READWRITE} connclientfamily  connclientfamily.conf  connclientfamily.conf
	[ ! -f core ]

OUTPUT:
	mkdir -p OUTPUT

update:
	cp OUTPUT/connclientfamily.conf.out connclientfamily.conf.out

# Local Variables:
# compile-command: "(cd ../../../programs/readwriteconf && make clean && make programs) && make check"
# End:
