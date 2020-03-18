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

OPENSWANSRCDIR?=$(shell cd ..; pwd)
srcdir?=${OPENSWANSRCDIR}/programs/

include ${OPENSWANSRCDIR}/Makefile.inc

check:
	@${MAKE} -C functional check
	@${MAKE} -C unit       check
	@${MAKE} -C build      check

clean:
	@${MAKE} -C functional clean
	@${MAKE} -C unit       clean
	@${MAKE} -C build      clean

testlist:
	@${MAKE} -C functional testlist
	@${MAKE} -C unit       testlist
	@${MAKE} -C build      testlist

programs:
	@true

install:
	@true



