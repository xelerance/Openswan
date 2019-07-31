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
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto

include ${OPENSWANSRCDIR}/Makefile.inc

UNITTESTS=
UNITTESTS+=ct02-parentI1
UNITTESTS+=ct10-parentI2
#algo UNITTESTS+=ct12-parentR2
UNITTESTS+=ct13-parentI3
UNITTESTS+=ct14-bigkeyI2

clean check:
	@for unittest in ${UNITTESTS}; do ${MAKE} -C $$unittest $@; done

testlist:
	@echo ${UNITTESTS}
