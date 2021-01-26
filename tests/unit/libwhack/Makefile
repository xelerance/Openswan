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

all: programs

include ${OPENSWANSRCDIR}/Makefile.inc

UNITTESTS+=wo01-msgstop
UNITTESTS+=wo02-msgstatus
UNITTESTS+=wo03-options
UNITTESTS+=wo04-connections

# running 'make check KEEPGOING=1' will run through all tests w/o stopping
ERROR_CHECK=$(if ${KEEPGOING},,set -e;)
programs clean check pcapupdate:
	@${ERROR_CHECK} for unittest in ${UNITTESTS}; do ${MAKE} -C $$unittest $@; done

testlist:
	@echo ${UNITTESTS}

testcount:
	@echo ${UNITTESTS} | wc -w
