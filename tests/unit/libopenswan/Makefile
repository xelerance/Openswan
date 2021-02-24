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
UNITTESTS+=lo01-sameid
UNITTESTS+=lo02-verifysigs
UNITTESTS+=lo03-includesecrets
UNITTESTS+=lo04-verifypubkeys
UNITTESTS+=lo05-datatot
UNITTESTS+=lo06-verifybadsigs
UNITTESTS+=lo07-bleichenbacher-attack
UNITTESTS+=lo08-oswconf

ERROR_CHECK=$(if ${KEEPGOING},,set -e;)

programs clean check pcapupdate:
clean check pcapupdate programs:
	@${ERROR_CHECK} for unittest in ${UNITTESTS}; do ${MAKE} -C $$unittest $@; done

testlist:
	@echo ${UNITTESTS}







