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

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/functional

include ${OPENSWANSRCDIR}/Makefile.inc

check:
	@${MAKE} -C 01-confread check
	@${MAKE} -C 03-plutostart check
	@${MAKE} -C 04-whackwrite check
	@${MAKE} -C 05-addconn check
	@${MAKE} -C 06-dnsdelay check
	@${MAKE} -C 06-alsoflip check
	@${MAKE} -C 07-sourceipv6 check
	@${MAKE} -C 08-sitelocalv6 check
	@${MAKE} -C 09-v6inv4 check
	@${MAKE} -C 10-defaultroute check
	@${MAKE} -C 11-subnets      check
	@${MAKE} -C 12-rwcertwrite  check
	@${MAKE} -C 13-bigpubkey  check


