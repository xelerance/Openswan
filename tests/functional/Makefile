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

clean check:
	@${MAKE} -C 01-confread $@
	@${MAKE} -C 03-plutostart $@
	@${MAKE} -C 04-whackwrite $@
	@${MAKE} -C 05-addconn $@
	@${MAKE} -C 06-dnsdelay $@
	@${MAKE} -C 06-alsoflip $@
	@${MAKE} -C 07-sourceipv6 $@
	@${MAKE} -C 08-sitelocalv6 $@
	@${MAKE} -C 09-v6inv4 $@
	@${MAKE} -C 10-defaultroute $@
	@${MAKE} -C 11-subnets      $@
	@${MAKE} -C 12-rwcertwrite  $@
	@${MAKE} -C 13-bigpubkey  $@


