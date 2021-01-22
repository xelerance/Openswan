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

FUNCTIONALTESTS=
FUNCTIONALTESTS+=01-confread
FUNCTIONALTESTS+=03-plutostart
FUNCTIONALTESTS+=04-whackwrite
FUNCTIONALTESTS+=05-addconn
FUNCTIONALTESTS+=06-dnsdelay
FUNCTIONALTESTS+=06-alsoflip
FUNCTIONALTESTS+=07-sourceipv6
FUNCTIONALTESTS+=08-sitelocalv6
FUNCTIONALTESTS+=09-v6inv4
FUNCTIONALTESTS+=10-defaultroute
FUNCTIONALTESTS+=11-subnets
FUNCTIONALTESTS+=12-rwcertwrite
FUNCTIONALTESTS+=13-bigpubkey
FUNCTIONALTESTS+=14-deadalgos
FUNCTIONALTESTS+=15-certload
FUNCTIONALTESTS+=16-v4inv6
FUNCTIONALTESTS+=17-connclientfamily
FUNCTIONALTESTS+=19-builtnss

# running 'make check KEEPGOING=1' will run through all tests w/o stopping
ERROR_CHECK=$(if ${KEEPGOING},,set -e;)
clean check pcapupdate:
	@${ERROR_CHECK} for unittest in ${FUNCTIONALTESTS}; do ${MAKE} -C $$unittest $@; done

testlist:
	@echo ${FUNCTIONALTESTS}
