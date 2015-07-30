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

clean check:
	@${MAKE} -C lp01-spdbtest $@
	@${MAKE} -C lp02-parentI1 $@
	@${MAKE} -C lp03-whacksemantics $@
	@${MAKE} -C lp04-nsscert  $@
	@${MAKE} -C lp05-sha256cert $@
	@: ${MAKE} -C lp06-parentR1notchosen $@
	@${MAKE} -C lp07-orient     $@
	@${MAKE} -C lp08-parentR1   $@
	@${MAKE} -C lp10-parentI2   $@
	@${MAKE} -C lp11-parentI2dup $@
	@${MAKE} -C lp12-parentR2    $@
	@${MAKE} -C lp13-parentI3    $@
	@${MAKE} -C lp14-initiateself $@
	@${MAKE} -C lp15-respondself $@
	@${MAKE} -C lp16-initiateselfI2 $@
	@${MAKE} -C lp17-childselfpolicy $@
	@${MAKE} -C lp18-certificateselfI1 $@
	@${MAKE} -C lp19-certreplyselfR1 $@
	@${MAKE} -C lp20-certificateselfI2 $@
	@${MAKE} -C lp21-certreplyselfR2 $@
	@${MAKE} -C lp22-certreplymanyR2  $@
	@${MAKE} -C lp23-davecertI1       $@
	@${MAKE} -C lp24-certreplydaveR1  $@
	@${MAKE} -C lp25-wrongcacert      $@

