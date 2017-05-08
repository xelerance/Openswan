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

UNITTESTS=lp01-spdbtest \
	lp02-parentI1 \
	lp03-whacksemantics \
	lp04-nsscert  \
	lp05-sha256cert \
	lp06-parentR1notchosen \
	lp07-orient     \
	lp08-parentR1   \
	lp10-parentI2   \
	lp11-parentI2dup \
	lp12-parentR2    \
	lp13-parentI3    \
	lp14-initiateself \
	lp15-respondself \
	lp16-initiateselfI2 \
	lp17-childselfpolicy \
	lp18-certificateselfI1 \
	lp19-certreplyselfR1 \
	lp20-certificateselfI2 \
	lp21-certreplyselfR2 \
	lp22-certreplymanyR2  \
	lp23-davecertI1       \
	lp24-certreplydaveR2  \
	lp25-wrongcacert      \
	lp26-davecertI2       \
	lp27-dnsloadI1        \
	lp28-addrinfoserialize \
	lp29-adns              \
	lp30-dnskick           \
	lp31-IDhostpair       \
	lp32-parentR2anychoice \
	lp33-IDanypair         \
	lp33-dnsload2          \
	lp33-IDanypair         \
	lp34-orientafterlisten  \
	lp36-h2hI1            \
	lp37-h2hR1            \
	lp38-h2hI2            \
	lp39-h2hR2            \
	lp40-orientafterprivate \
	lp41-orientmoon       \
	lp42-loadbobdefaultroute \
	lp43-parentM1 	\
	lp44-h2hR1-deny-ikev1 	\
	lp45-h2hR1-noikev2  	\
	lp46-rekeyikev2-I1   \
	lp47-rekeyikev2-R1   \
	lp48-rekeyikev2-inCR1 \
	lp50-rekey-no-reply-rekey \
	lp52-davecert-gatewayID-I1  \
	lp53-davecert-gatewayID-R1  \
	lp54-davecert-gatewayID-I2  \
	lp55-davecert-gatewayID-R2  \
	lp56-rekeyv2nopfs-I1  \
	lp57-rekeyv2nopfs-R1  \
	lp58-rekeyv2nopfs-inCR1  \
	lp60-bestif                 \
	lp61-nattI1 lp62-nattR1 lp63-nattI2

clean check pcapupdate:
	@set -e; for unittest in ${UNITTESTS}; do ${MAKE} -C $$unittest $@; done

testlist:
	@echo ${UNITTESTS}

