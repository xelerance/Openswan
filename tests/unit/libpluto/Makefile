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
	@${MAKE} -C lp06-parentR1notchosen $@
	@${MAKE} -C lp07-orient     $@
	@${MAKE} -C lp08-parentR1   $@
	: lp09 needs some analysis
	: @${MAKE} -C lp09-I1notify   $@
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
	@${MAKE} -C lp24-certreplydaveR2  $@
	@${MAKE} -C lp25-wrongcacert      $@
	@${MAKE} -C lp26-davecertI2       $@
	@${MAKE} -C lp27-dnsloadI1        $@
	@${MAKE} -C lp28-addrinfoserialize $@
	@${MAKE} -C lp29-adns              $@
	@${MAKE} -C lp30-dnskick           $@
	@${MAKE} -C lp31-IDhostpair       $@
	@${MAKE} -C lp32-parentR2anychoice $@
	@${MAKE} -C lp33-IDanypair         $@
	@${MAKE} -C lp33-dnsload2          $@
	@${MAKE} -C lp33-IDanypair         $@
	@${MAKE} -C lp34-orientafterlisten  $@
	@if [ $$(uname -m) == "x86_64" ]; then ${MAKE} -C lp35-threeconns  $@; fi
	@${MAKE} -C lp36-h2hI1            $@
	@${MAKE} -C lp37-h2hR1            $@
	@${MAKE} -C lp38-h2hI2            $@
	@${MAKE} -C lp39-h2hR2            $@
	@${MAKE} -C lp40-orientafterprivate $@
	@${MAKE} -C lp41-orientmoon       $@
	@${MAKE} -C lp42-loadbobdefaultroute $@
	@${MAKE} -C lp43-parentM1 	$@
	@${MAKE} -C lp44-h2hR1-deny-ikev1 	$@
	@${MAKE} -C lp45-h2hR1-noikev2  	$@
