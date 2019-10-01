# Openswan testing makefile
# Copyright (C) 2014 Michael Richardson <mcr@xelerance.com>
# Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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

OPENSWANSRCDIR?=$(shell cd ../../../..; pwd)
srcdir?=${OPENSWANSRCDIR}/tests/unit/libpluto/lp02-parentI1
include $(OPENSWANSRCDIR)/Makefile.inc

EXTRAFLAGS+=${USERCOMPILE} ${PORTINCLUDE} -I..
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/programs/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include

EXTRALIBS+=${OBJDIRTOP}/programs/pluto/hostpair.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/virtual.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/rcv_whack.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/myid.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/foodgroups.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ipsec_doi.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_parent.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_child.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_prfplus.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_x509.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/state.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/msgdigest.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/hmac.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/crypt_utils.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/cookie.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb_struct.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb_v2_struct.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/crypto.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_status.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_alg.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2.o
ifeq ($(USE_EXTRACRYPTO),true)
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_blowfish.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_twofish.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_serpent.o
endif
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_aes.o
#EXTRALIBS+=${OBJDIRTOP}/programs/pluto/vendor.o
EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${LIBOPENSWAN} ${LIBOSWLOG}
EXTRALIBS+=${LIBIPSECCONF} ${WHACKLIB} ${LIBOPENSWAN} ${LIBOSWKEYS} ${LIBALGOPARSE}
EXTRALIBS+=${LIBPLUTO} ${CRYPTOLIBS} ${LIBWHACK} ${LIBOSWLOG}
EXTRALIBS+=${LIBOPENSWAN} -lgmp ${LIBEFENCE} -lpcap

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}    ${HAVE_EFENCE}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

CONFBASE=${OPENSWANSRCDIR}/tests/functional/01-confread
UNITTEST1ARGS=${CONFBASE}/dooku ${CONFBASE}/dooku.conf dooku--cassidy-net
UNITTEST2ARGS=${CONFBASE}/cassidy ${CONFBASE}/cassidy.conf knothole--cassidy
UNITTEST3ARGS=${CONFBASE}/dooku ${CONFBASE}/n2n-transport.conf green

TESTNAME=whacksemantics
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

check: check1 check2 check3
update: update1 update2 update3

OUTPUT:
	@mkdir -p OUTPUT

${TESTNAME}: ${TESTNAME}.c
	@echo CC ${TESTNAME}.c
	@${CC} -g -O0 -o ${TESTNAME} ${EXTRAFLAGS} ${TESTNAME}.c ${EXTRALIBS}

# --- test 1 ---

.gdb1init:
	@echo "file ${TESTNAME}"          >$@
	@echo "set args "${UNITTEST1ARGS} >>$@

check1: OUTPUT ${TESTNAME} .gdb1init
	@echo "## CHECK 1 :: ${UNITTEST1ARGS}"
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} >OUTPUT/${TESTNAME}1.txt 2>&1
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}1.txt | diff - output1.txt
	@echo "## 1 OK"

update1:
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}1.txt >output1.txt

# --- test 2 ---

.gdb2init:
	@echo "file ${TESTNAME}"          >$@
	@echo "set args "${UNITTEST1ARGS} >>$@

check2: OUTPUT ${TESTNAME} .gdb2init
	@echo "## CHECK 2 :: ${UNITTEST2ARGS}"
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST2ARGS} >OUTPUT/${TESTNAME}2.txt 2>&1
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}2.txt | diff - output2.txt
	@echo "## 2 OK"

update2:
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}2.txt >output2.txt

# --- test 3 ---

.gdb3init:
	@echo "file ${TESTNAME}"          >$@
	@echo "set args "${UNITTEST1ARGS} >>$@

check3: OUTPUT ${TESTNAME} .gdb3init
	@echo "## CHECK 3 :: ${UNITTEST3ARGS}"
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST3ARGS} >OUTPUT/${TESTNAME}3.txt 2>&1
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}3.txt | diff - output3.txt
	@echo "## 3 OK"

update3:
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/conndebug.sed OUTPUT/${TESTNAME}3.txt >output3.txt

# ---

clean:
	rm -rf OUTPUT

pcapupdate:
	@true
