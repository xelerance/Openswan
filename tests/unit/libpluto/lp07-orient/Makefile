# Openswan testing makefile
# Copyright (C) 2015 Michael Richardson <mcr@xelerance.com>
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
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb_print.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/virtual.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/rcv_whack.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/myid.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/foodgroups.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ipsec_doi.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_parent.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_child.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_notify.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_derived_keys.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_prfplus.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_x509.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/state.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/msgdigest.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/hmac.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/db_ops.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/crypt_utils.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/cookie.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb_struct.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb_v2_struct.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/crypto.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2.o
ifeq ($(USE_EXTRACRYPTO),true)
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_blowfish.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_twofish.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_serpent.o
endif
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_aes.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ike_alg_sha2.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/vendor.o
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${LIBPLUTO} ${LIBALGOPARSE} ${CRYPTOLIBS} ${WHACKLIB}
EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}
EXTRALIBS+=-lgmp ${LIBEFENCE} -lpcap  ${NSS_LIBS} ${FIPS_LIBS}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
OUTPUTS=OUTPUT

include Makefile.testcase
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER
FILTERS=sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed -f ${TESTUTILS}/certsize.sed

Q=$(if ${V},,@)
programs ${TESTNAME}: ${TESTNAME}.c
	@echo " CC ${TESTNAME}"
	${Q}${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@echo " LD ${TESTNAME}"
	${Q}${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRALIBS}

check:	${WHACKFILE} ${TESTNAME} OUTPUT
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTESTARGS} >>.gdbinit
	ulimit -c unlimited && ./${TESTNAME} ${UNITTESTARGS} >OUTPUT/${TESTNAME}.txt 2>&1
	@${FILTERS} OUTPUT/${TESTNAME}.txt | diff - output.txt

OUTPUT:
	@mkdir -p OUTPUT


ifeq (${WHACKREFFILE},)
${WHACKFILE}: OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/${ENDNAME} --config ${SAMPLEDIR}/${ENDNAME}.conf --whackout=${WHACKFILE} ${CONNNAME}
else
${WHACKFILE}: ${WHACKREFFILE} OUTPUT
	cp ${WHACKREFFILE} ${WHACKFILE}
endif

update:
	${FILTERS} OUTPUT/${TESTNAME}.txt >output.txt

clean:
	rm -f ${TESTNAME} ${WHACKFILE} *.o *~


pcapupdate:
	@true

