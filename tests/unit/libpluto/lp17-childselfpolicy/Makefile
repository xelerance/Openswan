# Openswan unit testing makefile
# Copyright (C) 2014,2015 Michael Richardson <mcr@xelerance.com>
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
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/spdb_print.o
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG}

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/virtual.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/rcv_whack.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/myid.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/foodgroups.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ipsec_doi.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_parent.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_child.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_notify.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_derived_keys.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_prfplus.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_x509.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/state.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/msgdigest.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/hmac.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/keys.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/demux.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/db_ops.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/crypt_utils.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/cookie.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/spdb.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/spdb_struct.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/spdb_v2_struct.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/crypto.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ike_alg.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2.o
ifeq ($(USE_EXTRACRYPTO),true)
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_blowfish.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_twofish.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_serpent.o
endif
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_aes.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ike_alg_sha2.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/vendor.o
EXTRALIBS+=${LIBPLUTO} ${CRYPTOLIBS} ${WHACKLIB}
EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG} ${LIBOSWKEYS}
EXTRALIBS+=${LIBPLUTO} ${CRYPTOLIBS} ${WHACKLIB}
EXTRALIBS+=${LIBDESLITE} ${LIBAES}
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG}
EXTRALIBS+=${NSS_LIBS} ${FIPS_LIBS}
EXTRALIBS+=-lgmp ${LIBEFENCE} -lpcap  ${NSS_LIBS} ${FIPS_LIBS}

EXTRAFLAGS+=${NSS_FLAGS}    ${FIPS_FLAGS}
EXTRAFLAGS+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

READWRITE=${OBJDIRTOP}/programs/readwriteconf/readwriteconf
SAMPLEDIR=../samples
OUTPUTS=OUTPUT
WHACKFILE=${OUTPUTS}/ikev2client.record.${ARCH}
FILTERS=sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed -f ${TESTUTILS}/certsize.sed
include Makefile.testcase

EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

Q=$(if ${V},,@)
programs ${TESTNAME}: ${TESTNAME}.c $(wildcard ../seam_*.c) ${EXTRAOBJS}
	@echo " CC ${TESTNAME}"
	${Q}${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@echo " LD ${TESTNAME}"
	${Q}${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRAOBJS} ${EXTRALIBS}

check:: OUTPUT/R2-dump.txt

OUTPUT/R2-dump.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb1init
	@echo "set args "${UNITTEST1ARGS} >>.gdb1init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} >OUTPUT/${TESTNAME}_1.txt 2>&1
	tcpdump -n -t -v -r ${UNITTEST1PCAP} | tee OUTPUT/R2-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R2-dump.txt
	@${FILTERS} OUTPUT/${TESTNAME}_1.txt | diff - output1.txt

ifneq (${UNITTEST2PCAP},)
check:: OUTPUT/R2-any.txt

OUTPUT/R2-any.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb2init
	@echo "set args "${UNITTEST2ARGS} >>.gdb2init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST2ARGS} >OUTPUT/${TESTNAME}_2.txt 2>&1
	tcpdump -n -t -v -r ${UNITTEST2PCAP} | tee OUTPUT/R2-any.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R2-any.txt
	@${FILTERS} OUTPUT/${TESTNAME}_2.txt | diff - output2.txt
endif

${WHACKFILE}: ${SAMPLEDIR}/${ENDNAME}.conf OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/${ENDNAME} --config ${SAMPLEDIR}/${ENDNAME}.conf --whackout=${WHACKFILE} ${CONNNAME}

ifneq (${UNITTEST2PCAP},)
update:: update2
update2:
	-make OUTPUT/R2-any.txt
	${FILTERS} OUTPUT/${TESTNAME}_2.txt >output2.txt
	[ -f OUTPUT/R2-any.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R2-any.txt >R2-any.txt
endif

update:: update1
update1:
	-make OUTPUT/R2-dump.txt
	${FILTERS} OUTPUT/${TESTNAME}_1.txt >output1.txt
	[ -f OUTPUT/R2-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R2-dump.txt >R2-dump.txt


clean:
	rm -f OUTPUT/${TESTNAME}_*.txt ${TESTNAME} ${WHACKFILE} OUTPUT/*.pcap *~ *.o

OUTPUT:
	@mkdir -p OUTPUT

