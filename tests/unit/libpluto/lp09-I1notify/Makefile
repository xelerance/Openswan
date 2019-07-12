# FreeS/WAN testing makefile
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
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include/pluto
EXTRAFLAGS+=-I${OPENSWANSRCDIR}/include
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/spdb_print.o
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG}

EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/hostpair.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/virtual.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/rcv_whack.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/myid.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/foodgroups.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ipsec_doi.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_parent.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_child.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_derived_keys.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_prfplus.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/ikev2_x509.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/state.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/msgdigest.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/hmac.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/demux.o
EXTRAOBJS+=${OBJDIRTOP}/programs/pluto/crypt_ke.o
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
UNITTEST1ARGS=-r ${WHACKFILE} parker1--jj2 parentR1notify.pcap OUTPUT/parentI1n.pcap

TESTNAME=parent_outI1inR1
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER


check:	OUTPUT/R1notify-dump.txt

${TESTNAME}:	${WHACKFILE} OUTPUT $(wildcard ../seam_*.c) ${EXTRAOBJS}
	@echo CC ${TESTNAME}.c
	@${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRAOBJS} ${EXTRALIBS}
	@echo "file ${TESTNAME}"          >.gdbinit
	@echo "set args "${UNITTEST1ARGS} >>.gdbinit

OUTPUT/R1notify-dump.txt t1: ${WHACKFILE} ${TESTNAME}
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} >OUTPUT/${TESTNAME}1.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}1.txt | diff - output1.txt

${WHACKFILE}: OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/parker --config ${SAMPLEDIR}/parker.conf --whackout=${WHACKFILE} parker1--jj2

update: OUTPUT
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}1.txt >output1.txt

clean: OUTPUT
	rm -f OUTPUT/${TESTNAME}.txt ${TESTNAME} ${WHACKFILE} OUTPUT/parentI1.pcap *~ *.o

OUTPUT:
	@mkdir -p OUTPUT

