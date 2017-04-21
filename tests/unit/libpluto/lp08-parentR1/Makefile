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
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/spdb_print.o
EXTRALIBS+=${LIBOSWLOG} ${LIBOPENSWAN} ${LIBOSWLOG}

EXTRALIBS+=${OBJDIRTOP}/programs/pluto/hostpair.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/virtual.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/rcv_whack.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/myid.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/foodgroups.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ipsec_doi.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_parent.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_child.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_derived_keys.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_prfplus.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/ikev2_x509.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/state.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/msgdigest.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/hmac.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/plutoalg.o
EXTRALIBS+=${OBJDIRTOP}/programs/pluto/demux.o
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
EXTRALIBS+=${PLUTOLIB} ${CRYPTOLIBS} ${WHACKLIB}
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
WHACKFILE3=${OUTPUTS}/any1.record.${ARCH}
UNITTEST1ARGS=${WHACKFILE} parker1--jj2 parentI1badKE.pcap OUTPUT/parentR1notify.pcap
UNITTEST2ARGS=${WHACKFILE} parker1--jj2 parentI1.pcap      OUTPUT/parentR1.pcap
UNITTEST3ARGS=${WHACKFILE3} any1--jj2 parker1.pcap       OUTPUT/parentR1parker.pcap

TESTNAME=parentR1
EF_DISABLE_BANNER=1
export EF_DISABLE_BANNER

programs ${TESTNAME}: ${TESTNAME}.c $(wildcard ../seam_*.c)
	@${CC} -c -g -O0 ${TESTNAME}.c ${EXTRAFLAGS}
	@${CC} -g -O0 -o ${TESTNAME} ${TESTNAME}.o ${EXTRAFLAGS} ${EXTRALIBS}

check: OUTPUT/R1-dump.txt OUTPUT/R1notify-dump.txt OUTPUT/R1parker-dump.txt
OUTPUT/R1-dump.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb2init
	@echo "set args "${UNITTEST2ARGS} >>.gdb2init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST2ARGS} >OUTPUT/${TESTNAME}_2.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_2.txt | diff - output2.txt
	tcpdump -n -t -v -r OUTPUT/parentR1.pcap | tee OUTPUT/R1-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1-dump.txt

OUTPUT/R1notify-dump.txt:	${WHACKFILE} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"          >.gdb1init
	@echo "set args "${UNITTEST1ARGS} >>.gdb1init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST1ARGS} >OUTPUT/${TESTNAME}_1.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_1.txt | diff - output1.txt
	tcpdump -n -t -v -r OUTPUT/parentR1notify.pcap | tee OUTPUT/R1notify-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1notify-dump.txt

OUTPUT/R1parker-dump.txt:	${WHACKFILE3} ${TESTNAME}
	@mkdir -p OUTPUT
	@echo "file ${TESTNAME}"           >.gdb3init
	@echo "set args "${UNITTEST3ARGS} >>.gdb3init
	ulimit -c unlimited && ./${TESTNAME} ${UNITTEST3ARGS} >OUTPUT/${TESTNAME}_3.txt 2>&1
	@sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_3.txt | diff - output3.txt
	tcpdump -n -t -v -r OUTPUT/parentR1parker.pcap | tee OUTPUT/R1parker-dump.txt | sed -f ${TESTUTILS}/sanity.sed | diff - R1parker-dump.txt

${WHACKFILE}: ${SAMPLEDIR}/parker.conf
	@mkdir -p OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/parker --config ${SAMPLEDIR}/parker.conf --whackout=${WHACKFILE} parker1--jj2

${WHACKFILE3}: ${SAMPLEDIR}/parker.conf
	@mkdir -p OUTPUT
	${READWRITE} --rootdir=${SAMPLEDIR}/parker --config ${SAMPLEDIR}/parker.conf --whackout=${WHACKFILE3} any1--jj2

update: update3 update2 update1
update1:
	-make OUTPUT/R1-dump.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_1.txt >output1.txt
	[ -f OUTPUT/R1-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1-dump.txt >R1-dump.txt

update2:
	-make OUTPUT/R1notify-dump.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_2.txt >output2.txt
	[ -f OUTPUT/R1notify-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1notify-dump.txt >R1notify-dump.txt

update3:
	-make OUTPUT/R1parker-dump.txt
	sed -f ${TESTUTILS}/leak-detective.sed -f ${TESTUTILS}/whack-processing.sed OUTPUT/${TESTNAME}_3.txt >output3.txt
	[ -f OUTPUT/R1parker-dump.txt ] && sed -f ${TESTUTILS}/sanity.sed OUTPUT/R1parker-dump.txt >R1parker-dump.txt

clean:
	rm -f OUTPUT/${TESTNAME}_*.txt ${TESTNAME} ${WHACKFILE} OUTPUT/*.pcap

