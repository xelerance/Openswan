#
# Kunit tests for KLIPS -- SA reference allocation
#

OPENSWANSRCDIR?=$(shell cd ../../..;pwd)

include ${OPENSWANSRCDIR}/Makefile.inc

UMLPLAIN=$(shell . ${OPENSWANSRCDIR}/umlsetup.sh; echo $${POOLSPACE}/plain$${KERNVER})
KLIPS_TOP=${OPENSWANSRCDIR}/linux

#INPUTS=${OPENSWANSRCDIR}/testing/klips/inputs/02-sunrise-sunset-esp.pcap
#INPUTS+=${srcdir}cleartext.pcap

CC=gcc 
TESTCASE=sa01main

IPSEC_OBJS=ipsec_sa.o 
IPSEC_OBJS+=ipsec_snprintf.o ipsec_alg.o ipsec_sha1.o ipsec_md5c.o 
IPSEC_OBJS+=aes.o aes_cbc.o aes_xcbc_mac.o ipsec_alg_aes.o
IPSEC_OBJS+=cbc_enc.o set_key.o des_enc.o ecb_enc.o ipsec_alg_3des.o

include ${srcdir}../Makefile.kunit

# 
# Local Variables: 
# compile-command: "make"
# End: 
