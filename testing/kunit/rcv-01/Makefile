# I really am not happy about using symlinks to make this work.
#
# I think that there should be a better way to do this.
# see module26.sh in packaging/makefiles
#

OPENSWANSRCDIR?=$(shell cd ../../..;pwd)

include ${OPENSWANSRCDIR}/Makefile.inc

UMLPLAIN=$(shell . ${OPENSWANSRCDIR}/umlsetup.sh; echo $${POOLSPACE}/plain$${KERNVER})
KLIPS_TOP=${OPENSWANSRCDIR}/linux

INPUTS=${OPENSWANSRCDIR}/testing/klips/inputs/02-sunrise-sunset-esp.pcap
INPUTS+=${srcdir}cleartext.pcap

CC=gcc 
TESTCASE=rcv01main
PACKFILE=rcv01pack

IPSEC_OBJS=ipsec_rcv.o ipsec_esp.o ipsec_ah.o ipsec_ipcomp.o
IPSEC_OBJS+=ipsec_md5c.o ipsec_sha1.o ipsec_sa.o 
IPSEC_OBJS+=ipsec_life.o
IPSEC_OBJS+=cbc_enc.o set_key.o des_enc.o ecb_enc.o ipsec_alg_3des.o
IPSEC_OBJS+=ipsec_snprintf.o ipsec_alg.o
IPSEC_OBJS+=aes.o aes_cbc.o aes_xcbc_mac.o ipsec_alg_aes.o

include ${srcdir}../Makefile.kunit

# 
# Local Variables: 
# compile-command: "make"
# End: 
