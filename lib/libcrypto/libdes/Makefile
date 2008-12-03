ifndef OPENSWANSRCDIR
OPENSWANSRCDIR=$(shell cd ../../..; pwd)
endif

include ${OPENSWANSRCDIR}/Makefile.inc

DESSRC=${OPENSWANSRCDIR}/linux/net/ipsec/des

VPATH+=${DESSRC}

OPTS0= -DLIBDES_LIT 

OPTS= $(OPTS0) $(OPTS1) $(OPTS2) $(OPTS3) $(OPTS4)

OBJS=des_enc.o cbc_enc.o set_key.o ecb_enc.o fcrypt_b.o
FCRYPT = fcrypt.o
ONEFILE=fcrypt.c
LIBRARY=crypto/libdes
LIB=libdes.a

include ${srcdir}../../Makefile.library

