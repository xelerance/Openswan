OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS := hmac_sha2.o ike_alg_sha2.o

ONEFILE=ike_alg_sha2.c
LIBRARY=crypto/libsha2
LIB=libsha2.a
INCLUDES+=-I${srcdir}../include

ifeq ($(USE_LIBNSS),true)
OBJS  += sha2nss.o
CFLAGS+=-DHAVE_LIBNSS
INCLUDES+=-I/usr/include/nspr4 -I/usr/include/nss3
else
OBJS  += sha2.o
endif

include ${srcdir}../../Makefile.library

