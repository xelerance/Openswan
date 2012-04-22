LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := md5.o

ONEFILE=md5.c
LIBRARY=crypto/libmd5
LIB=libmd5.a

ifeq ($(USE_LIBNSS),true)
CFLAGS+=-DHAVE_LIBNSS
CFLAGS+=-I/usr/include/nspr4 -I/usr/include/nss3
endif

include ${srcdir}../../Makefile.library
