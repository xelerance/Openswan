OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS := sha1.o

ONEFILE=sha1.c
LIBRARY=crypto/libsha1
LIB=libsha1.a

ifeq ($(USE_LIBNSS),true)
CFLAGS+=-DHAVE_LIBNSS  
CFLAGS+=-I/usr/include/nspr4 -I/usr/include/nss3
endif


include ${srcdir}../../Makefile.library
