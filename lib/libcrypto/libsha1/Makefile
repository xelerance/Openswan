OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


ONEFILE=sha1.c
LIBRARY=crypto/libsha1
LIB=libsha1.a

ifeq ($(USE_LIBNSS),true)
CFLAGS+=-DHAVE_LIBNSS  
CFLAGS+=-I/usr/include/nspr4 -I/usr/include/nss3
OBJS := sha1nss.o
else
OBJS := sha1.o
endif


include ${srcdir}../../Makefile.library
