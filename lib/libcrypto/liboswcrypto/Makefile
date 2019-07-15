OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS := oswcrypto.o init.o xfrm_plugin.o groups.o
ifeq ($(HAVE_OCF),true)
OBJS += cryptodev.o
CFLAGS += -DHAVE_OCF=1
endif

ONEFILE=oswcrypto.c
LIBRARY=crypto/liboswcrypto
LIB=liboswcrypto.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library
