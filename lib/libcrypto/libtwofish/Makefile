LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := twofish.o twofish_cbc.o

ONEFILE=twofish.c
LIBRARY=crypto/libtwofish
LIB=libtwofish.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library

