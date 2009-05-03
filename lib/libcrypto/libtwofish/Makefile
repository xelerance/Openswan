OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS := twofish.o twofish_cbc.o

ONEFILE=twofish.c
LIBRARY=crypto/libtwofish
LIB=libtwofish.a
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library

