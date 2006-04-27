OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS := md5.o

ONEFILE=md5.c
LIBRARY=crypto/libmd5
LIB=libmd5.a

include ${srcdir}../../Makefile.library
