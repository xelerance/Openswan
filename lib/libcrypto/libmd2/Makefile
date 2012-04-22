LIBRESWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${LIBRESWANSRCDIR}/Makefile.inc
include ${LIBRESWANSRCDIR}/Makefile.ver

OBJS := md2.o

ONEFILE=md2.c
LIBRARY=crypto/libmd2
LIB=libmd2.a

include ${srcdir}../../Makefile.library
