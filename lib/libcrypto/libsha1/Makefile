OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS := sha1.o

ONEFILE=sha1.c
LIBRARY=crypto/libsha1
LIB=libsha1.a

include ${srcdir}../../Makefile.library
