OPENSWANSRCDIR?=$(shell cd ../../..; pwd)
srcdir?=./

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver

OBJS=serpent.o serpent_cbc.o
LIBRARY=crypto/libserpent
LIB=libserpent.a
ONEFILE=serpent.h
INCLUDES+=-I${srcdir}../include

include ${srcdir}../../Makefile.library

