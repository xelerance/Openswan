# Copyright (C) 2000, 2001  Internet Software Consortium.
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
# DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
# INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
# FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# $Id: Makefile,v 1.4 2005/09/17 21:57:45 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc
srcdir?=./

HOSTCINCLUDES =	-I${srcdir}${ISCHOSTARCH}/include \
		-I${srcdir}../libisc/${ISCHOSTARCH}/include \
		-I${srcdir}../libisc/nothreads/include \
		-I. -I./include -I${srcdir}include \
		-I${srcdir}../libisc/include

CINCLUDES =	-I${srcdir}${ISCARCH}/include \
		-I${srcdir}../libisc/${ISCARCH}/include \
		-I${srcdir}../libisc/nothreads/include \
		-I. -I./include -I${srcdir}include \
		-I${srcdir}../libisc/include
CDEFINES = ${USERCOMPILE} ${PORTINCLUDE}
CWARNINGS = -Werror

CFLAGS+=${CINCLUDES} ${CDEFINES} ${CWARNINGS}

VERSION="@(\#) openswan-hacking-9.3-for-osw2"
LIBINTERFACE=2
LIBREVISION=0
LIBAGE=1
LIB=libdns
HDRS=include/dns/enumtype.h include/dns/enumclass.h include/dns/rdatastruct.h code.h

# Alphabetically
OBJS =		name.o rdata.o compress.o result.o ttl.o rcode.o
OBJS +=         time.o key.o lib.o

# Alphabetically
SRCS =		name.c rdata.c compress.c result.c ttl.c rcode.c
SRCS +=         time.c key.c lib.c

programs all: ${LIB}.a

version.o: version.c
	${LIBTOOL} --mode=compile ${CC} ${ALL_CFLAGS} \
		-DVERSION=\"${VERSION}\" \
		-DLIBINTERFACE=${LIBINTERFACE} \
		-DLIBREVISION=${LIBREVISION} \
		-DLIBAGE=${LIBAGE} \
		${CINCLUDES} ${CDEFINES} ${CWARNINGS} \
		-c ${srcdir}/version.c

${LIB}.a: ${OBJS} version.o
	${AR} ${ARFLAGS} $@ ${OBJS} version.o

timestamp: ${LIB}.a
	touch timestamp

clean distclean mostlyclean realclean cleanall spotless::
	rm -f ${LIB}.a ${LIB}.la timestamp $(OBJS) version.o ${HDRS} gen

install checkprograms check install_file_list:
	@true

TAGS: ${SRCS}
	etags ${SRCS}

rdata.o: code.h 
name.o: ${HDRS}

include/dns/enumtype.h: gen
	mkdir -p include/dns
	./gen -s ${srcdir} -t > $@

include/dns/enumclass.h: gen
	mkdir -p include/dns
	./gen -s ${srcdir} -c > $@

include/dns/rdatastruct.h: gen \
		${srcdir}rdata/rdatastructpre.h \
		${srcdir}rdata/rdatastructsuf.h
	mkdir -p include/dns
	./gen -s ${srcdir} -i \
		-P ${srcdir}rdata/rdatastructpre.h \
		-S ${srcdir}rdata/rdatastructsuf.h > $@

code.h:	gen
	./gen -s ${srcdir} > code.h

# this program is to be built on the host, and should not be
# cross-compiled!
HOSTCC?=cc
gen: gen.c
	${HOSTCC} ${HOSTCINCLUDES} ${LDFLAGS} -o $@ ${srcdir}gen.c ${LIBS}

