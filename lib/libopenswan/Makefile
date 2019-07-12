# Openswan library
# Copyright (C) 1998-2001  Henry Spencer.
# Copyright (C) 2003, 2004 Xelerance Corporation
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#


OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


MANDIR=$(MANTREE)/man3

SRCS=addrtoa.c addrtot.c addrtypeof.c anyaddr.c atoaddr.c \
	atoasr.c atosubnet.c atoul.c constants.c copyright.c datatot.c \
	alloc.c biglset.c diag.c familytot.c \
	goodmask.c id.c initaddr.c initsaid.c initsubnet.c \
	iprange.c \
        keyblobtoid.c \
	lex.c mpzfuncs.c \
	optionsfrom.c oswconf.c oswtime.c oswid.c \
	prng.c \
	portof.c rangetoa.c rangetosubnet.c sameaddr.c \
	satot.c secrets.c strlcat.c subnetof.c subnettoa.c subnettot.c \
	subnettypeof.c ttoaddr.c ttodata.c ttoprotoport.c \
	ttosa.c ttosubnet.c ttoul.c ultoa.c ultot.c \
	$(X509LIB)

SRCS+=sanitizestring.c pfkey_print.c pfkey_sock.c pfkey_error.c

ifeq ($(USE_KLIPS),true)
KLIPS_DEFS=-DKLIPS
# Linux always supports udpfromto
UDPFROMTO_SRCS=udpfromto.c
endif

ifeq ($(USE_BSDKAME),true)
# BSD always supports udpfromto
UDPFROMTO_SRCS=udpfromto.c
endif

ifeq ($(USE_PFKEYv2),true)
PFKEYV2_DEFS=-DPFKEYV2
PFKEYV2_SRCS+=pfkey_v2_build.c pfkey_v2_ext_bits.c pfkey_v2_parse.c
PFKEYV2_SRCS+=pfkey_v2_debug.c
endif

CFLAGS+=-DUSE_SHA2
CFLAGS+=-I${OPENSWANSRCDIR}/lib/libcrypto/libsha2

OBJS=${SRCS:.c=.o} ${PFKEYV2_SRCS:.c=.o} ${UDPFROMTO_SRCS:.c=.o} version.o

MANSRCDIR=${OPENSWANSRCDIR}/lib/libopenswan

HDRS=internal.h

LIBA=libopenswan.a

# NSS things
DEFINES+=${NSS_FLAGS}    ${FIPS_FLAGS}
INCLUDES+=${NSS_HDRDIRS}  ${FIPS_HDRDIRS}

# Original flags
CFLAGS+=${PORTINCLUDE} -I.
CFLAGS+=-I${OPENSWANSRCDIR} -DDEBUG
CFLAGS+=${PFKEYV2_DEFS} ${KLIPS_DEFS}
CFLAGS+= -I${OPENSWANSRCDIR}/include ${PORTINCLUDE} $(USERCOMPILE) ${CROSSFLAGS} ${INCLUDES}
CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith

# must turn this off due to initsubnet.c
CFLAGS+= -Wno-error=cast-qual

# some files need -Wno-error-cpp, calculated in Makefile.common
CFLAGS+=${GCC_CPP_FLAG}

#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast
CFLAGS+= ${DEFINES}

ifeq ($(USE_NAT_TRAVERSAL),true)
CFLAGS+= -DNAT_TRAVERSAL
endif

ifeq ($(USE_SINGLE_CONF_DIR),true)
CFLAGS+= -DSINGLE_CONF_DIR=1
endif

ifeq ($(USE_DMALLOC),true)
CFLAGS+= -DDMALLOC
endif

ifeq ($(USE_LIBNSS),true)
CFLAGS+=-DHAVE_LIBNSS
CFLAGS+=-I/usr/include/nspr4 -I/usr/include/nss3
endif

ifeq ($(USE_MODP_RFC5114),true)
CFLAGS+=-DUSE_MODP_RFC5114
endif

ifeq ($(USE_LABELED_IPSEC),true)
CFLAGS+=-DHAVE_LABELED_IPSEC
endif

CFLAGS+=-DFINALCONFDIR=\"${FINALCONFDIR}\"
CFLAGS+=-DFINALCONFDDIR=\"${FINALCONFDDIR}\"
CFLAGS+=-DFINALCONFFILE=\"${FINALCONFFILE}\"
CFLAGS+=-DFINALVARDIR=\"${FINALVARDIR}\"
CFLAGS+=-DFINALLIBEXECDIR=\"${FINALLIBEXECDIR}\"
CFLAGS+=-DFINALLIBDIR=\"${FINALLIBDIR}\"
CFLAGS+=-DFINALSBINDIR=\"${FINALSBINDIR}\"

ARFLAGS=crvs
EXTHDRS=des.h
EXTLIBS=libdes.a
MANS=anyaddr.3 atoaddr.3 atoasr.3 atoul.3 goodmask.3 \
	initaddr.3 initsubnet.3 optionsfrom.3 portof.3 rangetosubnet.3 \
	sameaddr.3 subnetof.3 ttoaddr.3 ttodata.3 ttosa.3 ttoul.3 version.3

.PHONY:	all install clean l t lt tar check depend checkprograms

# we can't do tests with two conditions, but we can concatenate the strings
SHOULDWERESTART=${USE_OBJDIR}$(wildcard ttodata.3.xml)
ifeq ($(SHOULDWERESTART),truettodata.3.xml)
all programs clean install:
	@echo OBJDIR MAKE
	@cd ${OPENSWANSRCDIR} && cd ${OBJDIRTOP}/lib/libopenswan && make $@
else
all:	$(LIBA)
programs: $(LIBA)
clean:	cleanall
install: doinstall

endif

doinstall:
	true

install_file_list:
	@for f in $(MANS) ; \
	do \
		echo $(MANDIR)/ipsec_$$f;\
	done;
	@$(OPENSWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${MANSRCDIR}/$(man)) | \
	while read from to; \
	do \
		echo $(MANDIR)/$$to; \
	done

$(LIBA): $(OBJS)
	@echo AR ${LIBA}
	@$(AR) $(ARFLAGS) $(LIBA) $(OBJS)

$(OBJS):	$(HDRS)

%.o: %.c
	@echo CC $(notdir $<)
	@$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

# build version.c using version number from Makefile.ver
version.c:	version.in.c ${OPENSWANSRCDIR}/Makefile.ver
	@echo VERSION processing ${IPSECVERSION}
	@sed '/"/s/@IPSECVERSION@/$(IPSECVERSION)/' ${OPENSWANSRCDIR}/lib/libopenswan/version.in.c >$@

#libdes.a:	../libdes/libdes.a
#	ln -f -s ../libdes/libdes.a
#
# yes, that's CFLAG=, not CFLAGS=
#../libdes/libdes.a:
#	cd ../libdes ; \
#	if test " `arch | sed 's/^i[3456]/x/'`" = " x86" ; \
#	then $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' TESTING='' x86-elf ; \
#	else $(MAKE) CC='$(CC)' CFLAG='$(CFLAGS)' libdes.a ; \
#	fi

test-%: %.c
	${CC} ${CFLAGS} -D`echo $* | tr 'a-z' 'A-Z'`_MAIN $*.c -o test-$*

cleanall:
	rm -f $(LIBA) $(LIBL) *.o try* core *.core $(EXTHDRS) $(EXTLIBS) version.c


# developer-only stuff
l:
	$(MAKE) $(LIB) ARFLAGS=crv CFLAGS=-O
	$(RANLIB) $(LIB)

t:	$(LIB)
	ln -f -s ${srcdir}/atosubnet.c try.c
	${CC} ${CFLAGS} -DATOSUBNET_MAIN try.c $(LIB) -o try
	./try -r
	ln -f -s $[srcdir}/ttosubnet.c try1a.c
	${CC} ${CFLAGS} -DTTOSUBNET_MAIN try1a.c $(LIB) -o try1a
	./try1a -r
	ln -f -s ${srcdir}/ttodata.c try2.c
	${CC} ${CFLAGS} -DTTODATA_MAIN try2.c $(LIB) -o try2
	./try2 -r
	ln -f -s ${srcdir}/atoasr.c try3.c
	${CC} ${CFLAGS} -DATOASR_MAIN try3.c $(LIB) -o try3
	./try3 -r
	ln -f -s ${srcdir}/ttosa.c try4a.c
	${CC} ${CFLAGS} -DTTOSA_MAIN try4a.c $(LIB) -o try4a
	./try4a -r
	ln -f -s ${srcdir}/rangetosubnet.c try6.c
	${CC} ${CFLAGS} -DRANGETOSUBNET_MAIN try6.c $(LIB) -o try6
	./try6 -r
	ln -f -s ${srcdir}/addrtot.c try7.c
	${CC} ${CFLAGS} -DADDRTOT_MAIN try7.c $(LIB) -o try7
	./try7 -r

lt:	$(LIB)
	$(MAKE) t
	cp optionsfrom.c try5.c
	cc -DTEST try5.c $(LIB) -o try5
	echo --foo --bar >try5in1
	echo --optionsfrom >>try5in1
	echo try5in2 >>try5in1
	echo --foo >try5in2
	./try5 --foo --bar --optionsfrom try5in1 --bar something

tar:	clean
	tar -cvf /tmp/lib.tar Makefile [a-z]*

check:
	echo no checks in lib right now.

checkprograms:

# this should be a generic process.
# Gather dependencies caused by explicit #includes within .c files
depend:
	(ls $(wildcard $(SRCS)) $(wildcard $(addprefix ${KLIPSSRCDIR}/,$(SRCS)))) | grep '\.c' | xargs $(CC) -MM ${CFLAGS} ${PORTINCLUDE} ${ALLFLAGS} | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend

-include ${srcdir}Makefile.depend
