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


OPENSWANSRCDIR?=$(shell cd ../..; pwd)

include ${OPENSWANSRCDIR}/Makefile.inc
include ${OPENSWANSRCDIR}/Makefile.ver


MANDIR=$(MANTREE)/man3

QCB=${OPENSWANSRCDIR}/lib/libwhack/qcbor
SRCS=whackwrite.c aliascomp.c plutoopts.c

SRCS+=UsefulBuf.c qcbor_encode.c qcbor_decode.c qcbor_err_to_str.c
SRCS+=ieee754.c

OBJS=${SRCS:.c=.o}

MANSRCDIR=${OPENSWANSRCDIR}/lib/libopenswan
VPATH+= ${QCB}/src

LIB=libwhack.a

# Original flags
INCLUDES=-I. -I${OPENSWANSRCDIR} -I${QCB}/inc
INCLUDES+=-I${OPENSWANSRCDIR}/include
CFLAGS+=${PORTINCLUDE} ${INCLUDES}
CFLAGS+=-DDEBUG
CFLAGS+= -DQCBOR_DISABLE_FLOAT_HW_USE
CFLAGS+= -DQCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA
CFLAGS+= $(USERCOMPILE)
CFLAGS+= -Wall
#CFLAGS+= -Wconversion
#CFLAGS+= -Wmissing-prototypes
CFLAGS+= -Wpointer-arith
CFLAGS+= -Wno-cast-qual
#CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wstrict-prototypes
#CFLAGS+= -pedantic
#CFLAGS+= -W
#CFLAGS+= -Wwrite-strings
CFLAGS+= -Wbad-function-cast
# Allow compile on older gcc, but still support u_char, etc.
CFLAGS+= -std=gnu11

ifeq ($(USE_NAT_TRAVERSAL),true)
CFLAGS+= -DNAT_TRAVERSAL
endif

ifeq ($(USE_LABELED_IPSEC),true)
CFLAGS+= -DHAVE_LABELED_IPSEC
endif

ifeq ($(USE_DYNAMICDNS),true)
CFLAGS+= -DDYNAMICDNS
endif

ARFLAGS=crvs
MANS=

.PHONY:	all install clean l t lt tar check depend checkprograms

# we can't do tests with two conditions, but we can concatenate the strings
SHOULDWERESTART=${USE_OBJDIR}$(wildcard whackwrite.c)
ifeq ($(SHOULDWERESTART),truewhackwrite.c)
all programs clean install:
	cd ${OPENSWANSRCDIR} && cd ${OBJDIRTOP}/lib/libwhack && make $@
else
all:	$(LIB) ${LIBL}
programs: $(LIB) ${LIBL}
clean:	cleanall
install: doinstall

endif

doinstall:
	@mkdir -p $(MANDIR)
	@for f in $(MANS) ; \
	do \
		$(INSTALL) $(INSTMANFLAGS) $(MANSRCDIR)/$$f $(MANDIR)/ipsec_$$f || exit 1 ; \
	done
	@$(OPENSWANSRCDIR)/packaging/utils/manlink $(foreach man, $(MANS), ${MANSRCDIR}/$(man)) | \
	while read from to; \
	do \
		ln -s -f ipsec_$$from $(MANDIR)/$$to; \
	done


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

$(LIB): $(OBJS)
	@echo AR $(notdir $<)
	@$(AR) $(ARFLAGS) $(LIB) $(OBJS)


$(OBJS):	$(HDRS)

%.o: %.c
	@echo CC $(notdir $<)
	@$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

%.o: ${TC}/src/%.c
	@echo CC $(notdir $<)
	@$(CC) -c $(CFLAGS) $(CPPFLAGS) -o $@ $<

cleanall:
	rm -rf ${OBJS} $(LIB)

# Gather dependencies caused by explicit #includes within .c files
depend: ${DISTSRC}
	@(ls $(DISTSRC) | grep '\.c' | xargs $(GCC) -MM ${PORTINCLUDE} ${INCLUDES} ${ALLFLAGS} ) | sed -e 's,${OPENSWANSRCDIR},../..,g' >Makefile.depend

-include ${srcdir}Makefile.depend



