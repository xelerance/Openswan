# ipsec starter Makefile
# Copyright (C) 2001 Mathieu Lafon - Arkoon Network Security
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
# RCSID $Id: Makefile,v 1.11 2004/04/18 03:09:27 mcr Exp $

OPENSWANSRCDIR=../..
include ${OPENSWANSRCDIR}/Makefile.inc

LD=$(CC)
RM=rm
LEX=lex
BISON=bison

OPENSWANDIR=../..
OPENSWANLIB=$(OPENSWANDIR)/lib/libopenswan/libopenswan.a

ifeq ($(USE_NAT_TRAVERSAL),true)
DEFINES+=-DNAT_TRAVERSAL -DVIRTUAL_IP 
endif

#DEFINES+=-DALG_PATCH 
INCLUDES=-I${OPENSWANDIR}/linux/include -I$(OPENSWANDIR)/lib -I.. -I../..
CFLAGS=$(DEFINES) $(INCLUDES)
CFLAGS+=-DIPSEC_EXECDIR=\"${FINALLIBEXECDIR}\" -DIPSEC_CONFDDIR=\"${FINALCONFDDIR}\"
CFLAGS+=-DIPSEC_CONFDIR=\"${FINALCONFDIR}\"
LDFLAGS=
OBJS=starter.o parser.tab.o lex.yy.o confread.o invokepluto.o starterwhack.o starterlog.o klips.o \
	interfaces.o exec.o cmp.o keywords.o alloc.o
DISTSRC=$(OBJS:.o=.c)
DISTSRC+=cmp.h confread.h exec.h files.h interfaces.h klips.h starterlog.h
DISTSRC+=parser.h pluto.h starterwhack.h keywords.h
LIBS=../pluto/whacklib.o $(OPENSWANLIB)

PROGRAM=starter

all: starter

starter: $(OBJS) $(OPENSWANLIB)
	$(LD) $(LDFLAGS) -o starter $(OBJS) $(LIBS)

lex.yy.c: parser.tab.c parser.l parser.y parser.h
	$(LEX) parser.l

parser.tab.c: parser.l parser.y parser.h
	$(BISON) -v -d parser.y

.c.o:
	$(CC) $(CFLAGS) -c -o $@ $<

clean::
	$(RM) -f starter $(OBJS) parser.tab.* lex.yy.*

# Stolen from pluto/Makefile
gatherdeps:
	@ls | grep '\.c$$' | sed -e 's/\(.*\)\.c$$/\1.o: \1.c/'
	@echo
	@ls | grep '\.c$$' | xargs grep '^#[ 	]*include[ 	]*"' | \
		sed -e 's/\.c:#[ 	]*include[ 	]*"/.o: /' -e 's/".*//'

include ../Makefile.program

TAGS:	$(DISTSRC)
	LC_ALL=C etags $(ETAGSFLAGS) $(DISTSRC) $(LIBOPENSWANDIR)/*.[ch]

## gatherdeps

cmp.o: cmp.c
confread.o: confread.c
exec.o: exec.c
foo1.o: foo1.c
interfaces.o: interfaces.c
invokepluto.o: invokepluto.c
keywords.o: keywords.c
klips.o: klips.c
lex.yy.o: lex.yy.c
starterlog.o: starterlog.c
parser.tab.o: parser.tab.c
starter.o: starter.c
starterwhack.o: starterwhack.c

cmp.o: keywords.h
cmp.o: confread.h
cmp.o: cmp.h
confread.o: parser.h
confread.o: confread.h
confread.o: interfaces.h
confread.o: starterlog.h
exec.o: exec.h
exec.o: starterlog.h
interfaces.o: interfaces.h
interfaces.o: exec.h
interfaces.o: files.h
interfaces.o: starterlog.h
invokepluto.o: confread.h
invokepluto.o: pluto.h
invokepluto.o: files.h
invokepluto.o: starterwhack.h
invokepluto.o: starterlog.h
keywords.o: parser.h
keywords.o: keywords.h
keywords.o: parser.tab.h
keywords.o: parserlast.h
klips.o: confread.h
klips.o: klips.h
klips.o: files.h
klips.o: starterlog.h
klips.o: exec.h
lex.yy.o: keywords.h
lex.yy.o: parser.h
lex.yy.o: parser.tab.h
lex.yy.o: parserlast.h
starterlog.o: starterlog.h
parser.tab.o: keywords.h
parser.tab.o: parser.h
starter.o: confread.h
starter.o: starterlog.h
starter.o: files.h
starter.o: starterwhack.h
starter.o: pluto.h
starter.o: klips.h
starter.o: cmp.h
starter.o: interfaces.h
starter.o: keywords.h
starterwhack.o: ../pluto/defs.h
starterwhack.o: ../pluto/whack.h
starterwhack.o: starterwhack.h
starterwhack.o: confread.h
starterwhack.o: files.h
starterwhack.o: starterlog.h
