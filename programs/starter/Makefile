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
# RCSID $Id: Makefile,v 1.15 2004/12/18 18:13:44 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGLIBS=${WHACKLIB}

PROGRAM=starter

# starter.o is implictely included.
OBJS=parser.tab.o lex.yy.o confread.o confwrite.o
OBJS+=invokepluto.o starterwhack.o starterlog.o klips.o netkey.o 
OBJS+=interfaces.o exec.o cmp.o keywords.o alloc.o 
DISTSRC=$(OBJS:.o=.c)
DISTSRC+=cmp.h confread.h confwrite.h exec.h files.h interfaces.h
DISTSRC+=klips.h netkey.h starterlog.h
DISTSRC+=parser.h pluto.h starterwhack.h keywords.h

# reach into pluto for now.
INCLUDES=-I${OPENSWANSRCDIR}/programs/pluto
INCLUDES+=-I${srcdir}

lex.yy.c: parser.tab.c parser.l parser.y parser.h
	$(LEX) ${srcdir}parser.l

parser.tab.h parser.tab.c: parser.l parser.y parser.h
	$(BISON) -v -d ${srcdir}parser.y

cleanall::
	$(RM) -f parser.tab.* lex.yy.*

include ${srcdir}../Makefile.program

TAGS:	$(DISTSRC)
	LC_ALL=C etags $(ETAGSFLAGS) $(DISTSRC) $(LIBOPENSWANDIR)/*.[ch]

