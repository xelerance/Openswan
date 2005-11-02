# Makefile for miscelaneous programs
# Copyright (C) 2002  Michael Richardson	<mcr@freeswan.org>
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
# RCSID $Id: Makefile,v 1.6 2004/12/18 18:13:39 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGRAM=ipsec
PROGRAMDIR=${SBINDIR}
MANPROGPREFIX:=./
LIBFILES:=$(wildcard distro.txt)

include ${srcdir}../Makefile.program

#
# $Log: Makefile,v $
# Revision 1.6  2004/12/18 18:13:39  mcr
# 	adjusted Makefiles so that ${OBJDIR} builds work.
#
# Revision 1.5  2004/04/03 19:44:46  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.4  2002/08/02 15:51:28  mcr
# 	if the file "distro.txt" exists in this directory, then it
# 	will be installed into the LIBDIR. The ipsec --version
# 	(and now "ipsec version") command will look for this file
# 	and will print it as part of "ipsec --version".
#
# Revision 1.3  2002/06/02 22:02:14  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.2  2002/05/16 19:50:23  mcr
# 	.5 man pages should not have ipsec_ prepended.
# 	ipsec.8 man page is also an exception.
#
# Revision 1.1  2002/04/24 07:55:32  mcr
# 	#include ${srcdir}..tches and Makefiles for post-reorg compilation.
#
#
#

