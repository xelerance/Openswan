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
# RCSID $Id: Makefile,v 1.4 2004/12/18 18:13:42 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

PROGRAM=secrets

include ${srcdir}../Makefile.program

#
# $Log: Makefile,v $
# Revision 1.4  2004/12/18 18:13:42  mcr
# 	adjusted Makefiles so that ${OBJDIR} builds work.
#
# Revision 1.3  2004/04/03 19:44:48  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.2  2003/10/31 02:39:44  mcr
# 	new program "secrets" to reload the secrets.
#
# Revision 1.1.2.1  2003/09/21 14:01:17  mcr
# 	pre-liminary X.509 patch - does not yet pass tests.
#
# Revision 1.2  2002/06/02 22:02:14  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.1  2002/04/24 07:55:32  mcr
# 	#include ${srcdir}..tches and Makefiles for post-reorg compilation.
#
#
#

