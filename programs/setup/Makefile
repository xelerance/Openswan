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
# RCSID $Id: Makefile,v 1.12 2004/12/18 18:13:43 mcr Exp $

OPENSWANSRCDIR?=$(shell cd ../..; pwd)
include ${OPENSWANSRCDIR}/Makefile.inc

# this dance is because setup has to get installed as /etc/rc.d/init.d/ipsec
# not as /etc/rc.d/init.d/setup.
PROGRAMDIR=$(RCDIR)
PROGRAM=
EXTRA8MAN=setup.8

include ${srcdir}../Makefile.program

# We have to install the setup program into the rc.d directories.
# the original program goes into /etc/rc.d/init.d, and a symlink goes
# into the $BINDIR.
#
# the priorities match those in setup's chkconfig line
install:: setup
	@rm -f $(BINDIR)/setup
	@$(INSTALL) $(INSTBINFLAGS) setup $(RCDIR)/ipsec
	@ln -s $(FINALRCDIR)/ipsec $(BINDIR)/setup
	-@for i in 0 1 2 3 4 5 6; do mkdir -p $(RCDIR)/../rc$$i.d; done
	-@cd $(RCDIR)/../rc0.d && ln -f -s ../init.d/ipsec K76ipsec
	-@cd $(RCDIR)/../rc1.d && ln -f -s ../init.d/ipsec K76ipsec
	-@cd $(RCDIR)/../rc2.d && ln -f -s ../init.d/ipsec S47ipsec
	-@cd $(RCDIR)/../rc3.d && ln -f -s ../init.d/ipsec S47ipsec
	-@cd $(RCDIR)/../rc4.d && ln -f -s ../init.d/ipsec S47ipsec
	-@cd $(RCDIR)/../rc5.d && ln -f -s ../init.d/ipsec S47ipsec
	-@cd $(RCDIR)/../rc6.d && ln -f -s ../init.d/ipsec K76ipsec

install_file_list::
	@echo $(RCDIR)/ipsec
	@echo $(BINDIR)/setup
	@echo $(RCDIR)/../rc0.d/K76ipsec
	@echo $(RCDIR)/../rc1.d/K76ipsec
	@echo $(RCDIR)/../rc2.d/S47ipsec
	@echo $(RCDIR)/../rc3.d/S47ipsec
	@echo $(RCDIR)/../rc4.d/S47ipsec
	@echo $(RCDIR)/../rc5.d/S47ipsec
	@echo $(RCDIR)/../rc6.d/K76ipsec

cleanall::
	@rm -f setup

#
# $Log: Makefile,v $
# Revision 1.12  2004/12/18 18:13:43  mcr
# 	adjusted Makefiles so that ${OBJDIR} builds work.
#
# Revision 1.11  2004/04/03 19:44:48  ken
# FREESWANSRCDIR -> OPENSWANSRCDIR (patch by folken)
#
# Revision 1.10  2003/12/02 02:35:46  ken
# Stop IPsec *after* NFS, so we don't hang on NFS over IPsec mounts
#
# Revision 1.9  2002/08/10 19:47:06  mcr
# 	added clean:: target to remove "setup" even though it
# 	isn't the value set in PROGRAM
#
# Revision 1.8  2002/06/03 20:25:31  mcr
# 	man page for files actually existant in /proc/net changed back to
# 	ipsec_foo via new EXTRA5PROC process.
#
# Revision 1.7  2002/06/02 21:51:41  mcr
# 	changed TOPDIR->FREESWANSRCDIR in all Makefiles.
# 	(note that linux/net/ipsec/Makefile uses TOPDIR because this is the
# 	kernel sense.)
#
# Revision 1.6  2002/05/27 00:18:51  mcr
# 	updated install_file_list to include ${srcdir}...d/init.d/ipsec file.
#
# Revision 1.5  2002/05/24 03:20:41  mcr
# 	"setup" was installed, but was not the target of the install,
# 	so it was not built from setup.in.
#
# Revision 1.4  2002/05/22 22:05:58  mcr
# 	install setup program properly in /etc/rc.d/init.d/*ipsec*.
#
# Revision 1.3  2002/05/06 19:17:50  mcr
# 	added install_file_list target to gather list of all files that
# 	would be installed by "make install" (for PR#65).
# 	manlink has new "-n" option to just print which files would be
# 	created rather than actually doing it.
#
# Revision 1.2  2002/05/06 18:49:38  mcr
# 	init.d scripts were not properly installed.
#
# Revision 1.1  2002/04/24 07:55:32  mcr
# 	#include ${srcdir}..tches and Makefiles for post-reorg compilation.
#
#
#

