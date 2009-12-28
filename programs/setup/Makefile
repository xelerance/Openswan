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
doinstall:: setup
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

