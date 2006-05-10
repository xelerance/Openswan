/* FreeS/WAN files locations (files.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: files.h,v 1.5 2005/01/11 17:52:51 ken Exp $
 */

#ifndef _STARTER_FILES_H_
#define _STARTER_FILES_H_

#ifndef IPSEC_EXECDIR
#define IPSEC_EXECDIR   "/usr/local/libexec/ipsec"
#endif

#ifndef IPSEC_CONFDIR
#define IPSEC_CONFDIR   "/etc"
#endif
#define IPSEC_CONFDIR_VAR "IPSEC_CONFS"

#ifndef IPSEC_CONFDDIR
#define IPSEC_CONFDDIR   "/etc/ipsec.d"
#endif

#define DEFAULT_CTLBASE "/var/run/pluto/pluto"
#define CTL_SUFFIX      ".ctl"
#define PID_SUFFIX      ".pid"

#define MY_PID_FILE     "/var/run/pluto/ipsec-starter.pid"

#define DEV_RANDOM      "/dev/random"
#define DEV_URANDOM     "/dev/urandom"

#define PROC_IPSECVERSION   "/proc/net/ipsec_version"
#define PROC_NETKEY         "/proc/net/pfkey"
#define PROC_MODULES        "/proc/modules"
#define PROC_SYSFLAGS       "/proc/sys/net/ipsec"

#define PLUTO_CMD       IPSEC_EXECDIR"/pluto"
#define CTL_FILE        DEFAULT_CTLBASE CTL_SUFFIX
#define PID_FILE        DEFAULT_CTLBASE PID_SUFFIX

#define DYNIP_DIR       "/var/run/pluto/dynip"

#endif /* _STARTER_FILES_H_ */

