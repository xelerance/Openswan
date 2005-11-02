/* Openswan netkey handler (netkey.c)
 * Copyright (C) 2004 Xelerance Corporation
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
 * RCSID $Id: netkey.c,v 1.1 2004/12/01 07:31:26 ken Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <stdlib.h>

#include "confread.h"
#include "netkey.h"
#include "files.h"
#include "starterlog.h"
#include "exec.h"

static int _netkey_module_loaded = 0;

void starter_netkey_clear (void)
{
 	system("setkey -F");
}

void starter_netkey_cleanup (void)
{
	starter_netkey_clear();
	if (_netkey_module_loaded) {
		system("rmmod af_key");
		system("rmmod ah4");
		system("rmmod esp4");
		system("rmmod ah6");
		system("rmmod esp6");
		system("rmmod ipcomp");
		system("rmmod xfrm4_user");
		system("rmmod xfrm4_tunnel");
		_netkey_module_loaded = 0;
	}
}

static void _sysflags (char *name, int value)
{
	if (starter_exec(
		"echo %d >%s/%s 2>/dev/null", value?1:0, PROC_SYSFLAGS, name
		)!=0) {
		starter_log(LOG_LEVEL_ERR, "can't set sysflag %s to %d", name,
			value ? 1 : 0);
	}
}

int starter_netkey_set_config (struct starter_config *cfg)
{
	_sysflags("icmp", cfg->setup.options[KBF_FRAGICMP]);
	_sysflags("inbound_policy_check", 1);
	_sysflags("tos", cfg->setup.options[KBF_HIDETOS]);

	return 0;
}

int starter_netkey_init (void)
{
	struct stat stb;

	if (stat(PROC_NETKEY,&stb)!=0) {
		if (stat(PROC_MODULES,&stb)==0) {
			unsetenv("MODPATH");
			unsetenv("MODULECONF");
			system("depmod -a >/dev/null 2>&1 && modprobe xfrm4_tunnel esp4 ah4 af_key");
		}
		if (stat(PROC_NETKEY,&stb)==0) {
			_netkey_module_loaded = 1;
		}
		else {
			starter_log(LOG_LEVEL_ERR, "kernel appears to lack NETKEY");
			return 1;
		}
	}

	starter_netkey_clear();

	return 0;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
