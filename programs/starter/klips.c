/* FreeS/WAN IPsec starter (starter.c)
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
 * RCSID $Id: klips.c,v 1.5 2004/01/21 01:35:29 mcr Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <stdlib.h>

#include "ipsecconf/confread.h"
#include "ipsecconf/klips.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/exec.h"

static int _klips_module_loaded = 0;

void starter_klips_clear (void)
{
 	system(IPSEC_EXECDIR"/eroute --clear");
	system(IPSEC_EXECDIR"/spi --clear");
	system(IPSEC_EXECDIR"/klipsdebug --none");
}

void starter_klips_cleanup (void)
{
	starter_klips_clear();
	if (_klips_module_loaded) {
		system("rmmod ipsec");
		_klips_module_loaded = 0;
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

int starter_klips_set_config (struct starter_config *cfg)
{
    int i;
    extern struct keyword_enum_values kw_klipsdebug_list;

	_sysflags("icmp", cfg->setup.options[KBF_FRAGICMP]);
	_sysflags("inbound_policy_check", 1);
	_sysflags("tos", cfg->setup.options[KBF_HIDETOS]);

	starter_exec("%s/klipsdebug --none", IPSEC_EXECDIR);

	for(i=2; i<kw_klipsdebug_list.valuesize; i++)
	{
	    if(cfg->setup.options[KBF_KLIPSDEBUG] & kw_klipsdebug_list.values[i].value)
	    {
		starter_exec("%s/klipsdebug --%s", IPSEC_EXECDIR, kw_klipsdebug_list.values[i].name);
	    }
	}

	return 0;
}

int starter_klips_init (void)
{
	struct stat stb;

	if (stat(PROC_IPSECVERSION,&stb)!=0) {
		if (stat(PROC_MODULES,&stb)==0) {
			unsetenv("MODPATH");
			unsetenv("MODULECONF");
			system("depmod -a >/dev/null 2>&1 && modprobe ipsec");
		}
		if (stat(PROC_IPSECVERSION,&stb)==0) {
			_klips_module_loaded = 1;
		}
		else {
			starter_log(LOG_LEVEL_ERR, "kernel appears to lack KLIPS");
			return 1;
		}
	}

	starter_klips_clear();

	return 0;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
