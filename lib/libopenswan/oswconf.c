/* misc functions to get compile time and runtime options
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: oswalloc.h,v 1.3 2004/10/16 23:42:13 mcr Exp $
 */

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include "oswconf.h"
#include "oswalloc.h"

static struct osw_conf_options oco;
static bool setup=FALSE;

const struct osw_conf_options *osw_init_options(void)
{
    char buf[PATH_MAX];
    char *ipsec_conf_dir = FINALCONFDIR;
    char *ipsecd_dir = FINALCONFDDIR;
    char *conffile   = FINALCONFFILE;
    char *var_dir    = FINALVARDIR;
    char *exec_dir   = FINALLIBEXECDIR;
    char *lib_dir    = FINALLIBDIR;
    char *sbin_dir   = FINALSBINDIR;
    char *env;

    if(setup) return &oco;

    memset(&oco, 0, sizeof(oco));

    /* allocate them all to make it consistent */
    ipsec_conf_dir = clone_str(ipsec_conf_dir, "default conf");
    ipsecd_dir = clone_str(ipsecd_dir, "default conf");
    conffile   = clone_str(conffile, "default conf");
    var_dir    = clone_str(var_dir, "default conf");
    exec_dir   = clone_str(exec_dir, "default conf");
    lib_dir    = clone_str(lib_dir, "default conf");
    sbin_dir   = clone_str(sbin_dir, "default conf");
    
    /* figure out what we are doing, look for variables in the environment */
    if((env = getenv("IPSEC_CONFS")) != NULL) {
	pfree(ipsec_conf_dir);
	ipsec_conf_dir = clone_str(env, "ipsec_confs");

	/* if they change IPSEC_CONFS, reassign ipsecd as well */
	snprintf(buf, sizeof(buf), "%s/ipsec.d", ipsec_conf_dir);
	pfree(ipsecd_dir);
	ipsecd_dir = clone_str(buf, "ipsecdir");

	/* if they change IPSEC_CONFS, reassign ipsecd as well */
	snprintf(buf, sizeof(buf), "%s/ipsec.conf", ipsec_conf_dir);
	pfree(conffile);
	conffile = clone_str(buf, "ipsec.conf");
    }
    
    if((env = getenv("IPSEC_CONFFILE")) != NULL) {
	pfree(conffile);
	ipsec_conf_dir = clone_str(env, "ipsec.conf");
    }

    oco.confdir = ipsec_conf_dir;
    oco.conffile = conffile;

    return &oco;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
