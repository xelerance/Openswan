/*
 * A program to read the configuration file and load a single conn
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
 */

char addconn_c_version[] = "RCSID $Id: spi.c,v 1.114 2005/08/18 14:04:40 ken Exp $";

#include <asm/types.h>
#include <sys/types.h>
#include <sys/ioctl.h>
/* #include <linux/netdevice.h> */
#include <net/if.h>
/* #include <linux/types.h> */ /* new */
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

/* #include <sys/socket.h> */

#include <netinet/in.h>
#include <arpa/inet.h>
/* #include <linux/ip.h> */
#include <netdb.h>

#include <unistd.h>
#include <getopt.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswconf.h"
#include "oswlog.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterwhack.h"
//#include "ipsecconf/pluto.h"
//#include "ipsecconf/klips.h"
//#include "ipsecconf/netkey.h"
//#include "ipsecconf/cmp.h"
//#include "ipsecconf/interfaces.h"
//#include "ipsecconf/keywords.h"

char *progname;
int verbose=0;
int warningsarefatal = 0;

static const char *usage_string = ""
  "Usage: addconn [--config file] \n"
  "               [--defaultroute <addr>] [--defaultroutenexthop <addr>]\n"
  "               names\n";


static void usage(void)
{
    /* print usage */
    fputs(usage_string, stderr);
    exit(10);
}

char rootdir[PATH_MAX];       /* when evaluating paths, prefix this to them */

static struct option const longopts[] =
{
	{"config",              required_argument, NULL, 'C'},
	{"defaultroute",        required_argument, NULL, 'd'},
	{"defaultroutenexthop", required_argument, NULL, 'n'},
	{"debug",               no_argument, NULL, 'D'},
	{"verbose",             no_argument, NULL, 'D'},
	{"warningsfatal",       no_argument, NULL, 'W'},
	{"rootdir",             required_argument, NULL, 'R'},
	{"help",                no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};



int
main(int argc, char *argv[])
{
    int opt = 0;
    int all = 0;
    struct starter_config *cfg = NULL;
    char *err = NULL;
    char *confdir = NULL;
    char *configfile = NULL;
    int exit_status = 0;
    struct starter_conn *conn = NULL;

    extern int EF_PROTECT_BELOW;
    extern int EF_PROTECT_FREE;

    EF_PROTECT_BELOW=1;
    EF_PROTECT_FREE=1;
    

    progname = argv[0];
    rootdir[0]='\0';

    tool_init_log();

    while((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
	switch(opt) {
	case 'h':
	    //usage:
	    usage();
	    break;

	case 'D':
	    verbose++;
	    break;

	case 'W':
	    warningsarefatal++;
	    break;

	case 'C':
	    configfile = clone_str(optarg, "config file name");
	    break;

	case 'A':
	    all=1;
	    break;

	case 'R':
	    printf("setting rootdir=%s\n", optarg);
	    strncat(rootdir, optarg, sizeof(rootdir));
	    break;

	case 'd':
	    /* convert default route info */
	    break;

	case 'N':
	    /* convert next hop info */
	    break;

	}
    }

    /* if nothing to add, then complain */
    if(optind == argc && !all) {
	usage();
    }
    

    /* find config file */
    confdir = getenv(IPSEC_CONFDIR_VAR);
    if(confdir == NULL)
    {
	confdir = IPSEC_CONFDIR;
    }
	
    if(!configfile) {
	configfile = alloc_bytes(strlen(confdir)+sizeof("/ipsec.conf")+2,"conf file");

	/* calculate default value for configfile */
	configfile[0]='\0';
	strcpy(configfile, confdir);
	if(configfile[strlen(configfile)-1]!='/')
	{
	    strcat(configfile, "/");
	}
	strcat(configfile, "ipsec.conf");
    }

    if(verbose) {
	printf("opening file: %s\n", configfile);
    }

    starter_use_log (verbose, 1, verbose ? 0 : 1);

    cfg = confread_load(configfile, &err);
    
    if(cfg == NULL) {
	printf("can not load config '%s': %s\n",
	       configfile, err);
	exit(3);
    }
	

    if(all)
    {
	/* load all conns marked as auto=add or better */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_ADD
		|| conn->desired_state == STARTUP_START
		|| conn->desired_state == STARTUP_ROUTE) {
		starter_whack_add_conn(conn);
	    }
	}
    } else {
	/* load named conns, regardless of their state */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    int   connum;
	    for(connum = optind; connum<argc; connum++) {
		/* yes, let's make it case-insensitive */
		if(strcasecmp(conn->name, argv[connum])==0) {
		    if(conn->state == STATE_ADDED) {
			printf("conn %s already added\n", conn->name);
		    } else if(conn->state == STATE_FAILED) {
			printf("conn %s did not load properly\n", conn->name);
		    } else {
			printf("loading conn: %s\n", conn->name);
			exit_status = starter_whack_add_conn(conn);
			conn->state = STATE_ADDED;
		    }
		}
	    }
	}
    }
    
    exit(exit_status);
}

void exit_tool(int x)
{
  exit(x);
}

/*
 * $Log: spi.c,v $
 *
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 *
 */
