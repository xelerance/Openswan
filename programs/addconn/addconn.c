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
#include "ipsecconf/keywords.h"

char *progname;
int verbose=0;
int warningsarefatal = 0;

static const char *usage_string = ""
    "Usage: addconn [--config file] \n"
    "               [--addall] [--listroute] [--liststart]\n"
    "               [--rootdir dir] \n"
    "               [--configsetup] \n"
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
	{"addall",              no_argument, NULL, 'a'},
	{"listroute",           no_argument, NULL, 'r'},
	{"liststart",           no_argument, NULL, 's'},
	{"varprefix",           required_argument, NULL, 'P'},
	{"search",              no_argument, NULL, 'S'},
	{"rootdir",             required_argument, NULL, 'R'},
	{"configsetup",         no_argument, NULL, 'T'},
	{"help",                no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};



int
main(int argc, char *argv[])
{
    int opt = 0;
    int all = 0;
    int search = 0;
    int typeexport = 0;
    int listroute=0, liststart=0;
    struct starter_config *cfg = NULL;
    err_t err = NULL;
    char *confdir = NULL;
    char *configfile = NULL;
    char *varprefix = "";
    int exit_status = 0;
    struct starter_conn *conn = NULL;
    char *defaultroute = NULL;
    char *defaultnexthop = NULL;

#if 0
    /* efence settings */
    extern int EF_PROTECT_BELOW;
    extern int EF_PROTECT_FREE;

    EF_PROTECT_BELOW=1;
    EF_PROTECT_FREE=1;
#endif
    

    progname = argv[0];
    rootdir[0]='\0';

    tool_init_log();

    while((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
	switch(opt) {
	case 'h':
	    //usage:
	    usage();
	    break;

	case 'a':
	    all=1;
	    break;

	case 'D':
	    verbose++;
	    break;

	case 'W':
	    warningsarefatal++;
	    break;

	case 'S':
	    search++;
	    break;

	case 'T':
	    typeexport++;
	    break;

	case 'C':
	    configfile = clone_str(optarg, "config file name");
	    break;

	case 'A':
	    all=1;
	    break;

	case 'r':
	    listroute=1;
	    break;

	case 's':
	    liststart=1;
	    break;

	case 'P':
	    varprefix=optarg;
	    break;

	case 'R':
	    printf("setting rootdir=%s\n", optarg);
	    strncat(rootdir, optarg, sizeof(rootdir));
	    break;

	case 'd':
	    defaultroute=optarg;
	    break;

	case 'n':
	    defaultnexthop=optarg;
	    break;

	default:
	    usage();
	}
    }

    /* if nothing to add, then complain */
    if(optind == argc && !all && !listroute && !liststart && !search && !typeexport) {
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

    if(defaultroute) {
	err_t e;
	char b[ADDRTOT_BUF];
	e = ttoaddr(defaultroute, strlen(defaultroute), AF_INET, &cfg->dr);
	if(e) {
	    printf("invalid default route: %s\n", e);
	    exit(4);
	}

	if(verbose) {
	    addrtot(&cfg->dr, 0, b, sizeof(b));
	    printf("default route is: %s\n", b);
	}
    }

    if(defaultnexthop) {
	err_t e;
	char b[ADDRTOT_BUF];
	e = ttoaddr(defaultnexthop, strlen(defaultnexthop), AF_INET, &cfg->dnh);
	if(e) {
	    printf("invalid default route: %s\n", e);
	    exit(4);
	}

	if(verbose) {
	    addrtot(&cfg->dnh, 0, b, sizeof(b));
	    printf("default nexthop is: %s\n", b);
	}
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
		starter_whack_add_conn(cfg, conn);
	    }
	}
    } else if(listroute) {
	/* list all conns marked as auto=route or start or better */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START
		|| conn->desired_state == STARTUP_ROUTE) {
		printf("%s ", conn->name);
	    }
	    printf("\n");
	}
    } else if(liststart) {
	/* list all conns marked as auto=route or start or better */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    if (conn->desired_state == STARTUP_START) {
		printf("%s ", conn->name);
	    }
	    printf("\n");
	}
    } else if(search) {
	char *sep="";
	if((argc-optind) < 2 ) {
	    printf("%s_confreadstatus=failed\n", varprefix);
	    exit(3);
	}

	printf("%s_confreadstatus=\n", varprefix);
	printf("%s_confreadnames=\"",varprefix);
	
	/* find conn names that have value set */
	for(conn = cfg->conns.tqh_first;
	    conn != NULL;
	    conn = conn->link.tqe_next)
	{
	    /* we recognize a limited set of values */
	    if(strcasecmp(argv[optind],"auto")==0 &&
	       strcasecmp(argv[optind+1],"manual")==0) {
		if(conn->manualkey) {
		    printf("%s%s", sep, conn->name);
		    sep=" ";
		}
	    }
	}
	printf("\"\n");
	exit(0);

    } else if(typeexport) {
        struct keyword_def *kd;

	printf("export %sconfreadstatus=''\n", varprefix);
	for(kd=ipsec_conf_keywords_v2; kd->keyname != NULL; kd++) {
	    if((kd->validity & kv_config)==0) continue;

	    if(kd->type == kt_string ||
	       kd->type == kt_filename ||
	       kd->type == kt_dirname ||
	       kd->type == kt_loose_enum) {
		if(cfg->setup.strings[kd->field]) {
		    printf("export %s%s='%s'\n",
			   varprefix, kd->keyname,
			   cfg->setup.strings[kd->field]);
		}
	    } else if(kd->type==kt_bool) {
		printf("export %s%s='%s'\n",
		       varprefix, kd->keyname,
		       cfg->setup.options[kd->field] ? "yes" : "no");
	    } else {
		
		if(cfg->setup.options[kd->field]) {
		    printf("export %s%s='%d'\n",
			   varprefix, kd->keyname,
			   cfg->setup.options[kd->field]);
		}
	    }
	}

	exit(0);

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
			exit_status = starter_whack_add_conn(cfg, conn);
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
