/*
 * This program reads a configuration file and then writes it out
 * again to stdout.
 * That's not that useful in practice, but it helps a lot in debugging.
 *
 * Copyright (C) 2006-2014 Michael Richardson <mcr@xelerance.com>
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

char readwriteconf_c_version[] = "@(#) Xelerance Openswan readwriteconf";

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
#include "whack.h"
#include "pluto/whackfile.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/confwrite.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/files.h"
#include "ipsecconf/starterwhack.h"
/* #include "ipsecconf/pluto.h"
 * #include "ipsecconf/klips.h"
 * #include "ipsecconf/netkey.h"
 * #include "ipsecconf/cmp.h"
 * #include "ipsecconf/interfaces.h"
 * #include "ipsecconf/keywords.h" */

char *progname;
int verbose=0;
int warningsarefatal = 0;

static const char *usage_string = ""
    "Usage: readwriteconn [--config file] \n"
    "       [--rootdir X] [--rootdir2 Y]   -- also look here for files\n"
    "       [--debug] [--verbose]          -- enable debugging or verbose\n"
    "       [--text]                       -- enable text output\n"
    "       [--whackout=file]       -- enable generating messages out\n";


static void usage(void)
{
    /* print usage */
    fputs(usage_string, stderr);
    exit(10);
}

static struct option const longopts[] =
{
	{"config",              required_argument, NULL, 'C'},
	{"debug",               no_argument, NULL, 'D'},
	{"verbose",             no_argument, NULL, 'D'},
	{"warningsarefatal",    no_argument, NULL, 'W'},
	{"whackout",            required_argument, NULL, 'w'},
	{"text",                no_argument, NULL, 'T'},
	{"rootdir",             required_argument, NULL, 'R'},
	{"rootdir2",            required_argument, NULL, 'S'},
	{"help",                no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};



int
main(int argc, char *argv[])
{
    int opt = 0;
    int textout  = 1;
    int whackout = 0;              /* if true, write whack messages */
    char *whackfile = NULL;
    struct starter_config *cfg = NULL;
    err_t err = NULL;
    char *confdir = NULL;
    char *configfile = NULL;
    struct starter_conn *conn = NULL;

    progname = argv[0];
    rootdir[0]='\0';

    tool_init_log();

    while((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
	switch(opt) {
	case 'h':
	    /* usage: */
	    usage();
	    break;

        case 'T':
            textout = 1;
            break;

        case 'w':
            whackfile = clone_str(optarg, "output file name");
            whackout  = 1;
            textout   = 0;
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

	case 'R':
            if(verbose) printf("#setting rootdir=%s\n", optarg);
	    strlcat(rootdir, optarg, sizeof(rootdir));
	    break;

	case 'S':
            if(verbose) printf("#setting rootdir2=%s\n", optarg);
            rootdir2[0]='\0';
	    strlcat(rootdir2, optarg, sizeof(rootdir2));
	    break;
	}
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

    if(verbose > 3) {
	extern int yydebug;
	yydebug=1;
    }

    if(verbose) {
	printf("opening file: %s\n", configfile);
    }

    starter_use_log (verbose, 1, verbose ? 0 : 1);

    cfg = confread_load(configfile, &err, FALSE, NULL,FALSE);

    if(!cfg) {
	printf("config file: %s can not be loaded: %s\n", configfile, err);
	exit(3);
    }

    if(textout) {
        /* load all conns marked as auto=add or better */
        for(conn = cfg->conns.tqh_first;
            conn != NULL;
            conn = conn->link.tqe_next)
            {
                printf("#conn %s loaded\n", conn->name);
            }

        confwrite(cfg, stdout);
    }

    if(whackout && whackfile!=NULL) {
        if(!openwhackrecordfile(whackfile)) {
            perror(whackfile);
            exit(5);
        }
        /* load all conns marked as auto=add or better */

        for(conn = cfg->conns.tqh_first;
            conn != NULL;
            conn = conn->link.tqe_next)
            {
                argv+=optind;
                argc-=optind;
                for(; argc>0; argc--, argv++) {
                    char *conn_name = *argv;
                    if(verbose) {
                        printf("processing conn: %s\n", conn_name);
                    }
                    if(strcasecmp(conn->name, conn_name)==0) {
                        struct whack_message msg1;
                        if(starter_whack_build_basic_conn(cfg, &msg1, conn)==0) {
                            unsigned int len = serialize_whack_msg(&msg1);
                            writewhackrecord((char *)&msg1, len);
                        }
                    }
                }
            }
    }

    confread_free(cfg);
    exit(0);
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
