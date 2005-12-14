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

#include "constants.h"
#include "oswalloc.h"
#include "oswconf.h"
#include "oswlog.h"

char *progname;
int debug=0;

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

static struct option const longopts[] =
{
	{"config",              required_argument, NULL, 'C'},
	{"defaultroute",        required_argument, NULL, 'd'},
	{"defaultroutenexthop", required_argument, NULL, 'n'},
	{"debug",               no_argument, NULL, 'D'},
	{"help",                no_argument, NULL, 'h'},
	{0, 0, 0, 0}
};



int
main(int argc, char *argv[])
{
    int opt;
    char *configfile;

    progname = argv[0];

    tool_init_log();

    while((opt = getopt_long(argc, argv, "", longopts, 0)) != EOF) {
	switch(opt) {
	case 'h':
	    //usage:
	    usage();
	    break;

	case 'D':
	    debug++;
	    break;

	case 'C':
	    configfile = clone_str(optarg, "config file name");
	    break;

	case 'd':
	    /* convert default route info */
	    break;

	case 'N':
	    /* convert next hop info */
	    break;

	}
    }

    

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
