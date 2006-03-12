/*
 * show the host keys in various formats
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
 * replaces a shell script.
 *
 * RCSID $Id: ranbits.c,v 1.12 2004/04/04 01:50:56 ken Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openswan.h>

#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswconf.h"
#include "secrets.h"

char usage[] = "Usage: ipsec showhostkey [--ipseckey {gateway}][--left ] [--right ]\n"
             "                         [--dump ] [--list ] [--x509self]\n"
             "                         [--x509req ] [--x509cert ]      \n"
             "                         [ --txt gateway ] [--dhclient ] \n"
             "                         [ --file secretfile ] \n"
             "                         [ --keynum count ] [ --id identity ]\n"
             "                         [ --rsaid keyid ] [--verbose] [--version]\n";

struct option opts[] = {
  {"key",	no_argument,	NULL,	'k',},
  {"left",	no_argument,	NULL,	'l',},
  {"right",	no_argument,	NULL,	'r',},
  {"dump",	no_argument,	NULL,	'D',},
  {"list",	no_argument,	NULL,	'L',},
  {"x509self",	no_argument,	NULL,	's',},
  {"x509req",	no_argument,	NULL,	'R',},
  {"x509cert",	no_argument,	NULL,	'c',},
  {"txt",	required_argument,NULL,	't',},
  {"ipseckey",	required_argument,NULL,	'K',},
  {"dhclient",	no_argument,    NULL,	'd',},
  {"file",	required_argument,NULL,	'f',},
  {"keynum",	required_argument,NULL,	'n',},
  {"id",	required_argument,NULL,	'i',},
  {"rsaid",	required_argument,NULL,	'I',},
  {"version",	no_argument,	 NULL,	'V',},
  {"verbose",	no_argument,	 NULL,	'v',},
  {0,		0,	NULL,	0,}
};

char *progname = "ipsec showhostkey";	/* for messages */

void exit_tool(int code)
{
    tool_close_log();
    exit(code);
}

void
showhostkey_log(int mess_no, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vfprintf(stderr, message, args);
    va_end(args);
}
     

int main(int argc, char *argv[])
{
    char secrets_file[PATH_MAX];
    int opt;
    int errflg = 0;
    bool key_flg=FALSE;
    bool left_flg=FALSE;
    bool right_flg=FALSE;
    bool dump_flg=FALSE;
    bool list_flg=FALSE;
    bool x509self_flg=FALSE;
    bool x509req_flg=FALSE;
    bool x509cert_flg=FALSE;
    bool txt_flg=FALSE;
    bool ipseckey_flg=FALSE;
    bool dhclient_flg=FALSE;
    const struct osw_conf_options *oco = osw_init_options();
    const char *rsakeyid;
    struct secret *host_secrets = NULL;
    prompt_pass_t pass;

    /* start up logging system */
    tool_init_log();

    snprintf(secrets_file, PATH_MAX, "%s/ipsec.secrets", oco->confdir);
    
    while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
	switch (opt) {
	case 'k':
	case 'l':
	case 'r':
	    break;

	case 'D': /* --dump */
	    dump_flg=TRUE;
	    break;

	case 'L':
	case 's':
	case 'R':
	case 'c':
	case 't':
	case 'd':
	    break;

	case 'f':  /* --file arg */
	    secrets_file[0]='\0';
	    strncat(secrets_file, optarg, PATH_MAX);
	    break;

	case 'I':
	    rsakeyid=clone_str(optarg, "rsakeyid");
	    break;

	case 'n':
	case 'i':
	case 'v':
	case 'h':
	    break;

	default:
	    goto usage;
	}
    }

    if(errflg) {
    usage:
	fputs(usage, stderr);
	exit(1);
    }
    
    if(!key_flg && !left_flg && !right_flg && !dump_flg && !list_flg
       && !x509self_flg && !x509req_flg && !x509cert_flg && !txt_flg
       && !ipseckey_flg && !dhclient_flg) {
	fprintf(stderr, "You must specify some operation\n");
	goto usage;
    }
    
    /* now load file from indicated location */
    pass.prompt=showhostkey_log;
    pass.fd = 2; /* stderr */
    osw_load_preshared_secrets(&host_secrets, secrets_file, &pass);

    

    exit(0);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
