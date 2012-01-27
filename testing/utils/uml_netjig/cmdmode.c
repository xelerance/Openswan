/*
 * @(#) jig to exercise a UML/FreeSWAN kernel with two interfaces
 *
 * Copyright (C) 2001 Michael Richardson  <mcr@freeswan.org>
 * Copyright (C) 2005 Michael Richardson  <mcr@xelerance.com>
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
 * @(#) based upon uml_router from User-Mode-Linux tools package
 *
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <ctype.h>

#define _GNU_SOURCE 1
#include <getopt.h>

#include "pcap.h"
#include <sys/queue.h>

#include "nethub.h"
#include "netjig.h"

/*
 * QUIT
 */
int quitprog(struct netjig_state *ns, int argc, char **argv)
{
  ns->done=1;
  ns->waitplay=1;
  return 0;
}


/*
 * NEWSWITCH --arpreply switch-name 
 */
int create_new_switch(struct netjig_state *ns, int argc, char **argv)
{
	int opt;
	struct nethub *nh;
	int arpreply;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{"arpreply",    no_argument, 0, 'a'},
			{NULL,          0,           0, 0},
		};

	arpreply=0;
	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "ha",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 3 LINES\n");
			goto usage;

		case 'a':
			arpreply++;
			break;
		}
	}

	if(optind+1 != argc) {
		fprintf(ns->cmdproto_out,"FAIL 4 LINES\n");
	usage:
		fprintf(ns->cmdproto_out,"ERROR - missing switchname\n");
			fprintf(ns->cmdproto_out,"NEWSWITCH --arpreply switchname\n"
			       "\tswitchname is name of hub\n"
			       "\treturns environment variables for new sockets\n");
			fflush(stdout);
			return 1;
	}

	nh = init_nethub(ns, argv[optind],
			 NULL, NULL, /* compat_v0 */ 1);
	nh->nh_allarp = arpreply;

	fprintf(ns->cmdproto_out,"OK 3 LINES\n");
	fprintf(ns->cmdproto_out,"ARPREPLY=%d\n", arpreply);
	fprintf(ns->cmdproto_out,"%s\n%s\n", nh->ctl_socket_name_env, nh->data_socket_name_env);
	fflush(ns->cmdproto_out);
	return 0;
}

void nosig(int sig)
{
  fprintf(stderr, "Caught signal %d, cleaning up and exiting\n", sig);
}

/*
 * SETDEBUG value
 */
int setdebug(struct netjig_state *ns, int argc, char **argv)
{
	int newdebug;
	char *foo;
	int opt;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{ NULL,         0, 0, 0},

		};

	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "h",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
			fprintf(ns->cmdproto_out,"FAIL 4 LINES\n");
			fprintf(ns->cmdproto_out, "unknown option %s\n",
				argv[optind]);
			goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"debug <num> - sets the debug level\n");
			fflush(stdout);
			return 1;
		}
	}


	if(argc > 1) {
		newdebug=strtol(argv[1], &foo, 0);
		if(optarg==foo) {
			fprintf(ns->cmdproto_out,"FAIL 2 LINES\n");
			fprintf(ns->cmdproto_out,"ERROR - bad value: %s\n",argv[0]);
			goto usage;
		}
		ns->debug = newdebug;
	} else {
			fprintf(ns->cmdproto_out,"OK 1 LINES\n");
			fprintf(ns->cmdproto_out,"debug=%d\n", ns->debug);
			return 0;
	}
		
	return 0;
}


/*
 * SETRATE value
 */
int setrate(struct netjig_state *ns, int argc, char **argv)
{
	int newrate;
	char *foo;
	int opt;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{ NULL,         0, 0, 0},

		};

	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "h",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
			fprintf(ns->cmdproto_out,"FAIL 4 LINES\n");
			fprintf(ns->cmdproto_out, "unknown option %s\n",
				argv[optind]);
			goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"setrate <num> - sets the packet replay rate (in ms)\n");
			fflush(stdout);
			return 1;
		}
	}


	if(argc > 1) {
	  newrate=strtol(argv[1], &foo, 0);
	  if(optarg==foo) {
	    fprintf(ns->cmdproto_out,"FAIL 2 LINES\n");
	    fprintf(ns->cmdproto_out,"ERROR - bad value: %s\n",argv[0]);
	    goto usage;
	  } else {
	    ns->packetrate = newrate;
	    fprintf(ns->cmdproto_out,"OK 1 LINES\n");
	    fprintf(ns->cmdproto_out,"packetrate=%d\n", ns->packetrate);
	    return 0;
	  }
	}
		
	return 0;
}

/*
 * SETARP --switchname=foo {--on,--off}
 */
int setarp(struct netjig_state *ns, int argc, char **argv)
{
	int opt;
	struct nethub *nh;
	int arpon;
	char *switchname;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{"switchname",  required_argument, 0, 's'},
			{"on",          no_argument, 0, 'y'},
			{"off",         no_argument, 0, 'n'},
			{ NULL,         0, 0, 0},

		};

	arpon = -1;
	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "hs:yn",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
		  fprintf(ns->cmdproto_out,"FAIL 5 LINES\n");
		  fprintf(ns->cmdproto_out, "unknown option %s\n",
			  argv[optind]);
		  goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 4 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"RECORDFILE - records a pcap file from an interface.\n"
				"\t--switchname=name   which hub to record\n"
				"\t--on                turn on  ARP replies for the named switch\n"
				"\t--off               turn off ARP replies for the named switch\n"
				);

			fflush(stdout);
			return 1;
		case 's':
			switchname=optarg;
			break;
		case 'y':
			arpon=1;
			break;
		case 'n':
			arpon=0;
			break;
		}
	}

	nh = find_nethubbyname(ns, switchname);
	if(nh==NULL) {  /* not found */
		fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
		fprintf(ns->cmdproto_out,"ERROR - switch '%s' not found\n", switchname);
		return 2;
	}
	  
	if(arpon == -1) {
		fprintf(ns->cmdproto_out,"OK 1 LINES\n");
		fprintf(ns->cmdproto_out,"switch '%s' ARP state is: %d\n", switchname, nh->nh_allarp);
		return 3;
	}
		
	if(ns->debug) {
	  fprintf(stderr, "%s: switch '%s' setting arp reply to %d\n",
		  progname, nh->nh_name, arpon);
	}

	nh->nh_allarp = arpon;
	fprintf(ns->cmdproto_out,"OK 0 LINES\n");
	fflush(ns->cmdproto_out);
	return 0;
}

/*
 * RECORDFILE --switchname=foo --recordfile=bar 
 */
int recordfile(struct netjig_state *ns, int argc, char **argv)
{
	int opt;
	struct nethub *nh;
	char *recordfilename;
	char *switchname;
	pcap_t *pt;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{"switchname",  required_argument, 0, 's'},
			{"recordfile",  required_argument, 0, 'f'},
			{"file",  required_argument, 0, 'f'},
			{ NULL,         0, 0, 0},

		};

	/*	signal(SIGUSR1, nosig); */
	/*pause(); */

	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "f:hs:",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
		  fprintf(ns->cmdproto_out,"FAIL 4 LINES\n");
		  fprintf(ns->cmdproto_out, "unknown option %s\n",
			  argv[optind]);
		  goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 3 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"RECORDFILE - records a pcap file from an interface.\n"
				"\t--switchname=name   which hub to record\n"
				"\t--recordfile=file   the pcap file to record\n");

			fflush(stdout);
			return 1;
		case 's':
			switchname=optarg;
			break;
		case 'f':
			recordfilename=optarg;
			break;
		}
	}

	nh = find_nethubbyname(ns, switchname);
	if(nh==NULL) {  /* not found */
	  fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
	  fprintf(ns->cmdproto_out,"ERROR - switch '%s' not found\n", switchname);
	  return 2;
	}
	  
	if(ns->debug) {
	  fprintf(stderr, "%s: will record %s from '%s' network\n",
		  progname, recordfilename, nh->nh_name);
	}

	pt = pcap_open_dead(DLT_EN10MB, 1536);
	nh->nh_output = pcap_dump_open(pt, recordfilename);

	if(nh->nh_output == NULL) {
	  fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
	  fprintf(ns->cmdproto_out,"ERROR - recordfile '%s' failed\n", recordfilename);
	  return 3;
	}
	  
	nh->nh_outputFile = strdup(recordfilename);

	fprintf(ns->cmdproto_out,"OK 0 LINES\n");
	fflush(ns->cmdproto_out);
	return 0;
}

/*
 * PLAYFILE --switchname=foo --playfile=bar --rate={#,ontick}
 */
int playfile(struct netjig_state *ns, int argc, char **argv)
{
	int opt;
	struct nethub *nh;
	char errbuf[256];
	int rate;
	char *playfilename = NULL;
	char *switchname = NULL;
	char *foo;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{"switchname",  required_argument, 0, 's'},
			{"playfile",    required_argument, 0, 'f'},
			{"file",        required_argument, 0, 'f'},
			{"rate",        required_argument, 0, 'r'},
			{ NULL,         0, 0, 0}, 
		};

	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "f:hr:s:",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
			fprintf(ns->cmdproto_out,"FAIL 6 LINES\n");
			fprintf(ns->cmdproto_out, "unknown option %s\n",
				argv[optind]);
			goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 5 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"PLAYFILE - replays a pcap file out a network.\n"
				"\t--switchname=name   which hub to play through\n"
				"\t--playfile=file     the pcap file to play\n"
				"\t--rate=num/onclick  how many seconds between packets."
				"\t                    \"ontick\" means to play a packet each time the \n"
				"\t                    TICK cmd is invoked\n");
			fflush(stdout);
			return 1;
		case 's':
			switchname=optarg;
			break;
		case 'f':
			playfilename=optarg;
			break;
		case 'r':
		  if(strcasecmp(optarg, "ontick")==0) {
		    rate=-1;
		  } else {
		    rate=strtol(optarg, &foo, 0);
		    if(optarg==foo) {
		      fprintf(ns->cmdproto_out,"FAIL 7 LINES\n");
		      fprintf(ns->cmdproto_out,"ERROR - bad rate: %s\n",optarg);
		      goto usage;
		    }
		  }
		}
	}

	if(switchname==NULL) {
	  goto usage;
	}

	if(playfilename==NULL) {
	  goto usage;
	}

	nh = find_nethubbyname(ns, switchname);
	if(nh==NULL) {  /* not found */
	  fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
	  fprintf(ns->cmdproto_out,"ERROR - switch '%s' not found\n", switchname);
	  return 2;
	}
	  
	if(ns->debug) {
	  fprintf(stderr, "%s: will play %s to '%s' network\n",
		  progname, playfilename, nh->nh_name);
	}

	nh->nh_inputFile = strdup(playfilename);
	nh->nh_input = pcap_open_offline(nh->nh_inputFile, errbuf);
	if(nh->nh_input == NULL) {
	  fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
	  fprintf(ns->cmdproto_out,"ERROR - playfile '%s': %s\n",
		  playfilename, errbuf);
	  fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
	  return 3;
	}
	  

	nh->nh_rate = rate;
	
	fprintf(ns->cmdproto_out,"OK 0 LINES\n");
	fflush(ns->cmdproto_out);
	return 0;
}

/*
 * TICK - send a packet
 */
int tickcmd(struct netjig_state *ns, int argc, char **argv)
{
	ns->forcetick=1;
	return 0;
}

/*
 * WAITPLAY --switchname=all
 */
int waitplay(struct netjig_state *ns, int argc, char **argv)
{
	int opt;
	char *switchname;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
			{"switchname",  required_argument, 0, 's'},
		};

	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "f:hr:s:",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
			fprintf(ns->cmdproto_out, "FAIL 3 LINES\n");
			fprintf(ns->cmdproto_out, "unknown option %s\n",
				argv[optind]);
			goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 2 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"WAITPLAY - waits for all packets from a given switch to be played.\n"
				"\t--switchname=name   which hub to play through\n");
			fflush(stdout);
			return 1;
		case 's':
			switchname=optarg;
			break;
		}
	}

	ns->waitplay=1;
	return 0;
}

/*
 * CD dir
 */
int dochdir(struct netjig_state *ns, int argc, char **argv)
{
	int opt;
	static struct option long_options[] =
		{
			{"help",        no_argument, 0, 'h'},
		};

	opterr=0;
	optind=1;
	while((opt = getopt_long(argc, argv, "h",
				 long_options, NULL)) !=  EOF) {
		switch(opt) {
		default:
			fprintf(ns->cmdproto_out, "FAIL 3 LINES\n");
			fprintf(ns->cmdproto_out, "unknown option %s\n",
				argv[optind]);
			goto usage;
		case 'h':
			fprintf(ns->cmdproto_out,"FAIL 2 LINES\n");
		usage:
			fprintf(ns->cmdproto_out,"CD <dir> - changes directory\n");
			fflush(stdout);
			return 1;
		}
	}

	if(optind == argc) {
	  /* no arguments! */
	  goto usage;
	}
	
	if(chdir(argv[optind])!=0) {
	  int e;
	  e=errno;
	  fprintf(ns->cmdproto_out,"FAIL 1 LINES\n");
	  fprintf(ns->cmdproto_out,"ERROR - chdir(%s) : %s\n",
		  argv[optind], strerror(e));
	  return 1;
	}
	  
	fprintf(ns->cmdproto_out,"OK 1 LINES\n");
	fprintf(ns->cmdproto_out,"DIR=%s\n",getcwd(NULL, 0));
	return 0;
}

void finish_waitplay(struct netjig_state *ns)
{
  fprintf(ns->cmdproto_out,"OK 0 LINES\n");
  ns->waitplay=0;
  cmdprompt(ns);
}


void cmdprompt(struct netjig_state *ns)
{
	if(ns->cmdlaststat) {
		fprintf(ns->cmdproto_out,"FAIL stat=%d netjig>", ns->cmdlaststat);
	} else {
		fprintf(ns->cmdproto_out,"OK netjig>");
	}
	ns->cmdlaststat=0;
	fflush(stdout);
}

int cmdparse(struct netjig_state *ns,
	     char   *cmdline)
{
	char *argv[256];
	int   argc;
	char *arg;
	static struct cmd_entry {
		const char *cmdname;
		int (*cmdfunc)(struct netjig_state *, int, char **);
	} cmds[]={
		{"newswitch", create_new_switch},
		{"playfile",  playfile},
		{"recordfile",recordfile},
		{"quit",      quitprog},
		{"waitplay",  waitplay},
		{"tick",      tickcmd},
		{"setrate",   setrate},
		{"setarp",    setarp},
		{"debug",     setdebug},
		{"chdir",     dochdir},
		{"cd",        dochdir},
		{NULL,        NULL}};
	struct cmd_entry *ce;

	argc=0;
	while((arg=strsep(&cmdline, " \t\n"))!=NULL) {
	  argv[argc++]=arg;
	  while(cmdline && isspace(*cmdline)) {
	    cmdline++;
	  }
	}
	argv[argc]=NULL;

	if(argc==0 || argv[0][0]=='\0') {
		return 0;
	}

	ce=cmds;
	if(strcasecmp("help", argv[0]) == 0) {
		fprintf(ns->cmdproto_out, "FAIL %lu LINES\n",
			(sizeof(cmds)/sizeof(struct cmd_entry))-1);
		while(ce->cmdname != NULL) {
			fprintf(ns->cmdproto_out, "\t%s\n", ce->cmdname);
			ce++;
		}
		ns->cmdlaststat=1;
		cmdprompt(ns);
		return 0;
	}
	
	while(ce->cmdname != NULL) {
		if(strcasecmp(ce->cmdname, argv[0])==0) {
			ns->cmdlaststat=(*ce->cmdfunc)(ns, argc, argv);
			if(!ns->waitplay) {
			  cmdprompt(ns);
			}
			return ns->cmdlaststat;
		}
		ce++;
	}

	if(ce->cmdname==NULL) {
	  ns->cmdlaststat=4;
	  cmdprompt(ns);
	}
	return 0;
}

int cmdread(struct netjig_state *ns,
	     char  *buf,
	     int    len)
{
	char *nl;
	int   cmdlen;

	/* 
	 * have to handle partial reads and multiple commands
	 * per read, since this may in fact be a file or a pipe.
	 */
	if((ns->cmdloc + len) > CMDBUF_LEN-1) {
		fprintf(stderr, "Command is too long, discarding!\n");
		fflush(stdout);
		
		ns->cmdloc=0;
		return 0;
	}
	memcpy(ns->cmdbuf+ns->cmdloc, buf, len);
	ns->cmdloc+=len;
	ns->cmdbuf[ns->cmdloc]='\0';

	while((nl = strchr(ns->cmdbuf, '\n')) != NULL) {
		/* found a newline, so turn it into a \0, and process the
		 * command, and then we will pull the rest of the buffer
		 * up.
		 */
		*nl='\0';
		cmdlen=nl-ns->cmdbuf+1;

		cmdparse(ns, ns->cmdbuf);

		memmove(ns->cmdbuf, ns->cmdbuf+cmdlen, cmdlen);
		ns->cmdloc -= cmdlen;
	}
	return 1;
}

/*
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 2
 * End:
 *
 */
