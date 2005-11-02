/* Openswan IPsec starter (starter.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
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
 * RCSID $Id: starter.c,v 1.12 2005/01/11 17:52:51 ken Exp $
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "confread.h"
#include "confwrite.h"
#include "starterlog.h"
#include "files.h"
#include "starterwhack.h"
#include "pluto.h"
#include "klips.h"
#include "netkey.h"
#include "cmp.h"
#include "interfaces.h"
#include "keywords.h"

#define FLAG_ACTION_START_PLUTO   0x01
#define FLAG_ACTION_RELOAD        0x02
#define FLAG_ACTION_FORCE_RELOAD  0x04
#define FLAG_ACTION_QUIT          0x08
#define FLAG_ACTION_LISTEN        0x10

static unsigned int _action_ = 0;
int verbose = 0;
int warningsarefatal = 0;

char configfile[PATH_MAX];
char rootdir[PATH_MAX];       /* when evaluating paths, prefix this to them */
int showonly = 0;

static void fsig(int signal)
{
	 switch (signal) {
	 	case SIGCHLD: {
				int status;
				pid_t pid;
				char *name = NULL;

				while ((pid=waitpid(-1,&status,WNOHANG))>0) {
					if (pid == starter_pluto_pid()) name = " (Pluto)";
					if (WIFSIGNALED(status))
						starter_log(LOG_LEVEL_INFO, 
							"child %d%s has been killed by sig %d\n",
							pid, name?name:"", WTERMSIG(status));
					else if (WIFSTOPPED(status))
						starter_log(LOG_LEVEL_INFO, 
							"child %d%s has been stopped by sig %d\n",
							pid, name?name:"", WSTOPSIG(status));
					else if (WIFEXITED(status))
						starter_log(LOG_LEVEL_INFO, 
							"child %d%s has quit (exit code %d)\n",
							pid, name?name:"", WEXITSTATUS(status));
					else
						starter_log(LOG_LEVEL_INFO, 
							"child %d%s has quit", pid, name?name:"");

					if (pid == starter_pluto_pid())
						starter_pluto_sigchild(pid);
				}
			}
			break;

		case SIGPIPE:
			/** ignore **/
			break;

		case SIGALRM:
			_action_ |= FLAG_ACTION_START_PLUTO;
			break;

		case SIGHUP:
			_action_ |= FLAG_ACTION_RELOAD;
			break;

		case SIGTERM:
		case SIGQUIT:
		case SIGINT:
			_action_ |= FLAG_ACTION_QUIT;
			break;

		case SIGUSR1:
			_action_ |= FLAG_ACTION_FORCE_RELOAD;
			_action_ |= FLAG_ACTION_RELOAD;
			break;

		default:
			starter_log(LOG_LEVEL_ERR, 
				"fsig(): unknown signal %d -- investigate", signal);
			break;
	 }
}

static void usage(char *name)
{
	fprintf(stderr, "Usage: %s [--debug] [--auto_reload <x sec>]\n", name);
	exit(1);
}

int main (int argc, char **argv)
{
	struct starter_config *cfg = NULL, *new_cfg;
	struct starter_conn *conn, *conn2;
	struct stat stb;
	char *err = NULL;
	int i, debug=0, no_fork=0;
	struct timeval tv;
	unsigned long auto_reload = 0;
	time_t last_reload;
	int id = 1;
	extern int yydebug;
	char *confdir;
	bool justdump = FALSE;

	/* find environment location for /etc */
	confdir = getenv(IPSEC_CONFDIR_VAR);
	if(confdir == NULL)
	{
	    confdir = IPSEC_CONFDIR;
	}
		
	/* calculate default value for configfile */
	configfile[0]='\0';
	strncat(configfile, confdir, sizeof(configfile));
	if(configfile[strlen(configfile)-1]!='/')
	{
	    strncat(configfile, "/", sizeof(configfile));
	}
	strncat(configfile, "ipsec.conf", sizeof(configfile));

	/**
	 * Parse command line
	 */
	for (i=1; i<argc; i++) {
		if (strcmp(argv[i],"--debug")==0) {
			debug = 1;
			no_fork = 1;
		}
		else if (strcmp(argv[i],"--no_fork")==0) {
			no_fork = 1;
		}
		else if (strcmp(argv[i],"--configfile")==0 && (i+1)<argc && argv[i+1]!=NULL) {
		    strcpy(configfile, argv[i+1]);
		    i++;
		}
		else if (strcmp(argv[i],"--rootdir")==0 && (i+1)<argc && argv[i+1]!=NULL) {
		    strcpy(rootdir, argv[i+1]);
		    i++;
		}
		else if (strcmp(argv[i],"--parsedebug")==0) {
  	                yydebug = 1;
		}
		else if (strcmp(argv[i],"--verbose")==0) {
		    verbose = 1;
		}
		else if (strcmp(argv[i],"-Werror")==0) {
		    warningsarefatal = 1;
		}
		else if (strcmp(argv[i],"--dumpcfg")==0) {
		    justdump = TRUE;
		}
		else if (strcmp(argv[i],"--showonly")==0) {
			showonly = 1;
			warningsarefatal = 0;
		}
		else if ((strcmp(argv[i],"--auto_reload")==0) && (i+1 < argc)) {
			auto_reload = atoi(argv[++i]);
			if (!auto_reload) usage(argv[0]);
		}
		else {
			usage(argv[0]);
		}
	}

	starter_use_log (debug, 1, debug ? 0 : 1);

	/**
	 * Init
	 */
	signal(SIGHUP,fsig);
	signal(SIGCHLD,fsig);
	signal(SIGPIPE,fsig);
	signal(SIGINT,fsig);
	signal(SIGTERM,fsig);
	signal(SIGQUIT,fsig);
	signal(SIGALRM,fsig);
	signal(SIGUSR1,fsig);

	/**
	 * Verify that we can start
	 */
	if (!showonly && getuid()!=0) {
		starter_log(LOG_LEVEL_ERR, "ERROR: Must be root (uid=0)");
		exit(1);
	}

	if (!showonly && stat(PID_FILE,&stb)==0) {
		starter_log(LOG_LEVEL_ERR,
			"ERROR: pluto is already running (%s exists) -- aborting", PID_FILE);
		exit(1);
	}

	if (stat(DEV_RANDOM,&stb)!=0) {
		starter_log(LOG_LEVEL_ERR, "ERROR: Unable to start Openswan IPsec, no %s!",
			DEV_RANDOM);
		exit(1);
	}

	if (stat(DEV_URANDOM,&stb)!=0) {
		starter_log(LOG_LEVEL_ERR, "ERROR: Unable to start Openswan IPsec, no %s!",
			DEV_URANDOM);
		exit(1);
	}

	cfg = confread_load(configfile, &err);
	if (!cfg) {
		starter_log(LOG_LEVEL_ERR, "ERROR: Can't load config: %s", err ? err : "unknown error");
		if (err) free(err);
		exit(1);
	}
	if (err) free(err);

	if(justdump)
	{
	    confwrite(cfg,stdout);
	    exit(0);
	}

	/* Need to determine which stack to use here, and if() it */
	if ((starter_klips_init()!=0) || (starter_klips_set_config(cfg)!=0)) {
		exit(1);
	}

	starter_ifaces_init();
	starter_ifaces_clear();

	last_reload = time(NULL);

	starter_log(LOG_LEVEL_INFO, "Starting Openswan IPsec %s [starter]...",
		ipsec_version_code());

	/**
	 * Fork if we're not debugging stuff
	 */
	if (!no_fork) {
		switch (fork()) {
			case 0:
				starter_use_log (0, 0, 1);
				{
					int fnull;
					fnull = open("/dev/null", O_RDWR);
					if (fnull >= 0) {
						dup2(fnull,STDIN_FILENO);
						dup2(fnull,STDOUT_FILENO);
						dup2(fnull,STDERR_FILENO);
						close(fnull);
					}
				}
				break;
			case -1:
				starter_log(LOG_LEVEL_ERR, "ERROR: Can't fork: %s", strerror(errno));
				break;
			default:
				exit(0);
				break;
		}
	}

	/**
	 * Save pid file in /var/run/pluto/starter.pid
	 */
	{
		FILE *f = fopen(MY_PID_FILE, "w");
		if (f) {
			fprintf(f, "%u\n", getpid());
			fclose(f);
		}
	}

	starter_ifaces_load (cfg->setup.interfaces, cfg->setup.options[KBF_OVERRIDEMTU],
#ifdef NAT_TRAVERSAL
		cfg->setup.nat_traversal ? 1 : 0
#else
		0
#endif
		);

	_action_ = FLAG_ACTION_START_PLUTO;

	for (;;) {

		/**
		 * Stop pluto (if started) and exit
		 */
		if (_action_ & FLAG_ACTION_QUIT) {
			if (starter_pluto_pid()) {
				starter_stop_pluto();
			}
			starter_ifaces_clear();
			/* Need to determine which stack here... */
			starter_klips_cleanup();
			starter_netkey_cleanup();

			confread_free(cfg);
			starter_log(LOG_LEVEL_DEBUG, "ipsec starter stopped");
			unlink(MY_PID_FILE);
			exit(0);
		}

		/**
		 * Delete all connections. Will be added below
		 */
		if (_action_ & FLAG_ACTION_FORCE_RELOAD) {
			if (starter_pluto_pid()) {
			    for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
			    {
				if (conn->state == STATE_ADDED) {
				    starter_whack_del_conn(conn);
				    conn->state = STATE_TO_ADD;
				}
			    }
			}
			_action_ &= ~FLAG_ACTION_FORCE_RELOAD;
		}

		/**
		 * Reload a new config gile
		 */
		if (_action_ & FLAG_ACTION_RELOAD) {
			err = NULL;
			starter_log(LOG_LEVEL_INFO, "Reloading config %s...", configfile);
			new_cfg = confread_load(configfile, &err);
			if (new_cfg) {
				/**
				 * Switch to new config. New conn will be loaded below
				 */
				/* Check stacks here too */
				if (starter_cmp_klips(cfg, new_cfg)) {
					starter_log(LOG_LEVEL_DEBUG, "Klips has changed");
					starter_klips_set_config(new_cfg);
				}

				if (starter_ifaces_load (new_cfg->setup.interfaces,
					new_cfg->setup.options[KBF_OVERRIDEMTU],
#ifdef NAT_TRAVERSAL
					new_cfg->setup.nat_traversal ? 1 : 0
#else
					0
#endif
					)) {
					_action_ |= FLAG_ACTION_LISTEN;
				}

				if (starter_cmp_pluto(cfg, new_cfg)) {
					starter_log(LOG_LEVEL_DEBUG, "Pluto has changed");
					if (starter_pluto_pid()) {
						starter_stop_pluto();
					}
					_action_ &= ~FLAG_ACTION_LISTEN;
					_action_ |= FLAG_ACTION_START_PLUTO;
				}
				else {
				    /**
				     * Only reload conns if pluto is not killed
				     */
				    /**
				     * Look for new connections that are already loaded
				     */
				    for(conn = cfg->conns.tqh_first;
					conn != NULL;
					conn = conn->link.tqe_next)
				    {
					if (conn->state == STATE_ADDED)
					{
					    for(conn2 = cfg->conns.tqh_first; conn2 != NULL; conn2 = conn2->link.tqe_next)
					    {
						if ((conn2->state == STATE_TO_ADD) &&
						    (starter_cmp_conn(conn,conn2)==0)) {
						    conn->state = STATE_REPLACED;
						    conn2->state = STATE_ADDED;
						    conn2->id = conn->id;
						    break;
						}
					    }
					}
				    }
				    /**
				     * Remove now unused conn
				     */
				    for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
				    {
					if (conn->state == STATE_ADDED)
					{
					    starter_whack_del_conn(conn);
					}
				    }
				}
				confread_free(cfg);
				cfg = new_cfg;
			}
			else {
				starter_log(LOG_LEVEL_ERR,
					"can't reload config file: %s -- keeping old one", err);
			}
			if (err) free(err);
			_action_ &= ~FLAG_ACTION_RELOAD;
			last_reload = time(NULL);
		}

		/**
		 * Start pluto
		 */
		if (_action_ & FLAG_ACTION_START_PLUTO) {
			if (starter_pluto_pid()==0) {
				starter_log(LOG_LEVEL_INFO, "Attempting to start pluto...");
				/* Again, check stacks here and if() */
				starter_klips_clear();
				starter_netkey_clear();
				if (starter_start_pluto(cfg,debug)==0) {
					starter_whack_listen();
				}
				else {
					/** schedule next try **/
					alarm(PLUTO_RESTART_DELAY);
				}
			}
			_action_ &= ~FLAG_ACTION_START_PLUTO;
  		        for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
			{
			    if (conn->state == STATE_ADDED)
				conn->state = STATE_TO_ADD;
			}
		}

		/**
		 * Tell pluto to reread its interfaces
		 */
		if (_action_ & FLAG_ACTION_LISTEN) {
			starter_whack_listen();
			_action_ &= ~FLAG_ACTION_LISTEN;
		}

		/**
		 * Add stale connections
		 */
		if (starter_pluto_pid()!=0) {
		    for(conn = cfg->conns.tqh_first; conn != NULL; conn = conn->link.tqe_next)
		    {
			switch(conn->desired_state)
			{
			case STARTUP_NO:
			    break;

			case STARTUP_POLICY:
			    /* mark conn as not negotiable
			     * starter_whack_route_conn(conn);
			     */
			    break;
			    
			case STARTUP_ADD:
			case STARTUP_START:
			case STARTUP_ROUTE:
			    if (conn->state == STATE_LOADED)
			    {
				if (conn->id == 0) {
				    /**
				     * Affect new unique id
				     */
				    conn->id = id++;
				}
				starter_whack_add_conn(conn);
				conn->state = STATE_ADDED;
			    }
			    break;
			}
			
			if(conn->state == STATE_ADDED)
			{
			    switch(conn->desired_state)
			    {
			    case STARTUP_NO:
			    case STARTUP_POLICY:
			    case STARTUP_ADD:
				break;
				
			    case STARTUP_START:
				starter_whack_initiate_conn(conn);
				break;
				
			    case STARTUP_ROUTE:
				starter_whack_route_conn(conn);
				break;
			    }
			    
			    conn->state = STATE_UP;
			}
		    }
		}
		
		/**
		 * If auto_reload activated, when to stop select
		 */
		if (auto_reload) {
		    time_t now = time(NULL);
		    tv.tv_sec = (now<last_reload+auto_reload) ?
			(last_reload+auto_reload-now) : 0;
		    tv.tv_usec = 0;
		}
		
		/**
		 * Wait for something to happend
		 */
		if (select (0, NULL, NULL, NULL, auto_reload ? &tv : NULL) == 0) {
		    /**
		     * Timeout -> auto_reload
		     */
		    _action_ |= FLAG_ACTION_RELOAD;
		}
}

	return 0;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
