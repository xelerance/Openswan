/* Pluto main program
 * Copyright (C) 1997      Angelos D. Keromytis.
 * Copyright (C) 1998-2001 D. Hugh Redelmeier.
 * Copyright (C) 2001-2013 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>

#include <openswan.h>

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "sysdep.h"
#include "setproctitle.h"
#include "constants.h"
#include "oswconf.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "ac.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "foodgroups.h"
#include "packet.h"
#include "demux.h"  /* needs packet.h */
#include "pluto/server.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "keys.h"
#include "secrets.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "rnd.h"
#include "pluto/state.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "ocsp.h"
#include "fetch.h"
#include "timer.h"

#include "sha1.h"
#include "md5.h"
#include "pluto/crypto.h"	/* requires sha1.h and md5.h */
#include "vendor.h"
#include "pluto_crypt.h"
#include "rcv_whack.h"

#include "pluto/virtual.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifdef TPM
#include <tcl.h>
#include "tpm/tpm.h"
#endif

#include "oswcrypto.h"
#include "pluto/opts.h"

#ifndef IPSECDIR
#define IPSECDIR "/etc/ipsec.d"
#endif

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <nspr.h>
# ifdef FIPS_CHECK
#  include <fipscheck.h>
   /* hardcoded path needs fixing! */
#  define IPSECLIBDIR "/usr/libexec/ipsec"
#  define IPSECSBINDIR "/usr/sbin"
# endif
#endif

#ifdef HAVE_LIBCAP_NG
#include <cap-ng.h>
#endif

#ifdef HAVE_LABELED_IPSEC
#include "security_selinux.h"
#endif

const char *progname = NULL;

#ifdef DEBUG
openswan_passert_fail_t openswan_passert_fail = passert_fail;
#endif


/* lock file support
 * - provides convenient way for scripts to find Pluto's pid
 * - prevents multiple Plutos competing for the same port
 * - same basename as unix domain control socket
 * NOTE: will not take account of sharing LOCK_DIR with other systems.
 */

static void pluto_sigusr1(int signum UNUSED)
{
    openswan_log("signal 1 received");
    signal(SIGUSR1, pluto_sigusr1);
}

/** create lockfile, or die in the attempt */
static int
create_lock(void)
{
    int fd;
    struct osw_conf_options *oco = osw_init_options();

    if(mkdir(oco->ctlbase, 0755) != 0) {
	if(errno != EEXIST) {
	    fprintf(stderr, "pluto: unable to create lock dir: \"%s\": %s\n"
		    , oco->ctlbase, strerror(errno));
	    exit_pluto(10);
	}
    }

    fd = open(oco->pluto_lock, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC
	      , S_IRUSR | S_IRGRP | S_IROTH);

    if (fd < 0)
    {
	if (errno == EEXIST)
	{
	    fprintf(stderr, "pluto: lock file \"%s\" already exists\n"
		, oco->pluto_lock);
	    exit_pluto(10);
	}
	else
	{
	    fprintf(stderr
		, "pluto: unable to create lock file \"%s\" (%d %s)\n"
		, oco->pluto_lock, errno, strerror(errno));
	    exit_pluto(1);
	}
    }
    oco->pluto_lock_created = TRUE;
    return fd;
}

/** fill_lock - Populate the lock file with pluto's PID
 *
 * @param lockfd File Descriptor for the lock file
 * @param pid PID (pid_t struct) to be put into the lock file
 * @return bool True if successful
 */
static bool
fill_lock(int lockfd, pid_t pid)
{
    char buf[30];	/* holds "<pid>\n" */
    int len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int) pid);
    bool ok = len > 0 && write(lockfd, buf, len) == len;

    close(lockfd);
    return ok;
}

/** delete_lock - Delete the lock file
 *
 */
static void
delete_lock(void)
{
    const struct osw_conf_options *oco = osw_init_options();
    if (oco->pluto_lock_created)
    {
	delete_ctl_socket();
	unlink(oco->pluto_lock);	/* is noting failure useful? */
    }
}

u_char    secret_of_the_day[SHA1_DIGEST_SIZE];
u_char    ikev2_secret_of_the_day[SHA1_DIGEST_SIZE];

void
init_secret(void)
{
    /*
     * Generate the secret value for responder cookies, and
     * schedule an event for refresh.
     */
    get_rnd_bytes(secret_of_the_day, sizeof(secret_of_the_day));
    event_schedule(EVENT_REINIT_SECRET, EVENT_REINIT_SECRET_DELAY, NULL);
}


int
main(int argc, char **argv)
{
    int lockfd;
    struct osw_conf_options *oco;
    chunk_t option_encoded;
    err_t   e;

    /** Overridden by virtual_private= in ipsec.conf */
#ifdef LEAK_DETECTIVE
    leak_detective=1;
#else
    leak_detective=0;
#endif

    progname = argv[0];
    alloc_chunk(option_encoded, 4096, "encoded_options");

#ifdef HAVE_LIBCAP_NG
	/* Drop capabilities */
	capng_clear(CAPNG_SELECT_BOTH);
	capng_updatev(CAPNG_ADD, CAPNG_EFFECTIVE|CAPNG_PERMITTED,
			CAP_NET_BIND_SERVICE, CAP_NET_ADMIN, CAP_NET_RAW,
			CAP_IPC_LOCK, -1);
	/* our children must be able to CAP_NET_ADMIN to change routes.
	 */
	capng_updatev(CAPNG_ADD, CAPNG_BOUNDING_SET,
			CAP_NET_ADMIN, -1);
	capng_apply(CAPNG_SELECT_BOTH);
#endif


#ifdef DEBUG
    openswan_passert_fail = passert_fail;
#endif

    initproctitle(argc, argv);

    if(getenv("PLUTO_WAIT_FOR_GDB")) {
	sleep(120);
    }

    e = pluto_options_process(argc, argv, &option_encoded);
    if(e) {
        pluto_usage(e);
    }

    reset_debugging();

    oco = osw_init_options();
    /* see if there is an environment variable */
    oco->coredir = getenv("PLUTO_CORE_DIR");

#ifdef HAVE_NO_FORK
    oco->fork_desired = FALSE;
    oco->nhelpers = 0;
#endif

    /* if a core dir was set, chdir there */
    if(oco->coredir)
	if(chdir(oco->coredir) == -1) {
	   int e = errno;
	   openswan_log("pluto: chdir() do dumpdir failed (%d %s)\n",
                    e, strerror(e));
    }

    /* now process the command line options encoded to option_encoded */
    whack_decode_and_process(-1, &option_encoded);

    lockfd = create_lock();

    /* select between logging methods */

    if (oco->log_to_stderr_desired) {
	oco->log_to_syslog = FALSE;
	if (oco->log_with_timestamp_desired)
	   oco->log_with_timestamp = TRUE;
    }
    else
	oco->log_to_stderr = FALSE;

#ifdef DEBUG
#if 0
    if(kernel_ops->set_debug) {
	(*kernel_ops->set_debug)(cur_debugging, DBG_log, DBG_log);
    }
#endif
#endif

    /** create control socket.
     * We must create it before the parent process returns so that
     * there will be no race condition in using it.  The easiest
     * place to do this is before the daemon fork.
     */
    {
	err_t ugh = init_ctl_socket();

	if (ugh != NULL)
	{
	    fprintf(stderr, "pluto: %s", ugh);
	    exit_pluto(1);
	}
    }

#ifdef IPSECPOLICY
    /* create info socket. */
    {
	err_t ugh = init_info_socket();

	if (ugh != NULL)
	{
	    fprintf(stderr, "pluto: %s", ugh);
	    exit_pluto(1);
	}
    }
#endif

    /* If not suppressed, do daemon fork */

    if (oco->fork_desired)
    {
	{
	    pid_t pid = fork();

	    if (pid < 0)
	    {
		int e = errno;

		fprintf(stderr, "pluto: fork failed (%d %s)\n",
		    errno, strerror(e));
		exit_pluto(1);
	    }

	    if (pid != 0)
	    {
		/* parent: die, after filling PID into lock file.
		 * must not use exit_pluto: lock would be removed!
		 */
		exit(fill_lock(lockfd, pid)? 0 : 1);
	    }
	}

	if (setsid() < 0)
	{
	    int e = errno;

	    fprintf(stderr, "setsid() failed in main(). Errno %d: %s\n",
		errno, strerror(e));
	    exit_pluto(1);
	}
    }
    else
    {
	/* no daemon fork: we have to fill in lock file */
	(void) fill_lock(lockfd, getpid());
	fprintf(stdout, "Pluto initialized\n");
	fflush(stdout);
    }

    /** Close everything but ctl_fd and (if needed) stderr.
     * There is some danger that a library that we don't know
     * about is using some fd that we don't know about.
     * I guess we'll soon find out.
     */
    {
	int i;

	for (i = getdtablesize() - 1; i >= 0; i--)  /* Bad hack */
	    if ((!oco->log_to_stderr || i != 2)
#ifdef IPSECPOLICY
	    && i != info_fd
#endif
	    && i != ctl_fd)
		close(i);

	/* make sure that stdin, stdout, stderr are reserved */
	if (open("/dev/null", O_RDONLY) != 0)
	    osw_abort();
	if (dup2(0, 1) != 1)
	    osw_abort();
	if (!oco->log_to_stderr && dup2(0, 2) != 2)
	    osw_abort();
    }

    init_constants();
    pluto_init_log();

#ifdef HAVE_LIBNSS
	char buf[100];
	snprintf(buf, sizeof(buf), "sql:%s",oco->confddir);
	loglog(RC_LOG_SERIOUS,"nss directory plutomain: %s",buf);
	SECStatus nss_init_status= NSS_InitReadWrite(buf);
	if (nss_init_status != SECSuccess) {
	    loglog(RC_LOG_SERIOUS, "NSS initialization failed (err %d)\n", PR_GetError());
        exit_pluto(10);
	} else {
	    loglog(RC_LOG_SERIOUS, "NSS Initialized");
	    PK11_SetPasswordFunc(getNSSPassword);

#ifdef FIPS_CHECK
	const char *package_files[]= { IPSECLIBDIR"/setup",
				        IPSECLIBDIR"/addconn",
				        IPSECLIBDIR"/auto",
				        IPSECLIBDIR"/barf",
				        IPSECLIBDIR"/_copyright",
				        IPSECLIBDIR"/eroute",
  				        IPSECLIBDIR"/ikeping",
				        IPSECLIBDIR"/_include",
					IPSECLIBDIR"/_keycensor",
					IPSECLIBDIR"/klipsdebug",
					IPSECLIBDIR"/look",
					IPSECLIBDIR"/newhostkey",
					IPSECLIBDIR"/pf_key",
					IPSECLIBDIR"/_plutoload",
					IPSECLIBDIR"/_plutorun",
					IPSECLIBDIR"/ranbits",
					IPSECLIBDIR"/_realsetup",
					IPSECLIBDIR"/rsasigkey",
					IPSECLIBDIR"/pluto",
					IPSECLIBDIR"/_secretcensor",
					IPSECLIBDIR"/secrets",
					IPSECLIBDIR"/showdefaults",
					IPSECLIBDIR"/showhostkey",
					IPSECLIBDIR"/showpolicy",
					IPSECLIBDIR"/spi",
					IPSECLIBDIR"/spigrp",
					IPSECLIBDIR"/_startklips",
					IPSECLIBDIR"/_startnetkey",
					IPSECLIBDIR"/tncfg",
					IPSECLIBDIR"/_updown",
					IPSECLIBDIR"/_updown.klips",
					IPSECLIBDIR"/_updown.mast",
					IPSECLIBDIR"/_updown.netkey",
					IPSECLIBDIR"/verify",
					IPSECLIBDIR"/whack",
					IPSECSBINDIR"/ipsec",
					NULL
					};

       if (Pluto_IsFIPS() && !FIPSCHECK_verify_files(package_files)) {
             loglog(RC_LOG_SERIOUS, "FIPS integrity verification test failed");
             exit_pluto(10);
        }
#endif

      }
#endif

    /* Note: some scripts may look for this exact message -- don't change
     * ipsec barf was one, but it no longer does.
     */
    {
	const char *vc = ipsec_version_code();
#ifdef PLUTO_SENDS_VENDORID
	const char *v = init_pluto_vendorid();
	openswan_log("Starting Pluto (Openswan Version %s%s; Vendor ID %s) pid:%u"
		     , vc, compile_time_interop_options, v, getpid());
#else
	openswan_log("Starting Pluto (Openswan Version %s%s) pid:%u"
		     , vc, compile_time_interop_options, getpid());
#endif
#ifdef HAVE_LIBNSS
	if(Pluto_IsFIPS()) {
		openswan_log("Pluto is running in FIPS mode");
	}
#endif

	if((vc[0]=='c' && vc[1]=='v' && vc[2]=='s') ||
	   (vc[2]=='g' && vc[3]=='i' && vc[4]=='t')) {
	    /*
	     * when people build RPMs from CVS or GIT, make sure they
	     * get blamed appropriately, and that we get some way to
	     * identify who did it, and when they did it. Use string concat,
	     * so that strings the binary can or classic SCCS "what", will find
	     * stuff too.
	     */
	    openswan_log("@(#) built on "__DATE__":" __TIME__ " by " BUILDER);
	}
    }

    if(oco->coredir) {
	openswan_log("core dump dir: %s", oco->coredir);
    }

    /* do this really early so that child process is as small as possible */
    init_adns();

    /* establish SIGUSR1 handler */
    signal(SIGUSR1, pluto_sigusr1);


#ifdef LEAK_DETECTIVE
	openswan_log("LEAK_DETECTIVE support [enabled]");
#else
	openswan_log("LEAK_DETECTIVE support [disabled]");
#endif

#ifdef HAVE_OCF
       {
        struct stat buf;
	errno=0;

	if( stat("/dev/crypto",&buf) != -1)
		openswan_log("OCF support for IKE via /dev/crypto [enabled]");
	else
		openswan_log("OCF support for IKE via /dev/crypto [failed:%s]", strerror(errno));
       }
#else
	openswan_log("OCF support for IKE [disabled]");
#endif

   /* Check for SAREF support */
#ifdef KLIPS_MAST
        saref_init();
#endif

#ifdef HAVE_LIBNSS
	openswan_log("NSS support [enabled]");
#else
	openswan_log("NSS support [disabled]");
#endif

#ifdef HAVE_STATSD
	openswan_log("HAVE_STATSD notification via /bin/openswan-statsd enabled");
#else
	openswan_log("HAVE_STATSD notification support not compiled in");
#endif


/** Log various impair-* functions if they were enabled */

    if(DBGP(IMPAIR_BUST_MI2))
	openswan_log("Warning: IMPAIR_BUST_MI2 enabled");
    if(DBGP(IMPAIR_BUST_MR2))
	openswan_log("Warning: IMPAIR_BUST_MR2 enabled");
    if(DBGP(IMPAIR_SA_CREATION))
	openswan_log("Warning: IMPAIR_SA_CREATION enabled");
    if(DBGP(IMPAIR_JACOB_TWO_TWO))
	openswan_log("Warning: IMPAIR_JACOB_TWO_TWO enabled");
    if(DBGP(IMPAIR_DIE_ONINFO))
	openswan_log("Warning: IMPAIR_DIE_ONINFO enabled");
    if(DBGP(IMPAIR_MAJOR_VERSION_BUMP))
	openswan_log("Warning: IMPAIR_MAJOR_VERSION_BUMP enabled");
    if(DBGP(IMPAIR_MINOR_VERSION_BUMP))
	openswan_log("Warning: IMPAIR_MINOR_VERSION_BUMP enabled");
    if(DBGP(IMPAIR_RETRANSMITS))
	openswan_log("Warning: IMPAIR_RETRANSMITS enabled");
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG))
	openswan_log("Warning: IMPAIR_SEND_BOGUS_ISAKMP_FLAG enabled");
    if(DBGP(IMPAIR_DELAY_ADNS_KEY_ANSWER))
	openswan_log("Warning: IMPAIR_DELAY_ADNS_KEY_ANSWER enabled");
    if(DBGP(IMPAIR_DELAY_ADNS_TXT_ANSWER))
	openswan_log("Warning: IMPAIR_DELAY_ADNS_TXT_ANSWER enabled");

/** Initialize all of the various features */

#ifdef NAT_TRAVERSAL
    init_nat_traversal(oco->nat_traversal, oco->keep_alive
                       , oco->force_keepalive, oco->nat_t_spf);
#endif

    init_virtual_ip(oco->virtual_private);
    init_rnd_pool();
    init_timer();
    init_secret();
    init_states();
    init_connections();
    init_crypto();
    init_crypto_helpers(oco->nhelpers);
    load_oswcrypto();
    init_demux();
    init_kernel();
    init_id();

#ifdef TPM
    init_tpm();
#endif

#ifdef HAVE_THREADS
    init_fetch();
#endif

    ocsp_set_default_uri(oco->ocspuri);

    /* loading X.509 CA certificates */
    load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);
    /* loading X.509 AA certificates */
    load_authcerts("AA cert", oco->aacerts_dir, AUTH_AA);
    /* loading X.509 OCSP certificates */
    load_authcerts("OCSP cert", oco->ocspcerts_dir, AUTH_OCSP);

    /* loading X.509 CRLs */
    load_crls();
    /* loading attribute certificates (experimental) */
    load_acerts();

#ifdef HAVE_LIBNSS
    /*Loading CA certs from NSS DB*/
    load_authcerts_from_nss("CA cert",  AUTH_CA);
#endif

#ifdef HAVE_LABELED_IPSEC
    init_avc();
#endif

    daily_log_event();
    call_server();
    return -1;	/* Shouldn't ever reach this */
}

/* leave pluto, with status.
 * Once child is launched, parent must not exit this way because
 * the lock would be released.
 *
 *  0 OK
 *  1 general discomfort
 * 10 lock file exists
 */
void
exit_pluto(int status)
{
    reset_globals();	/* needed because we may be called in odd state */
    free_preshared_secrets();
    free_remembered_public_keys();
    delete_every_connection();

    /* free memory allocated by initialization routines.  Please don't
       forget to do this. */

#ifdef TPM
    free_tpm();
#endif

#ifdef HAVE_THREADS
    free_crl_fetch();          /* free chain of crl fetch requests */
#endif
#ifdef HAVE_OCSP
    free_ocsp_fetch();         /* free chain of ocsp fetch requests */
#endif
    free_authcerts();          /* free chain of X.509 authority certificates */
    free_crls();               /* free chain of X.509 CRLs */
    free_acerts();             /* free chain of X.509 attribute certificates */
    free_ocsp();               /* free ocsp cache */

    osw_conf_free_oco();	/* free global_oco containing path names */

    free_myFQDN();	    /* free myid FQDN */

    free_ifaces();          /* free interface list from memory */
    stop_adns();            /* Stop async DNS process (if running) */
    free_md_pool();         /* free the md pool */
#ifdef HAVE_LIBNSS
    NSS_Shutdown();
#endif
    delete_lock();          /* delete any lock files */
#ifdef LEAK_DETECTIVE
    report_leaks();         /* report memory leaks now, after all free()s */
#endif /* LEAK_DETECTIVE */
    close_log();            /* close the logfiles */
    exit(status);           /* exit, with our error code */
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
