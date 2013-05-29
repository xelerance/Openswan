/* whack communicating routines
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
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

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef HOST_NAME_MAX   /* POSIX 1003.1-2001 says <unistd.h> defines this */
# define HOST_NAME_MAX  255 /* upper bound, according to SUSv2 */
#endif
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <fcntl.h>

#include <openswan.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "oswconf.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "ac.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "foodgroups.h"
#include "whack.h"	/* needs connections.h */
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "state.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "kernel.h"	/* needs connections.h */
#include "rcv_whack.h"
#include "log.h"
#include "keys.h"
#include "secrets.h"
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "server.h"
#include "fetch.h"
#include "ocsp.h"
#include "timer.h"

#include "kernel_alg.h"
#include "ike_alg.h"

#ifdef TPM
#include "tpm/tpm.h"
#endif

/* bits loading keys from asynchronous DNS */

enum key_add_attempt {
    ka_TXT,
#ifdef USE_KEYRR
    ka_KEY,
#endif
    ka_roof	/* largest value + 1 */
};

struct key_add_common {
    int refCount;
    char *diag[ka_roof];
    int whack_fd;
    bool success;
};

struct key_add_continuation {
    struct adns_continuation ac;	/* common prefix */
    struct key_add_common *common;	/* common data */
    enum key_add_attempt lookingfor;
};

static void
key_add_ugh(const struct id *keyid, err_t ugh)
{
    char name[IDTOA_BUF];	/* longer IDs will be truncated in message */

    (void)idtoa(keyid, name, sizeof(name));
    loglog(RC_NOKEY
	, "failure to fetch key for %s from DNS: %s", name, ugh);
}

/* last one out: turn out the lights */
static void
key_add_merge(struct key_add_common *oc, const struct id *keyid)
{
    if (oc->refCount == 0)
    {
	enum key_add_attempt kaa;

	/* if no success, print all diagnostics */
	if (!oc->success)
	    for (kaa = ka_TXT; kaa != ka_roof; kaa++)
		key_add_ugh(keyid, oc->diag[kaa]);

	for (kaa = ka_TXT; kaa != ka_roof; kaa++)
	    pfreeany(oc->diag[kaa]);

	close(oc->whack_fd);
	pfree(oc);
    }
}

static char whackrecordname[PATH_MAX];
static FILE *whackrecordfile=NULL;

/*
 * writes out 64-bit time, even though we actually
 * only have 32-bit time here. Assumes that time will
 * be written out in big-endian format, with MSB word
 * being first.
 *
 */
static bool writewhackrecord(char *buf, int buflen)
{
    u_int32_t header[3];
    time_t n;

    /* round up buffer length */
    int abuflen = (buflen + 3) & ~0x3;

    /* bail if we aren't writing anything */
    if(whackrecordfile == NULL) return TRUE;

    header[0]=buflen + sizeof(u_int32_t)*3;
    header[1]=0;
    time(&n);
    header[2]=n;

    /* DBG_log("buflen: %u abuflen: %u\n", header[0], abuflen); */

    if(fwrite(header, sizeof(u_int32_t)*3, 1, whackrecordfile) < 1) {
	DBG_log("writewhackrecord: fwrite error when writing header");
    }

    if(fwrite(buf, abuflen, 1, whackrecordfile) < 1) {
	DBG_log("writewhackrecord: fwrite error when writing buf");
    }

    return TRUE;
}


/*
 * we write out an empty record with the right WHACK magic.
 * this should permit a later mechanism to figure out the
 * endianess of the file, since we will get records from
 * other systems for analysis eventually.
 */
static bool openwhackrecordfile(char *file)
{
    char when[256];
    char FQDN[HOST_NAME_MAX + 1];
    u_int32_t magic;
    struct tm tm1, *tm;
    time_t n;

    strcpy(FQDN, "unknown host");
    gethostname(FQDN, sizeof(FQDN));

    strncpy(whackrecordname, file, sizeof(whackrecordname));
    whackrecordfile = fopen(whackrecordname, "w");
    if(whackrecordfile==NULL) {
	openswan_log("Failed to open whack record file: '%s'\n"
		     , whackrecordname);
	return FALSE;
    }

    time(&n);
    tm = localtime_r(&n, &tm1);
    strftime(when, sizeof(when), "%F %T", tm);

    fprintf(whackrecordfile, "#!-pluto-whack-file- recorded on %s on %s\n",
	    FQDN, when);

    magic = WHACK_BASIC_MAGIC;
    writewhackrecord((char *)&magic, 4);

    DBG(DBG_CONTROL
	, DBG_log("started recording whack messages to %s\n"
		  , whackrecordname));
    return TRUE;
}



static void
key_add_continue(struct adns_continuation *ac, err_t ugh)
{
    struct key_add_continuation *kc = (void *) ac;
    struct key_add_common *oc = kc->common;

    passert(whack_log_fd == NULL_FD);
    whack_log_fd = oc->whack_fd;

    if (ugh != NULL)
    {
	oc->diag[kc->lookingfor] = clone_str(ugh, "key add error");
    }
    else
    {
	oc->success = TRUE;
	transfer_to_public_keys(kc->ac.gateways_from_dns
#ifdef USE_KEYRR
	    , &kc->ac.keys_from_dns
#endif /* USE_KEYRR */
	    );
    }

    oc->refCount--;
    key_add_merge(oc, &ac->id);
    whack_log_fd = NULL_FD;
}

static void
key_add_request(const struct whack_message *msg)
{
    struct id keyid;
    err_t ugh = atoid(msg->keyid, &keyid, FALSE);

    if (ugh != NULL)
    {
	loglog(RC_BADID, "bad --keyid \"%s\": %s", msg->keyid, ugh);
    }
    else
    {
	if (!msg->whack_addkey)
	    delete_public_keys(&pluto_pubkeys, &keyid, msg->pubkey_alg);

	if (msg->keyval.len == 0)
	{
	    struct key_add_common *oc
		= alloc_thing(struct key_add_common
			      , "key add common things");
	    enum key_add_attempt kaa;

	    /* initialize state shared by queries */
	    oc->refCount = 0;
	    oc->whack_fd = dup_any(whack_log_fd);
	    oc->success = FALSE;

	    for (kaa = ka_TXT; kaa != ka_roof; kaa++)
	    {
		struct key_add_continuation *kc
		    = alloc_thing(struct key_add_continuation
			, "key add continuation");

		oc->diag[kaa] = NULL;
		oc->refCount++;
		kc->common = oc;
		kc->lookingfor = kaa;
		switch (kaa)
		{
		case ka_TXT:
		    ugh = start_adns_query(&keyid
			, &keyid	/* same */
			, ns_t_txt
			, key_add_continue
			, &kc->ac);
		    break;
#ifdef USE_KEYRR
		case ka_KEY:
		    ugh = start_adns_query(&keyid
			, NULL
			, ns_t_key
			, key_add_continue
			, &kc->ac);
		    break;
#endif /* USE_KEYRR */
		default:
		    bad_case(kaa);	/* suppress gcc warning */
		}
		if (ugh != NULL)
		{
		    oc->diag[kaa] = clone_str(ugh, "early key add failure");
		    oc->refCount--;
		}
	    }

	    /* Done launching queries.
	     * Handle total failure case.
	     */
	    key_add_merge(oc, &keyid);
	}
	else
	{
	    ugh = add_public_key(&keyid, DAL_LOCAL, msg->pubkey_alg
		, &msg->keyval, &pluto_pubkeys);
	    if (ugh != NULL)
		loglog(RC_LOG_SERIOUS, "%s", ugh);
	}
    }
}

/*
 * handle a whack message.
 */
void whack_process(int whackfd, struct whack_message msg)
{
    const struct osw_conf_options *oco = osw_init_options();

    if (msg.whack_options)
    {
	switch(msg.opt_set) {
	case WHACK_ADJUSTOPTIONS:
#ifdef DEBUG
	    if (msg.name == NULL)
	    {
		/* we do a two-step so that if either old or new would
		 * cause the message to print, it will be printed.
		 */
		set_debugging(cur_debugging | msg.debugging);
		DBG(DBG_CONTROL
		    , DBG_log("base debugging = %s"
			      , bitnamesof(debug_bit_names, msg.debugging)));
		base_debugging = msg.debugging;
		set_debugging(base_debugging);
	    }
	    else if (!msg.whack_connection)
	    {
		struct connection *c = con_by_name(msg.name, TRUE);

		if (c != NULL)
		{
		    c->extra_debugging = msg.debugging;
		    DBG(DBG_CONTROL
			, DBG_log("\"%s\" extra_debugging = %s"
				  , c->name
				  , bitnamesof(debug_bit_names, c->extra_debugging)));
		}
	    }
#endif
	    break;

	case WHACK_SETDUMPDIR:
	    /* XXX */
	    break;

	case WHACK_STARTWHACKRECORD:
	    /* close old filename */
	    if(whackrecordfile) {
		DBG(DBG_CONTROL
		    , DBG_log("stopped recording whack messages to %s\n"
			      , whackrecordname));
		fclose(whackrecordfile);
	    }
	    whackrecordfile=NULL;

	    openwhackrecordfile(msg.string1);

	    /* do not do any other processing for these */
	    goto done;

	case WHACK_STOPWHACKRECORD:
	    if(whackrecordfile) {
		DBG(DBG_CONTROL
		    , DBG_log("stopped recording whack messages to %s\n"
			      , whackrecordname));
		fclose(whackrecordfile);
	    }
	    whackrecordfile=NULL;
	    /* do not do any other processing for these */
	    goto done;
	}
    }

    if (msg.whack_myid)
	set_myid(MYID_SPECIFIED, msg.myid);

    /* Deleting combined with adding a connection works as replace.
     * To make this more useful, in only this combination,
     * delete will silently ignore the lack of the connection.
     */
    if (msg.whack_delete)
	delete_connections_by_name(msg.name, !msg.whack_connection);

    if (msg.whack_deletestate)
    {
	struct state *st = state_with_serialno(msg.whack_deletestateno);

	if (st == NULL)
	{
	    loglog(RC_UNKNOWN_NAME, "no state #%lu to delete"
		, msg.whack_deletestateno);
	}
	else
	{
	    delete_state(st);
	}
    }

    if (msg.whack_crash)
	delete_states_by_peer(&msg.whack_crash_peer);

    if (msg.whack_connection)
	add_connection(&msg);

    /* process "listen" before any operation that could require it */
    if (msg.whack_listen)
    {
	fflush(stderr);
	fflush(stdout);
	close_peerlog();    /* close any open per-peer logs */
	openswan_log("listening for IKE messages");
	listening = TRUE;
	daily_log_reset();
	reset_adns_restart_count();
	set_myFQDN();
	find_ifaces();
	load_preshared_secrets(NULL_FD);
	load_groups();
    }
    if (msg.whack_unlisten)
    {
	openswan_log("no longer listening for IKE messages");
	listening = FALSE;
    }

    if (msg.whack_reread & REREAD_SECRETS)
    {
	load_preshared_secrets(whackfd);
    }


    if (msg.whack_list & LIST_PUBKEYS)
    {
	list_public_keys(msg.whack_utc, msg.whack_check_pub_keys);
    }

    if (msg.whack_reread & REREAD_CACERTS)
    {
	load_authcerts("CA cert", oco->cacerts_dir, AUTH_CA);
#ifdef HAVE_LIBNSS
       load_authcerts_from_nss("CA cert", AUTH_CA);
#endif
     }

    if (msg.whack_reread & REREAD_AACERTS)
    {
       load_authcerts("AA cert", oco->aacerts_dir, AUTH_AA);
    }

    if (msg.whack_reread & REREAD_OCSPCERTS)
    {
       load_authcerts("OCSP cert", oco->ocspcerts_dir, AUTH_OCSP);
    }

    if (msg.whack_reread & REREAD_ACERTS)
    {
       load_acerts();
    }

    if (msg.whack_reread & REREAD_CRLS)

    {
	load_crls();
    }

    if (msg.tpmeval)
    {
#ifdef TPM
	passert(msg.tpmeval != NULL);
	tpm_eval(msg.tpmeval);
#else
	openswan_log("Pluto not built with TAPROOM");
#endif
    }

#ifdef HAVE_OCSP
    if (msg.whack_purgeocsp)
    {
       free_ocsp_fetch();
       free_ocsp_cache();
    }
#endif

    if (msg.whack_list & LIST_PSKS)
    {
	list_psks();
    }

    if (msg.whack_list & LIST_CERTS)
    {
	list_certs(msg.whack_utc);
    }


    if (msg.whack_list & LIST_AACERTS)
    {
       list_authcerts("AA", AUTH_AA, msg.whack_utc);
    }

    if (msg.whack_list & LIST_OCSPCERTS)
    {
       list_authcerts("OCSP", AUTH_OCSP, msg.whack_utc);
    }

    if (msg.whack_list & LIST_ACERTS)
    {
       list_acerts(msg.whack_utc);
    }

    if (msg.whack_list & LIST_GROUPS)
    {
       list_groups(msg.whack_utc);
     }


    if (msg.whack_list & LIST_CACERTS)
    {
	list_authcerts("CA", AUTH_CA, msg.whack_utc);
    }

    if (msg.whack_list & LIST_CRLS)
    {
	list_crls(msg.whack_utc, strict_crl_policy);
#ifdef HAVE_THREADS
	list_crl_fetch_requests(msg.whack_utc);
#endif
    }

#ifdef HAVE_OCSP
    if (msg.whack_list & LIST_OCSP)
    {
       list_ocsp_cache(msg.whack_utc, strict_crl_policy);
       list_ocsp_fetch_requests(msg.whack_utc);
    }
#endif

    if (msg.whack_list & LIST_EVENTS)
    {
	timer_list();
    }

    if (msg.whack_key)
    {
	/* add a public key */
	key_add_request(&msg);
    }

    if (msg.whack_route)
    {
	if (!listening)
	    whack_log(RC_DEAF, "need --listen before --route");
	else
	{
	    struct connection *c = con_by_name(msg.name, TRUE);

	    if (c != NULL)
	    {
		set_cur_connection(c);
		if (!oriented(*c))
		    whack_log(RC_ORIENT
			, "we cannot identify ourselves with either end of this connection");
		else if (c->policy & POLICY_GROUP)
		    route_group(c);
		else if (!trap_connection(c))
		    whack_log(RC_ROUTE, "could not route");
		reset_cur_connection();
	    }
	}
    }

    if (msg.whack_unroute)
    {
	struct connection *c = con_by_name(msg.name, TRUE);

	if (c != NULL)
	{
	    struct spd_route *sr;
	    int fail = 0;

	    set_cur_connection(c);

	    for (sr = &c->spd; sr != NULL; sr = sr->next)
	    {
		if (sr->routing >= RT_ROUTED_TUNNEL)
		    fail++;
	    }
	    if (fail > 0)
		whack_log(RC_RTBUSY, "cannot unroute: route busy");
	    else if (c->policy & POLICY_GROUP)
		unroute_group(c);
	    else
		unroute_connection(c);
	    reset_cur_connection();
	}
    }

    if (msg.whack_initiate)
    {
	if (!listening)
	    whack_log(RC_DEAF, "need --listen before --initiate");
	else
	    initiate_connection(msg.name
				, msg.whack_async ? NULL_FD : dup_any(whackfd)
				, msg.debugging
				, pcim_demand_crypto);
    }

    if (msg.whack_oppo_initiate)
    {
	if (!listening)
	    whack_log(RC_DEAF, "need --listen before opportunistic initiation");
	else
	    (void)initiate_ondemand(&msg.oppo_my_client, &msg.oppo_peer_client, 0
		, FALSE
		, msg.whack_async? NULL_FD : dup_any(whackfd)
#ifdef HAVE_LABELED_IPSEC
		, NULL
#endif
		, "whack");
    }

    if (msg.whack_terminate)
	terminate_connection(msg.name);

    if (msg.whack_status)
	show_status();

    if (msg.whack_shutdown)
    {
	openswan_log("shutting down");
	exit_pluto(0);	/* delete lock and leave, with 0 status */
    }

done:
    whack_log_fd = NULL_FD;
    close(whackfd);
}

/*
 * Handle a whack request.
 */
void
whack_handle(int whackctlfd)
{
    struct whack_message msg, msg_saved;
    struct sockaddr_un whackaddr;
    socklen_t whackaddrlen = sizeof(whackaddr);
    int whackfd = accept(whackctlfd, (struct sockaddr *)&whackaddr, &whackaddrlen);
    /* Note: actual value in n should fit in int.  To print, cast to int. */
    ssize_t n;
    /* static int msgnum=0; */

    if (whackfd < 0)
    {
	log_errno((e, "accept() failed in whack_handle()"));
	return;
    }
    if (fcntl(whackfd, F_SETFD, FD_CLOEXEC) < 0)
    {
       log_errno((e, "failed to set CLOEXEC in whack_handle()"));
       close(whackfd);
       return;
    }
    memset(&msg, 0, sizeof(msg));
    n = read(whackfd, &msg, sizeof(msg));
    if (n <= 0)
    {
	log_errno((e, "read() failed in whack_handle()"));
	close(whackfd);
	return;
    }

    whack_log_fd = whackfd;

    msg_saved = msg;

    /* DBG_log("msg %d size=%u\n", ++msgnum, n); */

    /* sanity check message */
    {
	err_t ugh = NULL;
        struct whackpacker wp;

        wp.msg = &msg;
        wp.n   = n;
        wp.str_next = msg.string;
        wp.str_roof = (unsigned char *)&msg + n;

	if ((size_t)n < offsetof(struct whack_message, whack_shutdown) + sizeof(msg.whack_shutdown))
	{
	    ugh = builddiag("ignoring runt message from whack: got %d bytes", (int)n);
	}
	else if (msg.magic != WHACK_MAGIC)
	{
	    if (msg.magic == WHACK_BASIC_MAGIC)
	    {
		/* Only basic commands.  Simpler inter-version compatibility. */
		if (msg.whack_status)
		    show_status();

		if (msg.whack_shutdown)
		{
		    openswan_log("shutting down");
		    exit_pluto(0);	/* delete lock and leave, with 0 status */
		}
		ugh = "";	/* bail early, but without complaint */
	    }
	    else
	    {
		ugh = builddiag("ignoring message from whack with bad magic %d; should be %d; Mismatched versions of userland tools and KLIPS code."
		    , msg.magic, WHACK_MAGIC);
	    }
	}
        else if ((ugh = unpack_whack_msg(&wp)) != NULL)
        {
            /* nothing, ugh is already set */
        }
        else
        {
            msg.keyval.ptr = wp.str_next;    /* grab chunk */
        }

	if (ugh != NULL)
	{
	    if (*ugh != '\0')
		loglog(RC_BADWHACKMESSAGE, "%s", ugh);
	    whack_log_fd = NULL_FD;
	    close(whackfd);
	    return;
	}
    }

    /* dump record if necessary */
    writewhackrecord((char *)&msg_saved, n);

    whack_process(whackfd, msg);
}

/*
 * interactive input from the whack user, using current whack_fd
 */
bool whack_prompt_for(int whackfd
		      , const char *prompt1
		      , const char *prompt2
		      , bool echo
		      , char *ansbuf, size_t ansbuf_len)
{
    int savewfd = whack_log_fd;
    ssize_t n;

    whack_log_fd = whackfd;

    DBG(DBG_CONTROLMORE, DBG_log("prompting for %s:", prompt2));

    whack_log(echo ? RC_XAUTHPROMPT : RC_ENTERSECRET
	      , "%s prompt for %s:"
	      , prompt1, prompt2);

    whack_log_fd = savewfd;

    n = read(whackfd, ansbuf, ansbuf_len);

    if(n == -1) {
	whack_log(RC_LOG_SERIOUS, "read(whackfd) failed: %s", strerror(errno));
	return FALSE;
    }

    if(strlen(ansbuf) == 0) {
	whack_log(RC_LOG_SERIOUS, "no %s entered, aborted", prompt2);
	return FALSE;
    }

    return TRUE;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
