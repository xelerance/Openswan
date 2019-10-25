/* Openswan config file parser (confread.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2004 Xelerance Corporation
 * Copyright (C) 2004-2015 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2006-2012 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Michael Smith <msmith@cbnco.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
 */

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/queue.h>

#include "oswalloc.h"
#include "libopenswan.h"
#include "secrets.h"
#include "oswkeys.h"

#include "ipsecconf/parser.h"
#include "ipsecconf/files.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/interfaces.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/starterwhack.h"
#include "ipsecconf/oeconns.h"

#ifdef HAVE_LIBNSS
/* #ifdef FIPS_CHECK */
#include "oswconf.h"
#endif

/* errors that are returned to the caller are kept here */
static char tmp_err[512];

/*
 * A policy only conn means that we load it, and do the appropriate firewalling
 * to make sure that no packets get out that this conn would apply to, but we
 * refuse to negotiate it in any way, either incoming or outgoing.
 */
#define POLICY_ONLY_CONN(conn) if(conn->options[KBF_AUTO] > STARTUP_ROUTE) { conn->options[KBF_AUTO]=STARTUP_POLICY; }



/**
 * Set up hardcoded defaults, from data in programs/pluto/constants.h
 *
 * @param cfg starter_config struct
 * @return void
 */
void ipsecconf_default_values(struct starter_config *cfg)
{
	if (!cfg)
		return;

	zero(cfg);

	TAILQ_INIT(&cfg->conns);

	cfg->setup.options[KBF_FRAGICMP] = TRUE;
	cfg->setup.options[KBF_HIDETOS]  = TRUE;
	cfg->setup.options[KBF_PLUTORESTARTONCRASH]  = TRUE;
	cfg->setup.options[KBF_PLUTOSTDERRLOGTIME]  = FALSE;
	cfg->setup.options[KBF_UNIQUEIDS] = TRUE;
        /* XXX not yet: cfg->setup.options[KBF_PLUTOFORK] = FALSE; */
	cfg->setup.options[KBF_IKEPORT]    = IKE_UDP_PORT;
	cfg->setup.options[KBF_NATIKEPORT] = NAT_IKE_UDP_PORT;
	cfg->setup.options[KBF_NHELPERS]  = -1; /* MCR XXX */
	cfg->setup.options[KBF_KEEPALIVE] = 0;
	cfg->setup.options[KBF_SECCTX]    = SECCTX;
	cfg->setup.options[KBF_DISABLEPORTFLOATING]= FALSE;
	cfg->setup.options[KBF_FORCE_KEEPALIVE]= FALSE;

	cfg->conn_default.options[KBF_NAT_KEEPALIVE] = TRUE;    /* per conn */
	cfg->conn_default.options[KBF_TYPE] = KS_TUNNEL;

	/*Cisco interop: remote peer type*/
	cfg->conn_default.options[KBF_INITIAL_CONTACT] = FALSE;
	/* cfg->conn_default.options[KBF_CISCO_UNITY] = FALSE; */
	cfg->conn_default.options[KBF_SEND_VENDORID] = FALSE;

	cfg->conn_default.options[KBF_REMOTEPEERTYPE] = NON_CISCO;

	cfg->conn_default.options[KBF_SHA2_TRUNCBUG] = FALSE;

	cfg->conn_default.options[KBF_IKEV1_NATT] = natt_both;

	/*Network Manager support*/
	cfg->conn_default.options[KBF_NMCONFIGURED]   = FALSE;

	cfg->conn_default.options[KBF_LOOPBACK]      = FALSE;
	cfg->conn_default.options[KBF_LABELED_IPSEC] = FALSE;
#if 0
	cfg->conn_default.options[KBF_XAUTHBY] = XAUTHBY_FILE;
	cfg->conn_default.options[KBF_XAUTHFAIL] = XAUTHFAIL_HARD;
#endif

	cfg->conn_default.policy = POLICY_RSASIG | POLICY_TUNNEL |
				   POLICY_ENCRYPT | POLICY_PFS;
	cfg->conn_default.policy |= POLICY_IKEV2_ALLOW;         /* ikev2=yes */
	cfg->conn_default.policy |= POLICY_SAREF_TRACK;         /* sareftrack=yes */
	/* cfg->conn_default.policy |= POLICY_IKE_FRAG_ALLOW; */     /* ike_frag=yes */

	cfg->conn_default.options[KBF_IKELIFETIME] = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;

	cfg->conn_default.options[KBF_SALIFETIME]  = SA_LIFE_DURATION_DEFAULT;
	cfg->conn_default.options[KBF_REKEYMARGIN] = SA_REPLACEMENT_MARGIN_DEFAULT;
	cfg->conn_default.options[KBF_REKEYFUZZ]   = SA_REPLACEMENT_FUZZ_DEFAULT;
	cfg->conn_default.options[KBF_KEYINGTRIES] = SA_REPLACEMENT_RETRIES_DEFAULT;

	/* now here is a sticker.. we want it on. But pluto has to be smarter first */
	cfg->conn_default.options[KBF_OPPOENCRYPT] = FALSE;

	cfg->conn_default.options[KBF_CLIENTADDRFAMILY] = AF_INET;

	cfg->conn_default.left.end_addr_family = AF_INET;
	anyaddr(AF_INET, &cfg->conn_default.left.addr);
	cfg->conn_default.left.nexttype  = KH_NOTSET;
	anyaddr(AF_INET, &cfg->conn_default.left.nexthop);

	cfg->conn_default.right.end_addr_family = AF_INET;
	anyaddr(AF_INET, &cfg->conn_default.right.addr);
	cfg->conn_default.right.nexttype = KH_NOTSET;
	anyaddr(AF_INET, &cfg->conn_default.right.nexthop);

	cfg->conn_default.options[KBF_AUTO] = STARTUP_NO;
	cfg->conn_default.state = STATE_LOADED;

	cfg->ctlbase = clone_str(CTL_FILE, "default base");
}

/* format error, and append to string of errors */
static bool error_append(char **perr, const char *fmt, ...)
{
    static char tmp_err[512];

	va_list args;

	char *nerr;
	int len;

	va_start(args, fmt);
	vsnprintf(tmp_err, sizeof(tmp_err) - 1, fmt, args);
	va_end(args);

	len = 1 + strlen(tmp_err) + (*perr != NULL ? strlen(*perr) : 0);
	nerr = alloc_bytes(len, "error_append len");
	nerr[0] = '\0';
	if (*perr != NULL) {
		strcpy(nerr, *perr);	/* safe: see allocation above */
		pfree(*perr);
	}
	strcat(nerr, tmp_err);	/* safe: see allocation above */
	*perr = nerr;

	return TRUE;
}


#define KW_POLICY_FLAG(val,fl) if(conn->options_set[val]) \
        { if(conn->options[val]) \
	  { \
	    conn->policy |= fl; \
	  } else { \
	    conn->policy &= ~fl;\
	  }}

#define KW_POLICY_NEGATIVE_FLAG(val,fl) if(conn->options_set[val]) \
        { if(!conn->options[val]) \
	  { \
	    conn->policy |= fl; \
	  } else { \
	    conn->policy &= ~fl;\
	  }}

#define FREE_LIST(v) { if ((v) != NULL) { free_list(v); (v) = NULL; } }
/**
 * Free the pointer list
 *
 * @param list list of pointers
 * @return void
 */
static void free_list(char **list)
{
	char **s;

	for (s = list ; *s; s++)
		pfreeany(*s);
	pfree(list);
}

/**
 * Create a new list (array) of pointers to strings, NULL-terminated
 *
 * @param value string to be broken up at spaces, creating strings for list
 * @return new_list (pointer to NULL-terminated array of pointers to strings)
 */
static char **new_list(char *value)
{
	char *val, *b, *e, *end, **nlist;
	int count;

	if(value == NULL) return NULL;

	/* avoid damaging original string */
	val = clone_str(value, "new_list value");
	end = val + strlen(val);

	/* count number of items in string */
	for (b=val, count=0; b<end; ) {
		for (e=b; ((*e!=' ') && (*e!='\0')); e++);
		*e = '\0';
		if (e!=b) { count++; }
		b=e+1;
	}
	if (count == 0) {
		pfree(val);
		return NULL;
	}

	nlist = (char **)alloc_bytes((count + 1) * sizeof(char *), "new_list nlist");
	for (b = val, count = 0; b < end; ) {
		e = b + strlen(b);
		if (e != b) {
			nlist[count++] = clone_str(b, "new_list item");
                }
		b = e + 1;
	}
	nlist[count] = NULL;
	pfree(val);
	return nlist;
}

/**
 * Load a parsed config
 *
 * @param cfg starter_config structure
 * @param cfgp config_parsed (ie: valid) struct
 * @param perr pointer to store errors in
 * @return int 0 if successfull
 */
static bool load_setup(struct starter_config *cfg,
		      struct config_parsed *cfgp)
{
    bool err = FALSE;
    struct kw_list *kw;

    for (kw = cfgp->config_setup; kw; kw = kw->next) {

        /**
         * the parser already made sure that only config keywords were used,
         * but we double check!
         */
        assert(kw->keyword.keydef->validity & kv_config);

        if(kw->keyword.keydef->validity & kv_obsolete) {
            starter_log(LOG_LEVEL_INFO,
                        "Warning: obsolete keyword '%s' ignored on read",
                        kw->keyword.keydef->keyname);
        }

        switch (kw->keyword.keydef->type) {
        case kt_string:
        case kt_filename:
        case kt_dirname:
        case kt_loose_enum:
        case kt_loose_enumarg:
            /* all treated as strings for now */
            assert(kw->keyword.keydef->field < sizeof(cfg->setup.strings));
            pfreeany(cfg->setup.strings[kw->keyword.keydef->field]);
            cfg->setup.strings[kw->keyword.keydef->field] =
                clone_str(kw->keyword.string, "kt_loose_enum kw->keyword.string");
            cfg->setup.strings_set[kw->keyword.keydef->field] =TRUE;
            break;

        case kt_list:
        case kt_bool:
        case kt_invertbool:
        case kt_enum:
        case kt_number:
        case kt_time:
        case kt_percent:
            /* all treated as a number for now */
            assert(kw->keyword.keydef->field <
                   sizeof(cfg->setup.options));
            cfg->setup.options[kw->keyword.keydef->field] =
                kw->number;
            cfg->setup.options_set[kw->keyword.keydef->field] =
                TRUE;
            break;

        case kt_bitstring:
        case kt_rsakey:
        case kt_ipaddr:
        case kt_subnet:
            /* case kt_range: */
        case kt_idtype:
            err = TRUE;
            break;

        case kt_appendstring:
        case kt_appendlist:
            /* XXX not yet implemented */
            break;
        case kt_comment:
            break;

        }
    }

    /* now process some things with specific values */

    /* interfaces has to be chopped up */
    if (cfg->setup.interfaces)
        FREE_LIST(cfg->setup.interfaces);
    cfg->setup.interfaces = new_list(cfg->setup.strings[KSF_INTERFACES]);

    return err;
}

/**
 * Validate that yes in fact we are one side of the tunnel
 *
 * The function checks that IP addresses are valid, nexthops are
 * present (if needed) as well as policies, and sets the leftID
 * from the left= if it isn't set.
 *
 * @param conn_st a connection definition
 * @param end a connection end
 * @param left boolean (are we 'left'? 1 = yes, 0 = no)
 * @param perr pointer to char containing error value
 * @return bool TRUE if failed
 */
static bool validate_end(struct starter_conn *conn_st
			, struct starter_end *end
			, bool left
			, bool resolvip UNUSED
			, err_t *perr)
{
    err_t er = NULL;
    char *err_str = NULL;
    const char *leftright=(left ? "left" : "right");
    int family;
    int newfamily;
    bool err = FALSE;

#define ERR_FOUND(args...) do { err += error_append(&err_str, ##args); } while(0)

    if(!end->options_set[KNCF_IP]) {
	conn_st->state = STATE_INCOMPLETE;
    }

    family = AF_UNSPEC;
    if(conn_st->options_set[KBF_ENDADDRFAMILY]) {
	    family = conn_st->options[KBF_ENDADDRFAMILY];
    }

    end->addrtype=end->options[KNCF_IP];
    end->end_addr_family = family;
    newfamily = family;

    /* validate the KSCF_IP/KNCF_IP */
    switch(end->addrtype) {
    case KH_ANY:
	anyaddr(family, &(end->addr));
	break;

    case KH_IFACE:
	/* generally, this doesn't show up at this stage */

	break;

    case KH_IPADDR:
        /* right=/left= */
	assert(end->strings[KSCF_IP] != NULL);

	if (end->strings[KSCF_IP][0]=='%') {
	    if (end->iface) pfree(end->iface);
            end->iface = clone_str(end->strings[KSCF_IP] + 1, "KH_IPADDR end->iface");
	    if (starter_iface_find(end->iface, family, &(end->addr),
				   &(end->nexthop)) == -1) {
	        conn_st->state = STATE_INVALID;
	    }
	    /* not numeric, so set the type to the iface type */
	    end->addrtype = KH_IFACE;
	    break;
	}

	er = ttoaddr_num(end->strings[KNCF_IP], 0, AF_INET6, &(end->addr));
	if(er == NULL) { /* no error! */
		newfamily = AF_INET6;
	} else { /* error */
		er = ttoaddr_num(end->strings[KNCF_IP], 0, AF_INET, &(end->addr));
		if(er == NULL) {
			newfamily = AF_INET;
		}
	}
	if(family == 0) {
		end->end_addr_family = newfamily;
	}

	if(er) {
	    /* not numeric, so set the type to the string type */
	    end->addrtype = KH_IPHOSTNAME;
	}

        if(end->id == NULL) {
            char idbuf[ADDRTOT_BUF];
            addrtot(&end->addr, 0, idbuf, sizeof(idbuf));

            end->id= clone_str(idbuf, "end id");
        }
	break;

    case KH_OPPO:
	conn_st->policy |= POLICY_OPPO;
	break;

    case KH_OPPOGROUP:
	conn_st->policy |= POLICY_OPPO|POLICY_GROUP;
	break;

    case KH_GROUP:
	conn_st->policy |= POLICY_GROUP;
	break;

    case KH_IPHOSTNAME:
        /* XXX */
	break;

    case KH_DEFAULTROUTE:
	break;

    case KH_NOTSET:
	break;
    }

    /* validate the KSCF_SUBNET */
    if(end->strings_set[KSCF_SUBNET])
    {
	char *value = end->strings[KSCF_SUBNET];
	unsigned int client_family = AF_UNSPEC;

	if(conn_st->tunnel_addr_family != 0) {
	    client_family = conn_st->tunnel_addr_family;
        }

        if ( ((strlen(value)>=6) && (strncmp(value,"vhost:",6)==0)) ||
	     ((strlen(value)>=5) && (strncmp(value,"vnet:",5)==0)) ) {
	    er = NULL;
	    end->virt = clone_str(value, "end->virt");
	}
	else {
	    end->has_client = TRUE;
	    er = ttosubnet(value, 0, client_family, &(end->subnet));
            client_family = end->subnet.addr.u.v4.sin_family;
	}

	if (er) ERR_FOUND("bad subnet %ssubnet=%s [%s] family=%s", leftright, value, er, family2str(family));

        end->tunnel_addr_family = client_family;
    }

    /* set nexthop address to something consistent, by default */
    anyaddr(family, &end->nexthop);
    anyaddr(addrtypeof(&end->addr), &end->nexthop);

    /* validate the KSCF_NEXTHOP */
    if(end->strings_set[KSCF_NEXTHOP])
    {
	char *value = end->strings[KSCF_NEXTHOP];

	if(strcasecmp(value, "%defaultroute")==0) {
	    end->nexttype=KH_DEFAULTROUTE;
	} else {
            if (tnatoaddr(value, strlen(value), AF_INET,
                          &(end->nexthop)) != NULL &&
                tnatoaddr(value, strlen(value), AF_INET6,
                          &(end->nexthop)) != NULL) {
                er = ttoaddr(value, 0, family, &(end->nexthop));
                if (er) ERR_FOUND("bad addr %snexthop=%s [%s]", leftright, value, er);
            }
            end->nexttype = KH_IPADDR;
	}
    } else {
      if (end->addrtype == KH_DEFAULTROUTE) {
        end->nexttype = KH_DEFAULTROUTE;
      }
      anyaddr(family, &end->nexthop);
    }

    /* validate the KSCF_ID */
    if(end->strings_set[KSCF_ID])
    {
	char *value = end->strings[KSCF_ID];

        pfreeany(end->id);
        end->id = clone_str(value, "end->id");
    }

    if(end->options_set[KSCF_RSAKEY1]) {
	end->rsakey1_type = end->options[KSCF_RSAKEY1];
	end->rsakey2_type = end->options[KSCF_RSAKEY2];

	switch(end->rsakey1_type) {
        case PUBKEY_NOTSET:
            /* really should not happen! */
            break;

	case PUBKEY_DNS:
	case PUBKEY_DNSONDEMAND:
        case PUBKEY_CERTIFICATE:
            /* pass it on */
	    break;

        case PUBKEY_PREEXCHANGED:
	    /* validate the KSCF_RSAKEY1/RSAKEY2 */
	    if(end->strings_set[KSCF_RSAKEY1])
	    {
		char *value = end->strings[KSCF_RSAKEY1];
                osw_public_key opk1;
                zero(&opk1);

                pfreeany(end->rsakey1);
                end->rsakey1 = (unsigned char *)clone_str(value,"end->rsakey1");
                if(str2pubkey(end->rsakey1, PUBKEY_ALG_RSA, &opk1) == NULL) {
                    end->rsakey1_ckaid = clone_str(opk1.key_ckaid_print_buf, "end->rsakey1_ckaid");
                    free_RSA_public_content(&opk1.u.rsa);
                }
	    }
	    if(end->strings_set[KSCF_RSAKEY2])
	    {
		char *value = end->strings[KSCF_RSAKEY2];
                osw_public_key opk2;
                zero(&opk2);

                pfreeany(end->rsakey2);
                end->rsakey2 = (unsigned char *)clone_str(value,"end->rsakey2");
                if(str2pubkey(end->rsakey2, PUBKEY_ALG_RSA, &opk2) == NULL) {
                    end->rsakey2_ckaid = clone_str(opk2.key_ckaid_print_buf, "end->rsakey2_ckaid");
                    free_RSA_public_content(&opk2.u.rsa);
                }
	    }
	}
    }

    /* validate the KSCF_SOURCEIP, if any, and if set,
     * set the subnet to same value, if not set.
     */
    if(end->strings_set[KSCF_SOURCEIP])
    {
	char *value = end->strings[KSCF_SOURCEIP];

	if (tnatoaddr(value, strlen(value), AF_INET, &(end->sourceip)) != NULL
	    && tnatoaddr(value, strlen(value), AF_INET6, &(end->sourceip)) != NULL) {

	    er = ttoaddr(value, 0, 0, &(end->sourceip));
	    if (er) ERR_FOUND("bad addr %ssourceip=%s [%s]", leftright, value, er);

	} else {
		er = tnatoaddr(value, 0, 0, &(end->sourceip));
		if (er) ERR_FOUND("bad numerical addr %ssourceip=%s [%s]", leftright, value, er);
	}

	if(!end->has_client) {
	    starter_log(LOG_LEVEL_INFO, "defaulting %ssubnet to %s\n", leftright, value);
	    er = addrtosubnet(&end->sourceip, &end->subnet);
	    if (er) ERR_FOUND("attempt to default %ssubnet from %s failed: %s", leftright, value, er);
	    end->has_client = TRUE;
	    end->has_client_wildcard = FALSE;
	}
    }

    /* copy certificate path name */
    if(end->strings_set[KSCF_CERT]) {
        end->rsakey1_type = PUBKEY_CERTIFICATE;
        end->cert = clone_str(end->strings[KSCF_CERT], "KSCF_CERT");
    }

    if(end->strings_set[KSCF_CA]) {
        end->rsakey1_type = PUBKEY_CERTIFICATE;
        end->ca = clone_str(end->strings[KSCF_CA], "KSCF_CA");
    }

    if(end->strings_set[KSCF_UPDOWN]) {
        end->updown = clone_str(end->strings[KSCF_UPDOWN], "KSCF_UPDOWN");
    }

    if(end->strings_set[KSCF_PROTOPORT]) {
	err_t ugh;
	char *value = end->strings[KSCF_PROTOPORT];

	ugh = ttoprotoport(value, 0, &end->protocol, &end->port, &end->has_port_wildcard);

	if (ugh) ERR_FOUND("bad %sprotoport=%s [%s]", leftright, value, ugh);
    }

    if (end->options_set[KNCF_XAUTHSERVER] ||
        end->options_set[KNCF_XAUTHCLIENT]) {
	conn_st->policy |= POLICY_XAUTH;
    }

    /*
    KSCF_SUBNETWITHIN    --- not sure what to do with it.
    KSCF_ESPENCKEY       --- todo (manual keying)
    KSCF_ESPAUTHKEY      --- todo (manual keying)
    KSCF_SOURCEIP     = 16,
    KSCF_MAX          = 19
    */

    if(err) *perr = err_str;
    return err;
#  undef ERR_FOUND
}


/**
 * Take keywords from ipsec.conf syntax and load into a conn struct
 *
 *
 * @param conn a connection definition
 * @param sl a section_list
 * @param assigned_value is set to either k_set, or k_default.
 *        k_default is used when we are loading a conn that should be
 *        considered to be a "default" value, and that replacing this
 *        value is considered acceptable.
 * @return bool 0 if successfull
 */
bool translate_conn (struct starter_conn *conn
		     , struct section_list *sl
		     , enum keyword_set   assigned_value
		     , err_t *error
                     , bool alsoflip)
{
    unsigned int err, field;
    ksf    *the_strings;
    knf    *the_options;
    str_set *set_strings;
    int_set *set_options;
    volatile int i;              /* just to keep it around for debugging */
    struct kw_list *kw = sl->kw;

    err = 0;
    i = 0;

    for ( ; kw; kw=kw->next)
    {
        char keyname[128];

	i++;
	the_strings = &conn->strings;
	set_strings = &conn->strings_set;
	the_options = &conn->options;
	set_options = &conn->options_set;

        /* initialize with base value */
        strcpy(keyname, kw->keyword.keydef->keyname);

        if((kw->keyword.keydef->validity & kv_conn) == 0)
	{
	    /* this isn't valid in a conn! */
	    *error = (const char *)tmp_err;

	    snprintf(tmp_err, sizeof(tmp_err),
		     "keyword '%s' is not valid in a conn (%s) (#%d)\n",
		     keyname, sl->name, i);
	    starter_log(LOG_LEVEL_INFO, "%s", tmp_err);
	    continue;
	}

        if(kw->keyword.keydef->validity & kv_obsolete) {
	    starter_log(LOG_LEVEL_DEBUG,"Warning: obsolete keyword %s ignored\n",kw->keyword.keydef->keyname);
        }

        if(kw->keyword.keydef->validity & kv_leftright)
	{
            struct starter_end *left, *right;
            left  = &conn->left;
            right = &conn->right;
            if(alsoflip) {
                left = &conn->right;
                right= &conn->left;
            }

	    if(kw->keyword.keyleft)
	    {
                snprintf(keyname, sizeof(keyname), "left%s", kw->keyword.keydef->keyname);
		the_strings = &left->strings;
		the_options = &left->options;
		set_strings = &left->strings_set;
		set_options = &left->options_set;
	    } else {
                snprintf(keyname, sizeof(keyname), "right%s", kw->keyword.keydef->keyname);
		the_strings = &right->strings;
		the_options = &right->options;
		set_strings = &right->strings_set;
 		set_options = &right->options_set;
	    }
	}

	field = kw->keyword.keydef->field;

#ifdef PARSER_TYPE_DEBUG
	starter_log(LOG_LEVEL_DEBUG, "#analyzing %s[%d] kwtype=%d\n",
		    keyname, field,
		    kw->keyword.keydef->type);
#endif

	assert(kw->keyword.keydef != NULL);
	switch(kw->keyword.keydef->type)
	{
	case kt_string:
	case kt_filename:
	case kt_dirname:
	case kt_bitstring:
	case kt_ipaddr:
	case kt_subnet:
	case kt_idtype:
	    /* all treated as strings for now */
	    assert(kw->keyword.keydef->field < KEY_STRINGS_MAX);
	    if((*set_strings)[field] == k_set)
	    {
		*error = tmp_err;

                /* keyname[0] test looks for left=/right= */
		snprintf(tmp_err, sizeof(tmp_err)
			 , "duplicate string key '%s' in conn %s (line=%u) while processing def %s (ignored)"
			 , keyname
			 , conn->name, kw->lineno
			 , sl->name);

		starter_log(LOG_LEVEL_INFO, "%s", tmp_err);
		if(kw->keyword.string == NULL
		   || (*the_strings)[field] == NULL
		   || strcmp(kw->keyword.string, (*the_strings)[field])!=0)
		{
		    err++;
		    break;
		}
	    }
            pfreeany((*the_strings)[field]);

	    if(kw->keyword.string == NULL) {
		*error = tmp_err;

		snprintf(tmp_err, sizeof(tmp_err)
			 , "Invalid %s value"
			 , keyname);
		    err++;
		    break;
            }

            (*the_strings)[field] = clone_str(kw->keyword.string,"kt_idtype kw->keyword.string");
	    (*set_strings)[field] = assigned_value;
	    break;

	case kt_appendstring:
	case kt_appendlist:
	    /* implicitely, this field can have multiple values */
	    assert(kw->keyword.keydef->field < KEY_STRINGS_MAX);
	    if(!(*the_strings)[field])
	    {
                (*the_strings)[field] = clone_str(kw->keyword.string, "kt_appendlist kw->keyword.string");
	    } else {
                char *s = (*the_strings)[field];
                size_t old_len = strlen(s);	/* excludes '\0' */
                size_t new_len = strlen(kw->keyword.string);
                char *n;

                n = alloc_bytes(old_len + 1 + new_len + 1, "kt_appendlist");
                memcpy(n, s, old_len);
                n[old_len] = ' ';
                memcpy(n + old_len + 1, kw->keyword.string, new_len + 1);	/* includes '\0' */
                (*the_strings)[field] = n;
                pfree(s);
	    }
	    (*set_strings)[field] = TRUE;
	    break;

	case kt_rsakey:
	case kt_loose_enum:
	case kt_loose_enumarg:
	    assert(field < KEY_STRINGS_MAX);
	    assert(field < KEY_NUMERIC_MAX);

	    if((*set_options)[field] == k_set)
	    {
                bool fatal = FALSE;

		*error = tmp_err;
		/* only fatal if we try to change values */
		if((*the_options)[field] != kw->number
		   || !((*the_options)[field] == LOOSE_ENUM_OTHER
			&& kw->number == LOOSE_ENUM_OTHER
			&& kw->keyword.string != NULL
			&& (*the_strings)[field] != NULL
			&& strcmp(kw->keyword.string, (*the_strings)[field])==0))
		{
                    fatal = TRUE;
		    err++;
		}
		snprintf(tmp_err, sizeof(tmp_err)
			 , "duplicate loose key '%s' in conn %s (line=%u) while processing def %s%s"
			 , keyname
			 , conn->name, kw->lineno
			 , sl->name, fatal ? "(FATAL!)":"");

		starter_log(LOG_LEVEL_INFO, "%s", tmp_err);

                if(fatal) {
		    break;
                }

	    }

	    (*the_options)[field] = kw->number;
	    if(kw->number == LOOSE_ENUM_OTHER)
	    {
		assert(kw->keyword.string != NULL);
                pfreeany((*the_strings)[field]);
                (*the_strings)[field] = clone_str(kw->keyword.string, "kt_loose_enum kw->keyword.string");
                (*set_strings)[field] = TRUE;
	    } else if(kw->keyword.keydef->type == kt_loose_enumarg && kw->argument != NULL) {
                pfreeany((*the_strings)[field]);
                (*the_strings)[field] = clone_str(kw->argument, "kt_loose_enum kw->keyword.argument");
                (*set_strings)[field] = TRUE;
            }

	    (*set_options)[field] = assigned_value;
	    break;

	case kt_list:
	case kt_bool:
	case kt_invertbool:
	case kt_enum:
	case kt_number:
	case kt_time:
	case kt_percent:
	    /* all treated as a number for now */
	    assert(field < KEY_NUMERIC_MAX);

	    if((*set_options)[field] == k_set)
	    {
		starter_log(LOG_LEVEL_INFO
                            , "duplicate enum key '%s' in conn %s (line=%u) while processing def %s"
                            , keyname, conn->name, kw->lineno, sl->name);
		if((*the_options)[field] != kw->number)
		{
		    err++;
		    break;
		}
	    }

#if 0
	    starter_log(LOG_LEVEL_DEBUG, "#setting %s[%d]=%u at line=%u\n",
			keyname, field, kw->number, kw->lineno);
#endif
	    (*the_options)[field] = kw->number;
	    (*set_options)[field] = assigned_value;
	    break;

	case kt_comment:
	    break;
	}
    }
    return err;
}


void move_comment_list(struct starter_comments_list *to,
		       struct starter_comments_list *from)
{
    struct starter_comments *sc, *scnext;

    for(sc = from->tqh_first;
	sc != NULL;
	sc = scnext) {
	scnext = sc->link.tqe_next;
	TAILQ_REMOVE(from, sc,link);
	TAILQ_INSERT_TAIL(to, sc,link);
    }
}

static int load_conn_basic(struct starter_conn *conn
			   , struct section_list *sl
			   , enum keyword_set assigned_value
			   , err_t *perr)
{
    int err;

    /*turn all of the keyword/value pairs into options/strings in left/right */
    err = translate_conn(conn, sl, assigned_value, perr, FALSE);

    return err;
}

char **process_alsos(struct starter_config *cfg
                     , struct starter_conn *conn
                     , struct config_parsed *cfgp
                     , char **alsos, int alsosize
                     , bool alsoflip
                     , err_t *perr)
{
    int   alsoplace;
    unsigned int err;
    alsoplace = 0;

    /*alsos is equal to conn->alsos that has been already veirfied for NULL*/
    while(alsoplace < alsosize && alsos[alsoplace] != NULL
          && alsoplace < ALSO_LIMIT) {
        struct section_list *sl1;

        /*
         * for each also= listed, go find this section's keyword list, and
         * load it as well. This may extend the also= list (and the end),
         * which we handle by zeroing the also list, and adding to it after
         * checking for duplicates.
         */
        for(sl1 = cfgp->sections.tqh_first;
            sl1 != NULL && strcasecmp(alsos[alsoplace], sl1->name) != 0;
            sl1 = sl1->link.tqe_next);

        starter_log(LOG_LEVEL_DEBUG, "\twhile loading conn '%s' also including '%s'"
                    , conn->name, alsos[alsoplace]);

        /*
         * if we found something that matches by name, and we haven't been
         * there, then process it.
         */
        if(sl1 && !sl1->beenhere)  {
            conn->strings_set[KSF_ALSO]=FALSE;
            pfreeany(conn->strings[KSF_ALSO]);
            conn->strings[KSF_ALSO]=NULL;
            sl1->beenhere = TRUE;

            /* translate things, but do not replace earlier settings!*/
            err += translate_conn(conn, sl1, k_set, perr, alsoflip);

            if(conn->strings[KSF_ALSO]) {
                char **newalsos;
                int   newalsoplace;

                /* now, check out the KSF_ALSO, and extend list if we need to */
                newalsos = new_list(conn->strings[KSF_ALSO]);

                if(newalsos && newalsos[0]!=NULL) {
                    char **ra;
                    /* count them */
                    for(newalsoplace=0; newalsos[newalsoplace]!=NULL; newalsoplace++);

                    /* extend conn->alsos */
                    ra = alloc_bytes((alsosize + newalsoplace + 1) * sizeof(char *),
                                     "conn->alsos");
                    memcpy(ra, alsos, alsosize * sizeof(char *));
                    pfree(alsos);
                    alsos = ra;

                    for(newalsoplace=0; newalsos[newalsoplace]!=NULL; newalsoplace++) {
                        assert(conn != NULL);
                        assert(conn->name != NULL);
                        starter_log(LOG_LEVEL_DEBUG
                                    , "\twhile processing section '%s' added also=%s"
                                    , sl1->name, newalsos[newalsoplace]);

                        alsos[alsosize++] = clone_str(newalsos[newalsoplace], "alsos");
                    }
                    alsos[alsosize]=NULL;
                }
                FREE_LIST(newalsos);
            }
        }

        alsoplace++;
	if(alsoplace >= ALSO_LIMIT)
	{
	    starter_log(LOG_LEVEL_INFO
			, "while loading conn '%s', too many also= used at section %s. Limit is %d"
			, conn->name
			, conn->alsos[alsoplace]
			, ALSO_LIMIT);
            *perr = "too many also";
	    return NULL;
	}
    }
    return alsos;
}

static int validate_family_consistency(const char *connname,
                                       const char *addrtype,
                                       unsigned int left,
                                       unsigned int right,
                                       unsigned int family)
{
    unsigned int nfamily = AF_LOCAL; /* an invalid value */

    /* they could all be equal and consistent */
    if(left == family && right == family) {
        return family;
    }

    /* if right has a family, use it */
    if(left == 0 &&
       family      == 0 &&
       right != 0) {
        left = nfamily = right;
    }

    /* if left has a family, use it */
    if(left  != 0 &&
       family       == 0 &&
       right == 0) {
        right = nfamily = left;
    }

    /* if left and right are blank, then set them from family */
    if(left  == 0 &&
       family       != 0 &&
       right == 0) {
        nfamily = right = left = family;
    }

    /* if family is blank, and left and right are set to the same value,
     * then set family to that value.
     */
    if(left  != 0 &&
       family       == 0 &&
       right != 0 &&
       left  == right) {
        nfamily = right;
    }

    /* they could be all unspecified, which is not inconsistent, just not useful */
    if(left == 0 && family == 0 && right == 0) {
        return AF_UNSPEC;
    }

    /* if the end_address family is *STILL* 0, then it must be that there is an
       inconsistency in the left/right ends.
    */
    if(nfamily == AF_LOCAL) {
        char b1[KEYWORD_NAME_BUFLEN];
        char b2[KEYWORD_NAME_BUFLEN];
        char b3[KEYWORD_NAME_BUFLEN];
        starter_log(LOG_LEVEL_ERR,
                    "%s: inconsistent left/right %s address family: policy=%s left=%s right=%s",
                    connname,
                    addrtype,
                    keyword_name(&kw_connaddrfamily_list, family, b1),
                    keyword_name(&kw_connaddrfamily_list, left, b2),
                    keyword_name(&kw_connaddrfamily_list, right, b3));
        return AF_UNSPEC;
    }

    return nfamily;
}

static int load_conn (struct starter_config *cfg
		      , struct starter_conn *conn
		      , struct config_parsed *cfgp
		      , struct section_list *sl
		      , bool alsoprocessing
		      , bool defaultconn
		      , bool resolvip
		      , err_t *perr)
{
    unsigned int err;
    err = 0;

    err += load_conn_basic(conn, sl, defaultconn ? k_default : k_set, perr);

    move_comment_list(&conn->comments, &sl->comments);

    if(err) return err;

    if(conn->strings[KSF_ALSO] != NULL
       && !alsoprocessing)
    {
	starter_log(LOG_LEVEL_INFO
		    , "also= is not valid in section '%s'"
		    , sl->name);
	return 1;
    }

    /* now, process the also's */
    if (conn->alsos) free_list(conn->alsos);
    conn->alsos = new_list(conn->strings[KSF_ALSO]);

    if(alsoprocessing && conn->alsos)
    {
        unsigned int alsosize;
        char **alsos;
        struct section_list *sl1;

	/* reset all of the "beenhere" flags: can not also= and alsoflip= the same conn, btw. */
	for(sl1 = cfgp->sections.tqh_first; sl1 != NULL; sl1 = sl1->link.tqe_next)
	{
	    sl1->beenhere = FALSE;
	}
	sl->beenhere = TRUE;

        /* count them */
        alsos = conn->alsos;
        conn->alsos = NULL;
        for(alsosize=0; alsos[alsosize]!=NULL; alsosize++);

        starter_log(LOG_LEVEL_DEBUG, "# conn %s processing alsos", conn->name);
        conn->alsos = process_alsos(cfg, conn, cfgp, alsos, alsosize, FALSE, perr);

        if(conn->strings[KSF_ALSOFLIP]) {
            alsos = new_list(conn->strings[KSF_ALSOFLIP]);
            for(alsosize=0; alsos[alsosize]!=NULL; alsosize++);

            starter_log(LOG_LEVEL_DEBUG, "# conn %s processing alsoflips", conn->name);
            conn->also_flips = process_alsos(cfg, conn, cfgp, alsos, alsosize, TRUE, perr);
        }
    }

#ifdef PARSER_TYPE_DEBUG
    /* translate strings/numbers into conn items */
    starter_log(LOG_LEVEL_DEBUG, "#checking options_set[KBF_TYPE,%d]=%d %d\n",
		KBF_TYPE,
		conn->options_set[KBF_TYPE], conn->options[KBF_TYPE]);
#endif

    if(conn->options_set[KBF_TYPE]) {
	switch((enum keyword_satype)conn->options[KBF_TYPE]) {
	case KS_TUNNEL:
	    conn->policy |= POLICY_TUNNEL;
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    break;

	case KS_TRANSPORT:
	    conn->policy &= ~POLICY_TUNNEL;
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    break;

	case KS_UDPENCAP:
	    /* no way to specify this yet! */
	    break;

	case KS_PASSTHROUGH:
	    conn->policy &= ~(POLICY_ENCRYPT|POLICY_AUTHENTICATE|POLICY_TUNNEL|POLICY_RSASIG);
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    conn->policy |= POLICY_SHUNT_PASS;
	    break;

	case KS_DROP:
	    conn->policy &= ~(POLICY_ENCRYPT|POLICY_AUTHENTICATE|POLICY_TUNNEL|POLICY_RSASIG);
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    conn->policy |= POLICY_SHUNT_DROP;
	    break;

	case KS_REJECT:
	    conn->policy &= ~(POLICY_ENCRYPT|POLICY_AUTHENTICATE|POLICY_TUNNEL|POLICY_RSASIG);
	    conn->policy &= ~POLICY_SHUNT_MASK;
	    conn->policy |= POLICY_SHUNT_REJECT;
	    break;
	}
    }

    KW_POLICY_FLAG(KBF_COMPRESS, POLICY_COMPRESS);
    KW_POLICY_FLAG(KBF_PFS,  POLICY_PFS);

    /* reset authby flags */
    if(conn->options_set[KBF_AUTHBY]) {
	conn->policy &= ~(POLICY_ID_AUTH_MASK);
	conn->policy |= conn->options[KBF_AUTHBY];

#if STARTER_POLICY_DEBUG
	starter_log(LOG_LEVEL_DEBUG,
		    "%s: setting conn->policy=%08x (%08x)\n",
		    conn->name,
		    (unsigned int)conn->policy,
		    conn->options[KBF_AUTHBY]);
#endif
    }

    KW_POLICY_NEGATIVE_FLAG(KBF_REKEY, POLICY_DONT_REKEY);

    KW_POLICY_FLAG(KBF_AGGRMODE, POLICY_AGGRESSIVE);

    KW_POLICY_FLAG(KBF_MODECONFIGPULL, POLICY_MODECFG_PULL);

    KW_POLICY_FLAG(KBF_OVERLAPIP, POLICY_OVERLAPIP);

    KW_POLICY_FLAG(KBF_IKEv2_ALLOW_NARROWING, POLICY_IKEV2_ALLOW_NARROWING);

    if(conn->strings_set[KSF_ESP]) {
        conn->esp = clone_str(conn->strings[KSF_ESP],"KSF_ESP");
    }

#ifdef HAVE_LABELED_IPSEC
    if(conn->strings_set[KSF_POLICY_LABEL]) {
        conn->policy_label = clone_str(conn->strings[KSF_POLICY_LABEL],"KSF_POLICY_LABEL");
    }
    starter_log(LOG_LEVEL_DEBUG,"connection's  policy label: %s", conn->policy_label);
#endif

#if 0
    if (conn->strings_set[KSF_MODECFGDNS1]) {
        conn->modecfg_dns1 = clone_str(conn->strings[KSF_MODECFGDNS1],"KSF_MODECFGDNS1");
    }
    if (conn->strings_set[KSF_MODECFGDNS2]) {
        conn->modecfg_dns2 = clone_str(conn->strings[KSF_MODECFGDNS2], "KSF_MODECFGDNS2");
    }
    if (conn->strings_set[KSF_MODECFGDOMAIN]) {
        conn->modecfg_domain = clone_str(conn->strings[KSF_MODECFGDOMAIN],"KSF_MODECFGDOMAIN");
    }
    if (conn->strings_set[KSF_MODECFGBANNER]) {
        conn->modecfg_banner = clone_str(conn->strings[KSF_MODECFGBANNER],"KSF_MODECFGBANNER");
    }
#endif

    if(conn->strings_set[KSF_IKE]) {
        conn->ike = clone_str(conn->strings[KSF_IKE],"KSF_IKE");
    }

    if(conn->strings_set[KSF_CONNALIAS]) {
        conn->connalias = clone_str(conn->strings[KSF_CONNALIAS],"KSF_CONNALIAS");
    }

    if(conn->options_set[KBF_PHASE2]) {
	conn->policy &= ~(POLICY_AUTHENTICATE|POLICY_ENCRYPT);
	conn->policy |= conn->options[KBF_PHASE2];
    }

    /* keyexchange= may also set IKEv1/IKEv2 options, but it has lower
     * precedence vs ikev2= /ikev1, so process it first
     */

    if(conn->options_set[KBF_KEYEXCHANGE]) {
        switch(conn->options[KBF_KEYEXCHANGE]) {
        case KE_IKE:
            /* nothing, we do not support any other kind */
            break;

        case KE_IKEv1:
            /* normally allowed, so do not set IKEV1_DISABLED */
            conn->options[KBF_KEYEXCHANGE] = KE_IKE;
	    conn->policy &= ~(POLICY_IKEV2_ALLOW|POLICY_IKEV2_PROPOSE);
            break;

        case KE_IKEv2:
            /* same as fo_insist */
            conn->options[KBF_KEYEXCHANGE] = KE_IKE;
	    conn->policy |= POLICY_IKEV1_DISABLE;
	    conn->policy |= POLICY_IKEV2_ALLOW|POLICY_IKEV2_PROPOSE;
        }
    }

    /* ikev1 = yes/no */
    KW_POLICY_NEGATIVE_FLAG(KBF_IKEv1, POLICY_IKEV1_DISABLE);
    if(conn->options_set[KBF_IKEv2]) {
	switch(conn->options[KBF_IKEv2]) {
	case fo_never:
	    conn->policy &= ~(POLICY_IKEV2_ALLOW|POLICY_IKEV2_PROPOSE);
	    break;

	case fo_permit:
	    /* this is the default for now */
	    conn->policy |= POLICY_IKEV2_ALLOW;
	    break;

	case fo_propose:
	    conn->policy |= POLICY_IKEV2_ALLOW|POLICY_IKEV2_PROPOSE;
	    break;

	case fo_insist:
	    conn->policy |= POLICY_IKEV1_DISABLE;
	    conn->policy |= POLICY_IKEV2_ALLOW|POLICY_IKEV2_PROPOSE;
	    break;
	}
    }

    if(conn->options_set[KBF_SAREFTRACK]) {
	switch(conn->options[KBF_SAREFTRACK]) {
	case sat_yes:
	    /* this is the default */
	    conn->policy |= POLICY_SAREF_TRACK;
	    break;

	case sat_conntrack:
	    conn->policy |= POLICY_SAREF_TRACK|POLICY_SAREF_TRACK_CONNTRACK;
	    break;

	case sat_no:
	    conn->policy &= ~POLICY_SAREF_TRACK;
	    conn->policy &= ~POLICY_SAREF_TRACK_CONNTRACK;
	    break;
	}
    }

    if(conn->options_set[KBF_ENDADDRFAMILY]) {
        conn->end_addr_family = conn->options[KBF_ENDADDRFAMILY];
    }
    if(conn->options_set[KBF_CLIENTADDRFAMILY]) {
        conn->tunnel_addr_family = conn->options[KBF_CLIENTADDRFAMILY];
    }

    err += validate_end(conn, &conn->left,  TRUE,  resolvip, perr);
    err += validate_end(conn, &conn->right, FALSE, resolvip, perr);

    if(!defaultconn) {
        /*
         * At this point, the two ends should be sufficiently well declared that
         * one can verify if the two ends are using the same address family.
         * This is a bit more complex and just an ==, as one end may be unspecified.
         * In that case, it should adopt the family of the other end. If both
         * are unspecified, then this is an error, unless the conn already
         * has an end/tunnel family specified.
         */

        conn->end_addr_family = validate_family_consistency(conn->name, "end",
                                                            conn->left.end_addr_family,
                                                            conn->right.end_addr_family,
                                                            conn->end_addr_family);

        conn->tunnel_addr_family = validate_family_consistency(conn->name, "tunnel",
                                                            conn->left.tunnel_addr_family,
                                                            conn->right.tunnel_addr_family,
                                                            conn->tunnel_addr_family);
    }

    if(conn->options_set[KBF_AUTO]) {
	conn->desired_state = conn->options[KBF_AUTO];
    }

    return err;
}


void conn_default (char *n, struct starter_conn *conn,
		   struct starter_conn *def)
{
    int i;

    /* structure copy to start */
    *conn = *def;

    /* unlink it */
    memset(&conn->link, 0, sizeof(conn->link));

#define CONN_STR2(v,T) if (v) v=(T)clone_str((char *)v, #v)
#define CONN_STR(v) if (v) v=clone_str((char *)v, #v)
    CONN_STR(conn->left.iface);
    CONN_STR(conn->left.id);
    CONN_STR2(conn->left.rsakey1, unsigned char * );
    CONN_STR2(conn->left.rsakey2, unsigned char * );
    CONN_STR(conn->right.iface);
    CONN_STR(conn->right.id);
    CONN_STR2(conn->right.rsakey1, unsigned char *);
    CONN_STR2(conn->right.rsakey2, unsigned char *);

    for(i=0; i<KSCF_MAX; i++)
    {
	CONN_STR(conn->left.strings[i]);
	CONN_STR(conn->right.strings[i]);
    }
    for(i=0; i<KNCF_MAX; i++)
    {
	conn->left.options[i] = def->left.options[i];
	conn->right.options[i]= def->right.options[i];
    }
    for(i=0 ;i<KSF_MAX; i++)
    {
	CONN_STR(conn->strings[i]);
    }
    for(i=0 ;i<KBF_MAX; i++)
    {
	conn->options[i] = def->options[i];
    }

    CONN_STR(conn->esp);
    CONN_STR(conn->ike);
    CONN_STR(conn->policy_label);
    conn->policy = def->policy;
#undef CONN_STR
#undef CONN_STR2
}

struct starter_conn *alloc_add_conn(struct starter_config *cfg, char *name, err_t *perr)
{
    struct starter_conn *conn;

    conn = (struct starter_conn *)alloc_bytes(sizeof(struct starter_conn),"add_conn starter_conn");

    zero(conn);
    conn_default(name, conn, &cfg->conn_default);
    conn->name = clone_str(name, "conn name");
    conn->desired_state = STARTUP_NO;
    conn->state = STATE_FAILED;

    TAILQ_INIT(&conn->comments);

    TAILQ_INSERT_TAIL(&cfg->conns, conn, link);
    return conn;
}

int init_load_conn(struct starter_config *cfg
		   , struct config_parsed *cfgp
		   , struct section_list *sconn
		   , bool alsoprocessing
		   , bool defaultconn
		   , bool resolvip
		   , err_t *perr)
{
    int connerr;
    struct starter_conn *conn;
    starter_log(LOG_LEVEL_DEBUG, "Loading conn %s", sconn->name);

    conn = alloc_add_conn(cfg, sconn->name, perr);
    if(conn == NULL) {
	return -1;
    }

    connerr = load_conn (cfg, conn, cfgp, sconn, TRUE,
			 defaultconn, resolvip, perr);

    if(connerr != 0) {
	starter_log(LOG_LEVEL_INFO, "while loading '%s': %s\n",
		    sconn->name, *perr);
    }
    if(connerr == 0)
    {
	conn->state = STATE_LOADED;
    }
    return connerr;
}


struct starter_config *confread_load(const char *file
				     , err_t *perr
				     , bool resolvip
				     , char *ctlbase
				     , bool setuponly)
{
	struct starter_config *cfg = NULL;
	struct config_parsed *cfgp;
	struct section_list *sconn;
	unsigned int err = 0, connerr;

	/**
	 * Load file
	 */
	cfgp = parser_load_conf(file, perr);
	if (!cfgp) return NULL;

	cfg = (struct starter_config *)alloc_bytes(sizeof(struct starter_config),"starter_config cfg");

	zero(cfg);

	/**
	 * Set default values
	 */
	ipsecconf_default_values(cfg);

	if(ctlbase) {
	    pfree(cfg->ctlbase);
	    cfg->ctlbase = clone_str(ctlbase, "control socket");
	}
        starter_whack_init_cfg(cfg); /* set default sender to send to socket */

	/**
	 * Load setup
	 */
	err += load_setup(cfg, cfgp);

	if(err) {
		parser_free_conf(cfgp);
		confread_free(cfg);
		return NULL;
	}

	if(!setuponly) {
	   /**
	    * Find %default and %oedefault conn
	    *
	    */
	   for(sconn = cfgp->sections.tqh_first; (!err) && sconn != NULL; sconn = sconn->link.tqe_next)
	   {
		if (strcmp(sconn->name,"%default")==0) {
			starter_log(LOG_LEVEL_DEBUG, "Loading default conn");
			err += load_conn (cfg, &cfg->conn_default,
					  cfgp, sconn, FALSE,
					  /*default conn*/TRUE,
					  resolvip, perr);
		}

		if (strcmp(sconn->name,"%oedefault")==0) {
			starter_log(LOG_LEVEL_DEBUG, "Loading oedefault conn");
			err += load_conn (cfg, &cfg->conn_oedefault,
					  cfgp, sconn, FALSE,
					  /*default conn*/TRUE,
					  resolvip, perr);
			if(err == 0) {
			    cfg->got_oedefault=TRUE;
			}
		}
	   }

	   /**
	    * Load other conns
	    */
	   for(sconn = cfgp->sections.tqh_first; sconn != NULL; sconn = sconn->link.tqe_next)
	   {
		if (strcmp(sconn->name,"%default")==0) continue;
		if (strcmp(sconn->name,"%oedefault")==0) continue;

		connerr = init_load_conn(cfg, cfgp, sconn, TRUE, FALSE,
					 resolvip, perr);

		if(connerr == -1) {
		    parser_free_conf(cfgp);
		    confread_free(cfg);
		    return NULL;
		}
		err += connerr;
	   }

	   /* if we have OE on, then create any missing OE conns! */
	   if(cfg->setup.options[KBF_OPPOENCRYPT]) {
	       starter_log(LOG_LEVEL_DEBUG, "Enabling OE conns\n");
	       add_any_oeconns(cfg, cfgp);
	   }
	}

	parser_free_conf(cfgp);

	return cfg;
}

static void confread_free_conn(struct starter_conn *conn)
{
    int i;
    pfreeany(conn->left.iface);
    pfreeany(conn->left.id);
    pfreeany(conn->left.rsakey1);
    pfreeany(conn->left.rsakey2);
    pfreeany(conn->right.iface);
    pfreeany(conn->right.id);
    pfreeany(conn->right.rsakey1);
    pfreeany(conn->right.rsakey2);

    pfreeany(conn->left.rsakey1_ckaid);
    pfreeany(conn->left.rsakey2_ckaid);
    pfreeany(conn->right.rsakey1_ckaid);
    pfreeany(conn->right.rsakey2_ckaid);

    for(i=0; i<KSCF_MAX; i++) {
        pfreeany(conn->left.strings[i]);
        pfreeany(conn->right.strings[i]);
    }
    for(i=0 ;i<KSF_MAX; i++) {
        pfreeany(conn->strings[i]);
    }

    pfreeany(conn->connalias);
    pfreeany(conn->name);

    pfreeany(conn->esp);
    pfreeany(conn->ike);

#if 0
    pfreeany(conn->modecfg_dns1);
    pfreeany(conn->modecfg_dns2);
#endif

    pfreeany(conn->left.virt);
    pfreeany(conn->right.virt);
}

void confread_free(struct starter_config *cfg)
{
    int i;
    struct starter_conn *conn, *c;
    FREE_LIST(cfg->setup.interfaces);
    pfreeany(cfg->setup.virtual_private);
    pfreeany(cfg->setup.listen);
    for(i=0 ;i<KSF_MAX; i++) {
        pfreeany(cfg->setup.strings[i]);
    }
    confread_free_conn(&(cfg->conn_default));

    for(conn = cfg->conns.tqh_first; conn != NULL; ) {
        c = conn;
        conn = conn->link.tqe_next;
        confread_free_conn(c);
        pfree(c);
    }
    pfree(cfg);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
