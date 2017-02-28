/* command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2003  D. Hugh Redelmeier.
 * Copyright (C) 2004-2008 Michael Richardson <mcr@sandelman.ottawa.on.ca>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Shingo Yamawaki
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>

#include <openswan.h>

#include "sysdep.h"
#include "socketwrapper.h"
#include "constants.h"
#include "oswlog.h"

#include "pluto/defs.h"
#include "whack.h"

/**
 * Print the 'ipsec --whack help' message
 */
static void
help(void)
{
    fprintf(stderr
	, "Usage:\n\n"
	"all forms:"
	    " [--optionsfrom <filename>]"
	    " [--ctlbase <path>]"
	    " [--label <string>]"
	    "\n\n"
	"help: whack"
	    " [--help]"
	    " [--version]"
	    "\n\n"
	"connection: whack"
	    " --name <connection_name>"
	    " \\\n   "
	    " --connalias <alias_names>"
	    " \\\n   "
	    " [--ipv4 | --ipv6]"
	    " [--tunnelipv4 | --tunnelipv6]"
	    " \\\n   "
	    " (--host <ip-address> | --id <identity> | --cert <path>)"
	    " \\\n   "
	    " [--ca <distinguished name>]"
	    " \\\n   "
	    " [--nexthop <ip-address>]"
	    " [--client <subnet> | --clientwithin <address range>]"
	    " \\\n   "
	    " [--ikeport <port-number>]"
	    " [--srcip <ip-address>]"
	    " \\\n   "
	    " [--clientprotoport <protocol>/<port>]"
	    " [--dnskeyondemand]"
	    " \\\n   "
	    " [--updown <updown>]"
	    " \\\n   "
	    " (--host <ip-address> | --id <identity>)"
            " \\\n   "
            " [--groups <access control groups>]"
            " [--cert <path>]"
	    " [--ca <distinguished name>]"
	    " [--sendcert]"
	    " [--sendcerttype number]"
	    " \\\n   "
	    " [--ikeport <port-number>]"
	    " \\\n   "
	    " [--nexthop <ip-address>]"
	    " \\\n   "
	    " [--client <subnet> | --clientwithin <address range>]"
	    " \\\n   "
	    " [--clientprotoport <protocol>/<port>]"
	    " \\\n   "
	    " [--dnskeyondemand]"
	    " [--updown <updown>]"
	    " \\\n   "
	    " [--psk]"
	    " [--rsasig]"
	    " \\\n   "
	    " [--encrypt]"
	    " [--authenticate]"
	    " [--compress]"
	    " [--overlapip]"
	    " [--tunnel]"
	    " [--pfs]"
	    " \\\n   "
	    " [--pfsgroup [modp1024] | [modp1536] | [modp2048] | [modp3072] | [modp4096] | [modp6144] | [modp8192]]"
	    " \\\n   "
	    " [--ikelifetime <seconds>]"
	    " [--ipseclifetime <seconds>]"
	    " \\\n   "
	    " [--reykeymargin <seconds>]"
	    " [--reykeyfuzz <percentage>]"
	    " \\\n   "
	    " [--keyingtries <count>]"
	    " \\\n   "
	    " [--esp <esp-algos>]"
	    " \\\n   "
	    " [--remote_peer_type <cisco>]"
	    " \\\n   "
	    "[--nm_configured]"
	    " \\\n   "
	    " [--dontrekey]"
	    " [--aggrmode]"
	    " [--forceencaps]"
            " \\\n   "
            " [--dpddelay <seconds> --dpdtimeout <seconds>]"
            " [--dpdaction (clear|hold|restart|restart_by_peer)]"
            " \\\n   "

#ifdef XAUTH
	    " [--xauthserver]"
	    " [--xauthclient]"
#endif
#ifdef MODECFG
	    " [--modecfgserver]"
	    " [--modecfgclient]"
	    " [--modecfgpull]"
#ifdef MODECFG_DNSWINS
	    " [--modecfgdns1]"
	    " [--modecfgdns2]"
	    " [--modecfgwins1]"
	    " [--modecfgwins2]"
#endif
#endif
	    " \\\n   "
	    " [--metric <metric>]"
	    " \\\n   "
	    " [--initiateontraffic|--pass|--drop|--reject]"
	    " \\\n   "
	    " [--failnone|--failpass|--faildrop|--failreject]"
            " \\\n   "
	    " --to"
	    "\n\n"
	"routing: whack"
	    " (--route | --unroute)"
	    " --name <connection_name>"
	    "\n\n"
	"initiation:"
	    "\n "
	    " whack"
	    " (--initiate | --terminate)"
	    " --name <connection_name>"
	    " [--asynchronous]"
	    " [--xauthname name]"
	    " [--xauthpass pass]"
	    "\n\n"
	"opportunistic initiation: whack"
	    " [--tunnelipv4 | --tunnelipv6]"
	    " \\\n   "
	    " --oppohere <ip-address>"
	    " --oppothere <ip-address>"
	    "\n\n"
	"delete: whack"
	    " --delete"
	    " --name <connection_name>"
	    "\n\n"
	"deletestate: whack"
	    " --deletestate <state_object_number>"
            " --crash <ip-address>"
	    "\n\n"
	"pubkey: whack"
	    " --keyid <id>"
	    " [--addkey]"
	    " [--pubkeyrsa <key>]"
	    "\n\n"
	"myid: whack"
	    " --myid <id>"
	    "\n\n"
#ifdef DEBUG
	"debug: whack [--name <connection_name>]"
	    " \\\n   "
	    " [--debug-none]"
	    " [--debug-all]"
	    " \\\n   "
	    " [--debug-raw]"
	    " [--debug-crypt]"
	    " [--debug-parsing]"
	    " [--debug-emitting]"
	    " \\\n   "
	    " [--debug-control]"
	    " [--debug-controlmore]"
	    " [--debug-klips]"
	    " [--debug-netkey]"
	    " [--debug-dns]"
	    " [--debug-pfkey]"
	    " [--debug-dpd]"
	    " \\\n   "
	    " [--debug-natt]"
	    " [--debug-x509]"
	    " [--debug-oppo]"
	    " [--debug-oppoinfo]"
	    " \\\n   "
	    " [--debug-private]"
	    "\n\n"
	"testcases: [--whackrecord file] [--whackstoprecord]\n"
#endif
	"listen: whack"
	    " (--listen | --unlisten)"
	    "\n\n"
	"list: whack [--utc]"
	    " [--checkpubkeys]"
	    " [--listpubkeys]"
	    " [--listcerts]"
	    " [--listcacerts]"
            " \\\n   "
            " [--listacerts]"
            " [--listaacerts]"
            " [--listocspcerts]"
            " \\\n   "
            " [--listgroups]"
	    " [--listcrls]"
            " [--listocsp]"

            " [--listhostpairs]"
	    " [--listpsks]"
	    " [--listall]"
	    "\n\n"
        "purge: whack"
            " [--purgeocsp]"
            "\n\n"

        "events: whack"
            " [--listevents]"
            "\n\n"

        "lists: whack"
            " [--listhostpairs]"
            "\n\n"

	"reread: whack"
	    " [--rereadsecrets]"
	    " [--rereadcacerts]"
            " [--rereadaacerts]"
            " [--rereadocspcerts]"
            " \\\n   "
            " [--rereadacerts]"

	    " [--rereadcrls]"
	    " [--rereadall]"
	    "\n\n"
	"status: whack"
	    " --status"
	    "\n\n"
	"shutdown: whack"
	    " --shutdown"
	    "\n\n"
#ifdef TPM
        "taproom: whack"
	    " --tpmeval string"
	    "\n\n"
#endif
	"Openswan %s\n"
	, ipsec_version_code());
}

static const char *label = NULL;	/* --label operand, saved for diagnostics */

const char *progname = NULL;
static const char *name = NULL;	/* --name operand, saved for diagnostics */

/** Print a string as a diagnostic, then exit whack unhappily
 *
 * @param mess The error message to print when exiting
 * @return void
 */
static void
diag(const char *mess)
{
    if (mess != NULL)
    {
	fprintf(stderr, "whack error: ");
	if (label != NULL)
	    fprintf(stderr, "%s ", label);
	if (name != NULL)
	    fprintf(stderr, "\"%s\" ", name);
	fprintf(stderr, "%s\n", mess);
    }

    exit(RC_WHACK_PROBLEM);
}

/**
 * Conditially calls diag if ugh is set.
 * Prints second arg, if non-NULL, as quoted string
 *
 * @param ugh Error message
 * @param this Optional 2nd part of error message
 * @return void
 */
static void
diagq(err_t ugh, const char *this)
{
    if (ugh != NULL)
    {
	if (this == NULL)
	{
	    diag(ugh);
	}
	else
	{
	    char buf[120];	/* arbitrary limit */

	    snprintf(buf, sizeof(buf), "%s \"%s\"", ugh, this);
	    diag(buf);
	}
    }
}

/**
 * complex combined operands return one of these enumerated values
 * Note: these become flags in an lset_t.  Since there are more than
 * 32, we partition them into:
 * - OPT_* options (most random options)
 * - LST_* options (list various internal data)
 * - DBGOPT_* option (DEBUG options)
 * - END_* options (End description options)
 * - CD_* options (Connection Description options)
 */
enum option_enums {
#   define OPT_FIRST	OPT_CTLBASE
    OPT_CTLBASE,
    OPT_NAME,
    OPT_CONNALIAS,

    OPT_CD,

    OPT_KEYID,
    OPT_ADDKEY,
    OPT_PUBKEYRSA,

    OPT_MYID,

    OPT_ROUTE,
    OPT_UNROUTE,

    OPT_INITIATE,
    OPT_TERMINATE,
    OPT_DELETE,
    OPT_DELETESTATE,
    OPT_LISTEN,
    OPT_UNLISTEN,

    OPT_PURGEOCSP,

    OPT_REREADSECRETS,
    OPT_REREADCACERTS,
    OPT_REREADAACERTS,
    OPT_REREADOCSPCERTS,
    OPT_REREADACERTS,
    OPT_REREADCRLS,
    OPT_REREADALL,

    OPT_STATUS,
    OPT_SHUTDOWN,

    OPT_OPPO_HERE,
    OPT_OPPO_THERE,

#   define OPT_LAST1 OPT_OPPO_THERE  /* last "normal" option */

#define OPT_FIRST2  OPT_ASYNC

    OPT_ASYNC,

    OPT_DELETECRASH,
    OPT_XAUTHNAME,
    OPT_XAUTHPASS,
    OPT_TPMEVAL,
    OPT_WHACKRECORD,
    OPT_WHACKSTOPRECORD,

#define OPT_LAST2 OPT_WHACKSTOPRECORD /* last "normal" option */


/* List options */

#   define LST_FIRST LST_UTC   /* first list option */
    LST_UTC,
    LST_CHECKPUBKEYS,
    LST_PUBKEYS,
    LST_CERTS,
    LST_CACERTS,
    LST_ACERTS,
    LST_AACERTS,
    LST_OCSPCERTS,
    LST_GROUPS,
    LST_CRLS,
    LST_OCSP,
    LST_CARDS,
    LST_PSKS,
    LST_EVENTS,
    LST_HOSTPAIRS,
    LST_ALL,

#   define LST_LAST LST_ALL    /* last list option */


/* Connection End Description options */

#   define END_FIRST END_HOST	/* first end description */
    END_HOST,
    END_ID,
    END_CERT,
    END_CA,
    END_GROUPS,
    END_IKEPORT,
    END_NEXTHOP,
    END_CLIENT,
    END_CLIENTWITHIN,
    END_CLIENTPROTOPORT,
    END_DNSKEYONDEMAND,
    END_XAUTHNAME,
    END_XAUTHSERVER,
    END_XAUTHCLIENT,
    END_MODECFGCLIENT,
    END_MODECFGSERVER,
    END_SENDCERT,
    END_CERTTYPE,
    END_SRCIP,
    END_UPDOWN,
    END_TUNDEV,

#define END_LAST  END_TUNDEV	/* last end description*/

/* Connection Description options -- segregated */

#   define CD_FIRST CD_TO	/* first connection description */
    CD_TO,

#   define CD_POLICY_FIRST  CD_PSK
    CD_PSK,	/* same order as POLICY_* 0 */
    CD_RSASIG,	/* same order as POLICY_* 1 */
    CD_ENCRYPT,	/* same order as POLICY_* 2 */
    CD_AUTHENTICATE,	/* same order as POLICY_* 3 */
    CD_COMPRESS,	/* same order as POLICY_* 4 */
    CD_TUNNEL,	/* same order as POLICY_* 5 */
    CD_PFS,	/* same order as POLICY_* 6 */
    CD_DISABLEARRIVALCHECK,	/* same order as POLICY_* 7 */
    CD_SHUNT0,	/* same order as POLICY_* 8 */
    CD_SHUNT1,	/* same order as POLICY_* 9 */
    CD_FAIL0,	/* same order as POLICY_* 10 */
    CD_FAIL1,	/* same order as POLICY_* 11 */
    CD_DONT_REKEY,	/* same order as POLICY_* 12 */
    CD_OPP0,	        /* same order as POLICY_* 13 */
    CD_GROUP,           /* same order as POLICY_* 14 */
    CD_GROUPED,         /* same order as POLICY_* 15 */
    CD_UP,              /* same order as POLICY_* 16 */
    CD_DUMMY,           /* same order as POLICY_* 17 -- was XAUTH */
    CD_MODECFGPULL,     /* same order as POLICY_* 18 */
    CD_AGGRESSIVE,      /* same order as POLICY_* 19 */
    CD_PERHOST,      /* should we specialize the policy to the host? */
    CD_SUBHOST,      /* if the policy applies below the host level (TCP/UDP/SCTP ports) */
    CD_PERPROTO,     /* should we specialize the policy to the protocol? */
    CD_OVERLAPIP,    /* can two conns that have subnet=vhost: declare the same IP? */
    CD_MODECFGDNS1,
    CD_MODECFGDNS2,
    CD_MODECFGWINS1,
    CD_MODECFGWINS2,
    CD_METRIC,
    CD_CONNMTU,
    CD_TUNNELIPV4,
    CD_TUNNELIPV6,
    CD_CONNIPV4,
    CD_CONNIPV6,

    CD_IKELIFETIME,
    CD_IPSECLIFETIME,
    CD_RKMARGIN,
    CD_RKFUZZ,
    CD_KTRIES,
    CD_DPDDELAY,
    CD_DPDTIMEOUT,
    CD_DPDACTION,
    CD_FORCEENCAPS,
    CD_IKE,
    CD_PFSGROUP,
    CD_REMOTEPEERTYPE,
    CD_SHA2_TRUNCBUG,
    CD_NMCONFIGURED,
    CD_LOOPBACK,
    CD_LABELED_IPSEC,
    CD_POLICY_LABEL,
    CD_ESP
#   define CD_LAST CD_ESP	/* last connection description */

#ifdef DEBUG	/* must be last so others are less than 32 to fit in lset_t */
#   define DBGOPT_FIRST DBGOPT_NONE
    ,
    /* NOTE: these definitions must match DBG_* and IMPAIR_* in constants.h */
    DBGOPT_NONE,
    DBGOPT_ALL,

    DBGOPT_RAW,		/* same order as DBG_* */
    DBGOPT_CRYPT,	/* same order as DBG_* */
    DBGOPT_PARSING,	/* same order as DBG_* */
    DBGOPT_EMITTING,	/* same order as DBG_* */
    DBGOPT_CONTROL,	/* same order as DBG_* */
    DBGOPT_LIFECYCLE,	/* same order as DBG_* */
    DBGOPT_KLIPS,	/* same order as DBG_* */
    DBGOPT_DNS,		/* same order as DBG_* */
    DBGOPT_OPPO,	/* same order as DBG_* */
    DBGOPT_CONTROLMORE,	/* same order as DBG_* */
    DBGOPT_PFKEY,	/* same order as DBG_* */
    DBGOPT_NATT,        /* same order as DBG_* */
    DBGOPT_X509,        /* same order as DBG_* */
    DBGOPT_DPD,         /* same order as DBG_* */
    DBGOPT_OPPOINFO,
    DBGOPT_WHACKWATCH,
    DBGOPT_RES16,
    DBGOPT_RES17,
    DBGOPT_RES18,
    DBGOPT_RES19,

    DBGOPT_PRIVATE,	/* same order as DBG_* */

    DBGOPT_IMPAIR_DELAY_ADNS_KEY_ANSWER,	/* same order as IMPAIR_* */
    DBGOPT_IMPAIR_DELAY_ADNS_TXT_ANSWER,	/* same order as IMPAIR_* */
    DBGOPT_IMPAIR_BUST_MI2,	/* same order as IMPAIR_* */
    DBGOPT_IMPAIR_BUST_MR2,	/* same order as IMPAIR_* */
    DBGOPT_IMPAIR_SA_CREATION,  /* make all SA creation fail */
    DBGOPT_IMPAIR_DIE_ONINFO,   /* cause state to be deleted upon receipt of information payload */
    DBGOPT_IMPAIR_JACOB_TWO_TWO, /* cause pluto to send all messages twice */
    DBGOPT_IMPAIR_MAJOR_VERSION_BUMP, /* cause pluto to send IKE major version higher then we support */
    DBGOPT_IMPAIR_MINOR_VERSION_BUMP, /* cause pluto to send IKE minor version higher then we support */
    DBGOPT_IMPAIR_RETRANSMITS, /* cause pluto to never retransmit packets */
    DBGOPT_IMPAIR_SEND_BOGUS_ISAKMP_FLAG, /* cause pluto to never retransmit packets */

#   define DBGOPT_LAST DBGOPT_IMPAIR_SEND_BOGUS_ISAKMP_FLAG
#endif

};

/* Carve up space for result from getop_long.
 * Stupidly, the only result is an int.
 * Numeric arg is bit immediately left of basic value.
 *
 */
#define OPTION_OFFSET	256	/* to get out of the way of letter options */
#define NUMERIC_ARG (1 << 11)	/* expect a numeric argument */
#define AUX_SHIFT   12	/* amount to shift for aux information */

static const struct option long_opts[] = {
#   define OO	OPTION_OFFSET
    /* name, has_arg, flag, val */

    { "help", no_argument, NULL, 'h' },
    { "version", no_argument, NULL, 'v' },
    { "optionsfrom", required_argument, NULL, '+' },
    { "label", required_argument, NULL, 'l' },

    { "ctlbase", required_argument, NULL, OPT_CTLBASE + OO },
    { "name", required_argument, NULL, OPT_NAME + OO },
    { "connalias", required_argument, NULL, OPT_CONNALIAS + OO },

    { "keyid", required_argument, NULL, OPT_KEYID + OO },
    { "addkey", no_argument, NULL, OPT_ADDKEY + OO },
    { "pubkeyrsa", required_argument, NULL, OPT_PUBKEYRSA + OO },

    { "myid", required_argument, NULL, OPT_MYID + OO },

    { "route", no_argument, NULL, OPT_ROUTE + OO },
    { "unroute", no_argument, NULL, OPT_UNROUTE + OO },

    { "initiate", no_argument, NULL, OPT_INITIATE + OO },
    { "terminate", no_argument, NULL, OPT_TERMINATE + OO },
    { "delete", no_argument, NULL, OPT_DELETE + OO },
    { "deletestate", required_argument, NULL, OPT_DELETESTATE + OO + NUMERIC_ARG },
    { "crash", required_argument, NULL, OPT_DELETECRASH + OO },
    { "listen", no_argument, NULL, OPT_LISTEN + OO },
    { "unlisten", no_argument, NULL, OPT_UNLISTEN + OO },
    { "purgeocsp", no_argument, NULL, OPT_PURGEOCSP + OO },

    { "rereadsecrets", no_argument, NULL, OPT_REREADSECRETS + OO },
    { "rereadcacerts", no_argument, NULL, OPT_REREADCACERTS + OO },
    { "rereadaacerts", no_argument, NULL, OPT_REREADAACERTS + OO },
    { "rereadocspcerts", no_argument, NULL, OPT_REREADOCSPCERTS + OO },
    { "rereadacerts", no_argument, NULL, OPT_REREADACERTS + OO },

    { "rereadcrls", no_argument, NULL, OPT_REREADCRLS + OO },
    { "rereadall", no_argument, NULL, OPT_REREADALL + OO },
    { "status", no_argument, NULL, OPT_STATUS + OO },
    { "shutdown", no_argument, NULL, OPT_SHUTDOWN + OO },
    { "xauthname", required_argument, NULL, OPT_XAUTHNAME + OO },
    { "xauthuser", required_argument, NULL, OPT_XAUTHNAME + OO },
    { "xauthpass", required_argument, NULL, OPT_XAUTHPASS + OO },
    { "tpmeval",   required_argument, NULL, OPT_TPMEVAL   + OO },

    { "oppohere", required_argument, NULL, OPT_OPPO_HERE + OO },
    { "oppothere", required_argument, NULL, OPT_OPPO_THERE + OO },

    { "asynchronous", no_argument, NULL, OPT_ASYNC + OO },

    /* list options */

    { "utc", no_argument, NULL, LST_UTC + OO },
    { "checkpubkeys", no_argument, NULL, LST_CHECKPUBKEYS + OO },
    { "listpubkeys", no_argument, NULL, LST_PUBKEYS + OO },
    { "listcerts", no_argument, NULL, LST_CERTS + OO },
    { "listcacerts", no_argument, NULL, LST_CACERTS + OO },
    { "listacerts", no_argument, NULL, LST_ACERTS + OO },
    { "listaacerts", no_argument, NULL, LST_AACERTS + OO },
    { "listocspcerts", no_argument, NULL, LST_OCSPCERTS + OO },
    { "listgroups", no_argument, NULL, LST_GROUPS + OO },
    { "listcrls", no_argument, NULL, LST_CRLS + OO },
    { "listocsp", no_argument, NULL, LST_OCSP + OO },
    { "listpsks", no_argument, NULL, LST_PSKS + OO },
    { "listevents", no_argument, NULL, LST_EVENTS + OO },
    { "listpairs",     no_argument, NULL, LST_HOSTPAIRS + OO },
    { "listhostpairs", no_argument, NULL, LST_HOSTPAIRS + OO },
    { "listall", no_argument, NULL, LST_ALL + OO },


    /* options for an end description */

    { "host", required_argument, NULL, END_HOST + OO },
    { "id", required_argument, NULL, END_ID + OO },
    { "cert", required_argument, NULL, END_CERT + OO },
    { "ca", required_argument, NULL, END_CA + OO },
    { "groups", required_argument, NULL, END_GROUPS + OO },
    { "ikeport", required_argument, NULL, END_IKEPORT + OO + NUMERIC_ARG },
    { "nexthop", required_argument, NULL, END_NEXTHOP + OO },
    { "client", required_argument, NULL, END_CLIENT + OO },
    { "clientwithin", required_argument, NULL, END_CLIENTWITHIN + OO },
    { "clientprotoport", required_argument, NULL, END_CLIENTPROTOPORT + OO },
    { "dnskeyondemand", no_argument, NULL, END_DNSKEYONDEMAND + OO },
    { "srcip",  required_argument, NULL, END_SRCIP + OO },
    { "updown", required_argument, NULL, END_UPDOWN + OO },
    { "tundev", required_argument, NULL, END_TUNDEV + OO + NUMERIC_ARG },


    /* options for a connection description */

    { "to", no_argument, NULL, CD_TO + OO },

    { "psk", no_argument, NULL, CD_PSK + OO },
    { "rsasig", no_argument, NULL, CD_RSASIG + OO },

    { "encrypt", no_argument, NULL, CD_ENCRYPT + OO },
    { "authenticate", no_argument, NULL, CD_AUTHENTICATE + OO },
    { "compress",  no_argument, NULL, CD_COMPRESS + OO },
    { "overlapip", no_argument, NULL, CD_OVERLAPIP + OO },
    { "tunnel", no_argument, NULL, CD_TUNNEL + OO },
    { "tunnelipv4", no_argument, NULL, CD_TUNNELIPV4 + OO },
    { "tunnelipv6", no_argument, NULL, CD_TUNNELIPV6 + OO },
    { "pfs", no_argument, NULL, CD_PFS + OO },
    { "sha2_truncbug", no_argument, NULL, CD_SHA2_TRUNCBUG + OO },
    { "aggrmode", no_argument, NULL, CD_AGGRESSIVE + OO },
    { "disablearrivalcheck", no_argument, NULL, CD_DISABLEARRIVALCHECK + OO },
    { "initiateontraffic", no_argument, NULL
	, CD_SHUNT0 + (POLICY_SHUNT_TRAP >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
    { "pass", no_argument, NULL
	, CD_SHUNT0 + (POLICY_SHUNT_PASS >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
    { "drop", no_argument, NULL
	, CD_SHUNT0 + (POLICY_SHUNT_DROP >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
    { "reject", no_argument, NULL
	, CD_SHUNT0 + (POLICY_SHUNT_REJECT >> POLICY_SHUNT_SHIFT << AUX_SHIFT) + OO },
    { "failnone", no_argument, NULL
	, CD_FAIL0 + (POLICY_FAIL_NONE >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
    { "failpass", no_argument, NULL
	, CD_FAIL0 + (POLICY_FAIL_PASS >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
    { "faildrop", no_argument, NULL
	, CD_FAIL0 + (POLICY_FAIL_DROP >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
    { "failreject", no_argument, NULL
	, CD_FAIL0 + (POLICY_FAIL_REJECT >> POLICY_FAIL_SHIFT << AUX_SHIFT) + OO },
    { "dontrekey", no_argument, NULL, CD_DONT_REKEY + OO },
    { "forceencaps", no_argument, NULL, CD_FORCEENCAPS + OO },
    { "dpddelay", required_argument, NULL, CD_DPDDELAY + OO + NUMERIC_ARG },
    { "dpdtimeout", required_argument, NULL, CD_DPDTIMEOUT + OO + NUMERIC_ARG },
    { "dpdaction", required_argument, NULL, CD_DPDACTION + OO },
#ifdef XAUTH
    { "xauth", no_argument, NULL, END_XAUTHSERVER + OO },
    { "xauthserver", no_argument, NULL, END_XAUTHSERVER + OO },
    { "xauthclient", no_argument, NULL, END_XAUTHCLIENT + OO },
#endif
#ifdef MODECFG
    { "modecfgpull",   no_argument, NULL, CD_MODECFGPULL + OO },
    { "modecfgserver", no_argument, NULL, END_MODECFGSERVER + OO },
    { "modecfgclient", no_argument, NULL, END_MODECFGCLIENT + OO },
#ifdef MODECFG_DNSWINS
    { "modecfgdns1", required_argument, NULL, CD_MODECFGDNS1 + OO },
    { "modecfgdns2", required_argument, NULL, CD_MODECFGDNS2 + OO },
    { "modecfgwins1", required_argument, NULL, CD_MODECFGWINS1 + OO },
    { "modecfgwins2", required_argument, NULL, CD_MODECFGWINS2 + OO },
    { "modeconfigserver", no_argument, NULL, END_MODECFGSERVER + OO },
    { "modeconfigclient", no_argument, NULL, END_MODECFGCLIENT + OO },
#endif
#endif
    { "metric", required_argument, NULL, CD_METRIC + OO + NUMERIC_ARG },
    { "mtu", required_argument, NULL, CD_CONNMTU + OO + NUMERIC_ARG },
    { "sendcert", required_argument, NULL, END_SENDCERT + OO },
    { "certtype", required_argument, NULL, END_CERTTYPE + OO + NUMERIC_ARG },
    { "ipv4", no_argument, NULL, CD_CONNIPV4 + OO },
    { "ipv6", no_argument, NULL, CD_CONNIPV6 + OO },

    { "ikelifetime", required_argument, NULL, CD_IKELIFETIME + OO + NUMERIC_ARG },
    { "ipseclifetime", required_argument, NULL, CD_IPSECLIFETIME + OO + NUMERIC_ARG },
    { "rekeymargin", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG },
    { "rekeywindow", required_argument, NULL, CD_RKMARGIN + OO + NUMERIC_ARG },	/* OBSOLETE */
    { "rekeyfuzz", required_argument, NULL, CD_RKFUZZ + OO + NUMERIC_ARG },
    { "keyingtries", required_argument, NULL, CD_KTRIES + OO + NUMERIC_ARG },
    { "ike",    required_argument, NULL, CD_IKE + OO },
    { "ikealg", required_argument, NULL, CD_IKE + OO },
    { "pfsgroup", required_argument, NULL, CD_PFSGROUP + OO },
    { "esp", required_argument, NULL, CD_ESP + OO },
    { "remote_peer_type", required_argument, NULL, CD_REMOTEPEERTYPE + OO},
#ifdef HAVE_NM
    { "nm_configured", no_argument, NULL, CD_NMCONFIGURED + OO},
#endif
#ifdef HAVE_LABELED_IPSEC
    { "loopback", no_argument, NULL, CD_LOOPBACK + OO},
    { "labeledipsec", no_argument, NULL, CD_LABELED_IPSEC + OO},
    { "policylabel", required_argument, NULL, CD_POLICY_LABEL + OO },
#endif
#ifdef DEBUG
    { "debug-none", no_argument, NULL, DBGOPT_NONE + OO },
    { "debug-all", no_argument, NULL, DBGOPT_ALL + OO },
    { "debug-raw", no_argument, NULL, DBGOPT_RAW + OO },
    { "debug-crypt", no_argument, NULL, DBGOPT_CRYPT + OO },
    { "debug-parsing", no_argument, NULL, DBGOPT_PARSING + OO },
    { "debug-emitting", no_argument, NULL, DBGOPT_EMITTING + OO },
    { "debug-control", no_argument, NULL, DBGOPT_CONTROL + OO },
    { "debug-lifecycle", no_argument, NULL, DBGOPT_LIFECYCLE + OO },
    { "debug-klips",  no_argument, NULL, DBGOPT_KLIPS + OO },
    { "debug-netkey", no_argument, NULL, DBGOPT_KLIPS + OO },
    { "debug-xfrm",   no_argument, NULL, DBGOPT_KLIPS + OO },
    { "debug-dns", no_argument, NULL, DBGOPT_DNS + OO },
    { "debug-oppo", no_argument, NULL, DBGOPT_OPPO + OO },
    { "debug-oppoinfo", no_argument, NULL, DBGOPT_OPPOINFO + OO },
    { "debug-whackwatch",  no_argument, NULL, DBGOPT_WHACKWATCH + OO },
    { "debug-controlmore", no_argument, NULL, DBGOPT_CONTROLMORE + OO },
    { "debug-pfkey",   no_argument, NULL, DBGOPT_PFKEY + OO },
    { "debug-nattraversal", no_argument, NULL, DBGOPT_NATT + OO },
    { "debug-natt",    no_argument, NULL, DBGOPT_NATT + OO },
    { "debug-nat_t",   no_argument, NULL, DBGOPT_NATT + OO },
    { "debug-nat-t",   no_argument, NULL, DBGOPT_NATT + OO },
    { "debug-x509",    no_argument, NULL, DBGOPT_X509 + OO },
    { "debug-dpd",     no_argument, NULL, DBGOPT_DPD + OO },
    { "debug-private", no_argument, NULL, DBGOPT_PRIVATE + OO },

    { "impair-delay-adns-key-answer", no_argument, NULL, DBGOPT_IMPAIR_DELAY_ADNS_KEY_ANSWER + OO },
    { "impair-delay-adns-txt-answer", no_argument, NULL, DBGOPT_IMPAIR_DELAY_ADNS_TXT_ANSWER + OO },
    { "impair-bust-mi2", no_argument, NULL, DBGOPT_IMPAIR_BUST_MI2 + OO },
    { "impair-bust-mr2", no_argument, NULL, DBGOPT_IMPAIR_BUST_MR2 + OO },
    { "impair-sa-fail",    no_argument, NULL, DBGOPT_IMPAIR_SA_CREATION + OO },
    { "impair-die-oninfo", no_argument, NULL, DBGOPT_IMPAIR_DIE_ONINFO  + OO },
    { "impair-jacob-two-two", no_argument, NULL, DBGOPT_IMPAIR_JACOB_TWO_TWO + OO },
    { "impair-major-version-bump", no_argument, NULL, DBGOPT_IMPAIR_MAJOR_VERSION_BUMP + OO },
    { "impair-minor-version-bump", no_argument, NULL, DBGOPT_IMPAIR_MINOR_VERSION_BUMP + OO },
    { "impair-retransmits", no_argument, NULL, DBGOPT_IMPAIR_RETRANSMITS + OO },
    { "impair-send-bogus-isakmp-flag", no_argument, NULL, DBGOPT_IMPAIR_SEND_BOGUS_ISAKMP_FLAG + OO },
    { "whackrecord",     required_argument, NULL, OPT_WHACKRECORD + OO},
    { "whackstoprecord", no_argument, NULL, OPT_WHACKSTOPRECORD + OO},
#endif
#   undef OO
    { 0,0,0,0 }
};

struct sockaddr_un ctl_addr = {
    .sun_family = AF_UNIX,
    .sun_path   = DEFAULT_CTLBASE CTL_SUFFIX,
#if defined(HAS_SUN_LEN)
    .sun_len = sizeof(struct sockaddr_un),
#endif
};


static void
check_life_time(time_t life, time_t limit, const char *which
, const struct whack_message *msg)
{
    time_t mint = msg->sa_rekey_margin * (100 + msg->sa_rekey_fuzz) / 100;

    if (life > limit)
    {
	char buf[200];	/* arbitrary limit */

	snprintf(buf, sizeof(buf)
	    , "%s [%lu seconds] must be less than %lu seconds"
	    , which, (unsigned long)life, (unsigned long)limit);
	diag(buf);
    }
    if ((msg->policy & POLICY_DONT_REKEY) == LEMPTY && life <= mint)
    {
	char buf[200];	/* arbitrary limit */

	snprintf(buf, sizeof(buf)
	    , "%s [%lu] must be greater than"
	    " rekeymargin*(100+rekeyfuzz)/100 [%lu*(100+%lu)/100 = %lu]"
	    , which
	    , (unsigned long)life
	    , (unsigned long)msg->sa_rekey_margin
	    , (unsigned long)msg->sa_rekey_fuzz
	    , (unsigned long)mint);
	diag(buf);
    }
}

static void
update_ports(struct whack_message * m)
{
    int port;

    if (m->left.port != 0) {
        port = htons(m->left.port);
        setportof(port, &m->left.host_addr);
        setportof(port, &m->left.client.addr);
    }
    if (m->right.port != 0) {
        port = htons(m->right.port);
        setportof(port, &m->right.host_addr);
        setportof(port, &m->right.client.addr);
    }
}

static void
check_end(struct whack_end *this, struct whack_end *that
, bool default_nexthop, sa_family_t caf, sa_family_t taf)
{
    if (caf != addrtypeof(&this->host_addr))
	diag("address family of host inconsistent");

    if (default_nexthop)
    {
	if (isanyaddr(&that->host_addr))
	    diag("our nexthop must be specified when other host is a %any or %opportunistic");
	this->host_nexthop = that->host_addr;
    }

    if (caf != addrtypeof(&this->host_nexthop))
	diag("address family of nexthop inconsistent");

    if (this->has_client)
    {
	if (taf != subnettypeof(&this->client))
	    diag("address family of client subnet inconsistent");
    }
    else
    {
	/* fill in anyaddr-anyaddr as (missing) client subnet */
	ip_address cn;

	diagq(anyaddr(caf, &cn), NULL);
	diagq(rangetosubnet(&cn, &cn, &this->client), NULL);
    }

    /* check protocol */
    if (this->protocol != that->protocol)
	diagq("the protocol for leftprotoport and rightprotoport must be the same", NULL);
}

static void
send_reply(int sock, char *buf, ssize_t len)
{
    /* send the secret to pluto */
    if (write(sock, buf, len) != len)
    {
	int e = errno;

	fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(e));
	exit(RC_WHACK_PROBLEM);
    }
}

/* This is a hack for initiating ISAKMP exchanges. */

int
main(int argc, char **argv)
{
    struct whack_message msg;
    struct whackpacker wp;
    char esp_buf[256];	/* uses snprintf */
    lset_t
        opts_seen = LEMPTY,
        opts2_seen = LEMPTY,
        lst_seen = LEMPTY,
        cd_seen = LEMPTY,
        end_seen = LEMPTY,
        end_seen_before_to = LEMPTY;
    const char
	*af_used_by = NULL,
	*tunnel_af_used_by = NULL;

    char xauthname[128];
    char xauthpass[128];
    int xauthnamelen = 0, xauthpasslen = 0;
    bool gotxauthname = FALSE, gotxauthpass = FALSE;
    const char *ugh;

    progname = argv[0];

    /* check division of numbering space */
#ifdef DEBUG
    assert(OPTION_OFFSET + DBGOPT_LAST < NUMERIC_ARG);
#else
    assert(OPTION_OFFSET + CD_LAST < NUMERIC_ARG);
#endif
    assert(OPT_LAST1- OPT_FIRST < (sizeof opts_seen * BITS_PER_BYTE)-1);
    assert(OPT_LAST2- OPT_FIRST2< (sizeof opts2_seen * BITS_PER_BYTE)-1);
    assert(LST_LAST - LST_FIRST < (sizeof lst_seen * BITS_PER_BYTE)-1);
    assert(END_LAST - END_FIRST < (sizeof end_seen * BITS_PER_BYTE)-1);
    assert(CD_LAST - CD_FIRST < (sizeof cd_seen * BITS_PER_BYTE));
#ifdef DEBUG	/* must be last so others are less than (sizeof cd_seen * BITS_PER_BYTE) to fit in lset_t */
    assert(DBGOPT_LAST - DBGOPT_FIRST < (sizeof cd_seen * BITS_PER_BYTE));
#endif
    /* check that POLICY bit assignment matches with CD_ */
    assert(LELEM(CD_DONT_REKEY - CD_POLICY_FIRST) == POLICY_DONT_REKEY);

    zero(&msg);

    clear_end(&msg.right);	/* left set from this after --to */

    msg.name = NULL;
#ifdef DYNAMICDNS
    msg.dnshostname = NULL;
#endif /* DYNAMICDNS */

    msg.keyid = NULL;
    msg.keyval.ptr = NULL;
    msg.esp = NULL;
    msg.ike = NULL;
    msg.pfsgroup = NULL;

    msg.remotepeertype = NON_CISCO;
    msg.sha2_truncbug  = FALSE;

    /*Network Manager support*/
    msg.nmconfigured   = FALSE;

    msg.loopback = FALSE;
    msg.labeled_ipsec = FALSE;
    msg.policy_label = NULL;

    msg.sa_ike_life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;
    msg.sa_ipsec_life_seconds = PLUTO_SA_LIFE_DURATION_DEFAULT;
    msg.sa_rekey_margin = SA_REPLACEMENT_MARGIN_DEFAULT;
    msg.sa_rekey_fuzz = SA_REPLACEMENT_FUZZ_DEFAULT;
    msg.sa_keying_tries = SA_REPLACEMENT_RETRIES_DEFAULT;

    msg.end_addr_family = AF_INET;
    msg.tunnel_addr_family = AF_INET;

    for (;;)
    {
	int long_index;
	unsigned long opt_whole=0;	/* numeric argument for some flags */

	/* Note: we don't like the way short options get parsed
	 * by getopt_long, so we simply pass an empty string as
	 * the list.  It could be "hp:d:c:o:eatfs" "NARXPECK".
	 */
	volatile int c = getopt_long(argc, argv, "", long_opts, &long_index) - OPTION_OFFSET;
	int aux = 0;

	/* decode a numeric argument, if expected */
	if (0 <= c)
	{
	    if (c & NUMERIC_ARG)
	    {
		char *endptr;

		c -= NUMERIC_ARG;
		opt_whole = strtoul(optarg, &endptr, 0);

		if (*endptr != '\0' || endptr == optarg)
		    diagq("badly formed numeric argument", optarg);
	    }
	    if (c >= (1 << AUX_SHIFT))
	    {
		aux = c >> AUX_SHIFT;
		c -= aux << AUX_SHIFT;
	    }
	}

	/* per-class option processing */
	if (0 <= c && c <= OPT_LAST1)
	{
	    /* OPT_* options get added opts_seen.
	     * Reject repeated options (unless later code intervenes).
	     */
	    lset_t f = LELEM(c);

	    if (opts_seen & f)
		diagq("duplicated flag", long_opts[long_index].name);
	    opts_seen |= f;
	}
	else if (OPT_FIRST2 <= c && c <= OPT_LAST2)
	{
	    /* OPT_* options get added opts_seen2.
	     * Reject repeated options (unless later code intervenes).
	     */
	    lset_t f = LELEM(c);

	    if (opts2_seen & f)
		diagq("duplicated flag", long_opts[long_index].name);
	    opts2_seen |= f;
	}
        else if (LST_FIRST <= c && c <= LST_LAST)
        {
            /* LST_* options get added lst_seen.
             * Reject repeated options (unless later code intervenes).
             */
            lset_t f = LELEM(c - LST_FIRST);

            if (lst_seen & f)
                diagq("duplicated flag", long_opts[long_index].name);
            lst_seen |= f;
        }
#ifdef DEBUG
	else if (DBGOPT_FIRST <= c && c <= DBGOPT_LAST)
	{
	    /* DBGOPT_* options are treated separately to reduce
	     * potential members of opts_seen.
	     */
	    msg.whack_options = TRUE;
	}
#endif
	else if (END_FIRST <= c && c <= END_LAST)
	{
	    /* END_* options are added to end_seen.
	     * Reject repeated options (unless later code intervenes).
	     */
	    lset_t f = LELEM(c - END_FIRST);

	    if (end_seen & f)
		diagq("duplicated flag", long_opts[long_index].name);
	    end_seen |= f;
	    opts_seen |= LELEM(OPT_CD);
	}
	else if (CD_FIRST <= c && c <= CD_LAST)
	{
	    /* CD_* options are added to cd_seen.
	     * Reject repeated options (unless later code intervenes).
	     */
	    lset_t f = LELEM(c - CD_FIRST);

	    if (cd_seen & f)
		diagq("duplicated flag", long_opts[long_index].name);
	    cd_seen |= f;
	    opts_seen |= LELEM(OPT_CD);
	}

	/* Note: "break"ing from switch terminates loop.
	 * most cases should end with "continue".
	 */
	switch (c)
	{
	case EOF - OPTION_OFFSET:	/* end of flags */
	    break;

	case 0 - OPTION_OFFSET: /* long option already handled */
	    continue;

	case ':' - OPTION_OFFSET:	/* diagnostic already printed by getopt_long */
	case '?' - OPTION_OFFSET:	/* diagnostic already printed by getopt_long */
	    diag(NULL);	/* print no additional diagnostic, but exit sadly */
	    break;	/* not actually reached */

	case 'h' - OPTION_OFFSET:	/* --help */
	    help();
	    return 0;	/* GNU coding standards say to stop here */

	case 'v' - OPTION_OFFSET:	/* --version */
	    {
		printf("%s\n", ipsec_version_string());
	    }
	    return 0;	/* GNU coding standards say to stop here */

	case 'l' - OPTION_OFFSET:	/* --label <string> */
	    label = optarg;	/* remember for diagnostics */
	    continue;

	case '+' - OPTION_OFFSET:	/* --optionsfrom <filename> */
	    optionsfrom(optarg, &argc, &argv, optind, stderr);
	    /* does not return on error */
	    continue;

	/* the rest of the options combine in complex ways */

	case OPT_CTLBASE:	/* --port <ctlbase> */
	    if (snprintf(ctl_addr.sun_path, sizeof(ctl_addr.sun_path)
	    , "%s%s", optarg, CTL_SUFFIX) == -1)
		diag("<ctlbase>" CTL_SUFFIX " must be fit in a sun_addr");
	    continue;

	case OPT_NAME:	/* --name <connection-name> */
	    name = optarg;
	    msg.name = optarg;
	    continue;

	case OPT_KEYID:	/* --keyid <identity> */
	    msg.whack_key = TRUE;
	    msg.keyid = optarg;	/* decoded by Pluto */
	    continue;

	case OPT_MYID:	/* --myid <identity> */
	    msg.whack_myid = TRUE;
	    msg.myid = optarg;	/* decoded by Pluto */
	    continue;

	case OPT_ADDKEY:	/* --addkey */
	    msg.whack_addkey = TRUE;
	    continue;

	case OPT_PUBKEYRSA:	/* --pubkeyrsa <key> */
	    {
		static char keyspace[RSA_MAX_ENCODING_BYTES];
		char mydiag_space[TTODATAV_BUF];
		ugh = ttodatav(optarg, 0, 0
		    , keyspace, sizeof(keyspace)
		    , &msg.keyval.len, mydiag_space, sizeof(mydiag_space)
		    , TTODATAV_SPACECOUNTS);

		if (ugh != NULL)
		{
		    char ugh_space[80];	/* perhaps enough space */

		    snprintf(ugh_space, sizeof(ugh_space)
			, "RSA public-key data malformed (%s)", ugh);
		    diagq(ugh_space, optarg);
		}
		msg.pubkey_alg = PUBKEY_ALG_RSA;
		msg.keyval.ptr = (unsigned char *)keyspace;
	    }
	    continue;

	case OPT_ROUTE:	/* --route */
	    msg.whack_route = TRUE;
	    continue;

	case OPT_UNROUTE:	/* --unroute */
	    msg.whack_unroute = TRUE;
	    continue;

	case OPT_INITIATE:	/* --initiate */
	    msg.whack_initiate = TRUE;
	    continue;

	case OPT_TERMINATE:	/* --terminate */
	    msg.whack_terminate = TRUE;
	    continue;

	case OPT_DELETE:	/* --delete */
	    msg.whack_delete = TRUE;
	    continue;

	case OPT_DELETESTATE:	/* --deletestate <state_object_number> */
	    msg.whack_deletestate = TRUE;
	    msg.whack_deletestateno = opt_whole;
	    continue;

	case OPT_DELETECRASH:   /* --crash <ip-address> */
	    msg.whack_crash = TRUE;
	    diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family, &msg.whack_crash_peer), optarg);
	    if (isanyaddr(&msg.whack_crash_peer))
		diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
	    continue;

	case OPT_LISTEN:	/* --listen */
	    msg.whack_listen = TRUE;
	    continue;

	case OPT_UNLISTEN:	/* --unlisten */
	    msg.whack_unlisten = TRUE;
	    continue;

        case OPT_PURGEOCSP:     /* --purgeocsp */
            msg.whack_purgeocsp = TRUE;
            continue;

        case OPT_REREADSECRETS:   /* --rereadsecrets */
        case OPT_REREADCACERTS:   /* --rereadcacerts */
        case OPT_REREADAACERTS:   /* --rereadaacerts */
        case OPT_REREADOCSPCERTS: /* --rereadocspcerts */
        case OPT_REREADACERTS:    /* --rereadacerts */
        case OPT_REREADCRLS:      /* --rereadcrls */
	    msg.whack_reread |= LELEM(c-OPT_REREADSECRETS);
	    continue;

	case OPT_REREADALL:	/* --rereadall */
	    msg.whack_reread = REREAD_ALL;
	    continue;

	case OPT_STATUS:	/* --status */
	    msg.whack_status = TRUE;
	    continue;

	case OPT_SHUTDOWN:	/* --shutdown */
	    msg.whack_shutdown = TRUE;
	    continue;

	case OPT_OPPO_HERE:	/* --oppohere <ip-address> */
	    tunnel_af_used_by = long_opts[long_index].name;
	    diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family, &msg.oppo_my_client), optarg);
	    if (isanyaddr(&msg.oppo_my_client))
		diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
	    continue;

	case OPT_OPPO_THERE:	/* --oppohere <ip-address> */
	    tunnel_af_used_by = long_opts[long_index].name;
	    diagq(ttoaddr(optarg, 0, msg.tunnel_addr_family, &msg.oppo_peer_client), optarg);
	    if (isanyaddr(&msg.oppo_peer_client))
		diagq("0.0.0.0 or 0::0 isn't a valid client address", optarg);
	    continue;

	case OPT_ASYNC:
	    msg.whack_async = TRUE;
	    continue;

        /* List options */

         case LST_UTC:          /* --utc */
            msg.whack_utc = TRUE;
             continue;

        case LST_PUBKEYS:       /* --listpubkeys */
        case LST_CERTS:         /* --listcerts */
        case LST_CACERTS:       /* --listcacerts */
        case LST_ACERTS:        /* --listacerts */
        case LST_AACERTS:       /* --listaacerts */
        case LST_OCSPCERTS:     /* --listocspcerts */
        case LST_GROUPS:        /* --listgroups */
        case LST_CRLS:          /* --listcrls */
        case LST_OCSP:          /* --listocsp */
        case LST_PSKS:          /* --listpsks */
        case LST_EVENTS:        /* --listevents */
        case LST_HOSTPAIRS:     /* --listhostpairs */
            msg.whack_list |= LELEM(c - LST_PUBKEYS);
            continue;

	case LST_CHECKPUBKEYS:   /* --checkpubkeys */
	    msg.whack_list |= LELEM(LST_PUBKEYS - LST_PUBKEYS);
	    msg.whack_check_pub_keys = TRUE;
	    continue;

        case LST_ALL:   /* --listall */
            msg.whack_list = LIST_ALL;
            continue;

	/* Connection Description options */

	case END_HOST:	/* --host <ip-address> */
	{
	    lset_t new_policy = LEMPTY;

	    af_used_by = long_opts[long_index].name;
	    diagq(anyaddr(msg.end_addr_family, &msg.right.host_addr), optarg);
	    if (streq(optarg, "%any"))
	    {
	    }
	    else if (streq(optarg, "%opportunistic"))
	    {
		/* always use tunnel mode; mark as opportunistic */
		new_policy |= POLICY_TUNNEL | POLICY_OPPO;
	    }
	    else if (streq(optarg, "%group"))
	    {
		/* always use tunnel mode; mark as group */
		new_policy |= POLICY_TUNNEL | POLICY_GROUP;
	    }
	    else if (streq(optarg, "%opportunisticgroup"))
	    {
		/* always use tunnel mode; mark as opportunistic */
		new_policy |= POLICY_TUNNEL | POLICY_OPPO | POLICY_GROUP;
	    }
	    else
	    {
		diagq(ttoaddr(optarg, 0, msg.end_addr_family
		    , &msg.right.host_addr), optarg);
	    }

	    msg.policy |= new_policy;

	    if (new_policy & (POLICY_OPPO | POLICY_GROUP))
	    {
		if (!LHAS(end_seen, END_CLIENT - END_FIRST))
		{
		    /* set host to 0.0.0 and --client to 0.0.0.0/0
		     * or IPV6 equivalent
		     */
		    ip_address any;

		    tunnel_af_used_by = optarg;
		    diagq(anyaddr(msg.tunnel_addr_family, &any), optarg);
		    diagq(initsubnet(&any, 0, '0', &msg.right.client), optarg);
		}
		msg.right.has_client = TRUE;
	    }
	    if (new_policy & POLICY_GROUP)
	    {
		/* client subnet must not be specified by user:
		 * it will come from the group's file.
		 */
		if (LHAS(end_seen, END_CLIENT - END_FIRST))
		    diag("--host %group clashes with --client");

		end_seen |= LELEM(END_CLIENT - END_FIRST);
	    }
	    if (new_policy & POLICY_OPPO)
		msg.right.key_from_DNS_on_demand = TRUE;
	    continue;
	}

	case END_ID:	/* --id <identity> */
	    msg.right.id = optarg;	/* decoded by Pluto */
	    continue;

	case END_SENDCERT:
   	    if(streq(optarg, "yes") || streq(optarg, "always"))
	    {
		msg.right.sendcert = cert_alwayssend;
	    }
	    else if(streq(optarg, "no") || streq(optarg, "never"))
	    {
		msg.right.sendcert = cert_neversend;
	    }
	    else if(streq(optarg, "ifasked"))
	    {
		msg.right.sendcert = cert_sendifasked;
	    }
	    else if(streq(optarg, "forced"))
	    {
		msg.right.sendcert = cert_forcedtype;
	    }
	    else
	    {
		diagq("whack sendcert value is not legal", optarg);
		continue;
	    }
	    continue;

	case END_CERTTYPE:
	    msg.right.certtype = opt_whole;
	    continue;

	case END_CERT:	/* --cert <path> */
	    msg.right.cert = optarg;	/* decoded by Pluto */
	    continue;

	case END_CA:	/* --ca <distinguished name> */
	    msg.right.ca = optarg;	/* decoded by Pluto */
	    continue;

        case END_GROUPS:/* --groups <access control groups> */
            msg.right.groups = optarg;  /* decoded by Pluto */
            continue;


	case END_IKEPORT:	/* --ikeport <port-number> */
	    if (opt_whole<=0 || opt_whole >= 0x10000)
		diagq("<port-number> must be a number between 1 and 65535", optarg);
	    msg.right.host_port = opt_whole;
	    continue;

	case END_NEXTHOP:	/* --nexthop <ip-address> */
	    af_used_by = long_opts[long_index].name;
	    if (streq(optarg, "%direct"))
		diagq(anyaddr(msg.end_addr_family
		    , &msg.right.host_nexthop), optarg);
	    else
		diagq(ttoaddr(optarg, 0, msg.end_addr_family
		    , &msg.right.host_nexthop), optarg);
	    continue;

	case END_SRCIP:	       /* --srcip <ip-address> */
	    af_used_by = long_opts[long_index].name;
	    diagq(ttoaddr(optarg, 0, msg.end_addr_family
			  , &msg.right.host_srcip), optarg);
	    continue;

	case END_CLIENT:	/* --client <subnet> */
	    if (end_seen & LELEM(END_CLIENTWITHIN - END_FIRST))
		diag("--client conflicts with --clientwithin");
	    tunnel_af_used_by = long_opts[long_index].name;
	    if ( ((strlen(optarg)>=6) && (strncmp(optarg,"vhost:",6)==0)) ||
		((strlen(optarg)>=5) && (strncmp(optarg,"vnet:",5)==0)) ) {
		msg.right.virt = optarg;
	    }
	    else {
		diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
		msg.right.has_client = TRUE;
	    }
	    msg.policy |= POLICY_TUNNEL;	/* client => tunnel */
	    continue;

	case END_CLIENTWITHIN:	/* --clienwithin <address range> */
	    if (end_seen & LELEM(END_CLIENT - END_FIRST))
		diag("--clientwithin conflicts with --client");
	    tunnel_af_used_by = long_opts[long_index].name;
	    diagq(ttosubnet(optarg, 0, msg.tunnel_addr_family, &msg.right.client), optarg);
	    msg.right.has_client = TRUE;
	    msg.right.has_client_wildcard = TRUE;
	    continue;

	case END_CLIENTPROTOPORT: /* --clientprotoport <protocol>/<port> */
	    diagq(ttoprotoport(optarg, 0, &msg.right.protocol, &msg.right.port
	    	, &msg.right.has_port_wildcard), optarg);
	    continue;

	case END_DNSKEYONDEMAND:	/* --dnskeyondemand */
	    msg.right.key_from_DNS_on_demand = TRUE;
	    continue;

	case END_UPDOWN:	/* --updown <updown> */
	    msg.right.updown = optarg;
	    continue;

	case END_TUNDEV:	/* --tundev <mast#> */
	    msg.right.tundev = opt_whole;
	    continue;

	case CD_TO:		/* --to */
	    /* process right end, move it to left, reset it */
	    if (!LHAS(end_seen, END_HOST - END_FIRST))
		diag("connection missing --host before --to");
	    msg.left = msg.right;
	    clear_end(&msg.right);
	    end_seen_before_to = end_seen;
	    end_seen = LEMPTY;
	    continue;

	case CD_PSK:		/* --psk */
	case CD_RSASIG:		/* --rsasig */
	case CD_ENCRYPT:	/* --encrypt */
	case CD_AUTHENTICATE:	/* --authenticate */
	case CD_COMPRESS:	/* --compress */
	case CD_OVERLAPIP:	/* --overlapip */
	case CD_TUNNEL:		/* --tunnel */
	case CD_PFS:		/* --pfs */
	case CD_AGGRESSIVE:	/* --aggrmode */
	case CD_DISABLEARRIVALCHECK:	/* --disablearrivalcheck */
	case CD_DONT_REKEY:	/* --donotrekey */
	case CD_MODECFGPULL:    /* --modecfgpull */
	    msg.policy |= LELEM(c - CD_POLICY_FIRST);
	    continue;

	/* --initiateontraffic
	 * --pass
	 * --drop
	 * --reject
	 */
	case CD_SHUNT0:
	    msg.policy = (msg.policy & ~POLICY_SHUNT_MASK)
		| ((lset_t)aux << POLICY_SHUNT_SHIFT);
	    continue;

	/* --failnone
	 * --failpass
	 * --faildrop
	 * --failreject
	 */
	case CD_FAIL0:
	    msg.policy = (msg.policy & ~POLICY_FAIL_MASK)
		| ((lset_t)aux << POLICY_FAIL_SHIFT);
	    continue;

	case CD_IKELIFETIME:    /* --ikelifetime <seconds> */
	    msg.sa_ike_life_seconds = opt_whole;
	    continue;

	case CD_IPSECLIFETIME:	/* --ipseclifetime <seconds> */
	    msg.sa_ipsec_life_seconds = opt_whole;
	    continue;

	case CD_RKMARGIN:	/* --rekeymargin <seconds> */
	    msg.sa_rekey_margin = opt_whole;
	    continue;

	case CD_RKFUZZ:	/* --rekeyfuzz <percentage> */
	    msg.sa_rekey_fuzz = opt_whole;
	    continue;

	case CD_KTRIES:	/* --keyingtries <count> */
	    msg.sa_keying_tries = opt_whole;
	    continue;

	case CD_FORCEENCAPS:
            msg.forceencaps = TRUE;
            continue;

        case CD_DPDDELAY:
            msg.dpd_delay = opt_whole;
            continue;

        case CD_DPDTIMEOUT:
            msg.dpd_timeout = opt_whole;
            continue;

        case CD_DPDACTION:
            msg.dpd_action = 255;
            if( strcmp(optarg, "clear") == 0) {
                    msg.dpd_action = DPD_ACTION_CLEAR;
            }
            if( strcmp(optarg, "hold") == 0) {
                    msg.dpd_action = DPD_ACTION_HOLD;
            }
            if( strcmp(optarg, "restart") == 0) {
                    msg.dpd_action = DPD_ACTION_RESTART;
            }
            if( strcmp(optarg, "restart_by_peer") == 0) {
                    msg.dpd_action = DPD_ACTION_RESTART_BY_PEER;
            }
            continue;

	case CD_IKE:	/* --ike <ike_alg1,ike_alg2,...> */
	    msg.ike = optarg;
	    continue;

	case CD_PFSGROUP:	/* --pfsgroup modpXXXX */
	    msg.pfsgroup = optarg;
	    continue;

	case CD_ESP:	/* --esp <esp_alg1,esp_alg2,...> */
	    msg.esp = optarg;
	    continue;

	case CD_REMOTEPEERTYPE: /* --remote_peer_type  <cisco> */
	    if ( strcmp(optarg, "cisco" ) == 0) {
		msg.remotepeertype = CISCO;
	    }
	    else {
		msg.remotepeertype = NON_CISCO;
	    }
	    continue;

	case CD_SHA2_TRUNCBUG: /* --sha2_truncbug */
	    if ( strcmp(optarg, "yes" ) == 0) {
		msg.sha2_truncbug = TRUE;
	    }
	    else {
		msg.sha2_truncbug = FALSE;
	    }
            continue;

#ifdef HAVE_NM
	case CD_NMCONFIGURED: /* --nm_configured */
	    if ( strcmp(optarg, "yes" ) == 0) {
		msg.nmconfigured = TRUE;
	    }
	    else {
		msg.nmconfigured = FALSE;
	    }
		continue;
#endif

#ifdef HAVE_LABELED_IPSEC
	case CD_LOOPBACK:
		msg.loopback = LB_YES;
		continue;

        case CD_LABELED_IPSEC:
                msg.labeled_ipsec = LI_YES;
                continue;

        case CD_POLICY_LABEL:
                msg.policy_label = optarg;
                continue;
#endif

	case CD_CONNIPV4:
	    if (LHAS(cd_seen, CD_CONNIPV6 - CD_FIRST))
		diag("--ipv4 conflicts with --ipv6");

	    /* Since this is the default, the flag is redundant.
	     * So we don't need to set msg.addr_family
	     * and we don't need to check af_used_by
	     * and we don't have to consider defaulting tunnel_addr_family.
	     */
	    continue;

	case CD_CONNIPV6:
	    if (LHAS(cd_seen, CD_CONNIPV4 - CD_FIRST))
		diag("--ipv6 conflicts with --ipv4");

	    if (af_used_by != NULL)
		diagq("--ipv6 must precede", af_used_by);

	    af_used_by = long_opts[long_index].name;
	    msg.end_addr_family = AF_INET6;

	    /* Consider defaulting tunnel_addr_family to AF_INET6.
	     * Do so only if it hasn't yet been specified or used.
	     */
	    if (LDISJOINT(cd_seen, LELEM(CD_TUNNELIPV4 - CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST))
	    && tunnel_af_used_by == NULL)
		msg.tunnel_addr_family = AF_INET6;
	    continue;

	case CD_TUNNELIPV4:
	    if (LHAS(cd_seen, CD_TUNNELIPV6 - CD_FIRST))
		diag("--tunnelipv4 conflicts with --tunnelipv6");

	    if (tunnel_af_used_by != NULL)
		diagq("--tunnelipv4 must precede", af_used_by);

	    msg.tunnel_addr_family = AF_INET;
	    continue;

	case CD_TUNNELIPV6:
	    if (LHAS(cd_seen, CD_TUNNELIPV4 - CD_FIRST))
		diag("--tunnelipv6 conflicts with --tunnelipv4");

	    if (tunnel_af_used_by != NULL)
		diagq("--tunnelipv6 must precede", af_used_by);

	    msg.tunnel_addr_family = AF_INET6;
	    continue;

#ifdef XAUTH
	case END_XAUTHSERVER:	/* --xauthserver */
	    msg.right.xauth_server = TRUE;
	    continue;

	case END_XAUTHCLIENT:	/* --xauthclient */
	    msg.right.xauth_client = TRUE;
	    continue;

	case OPT_XAUTHNAME:
	    /* we can't tell if this is going to be --initiate, or
	     * if this is going to be an conn definition, so do
	     * both actions */
	    msg.right.xauth_name = optarg;
	    gotxauthname = TRUE;
	    xauthname[0]='\0';
	    strncat(xauthname, optarg, sizeof(xauthname) - strlen(xauthname)-1);
	    xauthnamelen = strlen(xauthname)+1;
	    continue;

	case OPT_XAUTHPASS:
	  gotxauthpass = TRUE;
	  xauthpass[0]='\0';
	  strncat(xauthpass, optarg, sizeof(xauthpass) - strlen(xauthpass)-1);
	  xauthpasslen = strlen(xauthpass)+1;
	  continue;

#ifdef MODECFG
	case END_MODECFGCLIENT:
	    msg.right.modecfg_client = TRUE;
	    continue;

	case END_MODECFGSERVER:
	    msg.right.modecfg_server = TRUE;
	    continue;

#ifdef MODECFG_DNSWINS
	case CD_MODECFGDNS1:
	   af_used_by = long_opts[long_index].name;
	   diagq(ttoaddr(optarg, 0, msg.addr_family
		, &msg.modecfg_dns1), optarg);
	   continue;

	case CD_MODECFGDNS2:
	   af_used_by = long_opts[long_index].name;
	   diagq(ttoaddr(optarg, 0, msg.addr_family
		, &msg.modecfg_dns2), optarg);
	   continue;

	case CD_MODECFGWINS1:
	   af_used_by = long_opts[long_index].name;
	   diagq(ttoaddr(optarg, 0, msg.addr_family
		, &msg.modecfg_wins1), optarg);
	   continue;

	case CD_MODECFGWINS2:
	   af_used_by = long_opts[long_index].name;
	   diagq(ttoaddr(optarg, 0, msg.addr_family
		, &msg.modecfg_wins2), optarg);
	   continue;
#endif
#endif /* MODECFG */

#else
	case END_XAUTHSERVER:
	case END_XAUTHCLIENT:
	case END_XAUTHNAME:
	  diag("pluto is not built with XAUTH support");
	  continue;
#endif /* XAUTH */

	case CD_METRIC:
	    msg.metric = opt_whole;
	    continue;

	case CD_CONNMTU:
	    msg.connmtu = opt_whole;
	    continue;

	case OPT_TPMEVAL:
#ifdef TPM
	    msg.tpmeval = strdup(optarg);
	    msg.whack_reread |= REREAD_TPMEVAL;
	    printf("sending tpmeval: '%s'\n", msg.tpmeval);

#else
	    diag("TaProoM is not enabled in this build");
#endif
	    continue;

#ifdef DEBUG
	case OPT_WHACKRECORD:
	    msg.string1 = strdup(optarg);
	    msg.whack_options = TRUE;
	    msg.opt_set = WHACK_STARTWHACKRECORD;
	    break;

	case OPT_WHACKSTOPRECORD:
	    msg.whack_options = TRUE;
	    msg.opt_set = WHACK_STOPWHACKRECORD;
	    break;
#endif

#ifdef DEBUG
	case DBGOPT_NONE:	/* --debug-none */
	    msg.debugging = DBG_NONE;
	    continue;

	case DBGOPT_ALL:	/* --debug-all */
	    msg.debugging |= DBG_ALL;	/* note: does not include PRIVATE */
	    continue;

	case DBGOPT_RAW:	/* --debug-raw */
	case DBGOPT_CRYPT:	/* --debug-crypt */
	case DBGOPT_PARSING:	/* --debug-parsing */
	case DBGOPT_EMITTING:	/* --debug-emitting */
	case DBGOPT_CONTROL:	/* --debug-control */
	case DBGOPT_LIFECYCLE:	/* --debug-lifecycle */
	case DBGOPT_KLIPS:	/* --debug-klips */
	case DBGOPT_DNS:	/* --debug-dns */
	case DBGOPT_OPPO:	/* --debug-oppo */
	case DBGOPT_CONTROLMORE: /* --debug-controlmore */
	case DBGOPT_PFKEY:      /* --debug-pfkey */
	case DBGOPT_NATT:       /* --debug-pfkey */
	case DBGOPT_X509:       /* --debug-pfkey */
	case DBGOPT_DPD:        /* --debug-dpd */
	case DBGOPT_OPPOINFO:	/* --debug-oppoinfo */
	case DBGOPT_WHACKWATCH:	/* --debug-whackwatch */
	case DBGOPT_PRIVATE:	/* --debug-private */
	case DBGOPT_IMPAIR_DELAY_ADNS_KEY_ANSWER:	/* --impair-delay-adns-key-answer */
	case DBGOPT_IMPAIR_DELAY_ADNS_TXT_ANSWER:	/* --impair-delay-adns-txt-answer */
	case DBGOPT_IMPAIR_BUST_MI2:	/* --impair_bust_mi2 */
	case DBGOPT_IMPAIR_BUST_MR2:	/* --impair_bust_mr2 */
	case DBGOPT_IMPAIR_SA_CREATION:	/* --impair-sa-creation */
	case DBGOPT_IMPAIR_DIE_ONINFO:	/* --impair-die-oninfo */
	case DBGOPT_IMPAIR_JACOB_TWO_TWO: /* --impair-jacob-two-two */
	case DBGOPT_IMPAIR_MAJOR_VERSION_BUMP: /* --impair-major-version-bump */
	case DBGOPT_IMPAIR_MINOR_VERSION_BUMP: /* --impair-minor-version-bump */
	case DBGOPT_IMPAIR_RETRANSMITS: /* --impair-retransmits */
	case DBGOPT_IMPAIR_SEND_BOGUS_ISAKMP_FLAG: /* --impair-send-bogus-isakmp-flag */
	    msg.debugging |= LELEM(c-DBGOPT_RAW);
	    continue;
#endif
	default:
	    assert(FALSE);	/* unknown return value */
	}
	break;
    }

    if (optind != argc)
    {
	/* If you see this message unexpectedly, perhaps the
	 * case for the previous option ended with "break"
	 * instead of "continue"
	 */
	diagq("unexpected argument", argv[optind]);
    }

    /* For each possible form of the command, figure out if an argument
     * suggests whether that form was intended, and if so, whether all
     * required information was supplied.
     */

    /* check opportunistic initiation simulation request */
    switch (opts_seen & (LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE)))
    {
    case LELEM(OPT_OPPO_HERE):
    case LELEM(OPT_OPPO_THERE):
	diag("--oppohere and --oppothere must be used together");
	/*NOTREACHED*/
    case LELEM(OPT_OPPO_HERE) | LELEM(OPT_OPPO_THERE):
	msg.whack_oppo_initiate = TRUE;
	if (LIN(cd_seen, LELEM(CD_TUNNELIPV4 - CD_FIRST) | LELEM(CD_TUNNELIPV6 - CD_FIRST)))
	    opts_seen &= ~LELEM(OPT_CD);
	break;
    }

    /* check connection description */
    if (LHAS(opts_seen, OPT_CD))
    {
	if (!LHAS(cd_seen, CD_TO-CD_FIRST))
	    diag("connection description option, but no --to");

	if (!LHAS(end_seen, END_HOST-END_FIRST))
	    diag("connection missing --host after --to");

	if (isanyaddr(&msg.left.host_addr)
	&& isanyaddr(&msg.right.host_addr))
	    diag("hosts cannot both be 0.0.0.0 or 0::0");

	if (msg.policy & POLICY_OPPO)
	{
	    if ((msg.policy & (POLICY_PSK | POLICY_RSASIG)) != POLICY_RSASIG)
		diag("only RSASIG is supported for opportunism");
	    if ((msg.policy & POLICY_PFS) == 0)
		diag("PFS required for opportunism");
	    if ((msg.policy & POLICY_ENCRYPT) == 0)
		diag("encryption required for opportunism");
	}

	check_end(&msg.left, &msg.right, !LHAS(end_seen_before_to, END_NEXTHOP-END_FIRST)
	    , msg.end_addr_family, msg.tunnel_addr_family);

	check_end(&msg.right, &msg.left, !LHAS(end_seen, END_NEXTHOP-END_FIRST)
	    , msg.end_addr_family, msg.tunnel_addr_family);

	if (subnettypeof(&msg.left.client) != subnettypeof(&msg.right.client))
	    diag("endpoints clash: one is IPv4 and the other is IPv6");

	if (NEVER_NEGOTIATE(msg.policy))
	{
	    /* we think this is just a shunt (because he didn't specify
	     * a host authentication method).  If he didn't specify a
	     * shunt type, he's probably gotten it wrong.
	     */
	    if ((msg.policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP)
		diag("non-shunt connection must have --psk or --rsasig or both");
	}
	else
	{
	    /* not just a shunt: a real ipsec connection */
	    if ((msg.policy & POLICY_ID_AUTH_MASK) == LEMPTY)
		diag("must specify --rsasig or --psk for a connection");

	    if (!HAS_IPSEC_POLICY(msg.policy)
	    && (msg.left.has_client || msg.right.has_client))
		diag("must not specify clients for ISAKMP-only connection");
	}

	msg.whack_connection = TRUE;
    }

    /* decide whether --name is mandatory or forbidden */
    if (!LDISJOINT(opts_seen
    , LELEM(OPT_ROUTE) | LELEM(OPT_UNROUTE)
    | LELEM(OPT_INITIATE) | LELEM(OPT_TERMINATE)
    | LELEM(OPT_DELETE) | LELEM(OPT_CD)))
    {
	if (!LHAS(opts_seen, OPT_NAME))
	    diag("missing --name <connection_name>");
    }
    else if (!msg.whack_options)
    {
	if (LHAS(opts_seen, OPT_NAME))
	    diag("no reason for --name");
    }

    if (!LDISJOINT(opts_seen, LELEM(OPT_PUBKEYRSA) | LELEM(OPT_ADDKEY)))
    {
	if (!LHAS(opts_seen, OPT_KEYID))
	    diag("--addkey and --pubkeyrsa require --keyid");
    }

    if (!(msg.whack_connection || msg.whack_key || msg.whack_myid
	  || msg.whack_delete || msg.whack_deletestate
	  || msg.whack_initiate || msg.whack_oppo_initiate
	  || msg.whack_terminate
	  || msg.whack_route || msg.whack_unroute || msg.whack_listen
	  || msg.whack_unlisten || msg.whack_list || msg.whack_purgeocsp
	  || msg.whack_reread || msg.whack_crash
	  || msg.whack_status || msg.whack_options || msg.whack_shutdown))
    {
	diag("no action specified; try --help for hints");
    }

    if(msg.policy & POLICY_AGGRESSIVE) {
	if(msg.ike == NULL) {
	    diag("can not specify aggressive mode without ike= to set algorithm");
	}
    }

    update_ports(&msg);

    /* tricky quick and dirty check for wild values */
    if (msg.sa_rekey_margin != 0
    && msg.sa_rekey_fuzz * msg.sa_rekey_margin * 4 / msg.sa_rekey_margin / 4
     != msg.sa_rekey_fuzz)
	diag("rekeymargin or rekeyfuzz values are so large that they cause oveflow");

    check_life_time (msg.sa_ike_life_seconds, OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM
	, "ikelifetime", &msg);

    check_life_time(msg.sa_ipsec_life_seconds, SA_LIFE_DURATION_MAXIMUM
	, "ipseclifetime", &msg);

    if(msg.dpd_delay && !msg.dpd_timeout)
            diag("dpddelay specified, but dpdtimeout is zero, both should be specified");
    if(!msg.dpd_delay && msg.dpd_timeout)
            diag("dpdtimeout specified, but dpddelay is zero, both should be specified");
    if(msg.dpd_action != DPD_ACTION_CLEAR && msg.dpd_action != DPD_ACTION_HOLD
         && msg.dpd_action != DPD_ACTION_RESTART && msg.dpd_action != DPD_ACTION_RESTART_BY_PEER) {
            diag("dpdaction can only be \"clear\", \"hold\", \"restart\" or \"restart_by_peer\", defaulting to \"hold\"");
            msg.dpd_action = DPD_ACTION_HOLD;
    }

    if (msg.remotepeertype != CISCO && msg.remotepeertype != NON_CISCO) {
            diag("remote_peer_type can only be \"CISCO\" or \"NON_CISCO\" - defaulting to non-cisco mode");
            msg.remotepeertype = NON_CISCO; /*NON_CISCO=0*/
    }

    /* pack strings for inclusion in message */
    wp.msg = &msg;

    /* build esp message as esp="<esp>;<pfsgroup>" */
    if (msg.pfsgroup) {
	    snprintf(esp_buf, sizeof (esp_buf), "%s;%s",
		    msg.esp ? msg.esp : "",
		    msg.pfsgroup ? msg.pfsgroup : "");
	    msg.esp=esp_buf;
    }
    ugh = pack_whack_msg(&wp);
    if (ugh)
	diag(ugh);

    msg.magic = ((opts_seen & ~(LELEM(OPT_SHUTDOWN) | LELEM(OPT_STATUS)))
		| opts2_seen | lst_seen | cd_seen) != LEMPTY
	    || msg.whack_options
	? WHACK_MAGIC : WHACK_BASIC_MAGIC;

    /* send message to Pluto */
    if (access(ctl_addr.sun_path, R_OK | W_OK) < 0)
    {
	int e = errno;

	switch (e)
	{
	case EACCES:
	    fprintf(stderr, "whack: no right to communicate with pluto (access(\"%s\"))\n"
		, ctl_addr.sun_path);
	    break;
	case ENOENT:
	    fprintf(stderr, "whack: Pluto is not running (no \"%s\")\n"
		, ctl_addr.sun_path);
	    break;
	default:
	    fprintf(stderr, "whack: access(\"%s\") failed with %d %s\n"
		, ctl_addr.sun_path, errno, strerror(e));
	    break;
	}
	exit(RC_WHACK_PROBLEM);
    }
    else
    {
	int sock = safe_socket(AF_UNIX, SOCK_STREAM, 0);
	int exit_status = 0;
	ssize_t len = wp.str_next - (unsigned char *)&msg;

	if (sock == -1)
	{
	    int e = errno;

	    fprintf(stderr, "whack: socket() failed (%d %s)\n", e, strerror(e));
	    exit(RC_WHACK_PROBLEM);
	}

	if (connect(sock, (struct sockaddr *)&ctl_addr
	, offsetof(struct sockaddr_un, sun_path) + strlen(ctl_addr.sun_path)) < 0)
	{
	    int e = errno;

	    fprintf(stderr, "whack:%s connect() for \"%s\" failed (%d %s)\n"
		, e == ECONNREFUSED? " is Pluto running? " : ""
		, ctl_addr.sun_path, e, strerror(e));
	    exit(RC_WHACK_PROBLEM);
	}

	if (write(sock, &msg, len) != len)
	{
	    int e = errno;

	    fprintf(stderr, "whack: write() failed (%d %s)\n", e, strerror(e));
	    exit(RC_WHACK_PROBLEM);
	}

	/* for now, just copy reply back to stdout */

	{
	    char buf[4097];	/* arbitrary limit on log line length */
	    char *be = buf;

	    for (;;)
	    {
		char *ls = buf;
		ssize_t rl = read(sock, be, (buf + sizeof(buf)-1) - be);

		if (rl < 0)
		{
		    int e = errno;

		    fprintf(stderr, "whack: read() failed (%d %s)\n", e, strerror(e));
		    exit(RC_WHACK_PROBLEM);
		}
		if (rl == 0)
		{
		    if (be != buf)
			fprintf(stderr, "whack: last line from pluto too long or unterminated\n");
		    break;
		}

		be += rl;
		*be = '\0';

		for (;;)
		{
		    char *le = strchr(ls, '\n');

		    if (le == NULL)
		    {
			/* move last, partial line to start of buffer */
			memmove(buf, ls, be-ls);
			be -= ls - buf;
			break;
		    }

		    le++;	/* include NL in line */
		    if(write(STDOUT_FILENO, ls, le - ls) != (le-ls)) {
			int e = errno;
			fprintf(stderr, "whack: write() failed to stdout(%d %s)\n", e, strerror(e));
		    }

		    /* figure out prefix number
		     * and how it should affect our exit status
		     */
		    {
			unsigned long s = strtoul(ls, NULL, 10);

			switch (s)
			{
			case RC_COMMENT:
			case RC_LOG:
			    /* ignore */
			    break;
			case RC_SUCCESS:
			    /* be happy */
			    exit_status = 0;
			    break;

			case RC_ENTERSECRET:
			    if(!gotxauthpass)
			    {
				xauthpasslen = whack_get_secret(xauthpass
							  , sizeof(xauthpass));
			    }
			    send_reply(sock, xauthpass, xauthpasslen);
			    break;

			case RC_XAUTHPROMPT:
			    if(!gotxauthname)
			    {
				xauthnamelen = whack_get_value(xauthname
							 , sizeof(xauthname));
			    }
			    send_reply(sock, xauthname, xauthnamelen);
			    break;

			/* case RC_LOG_SERIOUS: */
			default:
			    if( msg.whack_async )
				exit_status=0;
			    else
				exit_status = s;
			    break;
			}
		    }
		    ls = le;
		}
	    }
	}
	return exit_status;
    }
}

void exit_tool(int val)
{
  exit(val);
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
