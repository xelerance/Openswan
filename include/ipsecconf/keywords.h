/* Openswan config file parser (parser.h)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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

#ifndef _KEYWORDS_H_
#define _KEYWORDS_H_

#ifndef _OPENSWAN_H
#include "openswan.h"
#include "constants.h"
#endif
#include "sysqueue.h"


/*
 * these are global configuration parameters, and appear in
 * "config setup" stanza, and as non-left/right items in
 * the "conn foo" stanzas
 */
enum keyword_string_config_field {
    KSF_DPDACTION    = 0,  /* loose_enum evantually */
    KSF_INTERFACES,
    KSF_PREPLUTO,
    KSF_POSTPLUTO,
    /* KSF_PACKETDEFAULT = 5, */
    KSF_VIRTUALPRIVATE,
    KSF_SYSLOG,
    KSF_DUMPDIR,
    KSF_MANUALSTART,
    KSF_PLUTOLOAD,
    KSF_PLUTOSTART,
    KSF_MYID,
    KSF_PLUTO,
    KSF_PLUTOOPTS,
    KSF_PLUTOSTDERRLOG,
    KSF_PROTOSTACK,
    KSF_IKE,
    KSF_ESP,
    KSF_ALSO,
    KSF_ALSOFLIP,
    KSF_ACCELERATION,
    KSF_CONNALIAS,
    KSF_LISTEN,
    KSF_POLICY_LABEL,
    KSF_MODECFGDNS1,
    KSF_MODECFGDNS2,
    KSF_MODECFGDOMAIN,
    KSF_MODECFGBANNER,
    KSF_MAX
};

/* Numeric fields also include boolean fields */
/* and do not come in right/left variants */
enum keyword_numeric_config_field {
    KBF_DPDACTION        = 0,
    KBF_FAILURESHUNT = 1,
    KBF_TYPE         = 2,
    KBF_FRAGICMP,
    KBF_HIDETOS,
    KBF_UNIQUEIDS,
    KBF_PLUTOWAIT,
    KBF_PLUTOSTDERRLOGTIME,
    KBF_OVERRIDEMTU,
    KBF_CONNMTU,
    KBF_STRICTCRLPOLICY,
    KBF_NOCRSEND,
    KBF_NATTRAVERSAL,
    KBF_DISABLEPORTFLOATING,
    KBF_FORCE_KEEPALIVE,
    KBF_KEEPALIVE,
    KBF_PLUTORESTARTONCRASH,
    KBF_CRLCHECKINTERVAL,
    KBF_KLIPSDEBUG,
    KBF_PLUTODEBUG,
    KBF_NHELPERS,
    KBF_OPPOENCRYPT,
    KBF_DPDDELAY,
    KBF_DPDTIMEOUT,
    KBF_METRIC,
    KBF_PHASE2,
    KBF_AUTHBY,
    KBF_KEYEXCHANGE,
    KBF_AUTO,
    KBF_PFS,
    KBF_SHA2_TRUNCBUG,
    KBF_SALIFETIME,
    KBF_REKEY,
    KBF_REKEYMARGIN,
    KBF_REKEYFUZZ,
    KBF_COMPRESS,
    KBF_KEYINGTRIES,
    KBF_ARRIVALCHECK,
    KBF_IKELIFETIME,
    KBF_AGGRMODE,
    KBF_MODECONFIGPULL,
    KBF_FORCEENCAP,
    KBF_IKEv2,
    KBF_IKEv2_ALLOW_NARROWING,
    KBF_CONNADDRFAMILY,
    KBF_FORCEBUSY,
    KBF_OVERLAPIP,
    KBF_REMOTEPEERTYPE, /*Cisco interop: remote peer type*/
    KBF_NMCONFIGURED, /*Network Manager support*/
    KBF_LOOPBACK,
    KBF_LABELED_IPSEC,
    KBF_SAREFTRACK, /* saref tracking paramter for _updown */
    KBF_WARNIGNORE, /* to ignore obsoleted keywords */
    KBF_SECCTX, /*security context attribute value for labeled ipsec*/

    /* some keywords which are not yet valid for openswan */
    KBF_PLUTOFORK,
    KBF_NATIKEPORT,
    KBF_IKEPORT,
    KBF_NAT_KEEPALIVE,      /* per conn enabling/disabling of sending keep-alives */
    KBF_INITIAL_CONTACT,
    KBF_SEND_VENDORID,      /* per conn sending of our own libreswan vendorid */
    KBF_IKEV1_NATT,	    /* ikev1 NAT-T payloads to send/process */

    /* new ones here */
    KBF_ENDADDRFAMILY,

    KBF_MAX
};

/*
 * these are global configuration parameters, and appear in
 * normal conn sections, some of them come in left/right variants.
 *
 * NOTE: loose_enum values have both string and integer types,
 * and MUST have the same index for each.
 *
 * they come in left and right= variants.
 *
 */

enum keyword_string_conn_field {
    KSCF_IP           = 0,  /* loose_enum */
    KSCF_SUBNET       = 1,
    KSCF_NEXTHOP      = 2,  /* loose_enum */
    KSCF_UPDOWN       = 3,
    KSCF_ID           = 4,
    KSCF_RSAKEY1      = 5,  /* loose_enum */
    KSCF_RSAKEY2      = 6,  /* loose_enum */
    KSCF_CERT         = 7,
    KSCF_CA           = 8,
    KSCF_SUBNETWITHIN = 9,
    KSCF_PROTOPORT    = 10,
    KSCF_ESPENCKEY    = 13,
    KSCF_ESPAUTHKEY   = 14,
    KSCF_SOURCEIP     = 15,
    KSCF_XAUTHUSERNAME= 16,
    KSCF_SUBNETS      = 17,
    KSCF_MODECFGDNS1  = 18,
    KSCF_MODECFGDNS2  = 19,
    KSCF_MODECFGWINS1 = 20,
    KSCF_MODECFGWINS2 = 21,
    KSCF_MAX
};


enum keyword_numeric_conn_field {
    KNCF_IP               = 0,  /* loose_enum */
    KNCF_FIREWALL         = 1,
    KNCF_NEXTHOP          = 2,  /* loose_enum */
    KNCF_IDTYPE           = 3,
    KNCF_SPIBASE          = 4,
    KNCF_RSAKEY1          = 5,  /* loose_enum */
    KNCF_RSAKEY2          = 6,  /* loose_enum */
    KNCF_XAUTHSERVER      = 7,
    KNCF_XAUTHCLIENT      = 8,
    KNCF_MODECONFIGSERVER = 9,
    KNCF_MODECONFIGCLIENT = 10,
    KNCF_SPI,
    KNCF_ESPREPLAYWINDOW,
    KNCF_SENDCERT,
    KNCF_MAX
};

#define KEY_STRINGS_MAX ((int)KSF_MAX > (int)KSCF_MAX ? (int)KSF_MAX : (int)KSCF_MAX)+1
#define KEY_NUMERIC_MAX ((int)KBF_MAX > (int)KNCF_MAX ? (int)KBF_MAX : (int)KNCF_MAX)+1

/* these are bits set in a word */
enum keyword_valid {
    kv_config = LELEM(0),     /* may be present in config section */
    kv_conn   = LELEM(1),     /* may be present in conn section */
    kv_leftright = LELEM(2),  /* comes in leftFOO and rightFOO varients */
    kv_auto   = LELEM(3),     /* valid when keyingtype=auto */
    kv_manual = LELEM(4),     /* valid when keyingtype=manual */
    kv_alias  = LELEM(5),     /* is an alias for another keyword */
    kv_policy = LELEM(6),     /* is a policy affecting verb, processed specially */
    kv_processed = LELEM(7),  /* is processed, do not output literal string */
    kv_duplicateok = LELEM(8),  /* it is okay if also= items are duplicated */
    kv_obsolete    = LELEM(9),  /* option that is obsoleted, allow keyword but warn and ignore */

};
#define KV_CONTEXT_MASK (kv_config|kv_conn|kv_leftright)

/* values keyexchange= */
enum keyword_keyexchange {
    KE_NONE = 0,
    KE_IKE  = 1,
};

/* values for auto={add,start,route,ignore} */
enum keyword_auto {
    STARTUP_NO      = 0,
    STARTUP_POLICY  = 1,
    STARTUP_ADD     = 2,
    STARTUP_ROUTE   = 3,
    STARTUP_START   = 4
};

enum keyword_satype {
    KS_TUNNEL    = 0,
    KS_TRANSPORT = 1,
    KS_UDPENCAP  = 2,
    KS_PASSTHROUGH=3,
    KS_DROP      = 4,
    KS_REJECT    = 5,
};

enum keyword_type {
    kt_string,             /* value is some string */
    kt_appendstring,       /* value is some string, append duplicates */
    kt_appendlist,         /* value is some list, append duplicates */
    kt_filename,           /* value is a filename string */
    kt_dirname,            /* value is a dir name string */
    kt_bool,               /* value is an on/off type */
    kt_invertbool,         /* value is an off/on type ("disable") */
    kt_enum,               /* value is from a set of key words */
    kt_list,               /* a set of values from a set of key words */
    kt_loose_enum,         /* either a string, or a %-prefixed enum */
    kt_loose_enumarg,      /* either a string, or a %-prefixed enum w/option*/
    kt_rsakey,             /* a key, or set of values */
    kt_number,             /* an integer */
    kt_time,               /* a number representing time */
    kt_percent,            /* a number representing percentage */
    kt_ipaddr,             /* an IP address */
    kt_subnet,             /* an IP address subnet */
    kt_idtype,             /* an ID type */
    kt_bitstring,          /* an encryption/authentication key */
    kt_comment,            /* a value which is a cooked comment */
};

#define NOT_ENUM NULL

struct keyword_def {
    const char        *keyname;
    unsigned int       validity;       /* has bits kv_config or kv_conn set */
    enum keyword_type  type;
    unsigned int       field;          /* one of keyword_*_field */
    const struct keyword_enum_values *validenum;
    unsigned int       loose_enum_value;  /* what value to use if the for a literal type */
    char               deliminator;       /* for enum types, a deliminator */
};

struct keyword {
    struct keyword_def *keydef;
    bool                keyleft;
    char               *string;
};

struct kw_list {
    struct kw_list *next;
    struct keyword  keyword;
    /* char *string is buried in above keyword, because lexer returns "keyword" structures */
    double          decimal;
    unsigned int    number;
    char           *argument;
};

struct starter_comments {
    TAILQ_ENTRY(starter_comments) link;
    char *x_comment;
    char *commentvalue;
};

TAILQ_HEAD(starter_comments_list, starter_comments);

struct section_list {
    TAILQ_ENTRY(section_list) link;

    char *name;
    struct kw_list *kw;
    struct starter_comments_list comments;
    bool  beenhere;
};

struct config_parsed {
    struct kw_list *config_setup;

    TAILQ_HEAD(sectionhead, section_list) sections;
    int ipsec_conf_version;

    struct starter_comments_list comments;

    struct section_list conn_default;
    bool                got_default;
};

extern struct keyword_def ipsec_conf_keywords_v2[];
extern const int ipsec_conf_keywords_v2_count;

extern unsigned int parser_enum_list(struct keyword_def *kd, const char *s, bool list);
#define parser_loose_enum(X,Y) parser_loose_enum_arg(X,Y,NULL)
extern unsigned int parser_loose_enum_arg(struct keyword *k, const char *s,char **rest);


#endif /* _KEYWORDS_H_ */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
