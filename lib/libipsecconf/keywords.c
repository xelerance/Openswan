/*
 * Openswan config file parser (keywords.c)
 * Copyright (C) 2003-2006,2015 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
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

#include <sys/queue.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#ifndef _OPENSWAN_H
#include <openswan.h>
#include "constants.h"
#endif

#include "ipsecconf/parser.h"
#include "ipsecconf/keywords.h"
#include "parser.tab.h"
#include "ipsecconf/parserlast.h"

#define VALUES_INITIALIZER(t)	{ t, sizeof(t)/ sizeof(t[0]) }
#undef KEYWORD_PARSE_DEBUG

#ifdef KEYWORD_PARSE_DEBUG
/*
 * values for keyword types  (used for debugging)
 */
static const struct keyword_enum_value kt_values[]={
    KEV_LITERAL(kt_string),
    KEV_LITERAL(kt_appendstring),
    KEV_LITERAL(kt_appendlist),
    KEV_LITERAL(kt_filename),
    KEV_LITERAL(kt_dirname),
    KEV_LITERAL(kt_bool),
    KEV_LITERAL(kt_invertbool),
    KEV_LITERAL(kt_enum),
    KEV_LITERAL(kt_list),
    KEV_LITERAL(kt_loose_enum),
    KEV_LITERAL(kt_rsakey),
    KEV_LITERAL(kt_number),
    KEV_LITERAL(kt_time),
    KEV_LITERAL(kt_percent),
    KEV_LITERAL(kt_ipaddr),
    KEV_LITERAL(kt_subnet),
    KEV_LITERAL(kt_idtype),
    KEV_LITERAL(kt_bitstring),
    KEV_LITERAL(kt_comment),
};
static const struct keyword_enum_values kt_values_list = VALUES_INITIALIZER(kt_values);
#endif

/*
 * Values for failureshunt={passthrough, drop, reject, none}
 */
static const struct keyword_enum_value kw_failureshunt_values[]={
    { "none",        POLICY_FAIL_NONE },
    { "passthrough", POLICY_FAIL_PASS },
    { "drop",        POLICY_FAIL_DROP },
    { "reject",      POLICY_FAIL_REJECT },
};

static const struct keyword_enum_values kw_failureshunt_list = VALUES_INITIALIZER(kw_failureshunt_values);

/*
 * Values for keyexchange=
 */
static const struct keyword_enum_value kw_keyexchange_values[]={
    { "ike",  KE_IKE },
    { "ikev1",  KE_IKEv1 },
    { "isakmp", KE_IKEv1 },
    { "oakley", KE_IKEv1 },
    { "ikev2",  KE_IKEv2 },
    { "rfc7296",KE_IKEv2 },
};

static const struct keyword_enum_values kw_keyexchange_list = VALUES_INITIALIZER(kw_keyexchange_values);

/*
 * Values for Four-State options, such as ikev2
 */
static const struct keyword_enum_value kw_fourvalued_values[]={
    { "never",     fo_never  },
    { "permit",    fo_permit },
    { "propose",   fo_propose},
    { "insist",    fo_insist },
    { "yes",       fo_propose},
    { "always",    fo_insist },
    { "no",        fo_never  }
};

static const struct keyword_enum_values kw_fourvalued_list = VALUES_INITIALIZER(kw_fourvalued_values);

#if 0
/* No longer used */
/*
 * Values for yes/no/force, used by ike_frag
 */
static const struct keyword_enum_value kw_ynf_values[] = {
	{ "never",     ynf_no },
	{ "no",        ynf_no },
	{ "yes",       ynf_yes },
	{ "insist",     ynf_force },
	{ "force",     ynf_force },
};
static const struct keyword_enum_values kw_ynf_list = VALUES_INITIALIZER(kw_ynf_values);
#endif

/*
 * Values for authby={rsasig, secret}
 */
static const struct keyword_enum_value kw_authby_values[]={
    { "never",     0},
    { "rsasig",    POLICY_RSASIG},
    { "secret",    POLICY_PSK},
};
static const struct keyword_enum_values kw_authby_list = VALUES_INITIALIZER(kw_authby_values);

/*
 * Values for dpdaction={hold,clear,restart}
 */
static const struct keyword_enum_value kw_dpdaction_values[]={
    { "hold",    DPD_ACTION_HOLD},
    { "clear",   DPD_ACTION_CLEAR},
    { "restart",   DPD_ACTION_RESTART},
    { "restart_by_peer",   DPD_ACTION_RESTART_BY_PEER},
};

struct keyword_enum_values kw_dpdaction_list=
    { kw_dpdaction_values, sizeof(kw_dpdaction_values)/sizeof(struct keyword_enum_value)};


/*
 * Values for auto={add,start,route,ignore}
 */
static const struct keyword_enum_value kw_auto_values[]={
    { "ignore", STARTUP_NO },
    { "add",    STARTUP_ADD },
    { "route",  STARTUP_ROUTE },
    { "start",  STARTUP_START },
    { "up",     STARTUP_START }, /* alias */
};

static const struct keyword_enum_values kw_auto_list = VALUES_INITIALIZER(kw_auto_values);

/*
 * Values for connaddrfamily={ipv4,ipv6}
 */
static const struct keyword_enum_value kw_connaddrfamily_values[]={
    { "ipv4",   AF_INET },
    { "v4",     AF_INET },
    { "inet",   AF_INET },
    { "ipv6",   AF_INET6 },
    { "v6",     AF_INET6 },
    { "inet6",  AF_INET6 },
};

const struct keyword_enum_values kw_connaddrfamily_list = VALUES_INITIALIZER(kw_connaddrfamily_values);

/*
 * Values for type={tunnel,transport,udpencap}
 */
static const struct keyword_enum_value kw_type_values[]={
    { "tunnel",    KS_TUNNEL },
    { "transport", KS_TRANSPORT },
    { "udp",       KS_UDPENCAP },
    { "udpencap",  KS_UDPENCAP },
    { "pass",      KS_PASSTHROUGH },
    { "passthrough", KS_PASSTHROUGH },
    { "reject",    KS_REJECT },
    { "drop",      KS_DROP },
};

static const struct keyword_enum_values kw_type_list = VALUES_INITIALIZER(kw_type_values);

/*
 * Values for rsasigkey={%dnsondemand, %dns, literal }
 */
static const struct keyword_enum_value kw_rsasigkey_values[]={
    { "",             PUBKEY_PREEXCHANGED },
    { "%cert",        PUBKEY_CERTIFICATE },
    { "%dns",         PUBKEY_DNS },
    { "%dnsondemand", PUBKEY_DNSONDEMAND },
};

static const struct keyword_enum_values kw_rsasigkey_list = VALUES_INITIALIZER(kw_rsasigkey_values);

/*
 * Values for protostack={klips, none, auto, klipsmast, netkey }
 */
static const struct keyword_enum_value kw_proto_stack_list[]={
    { "none",         NO_KERNEL },
    { "auto",         AUTO_PICK },
    { "klips",        USE_KLIPS },
    { "mast",         USE_MASTKLIPS },
    { "netkey",       USE_NETKEY },
    { "native",       USE_NETKEY },
    { "bsd",          USE_BSDKAME },
    { "kame",         USE_BSDKAME },
    { "bsdkame",      USE_BSDKAME },
    { "win2k",        USE_WIN2K },
};

static const struct keyword_enum_values kw_proto_stack = VALUES_INITIALIZER(kw_proto_stack_list);

/*
 * Values for sareftrack={yes, no, conntrack }
 */
static const struct keyword_enum_value kw_sareftrack_values[]={
    { "yes",          sat_yes },
    { "no",           sat_no },
    { "conntrack",    sat_conntrack },
};

static const struct keyword_enum_values kw_sareftrack_list = VALUES_INITIALIZER(kw_sareftrack_values);

/*
 *  Cisco interop: remote peer type
 */

static const struct keyword_enum_value kw_remote_peer_type_list[]={
    { "cisco",         CISCO },
};
static const struct keyword_enum_values kw_remote_peer_type = VALUES_INITIALIZER(kw_remote_peer_type_list);

#if 0
/* no longer used */
static const struct keyword_enum_value kw_xauthby_list[] = {
	{ "file",        XAUTHBY_FILE },
	{ "pam",         XAUTHBY_PAM },
	{ "alwaysok",    XAUTHBY_ALWAYSOK },
};
static const struct keyword_enum_values kw_xauthby = VALUES_INITIALIZER(kw_xauthby_list);
#endif

/*
 * Values for right= and left=
 */
extern struct keyword_enum_values kw_host_list;


static const struct keyword_enum_value kw_plutodebug_values[]={
    { "none",     DBG_NONE },
    { "all",      DBG_ALL },
    { "raw",      DBG_RAW },
    { "crypt",    DBG_CRYPT },
    { "parsing",  DBG_PARSING },
    { "emitting", DBG_EMITTING },
    { "control",  DBG_CONTROL },
    { "lifecycle", DBG_LIFECYCLE },
    { "klips",    DBG_KLIPS },
    { "dns",      DBG_DNS },
    { "oppo",     DBG_OPPO },
    { "oppoinfo",    DBG_OPPOINFO },
    { "controlmore", DBG_CONTROLMORE },
    { "private",  DBG_PRIVATE },
    { "x509",     DBG_X509 },
    { "dpd",      DBG_DPD },
    { "pfkey",    DBG_PFKEY },
    { "natt",     DBG_NATT },
    { "nattraversal", DBG_NATT },

    { "impair-delay-adns-key-answer", IMPAIR_DELAY_ADNS_KEY_ANSWER },
    { "impair-delay-adns-txt-answer", IMPAIR_DELAY_ADNS_TXT_ANSWER },
    { "impair-bust-mi2", IMPAIR_BUST_MI2 },
    { "impair-bust-mr2", IMPAIR_BUST_MR2 },
};


struct keyword_enum_values kw_plutodebug_list=
    { kw_plutodebug_values, sizeof(kw_plutodebug_values)/sizeof(struct keyword_enum_value)};


static const struct keyword_enum_value kw_klipsdebug_values[]={
    { "all",      LRANGE(KDF_XMIT, KDF_COMP) },
    { "none",     0 },
    { "verbose",  LELEM(KDF_VERBOSE) },
    { "xmit",     LELEM(KDF_XMIT) },
    { "tunnel-xmit", LELEM(KDF_XMIT) },
    { "netlink",  LELEM(KDF_NETLINK) },
    { "xform",    LELEM(KDF_XFORM) },
    { "eroute",   LELEM(KDF_EROUTE) },
    { "spi",      LELEM(KDF_SPI) },
    { "radij",    LELEM(KDF_RADIJ) },
    { "esp",      LELEM(KDF_ESP) },
    { "ah",       LELEM(KDF_AH) },
    { "rcv",      LELEM(KDF_RCV) },
    { "tunnel",   LELEM(KDF_TUNNEL) },
    { "pfkey",    LELEM(KDF_PFKEY) },
    { "comp",     LELEM(KDF_COMP) },
    { "nat-traversal", LELEM(KDF_NATT) },
    { "nattraversal", LELEM(KDF_NATT) },
    { "natt",     LELEM(KDF_NATT) },
};

struct keyword_enum_values kw_klipsdebug_list=
    { kw_klipsdebug_values, sizeof(kw_klipsdebug_values)/sizeof(struct keyword_enum_value)};

static const struct keyword_enum_value kw_phase2types_values[]={
    { "ah+esp",   POLICY_ENCRYPT|POLICY_AUTHENTICATE },
    { "esp",      POLICY_ENCRYPT },
    { "ah",       POLICY_AUTHENTICATE },
    { "default",  POLICY_ENCRYPT },     /* alias, find it last */
};

static const struct keyword_enum_values kw_phase2types_list = VALUES_INITIALIZER(kw_phase2types_values);

/*
 * Values for {left/right}sendcert={never,sendifasked,always,forcedtype}
 */
static const struct keyword_enum_value kw_sendcert_values[]={
    { "never",        cert_neversend },
    { "sendifasked",  cert_sendifasked },
    { "alwayssend",   cert_alwayssend },
    { "always",       cert_alwayssend },
    { "forcedtype",   cert_forcedtype },
};

struct keyword_enum_values kw_sendcert_list=
    { kw_sendcert_values, sizeof(kw_sendcert_values)/sizeof(struct keyword_enum_value)};

/* MASTER KEYWORD LIST */
struct keyword_def ipsec_conf_keywords_v2[]={
    {"interfaces",     kv_config, kt_string,    KSF_INTERFACES,NOT_ENUM},
    {"myid",           kv_config, kt_string,    KSF_MYID,NOT_ENUM},
    {"syslog",         kv_config, kt_string,    KSF_SYSLOG,NOT_ENUM},
    {"klipsdebug",     kv_config, kt_list,      KBF_KLIPSDEBUG, &kw_klipsdebug_list},
    {"plutodebug",     kv_config, kt_list,      KBF_PLUTODEBUG, &kw_plutodebug_list},
    {"plutoopts",      kv_config, kt_string,    KSF_PLUTOOPTS,NOT_ENUM},
    {"plutostderrlog", kv_config, kt_filename,  KSF_PLUTOSTDERRLOG,NOT_ENUM},
    {"plutostderrlogtime",        kv_config, kt_bool,      KBF_PLUTOSTDERRLOGTIME,NOT_ENUM},
    {"plutorestartoncrash", kv_config, kt_bool, KBF_PLUTORESTARTONCRASH,NOT_ENUM},
    {"dumpdir",        kv_config, kt_dirname,   KSF_DUMPDIR,NOT_ENUM},
    {"manualstart",    kv_config, kt_string,    KSF_MANUALSTART,NOT_ENUM},
    {"pluto",          kv_config, kt_filename,  KSF_PLUTO, NOT_ENUM},
    {"plutowait",      kv_config, kt_bool,      KBF_PLUTOWAIT,NOT_ENUM},
    {"oe",             kv_config, kt_bool,      KBF_OPPOENCRYPT,NOT_ENUM},
    {"prepluto",       kv_config, kt_filename,  KSF_PREPLUTO,NOT_ENUM},
    {"postpluto",      kv_config, kt_filename,  KSF_POSTPLUTO,NOT_ENUM},
    {"fragicmp",       kv_config, kt_bool,      KBF_FRAGICMP,NOT_ENUM},
    {"hidetos",        kv_config, kt_bool,      KBF_HIDETOS,NOT_ENUM},
    {"uniqueids",      kv_config, kt_bool,      KBF_UNIQUEIDS,NOT_ENUM},
    {"overridemtu",    kv_config, kt_number,    KBF_OVERRIDEMTU,NOT_ENUM},
    {"nocrsend",       kv_config, kt_bool,      KBF_NOCRSEND,NOT_ENUM},
    {"strictcrlpolicy",kv_config, kt_bool,      KBF_STRICTCRLPOLICY,NOT_ENUM},
    {"crlcheckinterval",kv_config,kt_time,      KBF_CRLCHECKINTERVAL,NOT_ENUM},
    {"force_busy",     kv_config, kt_bool,      KBF_FORCEBUSY,NOT_ENUM},
    {"virtual_private",kv_config,kt_string,     KSF_VIRTUALPRIVATE,NOT_ENUM},
    {"nat_traversal", kv_config,kt_bool,        KBF_NATTRAVERSAL, NOT_ENUM},
    {"disable_port_floating", kv_config,kt_bool,KBF_DISABLEPORTFLOATING, NOT_ENUM},
    {"keep_alive", kv_config,kt_number,    KBF_KEEPALIVE, NOT_ENUM},
    {"force_keepalive", kv_config,kt_bool,    KBF_FORCE_KEEPALIVE, NOT_ENUM},
    {"listen",     kv_config, kt_string, KSF_LISTEN,NOT_ENUM},
    {"protostack",     kv_config, kt_string,    KSF_PROTOSTACK, &kw_proto_stack},
    {"nhelpers",kv_config,kt_number, KBF_NHELPERS, NOT_ENUM},
    {"secctx_attr_value",kv_config,kt_number, KBF_SECCTX, NOT_ENUM},
    /* these two options are obsoleted. Don't die on them */
    {"forwardcontrol", kv_config|kv_obsolete, kt_string, KBF_WARNIGNORE,NOT_ENUM},
    {"rp_filter",      kv_config|kv_obsolete, kt_string, KBF_WARNIGNORE,NOT_ENUM},

    /* this is "left=" and "right=" */
    {"",               kv_conn|kv_leftright, kt_loose_enumarg, KSCF_IP, &kw_host_list, LOOSE_ENUM_OTHER, '/'},

    {"ike",            kv_conn|kv_auto, kt_string, KSF_IKE,NOT_ENUM},

    {"subnet",         kv_conn|kv_auto|kv_leftright|kv_processed, kt_subnet, KSCF_SUBNET,NOT_ENUM},
    {"subnets",        kv_conn|kv_auto|kv_leftright, kt_appendlist, KSCF_SUBNETS,NOT_ENUM},
    {"sourceip",       kv_conn|kv_auto|kv_leftright, kt_ipaddr, KSCF_SOURCEIP,NOT_ENUM},
    {"nexthop",        kv_conn|kv_auto|kv_leftright, kt_ipaddr, KSCF_NEXTHOP,NOT_ENUM},
    {"firewall",       kv_conn|kv_auto|kv_leftright|kv_obsolete, kt_bool,   KNCF_FIREWALL,NOT_ENUM},
    {"updown",         kv_conn|kv_auto|kv_leftright, kt_filename, KSCF_UPDOWN,NOT_ENUM},
    {"id",             kv_conn|kv_auto|kv_leftright, kt_idtype, KSCF_ID,NOT_ENUM},
    {"rsasigkey",      kv_conn|kv_auto|kv_leftright, kt_rsakey, KSCF_RSAKEY1, &kw_rsasigkey_list, PUBKEY_PREEXCHANGED},
    {"rsasigkey2",     kv_conn|kv_auto|kv_leftright, kt_rsakey, KSCF_RSAKEY2, &kw_rsasigkey_list, PUBKEY_PREEXCHANGED},
    {"spibase",        kv_conn|kv_auto|kv_leftright, kt_number, KNCF_SPIBASE,NOT_ENUM},
    {"cert",           kv_conn|kv_auto|kv_leftright, kt_filename, KSCF_CERT,NOT_ENUM},
    {"sendcert",       kv_conn|kv_auto|kv_leftright, kt_enum,   KNCF_SENDCERT, &kw_sendcert_list},
    {"ca",             kv_conn|kv_auto|kv_leftright, kt_string, KSCF_CA,NOT_ENUM},

    /* these are conn statements which are not left/right */
    {"auto",           kv_conn|kv_duplicateok, kt_enum,   KBF_AUTO,        &kw_auto_list},
    {"also",           kv_conn,         kt_appendstring, KSF_ALSO,    NOT_ENUM},
    {"alsoflip",       kv_conn,         kt_appendstring, KSF_ALSOFLIP,NOT_ENUM},
    {"endaddrfamily",  kv_conn,         kt_enum,   KBF_ENDADDRFAMILY,     &kw_connaddrfamily_list},
    {"connaddrfamily", kv_conn,         kt_enum,   KBF_CLIENTADDRFAMILY,    &kw_connaddrfamily_list},
    {"clientaddrfamily", kv_conn,       kt_enum,   KBF_CLIENTADDRFAMILY,    &kw_connaddrfamily_list},
    {"tunneladdrfamily", kv_conn,       kt_enum,   KBF_CLIENTADDRFAMILY,    &kw_connaddrfamily_list},
    {"type",           kv_conn,         kt_enum,   KBF_TYPE,        &kw_type_list},
    {"authby",         kv_conn|kv_auto, kt_enum,   KBF_AUTHBY,     &kw_authby_list},
    {"keyexchange",    kv_conn|kv_auto, kt_enum,   KBF_KEYEXCHANGE, &kw_keyexchange_list},
    {"ikev1",          kv_conn|kv_auto|kv_processed,kt_bool,   KBF_IKEv1,       NOT_ENUM},
    {"ikev2",          kv_conn|kv_auto|kv_processed,kt_enum,KBF_IKEv2,&kw_fourvalued_list},
    {"narrowing",      kv_conn|kv_auto, kt_bool,   KBF_IKEv2_ALLOW_NARROWING, NOT_ENUM},
    {"sareftrack",     kv_conn|kv_auto|kv_processed,kt_enum,KBF_SAREFTRACK,&kw_sareftrack_list},
    {"pfs",            kv_conn|kv_auto, kt_bool,   KBF_PFS,          NOT_ENUM},
    {"sha2_truncbug",  kv_conn|kv_auto, kt_bool,   KBF_SHA2_TRUNCBUG,NOT_ENUM},
    {"keylife",        kv_conn|kv_auto|kv_alias, kt_time,   KBF_SALIFETIME,NOT_ENUM},
    {"lifetime",       kv_conn|kv_auto|kv_alias, kt_time,   KBF_SALIFETIME,NOT_ENUM},
    {"salifetime",     kv_conn|kv_auto, kt_time,   KBF_SALIFETIME,NOT_ENUM},
    {"loopback",       kv_conn|kv_auto, kt_bool,   KBF_LOOPBACK, NOT_ENUM},
    {"labeled_ipsec",  kv_conn|kv_auto, kt_bool,   KBF_LABELED_IPSEC, NOT_ENUM},
    {"policy_label",   kv_conn|kv_auto,         kt_string, KSF_POLICY_LABEL, NOT_ENUM},

    /* Cisco interop: remote peer type*/
    {"remote_peer_type", kv_conn|kv_auto, kt_enum, KBF_REMOTEPEERTYPE, &kw_remote_peer_type},

    /* Network Manager support*/
    {"nm_configured", kv_conn|kv_auto, kt_bool,    KBF_NMCONFIGURED, NOT_ENUM},

    {"forceencaps",    kv_conn|kv_auto, kt_bool,   KBF_FORCEENCAP, NOT_ENUM},
    {"overlapip",      kv_conn|kv_auto, kt_bool,   KBF_OVERLAPIP, NOT_ENUM},
    {"rekey",          kv_conn|kv_auto, kt_bool,   KBF_REKEY, NOT_ENUM},
    {"rekeymargin",    kv_conn|kv_auto, kt_time,   KBF_REKEYMARGIN,NOT_ENUM},
    {"rekeyfuzz",      kv_conn|kv_auto, kt_percent,   KBF_REKEYFUZZ,NOT_ENUM},
    {"keyingtries",    kv_conn|kv_auto, kt_number, KBF_KEYINGTRIES,NOT_ENUM},
    {"ikelifetime",    kv_conn|kv_auto, kt_time,   KBF_IKELIFETIME,NOT_ENUM},
    {"disablearrivalcheck", kv_conn|kv_auto, kt_invertbool, KBF_ARRIVALCHECK,NOT_ENUM},
    {"failureshunt",   kv_conn|kv_auto, kt_enum,   KBF_FAILURESHUNT, &kw_failureshunt_list},
    {"connalias",      kv_conn|kv_processed|kv_auto|kv_manual, kt_appendstring,   KSF_CONNALIAS, NOT_ENUM},

    /* attributes of the phase2 policy */
    {"phase2alg",      kv_conn|kv_auto|kv_manual,  kt_string, KSF_ESP,NOT_ENUM},
    {"esp",            kv_conn|kv_auto|kv_manual|kv_alias,  kt_string, KSF_ESP,NOT_ENUM},
    {"ah",             kv_conn|kv_auto|kv_manual|kv_alias,  kt_string, KSF_ESP,NOT_ENUM},
    {"subnetwithin",   kv_conn|kv_leftright, kt_string, KSCF_SUBNETWITHIN,NOT_ENUM},
    {"protoport",      kv_conn|kv_leftright|kv_processed, kt_string, KSCF_PROTOPORT,NOT_ENUM},
    {"phase2",         kv_conn|kv_auto|kv_manual|kv_policy,  kt_enum, KBF_PHASE2, &kw_phase2types_list},
    {"auth",           kv_conn|kv_auto|kv_manual|kv_policy|kv_alias,  kt_enum, KBF_PHASE2, &kw_phase2types_list},
    {"compress",       kv_conn|kv_auto, kt_bool,   KBF_COMPRESS,NOT_ENUM},

    /* route metric */
    {"metric",         kv_conn|kv_auto, kt_number, KBF_METRIC, NOT_ENUM},

    /* DPD */
    {"dpddelay",       kv_conn|kv_auto, kt_time, KBF_DPDDELAY,   NOT_ENUM},
    {"dpdtimeout",     kv_conn|kv_auto, kt_time, KBF_DPDTIMEOUT, NOT_ENUM},
    {"dpdaction",      kv_conn|kv_auto, kt_enum, KBF_DPDACTION,  &kw_dpdaction_list},

    {"firstmsgid",     kv_conn|kv_auto, kt_number, KBF_FIRSTMSGID, NOT_ENUM},

    {"mtu",            kv_conn|kv_auto,kt_number, KBF_CONNMTU, NOT_ENUM},

    /* aggr/xauth/modeconfig */
    {"aggrmode",    kv_conn|kv_auto, kt_invertbool,      KBF_AGGRMODE,NOT_ENUM},
    {"aggressive",  kv_conn|kv_auto, kt_invertbool,      KBF_AGGRMODE,NOT_ENUM},
    {"xauthserver", kv_conn|kv_auto|kv_leftright, kt_bool, KNCF_XAUTHSERVER,  NOT_ENUM},
    {"xauthclient", kv_conn|kv_auto|kv_leftright, kt_bool, KNCF_XAUTHCLIENT, NOT_ENUM},
    {"xauthname",   kv_conn|kv_auto|kv_leftright, kt_string, KSCF_XAUTHUSERNAME, NOT_ENUM},
    {"modecfgserver", kv_conn|kv_auto|kv_leftright, kt_bool, KNCF_MODECONFIGSERVER, NOT_ENUM},
    {"modecfgclient", kv_conn|kv_auto|kv_leftright, kt_bool, KNCF_MODECONFIGCLIENT, NOT_ENUM},
    {"xauthusername", kv_conn|kv_auto|kv_leftright, kt_string, KSCF_XAUTHUSERNAME, NOT_ENUM},
    {"modecfgpull", kv_conn|kv_auto, kt_invertbool, KBF_MODECONFIGPULL , NOT_ENUM},
    {"modecfgdns1", kv_conn|kv_auto|kv_leftright, kt_ipaddr, KSCF_MODECFGDNS1,NOT_ENUM},
    {"modecfgdns2", kv_conn|kv_auto|kv_leftright, kt_ipaddr, KSCF_MODECFGDNS2,NOT_ENUM},
    {"modecfgwins1", kv_conn|kv_auto|kv_leftright, kt_ipaddr, KSCF_MODECFGWINS1,NOT_ENUM},
    {"modecfgwins2", kv_conn|kv_auto|kv_leftright, kt_ipaddr, KSCF_MODECFGWINS2,NOT_ENUM},
    /* things for manual keying only */
    {"spi",            kv_conn|kv_leftright|kv_manual, kt_number, KNCF_SPI,NOT_ENUM},
    {"espenckey",      kv_conn|kv_leftright|kv_manual, kt_bitstring, KSCF_ESPENCKEY,NOT_ENUM},
    {"espauthkey",     kv_conn|kv_leftright|kv_manual, kt_bitstring, KSCF_ESPAUTHKEY,NOT_ENUM},
    {"espreplay_window",kv_conn|kv_leftright|kv_manual, kt_number, KNCF_ESPREPLAYWINDOW,NOT_ENUM},

    /* some things from libreswan, which we will probably accept */
    { "plutofork",      kv_config|kv_obsolete, kt_bool,      KBF_PLUTOFORK,  NOT_ENUM },

    {NULL, 0, 0, 0, NOT_ENUM}
};

/* distinguished keyword */
struct keyword_def ipsec_conf_keyword_comment=
{"x-comment",      kv_conn,   kt_comment, 0, NOT_ENUM};


const int ipsec_conf_keywords_v2_count = sizeof(ipsec_conf_keywords_v2)/sizeof(struct keyword_def);

/*
 * look for one of the above tokens, and set the value up right.
 *
 * if we don't find it, then strdup() the string and return a string
 *
 */

/* type is really "token" type, which is actually int */
int parser_find_keyword(const char *s, YYSTYPE *lval)
{
    struct keyword_def *k;
    bool keyleft;
    int  keywordtype;

    keyleft=FALSE;
    k = ipsec_conf_keywords_v2;

    while(k->keyname != NULL) {
	if(strcasecmp(s, k->keyname) == 0)
	{
	    break;
	}

	if(k->validity & kv_leftright)
	{
	    if(strncasecmp(s, "left", 4)==0
	       && strcasecmp(s+4, k->keyname)==0)
	    {
		keyleft=TRUE;
		break;
	    }
	    else if(strncasecmp(s, "right", 5)==0
		    && strcasecmp(s+5, k->keyname)==0)
	    {
		keyleft=FALSE;
		break;
	    }
	}

	k++;
    }

    lval->s = NULL;
    /* if we found nothing */
    if(k->keyname == NULL && (s[0]=='x' || s[0]=='X') && (s[1]=='-' || s[1] =='_'))
    {
	k = &ipsec_conf_keyword_comment;
	lval->k.string = strdup(s);
    }

    /* if we still found nothing */
    if(k->keyname == NULL) {
	lval->s = strdup(s);
	return STRING;
    }

    switch(k->type)
    {
    case kt_percent:
	keywordtype = PERCENTWORD;
	break;
    case kt_time:
	keywordtype = TIMEWORD;
	break;
    case kt_comment:
	keywordtype = COMMENT;
	break;
    case kt_bool:
    case kt_invertbool:
	keywordtype = BOOLWORD;
	break;
    default:
	keywordtype = KEYWORD;
	break;
    }

    /* else, set up llval.k to point, and return KEYWORD */
    lval->k.keydef = k;
    lval->k.keyleft = keyleft;
    return keywordtype;
}

unsigned int parser_enum_list(struct keyword_def *kd, const char *s, bool list)
{
    char *piece;
    char *scopy;
    int   numfound, kevcount;
    const struct keyword_enum_value *kev;
    unsigned int valresult;
    char complaintbuf[80];

    assert(kd->type == kt_list || kd->type == kt_enum);

    scopy = strdup(s);
    valresult = 0;

    /*
     * split up the string into comma separated pieces, and look each piece up in the
     * value list provided in the definition.
     */

    numfound=0;
    while((piece = strsep(&scopy, ":, \t")) != NULL)
    {
	/* discard empty strings */
	if(strlen(piece) == 0) {
	    continue;
	}

	assert(kd->validenum != NULL);
	for(kevcount = kd->validenum->valuesize, kev = kd->validenum->values;
	    kevcount > 0 && strcasecmp(piece, kev->name)!=0;
	    kev++, kevcount--);

	/* if we found something */
	if(kevcount != 0)
	{
	    /* count it */
	    numfound++;

	    valresult |= kev->value;
	}
	else
	{   /* we didn't find anything, complain */

	    snprintf(complaintbuf, sizeof(complaintbuf)
		     , "%s: %d: keyword %s, invalid value: %s"
		     , parser_cur_filename(), parser_cur_lineno()
		     , kd->keyname, piece);

	    if(warningsarefatal)
	    {
		fprintf(stderr, "ERROR: %s\n", complaintbuf);
		exit(1);
	    }
	    else
	    {
		fprintf(stderr, "WARNING: %s\n", complaintbuf);
	    }
	}
    }

    if(numfound > 1 && !list)
    {
	snprintf(complaintbuf, sizeof(complaintbuf)
		 , "%s: %d: keyword %s accepts only one value, not %s"
		 , parser_cur_filename(), parser_cur_lineno()
		 , kd->keyname, scopy);

	if(warningsarefatal)
	{
	    fprintf(stderr, "ERROR: %s\n", complaintbuf);
	    free(scopy);
	    exit(1);
	}
	else
	{
	    fprintf(stderr, "WARNING: %s\n", complaintbuf);
	    valresult=0;
	}
    }

    free(scopy);
    return valresult;
}

unsigned int parser_loose_enum_arg(struct keyword *k, const char *s, char **rest)
{
    struct keyword_def *kd = k->keydef;
    int   kevcount;
    const struct keyword_enum_value *kev;
    unsigned int valresult;

    assert(kd->type == kt_loose_enum || kd->type == kt_loose_enumarg || kd->type == kt_rsakey);
    assert(kd->validenum != NULL && kd->validenum->values != NULL);

    if(kd->deliminator != '\0') {
        char *nl = strchr(s, kd->deliminator);
        if(nl) {
            *nl='\0';
            nl++;
            if(rest) *rest = nl;
        }
    }

    for(kevcount = kd->validenum->valuesize, kev = kd->validenum->values;
	kevcount > 0 && strcasecmp(s, kev->name)!=0;
	kev++, kevcount--);

    /* if we found something */
    if(kevcount != 0)
    {
	assert(kev->value != 0);
	valresult = kev->value;
	k->string = NULL;
	return valresult;
    }

#ifdef KEYWORD_PARSE_DEBUG
    {
        char kdtypebuf[KEYWORD_NAME_BUFLEN];
        fprintf(stderr, "loose enum(%s) for %s is %d\n", s, keyword_name(&kt_values_list, kd->type, kdtypebuf),
                kd->loose_enum_value);
    }
#endif
    /* else, it's a literal other value */
    k->string = strdup(s);
    return kd->loose_enum_value;
}


/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */



