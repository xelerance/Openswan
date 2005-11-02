/* manifest constants
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
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
 * RCSID $Id: constants.h,v 1.120.2.2 2004/05/07 03:17:06 ken Exp $
 */

extern const char compile_time_interop_options[];

extern void init_constants(void);

/*
 * NOTE:For debugging purposes, constants.c has tables to map numbers back to names.
 * Any changes here should be reflected there.
 */

#define elemsof(array) (sizeof(array) / sizeof(*(array)))	/* number of elements in an array */

/* Many routines return only success or failure, but wish to describe
 * the failure in a message.  We use the convention that they return
 * a NULL on success and a pointer to constant string on failure.
 * The fact that the string is a constant is limiting, but it
 * avoids storage management issues: the recipient is allowed to assume
 * that the string will live "long enough" (usually forever).
 * <openswan.h> defines err_t for this return type.
 */

typedef int bool;
#define FALSE	0
#define TRUE	1

#define NULL_FD	(-1)	/* NULL file descriptor */
#define dup_any(fd) ((fd) == NULL_FD? NULL_FD : dup(fd))
#define close_any(fd) { if ((fd) != NULL_FD) { close(fd); (fd) = NULL_FD; } }

#define BITS_PER_BYTE	8
#define BYTES_FOR_BITS(b)   (((b) + BITS_PER_BYTE - 1) / BITS_PER_BYTE)

#define streq(a, b) (strcmp((a), (b)) == 0)	/* clearer shorthand */
#define strcaseeq(a, b) (strcasecmp((a), (b)) == 0)	/* clearer shorthand */

/* set type with room for at least 32 elements */

typedef unsigned long lset_t;
#define LEMPTY 0UL
#define LELEM(opt) (1UL << (opt))
#define LRANGE(lwb, upb) LRANGES(LELEM(lwb), LELEM(upb))
#define LRANGES(first, last) (last - first + last)
#define LHAS(set, elem)  ((LELEM(elem) & (set)) != LEMPTY)
#define LIN(subset, set)  (((subset) & (set)) == (subset))
#define LDISJOINT(a, b)  (((a) & (b)) == LEMPTY)

/* Control and lock pathnames */

#ifndef DEFAULT_CTLBASE
# define DEFAULT_CTLBASE "/var/run/pluto"
#endif

#define CTL_SUFFIX ".ctl"	/* for UNIX domain socket pathname */
#define LOCK_SUFFIX ".pid"	/* for pluto's lock */
#define INFO_SUFFIX ".info"     /* for UNIX domain socket for apps */

/* Routines to check and display values.
 *
 * An enum_names describes an enumeration.
 * enum_name() returns the name of an enum value, or NULL if invalid.
 * enum_show() is like enum_name, except it formats a numeric representation
 *    for any invalid value (in a static area!)
 *
 * bitnames() formats a display of a set of named bits (in a static area)
 */

typedef const struct enum_names enum_names;

extern const char *enum_name(enum_names *ed, unsigned long val);
extern const char *enum_show(enum_names *ed, unsigned long val);

extern bool testset(const char *const table[], lset_t val);
extern const char *bitnamesof(const char *const table[], lset_t val);

/* sparse_names is much like enum_names, except values are
 * not known to be contiguous or ordered.
 * The array of names is ended with one with the name sparse_end
 * (this avoids having to reserve a value to signify the end).
 * Often appropriate for enums defined by others.
 */
struct sparse_name {
    unsigned long val;
    const char *const name;
};
typedef const struct sparse_name sparse_names[];

extern const char *sparse_name(sparse_names sd, unsigned long val);
extern const char *sparse_val_show(sparse_names sd, unsigned long val);
extern const char sparse_end[];

#define FULL_INET_ADDRESS_SIZE    6

/* Group parameters from draft-ietf-ike-01.txt section 6 */

#define MODP_GENERATOR "2"

#define MODP768_MODULUS \
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " \
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " \
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " \
    "E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF"

#define MODP1024_MODULUS \
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " \
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " \
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " \
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED " \
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381 " \
    "FFFFFFFF FFFFFFFF"

#define MODP1536_MODULUS \
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " \
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " \
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " \
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED " \
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D " \
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F " \
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D " \
    "670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF "

#define LOCALSECRETSIZE		BYTES_FOR_BITS(256)

/* limits on nonce sizes.  See RFC2409 "The internet key exchange (IKE)" 5 */
#define MINIMUM_NONCE_SIZE	8	/* bytes */
#define DEFAULT_NONCE_SIZE	16	/* bytes */
#define MAXIMUM_NONCE_SIZE	256	/* bytes */

#define COOKIE_SIZE 8
#define MAX_ISAKMP_SPI_SIZE 16

#define MD2_DIGEST_SIZE         BYTES_FOR_BITS(128)     /* ought to be supplied by md2.h */
#define MD5_DIGEST_SIZE		BYTES_FOR_BITS(128)	/* ought to be supplied by md5.h */
#define SHA1_DIGEST_SIZE	BYTES_FOR_BITS(160)	/* ought to be supplied by sha1.h */

#define DES_CBC_BLOCK_SIZE	BYTES_FOR_BITS(64)

#define DSS_QBITS	160	/* bits in DSS's "q" (FIPS 186-1) */

/* to statically allocate IV, we need max of
 * MD5_DIGEST_SIZE, SHA1_DIGEST_SIZE, and DES_CBC_BLOCK_SIZE.
 * To avoid combinatorial explosion, we leave out DES_CBC_BLOCK_SIZE.
 */
#define MAX_DIGEST_LEN (MD5_DIGEST_SIZE > SHA1_DIGEST_SIZE? MD5_DIGEST_SIZE : SHA1_DIGEST_SIZE)

/* RFC 2404 "HMAC-SHA-1-96" section 3 */
#define HMAC_SHA1_KEY_LEN    SHA1_DIGEST_SIZE

/* RFC 2403 "HMAC-MD5-96" section 3 */
#define HMAC_MD5_KEY_LEN    MD5_DIGEST_SIZE

#define IKE_UDP_PORT	500

/* Timer events */

extern enum_names timer_event_names;

enum event_type {
    EVENT_NULL,	/* non-event */
    EVENT_REINIT_SECRET,	/* Refresh cookie secret */
#ifdef KLIPS
    EVENT_SHUNT_SCAN,	/* scan shunt eroutes known to kernel */
#endif
    EVENT_SO_DISCARD,	/* discard unfinished state object */
    EVENT_RETRANSMIT,	/* Retransmit packet */
    EVENT_SA_REPLACE,	/* SA replacement event */
    EVENT_SA_REPLACE_IF_USED,	/* SA replacement event */
    EVENT_SA_EXPIRE,	/* SA expiration event */
    EVENT_NAT_T_KEEPALIVE,
    EVENT_LOG_DAILY     /* reset certain log events/stats */
};

#define EVENT_REINIT_SECRET_DELAY		3600 /* 1 hour */
#define EVENT_RETRANSMIT_DELAY_0		10   /* 10 seconds */

/* Misc. stuff */

#define MAXIMUM_RETRANSMISSIONS              2
#define MAXIMUM_RETRANSMISSIONS_INITIAL      20

#define MAX_INPUT_UDP_SIZE             65536
#define MAX_OUTPUT_UDP_SIZE            65536

/* Version numbers */

#define ISAKMP_MAJOR_VERSION   0x1
#define ISAKMP_MINOR_VERSION   0x0

extern enum_names version_names;

/* Domain of Interpretation */

extern enum_names doi_names;

#define ISAKMP_DOI_ISAKMP          0
#define ISAKMP_DOI_IPSEC           1

/* IPsec DOI things */

#define IPSEC_DOI_SITUATION_LENGTH 4
#define IPSEC_DOI_LDI_LENGTH       4
#define IPSEC_DOI_SPI_SIZE         4

/* SPI value 0 is invalid and values 1-255 are reserved to IANA.
 * ESP: RFC 2402 2.4; AH: RFC 2406 2.1
 * IPComp RFC 2393 substitutes a CPI in the place of an SPI.
 * see also draft-shacham-ippcp-rfc2393bis-05.txt.
 * We (Openswan) reserve 0x100 to 0xFFF for manual keying, so
 * Pluto won't generate these values.
 */
#define IPSEC_DOI_SPI_MIN          0x100
#define IPSEC_DOI_SPI_OUR_MIN      0x1000

/* debugging settings: a set of selections for reporting
 * These would be more naturally situated in log.h,
 * but they are shared with whack.
 * IMPAIR_* actually change behaviour, usually badly,
 * to aid in testing.  Naturally, these are not included in ALL.
 *
 * NOTE: changes here must be done in concert with changes to DBGOPT_*
 * in whack.c.  A change to WHACK_MAGIC in whack.h will be required too.
 */
#ifdef DEBUG
extern const char *const debug_bit_names[];

#define DBG_RAW		LELEM(0)	/* raw packet I/O */
#define DBG_CRYPT	LELEM(1)	/* encryption/decryption of messages */
#define DBG_PARSING	LELEM(2)	/* show decoding of messages */
#define DBG_EMITTING	LELEM(3)	/* show encoding of messages */
#define DBG_CONTROL	LELEM(4)	/* control flow within Pluto */
#define DBG_LIFECYCLE	LELEM(5)	/* SA lifecycle */
#define DBG_KLIPS	LELEM(6)	/* messages to KLIPS */
#define DBG_DNS		LELEM(7)	/* DNS activity */
#define DBG_OPPO	LELEM(8)	/* opportunism */
#define DBG_CONTROLMORE LELEM(9)	/* more detailed debugging */

#define DBG_PFKEY	LELEM(10)	/*turn on the pfkey library debugging*/
#define DBG_NATT        LELEM(11)       /* debugging of NAT-traversal */
#define DBG_PRIVATE	LELEM(12)	/* private information: DANGER! */

#define IMPAIR0	13	/* first bit for IMPAIR_* */

#define IMPAIR_DELAY_ADNS_KEY_ANSWER	LELEM(IMPAIR0+0)	/* sleep before answering */
#define IMPAIR_DELAY_ADNS_TXT_ANSWER	LELEM(IMPAIR0+1)	/* sleep before answering */
#define IMPAIR_BUST_MI2	LELEM(IMPAIR0+2)	/* make MI2 really large */
#define IMPAIR_BUST_MR2	LELEM(IMPAIR0+3)	/* make MI2 really large */

#define DBG_NONE	0	/* no options on, including impairments */
#define DBG_ALL		LRANGES(DBG_RAW, DBG_NATT)  /* all logging options on EXCEPT DBG_PRIVATE */
#endif

/* State of exchanges
 *
 * The name of the state describes the last message sent, not the
 * message currently being input or output (except during retry).
 * In effect, the state represents the last completed action.
 *
 * Messages are named [MQ][IR]n where
 * - M stands for Main Mode (Phase 1);
 *   Q stands for Quick Mode (Phase 2)
 * - I stands for Initiator;
 *   R stands for Responder
 * - n, a digit, stands for the number of the message
 *
 * It would be more convenient if each state accepted a message
 * and produced one.  This is the case for states at the start
 * or end of an exchange.  To fix this, we pretend that there are
 * MR0 and QR0 messages before the MI1 and QR1 messages.  Similarly,
 * we pretend that there are MR4 and QR2 messages.
 *
 * STATE_MAIN_R0 and STATE_QUICK_R0 are intermediate states (not
 * retained between messages) representing the state that accepts the
 * first message of an exchange has been read but not processed.
 *
 * state_microcode state_microcode_table in demux.c describes
 * other important details.
 */

extern enum_names state_names;
extern const char *const state_story[];

enum state_kind {
    STATE_UNDEFINED,	/* 0 -- most likely accident */

    /*  Opportunism states: see "Opportunistic Encryption" 2.2 */

    OPPO_ACQUIRE,	/* got an ACQUIRE message for this pair */
    OPPO_GW_DISCOVERED,	/* got TXT specifying gateway */

    /* IKE states */

    STATE_MAIN_R0,
    STATE_MAIN_I1,
    STATE_MAIN_R1,
    STATE_MAIN_I2,
    STATE_MAIN_R2,
    STATE_MAIN_I3,
    STATE_MAIN_R3,
    STATE_MAIN_I4,

    STATE_QUICK_R0,
    STATE_QUICK_I1,
    STATE_QUICK_R1,
    STATE_QUICK_I2,
    STATE_QUICK_R2,

    STATE_INFO,
    STATE_INFO_PROTECTED,

    /* Xauth states */
    STATE_XAUTH_R0,              /* server state has sent request, awaiting reply */
    STATE_XAUTH_R1,              /* server state has sent success/fail, awaiting reply */
    STATE_MODE_CFG_R0,
    STATE_MODE_CFG_R1,
    STATE_MODE_CFG_R2,

    STATE_XAUTH_I0,              /* client state is awaiting request */
    STATE_XAUTH_I1,              /* client state is awaiting result code */

    STATE_IKE_ROOF

};

#define STATE_IKE_FLOOR	STATE_MAIN_R0

#define PHASE1_INITIATOR_STATES	 (LELEM(STATE_MAIN_I1) | LELEM(STATE_MAIN_I2) \
    | LELEM(STATE_MAIN_I3) | LELEM(STATE_MAIN_I4))
#define ISAKMP_SA_ESTABLISHED_STATES  (LELEM(STATE_MAIN_R3) | LELEM(STATE_MAIN_I4))

#define IS_PHASE1(s) (STATE_MAIN_R0 <= (s) && (s) <= STATE_MAIN_I4)
#define IS_QUICK(s) (STATE_QUICK_R0 <= (s) && (s) <= STATE_QUICK_R2)
#define IS_ISAKMP_SA_ESTABLISHED(s) ((s) == STATE_MAIN_R3 || (s) == STATE_MAIN_I4 \
				  || (s) == STATE_XAUTH_R0 || (s) == STATE_XAUTH_R1 \
                                  || (s) == STATE_XAUTH_I0 || (s) == STATE_XAUTH_I1)
#define IS_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_I2 || (s) == STATE_QUICK_R2)
#define IS_ONLY_INBOUND_IPSEC_SA_ESTABLISHED(s) ((s) == STATE_QUICK_R1)
#ifdef MODECFG
#define IS_MODE_CFG_ESTABLISHED(s) ((s) == STATE_MODE_CFG_R2)
#endif

/* kind of struct connection
 * Ordered (mostly) by concreteness.  Order is exploited.
 */

extern enum_names connection_kind_names;

enum connection_kind {
    CK_GROUP,		/* policy group: instantiates to template */
    CK_TEMPLATE,	/* abstract connection, with wildcard */
    CK_PERMANENT,	/* normal connection */
    CK_INSTANCE,	/* instance of template, created for a particular attempt */
    CK_GOING_AWAY	/* instance being deleted -- don't delete again */
};


/* routing status.
 * Note: routing ignores source address, but erouting does not!
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */

extern enum_names routing_story;

/* note that this is assumed to be ordered! */
enum routing_t {
    RT_UNROUTED,	/* unrouted */
    RT_UNROUTED_HOLD,	/* unrouted, but HOLD shunt installed */
    RT_ROUTED_ECLIPSED,	/* RT_ROUTED_PROSPECTIVE except bare HOLD or instance has eroute */
    RT_ROUTED_PROSPECTIVE,	/* routed, and prospective shunt installed */
    RT_ROUTED_HOLD,	/* routed, and HOLD shunt installed */
    RT_ROUTED_FAILURE,	/* routed, and failure-context shunt installed */
    RT_ROUTED_TUNNEL,	/* routed, and erouted to an IPSEC SA group */
    RT_UNROUTED_KEYED   /* keyed, but not routed, on purpose */
};

#define routed(rs) ((rs) > RT_UNROUTED_HOLD)
#define erouted(rs) ((rs) != RT_UNROUTED)
#define shunt_erouted(rs) (erouted(rs) && (rs) != RT_ROUTED_TUNNEL)

extern enum_names certpolicy_type_names;

enum certpolicy {
  cert_neversend   = 1,
  cert_sendifasked = 2,    /* the default */
  cert_alwayssend  = 3,
};




/* Payload types
 * RFC2408 Internet Security Association and Key Management Protocol (ISAKMP)
 * section 3.1
 *
 * RESERVED 14-127
 * Private USE 128-255
 */

extern enum_names payload_names;
extern const char *const payload_name[];

#define ISAKMP_NEXT_NONE       0	/* No other payload following */
#define ISAKMP_NEXT_SA         1	/* Security Association */
#define ISAKMP_NEXT_P          2	/* Proposal */
#define ISAKMP_NEXT_T          3	/* Transform */
#define ISAKMP_NEXT_KE         4	/* Key Exchange */
#define ISAKMP_NEXT_ID         5	/* Identification */
#define ISAKMP_NEXT_CERT       6	/* Certificate */
#define ISAKMP_NEXT_CR         7	/* Certificate Request */
#define ISAKMP_NEXT_HASH       8	/* Hash */
#define ISAKMP_NEXT_SIG        9	/* Signature */
#define ISAKMP_NEXT_NONCE      10	/* Nonce */
#define ISAKMP_NEXT_N          11	/* Notification */
#define ISAKMP_NEXT_D          12	/* Delete */
#define ISAKMP_NEXT_VID        13	/* Vendor ID */
#define ISAKMP_NEXT_ATTR       14       /* Mode config Attribute */
#define ISAKMP_NEXT_NATD_RFC   15       /* NAT-Traversal: NAT-D (rfc) */
#define ISAKMP_NEXT_NATOA_RFC  16       /* NAT-Traversal: NAT-OA (rfc) */
#define ISAKMP_NEXT_ROOF       17	/* roof on payload types */
#define ISAKMP_NEXT_NATD_DRAFTS   130   /* NAT-Traversal: NAT-D (drafts) */
#define ISAKMP_NEXT_NATOA_DRAFTS  131   /* NAT-Traversal: NAT-OA (drafts) */

/* These values are to be used within the Type field of an Attribute (14) 
 *    ISAKMP payload.  */
#define ISAKMP_CFG_REQUEST         1
#define ISAKMP_CFG_REPLY           2
#define ISAKMP_CFG_SET             3
#define ISAKMP_CFG_ACK             4

extern enum_names attr_msg_type_names;

/* Mode Config attribute values */
#define    INTERNAL_IP4_ADDRESS        1
#define    INTERNAL_IP4_NETMASK        2
#define    INTERNAL_IP4_DNS            3
#define    INTERNAL_IP4_NBNS           4
#define    INTERNAL_ADDRESS_EXPIRY     5
#define    INTERNAL_IP4_DHCP           6
#define    APPLICATION_VERSION         7
#define    INTERNAL_IP6_ADDRESS        8
#define    INTERNAL_IP6_NETMASK        9
#define    INTERNAL_IP6_DNS           10
#define    INTERNAL_IP6_NBNS          11
#define    INTERNAL_IP6_DHCP          12
#define    INTERNAL_IP4_SUBNET        13
#define    SUPPORTED_ATTRIBUTES       14
#define    INTERNAL_IP6_SUBNET        15

/* XAUTH attribute values */
#define    XAUTH_TYPE                16520
#define    XAUTH_USER_NAME           16521
#define    XAUTH_USER_PASSWORD       16522
#define    XAUTH_PASSCODE            16523
#define    XAUTH_MESSAGE             16524
#define    XAUTH_CHALLENGE           16525
#define    XAUTH_DOMAIN              16526
#define    XAUTH_STATUS              16527
#define    XAUTH_NEXT_PIN            16528
#define    XAUTH_ANSWER              16529

#define XAUTH_TYPE_GENERIC 0
#define XAUTH_TYPE_CHAP    1
#define XAUTH_TYPE_OTP     2
#define XAUTH_TYPE_SKEY    3

extern enum_names modecfg_attr_names;
extern enum_names xauth_type_names;

/* Exchange types
 * RFC2408 "Internet Security Association and Key Management Protocol (ISAKMP)"
 * section 3.1
 *
 * ISAKMP Future Use     6 - 31
 * DOI Specific Use     32 - 239
 * Private Use         240 - 255
 *
 * Note: draft-ietf-ipsec-dhless-enc-mode-00.txt Appendix A
 * defines "DHless RSA Encryption" as 6.
 */

extern enum_names exchange_names;

#define ISAKMP_XCHG_NONE       0
#define ISAKMP_XCHG_BASE       1
#define ISAKMP_XCHG_IDPROT     2	/* ID Protection */
#define ISAKMP_XCHG_AO         3	/* Authentication Only */
#define ISAKMP_XCHG_AGGR       4	/* Aggressive */
#define ISAKMP_XCHG_INFO       5	/* Informational */
#define ISAKMP_XCHG_MODE_CFG   6        /* Mode Config */

/* Extra exchange types, defined by Oakley
 * RFC2409 "The Internet Key Exchange (IKE)", near end of Appendix A
 */
#define ISAKMP_XCHG_QUICK      32	/* Oakley Quick Mode */
#define ISAKMP_XCHG_NGRP       33	/* Oakley New Group Mode */
/* added in draft-ietf-ipsec-ike-01.txt, near end of Appendix A */
#define ISAKMP_XCHG_ACK_INFO   34	/* Oakley Acknowledged Informational */

/* Flag bits */

extern const char *const flag_bit_names[];

#define ISAKMP_FLAG_ENCRYPTION   0x1
#define ISAKMP_FLAG_COMMIT       0x2

/* Situation definition for IPsec DOI */

extern const char *const sit_bit_names[];

#define SIT_IDENTITY_ONLY        0x01
#define SIT_SECRECY              0x02
#define SIT_INTEGRITY            0x04

/* Protocol IDs
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.4.1
 */

extern enum_names protocol_names;

#define PROTO_ISAKMP             1
#define PROTO_IPSEC_AH           2
#define PROTO_IPSEC_ESP          3
#define PROTO_IPCOMP             4

/* warning: trans_show uses enum_show, so same static buffer is used */
#define trans_show(p, t) \
    ((p)==PROTO_IPSEC_AH ? enum_show(&ah_transformid_names, (t)) \
    : (p)==PROTO_IPSEC_ESP ? enum_show(&esp_transformid_names, (t)) \
    : (p)==PROTO_IPCOMP ? enum_show(&ipcomp_transformid_names, (t)) \
    : "??")

/* many transform values are moved to openswan/ipsec_policy.h */

extern enum_names isakmp_transformid_names;

#define KEY_IKE               1

extern enum_names ah_transformid_names;
extern enum_names esp_transformid_names;
extern enum_names ipcomp_transformid_names;

/* the following are from RFC 2393/draft-shacham-ippcp-rfc2393bis-05.txt 3.3 */
typedef u_int16_t cpi_t;
#define IPCOMP_CPI_SIZE          2
#define IPCOMP_FIRST_NEGOTIATED  256
#define IPCOMP_LAST_NEGOTIATED   61439

/* Identification type values
 * RFC 2407 The Internet IP security Domain of Interpretation for ISAKMP 4.6.2.1
 */

extern enum_names ident_names;
extern enum_names cert_type_names;

/* Policies for establishing an SA
 *
 * These are used to specify attributes (eg. encryption) and techniques
 * (eg PFS) for an SA.
 * Note: certain CD_ definitions in whack.c parallel these -- keep them
 * in sync!
 */

extern const char *const sa_policy_bit_names[];
extern const char *prettypolicy(lset_t policy);

/* ISAKMP auth techniques (none means never negotiate) */
#define POLICY_PSK           LELEM(0)
#define POLICY_RSASIG        LELEM(1)

#define POLICY_ISAKMP_SHIFT	0	/* log2(POLICY_PSK) */

/* policies that affect ID types that are acceptable - RSA, PSK, XAUTH */
#define POLICY_ID_AUTH_MASK	LRANGES(POLICY_PSK, POLICY_RSASIG) 

/* policies that affect choices of proposal, note, does not include XAUTH */
#define POLICY_ISAKMP(x,xs,xc)	(((x) & LRANGES(POLICY_PSK, POLICY_RSASIG)) + \
                                 ((xs)*4) + ((xc)*8))

/* Quick Mode (IPSEC) attributes */
#define POLICY_ENCRYPT       LELEM(2)	/* must be first of IPSEC policies */
#define POLICY_AUTHENTICATE  LELEM(3)	/* must be second */
#define POLICY_COMPRESS      LELEM(4)	/* must be third */
#define POLICY_TUNNEL        LELEM(5)
#define POLICY_PFS           LELEM(6)
#define POLICY_DISABLEARRIVALCHECK  LELEM(7)	/* supress tunnel egress address checking */

#define POLICY_IPSEC_SHIFT	2	/* log2(POLICY_ENCRYPT) */
#define POLICY_IPSEC_MASK	LRANGES(POLICY_ENCRYPT, POLICY_DISABLEARRIVALCHECK)

/* shunt attributes: what to do when routed without tunnel (2 bits) */
#define POLICY_SHUNT_SHIFT	8	/* log2(POLICY_SHUNT_PASS) */
#define POLICY_SHUNT_MASK	(03ul << POLICY_SHUNT_SHIFT)

#define POLICY_SHUNT_TRAP	(0ul << POLICY_SHUNT_SHIFT) /* default: negotiate */
#define POLICY_SHUNT_PASS	(1ul << POLICY_SHUNT_SHIFT)
#define POLICY_SHUNT_DROP	(2ul << POLICY_SHUNT_SHIFT)
#define POLICY_SHUNT_REJECT	(3ul << POLICY_SHUNT_SHIFT)

/* fail attributes: what to do with failed negotiation (2 bits) */

#define POLICY_FAIL_SHIFT	10	/* log2(POLICY_FAIL_PASS) */
#define POLICY_FAIL_MASK	(03ul << POLICY_FAIL_SHIFT)

#define POLICY_FAIL_NONE     (0ul << POLICY_FAIL_SHIFT) /* default */
#define POLICY_FAIL_PASS     (1ul << POLICY_FAIL_SHIFT)
#define POLICY_FAIL_DROP     (2ul << POLICY_FAIL_SHIFT)
#define POLICY_FAIL_REJECT   (3ul << POLICY_FAIL_SHIFT)

/* connection policy
 * Other policies could vary per state object.  These live in connection.
 */
#define POLICY_DONT_REKEY     LELEM(12)	/* don't rekey state either Phase */
#define POLICY_OPPO     LELEM(13)	/* is this opportunistic? */
#define POLICY_GROUP	LELEM(14)	/* is this a group template? */
#define POLICY_GROUTED	LELEM(15)	/* do we want this group routed? */
#define POLICY_UP	LELEM(16)	/* do we want this up? */
#define POLICY_XAUTH        LELEM(17)  /* do we offer XAUTH? */
#define POLICY_MODE_CFG	    LELEM(18)  /* do we offer mode configuration? */


/* Any IPsec policy?  If not, a connection description
 * is only for ISAKMP SA, not IPSEC SA.  (A pun, I admit.)
 * Note: a connection can only be routed if it is NEVER_NEGOTIATE
 * or HAS_IPSEC_POLICY.
 */
#define HAS_IPSEC_POLICY(p) (((p) & POLICY_IPSEC_MASK) != 0)

/* Don't allow negotiation? */
#define NEVER_NEGOTIATE(p)  (LDISJOINT((p), POLICY_PSK | POLICY_RSASIG))


/* Oakley transform attributes
 * draft-ietf-ipsec-ike-01.txt appendix A
 */

extern enum_names oakley_attr_names;
extern const char *const oakley_attr_bit_names[];

#define OAKLEY_ENCRYPTION_ALGORITHM    1
#define OAKLEY_HASH_ALGORITHM          2
#define OAKLEY_AUTHENTICATION_METHOD   3
#define OAKLEY_GROUP_DESCRIPTION       4
#define OAKLEY_GROUP_TYPE              5
#define OAKLEY_GROUP_PRIME             6	/* B/V */
#define OAKLEY_GROUP_GENERATOR_ONE     7	/* B/V */
#define OAKLEY_GROUP_GENERATOR_TWO     8	/* B/V */
#define OAKLEY_GROUP_CURVE_A           9	/* B/V */
#define OAKLEY_GROUP_CURVE_B          10	/* B/V */
#define OAKLEY_LIFE_TYPE              11
#define OAKLEY_LIFE_DURATION          12	/* B/V */
#define OAKLEY_PRF                    13
#define OAKLEY_KEY_LENGTH             14
#define OAKLEY_FIELD_SIZE             15
#define OAKLEY_GROUP_ORDER            16	/* B/V */
#define OAKLEY_BLOCK_SIZE             17

/* for each Oakley attribute, which enum_names describes its values? */
extern enum_names *oakley_attr_val_descs[];

/* IPsec DOI attributes
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 */

extern enum_names ipsec_attr_names;

#define SA_LIFE_TYPE             1
#define SA_LIFE_DURATION         2	/* B/V */
#define GROUP_DESCRIPTION        3
#define ENCAPSULATION_MODE       4
#define AUTH_ALGORITHM           5
#define KEY_LENGTH               6
#define KEY_ROUNDS               7
#define COMPRESS_DICT_SIZE       8
#define COMPRESS_PRIVATE_ALG     9	/* B/V */

/* for each IPsec attribute, which enum_names describes its values? */
extern enum_names *ipsec_attr_val_descs[];

/* SA Lifetime Type attribute
 * RFC2407 The Internet IP security Domain of Interpretation for ISAKMP 4.5
 * Default time specified in 4.5
 *
 * There are two defaults for IPSEC SA lifetime, SA_LIFE_DURATION_DEFAULT,
 * and PLUTO_SA_LIFE_DURATION_DEFAULT.
 * SA_LIFE_DURATION_DEFAULT is specified in RFC2407 "The Internet IP
 * Security Domain of Interpretation for ISAKMP" 4.5.  It applies when
 * an ISAKMP negotiation does not explicitly specify a life duration.
 * PLUTO_SA_LIFE_DURATION_DEFAULT is specified in pluto(8).  It applies
 * when a connection description does not specify --ipseclifetime.
 * The value of SA_LIFE_DURATION_MAXIMUM is our local policy.
 */

extern enum_names sa_lifetime_names;

#define SA_LIFE_TYPE_SECONDS   1
#define SA_LIFE_TYPE_KBYTES    2

#define SA_LIFE_DURATION_DEFAULT    28800 /* eight hours (RFC2407 4.5) */
#define PLUTO_SA_LIFE_DURATION_DEFAULT    28800 /* eight hours (pluto(8)) */
#define SA_LIFE_DURATION_MAXIMUM    86400 /* one day */

#define SA_REPLACEMENT_MARGIN_DEFAULT	    540	  /* (IPSEC & IKE) nine minutes */
#define SA_REPLACEMENT_FUZZ_DEFAULT	    100	  /* (IPSEC & IKE) 100% of MARGIN */
#define SA_REPLACEMENT_RETRIES_DEFAULT	    3	/*  (IPSEC & IKE) */

#define SA_LIFE_DURATION_K_DEFAULT  0xFFFFFFFFlu

/* Encapsulation Mode attribute */

extern enum_names enc_mode_names;

#define ENCAPSULATION_MODE_UNSPECIFIED 0	/* not legal -- used internally */
#define ENCAPSULATION_MODE_TUNNEL      1
#define ENCAPSULATION_MODE_TRANSPORT   2

#define ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS       61443
#define ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS    61444
#define ENCAPSULATION_MODE_UDP_TUNNEL_RFC          3
#define ENCAPSULATION_MODE_UDP_TRANSPORT_RFC       4

#ifdef NAT_TRAVERSAL
#define ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS       61443
#define ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS    61444
#define ENCAPSULATION_MODE_UDP_TUNNEL_RFC          3
#define ENCAPSULATION_MODE_UDP_TRANSPORT_RFC       4
#endif

/* Auth Algorithm attribute */

extern enum_names auth_alg_names, extended_auth_alg_names;

#define AUTH_ALGORITHM_NONE        0	/* our private designation */
#define AUTH_ALGORITHM_HMAC_MD5    1
#define AUTH_ALGORITHM_HMAC_SHA1   2
#define AUTH_ALGORITHM_DES_MAC     3
#define AUTH_ALGORITHM_KPDK        4

/* Oakley Lifetime Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * As far as I can see, there is not specification for
 * OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT.  This could lead to interop problems!
 * For no particular reason, we chose one hour.
 * The value of OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM is our local policy.
 */
extern enum_names oakley_lifetime_names;

#define OAKLEY_LIFE_SECONDS   1
#define OAKLEY_LIFE_KILOBYTES 2

#define OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT 3600    /* one hour */
#define OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM 86400   /* 1 day */

/* Oakley PRF attribute (none defined)
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_prf_names;

/* HMAC (see rfc2104.txt) */

#define HMAC_IPAD            0x36
#define HMAC_OPAD            0x5C
#define HMAC_BUFSIZE         64

/* Oakley Encryption Algorithm attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * and from http://www.isi.edu/in-notes/iana/assignments/ipsec-registry
 */

extern enum_names oakley_enc_names;

#define OAKLEY_DES_CBC          1
#define OAKLEY_IDEA_CBC         2
#define OAKLEY_BLOWFISH_CBC     3
#define OAKLEY_RC5_R16_B64_CBC  4
#define OAKLEY_3DES_CBC         5
#define OAKLEY_CAST_CBC         6
#define OAKLEY_AES_CBC          7

/* Oakley Hash Algorithm attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * and from http://www.isi.edu/in-notes/iana/assignments/ipsec-registry
 */

extern enum_names oakley_hash_names;

#define OAKLEY_MD5      1
#define OAKLEY_SHA      2
#define OAKLEY_TIGER    3
#define OAKLEY_SHA2_256        4
#define OAKLEY_SHA2_384        5
#define OAKLEY_SHA2_512        6

/* Oakley Authentication Method attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 * Goofy Hybrid extensions from draft-ietf-ipsec-isakmp-hybrid-auth-05.txt
 * Goofy XAUTH extensions from draft-ietf-ipsec-isakmp-xauth-06.txt
 */

extern enum_names oakley_auth_names;

#define OAKLEY_PRESHARED_KEY       1
#define OAKLEY_DSS_SIG             2
#define OAKLEY_RSA_SIG             3
#define OAKLEY_RSA_ENC             4
#define OAKLEY_RSA_ENC_REV         5
#define OAKLEY_ELGAMAL_ENC         6
#define OAKLEY_ELGAMAL_ENC_REV     7

#define OAKLEY_AUTH_ROOF           8	/* roof on auth values THAT WE SUPPORT */

#define HybridInitRSA                                     64221
#define HybridRespRSA                                     64222
#define HybridInitDSS                                     64223
#define HybridRespDSS                                     64224

/* For XAUTH, store in st->xauth, and set equivalent in st->auth */
#define XAUTHInitPreShared                                65001
#define XAUTHRespPreShared                                65002
#define XAUTHInitDSS                                      65003
#define XAUTHRespDSS                                      65004
#define XAUTHInitRSA                                      65005
#define XAUTHRespRSA                                      65006
#define XAUTHInitRSAEncryption                            65007
#define XAUTHRespRSAEncryption                            65008
#define XAUTHInitRSARevisedEncryption                     65009
#define XAUTHRespRSARevisedEncryption                     65010



/* Oakley Group Description attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_group_names;

#define OAKLEY_GROUP_MODP768       1
#define OAKLEY_GROUP_MODP1024      2
#define OAKLEY_GROUP_GP155         3
#define OAKLEY_GROUP_GP185         4
#define OAKLEY_GROUP_MODP1536      5

/* Oakley Group Type attribute
 * draft-ietf-ipsec-ike-01.txt appendix A
 */
extern enum_names oakley_group_type_names;

#define OAKLEY_GROUP_TYPE_MODP     1
#define OAKLEY_GROUP_TYPE_ECP      2
#define OAKLEY_GROUP_TYPE_EC2N     3


/* Notify messages -- error types
 * See RFC2408 ISAKMP 3.14.1
 */

extern enum_names notification_names;
extern enum_names ipsec_notification_names;

typedef enum {
    NOTHING_WRONG =             0,  /* unofficial! */

    INVALID_PAYLOAD_TYPE =       1,
    DOI_NOT_SUPPORTED =          2,
    SITUATION_NOT_SUPPORTED =    3,
    INVALID_COOKIE =             4,
    INVALID_MAJOR_VERSION =      5,
    INVALID_MINOR_VERSION =      6,
    INVALID_EXCHANGE_TYPE =      7,
    INVALID_FLAGS =              8,
    INVALID_MESSAGE_ID =         9,
    INVALID_PROTOCOL_ID =       10,
    INVALID_SPI =               11,
    INVALID_TRANSFORM_ID =      12,
    ATTRIBUTES_NOT_SUPPORTED =  13,
    NO_PROPOSAL_CHOSEN =        14,
    BAD_PROPOSAL_SYNTAX =       15,
    PAYLOAD_MALFORMED =         16,
    INVALID_KEY_INFORMATION =   17,
    INVALID_ID_INFORMATION =    18,
    INVALID_CERT_ENCODING =     19,
    INVALID_CERTIFICATE =       20,
    CERT_TYPE_UNSUPPORTED =     21,
    INVALID_CERT_AUTHORITY =    22,
    INVALID_HASH_INFORMATION =  23,
    AUTHENTICATION_FAILED =     24,
    INVALID_SIGNATURE =         25,
    ADDRESS_NOTIFICATION =      26,
    NOTIFY_SA_LIFETIME =        27,
    CERTIFICATE_UNAVAILABLE =   28,
    UNSUPPORTED_EXCHANGE_TYPE = 29,
    UNEQUAL_PAYLOAD_LENGTHS =   30,

    /* ISAKMP status type */
    CONNECTED =              16384,

    /* IPSEC DOI additions; status types (RFC2407 IPSEC DOI 4.6.3)
     * These must be sent under the protection of an ISAKMP SA.
     */
    IPSEC_RESPONDER_LIFETIME = 24576,
    IPSEC_REPLAY_STATUS =      24577,
    IPSEC_INITIAL_CONTACT =    24578
    } notification_t;


/* Public key algorithm number
 * Same numbering as used in DNSsec
 * See RFC 2535 DNSsec 3.2 The KEY Algorithm Number Specification.
 * Also found in BIND 8.2.2 include/isc/dst.h as DST algorithm codes.
 */

enum pubkey_alg
{
    PUBKEY_ALG_RSA = 1,
    PUBKEY_ALG_DSA = 3,
};

/* Limits on size of RSA moduli.
 * The upper bound matches that of DNSsec (see RFC 2537).
 * The lower bound must be more than 11 octets for certain
 * the encoding to work, but it must be much larger for any
 * real security.  For now, we require 512 bits.
 */

#define RSA_MIN_OCTETS_RFC	12

#define RSA_MIN_OCTETS	BYTES_FOR_BITS(512)
#define RSA_MIN_OCTETS_UGH	"RSA modulus too small for security: less than 512 bits"

#define RSA_MAX_OCTETS	BYTES_FOR_BITS(4096)
#define RSA_MAX_OCTETS_UGH	"RSA modulus too large: more than 4096 bits"

/* Note: RFC 2537 encoding adds a few bytes.  If you use a small
 * modulus like 3, the overhead is only 2 bytes
 */
#define RSA_MAX_ENCODING_BYTES	(RSA_MAX_OCTETS + 2)

/* socket address family info */

struct af_info
{
    int af;
    const char *name;
    size_t ia_sz;
    size_t sa_sz;
    int mask_cnt;
    u_int8_t id_addr, id_subnet, id_range;
    const ip_address *any;
    const ip_subnet *none;	/* 0.0.0.0/32 or IPv6 equivalent */
    const ip_subnet *all;	/* 0.0.0.0/0 or IPv6 equivalent */
};

extern const struct af_info
    af_inet4_info,
    af_inet6_info;

extern const struct af_info *aftoinfo(int af);

extern enum_names af_names;

#define subnetisaddr(sn, a) (subnetishost(sn) && addrinsubnet((a), (sn)))
extern bool subnetisnone(const ip_subnet *sn);

/* BIND enumerated types */

extern enum_names
    rr_qtype_names,
    rr_type_names,
    rr_class_names;

/* How authenticated is info that might have come from DNS?
 * In order of increasing confidence.
 */
enum dns_auth_level {
    DAL_UNSIGNED,	/* AD in response, but no signature: no authentication */
    DAL_NOTSEC,	/* no AD in response: authentication impossible */
    DAL_SIGNED,	/* AD and signature in response: authentic */
    DAL_LOCAL	/* locally provided (pretty good) */
};

/*
 * define a macro for use in error messages
 */

#ifdef USE_KEYRR
#define RRNAME "TXT or KEY"
#else
#define RRNAME "TXT"
#endif

/*
 * private key types for keys.h
 */
enum PrivateKeyKind {
    PPK_PSK = 1,
    /* PPK_DSS, */	/* not implemented */
    PPK_RSA = 3,
    PPK_PIN = 4
};
extern enum_names ppk_names;

/* natt traversal types */
extern const char *const natt_type_bitnames[];
