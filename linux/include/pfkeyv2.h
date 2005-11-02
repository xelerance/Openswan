/*
 * RCSID $Id: pfkeyv2.h,v 1.31 2005/04/14 01:14:54 mcr Exp $
 */

/*
RFC 2367               PF_KEY Key Management API               July 1998


Appendix D: Sample Header File

This file defines structures and symbols for the PF_KEY Version 2
key management interface. It was written at the U.S. Naval Research
Laboratory. This file is in the public domain. The authors ask that
you leave this credit intact on any copies of this file.
*/
#ifndef __PFKEY_V2_H
#define __PFKEY_V2_H 1

#define PF_KEY_V2 2
#define PFKEYV2_REVISION        199806L

#define SADB_RESERVED    0
#define SADB_GETSPI      1
#define SADB_UPDATE      2
#define SADB_ADD         3
#define SADB_DELETE      4
#define SADB_GET         5
#define SADB_ACQUIRE     6
#define SADB_REGISTER    7
#define SADB_EXPIRE      8
#define SADB_FLUSH       9
#define SADB_DUMP       10
#define SADB_X_PROMISC  11
#define SADB_X_PCHANGE  12
#define SADB_X_GRPSA    13
#define SADB_X_ADDFLOW	14
#define SADB_X_DELFLOW	15
#define SADB_X_DEBUG	16
#define SADB_X_NAT_T_NEW_MAPPING  17
#define SADB_MAX                  17

struct sadb_msg {
  uint8_t sadb_msg_version;
  uint8_t sadb_msg_type;
  uint8_t sadb_msg_errno;
  uint8_t sadb_msg_satype;
  uint16_t sadb_msg_len;
  uint16_t sadb_msg_reserved;
  uint32_t sadb_msg_seq;
  uint32_t sadb_msg_pid;
};

struct sadb_ext {
  uint16_t sadb_ext_len;
  uint16_t sadb_ext_type;
};

struct sadb_sa {
  uint16_t sadb_sa_len;
  uint16_t sadb_sa_exttype;
  uint32_t sadb_sa_spi;
  uint8_t sadb_sa_replay;
  uint8_t sadb_sa_state;
  uint8_t sadb_sa_auth;
  uint8_t sadb_sa_encrypt;
  uint32_t sadb_sa_flags;
  uint32_t /*IPsecSAref_t*/ sadb_x_sa_ref; /* 32 bits */
  uint8_t sadb_x_reserved[4];
};

struct sadb_sa_v1 {
  uint16_t sadb_sa_len;
  uint16_t sadb_sa_exttype;
  uint32_t sadb_sa_spi;
  uint8_t sadb_sa_replay;
  uint8_t sadb_sa_state;
  uint8_t sadb_sa_auth;
  uint8_t sadb_sa_encrypt;
  uint32_t sadb_sa_flags;
};

struct sadb_lifetime {
  uint16_t sadb_lifetime_len;
  uint16_t sadb_lifetime_exttype;
  uint32_t sadb_lifetime_allocations;
  uint64_t sadb_lifetime_bytes;
  uint64_t sadb_lifetime_addtime;
  uint64_t sadb_lifetime_usetime;
  uint32_t sadb_x_lifetime_packets;
  uint32_t sadb_x_lifetime_reserved;
};

struct sadb_address {
  uint16_t sadb_address_len;
  uint16_t sadb_address_exttype;
  uint8_t sadb_address_proto;
  uint8_t sadb_address_prefixlen;
  uint16_t sadb_address_reserved;
};

struct sadb_key {
  uint16_t sadb_key_len;
  uint16_t sadb_key_exttype;
  uint16_t sadb_key_bits;
  uint16_t sadb_key_reserved;
};

struct sadb_ident {
  uint16_t sadb_ident_len;
  uint16_t sadb_ident_exttype;
  uint16_t sadb_ident_type;
  uint16_t sadb_ident_reserved;
  uint64_t sadb_ident_id;
};

struct sadb_sens {
  uint16_t sadb_sens_len;
  uint16_t sadb_sens_exttype;
  uint32_t sadb_sens_dpd;
  uint8_t sadb_sens_sens_level;
  uint8_t sadb_sens_sens_len;
  uint8_t sadb_sens_integ_level;
  uint8_t sadb_sens_integ_len;
  uint32_t sadb_sens_reserved;
};

struct sadb_prop {
  uint16_t sadb_prop_len;
  uint16_t sadb_prop_exttype;
  uint8_t sadb_prop_replay;
  uint8_t sadb_prop_reserved[3];
};

struct sadb_comb {
  uint8_t sadb_comb_auth;
  uint8_t sadb_comb_encrypt;
  uint16_t sadb_comb_flags;
  uint16_t sadb_comb_auth_minbits;
  uint16_t sadb_comb_auth_maxbits;
  uint16_t sadb_comb_encrypt_minbits;
  uint16_t sadb_comb_encrypt_maxbits;
  uint32_t sadb_comb_reserved;
  uint32_t sadb_comb_soft_allocations;
  uint32_t sadb_comb_hard_allocations;
  uint64_t sadb_comb_soft_bytes;
  uint64_t sadb_comb_hard_bytes;
  uint64_t sadb_comb_soft_addtime;
  uint64_t sadb_comb_hard_addtime;
  uint64_t sadb_comb_soft_usetime;
  uint64_t sadb_comb_hard_usetime;
  uint32_t sadb_x_comb_soft_packets;
  uint32_t sadb_x_comb_hard_packets;
};

struct sadb_supported {
  uint16_t sadb_supported_len;
  uint16_t sadb_supported_exttype;
  uint32_t sadb_supported_reserved;
};

struct sadb_alg {
  uint8_t sadb_alg_id;
  uint8_t sadb_alg_ivlen;
  uint16_t sadb_alg_minbits;
  uint16_t sadb_alg_maxbits;
  uint16_t sadb_alg_reserved;
};

struct sadb_spirange {
  uint16_t sadb_spirange_len;
  uint16_t sadb_spirange_exttype;
  uint32_t sadb_spirange_min;
  uint32_t sadb_spirange_max;
  uint32_t sadb_spirange_reserved;
};

struct sadb_x_kmprivate {
  uint16_t sadb_x_kmprivate_len;
  uint16_t sadb_x_kmprivate_exttype;
  uint32_t sadb_x_kmprivate_reserved;
};

struct sadb_x_satype {
  uint16_t sadb_x_satype_len;
  uint16_t sadb_x_satype_exttype;
  uint8_t sadb_x_satype_satype;
  uint8_t sadb_x_satype_reserved[3];
};
  
struct sadb_x_policy {
  uint16_t sadb_x_policy_len;
  uint16_t sadb_x_policy_exttype;
  uint16_t sadb_x_policy_type;
  uint8_t sadb_x_policy_dir;
  uint8_t sadb_x_policy_reserved;
  uint32_t sadb_x_policy_id;
  uint32_t sadb_x_policy_reserved2;
};
 
struct sadb_x_debug {
  uint16_t sadb_x_debug_len;
  uint16_t sadb_x_debug_exttype;
  uint32_t sadb_x_debug_tunnel;
  uint32_t sadb_x_debug_netlink;
  uint32_t sadb_x_debug_xform;
  uint32_t sadb_x_debug_eroute;
  uint32_t sadb_x_debug_spi;
  uint32_t sadb_x_debug_radij;
  uint32_t sadb_x_debug_esp;
  uint32_t sadb_x_debug_ah;
  uint32_t sadb_x_debug_rcv;
  uint32_t sadb_x_debug_pfkey;
  uint32_t sadb_x_debug_ipcomp;
  uint32_t sadb_x_debug_verbose;
  uint8_t sadb_x_debug_reserved[4];
};

struct sadb_x_nat_t_type {
  uint16_t sadb_x_nat_t_type_len;
  uint16_t sadb_x_nat_t_type_exttype;
  uint8_t sadb_x_nat_t_type_type;
  uint8_t sadb_x_nat_t_type_reserved[3];
};
struct sadb_x_nat_t_port {
  uint16_t sadb_x_nat_t_port_len;
  uint16_t sadb_x_nat_t_port_exttype;
  uint16_t sadb_x_nat_t_port_port;
  uint16_t sadb_x_nat_t_port_reserved;
};

/*
 * A protocol structure for passing through the transport level
 * protocol.  It contains more fields than are actually used/needed
 * but it is this way to be compatible with the structure used in
 * OpenBSD (http://www.openbsd.org/cgi-bin/cvsweb/src/sys/net/pfkeyv2.h)
 */
struct sadb_protocol {
  uint16_t sadb_protocol_len;
  uint16_t sadb_protocol_exttype;
  uint8_t  sadb_protocol_proto;
  uint8_t  sadb_protocol_direction;
  uint8_t  sadb_protocol_flags;
  uint8_t  sadb_protocol_reserved2;
};

#define SADB_EXT_RESERVED             0
#define SADB_EXT_SA                   1
#define SADB_EXT_LIFETIME_CURRENT     2
#define SADB_EXT_LIFETIME_HARD        3
#define SADB_EXT_LIFETIME_SOFT        4
#define SADB_EXT_ADDRESS_SRC          5
#define SADB_EXT_ADDRESS_DST          6
#define SADB_EXT_ADDRESS_PROXY        7
#define SADB_EXT_KEY_AUTH             8
#define SADB_EXT_KEY_ENCRYPT          9
#define SADB_EXT_IDENTITY_SRC         10
#define SADB_EXT_IDENTITY_DST         11
#define SADB_EXT_SENSITIVITY          12
#define SADB_EXT_PROPOSAL             13
#define SADB_EXT_SUPPORTED_AUTH       14
#define SADB_EXT_SUPPORTED_ENCRYPT    15
#define SADB_EXT_SPIRANGE             16
#define SADB_X_EXT_KMPRIVATE          17
#define SADB_X_EXT_SATYPE2            18
#ifdef KERNEL26_HAS_KAME_DUPLICATES
#define SADB_X_EXT_POLICY             18
#endif
#define SADB_X_EXT_SA2                19
#define SADB_X_EXT_ADDRESS_DST2       20
#define SADB_X_EXT_ADDRESS_SRC_FLOW   21
#define SADB_X_EXT_ADDRESS_DST_FLOW   22
#define SADB_X_EXT_ADDRESS_SRC_MASK   23
#define SADB_X_EXT_ADDRESS_DST_MASK   24
#define SADB_X_EXT_DEBUG              25
#define SADB_X_EXT_PROTOCOL           26
#define SADB_X_EXT_NAT_T_TYPE         27
#define SADB_X_EXT_NAT_T_SPORT        28
#define SADB_X_EXT_NAT_T_DPORT        29
#define SADB_X_EXT_NAT_T_OA           30
#define SADB_EXT_MAX                  30

/* SADB_X_DELFLOW required over and above SADB_X_SAFLAGS_CLEARFLOW */
#define SADB_X_EXT_ADDRESS_DELFLOW \
	( (1<<SADB_X_EXT_ADDRESS_SRC_FLOW) \
	| (1<<SADB_X_EXT_ADDRESS_DST_FLOW) \
	| (1<<SADB_X_EXT_ADDRESS_SRC_MASK) \
	| (1<<SADB_X_EXT_ADDRESS_DST_MASK))

#define SADB_SATYPE_UNSPEC    0
#define SADB_SATYPE_AH        2
#define SADB_SATYPE_ESP       3
#define SADB_SATYPE_RSVP      5
#define SADB_SATYPE_OSPFV2    6
#define SADB_SATYPE_RIPV2     7
#define SADB_SATYPE_MIP       8
#define SADB_X_SATYPE_IPIP    9
#ifdef KERNEL26_HAS_KAME_DUPLICATES
#define SADB_X_SATYPE_IPCOMP  9   /* ICK! */
#endif
#define SADB_X_SATYPE_COMP    10
#define SADB_X_SATYPE_INT     11
#define SADB_SATYPE_MAX       11

enum sadb_sastate {
  SADB_SASTATE_LARVAL=0,
  SADB_SASTATE_MATURE=1,
  SADB_SASTATE_DYING=2,
  SADB_SASTATE_DEAD=3
};
#define SADB_SASTATE_MAX 3

#define SADB_SAFLAGS_PFS		1
#define SADB_X_SAFLAGS_REPLACEFLOW	2
#define SADB_X_SAFLAGS_CLEARFLOW	4
#define SADB_X_SAFLAGS_INFLOW		8

/* not obvious, but these are the same values as used in isakmp,
 * and in freeswan/ipsec_policy.h. If you need to add any, they
 * should be added as according to 
 *   http://www.iana.org/assignments/isakmp-registry
 * 
 * and if not, then please try to use a private-use value, and
 * consider asking IANA to assign a value.
 */
#define SADB_AALG_NONE                  0
#define SADB_AALG_MD5HMAC               2
#define SADB_AALG_SHA1HMAC              3
#define SADB_X_AALG_SHA2_256HMAC	5
#define SADB_X_AALG_SHA2_384HMAC	6
#define SADB_X_AALG_SHA2_512HMAC	7
#define SADB_X_AALG_RIPEMD160HMAC	8
#define SADB_X_AALG_NULL		251	/* kame */
#define SADB_AALG_MAX			251

#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC		6
#define SADB_X_EALG_BLOWFISHCBC		7
#define SADB_EALG_NULL			11
#define SADB_X_EALG_AESCBC		12
#define SADB_EALG_MAX			255

#define SADB_X_CALG_NONE          0
#define SADB_X_CALG_OUI           1
#define SADB_X_CALG_DEFLATE       2
#define SADB_X_CALG_LZS           3
#define SADB_X_CALG_V42BIS        4
#ifdef KERNEL26_HAS_KAME_DUPLICATES
#define SADB_X_CALG_LZJH          4
#endif
#define SADB_X_CALG_MAX           4

#define SADB_X_TALG_NONE          0
#define SADB_X_TALG_IPv4_in_IPv4  1
#define SADB_X_TALG_IPv6_in_IPv4  2
#define SADB_X_TALG_IPv4_in_IPv6  3
#define SADB_X_TALG_IPv6_in_IPv6  4
#define SADB_X_TALG_MAX           4


#define SADB_IDENTTYPE_RESERVED   0
#define SADB_IDENTTYPE_PREFIX     1
#define SADB_IDENTTYPE_FQDN       2
#define SADB_IDENTTYPE_USERFQDN   3
#define SADB_X_IDENTTYPE_CONNECTION 4
#define SADB_IDENTTYPE_MAX        4

#define SADB_KEY_FLAGS_MAX     0
#endif /* __PFKEY_V2_H */

/*
 * $Log: pfkeyv2.h,v $
 * Revision 1.31  2005/04/14 01:14:54  mcr
 * 	change sadb_state to an enum.
 *
 * Revision 1.30  2004/04/06 02:49:00  mcr
 * 	pullup of algo code from alg-branch.
 *
 * Revision 1.29  2003/12/22 21:35:58  mcr
 * 	new patches from Dr{Who}.
 *
 * Revision 1.28  2003/12/22 19:33:15  mcr
 * 	added 0.6c NAT-T patch.
 *
 * Revision 1.27  2003/12/10 01:20:01  mcr
 * 	NAT-traversal patches to KLIPS.
 *
 * Revision 1.26  2003/10/31 02:26:44  mcr
 * 	pulled up port-selector patches.
 *
 * Revision 1.25.4.1  2003/09/21 13:59:34  mcr
 * 	pre-liminary X.509 patch - does not yet pass tests.
 *
 * Revision 1.25  2003/07/31 23:59:17  mcr
 * 	re-introduce kernel 2.6 duplicate values for now.
 * 	hope to get them changed!
 *
 * Revision 1.24  2003/07/31 22:55:27  mcr
 * 	added some definitions to keep pfkeyv2.h files in sync.
 *
 * Revision 1.23  2003/05/11 00:43:48  mcr
 * 	added comment about origin of values used
 *
 * Revision 1.22  2003/01/30 02:31:34  rgb
 *
 * Convert IPsecSAref_t from signed to unsigned to fix apparent SAref exhaustion bug.
 *
 * Revision 1.21  2002/12/16 19:26:49  mcr
 * 	added definition of FS 1.xx sadb structure
 *
 * Revision 1.20  2002/09/20 15:40:25  rgb
 * Added sadb_x_sa_ref to struct sadb_sa.
 *
 * Revision 1.19  2002/04/24 07:36:49  mcr
 * Moved from ./lib/pfkeyv2.h,v
 *
 * Revision 1.18  2001/11/06 19:47:47  rgb
 * Added packet parameter to lifetime and comb structures.
 *
 * Revision 1.17  2001/09/08 21:13:35  rgb
 * Added pfkey ident extension support for ISAKMPd. (NetCelo)
 *
 * Revision 1.16  2001/07/06 19:49:46  rgb
 * Added SADB_X_SAFLAGS_INFLOW for supporting incoming policy checks.
 *
 * Revision 1.15  2001/02/26 20:00:43  rgb
 * Added internal IP protocol 61 for magic SAs.
 *
 * Revision 1.14  2001/02/08 18:51:05  rgb
 * Include RFC document title and appendix subsection title.
 *
 * Revision 1.13  2000/10/10 20:10:20  rgb
 * Added support for debug_ipcomp and debug_verbose to klipsdebug.
 *
 * Revision 1.12  2000/09/15 06:41:50  rgb
 * Added V42BIS constant.
 *
 * Revision 1.11  2000/09/12 22:35:37  rgb
 * Restructured to remove unused extensions from CLEARFLOW messages.
 *
 * Revision 1.10  2000/09/12 18:50:09  rgb
 * Added IPIP tunnel types as algo support.
 *
 * Revision 1.9  2000/08/21 16:47:19  rgb
 * Added SADB_X_CALG_* macros for IPCOMP.
 *
 * Revision 1.8  2000/08/09 20:43:34  rgb
 * Fixed bitmask value for SADB_X_SAFLAGS_CLEAREROUTE.
 *
 * Revision 1.7  2000/01/21 06:28:37  rgb
 * Added flow add/delete message type macros.
 * Added flow address extension type macros.
 * Tidied up spacing.
 * Added klipsdebug switching capability.
 *
 * Revision 1.6  1999/11/27 11:56:08  rgb
 * Add SADB_X_SATYPE_COMP for compression, eventually.
 *
 * Revision 1.5  1999/11/23 22:23:16  rgb
 * This file has been moved in the distribution from klips/net/ipsec to
 * lib.
 *
 * Revision 1.4  1999/04/29 15:23:29  rgb
 * Add GRPSA support.
 * Add support for a second SATYPE, SA and DST_ADDRESS.
 * Add IPPROTO_IPIP support.
 *
 * Revision 1.3  1999/04/15 17:58:08  rgb
 * Add RCSID labels.
 *
 */
