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

#include <linux/pfkeyv2.h>

#define PF_KEY_V2               2
#define PFKEYV2_REVISION        199806L

enum sadb_msg_t {
	K_SADB_RESERVED=SADB_RESERVED,
	K_SADB_GETSPI=SADB_GETSPI,
	K_SADB_UPDATE=SADB_UPDATE,
	K_SADB_ADD=SADB_ADD,
	K_SADB_DELETE=SADB_DELETE,
	K_SADB_GET=SADB_GET,
	K_SADB_ACQUIRE=SADB_ACQUIRE,
	K_SADB_REGISTER=SADB_REGISTER,
	K_SADB_EXPIRE=SADB_EXPIRE,
	K_SADB_FLUSH=SADB_FLUSH,
	K_SADB_DUMP=SADB_DUMP,
	K_SADB_X_PROMISC=SADB_X_PROMISC,
	K_SADB_X_PCHANGE=SADB_X_PCHANGE,
	K_SADB_X_GRPSA=13,
	K_SADB_X_ADDFLOW=14,
	K_SADB_X_DELFLOW=15,
	K_SADB_X_DEBUG=16,
	K_SADB_X_NAT_T_NEW_MAPPING=17,
	K_SADB_X_PLUMBIF=18,
	K_SADB_X_UNPLUMBIF=19,
	K_SADB_MAX=19
};

#define SADB_X_GRPSA	    K_SADB_X_GRPSA		    
#define SADB_X_ADDFLOW	    K_SADB_X_ADDFLOW	    
#define SADB_X_DELFLOW	    K_SADB_X_DELFLOW	    
#define SADB_X_DEBUG	    K_SADB_X_DEBUG		    
#define SADB_X_PLUMBIF	    K_SADB_X_PLUMBIF	    
#define SADB_X_UNPLUMBIF    K_SADB_X_UNPLUMBIF	    

struct k_sadb_sa {
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
} __attribute__((packed));

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

struct sadb_x_satype {
  uint16_t sadb_x_satype_len;
  uint16_t sadb_x_satype_exttype;
  uint8_t sadb_x_satype_satype;
  uint8_t sadb_x_satype_reserved[3];
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

/*
 * a plumbif extension can appear in
 *          - a plumbif message to create the interface.
 *          - a unplumbif message to delete the interface.
 *          - a sadb add/replace to indicate which interface
 *                   a decrypted packet should emerge on.
 *
 * the create/delete part could/should be replaced with netlink equivalents,
 * or better yet, FORCES versions of same.
 * 
 */
struct sadb_x_plumbif {
	uint16_t sadb_x_outif_len;
	uint16_t sadb_x_outif_exttype;
	uint16_t sadb_x_outif_ifnum;
};

/*
 * devices 0-40959 are mastXXX devices.
 * devices 40960-49141 are mastXXX devices with transport set.
 * devices 49152-65536 are deprecated ipsecXXX devices.
 */
#define IPSECDEV_OFFSET       (48*1024)
#define MASTTRANSPORT_OFFSET  (40*1024)

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

/*
 * NOTE that there is a limit of 31 extensions due to current implementation
 * in pfkeyv2_ext_bits.c
 */
enum sadb_extension_t {
	K_SADB_EXT_RESERVED=SADB_RESERVED,
	K_SADB_EXT_SA=              SADB_EXT_SA,
	K_SADB_EXT_LIFETIME_CURRENT=SADB_EXT_LIFETIME_CURRENT,
	K_SADB_EXT_LIFETIME_HARD=   SADB_EXT_LIFETIME_HARD,
	K_SADB_EXT_LIFETIME_SOFT=   SADB_EXT_LIFETIME_SOFT,
	K_SADB_EXT_ADDRESS_SRC=     SADB_EXT_ADDRESS_SRC,
	K_SADB_EXT_ADDRESS_DST=     SADB_EXT_ADDRESS_DST,
	K_SADB_EXT_ADDRESS_PROXY=   SADB_EXT_ADDRESS_PROXY,
	K_SADB_EXT_KEY_AUTH=        SADB_EXT_KEY_AUTH,
	K_SADB_EXT_KEY_ENCRYPT=     SADB_EXT_KEY_ENCRYPT,
	K_SADB_EXT_IDENTITY_SRC=    SADB_EXT_IDENTITY_SRC,
	K_SADB_EXT_IDENTITY_DST=    SADB_EXT_IDENTITY_DST,
	K_SADB_EXT_SENSITIVITY=     SADB_EXT_SENSITIVITY,
	K_SADB_EXT_PROPOSAL=        SADB_EXT_PROPOSAL,
	K_SADB_EXT_SUPPORTED_AUTH=  SADB_EXT_SUPPORTED_AUTH,
	K_SADB_EXT_SUPPORTED_ENCRYPT=SADB_EXT_SUPPORTED_ENCRYPT,
	K_SADB_EXT_SPIRANGE=        SADB_EXT_SPIRANGE,
	K_SADB_X_EXT_KMPRIVATE=     SADB_X_EXT_KMPRIVATE,
	K_SADB_X_EXT_SATYPE2=       18,
	K_SADB_X_EXT_POLICY=        SADB_X_EXT_POLICY,
	K_SADB_X_EXT_SA2=           SADB_X_EXT_SA2,
	K_SADB_X_EXT_ADDRESS_DST2=  20,
	K_SADB_X_EXT_ADDRESS_SRC_FLOW=21,
	K_SADB_X_EXT_ADDRESS_DST_FLOW=22,
	K_SADB_X_EXT_ADDRESS_SRC_MASK=23,
	K_SADB_X_EXT_ADDRESS_DST_MASK=24,
	K_SADB_X_EXT_DEBUG=         25,
	K_SADB_X_EXT_PROTOCOL=      26,
	K_SADB_X_EXT_NAT_T_TYPE=    27,
	K_SADB_X_EXT_NAT_T_SPORT=   28,
	K_SADB_X_EXT_NAT_T_DPORT=   29,
	K_SADB_X_EXT_NAT_T_OA=      30,
	K_SADB_X_EXT_PLUMBIF=       31,
	K_SADB_EXT_MAX=             31,
};


#define SADB_X_EXT_SATYPE2		K_SADB_X_EXT_SATYPE2		
#define SADB_X_EXT_ADDRESS_DST2	        K_SADB_X_EXT_ADDRESS_DST2	
#define SADB_X_EXT_ADDRESS_SRC_FLOW	K_SADB_X_EXT_ADDRESS_SRC_FLOW	
#define SADB_X_EXT_ADDRESS_DST_FLOW	K_SADB_X_EXT_ADDRESS_DST_FLOW	
#define SADB_X_EXT_ADDRESS_SRC_MASK	K_SADB_X_EXT_ADDRESS_SRC_MASK	
#define SADB_X_EXT_ADDRESS_DST_MASK	K_SADB_X_EXT_ADDRESS_DST_MASK	
#define SADB_X_EXT_DEBUG		K_SADB_X_EXT_DEBUG		
#define SADB_X_EXT_PROTOCOL		K_SADB_X_EXT_PROTOCOL		

#undef SADB_X_EXT_NAT_T_TYPE		
#undef SADB_X_EXT_NAT_T_SPORT	        
#undef SADB_X_EXT_NAT_T_DPORT	        
#undef SADB_X_EXT_NAT_T_OA		
#define SADB_X_EXT_PLUMBIF		K_SADB_X_EXT_PLUMBIF		



/* K_SADB_X_DELFLOW required over and above K_SADB_X_SAFLAGS_CLEARFLOW */
#define K_SADB_X_EXT_ADDRESS_DELFLOW \
	( (1<<K_SADB_X_EXT_ADDRESS_SRC_FLOW) \
	| (1<<K_SADB_X_EXT_ADDRESS_DST_FLOW) \
	| (1<<K_SADB_X_EXT_ADDRESS_SRC_MASK) \
	| (1<<K_SADB_X_EXT_ADDRESS_DST_MASK))

enum sadb_satype {
	K_SADB_SATYPE_UNSPEC=SADB_SATYPE_UNSPEC,
	K_SADB_SATYPE_AH=SADB_SATYPE_AH,
	K_SADB_SATYPE_ESP=SADB_SATYPE_ESP,
	K_SADB_SATYPE_RSVP=SADB_SATYPE_RSVP,
	K_SADB_SATYPE_OSPFV2=SADB_SATYPE_OSPFV2,
	K_SADB_SATYPE_RIPV2=SADB_SATYPE_RIPV2,
	K_SADB_SATYPE_MIP=SADB_SATYPE_MIP,
	K_SADB_X_SATYPE_IPIP=9,
	K_SADB_X_SATYPE_COMP=10,
	K_SADB_X_SATYPE_INT=11
};
#define K_SADB_SATYPE_MAX       11

enum sadb_sastate {
  K_SADB_SASTATE_LARVAL=0,
  K_SADB_SASTATE_MATURE=1,
  K_SADB_SASTATE_DYING=2,
  K_SADB_SASTATE_DEAD=3
};
#undef  SADB_SASTATE_LARVAL
#undef  SADB_SASTATE_MATURE
#undef  SADB_SASTATE_DYING
#undef  SADB_SASTATE_DEAD
#define K_SADB_SASTATE_MAX 3

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
#define K_SADB_AALG_MAX			251

#define SADB_EALG_NONE                  0
#define SADB_EALG_DESCBC                2
#define SADB_EALG_3DESCBC               3
#define SADB_X_EALG_CASTCBC		6
#define SADB_X_EALG_BLOWFISHCBC		7
#define SADB_EALG_NULL			11
#define SADB_X_EALG_AESCBC		12
#undef SADB_EALG_MAX
#define K_SADB_EALG_MAX			255

#define SADB_X_CALG_NONE          0
#define SADB_X_CALG_OUI           1
#define SADB_X_CALG_DEFLATE       2
#define SADB_X_CALG_LZS           3
#define SADB_X_CALG_V42BIS        4
#ifdef KERNEL26_HAS_KAME_DUPLICATES
#define K_SADB_X_CALG_LZJH          4
#endif
#define K_SADB_X_CALG_MAX           4

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
#define K_SADB_IDENTTYPE_MAX        4

#define K_SADB_KEY_FLAGS_MAX     0
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
