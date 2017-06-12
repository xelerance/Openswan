/* parsing packets: formats and tools
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2017 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
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

#ifndef _PACKET_H
#define _PACKET_H

/* a struct_desc describes a structure for the struct I/O routines.
 * This requires arrays of field_desc values to describe struct fields.
 */

typedef const struct struct_desc {
    const char *name;
    const struct field_desc *fields;
    size_t size;
} struct_desc;

/* Note: if an ft_af_enum field has the ISAKMP_ATTR_AF_TV bit set,
 * the subsequent ft_lv field will be interpreted as an immediate value.
 * This matches how attributes are encoded.
 * See RFC 2408 "ISAKMP" 3.3
 */

enum field_type {
    ft_mbz,	/* must be zero, abort */
    ft_nat,	/* natural number (may be 0) */
    ft_len,	/* length of this struct and any following crud */
    ft_lv,	/* length/value field of attribute */
    ft_enum,	/* value from an enumeration */
    ft_loose_enum, /* value from an enumeration with only some names known */
    ft_af_enum,	/* Attribute Format + value from an enumeration */
    ft_af_loose_enum, /* Attribute Format + enumeration, some names known */
    ft_set,	/* bits representing set */
    ft_raw,	/* bytes to be left in network-order */
    ft_np,	/* enum of ISAKMP next payload values, location noted */
    ft_np_in,	/* ditto, but inside structure location noted */
    ft_zig,	/* should be zero, ignore if not. Continue */
    ft_end,	/* end of field list */
};

typedef const struct field_desc {
    enum field_type field_type;
    int	size;	/* size, in bytes, of field */
    const char *name;
    const void *desc;	/* enum_names for enum or char *[] for bits */
} field_desc;

/* The formatting of input and output of packets is done
 * through packet_byte_stream objects.
 * These describe a stream of bytes in memory.
 * Several routines are provided to manipulate these objects
 * Actual packet transfer is done elsewhere.
 */
struct packet_byte_stream
{
    struct packet_byte_stream *container;   /* PBS of which we are part */
    struct_desc *desc;
    const char *name;	/* what does this PBS represent? */
    u_int8_t
	*start,
	*cur,	/* current position in stream */
	*roof;	/* byte after last in PBS (actually just a limit on output) */

    u_int8_t   *next_payload_pointer;

    /* For an output PBS, the length field will be filled in later so
     * we need to record its particulars.  Note: it may not be aligned.
     */
    u_int8_t *lenfld;
    field_desc *lenfld_desc;
};
typedef struct packet_byte_stream pb_stream;

/* For an input PBS, pbs_offset is amount of stream processed.
 * For an output PBS, pbs_offset is current size of stream.
 * For an input PBS, pbs_room is size of stream.
 * For an output PBS, pbs_room is maximum size allowed.
 */
#define pbs_offset(pbs) ((size_t)((pbs)->cur - (pbs)->start))
#define pbs_room(pbs) ((size_t)((pbs)->roof - (pbs)->start))
#define pbs_left(pbs) ((size_t)((pbs)->roof - (pbs)->cur))

extern void init_pbs(pb_stream *pbs, u_int8_t *start, size_t len, const char *name);
extern void init_sub_pbs(pb_stream *parent_pbs, pb_stream *child_pbs, const char *name);

extern bool in_struct(void *struct_ptr, struct_desc *sd,
    pb_stream *ins, pb_stream *obj_pbs);
extern bool in_raw(void *bytes, size_t len, pb_stream *ins, const char *name);

extern bool out_struct(const void *struct_ptr, struct_desc *sd,
    pb_stream *outs, pb_stream *obj_pbs);
extern void pbs_set_np(pb_stream *outs, u_int8_t np);
extern void pbs_copy_np(pb_stream *from, pb_stream *to);

extern bool out_generic(u_int8_t np, struct_desc *sd,
    pb_stream *outs, pb_stream *obj_pbs);
extern bool out_generic_raw(u_int8_t np, struct_desc *sd,
    pb_stream *outs, const void *bytes, size_t len, const char *name);
#if 1
extern bool out_modify_previous_np(u_int8_t np, pb_stream *outs);
#endif
#define out_generic_chunk(np, sd, outs, ch, name) \
	out_generic_raw(np, sd, outs, (ch).ptr, (ch).len, name)
extern bool out_zero(size_t len, pb_stream *outs, const char *name);
extern bool out_raw(const void *bytes, size_t len, pb_stream *outs, const char *name);
#define out_chunk(ch, outs, name) out_raw((ch).ptr, (ch).len, (outs), (name))
extern void close_output_pbs(pb_stream *pbs);

#ifdef DEBUG
#define DBG_dump_pbs(pbs) DBG_dump((pbs)->name, (pbs)->start, pbs_offset(pbs))
extern void DBG_print_struct(const char *label, const void *struct_ptr,
    struct_desc *sd, bool len_meaningful);
#else
#define DBG_dump_pbs(pbs) do {} while(0)
#endif

/* ISAKMP Header: for all messages
 * layout from RFC 2408 "ISAKMP" section 3.1
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Initiator                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Responder                            !
 * !                            Cookie                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                          Message ID                           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                            Length                             !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * Although the drafts are a little unclear, there are a few
 * places that specify that messages should be padded with 0x00
 * octets (bytes) to make the length a multiple of something.
 *
 * RFC 2408 "ISAKMP" 3.6 specifies that all messages will be
 * padded to be a multiple of 4 octets in length.
 * ??? This looks vestigial, and we ignore this requirement.
 *
 * RFC 2409 "IKE" Appedix B specifies:
 *     Each message should be padded up to the nearest block size
 *     using bytes containing 0x00.
 * ??? This does not appear to be limited to encrypted messages,
 * but it surely must be: the block size is meant to be the encryption
 * block size, and that is meaningless for a non-encrypted message.
 *
 * RFC 2409 "IKE" 5.3 specifies:
 *     Encrypted payloads are padded up to the nearest block size.
 *     All padding bytes, except for the last one, contain 0x00. The
 *     last byte of the padding contains the number of the padding
 *     bytes used, excluding the last one. Note that this means there
 *     will always be padding.
 * ??? This is nuts since payloads are not padded, messages are.
 * It also contradicts Appendix B.  So we ignore it.
 *
 * Summary: we pad encrypted output messages with 0x00 to bring them
 * up to a multiple of the encryption block size.  On input, we require
 * that any encrypted portion of a message be a multiple of the encryption
 * block size.   After any decryption, we ignore padding (any bytes after
 * the first payload that specifies a next payload of none; we don't
 * require them to be zero).
 */

#define NSIZEOF_isakmp_hdr      28      /* on-the-wire sizeof struct isakmpg_hdr */
#define NOFFSETOF_isa_np        16       /* on-the-wire offset of isa_np (one octet) */
#define NOFFSETOF_isag_length   2       /* on-the-wire offset of isag_length (two octets, network order */
#define NOFFSETOF_isag_np       0       /* on-the-wire offset of isag_np (one octet) */
#define NSIZEOF_isakmp_generic  4       /* on-the-wire sizeof isakmp_generic) */

struct isakmp_hdr
{
    u_int8_t    isa_icookie[COOKIE_SIZE];
    u_int8_t    isa_rcookie[COOKIE_SIZE];
    u_int8_t    isa_np;                 /* Next payload */
    u_int8_t	isa_version;	/* high-order 4 bits: Major; low order 4: Minor */
    u_int8_t    isa_xchg;		/* Exchange type */
    u_int8_t    isa_flags;
    u_int32_t   isa_msgid;		/* Message ID (RAW) */
    u_int32_t   isa_length;		/* Length of message */
};

extern struct_desc isakmp_hdr_desc;

/* Generic portion of all ISAKMP payloads.
 * layout from RFC 2408 "ISAKMP" section 3.2
 * This describes the first 32-bit chunk of all payloads.
 * The previous next payload depends on the actual payload type.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_generic
{
    u_int8_t    isag_np;
    u_int8_t    isag_reserved;
    u_int16_t   isag_length;
};

extern struct_desc isakmp_generic_desc;

/* ISAKMP Data Attribute (generic representation within payloads)
 * layout from RFC 2408 "ISAKMP" section 3.3
 * This is not a payload type.
 * In TLV format, this is followed by a value field.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !A!       Attribute Type        !    AF=0  Attribute Length     !
 * !F!                             !    AF=1  Attribute Value      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * .                   AF=0  Attribute Value                       .
 * .                   AF=1  Not Transmitted                       .
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_attribute
{
    /* The high order bit of isaat_af_type is the Attribute Format
     * If it is off, the format is TLV: lv is the length of the following
     * attribute value.
     * If it is on, the format is TV: lv is the value of the attribute.
     * ISAKMP_ATTR_AF_MASK is the mask in host form.
     *
     * The low order 15 bits of isaat_af_type is the Attribute Type.
     * ISAKMP_ATTR_RTYPE_MASK is the mask in host form.
     */
    u_int16_t isaat_af_type;   /* high order bit: AF; lower 15: rtype */
    u_int16_t isaat_lv;			/* Length or value */
};

extern struct_desc
    isakmp_oakley_attribute_desc,
    isakmp_ipsec_attribute_desc,
    ikev2_trans_attr_desc;

/* ISAKMP Security Association Payload
 * layout from RFC 2408 "ISAKMP" section 3.4
 * A variable length Situation follows.
 * Previous next payload: ISAKMP_NEXT_SA
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                           Situation                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_sa
{
    u_int8_t  isasa_np;			/* Next payload */
    u_int8_t  isasa_reserved;
    u_int16_t isasa_length;		/* Payload length */
    u_int32_t isasa_doi;		/* DOI */
};

extern struct_desc isakmp_sa_desc;

extern struct_desc ipsec_sit_desc;

/* ISAKMP Proposal Payload
 * layout from RFC 2408 "ISAKMP" section 3.5
 * A variable length SPI follows.
 * Previous next payload: ISAKMP_NEXT_P
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Proposal #   !  Protocol-Id  !    SPI Size   !# of Transforms!
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                        SPI (variable)                         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_proposal
{
    u_int8_t    isap_np;
    u_int8_t    isap_reserved;
    u_int16_t   isap_length;
    u_int8_t    isap_proposal;
    u_int8_t    isap_protoid;
    u_int8_t    isap_spisize;
    u_int8_t    isap_notrans;		/* Number of transforms */
};

extern struct_desc isakmp_proposal_desc;

/* ISAKMP Transform Payload
 * layout from RFC 2408 "ISAKMP" section 3.6
 * Variable length SA Attributes follow.
 * Previous next payload: ISAKMP_NEXT_T
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Transform #  !  Transform-Id !           RESERVED2           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                        SA Attributes                          ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_transform
{
    u_int8_t    isat_np;
    u_int8_t    isat_reserved;
    u_int16_t   isat_length;
    u_int8_t    isat_transnum;		/* Number of the transform */
    u_int8_t    isat_transid;
    u_int16_t   isat_reserved2;
};

extern struct_desc
    isakmp_isakmp_transform_desc,
    isakmp_ah_transform_desc,
    isakmp_esp_transform_desc,
    isakmp_ipcomp_transform_desc;

/* ISAKMP Key Exchange Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.7
 * Variable Key Exchange Data follow the generic fields.
 * Previous next payload: ISAKMP_NEXT_KE
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Key Exchange Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_keyex_desc;

/* ISAKMP Identification Payload
 * layout from RFC 2408 "ISAKMP" section 3.8
 * See "struct identity" declared later.
 * Variable length Identification Data follow.
 * Previous next payload: ISAKMP_NEXT_ID
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !             DOI Specific ID Data              !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                   Identification Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_id
{
    u_int8_t    isaid_np;
    u_int8_t    isaid_reserved;
    u_int16_t   isaid_length;
    u_int8_t    isaid_idtype;
    u_int8_t    isaid_doi_specific_a;
    u_int16_t   isaid_doi_specific_b;
};

extern struct_desc isakmp_identification_desc;

/* IPSEC Identification Payload Content
 * layout from RFC 2407 "IPsec DOI" section 4.6.2
 * See struct isakmp_id declared earlier.
 * Note: Hashing skips the ISAKMP generic payload header
 * Variable length Identification Data follow.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Next Payload !   RESERVED    !        Payload Length         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !   ID Type     !  Protocol ID  !             Port              !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                     Identification Data                       ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_ipsec_id
{
    u_int8_t    isaiid_np;
    u_int8_t    isaiid_reserved;
    u_int16_t   isaiid_length;
    u_int8_t    isaiid_idtype;
    u_int8_t    isaiid_protoid;
    u_int16_t   isaiid_port;
};

extern struct_desc isakmp_ipsec_identification_desc;

/* ISAKMP Certificate Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.9
 * Variable length Certificate Data follow the generic fields.
 * Previous next payload: ISAKMP_NEXT_CERT.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Cert Encoding !                                               !
 * +-+-+-+-+-+-+-+-+                                               !
 * ~                       Certificate Data                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_cert
{
    u_int8_t    isacert_np;
    u_int8_t    isacert_reserved;
    u_int16_t   isacert_length;
    u_int8_t    isacert_type;
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cert)
 * yields the wrong value for the length.
 */
#define ISAKMP_CERT_SIZE		5

extern struct_desc isakmp_ipsec_certificate_desc;

/* ISAKMP Certificate Request Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.10
 * Variable length Certificate Types and Certificate Authorities follow.
 * Previous next payload: ISAKMP_NEXT_CR.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Cert. Type   !                                               !
 * +-+-+-+-+-+-+-+-+                                               !
 * ~                    Certificate Authority                      ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_cr
{
    u_int8_t    isacr_np;
    u_int8_t    isacr_reserved;
    u_int16_t   isacr_length;
    u_int8_t    isacr_type;
};

/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */
#define ISAKMP_CR_SIZE		5

extern struct_desc isakmp_ipsec_cert_req_desc;

/* ISAKMP Hash Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.11
 * Variable length Hash Data follow.
 * Previous next payload: ISAKMP_NEXT_HASH.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                           Hash Data                           ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_hash_desc;

/* ISAKMP Signature Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.12
 * Variable length Signature Data follow.
 * Previous next payload: ISAKMP_NEXT_SIG.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                         Signature Data                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_signature_desc;

/* ISAKMP Nonce Payload: no fixed fields beyond the generic ones.
 * layout from RFC 2408 "ISAKMP" section 3.13
 * Variable length Nonce Data follow.
 * Previous next payload: ISAKMP_NEXT_NONCE.
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                            Nonce Data                         ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_nonce_desc;

/* ISAKMP Notification Payload
 * layout from RFC 2408 "ISAKMP" section 3.14
 * This is followed by a variable length SPI
 * and then possibly by variable length Notification Data.
 * Previous next payload: ISAKMP_NEXT_N
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                Security Parameter Index (SPI)                 ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Notification Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

extern struct_desc isakmp_attr_desc;

/* From draft-dukes-ike-mode-cfg
3.2. Attribute Payload
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ! Next Payload  !   RESERVED    !         Payload Length        !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !     Type      !   RESERVED    !           Identifier          !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     !                                                               !
     !                                                               !
     ~                           Attributes                          ~
     !                                                               !
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct isakmp_mode_attr
{
    u_int8_t    isama_np;
    u_int8_t    isama_reserved;
    u_int16_t   isama_length;
    u_int8_t    isama_type;
    u_int8_t    isama_reserved2;
    u_int16_t   isama_identifier;
};

extern struct_desc isakmp_attr_desc;
extern struct_desc isakmp_xauth_attribute_desc;


/* ISAKMP Notification Payload
 * layout from RFC 2408 "ISAKMP" section 3.14
 * This is followed by a variable length SPI
 * and then possibly by variable length Notification Data.
 * Previous next payload: ISAKMP_NEXT_N
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol-ID  !   SPI Size    !      Notify Message Type      !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                Security Parameter Index (SPI)                 ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                       Notification Data                       ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_notification
{
    u_int8_t    isan_np;
    u_int8_t    isan_reserved;
    u_int16_t   isan_length;
    u_int32_t   isan_doi;
    u_int8_t    isan_protoid;
    u_int8_t    isan_spisize;
    u_int16_t   isan_type;
};

extern struct_desc isakmp_notification_desc;

/* ISAKMP Delete Payload
 * layout from RFC 2408 "ISAKMP" section 3.15
 * This is followed by a variable length SPI.
 * Previous next payload: ISAKMP_NEXT_D
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !              Domain of Interpretation  (DOI)                  !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol-Id  !   SPI Size    !           # of SPIs           !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct isakmp_delete
{
    u_int8_t    isad_np;
    u_int8_t    isad_reserved;
    u_int16_t   isad_length;
    u_int32_t   isad_doi;
    u_int8_t    isad_protoid;
    u_int8_t    isad_spisize;
    u_int16_t   isad_nospi;
};

extern struct_desc isakmp_delete_desc;

/* ISAKMP Vendor ID Payload
 * layout from RFC 2408 "ISAKMP" section 3.15
 * This is followed by a variable length VID.
 * Previous next payload: ISAKMP_NEXT_VID
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !   RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~                        Vendor ID (VID)                        ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
extern struct_desc isakmp_vendor_id_desc;

struct isakmp_nat_oa
{
    u_int8_t    isanoa_np;
    u_int8_t    isanoa_reserved_1;
    u_int16_t   isanoa_length;
    u_int8_t    isanoa_idtype;
    u_int8_t    isanoa_reserved_2;
    u_int16_t   isanoa_reserved_3;
};

extern struct_desc isakmp_nat_d;
extern struct_desc isakmp_nat_oa;

/* descriptor for each payload type
 *
 * There is a slight problem in that some payloads differ, depending
 * on the mode.  Since this is table only used for top-level payloads,
 * Proposal and Transform payloads need not be handled.
 * That leaves only Identification payloads as a problem.
 * We make all these entries NULL
 */
extern const struct_desc *payload_desc(unsigned p);

/*
 * IKEv2 structures
 */
/*
 * 3.2.  Generic Payload Header
 */
struct ikev2_generic
{
	u_int8_t    isag_np;
	u_int8_t    isag_critical;
	u_int16_t   isag_length;
};
extern struct_desc ikev2_generic_desc;

struct ikev2_sa
{
	u_int8_t  isasa_np;			/* Next payload */
	u_int8_t  isasa_critical;
	u_int16_t isasa_length;		/* Payload length */
};

extern struct_desc ikev2_sa_desc;

struct ikev2_prop
{
	u_int8_t  isap_np;		/* Next payload */
	u_int8_t  isap_critical;
	u_int16_t isap_length;		/* Payload length */
	u_int8_t  isap_propnum;
	u_int8_t  isap_protoid;
	u_int8_t  isap_spisize;
	u_int8_t  isap_numtrans;
};

extern struct_desc ikev2_prop_desc;

/* rfc4306, section 3.3.2 */
struct ikev2_trans
{
	u_int8_t  isat_np;	    /* Next payload */
	u_int8_t  isat_critical;
	u_int16_t isat_length;	    /* Payload length */
	u_int8_t  isat_type;        /* transform type */
	u_int8_t  isat_res2;
	u_int16_t  isat_transid;     /* ID */
};
extern struct_desc ikev2_trans_desc;

/* rfc4306, section 3.3.5 */
struct ikev2_trans_attr
{
	u_int16_t isatr_type;	     /* Attribute Type */
	u_int16_t isatr_lv;	     /* Length (AF=0) or Value (AF=1) */
	/* u_intXX_t isatr_value;      Value if AF=0, absent if AF=1 */
};
extern struct_desc ikev2_trans_attr_desc;

/* rfc4306, section 3.4 */
struct ikev2_ke
{
	u_int8_t  isak_np;	    /* Next payload */
	u_int8_t  isak_critical;
	u_int16_t isak_length;	    /* Payload length */
	u_int16_t isak_group;       /* transform type */
	u_int16_t isak_res2;
};
extern struct_desc ikev2_ke_desc;

/* rfc4306, section 3.5 */
struct ikev2_id
{
	u_int8_t  isai_np;	    /* Next payload */
	u_int8_t  isai_critical;
	u_int16_t isai_length;	    /* Payload length */
	u_int8_t  isai_type;        /* transform type */
	u_int8_t  isai_res1;
	u_int16_t isai_res2;
};
extern struct_desc ikev2_id_desc;

/* rfc4306, section 3.8 */
struct ikev2_a
{
	u_int8_t  isaa_np;	    /* Next payload */
	u_int8_t  isaa_critical;
	u_int16_t isaa_length;	    /* Payload length */
	u_int8_t  isaa_type;        /* auth type */
	u_int8_t  isaa_res1;
	u_int16_t isaa_res2;
};
extern struct_desc ikev2_a_desc;

/* rfc4306 section 3.6 CERT Payload */
struct ikev2_cert
{
    u_int8_t  isac_np;	    /* Next payload */
    u_int8_t  isac_critical;
    u_int16_t isac_length;	    /* Payload length */
    u_int8_t  isac_enc;            /* encoding type */
};


/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */
#define IKEV2_CERT_SIZE		5
extern struct_desc ikev2_certificate_desc;

/* rfc4306 section 3.6 CERTREQ Payload */
struct ikev2_certreq
{
    u_int8_t  isacertreq_np;	    /* Next payload */
    u_int8_t  isacertreq_critical;
    u_int16_t isacertreq_length;	  /* Payload length */
    u_int8_t  isacertreq_enc;            /* encoding type */
};


/* NOTE: this packet type has a fixed portion that is not a
 * multiple of 4 octets.  This means that sizeof(struct isakmp_cr)
 * yields the wrong value for the length.
 */
#define IKEV2_CERTREQ_SIZE		5
extern struct_desc  ikev2_certificate_req_desc;

/* rfc4306, section 3.9, nonce, uses generic header */
extern struct_desc ikev2_nonce_desc;

/* rfc4306 section 3.10 NOTIFY Payload
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Protocol ID  |   SPI Size    |      Notify Message Type      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                Security Parameter Index (SPI)                 ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       Notification Data                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

note that the protocol_ID is *0* whenever SPI SIZE is zero, which
applies to many IKE PARENT SA things like NAT_*

*/


struct ikev2_notify
{
    u_int8_t  isan_np;		/* Next payload */
    u_int8_t  isan_critical;
    u_int16_t isan_length;	/* Payload length */
    u_int8_t  isan_protoid;	/* Protocol ID: noSA=0,IKE=1,AH=2,ESP=3 */
    u_int8_t  isan_spisize;	/* SPI size: 0 for IKE_SA */
    u_int16_t isan_type;	/* Notification type, see v2_notification_t */
};
extern struct_desc ikev2_notify_desc;


/* IKEv2 Delete Payload
 * layout from RFC 5996 Section 3.11
 * This is followed by a variable length SPI.
 *
 *                      1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ! Next Payload  !C| RESERVED    !         Payload Length        !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !  Protocol ID  !   SPI Size    !           Num of SPIs         !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * !                                                               !
 * ~               Security Parameter Index(es) (SPI)              ~
 * !                                                               !
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ikev2_delete
{
    u_int8_t    isad_np;
    u_int8_t    isad_reserved;
    u_int16_t   isad_length;
    u_int8_t    isad_protoid;
    u_int8_t    isad_spisize;
    u_int16_t   isad_nrspi;
};

extern struct_desc ikev2_delete_desc;

/* rfc4306, section 3.12, vendor ID, uses generic header */
extern struct_desc ikev2_vendor_id_desc;

/* rfc4306, section 3.13 */
struct ikev2_ts
{
    u_int8_t  isat_np;	    /* Next payload */
    u_int8_t  isat_critical;
    u_int16_t isat_length;	    /* Payload length */
    u_int8_t  isat_num;         /* number of TSs */
    u_int8_t  isat_res1;
    u_int16_t isat_res2;
};
struct ikev2_ts1
{
    u_int8_t  isat1_type;
    u_int8_t  isat1_ipprotoid;
    u_int16_t isat1_sellen;
    u_int16_t isat1_startport;
    u_int16_t isat1_endport;
};
extern struct_desc ikev2_ts_desc;
extern struct_desc ikev2_ts1_desc;

/* rfc4306, section 3.14, encrypted payload, uses generic header */
extern struct_desc ikev2_e_desc;

/* union of all payloads */

union payload {
    struct isakmp_generic generic;
    struct isakmp_sa sa;
    struct isakmp_proposal proposal;
    struct isakmp_transform transform;
    struct isakmp_id id;    /* Main Mode */
    struct isakmp_cert cert;
    struct isakmp_cr cr;
    struct isakmp_ipsec_id ipsec_id;	/* Quick Mode */
    struct isakmp_notification notification;
    struct isakmp_delete delete;
    struct isakmp_nat_oa nat_oa;
    struct isakmp_mode_attr attribute;
    struct ikev2_generic    v2gen;
    struct ikev2_ke         v2ke;
    struct ikev2_trans      v2trans;
    struct ikev2_prop       v2prop;
    struct ikev2_sa         v2sa;
    struct ikev2_id         v2id;
    struct ikev2_a          v2a;
    struct ikev2_ts         v2ts;
    struct ikev2_cert       v2cert;
    struct ikev2_certreq    v2certreq;
    struct ikev2_notify     v2n;
    struct ikev2_delete     v2delete;
};


#endif /* _PACKET_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

