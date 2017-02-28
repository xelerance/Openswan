/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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

#ifndef _ID_H
#define _ID_H

/* see ipsec_policy.h for ID_* values, which are used in the kernel too */
struct id {
    bool       has_wildcards;  /* if there is wildcard buired in DN */
    int kind;		/* ID_* value */
    ip_address ip_addr;	/* ID_IPV4_ADDR, ID_IPV6_ADDR */
    chunk_t name;	/* ID_FQDN, ID_USER_FQDN (with @) */
			/* ID_KEY_ID, ID_DER_ASN_DN       */
};

extern void init_id(void);

struct id_list {
    struct id id;
    struct id_list *next;
};

extern const struct id empty_id;	/* ID_NONE */

enum myid_state {
    MYID_UNKNOWN,	/* not yet figured out */
    MYID_HOSTNAME,	/* our current hostname */
    MYID_IP,	/* our default IP address */
    MYID_SPECIFIED	/* as specified by ipsec.conf */
};

extern enum myid_state myid_state;
extern struct id myids[MYID_SPECIFIED+1];	/* %myid */
extern char *myid_str[MYID_SPECIFIED+1];      /* strings */
extern void set_myid(enum myid_state s, char *);
extern void show_myid_status(void);
extern const struct id *resolve_myid(const struct id *id);
extern void set_myFQDN(void);
extern void free_myFQDN(void);

extern void log_ckaid(const char *fmt, const unsigned char *key, unsigned int keylen);

extern err_t atoid(char *src, struct id *id, bool myid_ok);
extern void iptoid(const ip_address *ip, struct id *id);
extern unsigned char* temporary_cyclic_buffer(void);
extern int idtoa(const struct id *id, char *dst, size_t dstlen);
#define IDTOA_BUF	512
extern void escape_metachar(const char *src, char *dst, size_t dstlen);
extern void remove_metachar(const unsigned char *src, char *dst, size_t dstlen);
struct end;	/* forward declaration of tag (defined in connections.h) */
extern void unshare_id_content(struct id *id);
extern void free_id_content(struct id *id);
extern bool any_id(const struct id *a);
extern bool same_id(const struct id *a, const struct id *b);
extern bool same_exact_id(const struct id *a, const struct id *b);
#define MAX_WILDCARDS	15
extern bool match_id(const struct id *a, const struct id *b, int *wildcards);
extern int id_count_wildcards(const struct id *id);
#define id_is_ipaddr(id) ((id)->kind == ID_IPV4_ADDR || (id)->kind == ID_IPV6_ADDR)

struct isakmp_ipsec_id;	/* forward declaration of tag (defined in packet.h) */
extern void
    build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, struct end *end);

/* ip_str: a simple to use variant of addrtot.
 * It stores its result in a static buffer.
 * This means that newer calls overwrite the storage of older calls.
 * Note: this is not used in any of the logging functions, so their
 * callers may use it.
 */
extern const char *pluto_ip_str(const ip_address *src);

#endif /* _ID_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
