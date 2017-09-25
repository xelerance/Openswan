/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998, 1999  D. Hugh Redelmeier.
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

#ifndef _SPDB_H_
#define _SPDB_H_

#include "packet.h"

/* database of SA properties */

/* Attribute type and value pair.
 * Note: only "basic" values are represented so far.
 */
struct db_attr {
    union {
	enum ikev1_oakley_attr oakley;	/* ISAKMP_ATTR_AF_TV is implied;
					   0 for end */
	enum ikev1_ipsec_attr  ipsec;
	unsigned int ikev2;          /* one of: ikev2_trans_type_{prf,encr,dh,esn,integ} */
    } type;
    u_int16_t val;
};

/* transform */
struct db_trans {
	u_int16_t     transid;  /* Transform-Id */
	struct db_attr *attrs;	/* array */
	unsigned int attr_cnt;  /* number of elements */
};

/* proposal - IKEv1 */
struct db_prop {
    u_int8_t         protoid;	/* Protocol-Id */
    struct db_trans *trans;	/* array (disjunction-OR) */
    unsigned int trans_cnt;	/* number of elements */
    /* SPI size and value isn't part of DB */
};

/* conjunction (AND) of proposals - IKEv1 */
struct db_prop_conj {
	struct db_prop *props;	/* array */
	unsigned int prop_cnt;	/* number of elements */
};

struct db_v2_attr {
    unsigned int ikev2;
    u_int16_t    val;
};

/* transform - IKEv2 */
struct db_v2_trans {
    enum ikev2_trans_type    transform_type;    /* ENCR, PRF, etc.*/
    u_int16_t                value;	        /* Transform-Id */
    struct db_v2_attr *attrs;	 /* array of attributes */
    unsigned int attr_cnt;	         /* number of elements */
};

/* proposal - IKEv2 */
/* transforms are OR of each unique prop */
struct db_v2_prop_conj {
    u_int8_t            propnum;        /* OR with other propnum== */
	u_int8_t            protoid;	/* Protocol-Id: ikev2_trans_type */
    u_int8_t            spisize;        /* for proposal */
    struct db_v2_trans *trans;	     /* array (disjunction-OR when transform_type==) */
	unsigned int        trans_cnt;	/* number of elements */
};

/* top-level list of proposals */
struct db_v2_prop {
	struct db_v2_prop_conj  *props;	/* array */
    u_int8_t     conjnum;               /* number of next conjunction */
    unsigned int prop_cnt;	        /* number of elements in props*/
};

/* security association */
struct db_sa {
    bool                    parentSA;   /* set if this is a parent/oakley */
    struct db_context      *prop_v1_ctx;
    struct db_prop_conj    *prop_conjs; /* array */
    unsigned int prop_conj_cnt;         /* number of elements */

    struct db2_context     *prop_ctx;   /* if non-null, then attr/etc. are from it */
    struct db_v2_prop      *prop_disj;  /* array */
    unsigned int prop_disj_cnt;         /* number of elements... OR */
};

/* The oakley sadb is subscripted by a bitset with members
 * from POLICY_PSK and POLICY_RSASIG.
 */
extern struct db_sa oakley_sadb[1 << 4];
extern struct db_sa oakley_am_sadb[1 << 4];

/* The oakley sadb for aggressive mode.
 */
extern struct db_sa oakley_sadb_am;

/* The ipsec sadb is subscripted by a bitset with members
 * from POLICY_ENCRYPT, POLICY_AUTHENTICATE, POLICY_COMPRESS
 */
extern struct db_sa ipsec_sadb[1 << 3];

/* for db_sa */
#define AD_SAp(x)    prop_conjs: x, prop_conj_cnt: elemsof(x), parentSA:TRUE
#define AD_SAc(x)    prop_conjs: x, prop_conj_cnt: elemsof(x), parentSA:FALSE
#define AD_NULL     prop_conjs: NULL, prop_conj_cnt: 0,

/* for db_trans */
#define AD_TR(p, x) transid: p, attrs: x, attr_cnt: elemsof(x)

/* for db_prop */
#define AD_PR(p, x) protoid: p, trans: x, trans_cnt: elemsof(x)

/* for db_prop_conj */
#define AD_PC(x) props: x, prop_cnt: elemsof(x)


extern void free_sa_attr(struct db_attr *attr);
extern void free_sa_trans(struct db_trans *tr);
extern void free_sa_prop(struct db_prop *dp);
extern void free_sa_prop_conj(struct db_prop_conj *pc);
extern void free_sa(struct db_sa *f);
extern void clone_trans(struct db_trans *tr);
extern void clone_prop(struct db_prop *p, int extra);
extern void clone_propconj(struct db_prop_conj *pc, int extra);
extern struct db_sa *sa_copy_sa(struct db_sa *sa, int extra);
extern struct db_sa *sa_copy_sa_first(struct db_sa *sa);
extern struct db_sa *sa_merge_proposals(struct db_sa *a, struct db_sa *b);

extern int v2tov1_encr(enum ikev2_trans_type_encr encr);
extern int v2tov1_encr_child(enum ikev2_trans_type_encr encr);

extern int v2tov1_integ(enum ikev2_trans_type_integ v2integ);
extern int v2tov1_integ_child(enum ikev2_trans_type_integ v2integ);

extern bool extrapolate_v1_from_v2(struct db_sa *sadb, lset_t policy, enum phase1_role role);

/* in spdb_struct.c */
extern bool out_attr(int type, unsigned long val, struct_desc *attr_desc
		     , enum_names **attr_val_descs USED_BY_DEBUG
		     , pb_stream *pbs);

/* in spdb_print.c - normally never used in pluto */
extern void print_sa_attr_oakley(struct db_attr *at);
extern void print_sa_attr_ipsec(struct db_attr *at);
extern void print_sa_trans(bool parentSA, struct db_trans *tr);
extern void print_sa_prop(bool parentSA, struct db_prop *dp);
extern void print_sa_prop_conj(bool parentSA, struct db_prop_conj *pc);
extern void sa_print(struct db_sa *f);
extern void db_print(struct db_context *ctx);

extern void print_sa_v2_trans(struct db_v2_trans *tr);
extern void print_sa_v2_prop_conj(struct db_v2_prop_conj *dp);
extern void print_sa_v2_prop(struct db_v2_prop *pc);
extern void sa_v2_print(struct db_sa *f);

/* IKEv1 <-> IKEv2 things */
extern struct db_sa *sa_v1_convert(struct db_sa *f);
extern int  v2tov1_encr(enum ikev2_trans_type_encr);

#endif /*  _SPDB_H_ */

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
