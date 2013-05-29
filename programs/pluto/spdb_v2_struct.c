/* Security Policy Data Base/structure output
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "demux.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "ikev2.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#define return_on(var, val) do { var=val;goto return_out; } while(0);

/* Taken from spdb_v1_struct.c, as the format is similar */
bool
ikev2_out_attr(int type
	, unsigned long val
	, struct_desc *attr_desc
	, enum_names **attr_val_descs USED_BY_DEBUG
	, pb_stream *pbs)
{
    struct ikev2_trans_attr attr;

    if (val >> 16 == 0)
    {
	/* short value: use TV form - reuse ISAKMP_ATTR_defines for ikev2 */
	attr.isatr_type = type | ISAKMP_ATTR_AF_TV;
	attr.isatr_lv = val;
	if (!out_struct(&attr, attr_desc, pbs, NULL))
		return FALSE;
    }
    else
    {
	/*
	 * We really only support KEY_LENGTH, with does not use this long
	 * attribute style. See comments in out_attr() in spdb_v1_struct.c
	 */
	pb_stream val_pbs;
	u_int32_t nval = htonl(val);

	attr.isatr_type = type | ISAKMP_ATTR_AF_TLV;
	if (!out_struct(&attr, attr_desc, pbs, &val_pbs)
	|| !out_raw(&nval, sizeof(nval), &val_pbs, "long attribute value"))
		return FALSE;
	close_output_pbs(&val_pbs);
    }
    DBG(DBG_EMITTING,
	enum_names *d = attr_val_descs[type];

	if (d != NULL)
		DBG_log("    [%lu is %s]", val, enum_show(d, val)));
    return TRUE;
}

bool
ikev2_out_sa(pb_stream *outs
	     , unsigned int protoid
	     , struct db_sa *sadb
	     , struct state *st
	     , bool parentSA
	     , u_int8_t np)
{
    pb_stream sa_pbs;
    bool ret = FALSE;
    unsigned int  pc_cnt;

    /* SA header out */
    {
	struct ikev2_sa sa;

	memset(&sa, 0, sizeof(sa));
	sa.isasa_np       = np;
	sa.isasa_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
	   openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
	   sa.isasa_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
	}

	/* no ipsec_doi on IKEv2 */

	if (!out_struct(&sa, &ikev2_sa_desc, outs, &sa_pbs))
	    return_on(ret, FALSE);
    }

    passert(sadb != NULL);

    if(!parentSA) {
	st->st_esp.our_spi = get_ipsec_spi(0 /* avoid this # */
					   , IPPROTO_ESP
					   , &st->st_connection->spd
					   , TRUE /* tunnel */);
    }

    /* now send out all the proposals */
    for(pc_cnt=0; pc_cnt < sadb->prop_disj_cnt; pc_cnt++)
    {
	struct db_v2_prop *vp = &sadb->prop_disj[pc_cnt];
	unsigned int pr_cnt;

	/* now send out all the transforms */
	for(pr_cnt=0; pr_cnt < vp->prop_cnt; pr_cnt++)
	{
	    unsigned int ts_cnt;
	    struct db_v2_prop_conj *vpc = &vp->props[pr_cnt];

	    struct ikev2_prop p;
	    pb_stream t_pbs;

	    memset(&p, 0, sizeof(p));

	    /* if there is a next proposal, then the np needs to be set right*/
	    if(pr_cnt+1 < vp->prop_cnt || pc_cnt+1 < sadb->prop_disj_cnt) {
		p.isap_np      = ISAKMP_NEXT_P;
	    } else {
		p.isap_np      = ISAKMP_NEXT_NONE;
	    }

	    p.isap_length  = 0;
	    p.isap_propnum = vpc->propnum;
	    p.isap_protoid = protoid;
	    if(parentSA) {
		p.isap_spisize = 0;  /* set when we rekey */
	    } else {
		p.isap_spisize = 4;
	    }
	    p.isap_numtrans= vpc->trans_cnt;

	    if (!out_struct(&p, &ikev2_prop_desc, &sa_pbs, &t_pbs))
		return_on(ret, FALSE);

	    if(p.isap_spisize > 0) {
		if(parentSA) {
		    /* XXX set when rekeying */
		} else {
		    if(!out_raw(&st->st_esp.our_spi, 4
				, &t_pbs, "our spi"))
			return STF_INTERNAL_ERROR;
		}
	    }

	    for(ts_cnt=0; ts_cnt < vpc->trans_cnt; ts_cnt++) {
		struct db_v2_trans *tr = &vpc->trans[ts_cnt];
		struct ikev2_trans t;
		pb_stream at_pbs;
		unsigned int attr_cnt;

#if 0
		XXX;
		if() {
		}
#endif

		memset(&t, 0, sizeof(t));
		if(ts_cnt+1 < vpc->trans_cnt) {
		    t.isat_np      = ISAKMP_NEXT_T;
		} else {
		    t.isat_np      = ISAKMP_NEXT_NONE;
		}


		t.isat_length = 0;
		t.isat_type   = tr->transform_type;
		t.isat_transid= tr->transid;

		if (!out_struct(&t, &ikev2_trans_desc, &t_pbs, &at_pbs))
		    return_on(ret, FALSE);

		for (attr_cnt=0; attr_cnt < tr->attr_cnt; attr_cnt++) {
		    struct db_attr *attr = &tr->attrs[attr_cnt];

		    ikev2_out_attr(attr->type.ikev2, attr->val
			, &ikev2_trans_attr_desc, ikev2_trans_attr_val_descs
			, &at_pbs);
		}


		close_output_pbs(&at_pbs);
	    }
	    close_output_pbs(&t_pbs);
	}
    }

    close_output_pbs(&sa_pbs);
    ret = TRUE;

return_out:
    return ret;
}

struct db_trans_flat {
    u_int8_t               protoid;	        /* Protocol-Id */
    u_int16_t              auth_method;     	/* conveyed another way in ikev2*/
    u_int16_t              encr_transid;	/* Transform-Id */
    u_int16_t              integ_transid;	/* Transform-Id */
    u_int16_t              prf_transid;		/* Transform-Id */
    u_int16_t              group_transid;	/* Transform-Id */
    u_int16_t              encr_keylen;		/* Key length in bits */
};

enum ikev2_trans_type_encr v1tov2_encr(int oakley)
{
    switch(oakley) {
    case OAKLEY_DES_CBC:
	return IKEv2_ENCR_DES;
    case OAKLEY_IDEA_CBC:
	return IKEv2_ENCR_IDEA;
    case OAKLEY_BLOWFISH_CBC:
	return IKEv2_ENCR_BLOWFISH;
    case OAKLEY_RC5_R16_B64_CBC:
	return IKEv2_ENCR_RC5;
    case OAKLEY_3DES_CBC:
	return IKEv2_ENCR_3DES;
    case OAKLEY_CAST_CBC:
	return IKEv2_ENCR_CAST;
    case OAKLEY_AES_CBC:
	return IKEv2_ENCR_AES_CBC;
    case OAKLEY_TWOFISH_CBC_SSH:
    case OAKLEY_TWOFISH_CBC:
    case OAKLEY_SERPENT_CBC:
    default:
	return IKEv2_ENCR_INVALID;
    }
}

enum ikev2_trans_type_integ v1tov2_integ(int oakley)
{
    switch(oakley) {
    case OAKLEY_MD5:
        return IKEv2_AUTH_HMAC_MD5_96;
    case OAKLEY_SHA1:
        return IKEv2_AUTH_HMAC_SHA1_96;
    case OAKLEY_SHA2_256:
        return IKEv2_AUTH_HMAC_SHA2_256_128;
    default:
        return IKEv2_AUTH_INVALID;
   }
}

enum ikev2_trans_type_integ v1phase2tov2child_integ(int ikev1_phase2_auth)
{
    switch(ikev1_phase2_auth) {
    case AUTH_ALGORITHM_HMAC_MD5:
        return IKEv2_AUTH_HMAC_MD5_96;
    case AUTH_ALGORITHM_HMAC_SHA1:
        return IKEv2_AUTH_HMAC_SHA1_96;
    case AUTH_ALGORITHM_HMAC_SHA2_256:
        return IKEv2_AUTH_HMAC_SHA2_256_128;
    default:
        return IKEv2_AUTH_INVALID;
   }
}


static enum ikev2_trans_type_prf v1tov2_prf(int oakley)
{
    switch(oakley) {
    case OAKLEY_MD5:
        return IKEv2_PRF_HMAC_MD5;
    case OAKLEY_SHA1:
        return IKEv2_PRF_HMAC_SHA1;
    case OAKLEY_SHA2_256:
        return IKEv2_PRF_HMAC_SHA2_256;
    default:
        return IKEv2_PRF_INVALID;
    }
}

struct db_sa *sa_v2_convert(struct db_sa *f)
{
    unsigned int pcc, prc, tcc, pr_cnt, pc_cnt, propnum;
    int tot_trans, i;
    struct db_trans_flat   *dtfset;
    struct db_trans_flat   *dtfone;
    struct db_trans_flat   *dtflast;
    struct db_attr         *attrs;
    struct db_v2_trans     *tr;
    struct db_v2_prop_conj *pc;
    struct db_v2_prop      *pr;

    if(!f) return NULL;
    if(!f->dynamic) f = sa_copy_sa(f, 0);

    tot_trans=0;
    for(pcc=0; pcc<f->prop_conj_cnt; pcc++) {
	struct db_prop_conj *dpc = &f->prop_conjs[pcc];

	if(dpc->props == NULL) continue;
	for(prc=0; prc < dpc->prop_cnt; prc++) {
	    struct db_prop *dp = &dpc->props[prc];

	    if(dp->trans == NULL) continue;
	    for(tcc=0; tcc<dp->trans_cnt; tcc++) {
		tot_trans++;
	    }
	}
    }

    dtfset = alloc_bytes(sizeof(struct db_trans_flat)*tot_trans, "spdb_v2_dtfset");

    tot_trans=0;
    for(pcc=0; pcc<f->prop_conj_cnt; pcc++) {
	struct db_prop_conj *dpc = &f->prop_conjs[pcc];

	if(dpc->props == NULL) continue;
	for(prc=0; prc < dpc->prop_cnt; prc++) {
	    struct db_prop *dp = &dpc->props[prc];

	    if(dp->trans == NULL) continue;
	    for(tcc=0; tcc<dp->trans_cnt; tcc++) {
		struct db_trans *tr=&dp->trans[tcc];
		struct db_trans_flat *dtfone = &dtfset[tot_trans];
		unsigned int attr_cnt;

		dtfone->protoid      = dp->protoid;
		if(!f->parentSA) dtfone->encr_transid = tr->transid;

		for(attr_cnt=0; attr_cnt<tr->attr_cnt; attr_cnt++) {
		    struct db_attr *attr = &tr->attrs[attr_cnt];

		    if(f->parentSA) {
			switch(attr->type.oakley) {

			case OAKLEY_AUTHENTICATION_METHOD:
			    dtfone->auth_method = attr->val;
			    break;

			case OAKLEY_ENCRYPTION_ALGORITHM:
			    dtfone->encr_transid = v1tov2_encr(attr->val);
			    break;

			case OAKLEY_HASH_ALGORITHM:
			    dtfone->integ_transid = v1tov2_integ(attr->val);
			    dtfone->prf_transid = v1tov2_prf(attr->val);
			    break;

			case OAKLEY_GROUP_DESCRIPTION:
			    dtfone->group_transid = attr->val;
			    break;

			case OAKLEY_KEY_LENGTH:
			    dtfone->encr_keylen = attr->val;
			    break;

			default:
				openswan_log("sa_v2_convert(): Ignored unknown IKEv2 transform attribute type: %d",attr->type.oakley);
			    break;
			}
		    } else {
			switch(attr->type.ipsec) {
			case AUTH_ALGORITHM:
			    dtfone->integ_transid = v1phase2tov2child_integ(attr->val);
			    break;

			case KEY_LENGTH:
			    dtfone->encr_keylen = attr->val;
			    break;

			case ENCAPSULATION_MODE:
			    /* XXX */
			    break;

			default:
			    break;
			}
		    }
		}
		tot_trans++;
	    }
	}
    }

    pr=NULL;
    pr_cnt=0;
    if(tot_trans >= 1) {
	pr = alloc_bytes(sizeof(struct db_v2_prop), "db_v2_prop");
    }
    dtflast = NULL;
    tr = NULL;
    pc = NULL; pc_cnt = 0;
    propnum=1;

    for(i=0; i < tot_trans; i++) {
	int tr_cnt;
	int tr_pos;

	dtfone = &dtfset[i];

	if(dtfone->protoid == PROTO_ISAKMP) tr_cnt = 4;
	else tr_cnt=3;

	if(dtflast != NULL) {
	    /*
	     * see if previous protoid is identical to this
	     * one, and if so, then this is a disjunction (OR),
	     * otherwise, it's conjunction (AND)
	     */
	    if(dtflast->protoid == dtfone->protoid) {
		/* need to extend pr (list of disjunctions) by one */
		struct db_v2_prop *pr1;
		pr_cnt++;
		pr1 = alloc_bytes(sizeof(struct db_v2_prop)*(pr_cnt+1), "db_v2_prop");
		memcpy(pr1, pr, sizeof(struct db_v2_prop)*pr_cnt);
		pfree(pr);
		pr = pr1;

		/* need to zero this, so it gets allocated */
		propnum++;
		pc = NULL;
		pc_cnt=0;
	    } else {
		struct db_v2_prop_conj *pc1;
		/* need to extend pc (list of conjuections) by one */
		pc_cnt++;

		pc1 = alloc_bytes(sizeof(struct db_v2_prop_conj)*(pc_cnt+1), "db_v2_prop_conj");
		memcpy(pc1, pc, sizeof(struct db_v2_prop_conj)*pc_cnt);
		pfree(pc);
		pc = pc1;
		pr[pr_cnt].props=pc;
		pr[pr_cnt].prop_cnt=pc_cnt+1;

		/* do not increment propnum! */
	    }
	}
	dtflast = dtfone;

	if(!pc) {
	    pc = alloc_bytes(sizeof(struct db_v2_prop_conj), "db_v2_prop_conj");
	    pc_cnt=0;
	    pr[pr_cnt].props = pc;
	    pr[pr_cnt].prop_cnt = pc_cnt+1;
	}

	tr = alloc_bytes(sizeof(struct db_v2_trans)*(tr_cnt), "db_v2_trans");
	pc[pc_cnt].trans=tr;  pc[pc_cnt].trans_cnt = tr_cnt;

	pc[pc_cnt].propnum = propnum;
	pc[pc_cnt].protoid = dtfset->protoid;

	tr_pos = 0;
	tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_ENCR;
	tr[tr_pos].transid        = dtfone->encr_transid;
	if(dtfone->encr_keylen > 0 ) {
	    attrs = alloc_bytes(sizeof(struct db_attr), "db_attrs");
	    tr[tr_pos].attrs = attrs;
	    tr[tr_pos].attr_cnt = 1;
	    attrs->type.ikev2 = IKEv2_KEY_LENGTH;
	    attrs->val = dtfone->encr_keylen;
	}
	tr_pos++;

	tr[tr_pos].transid        = dtfone->integ_transid;
	tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_INTEG;
	tr_pos++;

	if(dtfone->protoid == PROTO_ISAKMP) {
	    /* XXX Let the user set the PRF.*/
	    tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_PRF;
	    tr[tr_pos].transid        = dtfone->prf_transid;
	    tr_pos++;
	    tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_DH;
	    tr[tr_pos].transid        = dtfone->group_transid;
	    tr_pos++;
	} else {
	    tr[tr_pos].transform_type = IKEv2_TRANS_TYPE_ESN;
	    tr[tr_pos].transid        = IKEv2_ESN_DISABLED;
	    tr_pos++;
	}
	passert(tr_cnt == tr_pos);
    }

    f->prop_disj = pr;
    f->prop_disj_cnt = pr_cnt+1;

    pfree(dtfset);

    return f;
}

bool
ikev2_acceptable_group(struct state *st, oakley_group_t group)
{
    struct db_sa *sadb = st->st_sadb;
    struct db_v2_prop *pd;
    unsigned int       pd_cnt;

    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	struct db_v2_prop_conj  *pj;
	struct db_v2_trans      *tr;
	unsigned int             tr_cnt;

	pd = &sadb->prop_disj[pd_cnt];

	/* In PARENT SAs, we only support one conjunctive item */
	if(pd->prop_cnt != 1) continue;

	pj = &pd->props[0];
	if(pj->protoid  != PROTO_ISAKMP) continue;

	for(tr_cnt=0; tr_cnt < pj->trans_cnt; tr_cnt++) {

	    tr = &pj->trans[tr_cnt];

	    switch(tr->transform_type) {
	    case IKEv2_TRANS_TYPE_DH:
		if(tr->transid == group)
		    return TRUE;
		break;
	    default:
		break;
	    }
	}
    }
    return FALSE;
}

static bool
spdb_v2_match_parent(struct db_sa *sadb
	      , unsigned propnum
	      , unsigned encr_transform
	      , int encr_keylen
	      , unsigned integ_transform
	      , int integ_keylen
	      , unsigned prf_transform
	      , int prf_keylen
	      , unsigned dh_transform)
{
    struct db_v2_prop *pd;
    unsigned int       pd_cnt;
    bool encr_matched, integ_matched, prf_matched, dh_matched;

    encr_matched=integ_matched=prf_matched=dh_matched=FALSE;

    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	struct db_v2_prop_conj  *pj;
	struct db_v2_trans      *tr;
	unsigned int             tr_cnt;
	int encrid, integid, prfid, dhid, esnid;

	pd = &sadb->prop_disj[pd_cnt];
	encrid = integid = prfid = dhid = esnid = 0;
	encr_matched=integ_matched=prf_matched=dh_matched=FALSE;
	if(pd->prop_cnt != 1) continue;

	/* In PARENT SAs, we only support one conjunctive item */
	pj = &pd->props[0];
	if(pj->protoid  != PROTO_ISAKMP) continue;

	for(tr_cnt=0; tr_cnt < pj->trans_cnt; tr_cnt++) {
	   int keylen = -1;
	   unsigned int attr_cnt;

	    tr = &pj->trans[tr_cnt];

	    for (attr_cnt=0; attr_cnt < tr->attr_cnt; attr_cnt++) {
		struct db_attr *attr = &tr->attrs[attr_cnt];

		if (attr->type.ikev2 == IKEv2_KEY_LENGTH)
			keylen = attr->val;
	    }

/* shouldn't these assignments of tr->transid be inside their if statements? */
	    switch(tr->transform_type) {
	    case IKEv2_TRANS_TYPE_ENCR:
		encrid = tr->transid;
		if(tr->transid == encr_transform && keylen == encr_keylen)
		    encr_matched=TRUE;
		break;

	    case IKEv2_TRANS_TYPE_INTEG:
		integid = tr->transid;
		if(tr->transid == integ_transform && keylen == integ_keylen)
		    integ_matched=TRUE;
		keylen = integ_keylen;
		break;

	    case IKEv2_TRANS_TYPE_PRF:
		prfid = tr->transid;
		if(tr->transid == prf_transform && keylen == prf_keylen)
		    prf_matched=TRUE;
		keylen = prf_keylen;
		break;

	    case IKEv2_TRANS_TYPE_DH:
		dhid = tr->transid;
		if(tr->transid == dh_transform)
		    dh_matched=TRUE;
		break;

	    default:
		continue; /* could be clearer as a break */
	    }

	    /* esn_matched not tested! */
	    if(dh_matched && prf_matched && integ_matched && encr_matched)
		return TRUE;
	}
	if(DBGP(DBG_CONTROLMORE)) {
	/* note: enum_show uses a static buffer so more than one call per
	   statement is dangerous */
	    DBG_log("proposal %u %s encr= (policy:%s vs offered:%s)"
		    , propnum
		    , encr_matched ? "succeeded" : "failed"
		    , enum_name(&trans_type_encr_names, encrid)
		    , enum_show(&trans_type_encr_names, encr_transform));
	    DBG_log("            %s integ=(policy:%s vs offered:%s)"
		    , integ_matched ? "succeeded" : "failed"
		    , enum_name(&trans_type_integ_names, integid)
		    , enum_show(&trans_type_integ_names, integ_transform));
	    DBG_log("            %s prf=  (policy:%s vs offered:%s)"
		    , prf_matched ? "succeeded" : "failed"
		    , enum_name(&trans_type_prf_names, prfid)
		    , enum_show(&trans_type_prf_names, prf_transform));
	    DBG_log("            %s dh=   (policy:%s vs offered:%s)"
		    , dh_matched ? "succeeded" : "failed"
		    , enum_name(&oakley_group_names, dhid)
		    , enum_show(&oakley_group_names, dh_transform));
	}

    }
    return FALSE;
}


#define MAX_TRANS_LIST 32         /* 32 is an arbitrary limit */

struct ikev2_transform_list {
    unsigned int encr_transforms[MAX_TRANS_LIST];
    int encr_keylens[MAX_TRANS_LIST];
    unsigned int encr_trans_next, encr_i;
    unsigned int integ_transforms[MAX_TRANS_LIST];
    int integ_keylens[MAX_TRANS_LIST];
    unsigned int integ_trans_next, integ_i;
    unsigned int prf_transforms[MAX_TRANS_LIST];
    int prf_keylens[MAX_TRANS_LIST];
    unsigned int prf_trans_next, prf_i;
    unsigned int dh_transforms[MAX_TRANS_LIST];
    unsigned int dh_trans_next, dh_i;
    unsigned int esn_transforms[MAX_TRANS_LIST];
    unsigned int esn_trans_next, esn_i;
    u_int32_t spi_values[MAX_TRANS_LIST];
    unsigned int spi_values_next;
};

static bool
ikev2_match_transform_list_parent(struct db_sa *sadb
				  , unsigned int propnum
				  , struct ikev2_transform_list *itl)
{
    if(itl->encr_trans_next < 1) {
	openswan_log("ignored proposal %u with no cipher transforms",
		     propnum);
	return FALSE;
    }
    if(itl->integ_trans_next < 1) {
	openswan_log("ignored proposal %u with no integrity transforms",
		     propnum);
	return FALSE;
    }
    if(itl->prf_trans_next < 1) {
	openswan_log("ignored proposal %u with no prf transforms",
		     propnum);
	return FALSE;
    }
    if(itl->dh_trans_next < 1) {
	openswan_log("ignored proposal %u with no diffie-hellman transforms",
		     propnum);
	return FALSE;
    }

    /*
     * now that we have a list of all the possibilities, see if any
     * of them fit.
     */
    for(itl->encr_i=0; itl->encr_i < itl->encr_trans_next; itl->encr_i++) {
	for(itl->integ_i=0; itl->integ_i < itl->integ_trans_next; itl->integ_i++) {
	    for(itl->prf_i=0; itl->prf_i < itl->prf_trans_next; itl->prf_i++) {
		for(itl->dh_i=0; itl->dh_i < itl->dh_trans_next; itl->dh_i++) {
		    if(spdb_v2_match_parent(sadb, propnum,
					    itl->encr_transforms[itl->encr_i],
					    itl->encr_keylens[itl->encr_i],
					    itl->integ_transforms[itl->integ_i],
					    itl->integ_keylens[itl->integ_i],
					    itl->prf_transforms[itl->prf_i],
					    itl->prf_keylens[itl->prf_i],
					    itl->dh_transforms[itl->dh_i])) {
			return TRUE;
		    }
		}
	    }
	}
    }
    return FALSE;
}

static stf_status
ikev2_process_transforms(struct ikev2_prop *prop
			 , pb_stream *prop_pbs
			 ,  struct ikev2_transform_list *itl)
{
    while(prop->isap_numtrans-- > 0) {
	pb_stream trans_pbs;
	pb_stream attr_pbs;
	/* u_char *attr_start; */
	/* size_t attr_len; */
	struct ikev2_trans trans;
	struct ikev2_trans_attr attr;
	int keylen = -1;
	/* err_t ugh = NULL; */	/* set to diagnostic when problem detected */

	if (!in_struct(&trans, &ikev2_trans_desc
		       , prop_pbs, &trans_pbs))
	    return BAD_PROPOSAL_SYNTAX;

	while (pbs_left(&trans_pbs) != 0) {
		if (!in_struct(&attr, &ikev2_trans_attr_desc, &trans_pbs
			, &attr_pbs))
		return BAD_PROPOSAL_SYNTAX;
		switch (attr.isatr_type) {
			case IKEv2_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
				keylen = attr.isatr_lv;
				break;
			default:
				openswan_log("ikev2_process_transforms(): Ignored unknown IKEv2 Transform Attribute: %d",attr.isatr_type);
		break;
		}
	}

	/* we read the attributes if we need to see details. */
	switch(trans.isat_type) {
	case IKEv2_TRANS_TYPE_ENCR:
	    if(itl->encr_trans_next < MAX_TRANS_LIST) {
		itl->encr_keylens[itl->encr_trans_next]=keylen;
		itl->encr_transforms[itl->encr_trans_next++]=trans.isat_transid;
	    } /* show failure with else */
	    break;

	case IKEv2_TRANS_TYPE_INTEG:
	    if(itl->integ_trans_next < MAX_TRANS_LIST) {
		itl->integ_keylens[itl->integ_trans_next]=keylen;
		itl->integ_transforms[itl->integ_trans_next++]=trans.isat_transid;
	    }
	    break;

	case IKEv2_TRANS_TYPE_PRF:
	    if(itl->prf_trans_next < MAX_TRANS_LIST) {
		itl->prf_keylens[itl->prf_trans_next]=keylen;
		itl->prf_transforms[itl->prf_trans_next++]=trans.isat_transid;
	    }
	    break;

	case IKEv2_TRANS_TYPE_DH:
	    if(itl->dh_trans_next < MAX_TRANS_LIST) {
		itl->dh_transforms[itl->dh_trans_next++]=trans.isat_transid;
	    }
	    break;

	case IKEv2_TRANS_TYPE_ESN:
	    if(itl->esn_trans_next < MAX_TRANS_LIST) {
		itl->esn_transforms[itl->esn_trans_next++]=trans.isat_transid;
	    }
	    break;
	}
    }
    return STF_OK;
}


static v2_notification_t
ikev2_emit_winning_sa(
    struct state *st
    , pb_stream *r_sa_pbs
    , struct trans_attrs ta
    , bool parentSA
    , struct ikev2_prop winning_prop)
{
    struct ikev2_prop  r_proposal = winning_prop;
    pb_stream r_proposal_pbs;
    struct ikev2_trans r_trans;
    pb_stream r_trans_pbs;

    memset(&r_trans, 0, sizeof(r_trans));

    if(parentSA) {
	/* Proposal - XXX */
	r_proposal.isap_spisize= 0;
    } else {
	r_proposal.isap_spisize= 4;
	st->st_esp.present = TRUE;
	st->st_esp.our_spi = get_ipsec_spi(0 /* avoid this # */
					   , IPPROTO_ESP
					   , &st->st_connection->spd
					   , TRUE /* tunnel */);
    }

    if(parentSA) {
	r_proposal.isap_numtrans = 4;
    } else {
	r_proposal.isap_numtrans = 3;
    }
    r_proposal.isap_np = ISAKMP_NEXT_NONE;

    if(!out_struct(&r_proposal, &ikev2_prop_desc
		   , r_sa_pbs, &r_proposal_pbs))
	impossible();

    if(!parentSA) {
	if(!out_raw(&st->st_esp.our_spi, 4, &r_proposal_pbs, "our spi"))
	    return STF_INTERNAL_ERROR;
    }

    /* Transform - cipher */
    r_trans.isat_type= IKEv2_TRANS_TYPE_ENCR;
    r_trans.isat_transid = ta.encrypt;
    r_trans.isat_np = ISAKMP_NEXT_T;
    if(!out_struct(&r_trans, &ikev2_trans_desc
		   , &r_proposal_pbs, &r_trans_pbs))
	impossible();
    if (ta.encrypter && ta.encrypter->keyminlen != ta.encrypter->keymaxlen)
	ikev2_out_attr(IKEv2_KEY_LENGTH, ta.enckeylen
		, &ikev2_trans_attr_desc, ikev2_trans_attr_val_descs
		, &r_trans_pbs);
    close_output_pbs(&r_trans_pbs);

    /* Transform - integrity check */
    r_trans.isat_type= IKEv2_TRANS_TYPE_INTEG;
    r_trans.isat_transid = ta.integ_hash;
    r_trans.isat_np = ISAKMP_NEXT_T;
    if(!out_struct(&r_trans, &ikev2_trans_desc
		   , &r_proposal_pbs, &r_trans_pbs))
	impossible();
    close_output_pbs(&r_trans_pbs);

    if(parentSA) {
	/* Transform - PRF hash */
	r_trans.isat_type= IKEv2_TRANS_TYPE_PRF;
	r_trans.isat_transid = ta.prf_hash;
	r_trans.isat_np = ISAKMP_NEXT_T;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, &r_trans_pbs))
	    impossible();
	close_output_pbs(&r_trans_pbs);

	/* Transform - DH hash */
	r_trans.isat_type= IKEv2_TRANS_TYPE_DH;
	r_trans.isat_transid = ta.groupnum;
	r_trans.isat_np = ISAKMP_NEXT_NONE;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, &r_trans_pbs))
	    impossible();
	close_output_pbs(&r_trans_pbs);
	st->st_oakley = ta;
    } else {
	/* Transform - ESN sequence */
	r_trans.isat_type= IKEv2_TRANS_TYPE_ESN;
	r_trans.isat_transid = IKEv2_ESN_DISABLED;
	r_trans.isat_np = ISAKMP_NEXT_NONE;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, &r_trans_pbs))
	    impossible();
	close_output_pbs(&r_trans_pbs);
    }

    /* close out the proposal */
    close_output_pbs(&r_proposal_pbs);
    close_output_pbs(r_sa_pbs);

    /* ??? If selection, we used to save the proposal in state.
     * We never used it.  From proposal_pbs.start,
     * length pbs_room(&proposal_pbs)
     */



    return NOTHING_WRONG;
}

v2_notification_t
ikev2_parse_parent_sa_body(
    pb_stream *sa_pbs,              /* body of input SA Payload */
    const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
    pb_stream *r_sa_pbs,	    /* if non-NULL, where to emit winning SA */
    struct state *st,  	            /* current state object */
    bool selection UNUSED           /* if this SA is a selection, only one
				     * tranform can appear. */
    )
{
    pb_stream proposal_pbs;
    struct ikev2_prop proposal;
    unsigned int np = ISAKMP_NEXT_P;
    /* we need to parse proposal structures until there are none */
    unsigned int lastpropnum=-1;
    bool conjunction, gotmatch;
    struct ikev2_prop winning_prop;
    struct db_sa *sadb;
    struct trans_attrs ta;
    struct connection *c = st->st_connection;
    int    policy_index = POLICY_ISAKMP(c->policy
					, c->spd.this.xauth_server
					, c->spd.this.xauth_client);

    struct ikev2_transform_list itl0, *itl;

    memset(&itl0, 0, sizeof(struct ikev2_transform_list));
    itl = &itl0;

    /* find the policy structures */
    sadb = st->st_sadb;
    if(!sadb) {
	st->st_sadb = &oakley_sadb[policy_index];
	sadb = oakley_alg_makedb(st->st_connection->alg_info_ike
				 , st->st_sadb, 0);
	if(sadb != NULL) {
	    st->st_sadb = sadb;
	}
	sadb = st->st_sadb;
    }
    sadb = st->st_sadb = sa_v2_convert(sadb);

    gotmatch = FALSE;
    conjunction = FALSE;
    zero(&ta);

    while(np == ISAKMP_NEXT_P) {
	/*
	 * note: we don't support ESN,
	 * so ignore any proposal that insists on it
	 */

	if(!in_struct(&proposal, &ikev2_prop_desc, sa_pbs, &proposal_pbs))
	    return PAYLOAD_MALFORMED;

	if(proposal.isap_protoid != PROTO_ISAKMP) {
	    loglog(RC_LOG_SERIOUS, "unexpected PARENT_SA, expected child");
	    return PAYLOAD_MALFORMED;
	}

	if (proposal.isap_spisize == 0)
	{
	    /* as it should be */
	}
	else if(proposal.isap_spisize <= MAX_ISAKMP_SPI_SIZE)
	{
	    u_char junk_spi[MAX_ISAKMP_SPI_SIZE];
	    if(!in_raw(junk_spi, proposal.isap_spisize, &proposal_pbs,
		       "PARENT SA SPI"))
		return PAYLOAD_MALFORMED;
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "invalid SPI size (%u) in PARENT_SA Proposal"
		   , (unsigned)proposal.isap_spisize);
	    return INVALID_SPI;
	}

	if(proposal.isap_propnum == lastpropnum) {
	    conjunction = TRUE;
	} else {
	    lastpropnum = proposal.isap_propnum;
	    conjunction = FALSE;
	}

	if(gotmatch && conjunction == FALSE) {
	    /* we already got a winner, and it was an OR with this one,
	       so do no more work. */
	    break;
	}

	if(!gotmatch && conjunction == TRUE) {
	    /*
	     * last one failed, and this next one is an AND, so this
	     * one can not succeed either, so don't bother.
	     */
	    continue;
	}

	gotmatch = FALSE;

	{ stf_status ret = ikev2_process_transforms(&proposal
						    , &proposal_pbs, itl);
	    if(ret != STF_OK) return ret;
	}

	np = proposal.isap_np;

	if(ikev2_match_transform_list_parent(sadb
					     , proposal.isap_propnum
					     , itl)) {

	    winning_prop = proposal;
	    gotmatch = TRUE;
	    /* gotmatch is true, so will never go inside if*/
	    //if(selection && !gotmatch && np == ISAKMP_NEXT_P) {
		//openswan_log("More than 1 proposal received from responder, ignoring rest. First one did not match");
		//return NO_PROPOSAL_CHOSEN;
	    //}
	}
    }

    /*
     * we are out of the loop. There are two situations in which we break
     * out: gotmatch == FALSE, means nothing selected.
     */
    if(!gotmatch) {
	return NO_PROPOSAL_CHOSEN;
    }

    /* there might be some work to do here if there was a conjunction,
     * not sure yet about that case.
     */

    /*
     * since we found something that matched, we might need to emit the
     * winning value.
     */
    ta.encrypt   = itl->encr_transforms[itl->encr_i];
    ta.enckeylen = itl->encr_keylens[itl->encr_i] > 0 ?
			itl->encr_keylens[itl->encr_i] : 0;
    ta.encrypter = (struct encrypt_desc *)ike_alg_ikev2_find(IKE_ALG_ENCRYPT
							     , ta.encrypt
							     , ta.enckeylen);
    passert(ta.encrypter != NULL);
    if (ta.enckeylen <= 0)
	ta.enckeylen = ta.encrypter->keydeflen;

    ta.integ_hash  = itl->integ_transforms[itl->integ_i];
    ta.integ_hasher= (struct hash_desc *)ike_alg_ikev2_find(IKE_ALG_INTEG,ta.integ_hash, 0);
    passert(ta.integ_hasher != NULL);

    ta.prf_hash    = itl->prf_transforms[itl->prf_i];
    ta.prf_hasher  = (struct hash_desc *)ike_alg_ikev2_find(IKE_ALG_HASH, ta.prf_hash, 0);
    passert(ta.prf_hasher != NULL);

    ta.groupnum    = itl->dh_transforms[itl->dh_i];
    ta.group       = lookup_group(ta.groupnum);

    st->st_oakley = ta;

    if (r_sa_pbs != NULL)
    {
	return ikev2_emit_winning_sa(st, r_sa_pbs
				     , ta
				     , /*parentSA*/TRUE
				     , winning_prop);
    }
    return NOTHING_WRONG;
}

static bool
spdb_v2_match_child(struct db_sa *sadb
	      , unsigned propnum
	      , unsigned encr_transform
	      , int encr_keylen
	      , unsigned integ_transform
	      , int integ_keylen
	      , unsigned esn_transform)
{
    struct db_v2_prop *pd;
    unsigned int       pd_cnt;
    bool encr_matched, integ_matched, esn_matched;

    encr_matched=integ_matched=esn_matched=FALSE;

    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	struct db_v2_prop_conj  *pj;
	struct db_v2_trans      *tr;
	unsigned int             tr_cnt;
	int encrid, integid, prfid, dhid, esnid;

	pd = &sadb->prop_disj[pd_cnt];
	encrid = integid = prfid = dhid = esnid = 0;
	encr_matched=integ_matched=esn_matched=FALSE;

	/* XXX need to fix this */
	if(pd->prop_cnt != 1) continue;

	pj = &pd->props[0];
	if(pj->protoid == PROTO_ISAKMP) continue;

	for(tr_cnt=0; tr_cnt < pj->trans_cnt; tr_cnt++) {
	   int keylen = -1;
	   unsigned int attr_cnt;

	    tr = &pj->trans[tr_cnt];

	    for (attr_cnt=0; attr_cnt < tr->attr_cnt; attr_cnt++) {
		struct db_attr *attr = &tr->attrs[attr_cnt];

		if (attr->type.ikev2 == IKEv2_KEY_LENGTH)
			keylen = attr->val;
	    }

	    switch(tr->transform_type) {
	    case IKEv2_TRANS_TYPE_ENCR:
		encrid = tr->transid;
		if(tr->transid == encr_transform && keylen == encr_keylen)
		    encr_matched=TRUE;
		break;

	    case IKEv2_TRANS_TYPE_INTEG:
		integid = tr->transid;
		if(tr->transid == integ_transform && keylen == integ_keylen)
		    integ_matched=TRUE;
		break;

	    case IKEv2_TRANS_TYPE_ESN:
		esnid = tr->transid;
		if(tr->transid == esn_transform)
		    esn_matched=TRUE;
		break;

	    default:
		continue;
	    }

	    if(esn_matched && integ_matched && encr_matched)
		return TRUE;
	}
	if(DBGP(DBG_CONTROLMORE)) {
	    DBG_log("proposal %u %s encr= (policy:%s vs offered:%s)"
		    , propnum
		    , encr_matched ? "failed" : "     "
		    , enum_name(&trans_type_encr_names, encrid)
		    , enum_name(&trans_type_encr_names, encr_transform));
	    DBG_log("            %s integ=(policy:%s vs offered:%s)"
		    , integ_matched ? "failed" : "     "
		    , enum_name(&trans_type_integ_names, integid)
		    , enum_name(&trans_type_integ_names, integ_transform));
	    DBG_log("            %s esn=  (policy:%s vs offered:%s)"
		    , esn_matched ? "failed" : "     "
		    , enum_name(&trans_type_esn_names, esnid)
		    , enum_name(&trans_type_esn_names, esn_transform));
	}

    }
    return FALSE;
}


static bool
ikev2_match_transform_list_child(struct db_sa *sadb
				 , unsigned int propnum
				 , struct ikev2_transform_list *itl)
{
    if(itl->encr_trans_next < 1) {
	openswan_log("ignored proposal %u with no cipher transforms",
		     propnum);
	return FALSE;
    }
    if(itl->integ_trans_next < 1) {
	openswan_log("ignored proposal %u with no integrity transforms",
		     propnum);
	return FALSE;
    }
    if(itl->esn_trans_next == 0) {
	/* what is the default for IKEv2? */
	itl->esn_transforms[itl->esn_trans_next++]=IKEv2_ESN_DISABLED;
    }

    /*
     * now that we have a list of all the possibilities, see if any
     * of them fit.
     */
    for(itl->encr_i=0; itl->encr_i < itl->encr_trans_next; itl->encr_i++) {
	for(itl->integ_i=0; itl->integ_i < itl->integ_trans_next; itl->integ_i++) {
	    for(itl->esn_i=0; itl->esn_i<itl->esn_trans_next; itl->esn_i++) {
		if(spdb_v2_match_child(sadb, propnum,
				       itl->encr_transforms[itl->encr_i],
				       itl->encr_keylens[itl->encr_i],
				       itl->integ_transforms[itl->integ_i],
				       itl->integ_keylens[itl->integ_i],
				       itl->esn_transforms[itl->esn_i])) {
		    return TRUE;
		}
	    }
	}
    }
    return FALSE;
}

v2_notification_t
ikev2_parse_child_sa_body(
    pb_stream *sa_pbs,              /* body of input SA Payload */
    const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
    pb_stream *r_sa_pbs,	    /* if non-NULL, where to emit winning SA */
    struct state *st,  	            /* current state object */
    bool selection                 /* if this SA is a selection, only one
				     * tranform can appear. */
    )
{
    pb_stream proposal_pbs;
    struct ikev2_prop proposal;
    unsigned int np = ISAKMP_NEXT_P;
    /* we need to parse proposal structures until there are none */
    unsigned int lastpropnum=-1;
    bool conjunction, gotmatch;
    struct ikev2_prop winning_prop;
    struct db_sa *p2alg;
    struct trans_attrs ta, ta1;
    struct connection *c = st->st_connection;
    struct ikev2_transform_list itl0, *itl;

    memset(&itl0, 0, sizeof(struct ikev2_transform_list));
    itl = &itl0;

    /* find the policy structures */
    p2alg = kernel_alg_makedb(c->policy
			      , c->alg_info_esp
			      , TRUE);

    p2alg = sa_v2_convert(p2alg);

    gotmatch = FALSE;
    conjunction = FALSE;
    zero(&ta);
    zero(&ta1);

    while(np == ISAKMP_NEXT_P) {
	/*
	 * note: we don't support ESN,
	 * so ignore any proposal that insists on it
	 */

	if(!in_struct(&proposal, &ikev2_prop_desc, sa_pbs, &proposal_pbs))
	    return PAYLOAD_MALFORMED;

	switch(proposal.isap_protoid) {
	case PROTO_ISAKMP:
	    loglog(RC_LOG_SERIOUS, "unexpected PARENT_SA, expected child");
	    return PAYLOAD_MALFORMED;
	    break;

	case PROTO_IPSEC_ESP:
	    if (proposal.isap_spisize == 4)
	    {
		unsigned int spival;
		if(!in_raw(&spival, proposal.isap_spisize
			   , &proposal_pbs, "CHILD SA SPI"))
		    return PAYLOAD_MALFORMED;

		DBG(DBG_PARSING
		    , DBG_log("SPI received: %08x", ntohl(spival)));
		itl->spi_values[itl->spi_values_next++]=spival;
	    }
	    else
	    {
		loglog(RC_LOG_SERIOUS, "invalid SPI size (%u) in CHILD_SA Proposal"
		       , (unsigned)proposal.isap_spisize);
		return INVALID_SPI;
	    }
	    break;

	default:
	    loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) found in PARENT_SA Proposal"
		   , enum_show(&protocol_names, proposal.isap_protoid));
	    return INVALID_PROTOCOL_ID;
	}

	if(proposal.isap_propnum == lastpropnum) {
	    conjunction = TRUE;
	} else {
	    lastpropnum = proposal.isap_propnum;
	    conjunction = FALSE;
	}

	if(gotmatch && conjunction == FALSE) {
	    /* we already got a winner, and it was an OR with this one,
	       so do no more work. */
	    break;
	}

	if(!gotmatch && conjunction == TRUE) {
	    /*
	     * last one failed, and this next one is an AND, so this
	     * one can not succeed either, so don't bother.
	     */
	    continue;
	}

	gotmatch = FALSE;

	{ stf_status ret = ikev2_process_transforms(&proposal
						    , &proposal_pbs, itl);
	    if(ret != STF_OK) return ret;
	}

	np = proposal.isap_np;

	if(ikev2_match_transform_list_child(p2alg
					    , proposal.isap_propnum
					    , itl)) {

	    gotmatch = TRUE;
	    winning_prop = proposal;

	    /* gotmatch is true, so will never go inside if*/
	    //if(selection && !gotmatch && np == ISAKMP_NEXT_P) {
		//openswan_log("More than 1 proposal received from responder, ignoring rest. First one did not match");
		//return NO_PROPOSAL_CHOSEN;
	    //}
	}
    }

    /*
     * we are out of the loop. There are two situations in which we break
     * out: gotmatch == FALSE, means nothing selected.
     */
    if(!gotmatch) {
	return NO_PROPOSAL_CHOSEN;
    }

    /* there might be some work to do here if there was a conjunction,
     * not sure yet about that case.
     */

    /*
     * since we found something that matched, we might need to emit the
     * winning value.
     */
    ta.encrypt   = itl->encr_transforms[itl->encr_i];
    ta.enckeylen = itl->encr_keylens[itl->encr_i] > 0 ?
			itl->encr_keylens[itl->encr_i] : 0;

    /* this is REALLY not correct, because this is not an IKE algorithm */
    /* XXX maybe we can leave this to ikev2 child key derivation */
    ta.encrypter = (struct encrypt_desc *)ike_alg_ikev2_find(IKE_ALG_ENCRYPT
							     , ta.encrypt
							     , ta.enckeylen);
    if (ta.encrypter)
    {
	if (!ta.enckeylen)
		ta.enckeylen = ta.encrypter->keydeflen;
    } else
	passert(ta.encrypt == IKEv2_ENCR_NULL);

    /* this is really a mess having so many different numbers for auth
     * algorithms.
     */
    ta.integ_hash  = itl->integ_transforms[itl->integ_i];

    /* here we obtain auth value for esp,
     * but loosse what is correct to be sent in the propoasl
     * so preserve the winning proposal.
     */
    ta1 = ta;
    ta.integ_hash  = alg_info_esp_v2tov1aa(ta.integ_hash);

    st->st_esp.attrs.transattrs = ta;
    st->st_esp.present = TRUE;

    /* if not confirming, then record the SPI value */
    if(!selection) {
	st->st_esp.attrs.spi = itl->spi_values[itl->spi_values_next -1];
    }
    st->st_esp.attrs.encapsulation = ENCAPSULATION_MODE_TUNNEL;

    if (r_sa_pbs != NULL)
    {
	return ikev2_emit_winning_sa(st, r_sa_pbs
				     , ta1
				     , /*parentSA*/FALSE
				     , winning_prop);
    }

    return NOTHING_WRONG;
}


stf_status ikev2_emit_ipsec_sa(struct msg_digest *md
			       , pb_stream *outpbs
			       , unsigned int np
			       , struct connection *c
			       , lset_t policy)
{
    int proto;
    struct db_sa *p2alg;

    if(c->policy & POLICY_ENCRYPT) {
	proto = PROTO_IPSEC_ESP;
    } else if(c->policy & POLICY_AUTHENTICATE) {
	proto = PROTO_IPSEC_AH;
    } else {
	return STF_FATAL;
    }

    p2alg = kernel_alg_makedb(policy
			      , c->alg_info_esp
			      , TRUE);

    p2alg = sa_v2_convert(p2alg);

    ikev2_out_sa(outpbs
		 , proto
		 , p2alg
		 , md->st
		 , FALSE, np);

    return STF_OK;
}



/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
