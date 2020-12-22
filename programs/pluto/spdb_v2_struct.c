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
#include "pluto/connections.h"	/* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "pluto/spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#include "pluto/plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "pluto/crypto.h" /* requires sha1.h and md5.h */

#include "demux.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "pluto/ike_alg.h"
#include "pluto/db2_ops.h"
#include "ikev2.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#define return_on(var, val) do { var=val;goto return_out; } while(0);

/* Taken from spdb_v1_struct.c, as the format is similar */
bool
ikev2_out_attr(unsigned int type
	, unsigned long val
	, struct_desc *attr_desc
	, enum_names **attr_val_descs USED_BY_DEBUG
	, pb_stream *pbs)
{
    struct ikev2_trans_attr attr;
    enum_names *d;

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
        if(type < ikev2_trans_attr_val_descs_size
           && (d = attr_val_descs[type])!=NULL) {
            DBG_log("    [%lu is %s]", val, enum_show(d, val));
        })

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

    pbs_set_np(outs, ISAKMP_NEXT_v2SA);

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
	get_ipsec_spi(&st->st_esp /* avoid this # */
		      , IPPROTO_ESP
		      , st
		      , TRUE /* tunnel */);
    }

    for(pc_cnt=0; pc_cnt < sadb->prop_disj_cnt; pc_cnt++)
    {
	struct db_v2_prop *vp = &sadb->prop_disj[pc_cnt];
	unsigned int pr_cnt;


	/* now send out all the proposals */
	for(pr_cnt=0; pr_cnt < vp->prop_cnt; pr_cnt++)
	{
	    unsigned int ts_cnt;
	    struct db_v2_prop_conj *vpc = &vp->props[pr_cnt];
	    struct ikev2_prop p;
	    pb_stream t_pbs;

	    if (!vp->props) {
                openswan_log("%s: FATAL: prop_cnt=%d, but props=NULL",
                             __func__, vp->prop_cnt);
                return STF_INTERNAL_ERROR;
            }
	    vpc = &vp->props[pr_cnt];

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

	    /* now send out all the transforms */
	    for(ts_cnt=0; ts_cnt < vpc->trans_cnt; ts_cnt++) {
		struct db_v2_trans *tr = &vpc->trans[ts_cnt];
		struct ikev2_trans t;
		pb_stream at_pbs;
		unsigned int attr_cnt;

		memset(&t, 0, sizeof(t));
		if(ts_cnt+1 < vpc->trans_cnt) {
		    t.isat_np      = ISAKMP_NEXT_T;
		} else {
		    t.isat_np      = ISAKMP_NEXT_NONE;
		}

		t.isat_length = 0;
		t.isat_type   = tr->transform_type;
		t.isat_transid= tr->value;

		if (!out_struct(&t, &ikev2_trans_desc, &t_pbs, &at_pbs))
		    return_on(ret, FALSE);

		for (attr_cnt=0; attr_cnt < tr->attr_cnt; attr_cnt++) {
		    struct db_v2_attr *attr = &tr->attrs[attr_cnt];

		    ikev2_out_attr(attr->ikev2, attr->val
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

/*
 * the inputs to this function are the proposals from the other end.
 * they get matched to the configured policy contained in the sadb.
 */
static bool
spdb_v2_match_parent(struct db_sa *sadb
	      , unsigned propnum
	      , unsigned encr_transform
	      , int encr_keylen
	      , unsigned integ_transform
	      , unsigned prf_transform
	      , unsigned dh_transform)
{
    struct db_v2_prop *pd;
    unsigned int       pd_cnt, attempt;
    bool encr_matched, integ_matched, prf_matched, dh_matched;

    attempt = 1;
    encr_matched=integ_matched=prf_matched=dh_matched=FALSE;

    //DBG_log("prop_disj_cnt: %u", sadb->prop_disj_cnt);
    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	unsigned int pj_cnt;
	int encrid, integid, prfid, dhid, esnid;
        int encr_keylen_policy;

	pd = &sadb->prop_disj[pd_cnt];
	encrid = integid = prfid = dhid = esnid = 0;
        encr_keylen_policy = 0;
	encr_matched=integ_matched=prf_matched=dh_matched=FALSE;

	for(pj_cnt=0; pj_cnt < pd->prop_cnt; pj_cnt++) {
	    struct db_v2_prop_conj  *pj;
	    struct db_v2_trans      *tr;
	    unsigned int             tr_cnt;

	    pj = &pd->props[pj_cnt];
	    if (pj->protoid != PROTO_ISAKMP)
		continue;

	    for(tr_cnt=0; tr_cnt < pj->trans_cnt; tr_cnt++) {
		int keylen = -1;
		unsigned int attr_cnt;

		tr = &pj->trans[tr_cnt];

		for (attr_cnt=0; attr_cnt < tr->attr_cnt; attr_cnt++) {
		    struct db_v2_attr *attr = &tr->attrs[attr_cnt];

		    if (attr->ikev2 == IKEv2_KEY_LENGTH)
			keylen = attr->val;
		}

		/* the assignments are outside of the if, because they are
		 * used to debug things when the match fails
		 */
		switch(tr->transform_type) {
		case IKEv2_TRANS_TYPE_ENCR:
		    encrid = tr->value;
		    encr_keylen_policy = keylen;
		    if(tr->value == encr_transform && (encr_keylen_policy == -1 || encr_keylen_policy == encr_keylen)) {
			encr_matched=TRUE;
		    }
		    break;

		case IKEv2_TRANS_TYPE_INTEG:
		    integid = tr->value;
		    if(tr->value == integ_transform) {
			integ_matched=TRUE;
		    }
		    break;

		case IKEv2_TRANS_TYPE_PRF:
		    prfid = tr->value;
		    if(tr->value == prf_transform) {
			prf_matched=TRUE;
		    }
		break;

		case IKEv2_TRANS_TYPE_DH:
		    dhid = tr->value;
		    if(tr->value == dh_transform) {
			dh_matched=TRUE;
		    }
		    break;

		default:
		    continue; /* could be clearer as a break */
		}

		/* esn_matched not tested! */
		if(dh_matched && prf_matched && integ_matched && encr_matched) {
		    if(DBGP(DBG_CONTROL)) {
			DBG_log("selected proposal %u encr=%s[%d] integ=%s prf=%s modp=%s"
                            , propnum
                            , enum_name(&trans_type_encr_names, encrid), encr_keylen
                            , enum_name(&trans_type_integ_names, integid)
                            , enum_name(&trans_type_prf_names, prfid)
                            , enum_name(&oakley_group_names, dhid));
		    }

		    return TRUE;
		}
	    }
	    /* only dumped when there is no match: it can be volumnous */
	    if(DBGP(DBG_CONTROLMORE)) {
		/* note: enum_show uses a static buffer so more than one call per
		 *       statement is dangerous */
		DBG_log("proposal %u %6s encr= (policy:%20s[%d] vs offered:%s[%d]) [%u,%u]"
		    , propnum
		    , encr_matched ? "succ" : "failed"
		    , enum_name(&trans_type_encr_names, encrid), encr_keylen
		    , enum_show(&trans_type_encr_names, encr_transform), encr_keylen_policy
                    , pd_cnt, attempt++);
		DBG_log("proposal %u %6s integ=(policy:%20s vs offered:%s)"
                    , propnum
		    , integ_matched ? "succ" : "failed"
		    , enum_name(&trans_type_integ_names, integid)
		    , enum_show(&trans_type_integ_names, integ_transform));
		DBG_log("proposal %u %6s prf=  (policy:%20s vs offered:%s)"
                    , propnum
		    , prf_matched ? "succ" : "failed"
		    , enum_name(&trans_type_prf_names, prfid)
		    , enum_show(&trans_type_prf_names, prf_transform));
		DBG_log("proposal %u %6s dh=   (policy:%20s vs offered:%s)"
                    , propnum
		    , dh_matched ? "succ" : "failed"
		    , enum_name(&oakley_group_names, dhid)
		    , enum_show(&oakley_group_names, dh_transform));
	    }
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
				  , struct ikev2_transform_list *itl
                                  , struct trans_attrs *winning)
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
                    DBG(DBG_PARSING,
                        DBG_log("encr: %u<=%u integ: %u<=%u prf: %u<=%u dh: %u<=%u",
                                itl->encr_i,  itl->encr_trans_next,
                                itl->integ_i, itl->integ_trans_next,
                                itl->prf_i,   itl->prf_trans_next,
                                itl->dh_i,    itl->dh_trans_next));
		    if(spdb_v2_match_parent(sadb, propnum,
					    itl->encr_transforms[itl->encr_i],
					    itl->encr_keylens[itl->encr_i],
					    itl->integ_transforms[itl->integ_i],
					    itl->prf_transforms[itl->prf_i],
					    itl->dh_transforms[itl->dh_i])) {
                        if(winning) {
                            winning->encrypt   = itl->encr_transforms[itl->encr_i];

                            if(itl->encr_keylens[itl->encr_i] == -1 ||
                               itl->encr_keylens[itl->encr_i] == 0) {
                                winning->enckeylen = 0;
                            } else {
                                winning->enckeylen = itl->encr_keylens[itl->encr_i];
                            }

                            winning->prf_hash  = itl->prf_transforms[itl->prf_i];
                            /* winning->prfkeylen = itl->prf_keylens[itl->prf_i]; */
                            winning->integ_hash  = itl->integ_transforms[itl->integ_i];
                            /* winning->prfkeylen = itl->integ_keylens[itl->integ_i]; */
                            winning->groupnum  = itl->dh_transforms[itl->dh_i];
                        }

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
    unsigned int encr_x, integ_x, prf_x, dh_x;

    encr_x=integ_x=prf_x=dh_x=0;
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
                encr_x = trans.isat_transid;
	    } /* show failure with else */
	    break;

	case IKEv2_TRANS_TYPE_INTEG:
	    if(itl->integ_trans_next < MAX_TRANS_LIST) {
		itl->integ_keylens[itl->integ_trans_next]=keylen;
		itl->integ_transforms[itl->integ_trans_next++]=trans.isat_transid;
                integ_x = trans.isat_transid;
	    }
	    break;

	case IKEv2_TRANS_TYPE_PRF:
	    if(itl->prf_trans_next < MAX_TRANS_LIST) {
		itl->prf_keylens[itl->prf_trans_next]=keylen;
		itl->prf_transforms[itl->prf_trans_next++]=trans.isat_transid;
                prf_x = trans.isat_transid;
	    }
	    break;

	case IKEv2_TRANS_TYPE_DH:
	    if(itl->dh_trans_next < MAX_TRANS_LIST) {
		itl->dh_transforms[itl->dh_trans_next++]=trans.isat_transid;
                dh_x = trans.isat_transid;
	    }
	    break;

	case IKEv2_TRANS_TYPE_ESN:
	    if(itl->esn_trans_next < MAX_TRANS_LIST) {
		itl->esn_transforms[itl->esn_trans_next++]=trans.isat_transid;
	    }
	    break;
	}
        DBG(DBG_PARSING,
            DBG_log("collect encr: %u<=%u integ: %u<=%u prf: %u<=%u dh: %u<=%u",
                    encr_x,  itl->encr_trans_next,
                    integ_x, itl->integ_trans_next,
                    prf_x,   itl->prf_trans_next,
                    dh_x,    itl->dh_trans_next));
    }
#if 0
    DBG_log("collected %u encr %u integ %u prf and  %u dh",
            itl->encr_trans_next,
            itl->integ_trans_next,
            itl->prf_trans_next,
            itl->dh_trans_next);
#endif
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
	get_ipsec_spi(&st->st_esp
		      , IPPROTO_ESP
		      , st
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
    struct trans_attrs ta;
    struct ikev2_transform_list itl0, *itl;


    /* find the policy structures */
    if(!st->st_sadb) {
        st->st_sadb = alginfo2parent_db2(st->st_connection->alg_info_ike);
    }
    //sa_v2_print(st->st_sadb);

    gotmatch = FALSE;
    conjunction = FALSE;
    zero(&ta);

    while(np == ISAKMP_NEXT_P) {
        memset(&itl0, 0, sizeof(struct ikev2_transform_list));
        itl = &itl0;
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

	if(ikev2_match_transform_list_parent(st->st_sadb
					     , proposal.isap_propnum
					     , itl
                                             , &ta)) {

	    winning_prop = proposal;
	    gotmatch = TRUE;
	}
    }

    /*
     * we are out of the loop. There are two situations in which we break
     * out: gotmatch == FALSE, means nothing selected.
     */
    if(!gotmatch) {
	return NO_PROPOSAL_CHOSEN;
    }


    /*
     * since we found something that matched, we might need to emit the
     * winning value.
     */
    ta.encrypter = (struct ike_encr_desc *)ike_alg_ikev2_find(IKEv2_TRANS_TYPE_ENCR
							     , ta.encrypt
							     , ta.enckeylen);
    passert(ta.encrypter != NULL);
    if (ta.enckeylen <= 0)
	ta.enckeylen = ta.encrypter->keydeflen;

    ta.integ_hasher= (struct ike_integ_desc *)ike_alg_ikev2_find(IKEv2_TRANS_TYPE_INTEG,ta.integ_hash, 0);
    passert(ta.integ_hasher != NULL);

    ta.prf_hasher  = (struct ike_prf_desc *)ike_alg_ikev2_find(IKEv2_TRANS_TYPE_PRF, ta.prf_hash, 0);
    passert(ta.prf_hasher != NULL);

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
	      , unsigned esn_transform)
{
    struct db_v2_prop *pd;
    unsigned int       pd_cnt;
    bool encr_matched, integ_matched, esn_matched;

    encr_matched=integ_matched=esn_matched=FALSE;

    if (encr_keylen <= 0)
	/* Use default key length */
	encr_keylen = kernel_alg_esp_enc_keylen(encr_transform) * BITS_PER_BYTE;

    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	struct db_v2_prop_conj  *pj;
	struct db_v2_trans      *tr;
	unsigned int             tr_cnt;
        unsigned int             pc_cnt;
	int encrid, integid, prfid, dhid, esnid;
        int encr_keylen_policy, integ_keylen_policy;

	pd = &sadb->prop_disj[pd_cnt];
        for(pc_cnt=0; pc_cnt < pd->prop_cnt; pc_cnt++) {
            pj = &pd->props[pc_cnt];
	encrid = integid = prfid = dhid = esnid = 0;
            encr_keylen_policy = integ_keylen_policy = 0;
            encr_matched=integ_matched=FALSE;
            esn_matched=TRUE;

            if(esn_transform != 0) {
                /* if it is non-zero, then it must match */
                /* otherwise the transform is probably omitted */
                esn_matched = FALSE;
            }

	if(pj->protoid == PROTO_ISAKMP) continue;

	for(tr_cnt=0; tr_cnt < pj->trans_cnt; tr_cnt++) {
	   int keylen = -1;
	   unsigned int attr_cnt;

	    tr = &pj->trans[tr_cnt];

	    for (attr_cnt=0; attr_cnt < tr->attr_cnt; attr_cnt++) {
                    struct db_v2_attr *attr = &tr->attrs[attr_cnt];

                    if (attr->ikev2 == IKEv2_KEY_LENGTH)
			keylen = attr->val;
	    }

	    switch(tr->transform_type) {
	    case IKEv2_TRANS_TYPE_ENCR:
                    encrid = tr->value;
                    encr_keylen_policy = keylen;
                    if(tr->value == encr_transform
                       && (encr_keylen_policy == -1
                           || encr_keylen_policy == encr_keylen)) {
		    encr_matched=TRUE;
                    }
		break;

	    case IKEv2_TRANS_TYPE_INTEG:
                    integid = tr->value;
                    integ_keylen_policy = keylen;
                    if(tr->value == integ_transform) {
		    integ_matched=TRUE;
                    }
		break;

	    case IKEv2_TRANS_TYPE_ESN:
                    esnid = tr->value;
                    if(tr->value == esn_transform) {
		    esn_matched=TRUE;
                    }
		break;

	    default:
		continue;
	    }

	    if(esn_matched && integ_matched && encr_matched)
		return TRUE;
	}
	if(DBGP(DBG_CONTROLMORE)) {
                DBG_log("proposal %u,%u %s encr= (policy:%20s[%d] vs offered:%s[%d])"
                        , propnum,pc_cnt
                        , encr_matched ? "match " : "failed"
                        , enum_name(&trans_type_encr_names, encrid), encr_keylen
                        , enum_name(&trans_type_encr_names, encr_transform), encr_keylen_policy);
                DBG_log("proposal %u,%u %s integ=(policy:%20s vs offered:%s)"
                        , propnum,pc_cnt
                        , integ_matched? "match " : "failed"
                        , enum_name(&trans_type_integ_names, integid)
                        , enum_name(&trans_type_integ_names, integ_transform));
                DBG_log("proposal %u,%u %s esn=  (policy:%20s vs offered:%s)"
                        , propnum,pc_cnt
                        , esn_matched  ? "match " : "failed"
                        , enum_name(&trans_type_esn_names, esnid)
                        , enum_name(&trans_type_esn_names, esn_transform));
            }
	}

    }
    return FALSE;
}


static bool
ikev2_match_transform_list_child(struct db_sa *sadb
				 , unsigned int propnum
				 , struct ikev2_transform_list *itl
                                 , struct trans_attrs *winning)
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
				       itl->esn_transforms[itl->esn_i])) {
                    if(winning) {
                        winning->encrypt   = itl->encr_transforms[itl->encr_i];

                        if(itl->encr_keylens[itl->encr_i] == -1 ||
                           itl->encr_keylens[itl->encr_i] == 0) {
                            winning->enckeylen = 0;
                        } else {
                            winning->enckeylen = itl->encr_keylens[itl->encr_i];
                        }

                        winning->integ_hash  = itl->integ_transforms[itl->integ_i];
                        winning->esn         =itl->esn_transforms[itl->esn_i];
                    }
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
    struct trans_attrs ta;
    struct connection *c = st->st_connection;
    struct ikev2_transform_list itl0, *itl;

    memset(&itl0, 0, sizeof(struct ikev2_transform_list));
    itl = &itl0;

    /* find the policy structures */
    p2alg = alginfo2child_db2(c->alg_info_esp);

    gotmatch = FALSE;
    conjunction = FALSE;
    zero(&ta);

    while(np == ISAKMP_NEXT_P) {
	/*
	 * note: we don't support ESN,
	 * so ignore any proposal that insists on it
	 */
        memset(&itl0, 0, sizeof(struct ikev2_transform_list));
        itl = &itl0;

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
					    , itl, &ta)) {

	    gotmatch = TRUE;
	    winning_prop = proposal;

	}

        if(gotmatch && selection && np == ISAKMP_NEXT_P) {
            openswan_log("More than 1 proposal received from responder, ignoring rest");
            break;
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
    ta.encrypter = (struct ike_encr_desc *)ike_alg_ikev2_find(IKEv2_TRANS_TYPE_ENCR
							     , ta.encrypt
							     , ta.enckeylen);
    if (ta.encrypter)
    {
	if (!ta.enckeylen)
	ta.enckeylen = ta.encrypter->keydeflen;
    } else
	passert(ta.encrypt == IKEv2_ENCR_NULL);

    ta.integ_hasher= (struct ike_integ_desc *)ike_alg_ikev2_find(IKEv2_TRANS_TYPE_INTEG,ta.integ_hash, 0);
    passert(ta.integ_hasher != NULL);

    /*
     * here we obtain auth value for esp,
     * but loosse what is correct to be sent in the propoasl
     * so preserve the winning proposal.
     */

    st->st_esp.attrs.transattrs = ta;
    st->st_esp.present = TRUE;

    /* record the SPI value */
    st->st_esp.attrs.spi = itl->spi_values[itl->spi_values_next -1];

    /* could get changed by a notify */
    if (st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_UNSPECIFIED)
        st->st_esp.attrs.encapsulation = ENCAPSULATION_MODE_TUNNEL;

    if (r_sa_pbs != NULL)
    {
	return ikev2_emit_winning_sa(st, r_sa_pbs
				     , ta
				     , /*parentSA*/FALSE
				     , winning_prop);
    }

    return NOTHING_WRONG;
}


stf_status ikev2_emit_ipsec_sa(struct msg_digest *md
			       , pb_stream *outpbs
			       , unsigned int np
			       , struct connection *c
			       , lset_t policy UNUSED)
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

    p2alg = alginfo2child_db2(c->alg_info_esp);
    passert(p2alg != NULL);
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
