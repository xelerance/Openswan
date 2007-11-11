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
#include "smartcard.h"
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

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "ikev2.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#define return_on(var, val) do { var=val;goto return_out; } while(0);

bool
ikev2_out_sa(pb_stream *outs
	     , struct db_sa *sadb
	     , struct state *st
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
	sa.isasa_critical = ISAKMP_PAYLOAD_CRITICAL;
	/* no ipsec_doi on IKEv2 */

	if (!out_struct(&sa, &ikev2_sa_desc, outs, &sa_pbs))
	    return_on(ret, FALSE);
    }

    if(sadb->prop_disj_cnt == 0 || sadb->prop_disj) {
	st->st_sadb = sadb = sa_v2_convert(st->st_sadb);
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
	    
	    /* if there is a next proposal, then the np needs to be set right */
	    if(pr_cnt+1 < vp->prop_cnt || pc_cnt+1 < sadb->prop_disj_cnt) {
		p.isap_np      = ISAKMP_NEXT_P;
	    } else {
		p.isap_np      = ISAKMP_NEXT_NONE;
	    }
	    
	    p.isap_length  = 0;
	    p.isap_propnum = vpc->propnum;
	    p.isap_protoid = PROTO_ISAKMP;
	    p.isap_spisize = 0;  /* set when we rekey */
	    p.isap_numtrans= vpc->trans_cnt;
	    
	    if (!out_struct(&p, &ikev2_prop_desc, &sa_pbs, &t_pbs))
		return_on(ret, FALSE);
	    
	    if(p.isap_spisize > 0) {
		/* out_raw() with SPI value */
	    }
	
	    for(ts_cnt=0; ts_cnt < vpc->trans_cnt; ts_cnt++) {
		struct db_v2_trans *tr = &vpc->trans[ts_cnt];
		struct ikev2_trans t;
		pb_stream at_pbs;
	    
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
		
		/* here we need to send out the attributes */
		/* XXX */
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

    u_int16_t              auth_method;     /* conveyed another way in ikev2*/
    u_int16_t              encr_transid;	/* Transform-Id */
    u_int16_t              integ_transid;	/* Transform-Id */
    u_int16_t              prf_transid;	/* Transform-Id */
    u_int16_t              group_transid;	/* Transform-Id */
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
    case AUTH_ALGORITHM_HMAC_MD5:
	return IKEv2_AUTH_HMAC_MD5_96;
    case AUTH_ALGORITHM_HMAC_SHA1:
	return IKEv2_AUTH_HMAC_SHA1_96;
    case AUTH_ALGORITHM_DES_MAC:
	return IKEv2_AUTH_DES_MAC;
    case AUTH_ALGORITHM_KPDK:
	return IKEv2_AUTH_KPDK_MD5;

    case AUTH_ALGORITHM_HMAC_SHA2_256:
    case AUTH_ALGORITHM_HMAC_SHA2_384:
    case AUTH_ALGORITHM_HMAC_SHA2_512:
    case AUTH_ALGORITHM_HMAC_RIPEMD:
    default:
	return IKEv2_AUTH_INVALID;
	/* return IKEv2_AUTH_AES_XCBC_96; */
    }
}

struct db_sa *sa_v2_convert(struct db_sa *f)
{
    unsigned int pcc, prc, tcc;
    int tot_trans, i;
    struct db_trans_flat *dtfset;
    struct db_trans_flat *dtfone;
    struct db_trans_flat *dtflast;
    struct db_v2_trans     *tr;
    struct db_v2_prop_conj *pc;
    struct db_v2_prop      *pr;
    unsigned int            pr_cnt, pc_cnt, propnum;

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
		
		dtfone->protoid        = dp->protoid;
		for(attr_cnt=0; attr_cnt<tr->attr_cnt; attr_cnt++) {
		    struct db_attr *attr = &tr->attrs[attr_cnt];
		    switch(attr->type) {
		    case OAKLEY_AUTHENTICATION_METHOD:
			dtfone->auth_method = attr->val;
			break;
			
		    case OAKLEY_ENCRYPTION_ALGORITHM:
			dtfone->encr_transid = attr->val;
			break;
		    case OAKLEY_HASH_ALGORITHM:
			if(dtfone->protoid == PROTO_ISAKMP) {
			    dtfone->prf_transid=attr->val;
			} else {
			    dtfone->integ_transid=attr->val;
			}
			break;
			
		    case OAKLEY_GROUP_DESCRIPTION:
			dtfone->group_transid = attr->val;
			break;

		    default:
			break;
		    }
		}
		tot_trans++;
	    }
	}
    }
    
    pr=NULL;
    pr_cnt=0;
    if(tot_trans > 1) {
	pr = alloc_bytes(sizeof(struct db_v2_prop), "db_v2_prop");
    }
    dtflast = NULL;
    tr = NULL;
    pc = NULL; pc_cnt = 0;
    propnum=1;
    
    for(i=0; i < tot_trans; i++) {
	int tr_cnt = 3;

	dtfone = &dtfset[i];

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
	if(dtfone->protoid != PROTO_ISAKMP) tr_cnt=4;
	    
	tr = alloc_bytes(sizeof(struct db_v2_trans)*(tr_cnt+1), "db_v2_trans");
	pc[pc_cnt].trans=tr;  pc[pc_cnt].trans_cnt = tr_cnt+1;
	
	pc[pc_cnt].propnum = propnum;
	pc[pc_cnt].protoid = dtfset->protoid;
	
	tr[0].transform_type = IKEv2_TRANS_TYPE_ENCR;
	tr[0].transid        = v1tov2_encr(dtfone->encr_transid);
	
	if(dtfone->integ_transid == 0) {
	    tr[1].transid        = IKEv2_AUTH_HMAC_SHA1_96;
	} else {
	    tr[1].transid        = v1tov2_integ(dtfone->integ_transid);
	}
	tr[1].transform_type = IKEv2_TRANS_TYPE_INTEG;
	
	tr[2].transform_type = IKEv2_TRANS_TYPE_PRF;
	tr[2].transid        = dtfone->prf_transid;
	
	tr[3].transform_type = IKEv2_TRANS_TYPE_DH;
	tr[3].transid        = dtfone->group_transid;

	if(dtfone->protoid != PROTO_ISAKMP) {
	    tr[4].transform_type = IKEv2_TRANS_TYPE_ESN;
	    tr[4].transid        = IKEv2_ESN_DISABLED;
	}
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
    bool dh_matched;

    dh_matched=FALSE;

    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	struct db_v2_prop_conj  *pj;
	struct db_v2_trans      *tr;
	unsigned int             tr_cnt;

	pd = &sadb->prop_disj[pd_cnt];
	dh_matched=FALSE;

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
spdb_v2_match(struct db_sa *sadb
	      , unsigned encr_transform
	      , unsigned integ_transform
	      , unsigned prf_transform
	      , unsigned dh_transform
	      , unsigned esn_transform)
{
    struct db_v2_prop *pd;
    unsigned int       pd_cnt;
    bool encr_matched, integ_matched, prf_matched, dh_matched, esn_matched;

    encr_matched=integ_matched=prf_matched=dh_matched=esn_matched=FALSE;

    for(pd_cnt=0; pd_cnt < sadb->prop_disj_cnt; pd_cnt++) {
	struct db_v2_prop_conj  *pj;
	struct db_v2_trans      *tr;
	unsigned int             tr_cnt;

	pd = &sadb->prop_disj[pd_cnt];
	encr_matched=integ_matched=prf_matched=dh_matched=esn_matched=FALSE;
	if(pd->prop_cnt != 1) continue;

	/* In PARENT SAs, we only support one conjunctive item */
	pj = &pd->props[0];
	if(pj->protoid  != PROTO_ISAKMP) continue;

	for(tr_cnt=0; tr_cnt < pj->trans_cnt; tr_cnt++) {

	    tr = &pj->trans[tr_cnt];
	    
	    switch(tr->transform_type) {
	    case IKEv2_TRANS_TYPE_ENCR:
		if(tr->transid == encr_transform)
		    encr_matched=TRUE;
		break;
		
	    case IKEv2_TRANS_TYPE_INTEG:
		if(tr->transid == integ_transform)
		    integ_matched=TRUE;
		break;
		
	    case IKEv2_TRANS_TYPE_PRF:
		if(tr->transid == prf_transform)
		    prf_matched=TRUE;
		break;
		
	    case IKEv2_TRANS_TYPE_DH:
		if(tr->transid == dh_transform)
		    dh_matched=TRUE;
		break;

	    case IKEv2_TRANS_TYPE_ESN:
		if(tr->transid == esn_transform)
		    esn_matched=TRUE;
		break;
	    }

	    if(dh_matched && prf_matched && integ_matched && encr_matched)
		return TRUE;
	}
    }
    return FALSE;
}


#define MAX_TRANS_LIST 32         /* 32 is an arbitrary limit */

notification_t
parse_ikev2_sa_body(
    pb_stream *sa_pbs,              /* body of input SA Payload */
    const struct ikev2_sa *sa_prop UNUSED, /* header of input SA Payload */
    pb_stream *r_sa_pbs UNUSED,	    /* if non-NULL, where to emit winning SA */
    bool selection UNUSED,          /* if this SA is a selection, only one 
				     * tranform can appear. */
    struct state *st)	        /* current state object */
{
    pb_stream proposal_pbs;
    struct ikev2_prop proposal;
    unsigned int np = ISAKMP_NEXT_P;
    /* we need to parse proposal structures until there are none */
    unsigned int lastpropnum=-1;
    bool conjunction, gotmatch, oldgotmatch;
    struct ikev2_prop winning_prop;
    struct db_sa *sadb;
    struct oakley_trans_attrs ta;
    struct connection *c = st->st_connection;
    int    policy_index = POLICY_ISAKMP(c->policy
					, c->spd.this.xauth_server
					, c->spd.this.xauth_client);
    unsigned int encr_transforms[MAX_TRANS_LIST];    
    unsigned int encr_trans_next=0, encr_i;
    unsigned int integ_transforms[MAX_TRANS_LIST];   
    unsigned int integ_trans_next=0, integ_i;
    unsigned int prf_transforms[MAX_TRANS_LIST];     
    unsigned int prf_trans_next=0,   prf_i;
    unsigned int dh_transforms[MAX_TRANS_LIST];      
    unsigned int dh_trans_next=0,    dh_i;
    unsigned int esn_transforms[MAX_TRANS_LIST];      
    unsigned int esn_trans_next=0,   esn_i;


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
	
    while(np == ISAKMP_NEXT_P) {
	/*
	 * note: we don't support ESN,
	 * so ignore any proposal that insists on it
	 */
	
	if(!in_struct(&proposal, &ikev2_prop_desc, sa_pbs, &proposal_pbs))
	    return PAYLOAD_MALFORMED;

	if(proposal.isap_protoid != PROTO_ISAKMP)
	{
	    loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) found in PARENT_SA Proposal"
		   , enum_show(&protocol_names, proposal.isap_protoid));
	    return INVALID_PROTOCOL_ID;
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

	oldgotmatch = gotmatch;
	gotmatch = FALSE;

	while(proposal.isap_numtrans-- > 0) {
	    pb_stream trans_pbs;
	    //u_char *attr_start;
	    //size_t attr_len;
	    struct ikev2_trans trans;
	    struct oakley_trans_attrs ta;
	    //err_t ugh = NULL;	/* set to diagnostic when problem detected */
	    zero(&ta);

	    if (!in_struct(&trans, &ikev2_trans_desc
			   , &proposal_pbs, &trans_pbs))
		return BAD_PROPOSAL_SYNTAX;
	    
	    /* we read the attributes if we need to see details. */
	    /* XXX deal with different sizes AES keys */
	    switch(trans.isat_type) {
	    case IKEv2_TRANS_TYPE_ENCR:
		if(encr_trans_next < MAX_TRANS_LIST) {
		    encr_transforms[encr_trans_next++]=trans.isat_transid;
		}
		break;
		
	    case IKEv2_TRANS_TYPE_INTEG:
		if(integ_trans_next < MAX_TRANS_LIST) {
		    integ_transforms[integ_trans_next++]=trans.isat_transid;
		}
		break;
		
	    case IKEv2_TRANS_TYPE_PRF:
		if(prf_trans_next < MAX_TRANS_LIST) {
		    prf_transforms[prf_trans_next++]=trans.isat_transid;
		}
		break;
		
	    case IKEv2_TRANS_TYPE_DH:
		if(dh_trans_next < MAX_TRANS_LIST) {
		    dh_transforms[dh_trans_next++]=trans.isat_transid;
		}
		break;

	    case IKEv2_TRANS_TYPE_ESN:
		if(esn_trans_next < MAX_TRANS_LIST) {
		    esn_transforms[esn_trans_next++]=trans.isat_transid;
		}
		break;
	    }
	}

	if(encr_trans_next < 1) {
	    openswan_log("ignored proposal %u with no cipher transforms",
			 proposal.isap_propnum);
	    continue;
	}
	if(integ_trans_next < 1) {
	    openswan_log("ignored proposal %u with no integrity transforms",
			 proposal.isap_propnum);
	    continue;
	}
	if(prf_trans_next < 1) {
	    openswan_log("ignored proposal %u with no prf transforms",
			 proposal.isap_propnum);
	    continue;
	}
	if(dh_trans_next < 1) {
	    openswan_log("ignored proposal %u with no diffie-hellman transforms",
			 proposal.isap_propnum);
	    continue;
	}
	if(esn_trans_next == 0) {
	    /* what is the default for IKEv2? */
	    esn_transforms[esn_trans_next++]=IKEv2_ESN_DISABLED;
	}

	/*
	 * now that we have a list of all the possibilities, see if any
	 * of them fit.
	 *
	 * XXX - have to deal with attributes.
	 *
	 */
	for(encr_i=0; encr_i < encr_trans_next; encr_i++) {
	    for(integ_i=0; integ_i < integ_trans_next; integ_i++) {
		for(prf_i=0; prf_i < prf_trans_next; prf_i++) {
		    for(dh_i=0; dh_i < dh_trans_next; dh_i++) {
			for(esn_i=0; esn_i < esn_trans_next; esn_i++) {
			    gotmatch = spdb_v2_match(sadb,
						     encr_transforms[encr_i],
						     integ_transforms[integ_i],
						     prf_transforms[prf_i],
						     dh_transforms[dh_i],
						     esn_transforms[esn_i]);
			    winning_prop = proposal;
			    if(gotmatch) break;
			}
			if(gotmatch) break;
		    }
		    if(gotmatch) break;
		}
		if(gotmatch) break;
	    }
	    if(gotmatch) break;
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
    ta.encrypt   = encr_transforms[encr_i];
    ta.encrypter = (struct encrypt_desc *)ike_alg_ikev2_find(IKE_ALG_ENCRYPT
							     , ta.encrypt
							     , /*keysize*/0);
    passert(ta.encrypter != NULL);
    ta.enckeylen = ta.encrypter->keydeflen;
    ta.integ_hash  = integ_transforms[integ_i];
    ta.integ_hasher= crypto_get_hasher(ta.integ_hash);
    ta.prf_hash  = prf_transforms[prf_i];
    ta.prf_hasher= crypto_get_hasher(ta.prf_hash);
    ta.groupnum  = dh_transforms[dh_i];
    ta.group     = lookup_group(ta.groupnum); 

    if (r_sa_pbs != NULL)
    {
	struct ikev2_prop  r_proposal = winning_prop;
	pb_stream r_proposal_pbs;
	struct ikev2_trans r_trans;
	pb_stream r_trans_pbs;

	memset(&r_trans, 0, sizeof(r_trans));

	/* Proposal - XXX */
	r_proposal.isap_spisize = 0;
	r_proposal.isap_numtrans = 5;
	r_proposal.isap_np = ISAKMP_NEXT_NONE;

	if(!out_struct(&r_proposal, &ikev2_prop_desc
		       , r_sa_pbs, &r_proposal_pbs))
	    impossible();

	/* Transform - cipher */
	r_trans.isat_type= IKEv2_TRANS_TYPE_ENCR;
	r_trans.isat_transid = ta.encrypt;
	r_trans.isat_np = ISAKMP_NEXT_T;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, NULL))
	    impossible();
	close_output_pbs(&r_trans_pbs);

	/* Transform - integrity check */
	r_trans.isat_type= IKEv2_TRANS_TYPE_INTEG;
	r_trans.isat_transid = ta.integ_hash;
	r_trans.isat_np = ISAKMP_NEXT_T;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, NULL))
	    impossible();
	close_output_pbs(&r_trans_pbs);

	/* Transform - PRF hash */
	r_trans.isat_type= IKEv2_TRANS_TYPE_PRF;
	r_trans.isat_transid = ta.groupnum;
	r_trans.isat_np = ISAKMP_NEXT_T;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, NULL))
	    impossible();
	close_output_pbs(&r_trans_pbs);

	/* Transform - DH hash */
	r_trans.isat_type= IKEv2_TRANS_TYPE_DH;
	r_trans.isat_transid = ta.prf_hash;
	r_trans.isat_np = ISAKMP_NEXT_T;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, NULL))
	    impossible();
	close_output_pbs(&r_trans_pbs);

	/* Transform - ESN sequence */
	r_trans.isat_type= IKEv2_TRANS_TYPE_ESN;
	r_trans.isat_transid = IKEv2_ESN_DISABLED;
	r_trans.isat_np = ISAKMP_NEXT_NONE;
	if(!out_struct(&r_trans, &ikev2_trans_desc
		       , &r_proposal_pbs, NULL))
	    impossible();
	close_output_pbs(&r_trans_pbs);

	/* close out the proposal */
	close_output_pbs(&r_proposal_pbs);
	close_output_pbs(r_sa_pbs);
    }

    /* ??? If selection, we used to save the proposal in state.
     * We never used it.  From proposal_pbs.start,
     * length pbs_room(&proposal_pbs)
     */
    
    /* copy over the results */
    st->st_oakley = ta;
    return NOTHING_WRONG;
}
    
    
/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
