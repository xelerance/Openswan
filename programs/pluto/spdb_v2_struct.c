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
	     , struct db_sa *sadb UNUSED
	     , struct state *st UNUSED
	     , u_int8_t np)
{
    pb_stream sa_pbs;
    bool ret = FALSE;
    int  pc_cnt;

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
	sa_v2_convert(sadb);
    }

    /* now send out all the proposals */
    for(pc_cnt=0; pc_cnt < sadb->prop_disj_cnt; pc_cnt++)
    {
	struct db_v2_prop *vp = &sadb->prop_disj[pc_cnt];
	int pr_cnt;	    

	/* now send out all the transforms */
	for(pr_cnt=0; pr_cnt < vp->prop_cnt; pr_cnt++)
	{
	    int ts_cnt;	    
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
	    p.isap_propnum = pr_cnt+1;
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

void sa_v2_convert(struct db_sa *f)
{
    int pcc, prc, tcc;
    int tot_trans, i;
    struct db_trans_flat *dtfset;
    struct db_trans_flat *dtfone;
    struct db_trans_flat *dtflast;
    struct db_v2_trans     *tr;
    struct db_v2_prop_conj *pc;
    struct db_v2_prop      *pr;
    int                     pr_cnt, pc_cnt;
    
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
		int attr_cnt;
		
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
    
    for(i=0; i < tot_trans; i++) {
	int tr_cnt = 3;

	dtfone = &dtfset[i];

	if(dtflast != NULL) {
	    /*
	     * see if previous protoid is identical to this
	     * one, and if so, then this is a disjunction (OR),
	     * otherwise, it's conjunction (AND)
	     */
	    if(dtflast->protoid != dtfone->protoid) {
		/* need to extend pr by one */
		struct db_v2_prop *pr1;
		pr_cnt++;
		pr1 = alloc_bytes(sizeof(struct db_v2_prop)*(pr_cnt+1), "db_v2_prop");
		memcpy(pr1, pr, sizeof(struct db_v2_prop)*pr_cnt);
		pfree(pr);
		pr = pr1;
		
		/* need to zero this, so it gets allocated */
		pc = NULL;
		pc_cnt=0;
	    } else {
		struct db_v2_prop_conj *pc1;
		/* need to extend pc by one */
		pc_cnt++;

		pc1 = alloc_bytes(sizeof(struct db_v2_prop_conj)*(pc_cnt+1), "db_v2_prop_conj");
		memcpy(pc1, pc, sizeof(struct db_v2_prop_conj)*pc_cnt);
		pfree(pc);
		pc = pc1;
		pr[pr_cnt].props=pc;
		pr[pr_cnt].prop_cnt=pc_cnt+1;
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
}

    
/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
