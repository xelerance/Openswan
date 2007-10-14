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
	sa.isasa_np     = np;
	sa.isasa_commit = ISAKMP_PAYLOAD_CRITICAL;
	/* no ipsec_doi on IKEv2 */

	if (!out_struct(&sa, &ikev2_sa_desc, outs, &sa_pbs))
	    return_on(ret, FALSE);
    }

    /* now send out all the proposals */
    for(pc_cnt=0; pc_cnt < sadb->prop_disj_cnt; pc_cnt++)
    {
	    struct db_v2_prop *vp = &sadb->prop_disj[pc_cnt];
	    struct ikev2_prop p;
	    pb_stream t_pbs;
	    int ts_cnt;	    

	    memset(&p, 0, sizeof(p));

	    if(pc_cnt+1 < sadb->prop_disj_cnt) {
		    p.isap_np      = ISAKMP_NEXT_P;
	    } else {
		    p.isap_np      = ISAKMP_NEXT_NONE;
	    }
		    
	    p.isap_length  = 0;
	    p.isap_propnum = pc_cnt+1;
	    p.isap_protoid = PROTO_ISAKMP;
	    p.isap_spisize = 0;  /* set when we rekey */
	    p.isap_numtrans= 1;

	    if (!out_struct(&p, &ikev2_prop_desc, &sa_pbs, &t_pbs))
		    return_on(ret, FALSE);

	    if(p.isap_spisize > 0) {
		    /* out_raw() with SPI value */
	    }

	    /* now send out all the transforms */
	    for(ts_cnt=0; ts_cnt < vp->prop_cnt; ts_cnt++)
	    {
		    struct db_v2_prop_conj *vpc = &vp->props[ts_cnt];
		    struct ikev2_trans t;
	    
		    memset(&t, 0, sizeof(t));
		    if(ts_cnt+1 < vp->prop_cnt) {
			    t.isat_np      = ISAKMP_NEXT_T;
		    } else {
			    t.isat_np      = ISAKMP_NEXT_NONE;
		    }
		    
		    t.isat_length = 0;
		    t.isat_type   = vpc->protoid;
		    t.isat_transid= ts_cnt+1;

		    if (!out_struct(&t, &ikev2_trans_desc, &t_pbs, NULL))
			    return_on(ret, FALSE);
	    }
    }

    close_output_pbs(&sa_pbs);
    ret = TRUE;

return_out:
    return ret;
}

struct db_trans_flat {
	u_int8_t               protoid;	        /* Protocol-Id */

	u_int16_t              auth_method; 
	u_int16_t              encr_transid;	/* Transform-Id */
	u_int16_t              hash_transid;	/* Transform-Id */
	u_int16_t              prf_transid;	/* Transform-Id */
	u_int16_t              group_transid;	/* Transform-Id */
};

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
	struct db_prop_conj *dpc = &f->prop_conjs[i];

	if(dpc->props == NULL) continue;
	for(prc=0; prc < dpc->prop_cnt; prc++) {
	    struct db_prop *dp = &dpc->props[i];

	    if(dp->trans == NULL) continue;
	    for(tcc=0; tcc<dp->trans_cnt; tcc++) {
		tot_trans++;
	    }
	}
    }
    
    dtfset = malloc(sizeof(struct db_trans_flat)*tot_trans);
    
    tot_trans=0;
    for(pcc=0; pcc<f->prop_conj_cnt; pcc++) {
	struct db_prop_conj *dpc = &f->prop_conjs[i];
	
	if(dpc->props == NULL) continue;
	for(prc=0; prc < dpc->prop_cnt; prc++) {
	    struct db_prop *dp = &dpc->props[i];
	    
	    if(dp->trans == NULL) continue;
	    for(tcc=0; tcc<dp->trans_cnt; tcc++) {
		struct db_trans *tr=&dp->trans[i];
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
			    dtfone->hash_transid=attr->val;
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
	pr = malloc(sizeof(struct db_v2_prop));
	pr_cnt = 1;
    }
    dtflast = NULL;
    tr = NULL;
    pc = NULL; pc_cnt = 0;
    
    for(i=0; i < tot_trans; i++) {
	int tr_cnt = 4;

	dtfone = &dtfset[i];
	if(dtflast != NULL) {
	    /*
	     * see if previous protoid is identical to this
	     * one, and if so, then this is a disjunction (OR),
	     * otherwise, it's conjunction (AND)
	     */
	    if(dtflast->protoid != dtfone->protoid) {
		/* need to extend pr by one */
		pr_cnt++;
		pr = realloc(pr, sizeof(struct db_v2_prop)*pr_cnt);
		/* need to zero this, so it gets allocated */
		pc = NULL;
		pc_cnt=0;
	    } else {
		/* need to extend pc by one */
		pc_cnt++;
		pc = realloc(pc, sizeof(struct db_v2_prop_conj)*pc_cnt);
	    }
	}
	dtflast = dtfone;
	
	if(!pc) {
	    pc = malloc(sizeof(struct db_v2_prop_conj));
	    pr[pr_cnt].props = pc;
	    pr[pr_cnt].prop_cnt = pc_cnt;
	}
	if(dtfone->protoid != PROTO_ISAKMP) tr_cnt=5;
	    
	tr = malloc(sizeof(struct db_v2_trans)*tr_cnt);
	pc[pc_cnt].trans=tr;  pc[pc_cnt].trans_cnt = tr_cnt;
	
	pc->protoid = dtfset->protoid;
	
	tr[0].transform_type = IKEv2_TRANS_TYPE_ENCR;
	tr[0].transid        = dtfset->encr_transid;
	
	tr[1].transform_type = IKEv2_TRANS_TYPE_INTEG;
	tr[1].transid        = dtfset->hash_transid;
	
	tr[2].transform_type = IKEv2_TRANS_TYPE_PRF;
	tr[2].transid        = dtfset->prf_transid;
	
	tr[3].transform_type = IKEv2_TRANS_TYPE_DH;
	tr[3].transid        = dtfset->group_transid;

	if(dtfone->protoid != PROTO_ISAKMP) {
	    tr[4].transform_type = IKEv2_TRANS_TYPE_ESN;
	    tr[4].transid        = IKEv2_ESN_DISABLED;
	}
    }
    
    f->prop_disj = pr;
    f->prop_disj_cnt = pr_cnt;
    
    free(dtfset);
}

    
/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
