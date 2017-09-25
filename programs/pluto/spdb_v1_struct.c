/* Security Policy Data Base (such as it is)
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
#include "pluto/connections.h"          /* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "keys.h"
#include "secrets.h"
#include "kernel.h"          /* needs connections.h */
#include "log.h"
#include "pluto/spdb.h"
#include "whack.h"          /* for RC_LOG_SERIOUS */
#include "pluto/plutoalg.h"

#include "sha1.h"
#include "md5.h"
#include "pluto/crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "pluto/ike_alg.h"
#include "db_ops.h"
#include "pluto/db2_ops.h"
#include "ikev1.h"

#ifdef NAT_TRAVERSAL
#include "nat_traversal.h"
#endif

#ifdef HAVE_LABELED_IPSEC
#include "security_selinux.h"
#endif

/* enable this for deeper debugging into extrapolate loop */
#define EXTRAPOLATE_DEBUG 0
int v2tov1_encr(enum ikev2_trans_type_encr encr)
{
    switch(encr) {
    case IKEv2_ENCR_DES:
        return OAKLEY_DES_CBC;
    case  IKEv2_ENCR_IDEA:
        return OAKLEY_IDEA_CBC;
    case  IKEv2_ENCR_BLOWFISH:
        return OAKLEY_BLOWFISH_CBC;
    case  IKEv2_ENCR_RC5:
        return OAKLEY_RC5_R16_B64_CBC;
    case  IKEv2_ENCR_3DES:
        return OAKLEY_3DES_CBC;
    case  IKEv2_ENCR_CAST:
        return OAKLEY_CAST_CBC;
    case  IKEv2_ENCR_AES_CBC:
        return OAKLEY_AES_CBC;
    default:
	return 0;
    }
}

int v2tov1_encr_child(enum ikev2_trans_type_encr encr)
{
    switch(encr) {
    case IKEv2_ENCR_DES:
        return ESP_DES;
    case  IKEv2_ENCR_IDEA:
        return ESP_IDEA;
    case  IKEv2_ENCR_BLOWFISH:
        return ESP_BLOWFISH;
    case  IKEv2_ENCR_RC5:
        return ESP_RC5;
    case  IKEv2_ENCR_3DES:
        return ESP_3DES;
    case  IKEv2_ENCR_CAST:
        return ESP_CAST;
    case  IKEv2_ENCR_AES_CBC:
        return ESP_AES;
    default:
	return 0;
    }
}

int v2tov1_integ(enum ikev2_trans_type_integ v2integ)
{
    switch(v2integ) {
    case IKEv2_AUTH_HMAC_MD5_96:
        return OAKLEY_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
        return OAKLEY_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
        return OAKLEY_SHA2_256;
     case IKEv2_AUTH_HMAC_SHA2_384_192:
         return OAKLEY_SHA2_384;
     case IKEv2_AUTH_HMAC_SHA2_512_256:
         return OAKLEY_SHA2_512;
     default:
         return -1;
     }
}

int v2tov1_integ_child(enum ikev2_trans_type_integ v2integ)
{
    switch(v2integ) {
    case IKEv2_AUTH_HMAC_MD5_96:
        return AUTH_ALGORITHM_HMAC_MD5;
    case IKEv2_AUTH_HMAC_SHA1_96:
        return AUTH_ALGORITHM_HMAC_SHA1;
    case IKEv2_AUTH_HMAC_SHA2_256_128:
        return AUTH_ALGORITHM_HMAC_SHA2_256;
    case IKEv2_AUTH_HMAC_SHA2_384_192:
        return AUTH_ALGORITHM_HMAC_SHA2_384;
    case IKEv2_AUTH_HMAC_SHA2_512_256:
        return AUTH_ALGORITHM_HMAC_SHA2_512;
    default:
        return IKEv2_AUTH_INVALID;
   }
}

/** output an attribute (within an SA) */
bool
out_attr(int type
           , unsigned long val
           , struct_desc *attr_desc
           , enum_names **attr_val_descs USED_BY_DEBUG
           , pb_stream *pbs)
{
    struct isakmp_attribute attr;

    if (val >> 16 == 0)
    {
          /* short value: use TV form */
          attr.isaat_af_type = type | ISAKMP_ATTR_AF_TV;
          attr.isaat_lv = val;
          if (!out_struct(&attr, attr_desc, pbs, NULL))
              return FALSE;
    }
    else
    {
          /* This is a real fudge!  Since we rarely use long attributes
           * and since this is the only place where we can cause an
           * ISAKMP message length to be other than a multiple of 4 octets,
           * we force the length of the value to be a multiple of 4 octets.
           * Furthermore, we only handle values up to 4 octets in length.
           * Voila: a fixed format!
           */
          pb_stream val_pbs;
          u_int32_t nval = htonl(val);

          attr.isaat_af_type = type | ISAKMP_ATTR_AF_TLV;
          if (!out_struct(&attr, attr_desc, pbs, &val_pbs)
          || !out_raw(&nval, sizeof(nval), &val_pbs, "long attribute value"))
              return FALSE;
          close_output_pbs(&val_pbs);
    }
    DBG(DBG_EMITTING,
          enum_names *d = attr_val_descs[type];

          if (d != NULL)
              DBG_log("    [%lu is %s]"
                    , val, enum_show(d, val)));
    return TRUE;
}

#define return_on(var, val) do { var=val;goto return_out; } while(0);

struct db_sa *
ikev1_alg_makedb(lset_t policy, struct alg_info_ike *ei, bool oneproposal UNUSED
                 , enum phase1_role role)
{
    struct db_sa *sadb;

    sadb = alginfo2parent_db2(ei);
    sadb->parentSA = TRUE;

    if(!extrapolate_v1_from_v2(sadb, policy, role)) {
        openswan_log("failed to create v1 PARENTSA policy from v2 settings");
        return NULL;
    }

    DBG(DBG_EMITTING,
        DBG_log("Translated IKEv2 policy to: ");
        sa_print(sadb));

    return sadb;

}

struct db_sa *
kernel_alg_makedb(lset_t policy UNUSED, struct alg_info_esp *ei, enum phase1_role role)
{
	struct db_sa *sadb;

    sadb = alginfo2child_db2(ei);
	sadb->parentSA = FALSE;

    if(!extrapolate_v1_from_v2(sadb, policy, role)) {
        openswan_log("failed to create v1 IPsec policy from v2 settings");
	return NULL;
    }

    DBG(DBG_EMITTING,
        DBG_log("Translated IKEv2 policy to: ");
        sa_print(sadb));

    return sadb;
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

/* static, if not for unit testing */
bool extrapolate_v1_from_v2(struct db_sa *sadb, lset_t policy, enum phase1_role role)
{
    unsigned int prop_disj;
    int tot_combos, cur_combo;
    //int propnum = 0;
    int i;
    int transform_values[IKEv2_TRANS_TYPE_COUNT];
    struct db_trans_flat *dtf;
    struct db_trans_flat *cur_dtf;

    /* if already did it, then just return */
    if(sadb->prop_conjs != NULL) return TRUE;

    /* the v2 info might be empty */
    if(sadb->prop_disj_cnt < 1) return TRUE;

    if(!sadb->prop_v1_ctx) {
        sadb->prop_v1_ctx = db_prop_new(sadb->prop_disj->props[0].protoid,
                      sadb->prop_disj->props[0].trans_cnt,
                      10 /* attributes */);

    }

    /* first count number of combinations expressed in IKEv2, so we can
     * allocate a table big for all the combinations */
    tot_combos = 0;
    prop_disj  = 0;
#if EXTRAPOLATE_DEBUG
    /* enable this when debugging problems with tot_combos */
    DBG_log("%u disj_cnt: %d/%d", tot_combos, prop_disj, sadb->prop_disj_cnt);
#endif
    for(prop_disj=0; prop_disj<sadb->prop_disj_cnt; prop_disj++) {
        unsigned int prop_conj;
        struct db_v2_prop *pd = &sadb->prop_disj[prop_disj];
#if EXTRAPOLATE_DEBUG
        /* enable this when debugging problems with tot_combos */
        DBG_log("%u disj_cnt: %d/%d conj: 0/%d", tot_combos, prop_disj, sadb->prop_disj_cnt, pd->prop_cnt);
#endif

        /* reset the transform values */
        for(i=0; i<IKEv2_TRANS_TYPE_COUNT; i++) {
            transform_values[i] = -1;
        }

        for(prop_conj = 0; prop_conj < pd->prop_cnt; prop_conj++) {
            unsigned int trans_i;
            struct db_v2_prop_conj *pc = &pd->props[prop_conj];
#if EXTRAPOLATE_DEBUG
            /* enable this when debugging problems with tot_combos */
            DBG_log("%u disj_cnt: %d/%d conj: %d/%d trans: 0/%d"
                    , tot_combos, prop_disj, sadb->prop_disj_cnt
                    , prop_conj, pd->prop_cnt
                    , pc->trans_cnt);
#endif
            for(trans_i=0; trans_i < pc->trans_cnt; trans_i++) {
                //unsigned int attr_i;
                struct db_v2_trans *tr = &pc->trans[trans_i];
#if EXTRAPOLATE_DEBUG
                /* enable this when debugging problems with tot_combos */
                DBG_log("%u disj_cnt: %d/%d conj: %d/%d trans: %d/%d type: %d"
                        , tot_combos, prop_disj, sadb->prop_disj_cnt
                        , prop_conj, pd->prop_cnt
                        , trans_i, pc->trans_cnt, tr->transform_type);
#endif

                if(tr->transform_type >= IKEv2_TRANS_TYPE_COUNT) continue;
                /* IKEv1 does not negotiate PRF, so ignore options like that */
                if(tr->transform_type == IKEv2_TRANS_TYPE_PRF) continue;

#if EXTRAPOLATE_DEBUG
                /* enable this when debugging problems with tot_combos */
                DBG_log("%u A: %u,%u,%u, noticing type[%u]=>%d (vs: %d)"
                        , tot_combos
                        , prop_disj, prop_conj, trans_i
                        , tr->transform_type, tr->value
                        , transform_values[tr->transform_type]);
#endif

                if(transform_values[tr->transform_type]==-1) {
                    transform_values[tr->transform_type] = tr->value;
                }
                if(transform_values[tr->transform_type] != tr->value) {
                    transform_values[tr->transform_type] = tr->value;

                    /*
                     * this may duplicate entries if they are not in order,
                     * but that's okay, because the duplicate check below
                     * will get rid of them.
                     */
                    tot_combos++;
                    DBG(DBG_EMITTING
                        ,DBG_log("counted combo %d: dh:%d encr:%d integ:%d"
                                 , tot_combos
                                 , transform_values[IKEv2_TRANS_TYPE_DH]
                                 , transform_values[IKEv2_TRANS_TYPE_ENCR]
                                 , transform_values[IKEv2_TRANS_TYPE_INTEG]));
                }
            }
        }
    }

    /* there is probably an additional combination at the end */
    if((transform_values[IKEv2_TRANS_TYPE_DH] != -1 || sadb->parentSA == FALSE)
       && transform_values[IKEv2_TRANS_TYPE_ENCR] != -1
       && transform_values[IKEv2_TRANS_TYPE_INTEG] != -1) {
        tot_combos++;
    }
    /* make a list of them all */
    dtf = alloca(sizeof(struct db_trans_flat)*tot_combos);
    memset(dtf, 0, sizeof(struct db_trans_flat)*tot_combos);
    cur_dtf = dtf;

    cur_combo=0;

    if(tot_combos == 0) {
        openswan_log("can not extrapolate IKEv1 policy from empty IKEv2 policy");
        return FALSE;
    }

    /* make sure we saw combinations for all the things we care about */
    if(transform_values[IKEv2_TRANS_TYPE_ENCR] == -1
       || transform_values[IKEv2_TRANS_TYPE_INTEG] == -1) {
        openswan_log("can not extrapolate IKEv1 policy from v2 policy missing encryption or integrity settings");
        return FALSE;
    }

    if(sadb->parentSA == TRUE) {
        if(transform_values[IKEv2_TRANS_TYPE_DH] == -1) {
            openswan_log("can not extrapolate IKEv1 parent policy from v2 policy missing group settings");
            return FALSE;
        }
    }
    for(prop_disj=0; prop_disj < sadb->prop_disj_cnt; prop_disj++) {
        unsigned int prop_conj;
        struct db_v2_prop *pd = &sadb->prop_disj[prop_disj];
        /* reset the transform values */
        for(i=0; i<IKEv2_TRANS_TYPE_COUNT; i++) {
            transform_values[i] = -1;
        }

        for(prop_conj = 0; prop_conj < pd->prop_cnt; prop_conj++) {
            unsigned int trans_i;
            struct db_v2_prop_conj *pc = &pd->props[prop_conj];
            for(trans_i=0; trans_i < pc->trans_cnt; trans_i++) {
                //int attr_i;
                struct db_v2_trans *tr = &pc->trans[trans_i];

                if(tr->transform_type >= IKEv2_TRANS_TYPE_COUNT) continue;

                /* IKEv1 does not negotiate PRF, so ignore options like that */
                if(tr->transform_type == IKEv2_TRANS_TYPE_PRF) continue;

#if 0
                DBG_log("B: %u,%u,%u, cc: %u setting type: tt[%u]=%d vs %d",
                        prop_disj, prop_conj, trans_i, cur_combo,
                        tr->transform_type,
                        transform_values[tr->transform_type],
                        tr->value);
#endif
                if(transform_values[tr->transform_type]==-1) {
                    transform_values[tr->transform_type] = tr->value;
                }

                switch(tr->transform_type) {
                case IKEv2_TRANS_TYPE_DH:
                    cur_dtf->group_transid = tr->value;
                    break;

                case IKEv2_TRANS_TYPE_ENCR:
                    cur_dtf->encr_transid = tr->value;
                    break;

                case IKEv2_TRANS_TYPE_INTEG:
                    cur_dtf->integ_transid = tr->value;
                    break;

                default:
                    /* if the trans_type is of another type, then just continue,
                     * because there is no value in the combinations IKEv1 can
                     * not express
                     */
                    continue;
                }

                if(transform_values[tr->transform_type] != tr->value) {
                    int combo_i;
                    struct db_trans_flat *old_dtf = cur_dtf;
                    transform_values[tr->transform_type] = tr->value;

                    /* do a duplicate check, which is a linear search */
                    for(combo_i = 0; combo_i < cur_combo; combo_i++) {
#if 0
                        DBG_log("%d: checking combo dh:%d:%d encr:%d:%d integ:%d:%d"
                            , combo_i
                            , cur_dtf->group_transid
                            , dtf[combo_i].group_transid
                            , cur_dtf->encr_transid
                            , dtf[combo_i].encr_transid
                            , cur_dtf->integ_transid
                            , dtf[combo_i].integ_transid);
#endif
                        if(cur_dtf->group_transid  == dtf[combo_i].group_transid
                           && cur_dtf->encr_transid == dtf[combo_i].encr_transid
                           && cur_dtf->integ_transid == dtf[combo_i].integ_transid) {
                            /* it is duplicate */
#if 0
                            DBG_log("    combo duplicate of %u", combo_i);
#endif
                            break;
                }
                    }
                    if(combo_i < cur_combo) continue;

                    /*
                     * some of the encr or integ values might not exist in IKEv1,
                     * so skip them.
                     */
                    if(v2tov1_encr(cur_dtf->encr_transid) == 0
                       || v2tov1_integ(cur_dtf->integ_transid) == 0) {
                        continue;
                    }

                    DBG(DBG_EMITTING
                        ,DBG_log("new combo %d: dh:%d encr:%d integ:%d"
                                 , cur_combo
                                 , cur_dtf->group_transid
                                 , cur_dtf->encr_transid
                                 , cur_dtf->integ_transid));
                    cur_dtf++;
                    *cur_dtf = *old_dtf;
                    ++cur_combo;
                    passert(cur_combo <= tot_combos);
                }
            }
        }
    }

    /*
     * check the last entry, in cur_dtf, and if it is different than dtf[cur_combo]
     * (assuming cur_combo>0), add it to the list.
     * if cur_combo == 0, then it's the only entry!
     */
    if(cur_combo == 0
       || (cur_dtf->group_transid != dtf[cur_combo].group_transid
           || cur_dtf->encr_transid != dtf[cur_combo].encr_transid
           || cur_dtf->integ_transid != dtf[cur_combo].integ_transid)) {
        cur_combo++;
    }

    cur_dtf = dtf;
    for(i=0; i<cur_combo; i++, cur_dtf++) {
        if(sadb->parentSA) {
            lset_t policies[][2] = {
                { POLICY_PSK,              OAKLEY_PRESHARED_KEY},
                { POLICY_RSASIG,           OAKLEY_RSA_SIG      },
                { POLICY_XAUTH|POLICY_PSK,    XAUTHInitPreShared},
                { POLICY_XAUTH|POLICY_RSASIG, XAUTHInitRSA     },
            };

            unsigned int pol_j;
            for(pol_j = 0; pol_j < elemsof(policies); pol_j++) {
                lset_t possible = policies[pol_j][0];
                if((policy & possible) == possible) {  /* must match exactly */

                    unsigned int oakley_auth_alg = policies[pol_j][1];

                    if(role == RESPONDER) {
                        oakley_auth_alg++;   /* because they are sequential */
                    }

                    db_trans_add(sadb->prop_v1_ctx, KEY_IKE);
                    db_attr_add_values(sadb->prop_v1_ctx, OAKLEY_AUTHENTICATION_METHOD,
                                       oakley_auth_alg);
                    db_attr_add_values(sadb->prop_v1_ctx, OAKLEY_ENCRYPTION_ALGORITHM,
                           v2tov1_encr(cur_dtf->encr_transid));
                    db_attr_add_values(sadb->prop_v1_ctx, OAKLEY_HASH_ALGORITHM,
                           v2tov1_integ(cur_dtf->integ_transid));
                    db_attr_add_values(sadb->prop_v1_ctx, OAKLEY_GROUP_DESCRIPTION,
                                       cur_dtf->group_transid);
                }
            }
        } else {
            /* child SA policy */
            db_trans_add(sadb->prop_v1_ctx, v2tov1_encr_child(cur_dtf->encr_transid));
            db_attr_add_ipsec_values(sadb->prop_v1_ctx, AUTH_ALGORITHM,
                               v2tov1_integ(cur_dtf->integ_transid));
            if(cur_dtf->group_transid) {
                db_attr_add_ipsec_values(sadb->prop_v1_ctx, GROUP_DESCRIPTION,
                                         cur_dtf->group_transid);
            }
            /* XXX could add ESN here too !*/
        }
    }

    sadb->prop_conjs = alloc_thing(struct db_prop_conj, "v1 policy proposal conj");
    sadb->prop_conj_cnt = 1;
    if(!sadb->prop_conjs) { return FALSE; }

    sadb->prop_conjs->props    = &sadb->prop_v1_ctx->prop;
    sadb->prop_conjs->prop_cnt =  1;

    return TRUE;
}


/**
 * Output an SA, as described by a db_sa.
 * This has the side-effect of allocating SPIs for us.
 *
 */
bool
out_sa(pb_stream *outs
       , struct db_sa *sadb
       , struct state *st
       , bool phase_one_mode
       , enum phase1_role role
       , bool aggressive_mode UNUSED
       , u_int8_t np)
{
    pb_stream sa_pbs;
    unsigned int pcn;
    bool ret = FALSE;
    bool ah_spi_generated = FALSE
          , esp_spi_generated = FALSE
          , ipcomp_cpi_generated = FALSE;

    if(!extrapolate_v1_from_v2(sadb, st->st_policy, role)) {
        openswan_log("can not derive IKEv1 policy from IKEv2 settings, failed");
        return_on(ret, FALSE);
    }

    if(!phase_one_mode && ((st->st_policy) & POLICY_COMPRESS)) {
        /* add IPcomp proposal if policy asks for it */
        struct db_trans *ipcomp_trans = alloc_thing(struct db_trans, "ipcomp_trans");

        /* allocate space for 2 proposals */
        struct db_prop *ipcomp_prop = alloc_bytes( (sizeof (struct db_prop) * 2), "ipcomp_prop");

        if (ipcomp_trans && ipcomp_prop) {
            passert(sadb->prop_conjs->prop_cnt == 1);

            /* construct the IPcomp proposal  */
            ipcomp_trans->transid = IPCOMP_DEFLATE;
            ipcomp_trans->attrs = NULL;
            ipcomp_trans->attr_cnt = 0;

            /* copy the original proposal */
            ipcomp_prop[0].protoid   = sadb->prop_conjs->props->protoid;
            ipcomp_prop[0].trans     = sadb->prop_conjs->props->trans;
            ipcomp_prop[0].trans_cnt = sadb->prop_conjs->props->trans_cnt;

            /* and add our IPcomp proposal */
            ipcomp_prop[1].protoid = PROTO_IPCOMP;
            ipcomp_prop[1].trans = ipcomp_trans;
            ipcomp_prop[1].trans_cnt = 1;

            /* free the old proposal, and ... */
            pfree (sadb->prop_conjs->props);

            /* ... use our new one instead */
            sadb->prop_conjs->props = ipcomp_prop;
            sadb->prop_conjs->prop_cnt += 1;
        }
        else {
            /* couldn't alloc something, so skip adding the proposal */
            if (ipcomp_trans)
                pfreeany (ipcomp_trans);
            if (ipcomp_prop)
                pfreeany (ipcomp_prop);
        }
    }

    /* SA header out */
    {
        struct isakmp_sa sa;

        sa.isasa_np = np;
        st->st_doi = sa.isasa_doi = ISAKMP_DOI_IPSEC;          /* all we know */
        if (!out_struct(&sa, &isakmp_sa_desc, outs, &sa_pbs))
            return_on(ret, FALSE);
    }

    /* within SA: situation out */
    st->st_situation = SIT_IDENTITY_ONLY;
    if (!out_struct(&st->st_situation, &ipsec_sit_desc, &sa_pbs, NULL))
        return_on(ret, FALSE);

    /* within SA: Proposal Payloads
     *
     * Multiple Proposals with the same number are simultaneous
     * (conjuncts) and must deal with different protocols (AH or ESP).
     * Proposals with different numbers are alternatives (disjuncts),
     * in preference order.
     * Proposal numbers must be monotonic.
     * See RFC 2408 "ISAKMP" 4.2
     */

    for (pcn = 0; pcn < sadb->prop_conj_cnt; pcn++)
    {
          struct db_prop_conj *pc;
          unsigned int pn;
          int valid_prop_cnt;

          pc = &sadb->prop_conjs[pcn];
          valid_prop_cnt = pc->prop_cnt;
          DBG(DBG_EMITTING,
              DBG_log("out_sa pcn: %d has %d valid proposals",
                        pcn, valid_prop_cnt));

          for (pn = 0; pn < pc->prop_cnt; pn++)
          {
              struct db_prop *p;
              pb_stream proposal_pbs;
              struct isakmp_proposal proposal;
              struct_desc *trans_desc;
              struct_desc *attr_desc;
              enum_names **attr_val_descs;
              unsigned int tn;
              bool tunnel_mode;

              /*
               * set the tunnel_mode bit on the last proposal only, and
               * only if we are trying to negotiate tunnel mode in the first
               * place.
               */
              tunnel_mode = (valid_prop_cnt == 1)
                    && (st->st_policy & POLICY_TUNNEL);

              /*
               * pick the part of the proposal we are trying to work on
               */
              p = &pc->props[pn];

              proposal.isap_proposal = pcn;
              proposal.isap_protoid = p->protoid;
              proposal.isap_spisize = phase_one_mode ? 0
                    : p->protoid == PROTO_IPCOMP ? IPCOMP_CPI_SIZE
                    : IPSEC_DOI_SPI_SIZE;

              DBG(DBG_EMITTING,
                    DBG_log("out_sa pcn: %d pn: %d<%d valid_count: %d trans_cnt: %d",
                              pcn, pn, pc->prop_cnt, valid_prop_cnt, p->trans_cnt));

              /* but, skip things if the transform count is zero */
              if(p->trans_cnt == 0) continue;

              /* Proposal header */
              if(--valid_prop_cnt > 0) {
                    proposal.isap_np = ISAKMP_NEXT_P;
              } else {
                    proposal.isap_np = ISAKMP_NEXT_NONE;
              }

              proposal.isap_notrans = p->trans_cnt;
              if (!out_struct(&proposal, &isakmp_proposal_desc
                                  , &sa_pbs, &proposal_pbs))
                    return_on(ret, FALSE);

              /* Per-protocols stuff:
               * Set trans_desc.
               * Set attr_desc.
               * Set attr_val_descs.
               * If not phase_one_mode, emit SPI.
               * We allocate SPIs on demand.
               * All ESPs in an SA will share a single SPI.
               * All AHs in an SAwill share a single SPI.
               * AHs' SPI will be distinct from ESPs'.
               * This latter is needed because KLIPS doesn't
               * use the protocol when looking up a (dest, protocol, spi).
               * ??? If multiple ESPs are composed, how should their SPIs
               * be allocated?
               */
              {
		  struct ipsec_proto_info *pi = NULL;
		  int proto = 0;
		  bool *spi_generated;

                    spi_generated = NULL;

                    switch (p->protoid)
                    {
                    case PROTO_ISAKMP:
                        passert(phase_one_mode);
                        trans_desc = &isakmp_isakmp_transform_desc;
                        attr_desc = &isakmp_oakley_attribute_desc;
                        attr_val_descs = oakley_attr_val_descs;
                        /* no SPI needed */
                        break;

                    case PROTO_IPSEC_AH:
                        passert(!phase_one_mode);
                        trans_desc = &isakmp_ah_transform_desc;
                        attr_desc = &isakmp_ipsec_attribute_desc;
                        attr_val_descs = ipsec_attr_val_descs;
			pi = &st->st_ah;
                        spi_generated = &ah_spi_generated;
                        proto = IPPROTO_AH;
                        break;

                    case PROTO_IPSEC_ESP:
                        passert(!phase_one_mode);
                        trans_desc = &isakmp_esp_transform_desc;
                        attr_desc = &isakmp_ipsec_attribute_desc;
                        attr_val_descs = ipsec_attr_val_descs;
			pi = &st->st_esp;
                        spi_generated = &esp_spi_generated;
                        proto = IPPROTO_ESP;
                        break;

                    case PROTO_IPCOMP:
                        passert(!phase_one_mode);
                        trans_desc = &isakmp_ipcomp_transform_desc;
                        attr_desc = &isakmp_ipsec_attribute_desc;
                        attr_val_descs = ipsec_attr_val_descs;

                        /* a CPI isn't quite the same as an SPI
                         * so we use specialized code to emit it.
                         */
                        if (!ipcomp_cpi_generated)
                        {
                              st->st_ipcomp.our_spi = get_my_cpi(st, tunnel_mode);
                              if (st->st_ipcomp.our_spi == 0)
                                  return_on(ret, FALSE);          /* problem generating CPI */

                              ipcomp_cpi_generated = TRUE;
                        }
                        /* CPI is stored in network low order end of an
                         * ipsec_spi_t.  So we start a couple of bytes in.
                         */
                        if (!out_raw((u_char *)&st->st_ipcomp.our_spi
                         + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
                        , IPCOMP_CPI_SIZE
                        , &proposal_pbs, "CPI"))
                              return_on(ret, FALSE);
                        break;

                    default:
                        bad_case(p->protoid);
                    }

                    if (pi != NULL)
                    {
                        if (spi_generated != NULL && !*spi_generated)
                        {
			    if (!get_ipsec_spi(pi
					       , proto
					       , st
					       , tunnel_mode)) {
				return FALSE;
			    }
			    *spi_generated = TRUE;
                        }
                        if (!out_raw((u_char *)&pi->our_spi, IPSEC_DOI_SPI_SIZE
				     , &proposal_pbs, "SPI"))
			    return_on(ret, FALSE);
                    }
              }

              /* within proposal: Transform Payloads */
              for (tn = 0; tn != p->trans_cnt; tn++)
              {
                    struct db_trans *t = &p->trans[tn];
                    pb_stream trans_pbs;
                    struct isakmp_transform trans;
                    unsigned int an;
                    lset_t transmitted = LEMPTY;

                    trans.isat_np = (tn == p->trans_cnt - 1)
                        ? ISAKMP_NEXT_NONE : ISAKMP_NEXT_T;
                    trans.isat_transnum = tn;
                    trans.isat_transid = t->transid;
                    if (!out_struct(&trans, trans_desc, &proposal_pbs, &trans_pbs))
                        return_on(ret, FALSE);

                    /* Within tranform: Attributes. */

                    /* For Phase 2 / Quick Mode, GROUP_DESCRIPTION is
                     * automatically generated because it must be the same
                     * in every transform.  Except IPCOMP.
                     */
                    if (p->protoid != PROTO_IPCOMP
                    && st->st_pfs_group != NULL)
                    {
                        passert(!phase_one_mode);
                        passert(st->st_pfs_group != &unset_group);
                        out_attr(GROUP_DESCRIPTION, st->st_pfs_group->group
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                    }

                    /* automatically generate duration
                     * and, for Phase 2 / Quick Mode, encapsulation.
                     */
                    if (phase_one_mode)
                    {
                        out_attr(OAKLEY_LIFE_TYPE, OAKLEY_LIFE_SECONDS
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                        out_attr(OAKLEY_LIFE_DURATION
                              , st->st_connection->sa_ike_life_seconds
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                    }
                    else
                    {
                        /* RFC 2407 (IPSEC DOI) 4.5 specifies that
                         * the default is "unspecified (host-dependent)".
                         * This makes little sense, so we always specify it.
                         *
                         * Unlike other IPSEC transforms, IPCOMP defaults
                         * to Transport Mode, so we can exploit the default
                         * (draft-shacham-ippcp-rfc2393bis-05.txt 4.1).
                         */
                        if (p->protoid != PROTO_IPCOMP
                        || st->st_policy & POLICY_TUNNEL)
                        {
                              if ((st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
                                        (!(st->st_policy & POLICY_TUNNEL))) {
                                        /* Inform user that we will not respect policy and only
                                         * propose Tunnel Mode
                                         */
                                        loglog(RC_LOG_SERIOUS, "NAT-Traversal: "
                                                  "Transport Mode not allowed due to security concerns -- "
                                                  "using Tunnel mode.  Rebuild Openswan with USE_NAT_TRAVERSAL_TRANSPORT_MODE=true in Makefile.inc to support transport mode.");
                              }

                              transmitted |= LELEM(ENCAPSULATION_MODE);
                              out_attr(ENCAPSULATION_MODE
                                  , NAT_T_ENCAPSULATION_MODE(st,st->st_policy)
                                  , attr_desc, attr_val_descs
                                  , &trans_pbs);
                        }
                        transmitted |= LELEM(SA_LIFE_TYPE);
                        out_attr(SA_LIFE_TYPE, SA_LIFE_TYPE_SECONDS
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
                        transmitted |= LELEM(SA_LIFE_DURATION);
                        out_attr(SA_LIFE_DURATION
                              , st->st_connection->sa_ipsec_life_seconds
                              , attr_desc, attr_val_descs
                              , &trans_pbs);
#ifdef HAVE_LABELED_IPSEC
                        if(st->sec_ctx != NULL && st->st_connection->labeled_ipsec) {
                              struct isakmp_attribute attr;
                              pb_stream val_pbs;
                              attr.isaat_af_type = secctx_attr_value | ISAKMP_ATTR_AF_TLV;
                              DBG(DBG_EMITTING, DBG_log("secctx_attr_value=%d, type=%d", secctx_attr_value, attr.isaat_af_type));
                              out_struct(&attr, attr_desc, &trans_pbs, &val_pbs);
                              DBG(DBG_EMITTING, DBG_log("placing security context attribute in the out going structure"));
                              DBG(DBG_EMITTING, DBG_log("sending ctx_doi"));
                              out_raw(&st->sec_ctx->ctx_doi, sizeof(st->sec_ctx->ctx_doi),  &val_pbs, " variable length sec ctx: ctx_doi");
                              DBG(DBG_EMITTING, DBG_log("sending ctx_alg"));
                              out_raw(&st->sec_ctx->ctx_alg, sizeof(st->sec_ctx->ctx_alg),  &val_pbs, " variable length sec ctx: ctx_alg");
                              DBG(DBG_EMITTING, DBG_log("sending ctx_len after conversion to network byte order"));
                              u_int16_t net_ctx_len = htons(st->sec_ctx->ctx_len);
                              out_raw(&net_ctx_len, sizeof(st->sec_ctx->ctx_len),  &val_pbs, " variable length sec ctx: ctx_len");
                              /*Sending '\0'  with sec ctx as we get it from kernel*/
                              out_raw(st->sec_ctx->sec_ctx_value, st->sec_ctx->ctx_len, &val_pbs, " variable length sec ctx");
                              DBG(DBG_EMITTING, DBG_log("placed security context attribute in the out going structure"));
                            close_output_pbs(&val_pbs);
                              DBG(DBG_EMITTING, DBG_log("end of security context attribute in the out going structure"));
                        }
#endif

                    }

                    /* spit out attributes from table */
                    for (an = 0; an < t->attr_cnt; an++)
                    {
                        struct db_attr *a = &t->attrs[an];
                        const enum_names *thing;
                        int type;

                        if(phase_one_mode) {
                            type = a->type.oakley;
                            thing= &oakley_attr_names;
                        } else {
                            type = a->type.ipsec;
                            thing= &ipsec_attr_names;
                        }

                        if(0) {
                            DBG(DBG_EMITTING
                                , DBG_log("emitting transform for %s with value %u"
                                          , enum_name(thing, type)
                                          , a->val));
                        }

                        if(transmitted & LELEM(type)) continue;
                        transmitted |= LELEM(type);
                        out_attr(type, a->val
                                 , attr_desc, attr_val_descs
                                 , &trans_pbs);
                    }

                    close_output_pbs(&trans_pbs);
              }
              close_output_pbs(&proposal_pbs);
          }
          /* end of a conjunction of proposals */
    }
    close_output_pbs(&sa_pbs);
    ret = TRUE;

return_out:

    if (sadb)
          free_sa(sadb);
    return ret;
}

/** Handle long form of duration attribute.
 * The code is can only handle values that can fit in unsigned long.
 * "Clamping" is probably an acceptable way to impose this limitation.
 *
 * @param pbs PB Stream
 * @return u_int32_t duration, in seconds.
 */
static u_int32_t
decode_long_duration(pb_stream *pbs)
{
    u_int32_t val = 0;

    /* ignore leading zeros */
    while (pbs_left(pbs) != 0 && *pbs->cur == '\0')
          pbs->cur++;

    if (pbs_left(pbs) > sizeof(val))
    {
          /* "clamp" too large value to max representable value */
          val -= 1;          /* portable way to get to maximum value */
          DBG(DBG_PARSING, DBG_log("   too large duration clamped to: %lu"
              , (unsigned long)val));
    }
    else
    {
          /* decode number */
          while (pbs_left(pbs) != 0)
              val = (val << BITS_PER_BYTE) | *pbs->cur++;
          DBG(DBG_PARSING, DBG_log("   long duration: %lu", (unsigned long)val));
    }
    return val;
}

/* Preparse the body of an ISAKMP SA Payload and find which policy is required
 * to match the packet. Errors are just ignored and will be detected and
 * handled later in parse_isakmp_sa_body().
 *
 * All we want for the moment is to know whether peer is using RSA or PSK.
 */
lset_t preparse_isakmp_sa_body(pb_stream *sa_pbs)
{
    pb_stream proposal_pbs;
    struct isakmp_proposal proposal;
    pb_stream trans_pbs;
    struct isakmp_transform trans;
    struct isakmp_attribute a;
    pb_stream attr_pbs;
    u_int32_t ipsecdoisit;
    unsigned trans_left;
    lset_t policy = 0;

    if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
          return LEMPTY;

    if (!in_struct(&proposal, &isakmp_proposal_desc, sa_pbs, &proposal_pbs))
          return LEMPTY;

    if (proposal.isap_spisize > MAX_ISAKMP_SPI_SIZE)
          return LEMPTY;

    if (proposal.isap_spisize > 0)
    {
          u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

          if (!in_raw(junk_spi, proposal.isap_spisize, &proposal_pbs, "Oakley SPI"))
    return LEMPTY;
    }

    trans_left = proposal.isap_notrans;
    while (trans_left--) {
          if (!in_struct(&trans, &isakmp_isakmp_transform_desc, &proposal_pbs,
              &trans_pbs))
              return LEMPTY;

          while (pbs_left(&trans_pbs) != 0) {
              if (!in_struct(&a, &isakmp_oakley_attribute_desc, &trans_pbs,
                    &attr_pbs))
                    return LEMPTY;
              switch (a.isaat_af_type) {
                    case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
                        switch (a.isaat_lv) {
                              case XAUTHInitPreShared:
                              case OAKLEY_PRESHARED_KEY:
                                        policy |= POLICY_PSK;
                                  break;
                              case XAUTHInitRSA:
                              case OAKLEY_RSA_SIG:
                                        policy |= POLICY_RSASIG;
                                  break;
                        }
                        break;
              }
          }
    }

    if ((policy & POLICY_PSK) && (policy & POLICY_RSASIG))
          policy &= ~(POLICY_PSK|POLICY_RSASIG);

    return policy;
}


/**
 * Parse the body of an ISAKMP SA Payload (i.e. Phase 1 / Main Mode).
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single tranform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * It also means that we are inR1, and this as implications when we are
 * doing XAUTH, as it changes the meaning of the XAUTHInit/XAUTHResp.
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * This routine is used by main_inI1_outR1() and main_inR1_outI2().
 */
notification_t
parse_isakmp_sa_body(
    pb_stream *sa_pbs,          /* body of input SA Payload */
    const struct isakmp_sa *sa,          /* header of input SA Payload */
    pb_stream *r_sa_pbs,          /* if non-NULL, where to emit winning SA */
    bool selection,          /* if this SA is a selection, only one tranform
                               * can appear. */
    struct state *st)          /* current state object */
{
    u_int32_t ipsecdoisit;
    pb_stream proposal_pbs;
    struct isakmp_proposal proposal;
    unsigned no_trans_left;
    int last_transnum;
    struct connection *c = st->st_connection;
    struct spd_route *spd, *me = &c->spd;
    bool xauth_init, xauth_resp;
    const char *role;

    role = "";

    xauth_init = xauth_resp = FALSE;

    /* calculate the per-end policy which might apply */
    for(spd = me; spd; spd = spd->next) {
          if(selection)
          { /* this is the initiator, we have proposed, they have answered,
             * and we must decide if they proposed what we wanted.
             */
              role = "initiator";
              xauth_init = xauth_init | spd->this.xauth_client;
              xauth_resp = xauth_resp | spd->this.xauth_server;
          }
          else
          { /* this is the responder, they have proposed to us, what
             * are we willing to be?
             */
              role = "responder";
              xauth_init = xauth_init | spd->this.xauth_server;
              xauth_resp = xauth_resp | spd->this.xauth_client;
          }
    }

    /* DOI */
    if (sa->isasa_doi != ISAKMP_DOI_IPSEC)
    {
          loglog(RC_LOG_SERIOUS, "Unknown/unsupported DOI %s", enum_show(&doi_names, sa->isasa_doi));
          /* XXX Could send notification back */
          return DOI_NOT_SUPPORTED;
    }

    /* Situation */
    if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
    {
          return SITUATION_NOT_SUPPORTED;
    }

    if (ipsecdoisit != SIT_IDENTITY_ONLY)
    {
          loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)"
              , bitnamesof(sit_bit_names, ipsecdoisit));
          /* XXX Could send notification back */
          return SITUATION_NOT_SUPPORTED;
    }

    /* The rules for ISAKMP SAs are scattered.
     * RFC 2409 "IKE" section 5 says that there
     * can only be one SA, and it can have only one proposal in it.
     * There may well be multiple transforms.
     */
    if (!in_struct(&proposal, &isakmp_proposal_desc, sa_pbs, &proposal_pbs))
          return PAYLOAD_MALFORMED;

    if (proposal.isap_np != ISAKMP_NEXT_NONE)
    {
          loglog(RC_LOG_SERIOUS, "Proposal Payload must be alone in Oakley SA; found %s following Proposal"
              , enum_show(&payload_names, proposal.isap_np));
          return PAYLOAD_MALFORMED;
    }

    if (proposal.isap_protoid != PROTO_ISAKMP)
    {
          loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) found in Oakley Proposal"
              , enum_show(&protocol_names, proposal.isap_protoid));
          return INVALID_PROTOCOL_ID;
    }

    /* Just what should we accept for the SPI field?
     * The RFC is sort of contradictory.  We will ignore the SPI
     * as long as it is of the proper size.
     *
     * From RFC2408 2.4 Identifying Security Associations:
     *   During phase 1 negotiations, the initiator and responder cookies
     *   determine the ISAKMP SA. Therefore, the SPI field in the Proposal
     *   payload is redundant and MAY be set to 0 or it MAY contain the
     *   transmitting entity's cookie.
     *
     * From RFC2408 3.5 Proposal Payload:
     *    o  SPI Size (1 octet) - Length in octets of the SPI as defined by
     *       the Protocol-Id.  In the case of ISAKMP, the Initiator and
     *       Responder cookie pair from the ISAKMP Header is the ISAKMP SPI,
     *       therefore, the SPI Size is irrelevant and MAY be from zero (0) to
     *       sixteen (16).  If the SPI Size is non-zero, the content of the
     *       SPI field MUST be ignored.  If the SPI Size is not a multiple of
     *       4 octets it will have some impact on the SPI field and the
     *       alignment of all payloads in the message.  The Domain of
     *       Interpretation (DOI) will dictate the SPI Size for other
     *       protocols.
     */
    if (proposal.isap_spisize == 0)
    {
          /* empty (0) SPI -- fine */
    }
    else if (proposal.isap_spisize <= MAX_ISAKMP_SPI_SIZE)
    {
          u_char junk_spi[MAX_ISAKMP_SPI_SIZE];

          if (!in_raw(junk_spi, proposal.isap_spisize, &proposal_pbs, "Oakley SPI"))
              return PAYLOAD_MALFORMED;
    }
    else
    {
          loglog(RC_LOG_SERIOUS, "invalid SPI size (%u) in Oakley Proposal"
              , (unsigned)proposal.isap_spisize);
          return INVALID_SPI;
    }

    if (selection && proposal.isap_notrans != 1)
    {
          loglog(RC_LOG_SERIOUS, "a single Transform is required in a selecting Oakley Proposal; found %u"
              , (unsigned)proposal.isap_notrans);
          return BAD_PROPOSAL_SYNTAX;
    }

    /* for each transform payload... */

    last_transnum = -1;
    no_trans_left = proposal.isap_notrans;
    for (;;)
    {
          pb_stream trans_pbs;
          u_char *attr_start;
          size_t attr_len;
          struct isakmp_transform trans;
          lset_t seen_attrs = 0
              , seen_durations = 0;
          u_int16_t life_type;
          struct trans_attrs ta;
          err_t ugh = NULL;          /* set to diagnostic when problem detected */
          char ugh_buf[256];          /* room for building a diagnostic */
          zero(&ta);

          life_type = 0;

          /* initialize only optional field in ta */
          ta.life_seconds = OAKLEY_ISAKMP_SA_LIFETIME_DEFAULT;          /* When this SA expires (seconds) */

          if (no_trans_left == 0)
          {
              loglog(RC_LOG_SERIOUS, "number of Transform Payloads disagrees with Oakley Proposal Payload");
              return BAD_PROPOSAL_SYNTAX;
          }

          if (!in_struct(&trans, &isakmp_isakmp_transform_desc, &proposal_pbs, &trans_pbs))
              return BAD_PROPOSAL_SYNTAX;

          if (trans.isat_transnum <= last_transnum)
          {
              /* picky, picky, picky */
              loglog(RC_LOG_SERIOUS, "Transform Numbers are not monotonically increasing"
                    " in Oakley Proposal");
              return BAD_PROPOSAL_SYNTAX;
          }
          last_transnum = trans.isat_transnum;

          if (trans.isat_transid != KEY_IKE)
          {
              loglog(RC_LOG_SERIOUS, "expected KEY_IKE but found %s in Oakley Transform"
                    , enum_show(&isakmp_transformid_names, trans.isat_transid));
              return INVALID_TRANSFORM_ID;
          }

          attr_start = trans_pbs.cur;
          attr_len = pbs_left(&trans_pbs);

          /* process all the attributes that make up the transform */

          while (pbs_left(&trans_pbs) != 0)
          {
              struct isakmp_attribute a;
              pb_stream attr_pbs;
              u_int32_t val;          /* room for larger values */
              enum ikev1_oakley_attr attr;

              if (!in_struct(&a, &isakmp_oakley_attribute_desc, &trans_pbs, &attr_pbs))
                    return BAD_PROPOSAL_SYNTAX;

              if((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) >= 32) {
                  /* was a passert(), so you can crash Pluto by sending attributes >32 ?? */

                  loglog(RC_LOG_SERIOUS, "ignoring unknown attribute %u in Oakley Transform %u"
                         , a.isaat_af_type
                         , trans.isat_transnum);
                  continue;
              }

              if (LHAS(seen_attrs, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK))
              {
                    loglog(RC_LOG_SERIOUS, "repeated %s attribute in Oakley Transform %u"
                        , enum_show(&oakley_attr_names, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK)
                        , trans.isat_transnum);
                    return BAD_PROPOSAL_SYNTAX;
              }

              attr = a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK;
              seen_attrs |= LELEM(attr);

              val = a.isaat_lv;

              DBG(DBG_PARSING,
              {
                  enum_names *vdesc;
                  if(val < oakley_attr_val_descs_size) {
                      vdesc = oakley_attr_val_descs[val];

                      if (vdesc != NULL) {
                        const char *nm = enum_name(vdesc, val);

                        if (nm != NULL)
                              DBG_log("   [%u is %s]", (unsigned)val, nm);
                      }
                  } else {
                      DBG_log("   invalid oakley attr: %d", val);
                    }
              });

              switch (a.isaat_af_type)
              {
                    case OAKLEY_ENCRYPTION_ALGORITHM | ISAKMP_ATTR_AF_TV:
                        if (ikev1_alg_enc_ok(val, 0, c->alg_info_ike, &ugh, ugh_buf, sizeof(ugh_buf))) {
                            ta.encrypter = ikev1_alg_get_encr(val);
                            ta.encrypt   = ta.encrypter->common.algo_v2id;
                              ta.enckeylen = ta.encrypter->keydeflen;
                        }
                        break;

                    case OAKLEY_HASH_ALGORITHM | ISAKMP_ATTR_AF_TV:
                        if (ikev1_alg_integ_present(val, 0)) {
                              ta.integ_hasher = ikev1_crypto_get_hasher(val);
                              ta.integ_hash   = ta.integ_hasher->common.algo_v2id;
                              ta.prf_hasher   = ta.integ_hasher;
                              ta.prf_hash     = ta.integ_hash;
                        } else {
                              ugh = builddiag("%s is not supported"
                                  , enum_show(&oakley_hash_names, val));
                        }
                        break;

                    case OAKLEY_AUTHENTICATION_METHOD | ISAKMP_ATTR_AF_TV:
                        {
                      lset_t iap = st->st_policy & POLICY_ID_AUTH_MASK;

                         /* check that authentication method is acceptable */
                        switch (val)
                        {
#ifdef XAUTH
                        case XAUTHInitPreShared:
                              if(!xauth_init)
                              {
                                  ugh = builddiag("policy does not allow Extended Authentication (XAUTH) of initiator (we are %s)", role);
                                  break;
                              }
                              ta.xauth = val;
                              val = OAKLEY_PRESHARED_KEY;
                              goto psk;

                        case XAUTHRespPreShared:
                              if(!xauth_resp)
                              {
                                  ugh = builddiag("policy does not allow Extended Authentication (XAUTH) of responder (we are %s)", role);
                                  break;
                              }
                              ta.xauth = val;
                              val = OAKLEY_PRESHARED_KEY;
                              /* No break; */
#endif


                        case OAKLEY_PRESHARED_KEY:
#ifdef XAUTH
                        psk:
                              if(xauth_init && ta.xauth == 0)
                              {
                                  ugh = builddiag("policy mandates Extended Authentication (XAUTH) with PSK of initiator (we are %s)", role);
                                  break;
                              }
                              if(xauth_resp && ta.xauth == 0)
                              {
                                  ugh = builddiag("policy mandates Extended Authentication (XAUTH) with PSK of responder (we are %s)", role);
                                  break;
                              }
#endif

                              if ((iap & POLICY_PSK) == LEMPTY)
                              {
                                  ugh = "policy does not allow OAKLEY_PRESHARED_KEY authentication";
                              }
                              else
                              {
                                  /* check that we can find a preshared secret */
                                  struct connection *con = st->st_connection;

                                  if (get_preshared_secret(con) == NULL)
                                  {
                                        char mid[IDTOA_BUF]
                                            , hid[IDTOA_BUF];

                                        idtoa(&con->spd.this.id, mid, sizeof(mid));
                                        if (his_id_was_instantiated(con))
                                            strcpy(hid, "%any");
                                        else
                                            idtoa(&con->spd.that.id, hid, sizeof(hid));
                                        ugh = builddiag("Can't authenticate: no preshared key found for `%s' and `%s'"
                                            , mid, hid);
                                  }
                                  ta.auth = val;
                              }
                              break;
#ifdef XAUTH
                        case XAUTHInitRSA:
                              if(!xauth_init)
                              {
                                  ugh = builddiag("policy does not allow Extended Authentication (XAUTH) with RSA of initiator (we are %s)", role);
                                  break;
                              }
                              ta.xauth = val;
                              val = OAKLEY_RSA_SIG;
                              goto rsasig;

                        case XAUTHRespRSA:
                              if(!xauth_resp)
                              {
                                  ugh = builddiag("policy does not allow Extended Authentication (XAUTH) with RSA of responder (we are %s)", role);
                                  break;
                              }
                              ta.xauth = val;
                              val = OAKLEY_RSA_SIG;
                              /* No break; */
#endif

                        case OAKLEY_RSA_SIG:
#ifdef XAUTH
                        rsasig:
                              if(xauth_init && ta.xauth == 0)
                              {
                                  ugh = builddiag("policy mandates Extended Authentication (XAUTH) with RSA of initiator (we are %s)", role);
                                  break;
                              }
                              if(xauth_resp && ta.xauth == 0)
                              {
                                  ugh = builddiag("policy mandates Extended Authentication (XAUTH) with RSA of responder (we are %s)", role);
                                  break;
                              }
#endif
                              /* Accept if policy specifies RSASIG or is default */
                              if ((iap & POLICY_RSASIG) == LEMPTY)
                              {
                                  ugh = "policy does not allow OAKLEY_RSA_SIG authentication";
                              }
                              else
                              {
                                  /* We'd like to check that we can find a public
                                   * key for him and a private key for us that is
                                   * suitable, but we don't yet have his
                                   * Id Payload, so it seems futile to try.
                                   * We can assume that if he proposes it, he
                                   * thinks we've got it.  If we proposed it,
                                   * perhaps we know what we're doing.
                                   */
                                  ta.auth = val;
                              }
                              break;

                        default:
                              ugh = builddiag("Pluto does not support %s authentication"
                                  , enum_show(&oakley_auth_names, val));
                              break;
                        }
                        }
                        break;

                    case OAKLEY_GROUP_DESCRIPTION | ISAKMP_ATTR_AF_TV:
                        ta.group = lookup_group(val);
                        if (ta.group == NULL)
                        {
                              ugh = builddiag("OAKLEY_GROUP %d not supported",val);
                              break;
                        }
                        break;

                    case OAKLEY_LIFE_TYPE | ISAKMP_ATTR_AF_TV:
                        switch (val)
                        {
                        case OAKLEY_LIFE_SECONDS:
                        case OAKLEY_LIFE_KILOBYTES:
                              if (LHAS(seen_durations, val))
                              {
                                  loglog(RC_LOG_SERIOUS
                                        , "attribute OAKLEY_LIFE_TYPE value %s repeated"
                                        , enum_show(&oakley_lifetime_names, val));
                                  return BAD_PROPOSAL_SYNTAX;
                              }
                              seen_durations |= LELEM(val);
                              life_type = val;
                              break;
                        default:
                              ugh = builddiag("unknown value %s"
                                  , enum_show(&oakley_lifetime_names, val));
                              break;
                        }
                        break;

                    case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TLV:
                        val = decode_long_duration(&attr_pbs);
                        /* fall through */
                    case OAKLEY_LIFE_DURATION | ISAKMP_ATTR_AF_TV:
                        if (!LHAS(seen_attrs, OAKLEY_LIFE_TYPE))
                        {
                              ugh = "OAKLEY_LIFE_DURATION attribute not preceded by OAKLEY_LIFE_TYPE attribute";
                              break;
                        }
                        seen_attrs &= ~(LELEM(OAKLEY_LIFE_DURATION) | LELEM(OAKLEY_LIFE_TYPE));

                        switch (life_type)
                        {
                              case OAKLEY_LIFE_SECONDS:
                                  if (val > OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM)
                                        ugh = builddiag("peer requested %lu seconds"
                                            " which exceeds our limit %d seconds"
                                            , (long) val
                                            , OAKLEY_ISAKMP_SA_LIFETIME_MAXIMUM);
                                  ta.life_seconds = val;
                                  break;
                              case OAKLEY_LIFE_KILOBYTES:
                                  ta.life_kilobytes = val;
                                  break;
                              default:
                                  bad_case(life_type);
                        }
                        break;

                    case OAKLEY_KEY_LENGTH | ISAKMP_ATTR_AF_TV:
                        if ((seen_attrs & LELEM(OAKLEY_ENCRYPTION_ALGORITHM)) == 0)
                        {
                              ugh = "OAKLEY_KEY_LENGTH attribute not preceded by OAKLEY_ENCRYPTION_ALGORITHM attribute";
                              break;
                        }
                        if (ta.encrypter == NULL)
                        {
                              ugh = "NULL encrypter with seen OAKLEY_ENCRYPTION_ALGORITHM";
                            break;
                        }
                        /*
                         * check if this keylen is compatible with
                         * specified alg_info_ike
                         */
                        if (!ike_alg_enc_ok(ta.encrypt, val, c->alg_info_ike, NULL, ugh_buf, sizeof(ugh_buf))) {
                              ugh = "peer proposed key_len not valid for encrypt algo setup specified";
                        }
                        ta.enckeylen=val;
                        break;
#if 0 /* not yet supported */
                    case OAKLEY_GROUP_TYPE | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_PRF | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_FIELD_SIZE | ISAKMP_ATTR_AF_TV:

                    case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_GROUP_PRIME | ISAKMP_ATTR_AF_TLV:
                    case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_GROUP_GENERATOR_ONE | ISAKMP_ATTR_AF_TLV:
                    case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_GROUP_GENERATOR_TWO | ISAKMP_ATTR_AF_TLV:
                    case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_GROUP_CURVE_A | ISAKMP_ATTR_AF_TLV:
                    case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_GROUP_CURVE_B | ISAKMP_ATTR_AF_TLV:
                    case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TV:
                    case OAKLEY_GROUP_ORDER | ISAKMP_ATTR_AF_TLV:
#endif
                    default:
                        ugh = "unsupported OAKLEY attribute";
                        break;
              }

              if (ugh != NULL)
              {
                    loglog(RC_LOG_SERIOUS, "%s.  Attribute %s"
                        , ugh, enum_show(&oakley_attr_names, attr));
                    break;
              }
          }


          if (ugh == NULL)
          {
              /* a little more checking is in order */
              {
                    lset_t missing
                        = ~seen_attrs
                        & (LELEM(OAKLEY_ENCRYPTION_ALGORITHM)
                          | LELEM(OAKLEY_HASH_ALGORITHM)
                          | LELEM(OAKLEY_AUTHENTICATION_METHOD)
                          | LELEM(OAKLEY_GROUP_DESCRIPTION));

                    if (missing)
                    {
                        loglog(RC_LOG_SERIOUS, "missing mandatory attribute(s) %s in Oakley Transform %u"
                              , bitnamesof(oakley_attr_bit_names, missing)
                              , trans.isat_transnum);
                        return BAD_PROPOSAL_SYNTAX;
                    }
              }
              /* We must have liked this transform.
               * Lets finish early and leave.
               */

              DBG(DBG_PARSING | DBG_CRYPT
                    , DBG_log("Oakley Transform %u accepted", trans.isat_transnum));

              if (r_sa_pbs != NULL)
              {
                    struct isakmp_proposal r_proposal = proposal;
                    pb_stream r_proposal_pbs;
                    struct isakmp_transform r_trans = trans;
                    pb_stream r_trans_pbs;

                    /* Situation */
                    if (!out_struct(&ipsecdoisit, &ipsec_sit_desc, r_sa_pbs, NULL))
                        impossible();

                    /* Proposal */
#ifdef EMIT_ISAKMP_SPI
                    r_proposal.isap_spisize = COOKIE_SIZE;
#else
                    r_proposal.isap_spisize = 0;
#endif
                    r_proposal.isap_notrans = 1;
                    if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs, &r_proposal_pbs))
                        impossible();

                    /* SPI */
#ifdef EMIT_ISAKMP_SPI
                    if (!out_raw(my_cookie, COOKIE_SIZE, &r_proposal_pbs, "SPI"))
                        impossible();
                    r_proposal.isap_spisize = COOKIE_SIZE;
#else
                    /* none (0) */
#endif

                    /* Transform */
                    r_trans.isat_np = ISAKMP_NEXT_NONE;
                    if (!out_struct(&r_trans, &isakmp_isakmp_transform_desc, &r_proposal_pbs, &r_trans_pbs))
                        impossible();

                    if (!out_raw(attr_start, attr_len, &r_trans_pbs, "attributes"))
                        impossible();
                    close_output_pbs(&r_trans_pbs);
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

          /* on to next transform */
          no_trans_left--;

          if (trans.isat_np == ISAKMP_NEXT_NONE)
          {
              if (no_trans_left != 0)
              {
                    loglog(RC_LOG_SERIOUS, "number of Transform Payloads disagrees with Oakley Proposal Payload");
                    return BAD_PROPOSAL_SYNTAX;
              }
              break;
          }
          if (trans.isat_np != ISAKMP_NEXT_T)
          {
              loglog(RC_LOG_SERIOUS, "unexpected %s payload in Oakley Proposal"
                    , enum_show(&payload_names, proposal.isap_np));
              return BAD_PROPOSAL_SYNTAX;
          }
    }
    loglog(RC_LOG_SERIOUS, "no acceptable Oakley Transform");
    return NO_PROPOSAL_CHOSEN;
}

#if defined(AGGRESSIVE)
/* Initialize st_oakley field of state for use when initiating in
 * aggressive mode.
 *
 * This will return at most one proposal, since AGGR is dumb.
 *
 */

bool
init_am_st_oakley(struct state *st, lset_t policy)
{
    struct trans_attrs ta;
    struct connection *c = st->st_connection;
    struct db_sa *sadb;

    sadb = ikev1_alg_makedb(policy, c->alg_info_ike, TRUE, INITIATOR);
    if(sadb == NULL) {
        return FALSE;
    }

    /* now wanter into the proposed proposal, and extract what we need */

    struct db_attr  *enc, *hash, *auth, *grp;
    struct db_trans *trans;
    struct db_prop  *prop;
    struct db_prop_conj *cprop;

    /* When this SA expires (seconds) */
    ta.life_seconds = st->st_connection->sa_ike_life_seconds;
    ta.life_kilobytes = 1000000;

    if(sadb->prop_conj_cnt != 1) {
        return FALSE;
    }

    cprop = &sadb->prop_conjs[0];

    if(cprop->prop_cnt != 1) {
        return FALSE;
    }
    prop = &cprop->props[0];

    trans = &prop->trans[0];

    if(!(trans->attr_cnt == 4 || trans->attr_cnt == 5)) {
        return FALSE;
    }

    enc  = &trans->attrs[0];
    hash = &trans->attrs[1];
    auth = &trans->attrs[2];
    grp  = &trans->attrs[3];

    DBG(DBG_CONTROL
          , DBG_log("initiating aggressive mode with IKE=E=%d-H=%d-M=%d"
                      , enc->val
                      , hash->val
                      , grp->val));

    passert(enc->type.oakley == OAKLEY_ENCRYPTION_ALGORITHM);
    ta.encrypt = enc->val;             /* OAKLEY_ENCRYPTION_ALGORITHM */
    ta.encrypter = crypto_get_encrypter(ta.encrypt);
    passert(ta.encrypter != NULL);

    if(trans->attr_cnt == 5) {
          struct db_attr *enc_keylen;
          enc_keylen = &trans->attrs[4];
          ta.enckeylen = enc_keylen->val;
    } else {
          ta.enckeylen = ta.encrypter->keydeflen;
    }

    passert(hash->type.oakley == OAKLEY_HASH_ALGORITHM);
    ta.prf_hash = hash->val;               /* OAKLEY_HASH_ALGORITHM */
    ta.prf_hasher = crypto_get_hasher(ta.prf_hash);
    passert(ta.prf_hasher != NULL);

    passert(auth->type.oakley == OAKLEY_AUTHENTICATION_METHOD);
    ta.auth   = auth->val;             /* OAKLEY_AUTHENTICATION_METHOD */

    passert(grp->type.oakley == OAKLEY_GROUP_DESCRIPTION);
    ta.group = lookup_group(grp->val); /* OAKLEY_GROUP_DESCRIPTION */
    passert(ta.group != NULL);

    st->st_oakley = ta;

    return TRUE;
}
#endif


/**
 * Parse the body of an IPsec SA Payload (i.e. Phase 2 / Quick Mode).
 *
 * The main routine is parse_ipsec_sa_body; other functions defined
 * between here and there are just helpers.
 *
 * Various shortcuts are taken.  In particular, the policy, such as
 * it is, is hardwired.
 *
 * If r_sa is non-NULL, the body of an SA representing the selected
 * proposal is emitted into it.
 *
 * If "selection" is true, the SA is supposed to represent the
 * single tranform that the peer has accepted.
 * ??? We only check that it is acceptable, not that it is one that we offered!
 *
 * Only IPsec DOI is accepted (what is the ISAKMP DOI?).
 * Error response is rudimentary.
 *
 * Since all ISAKMP groups in all SA Payloads must match, st->st_pfs_group
 * holds this across multiple payloads.
 * &unset_group signifies not yet "set"; NULL signifies NONE.
 *
 * This routine is used by quick_inI1_outR1() and quick_inR1_outI2().
 */

static const struct ipsec_trans_attrs null_ipsec_trans_attrs = {
    .spi = 0,                                                  /* spi */
    .life_seconds =SA_LIFE_DURATION_DEFAULT,                    /* life_seconds */
    .life_kilobytes=SA_LIFE_DURATION_K_DEFAULT,                    /* life_kilobytes */
    .encapsulation =ENCAPSULATION_MODE_UNSPECIFIED,          /* encapsulation */
};

static bool
parse_ipsec_transform(struct isakmp_transform *trans
                      , struct ipsec_trans_attrs *attrs   /* must be in IKEv2 number space */
, pb_stream *prop_pbs
, pb_stream *trans_pbs
, struct_desc *trans_desc
, int previous_transnum          /* or -1 if none */
, bool selection
, bool is_last
, bool is_ipcomp
, struct state *st)          /* current state object */
{
    lset_t seen_attrs = 0
          , seen_durations = 0;
    u_int16_t life_type;
    const struct oakley_group_desc *pfs_group = NULL;

    life_type = 0;

    if (!in_struct(trans, trans_desc, prop_pbs, trans_pbs))
          return FALSE;

    if (trans->isat_transnum <= previous_transnum)
    {
          loglog(RC_LOG_SERIOUS, "Transform Numbers in Proposal are not monotonically increasing");
          return FALSE;
    }

    switch (trans->isat_np)
    {
          case ISAKMP_NEXT_T:
              if (is_last)
              {
                    loglog(RC_LOG_SERIOUS, "Proposal Payload has more Transforms than specified");
                    return FALSE;
              }
              break;
          case ISAKMP_NEXT_NONE:
              if (!is_last)
              {
                    loglog(RC_LOG_SERIOUS, "Proposal Payload has fewer Transforms than specified");
                    return FALSE;
              }
              break;
          default:
              loglog(RC_LOG_SERIOUS, "expecting Transform Payload, but found %s in Proposal"
                    , enum_show(&payload_names, trans->isat_np));
              return FALSE;
    }

    *attrs = null_ipsec_trans_attrs;
    attrs->transattrs.encrypt = trans->isat_transid;

    while (pbs_left(trans_pbs) != 0)
    {
          struct isakmp_attribute a;
          pb_stream attr_pbs;
          enum_names *vdesc;
          u_int32_t val;          /* room for larger value */
          u_int32_t type;
          bool ipcomp_inappropriate = is_ipcomp;          /* will get reset if OK */

          if (!in_struct(&a, &isakmp_ipsec_attribute_desc, trans_pbs, &attr_pbs))
              return FALSE;

#ifndef HAVE_LABELED_IPSEC
          /*This check is no longer valid when using security labels as SECCTX attribute is in private range and has value of 32001*/
          passert((a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK) < 32);
#endif

          if (LHAS(seen_attrs, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK))
          {
              loglog(RC_LOG_SERIOUS, "repeated %s attribute in IPsec Transform %u"
                    , enum_show(&ipsec_attr_names, a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK)
                    , trans->isat_transnum);
              return FALSE;
          }

          type = a.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK;
          seen_attrs |= LELEM(type);

          val = a.isaat_lv;

          vdesc  = ipsec_attr_val_descs[type];
          if (vdesc != NULL)
          {
              if (enum_name(vdesc, val) == NULL)
              {
                    loglog(RC_LOG_SERIOUS, "invalid value %u for attribute %s in IPsec Transform"
                        , (unsigned)val, enum_show(&ipsec_attr_names, a.isaat_af_type));
                    return FALSE;
              }
              DBG(DBG_PARSING
                    , if ((a.isaat_af_type & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV)
                        DBG_log("   [%u is %s]"
                              , (unsigned)val, enum_show(vdesc, val)));
          }

          switch (type)
          {
#ifdef HAVE_LABELED_IPSEC
          case SECCTX:
                    {
                    pb_stream *   pbs=&attr_pbs;
                        if (!parse_secctx_attr (pbs, st)) {
                        return FALSE;
                        }
                }
                    break;
#endif
          case SA_LIFE_TYPE:
                    ipcomp_inappropriate = FALSE;
                    if (LHAS(seen_durations, val))
                    {
                        loglog(RC_LOG_SERIOUS, "attribute SA_LIFE_TYPE value %s repeated in message"
                              , enum_show(&sa_lifetime_names, val));
                        return FALSE;
                    }
                    seen_durations |= LELEM(val);
                    life_type = val;
                    break;
          case SA_LIFE_DURATION:
              if((a.isaat_af_type & ISAKMP_ATTR_AF_TV) == 0) {
                    val = decode_long_duration(&attr_pbs);
                    /* fall through */
              }
                    ipcomp_inappropriate = FALSE;
                    if (!LHAS(seen_attrs, SA_LIFE_DURATION))
                    {
                        loglog(RC_LOG_SERIOUS, "SA_LIFE_DURATION IPsec attribute not preceded by SA_LIFE_TYPE attribute");
                        return FALSE;
                    }
                    seen_attrs &= ~(LELEM(SA_LIFE_DURATION) | LELEM(SA_LIFE_TYPE));

                    switch (life_type)
                    {
                        case SA_LIFE_TYPE_SECONDS:
                            /* silently limit duration to our maximum */
			    if(val <= SA_LIFE_DURATION_MAXIMUM) {
				if(val < (unsigned)st->st_connection->sa_ipsec_life_seconds) {
				    attrs->life_seconds = val;
				} else {
				    attrs->life_seconds = st->st_connection->sa_ipsec_life_seconds;
				}
			    }
			    else {
				attrs->life_seconds = SA_LIFE_DURATION_MAXIMUM;
			    }
                            break;
                        case SA_LIFE_TYPE_KBYTES:
                              attrs->life_kilobytes = val;
                              break;
                        default:
                      loglog(RC_LOG_SERIOUS, "invalid life type: %u", life_type);
                      return FALSE;
                    }
                    break;
          case GROUP_DESCRIPTION:
                    if (is_ipcomp)
                    {
                        /* Accept reluctantly.  Should not happen, according to
                         * draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
                         */
                        ipcomp_inappropriate = FALSE;
                        loglog(RC_COMMENT
                              , "IPCA (IPcomp SA) contains GROUP_DESCRIPTION."
                              "  Ignoring inapproprate attribute.");
                    }
                    pfs_group = lookup_group(val);
                    if (pfs_group == NULL)
                    {
                        loglog(RC_LOG_SERIOUS, "OAKLEY_GROUP %d not supported for PFS",val);
                        return FALSE;
                    }
                    break;

          case ENCAPSULATION_MODE:
                    ipcomp_inappropriate = FALSE;
#ifdef NAT_TRAVERSAL
                    switch (val) {
                              case ENCAPSULATION_MODE_TUNNEL:
                              case ENCAPSULATION_MODE_TRANSPORT:
                                        if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
                                                  loglog(RC_LOG_SERIOUS,
                                                            "%s must only be used if "
                                                            "NAT-Traversal is not detected",
                                                            enum_name(&enc_mode_names, val));
                                                  /*
                                                   * Accept it anyway because SSH-Sentinel does not
                                                   * use UDP_TUNNEL or UDP_TRANSPORT for the diagnostic.
                                                   *
                                                   * remove when SSH-Sentinel is fixed
                                                   */
#ifdef I_DONT_CARE_OF_SSH_SENTINEL
                                                  return FALSE;
#endif
                                        }
                                        attrs->encapsulation = val;
                                        break;

                              case ENCAPSULATION_MODE_UDP_TRANSPORT_DRAFTS:
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
                                        loglog(RC_LOG_SERIOUS,
                                                  "NAT-Traversal: Transport mode disabled due "
                                                  "to security concerns");
                                        return FALSE;
                                        break;
#endif

                              case ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS:
                                        if (st->hidden_variables.st_nat_traversal & NAT_T_WITH_ENCAPSULATION_RFC_VALUES) {
                                                  loglog(RC_LOG_SERIOUS,
                                                            "%s must only be used with old IETF drafts",
                                                            enum_name(&enc_mode_names, val));
                                                  if(st->st_connection->remotepeertype == CISCO) {
                                                  DBG_log( "Allowing, as this may be due to rekey");
                                                  attrs->encapsulation = val - ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS + ENCAPSULATION_MODE_TUNNEL;
                                                  }
                                                  else {
                                                  return FALSE;
                                                  }
                                        }
                                        else if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
                                                  attrs->encapsulation = val - ENCAPSULATION_MODE_UDP_TUNNEL_DRAFTS + ENCAPSULATION_MODE_TUNNEL;
                                        }
                                        else {
                                                  loglog(RC_LOG_SERIOUS,
                                                            "%s must only be used if "
                                                            "NAT-Traversal is detected",
                                                            enum_name(&enc_mode_names, val));
                                                  return FALSE;
                                        }
                                        break;

                              case ENCAPSULATION_MODE_UDP_TRANSPORT_RFC:
#ifndef I_KNOW_TRANSPORT_MODE_HAS_SECURITY_CONCERN_BUT_I_WANT_IT
                                        loglog(RC_LOG_SERIOUS,
                                                  "NAT-Traversal: Transport mode disabled due "
                                                  "to security concerns");
                                        return FALSE;
                                        break;
#endif

                              case ENCAPSULATION_MODE_UDP_TUNNEL_RFC:
                                        if ((st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
                                                  (st->hidden_variables.st_nat_traversal & NAT_T_WITH_ENCAPSULATION_RFC_VALUES)) {
                                                  attrs->encapsulation = val - ENCAPSULATION_MODE_UDP_TUNNEL_RFC + ENCAPSULATION_MODE_TUNNEL;
                                        }
                                        else if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
                                                  loglog(RC_LOG_SERIOUS,
                                                            "%s must only be used with NAT-T RFC",
                                                            enum_name(&enc_mode_names, val));
                                                  return FALSE;
                                        }
                                        else {
                                                  loglog(RC_LOG_SERIOUS,
                                                            "%s must only be used if "
                                                            "NAT-Traversal is detected",
                                                            enum_name(&enc_mode_names, val));
                                                  return FALSE;
                                        }
                                        break;
                              default:
                                        loglog(RC_LOG_SERIOUS,
                                                  "unknown ENCAPSULATION_MODE %d in IPSec SA", val);
                                        return FALSE;
                                        break;
                    }
#else
                    attrs->encapsulation = val;
#endif
                    break;
          case AUTH_ALGORITHM:
                    attrs->transattrs.integ_hash = ikev1toikev2integ(val);
                    break;
          case KEY_LENGTH:
                    attrs->transattrs.enckeylen = val;
                    break;
#if 0
          case KEY_ROUNDS:
                    attrs->key_rounds = val;
                    break;
#endif
#if 0 /* not yet implemented */
          case COMPRESS_DICT_SIZE:
                    break;
          case COMPRESS_PRIVATE_ALG:
                    break;

          case SA_LIFE_DURATION:
                    break;
          case COMPRESS_PRIVATE_ALG:
                    break;
#endif
              default:
#ifdef HAVE_LABELED_IPSEC
                    if(a.isaat_af_type == (secctx_attr_value | ISAKMP_ATTR_AF_TLV) ) {
                        pb_stream *   pbs=&attr_pbs;
                              if (!parse_secctx_attr (pbs, st)) {
                              return FALSE;
                              }
                    }
                    else {
#endif
                    loglog(RC_LOG_SERIOUS, "unsupported IPsec attribute %s"
                        , enum_show(&ipsec_attr_names, a.isaat_af_type));
                    return FALSE;
#ifdef HAVE_LABELED_IPSEC
                    }
#endif
          }

          if (ipcomp_inappropriate)
          {
              loglog(RC_LOG_SERIOUS, "IPsec attribute %s inappropriate for IPCOMP"
                    , enum_show(&ipsec_attr_names, a.isaat_af_type));
              return FALSE;
          }
    }

    /* Although an IPCOMP SA (IPCA) ought not to have a pfs_group,
     * if it does, demand that it be consistent.
     * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1.
     */
    if (!is_ipcomp || pfs_group != NULL)
    {
          if (st->st_pfs_group == &unset_group)
              st->st_pfs_group = pfs_group;

          if (st->st_pfs_group != pfs_group)
          {
              loglog(RC_LOG_SERIOUS, "GROUP_DESCRIPTION inconsistent with that of %s in IPsec SA"
                    , selection? "the Proposal" : "a previous Transform");
              return FALSE;
          }
    }

    if (LHAS(seen_attrs, SA_LIFE_DURATION))
    {
          loglog(RC_LOG_SERIOUS, "SA_LIFE_TYPE IPsec attribute not followed by SA_LIFE_DURATION attribute in message");
          return FALSE;
    }

    if (!LHAS(seen_attrs, ENCAPSULATION_MODE))
    {
          if (is_ipcomp)
          {
              /* draft-shacham-ippcp-rfc2393bis-05.txt 4.1:
               * "If the Encapsulation Mode is unspecified,
               * the default value of Transport Mode is assumed."
               * This contradicts/overrides the DOI (quuoted below).
               */
              attrs->encapsulation = ENCAPSULATION_MODE_TRANSPORT;
          }
          else
          {
              /* ??? Technically, RFC 2407 (IPSEC DOI) 4.5 specifies that
               * the default is "unspecified (host-dependent)".
               * This makes little sense, so we demand that it be specified.
               */
              loglog(RC_LOG_SERIOUS, "IPsec Transform must specify ENCAPSULATION_MODE");
              return FALSE;
          }
    }

    /* ??? should check for key_len and/or key_rounds if required */

    return TRUE;
}

static void
echo_proposal(struct state *st,
    struct isakmp_proposal r_proposal,          /* proposal to emit */
    struct isakmp_transform r_trans,          /* winning transformation within it */
    u_int8_t np,                              /* Next Payload for proposal */
    pb_stream *r_sa_pbs,                    /* SA PBS into which to emit */
    struct ipsec_proto_info *pi,          /* info about this protocol instance */
    struct_desc *trans_desc,                    /* descriptor for this transformation */
    pb_stream *trans_pbs,                    /* PBS for incoming transform */
    bool tunnel_mode)                              /* true for inner most tunnel SA */
{
    pb_stream r_proposal_pbs;
    pb_stream r_trans_pbs;

    /* Proposal */
    r_proposal.isap_np = np;
    r_proposal.isap_notrans = 1;
    if (!out_struct(&r_proposal, &isakmp_proposal_desc, r_sa_pbs, &r_proposal_pbs))
          impossible();

    /* allocate and emit our CPI/SPI */
    if (r_proposal.isap_protoid == PROTO_IPCOMP)
    {
          /* CPI is stored in network low order end of an
           * ipsec_spi_t.  So we start a couple of bytes in.
           * Note: we may fail to generate a satisfactory CPI,
           * but we'll ignore that.
           */
          pi->our_spi = get_my_cpi(st, tunnel_mode);
          out_raw((u_char *) &pi->our_spi
               + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
              , IPCOMP_CPI_SIZE
              , &r_proposal_pbs, "CPI");
    }
    else
    {
	get_ipsec_spi(pi
		      , r_proposal.isap_protoid == PROTO_IPSEC_AH ?
		      IPPROTO_AH : IPPROTO_ESP
		      , st
		      , tunnel_mode);

	/* XXX should check for errors */
	out_raw((u_char *) &pi->our_spi, IPSEC_DOI_SPI_SIZE
		, &r_proposal_pbs, "SPI");
    }

    /* Transform */
    r_trans.isat_np = ISAKMP_NEXT_NONE;
    if (!out_struct(&r_trans, trans_desc, &r_proposal_pbs, &r_trans_pbs))
          impossible();

    /* Transform Attributes: pure echo */
    trans_pbs->cur = trans_pbs->start + sizeof(struct isakmp_transform);
    if (!out_raw(trans_pbs->cur, pbs_left(trans_pbs)
    , &r_trans_pbs, "attributes"))
          impossible();

    close_output_pbs(&r_trans_pbs);
    close_output_pbs(&r_proposal_pbs);
}

notification_t
parse_ipsec_sa_body(
    pb_stream *sa_pbs,                    /* body of input SA Payload */
    const struct isakmp_sa *sa,          /* header of input SA Payload */
    pb_stream *r_sa_pbs,          /* if non-NULL, where to emit body of winning SA */
    bool selection,                    /* if this SA is a selection, only one transform may appear */
    struct state *st)                    /* current state object */
{
    const struct connection *c = st->st_connection;
    u_int32_t ipsecdoisit;
    pb_stream next_proposal_pbs;

    struct isakmp_proposal next_proposal;
    ipsec_spi_t next_spi;

    bool next_full = TRUE;

    /* DOI */
    if (sa->isasa_doi != ISAKMP_DOI_IPSEC)
    {
          loglog(RC_LOG_SERIOUS, "Unknown or unsupported DOI %s", enum_show(&doi_names, sa->isasa_doi));
          /* XXX Could send notification back */
          return DOI_NOT_SUPPORTED;
    }

    /* Situation */
    if (!in_struct(&ipsecdoisit, &ipsec_sit_desc, sa_pbs, NULL))
          return SITUATION_NOT_SUPPORTED;

    if (ipsecdoisit != SIT_IDENTITY_ONLY)
    {
          loglog(RC_LOG_SERIOUS, "unsupported IPsec DOI situation (%s)"
              , bitnamesof(sit_bit_names, ipsecdoisit));
          /* XXX Could send notification back */
          return SITUATION_NOT_SUPPORTED;
    }

    /* The rules for IPsec SAs are scattered.
     * RFC 2408 "ISAKMP" section 4.2 gives some info.
     * There may be multiple proposals.  Those with identical proposal
     * numbers must be considered as conjuncts.  Those with different
     * numbers are disjuncts.
     * Each proposal may have several transforms, each considered
     * an alternative.
     * Each transform may have several attributes, all applying.
     *
     * To handle the way proposals are combined, we need to do a
     * look-ahead.
     */

    if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs, &next_proposal_pbs))
          return BAD_PROPOSAL_SYNTAX;

    /* for each conjunction of proposals... */
    while (next_full)
    {
          int propno = next_proposal.isap_proposal;
          pb_stream esp_prop_pbs, ipcomp_prop_pbs;
          struct isakmp_proposal ah_proposal, esp_proposal, ipcomp_proposal;
#ifdef IPSEC_IKEV1_AH_BROKEN
          pb_stream ah_prop_pbs;
          ipsec_spi_t ah_spi = 0;
#endif
          ipsec_spi_t esp_spi, ipcomp_cpi;
          bool ah_seen = FALSE, esp_seen = FALSE, ipcomp_seen = FALSE;
          int inner_proto = 0;
          bool tunnel_mode = FALSE;
          u_int16_t well_known_cpi = 0;

          pb_stream ah_trans_pbs, esp_trans_pbs, ipcomp_trans_pbs;
          struct isakmp_transform ah_trans, esp_trans, ipcomp_trans;
          struct ipsec_trans_attrs ah_attrs, esp_attrs, ipcomp_attrs;

          ipcomp_cpi = 0;
          esp_spi = 0;

          memset(&ah_proposal, 0, sizeof(ah_proposal));
          memset(&esp_proposal, 0, sizeof(esp_proposal));
          memset(&ipcomp_proposal, 0, sizeof(ipcomp_proposal));

          /* for each proposal in the conjunction */
          do {

              if (next_proposal.isap_protoid == PROTO_IPCOMP)
              {
                    /* IPCOMP CPI */
                    if (next_proposal.isap_spisize == IPSEC_DOI_SPI_SIZE)
                    {
                        /* This code is to accommodate those peculiar
                         * implementations that send a CPI in the bottom of an
                         * SPI-sized field.
                         * See draft-shacham-ippcp-rfc2393bis-05.txt 4.1
                         */
                        u_int8_t filler[IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE];

                        if (!in_raw(filler, sizeof(filler)
                         , &next_proposal_pbs, "CPI filler")
                        || !all_zero(filler, sizeof(filler)))
                              return INVALID_SPI;
                    }
                    else if (next_proposal.isap_spisize != IPCOMP_CPI_SIZE)
                    {
                        loglog(RC_LOG_SERIOUS, "IPsec Proposal with improper CPI size (%u)"
                              , next_proposal.isap_spisize);
                        return INVALID_SPI;
                    }

                    /* We store CPI in the low order of a network order
                     * ipsec_spi_t.  So we start a couple of bytes in.
                     */
                    zero(&next_spi);
                    if (!in_raw((u_char *)&next_spi
                      + IPSEC_DOI_SPI_SIZE - IPCOMP_CPI_SIZE
                    , IPCOMP_CPI_SIZE, &next_proposal_pbs, "CPI"))
                        return INVALID_SPI;

                    /* If sanity ruled, CPIs would have to be such that
                     * the SAID (the triple (CPI, IPCOM, destination IP))
                     * would be unique, just like for SPIs.  But there is a
                     * perversion where CPIs can be well-known and consequently
                     * the triple is not unique.  We hide this fact from
                     * ourselves by fudging the top 16 bits to make
                     * the property true internally!
                     */
                    switch (ntohl(next_spi))
                    {
                    case IPCOMP_DEFLATE:
                        well_known_cpi = ntohl(next_spi);
                        next_spi = uniquify_his_cpi(next_spi, st);
                        if (next_spi == 0)
                        {
                              loglog(RC_LOG_SERIOUS
                                  , "IPsec Proposal contains well-known CPI that I cannot uniquify");
                              return INVALID_SPI;
                        }
                        break;
                    default:
                        if (ntohl(next_spi) < IPCOMP_FIRST_NEGOTIATED
                        || ntohl(next_spi) > IPCOMP_LAST_NEGOTIATED)
                        {
                              loglog(RC_LOG_SERIOUS, "IPsec Proposal contains CPI from non-negotiated range (0x%lx)"
                                  , (unsigned long) ntohl(next_spi));
                              return INVALID_SPI;
                        }
                        break;
                    }
              }
              else
              {
                    /* AH or ESP SPI */
                    if (next_proposal.isap_spisize != IPSEC_DOI_SPI_SIZE)
                    {
                        loglog(RC_LOG_SERIOUS, "IPsec Proposal with improper SPI size (%u)"
                              , next_proposal.isap_spisize);
                        return INVALID_SPI;
                    }

                    if (!in_raw((u_char *)&next_spi, sizeof(next_spi), &next_proposal_pbs, "SPI"))
                        return INVALID_SPI;

                    /* SPI value 0 is invalid and values 1-255 are reserved to IANA.
                     * RFC 2402 (ESP) 2.4, RFC 2406 (AH) 2.1
                     * IPCOMP???
                     */
                    if (ntohl(next_spi) < IPSEC_DOI_SPI_MIN)
                    {
                        loglog(RC_LOG_SERIOUS, "IPsec Proposal contains invalid SPI (0x%lx)"
                              , (unsigned long) ntohl(next_spi));
                        return INVALID_SPI;
                    }
              }

              if (next_proposal.isap_notrans == 0)
              {
                    loglog(RC_LOG_SERIOUS, "IPsec Proposal contains no Transforms (skipped)");
                    continue;
              }

              switch (next_proposal.isap_protoid)
              {
#ifdef IPSEC_IKEV1_AH_BROKEN
              case PROTO_IPSEC_AH:
                    if (ah_seen)
                    {
                        loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous AH Proposals");
                        return BAD_PROPOSAL_SYNTAX;
                    }
                    ah_seen = TRUE;
                    ah_prop_pbs = next_proposal_pbs;
                    ah_proposal = next_proposal;
                    ah_spi = next_spi;
                    break;
#endif

              case PROTO_IPSEC_ESP:
                    if (esp_seen)
                    {
                        loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous ESP Proposals");
                        return BAD_PROPOSAL_SYNTAX;
                    }
                    esp_seen = TRUE;
                    esp_prop_pbs = next_proposal_pbs;
                    esp_proposal = next_proposal;
                    esp_spi = next_spi;
                    break;

              case PROTO_IPCOMP:
                    if (ipcomp_seen)
                    {
                        loglog(RC_LOG_SERIOUS, "IPsec SA contains two simultaneous IPCOMP Proposals");
                        return BAD_PROPOSAL_SYNTAX;
                    }
                    ipcomp_seen = TRUE;
                    ipcomp_prop_pbs = next_proposal_pbs;
                    ipcomp_proposal = next_proposal;
                    ipcomp_cpi = next_spi;
                    break;

              default:
                    loglog(RC_LOG_SERIOUS, "unexpected Protocol ID (%s) in IPsec Proposal"
                        , enum_show(&protocol_names, next_proposal.isap_protoid));
                    return INVALID_PROTOCOL_ID;
              }

              /* refill next_proposal */
              if (next_proposal.isap_np == ISAKMP_NEXT_NONE)
              {
                    next_full = FALSE;
                    break;
              }
              else if (next_proposal.isap_np != ISAKMP_NEXT_P)
              {
                    loglog(RC_LOG_SERIOUS, "unexpected in Proposal: %s"
                        , enum_show(&payload_names, next_proposal.isap_np));
                    return BAD_PROPOSAL_SYNTAX;
              }

              if (!in_struct(&next_proposal, &isakmp_proposal_desc, sa_pbs, &next_proposal_pbs))
                    return BAD_PROPOSAL_SYNTAX;
          } while (next_proposal.isap_proposal == propno);

          /* Now that we have all conjuncts, we should try
           * the Cartesian product of eachs tranforms!
           * At the moment, we take short-cuts on account of
           * our rudimentary hard-wired policy.
           * For now, we find an acceptable AH (if any)
           * and then an acceptable ESP.  The only interaction
           * is that the ESP acceptance can know whether there
           * was an acceptable AH and hence not require an AUTH.
           */

          if (ah_seen)
          {
#ifdef IPSEC_IKEV1_AH_BROKEN
              int previous_transnum = -1;
              int tn;

              for (tn = 0; tn != ah_proposal.isap_notrans; tn++)
              {
                    int ok_transid = 0;
                    bool ok_auth = FALSE;

                    if (!parse_ipsec_transform(&ah_trans
                    , &ah_attrs
                    , &ah_prop_pbs
                    , &ah_trans_pbs
                    , &isakmp_ah_transform_desc
                    , previous_transnum
                    , selection
                    , tn == ah_proposal.isap_notrans - 1
                    , FALSE
                    , st))
                        return BAD_PROPOSAL_SYNTAX;

                    previous_transnum = ah_trans.isat_transnum;

                    /* we must understand ah_attrs.transid:
                     * COMBINED with ah_attrs.transattrs.integ_hash.
                     * See RFC 2407 "IPsec DOI" section 4.4.3
                     * The following combinations are legal,
                     * but we don't implement all of them:
                     * It seems as if each auth algorithm
                     * only applies to one ah transid.
                     * AH_MD5, AUTH_ALGORITHM_HMAC_MD5
                     * AH_MD5, AUTH_ALGORITHM_KPDK (unimplemented)
                     * AH_SHA, AUTH_ALGORITHM_HMAC_SHA1
                     * AH_DES, AUTH_ALGORITHM_DES_MAC (unimplemented)
                     */
                    switch (ah_attrs.transattrs.integ_hash)
                    {
AA                        XXXX;
                        case AUTH_ALGORITHM_NONE:
                              loglog(RC_LOG_SERIOUS, "AUTH_ALGORITHM attribute missing in AH Transform");
                              return BAD_PROPOSAL_SYNTAX;

                        case AUTH_ALGORITHM_HMAC_MD5:
                              ok_auth = TRUE;
                              /* fall through */
                        case AUTH_ALGORITHM_KPDK:
                              ok_transid = AH_MD5;
                              break;

                        case AUTH_ALGORITHM_HMAC_SHA1:
                              ok_auth = TRUE;
                              ok_transid = AH_SHA;
                              break;

                        case AUTH_ALGORITHM_DES_MAC:
                              ok_transid = AH_DES;
                              break;
                    }
                    if (ah_attrs.transattrs.encrypt != ok_transid)
                    {
                        loglog(RC_LOG_SERIOUS, "%s attribute inappropriate in %s Transform"
                              , enum_name(&auth_alg_names, ah_attrs.transattrs.integ_hash)
                              , enum_show(&ah_transformid_names, ah_attrs.transattrs.encrypt));
                        return BAD_PROPOSAL_SYNTAX;
                    }
                    if (!ok_auth)
                    {
                        DBG(DBG_CONTROL | DBG_CRYPT
                              , DBG_log("%s attribute unsupported"
                                  " in %s Transform from %s"
                                  , enum_name(&auth_alg_names, ah_attrs.transattrs.integ_hash)
                                  , enum_show(&ah_transformid_names, ah_attrs.transattrs.encrypt)
                                  , ip_str(&c->spd.that.host_addr)));
                        continue;   /* try another */
                    }
                    break;          /* we seem to be happy */
              }
              if (tn == ah_proposal.isap_notrans)
                    continue;          /* we didn't find a nice one */
              ah_attrs.spi = ah_spi;
              inner_proto = IPPROTO_AH;
              if (ah_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
                    tunnel_mode = TRUE;
#else
              loglog(RC_LOG_SERIOUS, "AH in IKEv1 mode is not supported. Proposal rejected");
              continue;
#endif
          }

          if (esp_seen)
          {
              int previous_transnum = -1;
              int tn;
              err_t ugh;

              for (tn = 0; tn != esp_proposal.isap_notrans; tn++)
              {
                    if (!parse_ipsec_transform(&esp_trans
                    , &esp_attrs
                    , &esp_prop_pbs
                    , &esp_trans_pbs
                    , &isakmp_esp_transform_desc
                    , previous_transnum
                    , selection
                    , tn == esp_proposal.isap_notrans - 1
                    , FALSE
                    , st))
                        return BAD_PROPOSAL_SYNTAX;

                    previous_transnum = esp_trans.isat_transnum;

                        ugh = kernel_alg_esp_enc_ok(esp_attrs.transattrs.encrypt
                                                            , esp_attrs.transattrs.enckeylen
                                                            , c->alg_info_esp);

                    if(ugh != NULL) {
                        loglog(RC_LOG_SERIOUS, "proposal refused due to: %s", ugh);
                                  loglog(RC_LOG_SERIOUS, "unsupported ESP Transform %s from %s"
                                           , enum_show(&esp_transformid_names, esp_attrs.transattrs.encrypt)
                                           , ip_str(&c->spd.that.host_addr));
                                  continue;   /* try another */
                    }

                    if(!ESP_AALG_PRESENT(esp_attrs.transattrs.integ_hash)) {
                                  loglog(RC_LOG_SERIOUS, "unsupported ESP auth alg %s from %s"
                               , enum_show(&trans_type_integ_names, esp_attrs.transattrs.integ_hash)
                                           , ip_str(&c->spd.that.host_addr));
                                  continue;   /* try another */
                    }

                    break;          /* we seem to be happy */
              }
              if (tn == esp_proposal.isap_notrans)
                    continue;          /* we didn't find a nice one */
              esp_attrs.spi = esp_spi;
              inner_proto = IPPROTO_ESP;
              if (esp_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
                    tunnel_mode = TRUE;
          }
          else if (st->st_policy & POLICY_ENCRYPT)
          {
              DBG(DBG_CONTROL | DBG_CRYPT
                    , DBG_log("policy for \"%s\" requires encryption but ESP not in Proposal from %s"
                        , c->name, ip_str(&c->spd.that.host_addr)));
              continue;          /* we needed encryption, but didn't find ESP */
          }
          else if ((st->st_policy & POLICY_AUTHENTICATE) && !ah_seen)
          {
              DBG(DBG_CONTROL | DBG_CRYPT
                    , DBG_log("policy for \"%s\" requires authentication"
                        " but none in Proposal from %s"
                        , c->name, ip_str(&c->spd.that.host_addr)));
              continue;          /* we need authentication, but we found neither ESP nor AH */
          }

          if (ipcomp_seen)
          {
              int previous_transnum = -1;
              int tn;

#ifdef NEVER          /* we think IPcomp is working now */
              /**** FUDGE TO PREVENT UNREQUESTED IPCOMP:
               **** NEEDED BECAUSE OUR IPCOMP IS EXPERIMENTAL (UNSTABLE).
               ****/
              if (!(st->st_policy & POLICY_COMPRESS))
              {
                    plog("compression proposed by %s, but policy for \"%s\" forbids it"
                        , ip_str(&c->spd.that.host_addr), c->name);
                    continue;          /* unwanted compression proposal */
              }
#endif
              if (!can_do_IPcomp)
              {
                    openswan_log("compression proposed by %s, but KLIPS is not configured with IPCOMP"
                        , ip_str(&c->spd.that.host_addr));
                    continue;
              }

              if (well_known_cpi != 0 && !ah_seen && !esp_seen)
              {
                    openswan_log("illegal proposal: bare IPCOMP used with well-known CPI");
                    return BAD_PROPOSAL_SYNTAX;
              }

              for (tn = 0; tn != ipcomp_proposal.isap_notrans; tn++)
              {
                    if (!parse_ipsec_transform(&ipcomp_trans
                    , &ipcomp_attrs
                    , &ipcomp_prop_pbs
                    , &ipcomp_trans_pbs
                    , &isakmp_ipcomp_transform_desc
                    , previous_transnum
                    , selection
                    , tn == ipcomp_proposal.isap_notrans - 1
                    , TRUE
                    , st))
                        return BAD_PROPOSAL_SYNTAX;

                    previous_transnum = ipcomp_trans.isat_transnum;

                    if (well_known_cpi != 0 && ipcomp_attrs.transattrs.encrypt != well_known_cpi)
                    {
                        openswan_log("illegal proposal: IPCOMP well-known CPI disagrees with transform");
                        return BAD_PROPOSAL_SYNTAX;
                    }

                    switch (ipcomp_attrs.transattrs.encrypt)
                    {
                        case IPCOMP_DEFLATE:    /* all we can handle! */
                              break;

                        default:
                              DBG(DBG_CONTROL | DBG_CRYPT
                                  , DBG_log("unsupported IPCOMP Transform %s from %s"
                                        , enum_show(&ipcomp_transformid_names, ipcomp_attrs.transattrs.encrypt)
                                        , ip_str(&c->spd.that.host_addr)));
                              continue;   /* try another */
                    }

                    if (ah_seen && ah_attrs.encapsulation != ipcomp_attrs.encapsulation)
                    {
                        /* ??? This should be an error, but is it? */
                        DBG(DBG_CONTROL | DBG_CRYPT
                              , DBG_log("AH and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
                    } else if (esp_seen && esp_attrs.encapsulation != ipcomp_attrs.encapsulation)
                    {
                        /* ??? This should be an error, but is it? */
                        DBG(DBG_CONTROL | DBG_CRYPT
                              , DBG_log("ESP and IPCOMP transforms disagree about encapsulation; TUNNEL presumed"));
                    }

                    break;          /* we seem to be happy */
              }
              if (tn == ipcomp_proposal.isap_notrans)
                    continue;          /* we didn't find a nice one */
              ipcomp_attrs.spi = ipcomp_cpi;
              inner_proto = IPPROTO_COMP;
              if (ipcomp_attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL)
                    tunnel_mode = TRUE;
          }

          /* Eureka: we liked what we saw -- accept it. */

          if (r_sa_pbs != NULL)
          {
              /* emit what we've accepted */

              /* Situation */
              if (!out_struct(&ipsecdoisit, &ipsec_sit_desc, r_sa_pbs, NULL))
                    impossible();

              /* AH proposal */
              if (ah_seen)
		  echo_proposal(st, ah_proposal
                        , ah_trans
                        , esp_seen || ipcomp_seen? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE
                        , r_sa_pbs
                        , &st->st_ah
                        , &isakmp_ah_transform_desc
                        , &ah_trans_pbs
                        , tunnel_mode && inner_proto == IPPROTO_AH);

              /* ESP proposal */
              if (esp_seen)
		  echo_proposal(st, esp_proposal
                        , esp_trans
                        , ipcomp_seen? ISAKMP_NEXT_P : ISAKMP_NEXT_NONE
                        , r_sa_pbs
                        , &st->st_esp
                        , &isakmp_esp_transform_desc
                        , &esp_trans_pbs
                        , tunnel_mode && inner_proto == IPPROTO_ESP);

              /* IPCOMP proposal */
              if (ipcomp_seen)
		  echo_proposal(st, ipcomp_proposal
                        , ipcomp_trans
                        , ISAKMP_NEXT_NONE
                        , r_sa_pbs
                        , &st->st_ipcomp
                        , &isakmp_ipcomp_transform_desc
                        , &ipcomp_trans_pbs
                        , tunnel_mode && inner_proto == IPPROTO_COMP);

              close_output_pbs(r_sa_pbs);
          }

          /* save decoded version of winning SA in state */

          st->st_ah.present = ah_seen;
          if (ah_seen)
              st->st_ah.attrs = ah_attrs;

          st->st_esp.present = esp_seen;
          if (esp_seen){
              st->st_esp.attrs = esp_attrs;
          }

          st->st_ipcomp.present = ipcomp_seen;
          if (ipcomp_seen)
              st->st_ipcomp.attrs = ipcomp_attrs;

          return NOTHING_WRONG;
    }

    loglog(RC_LOG_SERIOUS, "no acceptable Proposal in IPsec SA");
    return NO_PROPOSAL_CHOSEN;
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
