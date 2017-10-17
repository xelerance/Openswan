/*
 * This code handles PARENT (IKEv2) algorithm lists and choices
 *   based upon plutoalg.c, which was moved to libalgoparse.
 * (C)opyright 2017 Michael Richardson <mcr@xelerance.com>
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

#include <sys/types.h>
#include <stdlib.h>
#include <openswan.h>
#include <openswan/pfkeyv2.h>
#include <openswan/passert.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "pluto/defs.h"
#include "id.h"
#include "kernel_alg.h"
#include "alg_info.h"
#include "pluto/ike_alg.h"
#include "pluto/plutoalg.h"
#include "pluto/crypto.h"
#include "oswlog.h"

#include "pluto/connections.h"
#include "pluto/state.h"
#include "db_ops.h"


static void
kernel_alg_policy_algorithms(struct esp_info *esp_info)
{
    int ealg_i=esp_info->esp_ealg_id;
    switch(ealg_i) {
        case 0:
        case ESP_DES:
        case ESP_3DES:
        case ESP_NULL:
        case ESP_CAST:
            break;
        default:
            if (!esp_info->esp_ealg_keylen) {
                /**
                 * algos that need  KEY_LENGTH
                 *
                 * Note: this is a very dirty hack ;-)
                 *
                 * XXX:jjo
                 * Idea: Add a key_length_needed attribute to
                 * esp_ealg ??
                 */
                esp_info->esp_ealg_keylen=
                    esp_ealg[ealg_i].sadb_alg_maxbits;

            }
    }
}

static bool
kernel_alg_db_add(struct db_context *db_ctx
		  , struct esp_info *esp_info
		  , lset_t policy
		  , bool logit)
{
	int ealg_i=0, aalg_i;

	if(policy & POLICY_ENCRYPT) {
	    ealg_i=esp_info->esp_ealg_id;
	    if (!ESP_EALG_PRESENT(ealg_i)) {
		if(logit) {
		    openswan_loglog(RC_LOG_SERIOUS
				    , "requested kernel enc ealg_id=%d not present"
				    , ealg_i);
		} else {
		    DBG_log("requested kernel enc ealg_id=%d not present", ealg_i);
		}
		return FALSE;
	    }
	}

	aalg_i=alg_info_esp_aa2sadb(esp_info->esp_aalg_id);
	if (!ESP_AALG_PRESENT(aalg_i)) {
	    DBG_log("kernel_alg_db_add() kernel auth "
		    "aalg_id=%d not present",
		    aalg_i);
	    return FALSE;
	}

	/* 	do algo policy */
	kernel_alg_policy_algorithms(esp_info);

	if(policy & POLICY_ENCRYPT) {
	    /*	open new transformation */
	    db_trans_add(db_ctx, ealg_i);

            /* XXX-MCR todo: needs to handle IKEV2 now as well  #3949  */
	    /* add ESP auth attr (if present) */
	    if (esp_info->esp_aalg_id != AUTH_ALGORITHM_NONE) {
		db_attr_add_values(db_ctx,
				   AUTH_ALGORITHM, esp_info->esp_aalg_id);
	    }

	    /*	add keylegth if specified in esp= string */
	    if (esp_info->esp_ealg_keylen) {

		if(esp_info->esp_ealg_id == ESP_AES_GCM_8
			|| esp_info->esp_ealg_id == ESP_AES_GCM_12
			|| esp_info->esp_ealg_id == ESP_AES_GCM_16 ) {

			db_attr_add_values(db_ctx,
				   KEY_LENGTH, esp_info->esp_ealg_keylen - 4 * BITS_PER_BYTE);
		}
		else {
			db_attr_add_values(db_ctx,
				KEY_LENGTH, esp_info->esp_ealg_keylen );
		}
	    }

	} else if(policy & POLICY_AUTHENTICATE) {
	    /*	open new transformation */
	    db_trans_add(db_ctx, aalg_i);

	    /* add ESP auth attr */
	    db_attr_add_values(db_ctx,
			       AUTH_ALGORITHM, esp_info->esp_aalg_id);

	}

	return TRUE;
}

/*
 *	Create proposal with runtime kernel algos, merging
 *	with passed proposal if not NULL
 *
 *	for now this function does free() previous returned
 *	malloced pointer (this quirk allows easier spdb.c change)
 */
struct db_context *
kernel_alg_db_new(struct alg_info_esp *alg_info, lset_t policy, bool logit)
{
    int ealg_i, aalg_i;
    unsigned int tn=0;
	int i;
	const struct esp_info *esp_info;
	struct esp_info tmp_esp_info;
	struct db_context *ctx_new=NULL;
	struct db_trans *t;
	struct db_prop  *prop;
	unsigned int trans_cnt = 0;
	bool success = TRUE;
	int protoid = 0;

	if(policy & POLICY_ENCRYPT) {
	    trans_cnt=(esp_ealg_num*esp_aalg_num);
	    protoid = PROTO_IPSEC_ESP;
	} else if(policy & POLICY_AUTHENTICATE) {
	    trans_cnt=esp_aalg_num;
	    protoid = PROTO_IPSEC_AH;
	}

	DBG(DBG_EMITTING, DBG_log("kernel_alg_db_new() "
		"initial trans_cnt=%d",
		trans_cnt));

	/*	pass aprox. number of transforms and attributes */
	ctx_new = db_prop_new(protoid, trans_cnt, trans_cnt * 2);

	/*
	 * 	Loop: for each element (struct esp_info) of
	 * 	alg_info, if kernel support is present then
	 * 	build the transform (and attrs)
	 *
	 * 	if NULL alg_info, propose everything ...
	 */

	/* passert(alg_info!=0); */
	if (alg_info) {
		ALG_INFO_ESP_FOREACH(alg_info, esp_info, i) {
		    bool thistime;
		    tmp_esp_info = *esp_info;
		    thistime = kernel_alg_db_add(ctx_new
						 , &tmp_esp_info
						 , policy, logit);
		    if(thistime == FALSE) {
			success=FALSE;
		    }
		}
	} else {
		ESP_EALG_FOR_EACH_UPDOWN(ealg_i) {
			tmp_esp_info.esp_ealg_id=ealg_i;
			tmp_esp_info.esp_ealg_keylen=0;
			ESP_AALG_FOR_EACH(aalg_i) {
				tmp_esp_info.esp_aalg_id=alg_info_esp_sadb2aa(aalg_i);
				tmp_esp_info.esp_aalg_keylen=0;
				kernel_alg_db_add(ctx_new, &tmp_esp_info
						  , policy, FALSE);
			}
		}
	}

	if(success == FALSE) {
	    /* NO algorithms were found. oops */
	    db_destroy(ctx_new);
	    return NULL;
	}


	prop=db_prop_get(ctx_new);

	DBG(DBG_CONTROL|DBG_EMITTING, DBG_log("kernel_alg_db_new() "
		"will return p_new->protoid=%d, p_new->trans_cnt=%d",
		prop->protoid, prop->trans_cnt));

	for(t=prop->trans,tn=0;
	    t!= NULL && t[tn].transid != 0 && tn<prop->trans_cnt;
	    tn++) {
	    DBG(DBG_CONTROL|DBG_EMITTING,
		DBG_log("kernel_alg_db_new() "
			"    trans[%d]: transid=%d, attr_cnt=%d, "
			"attrs[0].type=%d, attrs[0].val=%d"
			, tn
			, t[tn].transid, t[tn].attr_cnt
			, t[tn].attrs ? t[tn].attrs[0].type.ipsec : 255
			, t[tn].attrs ? t[tn].attrs[0].val : 255
			));
	}
	prop->trans_cnt = tn;

	return ctx_new;
}

void kernel_alg_show_status(void)
{
	unsigned sadb_id,id;
	struct sadb_alg *alg_p;
	ESP_EALG_FOR_EACH(sadb_id) {
		id=sadb_id;
		alg_p=&esp_ealg[sadb_id];
		whack_log(RC_COMMENT, "algorithm ESP encrypt: id=%d, name=%s, "
				"ivlen=%d, keysizemin=%d, keysizemax=%d"
			, id
			, enum_name(&esp_transformid_names, id)
			, alg_p->sadb_alg_ivlen
			, alg_p->sadb_alg_minbits
			, alg_p->sadb_alg_maxbits
		 );

	}
	ESP_AALG_FOR_EACH(sadb_id) {
		id=alg_info_esp_sadb2aa(sadb_id);
		alg_p=&esp_aalg[sadb_id];
		whack_log(RC_COMMENT, "algorithm ESP auth attr: id=%d, name=%s, "
				"keysizemin=%d, keysizemax=%d"
			, id
			, enum_name(&auth_alg_names, id)
			, alg_p->sadb_alg_minbits
			, alg_p->sadb_alg_maxbits
		 );
	}
}

static const char *pfs_group_from_state(struct state *st)
{
    return st->st_pfs_group ?
        enum_show(&oakley_group_names,
                  st->st_pfs_group->group)
        : "phase1";
}

void
kernel_alg_show_connection(struct connection *c, const char *instance)
{
	char buf[1024];
	struct state *st;
	const char *satype;

	if(c->policy & POLICY_ENCRYPT) satype="ESP";
	else if(c->policy & POLICY_AUTHENTICATE) satype="AH";
	else satype="ESP+AH";

	if(c->alg_info_esp == NULL) return;

	if (c->alg_info_esp) {
	    alg_info_snprint(buf, sizeof(buf), (struct alg_info *)c->alg_info_esp);
	    whack_log(RC_COMMENT
		      , "\"%s\"%s:   %s algorithms wanted: %s"
		      , c->name
		      , instance, satype
		      , buf);
	}

	if (c->alg_info_esp) {
	    alg_info_snprint_phase2(buf, sizeof(buf), (struct alg_info_esp *)c->alg_info_esp);
	    whack_log(RC_COMMENT
		      , "\"%s\"%s:   %s algorithms loaded: %s"
		      , c->name
		      , instance, satype
		      , buf);
	}

	st = state_with_serialno(c->newest_ipsec_sa);
	if (st && st->st_esp.present)
		whack_log(RC_COMMENT
                          , "\"%s\"%s:   %s algorithm newest: %s_%03d-%s-%s"
                          , c->name
			  , instance, satype
                          , enum_show(&esp_transformid_names
                                      ,st->st_esp.attrs.transattrs.encrypt)
                          , st->st_esp.attrs.transattrs.enckeylen
                          , enum_show(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash)
                          , c->policy & POLICY_PFS ? pfs_group_from_state(st) : "nopfs"
		    );

	if (st && st->st_ah.present)
		whack_log(RC_COMMENT
		, "\"%s\"%s:   %s algorithm newest: %s-%s"
                          , c->name
			  , instance, satype
                          , enum_show(&auth_alg_names, st->st_esp.attrs.transattrs.integ_hash)
                          , c->policy & POLICY_PFS ? pfs_group_from_state(st) : "nopfs"
	);

}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
