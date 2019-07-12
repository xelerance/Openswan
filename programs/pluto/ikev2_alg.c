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

void kernel_alg_show_status(void)
{
	unsigned sadb_id,id;
	struct pluto_sadb_alg *alg_p;
	ESP_EALG_FOR_EACH(sadb_id) {
		id=sadb_id;
		alg_p=&esp_ealg[sadb_id];
		whack_log(RC_COMMENT, "algorithm ESP encrypt: id=%d, name=%s, "
				"ivlen=%d, keysizemin=%d, keysizemax=%d"
			, id
			, enum_name(&trans_type_encr_names, alg_p->encr_id)
			, alg_p->kernel_sadb_alg.sadb_alg_ivlen
			, alg_p->kernel_sadb_alg.sadb_alg_minbits
			, alg_p->kernel_sadb_alg.sadb_alg_maxbits
		 );

	}
	ESP_AALG_FOR_EACH(sadb_id) {
		id=alg_info_esp_sadb2aa(sadb_id);
		alg_p=&esp_aalg[sadb_id];
		whack_log(RC_COMMENT, "algorithm ESP auth attr: id=%d, name=%s, "
				"keysizemin=%d, keysizemax=%d"
			, id
			, enum_name(&trans_type_integ_names, alg_p->integ_id)
			, alg_p->kernel_sadb_alg.sadb_alg_minbits
			, alg_p->kernel_sadb_alg.sadb_alg_maxbits
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
