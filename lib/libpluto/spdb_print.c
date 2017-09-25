/* Security Policy Data Base debugging routines
 * Copyright (C) 2005-2017 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "pluto/defs.h"
#include "pluto/spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

#include "pluto/db_ops.h"

void
print_sa_attr_oakley(struct db_attr *at)
{
    const struct enum_names *en = NULL;

    if(at->type.oakley == 0) {
	return;
    }

    if(at->type.oakley <= oakley_attr_val_descs_size) {
	en = oakley_attr_val_descs[at->type.oakley];
    }
    DBG_log("        type: %u(%s) val: %u(%s)\n"
            , at->type.oakley
            , enum_name(&oakley_attr_names, at->type.oakley)
            , at->val,  en ? enum_name(en, at->val) : "unknown");
}

void
print_sa_attr_ipsec(struct db_attr *at)
{
    const struct enum_names *en = NULL;

    if(at->type.ipsec == 0) {
	return;
    }

    if(at->type.ipsec <= ipsec_attr_val_descs_size) {
	en = ipsec_attr_val_descs[at->type.ipsec];
    }
    DBG_log("        type: %u(%s) val: %u(%s)\n"
	   , at->type.ipsec
           , enum_name(&ipsec_attr_names, at->type.ipsec+ISAKMP_ATTR_AF_TV)
	   , at->val
           ,  en ? enum_name(en, at->val) : "unknown");
}

void
print_sa_trans(bool parentSA, struct db_trans *tr)
{
    unsigned int i;
    DBG_log("      transform: %u cnt: %u\n",
	   tr->transid, tr->attr_cnt);
    if (!tr->attrs) {
        if (tr->attr_cnt)
            printf("      !!! WARNING: tr->attrs found NULL\n");
        return;
    }
    for(i=0; i<tr->attr_cnt; i++) {
	if(parentSA) {
	    print_sa_attr_oakley(&tr->attrs[i]);
	} else {
	    print_sa_attr_ipsec(&tr->attrs[i]);
	}
    }
}

void
print_sa_prop(bool parentSA, struct db_prop *dp)
{
    unsigned int i;
    DBG_log("    protoid: %u (%s) cnt: %u\n"
	   , dp->protoid
	   , enum_name(&protocol_names, dp->protoid)
	   , dp->trans_cnt);
    if (!dp->trans) {
        if (dp->trans_cnt)
            printf("      !!! WARNING: dp->trans found NULL\n");
        return;
    }
    for(i=0; i<dp->trans_cnt; i++) {
	print_sa_trans(parentSA, &dp->trans[i]);
    }
}

void
print_sa_prop_conj(bool parentSA, struct db_prop_conj *pc)
{
    unsigned int i;
    DBG_log("  conjunctions cnt: %u\n",
	   pc->prop_cnt);
    if (!pc->props) {
        if (pc->prop_cnt)
            printf("      !!! WARNING: pc->props found NULL\n");
        return;
    }
    for(i=0; i<pc->prop_cnt; i++) {
	print_sa_prop(parentSA, &pc->props[i]);
    }
}

void
sa_print(struct db_sa *f)
{
    unsigned int i;
    DBG_log("sa disjunct cnt: %u\n",
	   f->prop_conj_cnt);
    if (!f->prop_conjs) {
        if (f->prop_conj_cnt)
            printf("      !!! WARNING: f->prop_conjs found NULL\n");
        return;
    }
    for(i=0; i<f->prop_conj_cnt; i++) {
	print_sa_prop_conj(f->parentSA, &f->prop_conjs[i]);
    }
}

void
db_print(struct db_context *ctx)
{
    print_sa_prop(ctx->prop.protoid == KEY_IKE, &ctx->prop);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
