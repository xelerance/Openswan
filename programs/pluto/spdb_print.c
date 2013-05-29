/* Security Policy Data Base debugging routines
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
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
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "spdb.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */

#include "alg_info.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "spdb.h"

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
    printf("        type: %u(%s) val: %u(%s)\n"
	   , at->type.oakley, enum_name(&oakley_attr_names, at->type.oakley+ISAKMP_ATTR_AF_TV)
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
    printf("        type: %u(%s) val: %u(%s)\n"
	   , at->type.ipsec, enum_name(&ipsec_attr_names, at->type.ipsec+ISAKMP_ATTR_AF_TV)
	   , at->val,  en ? enum_name(en, at->val) : "unknown");
}

void
print_sa_trans(struct db_sa *f, struct db_trans *tr)
{
    unsigned int i;
    printf("      transform: %u cnt: %u\n",
	   tr->transid, tr->attr_cnt);
    for(i=0; i<tr->attr_cnt; i++) {
	if(f->parentSA) {
	    print_sa_attr_oakley(&tr->attrs[i]);
	} else {
	    print_sa_attr_ipsec(&tr->attrs[i]);
	}
    }
}

void
print_sa_prop(struct db_sa *f, struct db_prop *dp)
{
    unsigned int i;
    printf("    protoid: %u (%s) cnt: %u\n"
	   , dp->protoid
	   , enum_name(&protocol_names, dp->protoid)
	   , dp->trans_cnt);
    for(i=0; i<dp->trans_cnt; i++) {
	print_sa_trans(f, &dp->trans[i]);
    }
}

void
print_sa_prop_conj(struct db_sa *f, struct db_prop_conj *pc)
{
    unsigned int i;
    printf("  conjunctions cnt: %u\n",
	   pc->prop_cnt);
    for(i=0; i<pc->prop_cnt; i++) {
	print_sa_prop(f, &pc->props[i]);
    }
}

void
sa_print(struct db_sa *f)
{
    unsigned int i;
    printf("sa disjunct cnt: %u\n",
	   f->prop_conj_cnt);
    for(i=0; i<f->prop_conj_cnt; i++) {
	print_sa_prop_conj(f, &f->prop_conjs[i]);
    }
}

static void
print_sa_v2_attr(struct db_attr *at)
{
    //const struct enum_names *en = NULL;

    if(at->type.ikev2 == 0) {
	return;
    }

    //en = NULL; /* XXX */
    printf("        type: %u(%s) val: %u(%s)\n"
	   , at->type.ikev2, "" /*enum_name(&oakley_attr_names, at->type+ISAKMP_ATTR_AF_TV)*/
	   , at->val, "unknown");
}

void
print_sa_v2_trans(struct db_v2_trans *tr)
{
    unsigned int i;
    const struct enum_names *en = NULL;

    if(tr->transform_type <= ikev2_transid_val_descs_size) {
	en = ikev2_transid_val_descs[tr->transform_type];
    }

    printf("      type: %u(%s) value: %u(%s) attr_cnt: %u\n"
	   , tr->transform_type
	   , enum_name(&trans_type_names, tr->transform_type)
	   , tr->transid, en ? enum_name(en, tr->transid) : "unknown"
	   , tr->attr_cnt);
    for(i=0; i<tr->attr_cnt; i++) {
	print_sa_v2_attr(&tr->attrs[i]);
    }
}

void
print_sa_v2_prop_conj(struct db_v2_prop_conj *dp)
{
    unsigned int i;
    printf("    proposal #%u protoid: %u (%s) cnt: %u\n"
	   , dp->propnum
	   , dp->protoid
	   , enum_name(&protocol_names, dp->protoid)
	   , dp->trans_cnt);
    for(i=0; i<dp->trans_cnt; i++) {
	print_sa_v2_trans(&dp->trans[i]);
    }
}

void
print_sa_v2_prop(struct db_v2_prop *pc)
{
    unsigned int i;
    printf("  conjunctions cnt: %u\n",
	   pc->prop_cnt);
    for(i=0; i<pc->prop_cnt; i++) {
	    print_sa_v2_prop_conj(&pc->props[i]);
    }
}

void
sa_v2_print(struct db_sa *f)
{
	unsigned int i;
	printf("sav2 disjoint cnt: %u\n",
	       f->prop_disj_cnt);
	for(i=0; i<f->prop_disj_cnt; i++) {
		print_sa_v2_prop(&f->prop_disj[i]);
	}
}


/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
