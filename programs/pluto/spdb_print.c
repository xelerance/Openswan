/* Security Policy Data Base debugging routines
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: spdb_print.c,v 1.2 2005/08/05 19:16:48 mcr Exp $
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
#include "smartcard.h"
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
print_sa_attr(struct db_attr *at)
{
    if(at->type == 0) {
	return;
    }
    
    printf("        type: %u val: %d\n", at->type, at->val);
}

void
print_sa_trans(struct db_trans *tr)
{
    int i;
    printf("      transform: %u cnt: %u\n",
	   tr->transid, tr->attr_cnt);
    for(i=0; i<tr->attr_cnt; i++) {
	print_sa_attr(&tr->attrs[i]);
    }
}

void
print_sa_prop(struct db_prop *dp)
{
    int i;
    printf("    protoid: %u (%s) cnt: %u\n"
	   , dp->protoid
	   , enum_name(&protocol_names, dp->protoid)
	   , dp->trans_cnt);
    for(i=0; i<dp->trans_cnt; i++) {
	print_sa_trans(&dp->trans[i]);
    }
}

void
print_sa_prop_conj(struct db_prop_conj *pc)
{
    int i;
    printf("  conjunctions cnt: %u\n",
	   pc->prop_cnt);
    for(i=0; i<pc->prop_cnt; i++) {
	print_sa_prop(&pc->props[i]);
    }
}

void
sa_print(struct db_sa *f)
{
    int i;
    printf("sa disjunct cnt: %u\n",
	   f->prop_conj_cnt);
    for(i=0; i<f->prop_conj_cnt; i++) {
	print_sa_prop_conj(&f->prop_conjs[i]);
    }
}

void
print_sa_v2_trans(struct db_v2_trans *tr)
{
    int i;
    printf("      type: %u(%s) transform: %u cnt: %u\n"
	   , tr->transform_type
	   , enum_name(&trans_type_names, tr->transform_type)
	   , tr->transid
	   , tr->attr_cnt);
    for(i=0; i<tr->attr_cnt; i++) {
	print_sa_attr(&tr->attrs[i]);
    }
}

void
print_sa_v2_prop_conj(struct db_v2_prop_conj *dp, int propnum)
{
    int i;
    printf("    proposal #%u protoid: %u (%s) cnt: %u\n", propnum
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
    int i;
    printf("  conjunctions cnt: %u\n",
	   pc->prop_cnt);
    for(i=0; i<pc->prop_cnt; i++) {
	    print_sa_v2_prop_conj(&pc->props[i], i);
    }
}

void
sa_v2_print(struct db_sa *f)
{
	int i;
	printf("sav2 disjoint cnt: %u\n",
	       f->prop_disj_cnt);
	for(i=0; i<f->prop_disj_cnt; i++) {
		print_sa_v2_prop(&f->prop_disj[i]);
	}
}
