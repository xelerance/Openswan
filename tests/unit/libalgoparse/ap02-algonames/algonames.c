/*
 * test case for
 *    converting from text form of ike=
 *    to a structure to represent it.
 *
 * Copyright (C) 2017 Michael Richardson <mcr@xelerance.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include "openswan.h"
#include "ike_alg.h"
#include "plutoalg.h"
#include "oswlog.h"
#include "lib/libalgoparse/algparse.h"

const char *progname;

void exit_tool(int x)
{
  exit(x);
}

struct artab {
    int   trans_type;
    char *ascii;		/* string to process */
    int   proto;
} atodatatab[] = {
    { IKEv2_TRANS_TYPE_ENCR,  "aes_cbc", IKEv2_ENCR_AES_CBC },
    { IKEv2_TRANS_TYPE_ENCR,  "aes_ctr", IKEv2_ENCR_AES_CTR },
    { IKEv2_TRANS_TYPE_ENCR,  "idea",    IKEv2_ENCR_IDEA },
    { IKEv2_TRANS_TYPE_ENCR,  "aes_ccm_16", IKEv2_ENCR_AES_CCM_16 },
    { IKEv2_TRANS_TYPE_DH,    "modp1024", OAKLEY_GROUP_MODP1024 },
    { IKEv2_TRANS_TYPE_DH,    "modp1536", OAKLEY_GROUP_MODP1536 },
    { IKEv2_TRANS_TYPE_DH,    "modp2048", OAKLEY_GROUP_MODP2048 },
    { IKEv2_TRANS_TYPE_DH,    "ecp256",   OAKLEY_GROUP_ECP256 },
    { IKEv2_TRANS_TYPE_DH,    "ecp384",   OAKLEY_GROUP_ECP384 },
    { IKEv2_TRANS_TYPE_DH,    "ecp512",   OAKLEY_GROUP_ECP512 },
    { 0,		NULL, FALSE, },
};

static void regress(void)
{
    int status = 0;
    struct artab *r;
    char buf[100];
    size_t n;

    for (r = atodatatab; r->ascii != NULL; r++) {
        enum_names *lookup = NULL;
        unsigned int item;

        if(r->trans_type < ikev2_transid_val_descs_size) {
           lookup = ikev2_transid_val_descs[r->trans_type];
        }

        if(!lookup) {
            fprintf(stderr, "invalid trans_type: %u\n", r->trans_type);
            continue;
        }

        switch(r->trans_type) {
        case IKEv2_TRANS_TYPE_ENCR:
            item = ealg_getbyname_ike(r->ascii, strlen(r->ascii));
            break;
        default:
            item = enum_search_nocase(lookup, r->ascii, strlen(r->ascii));
        }

        passert(item == r->proto);
    }

    exit(status);
}

/*
  - main - enumerate all the names of each algorithm, and use enum_search to look for some we care about.
 */
int
main(int argc, char *argv[])
{
	char buf[1024];
	char buf2[1024];
	size_t n;
	size_t i;
	char *p = buf;
	char *p2 = buf2;
	char *pgm = argv[0];
        int   result;
	const char *oops;
	struct alg_info_ike *alg_info_ike;
        const  char *err;

        progname = argv[0];

        regress();
	exit(0);
}



/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
