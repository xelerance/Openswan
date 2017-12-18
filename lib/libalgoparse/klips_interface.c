/*
 * Kernel runtime algorithm handling interface
 * Copyright Michael Richardson (C) 2017 <mcr@xelerance.com>
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * originally from kernel_alg.c,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
#include <unistd.h>
#include <sys/queue.h>

#include <openswan.h>

#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "oswlog.h"
#include "oswalloc.h"

/*
 *          Load kernel_alg arrays from /proc
 *           used in manual mode from klips/utils/spi.c as well as pluto.
 */
int
kernel_alg_proc_read(void)
{
    int satype;
    int supp_exttype;
    int alg_id, ivlen, minbits, maxbits;
    char name[20];
    struct sadb_alg sadb_alg;
    int ret;
    char buf[128];
    FILE *fp=fopen("/proc/net/pf_key_supported", "r");
    if (!fp)
        return -1;
    kernel_alg_init();
    while (fgets(buf, sizeof(buf), fp)) {
        if (buf[0] != ' ') /* skip titles */
            continue;
        sscanf(buf, "%d %d %d %d %d %d %s",
               &satype, &supp_exttype,
               &alg_id, &ivlen,
               &minbits, &maxbits, name);
        switch (satype) {
        case SADB_SATYPE_ESP:
            switch(supp_exttype) {
            case SADB_EXT_SUPPORTED_AUTH:
            case SADB_EXT_SUPPORTED_ENCRYPT:
                sadb_alg.sadb_alg_id=alg_id;
                sadb_alg.sadb_alg_ivlen=ivlen;
                sadb_alg.sadb_alg_minbits=minbits;
                sadb_alg.sadb_alg_maxbits=maxbits;
                sadb_alg.sadb_alg_reserved=0;
                ret=kernel_alg_add(satype, supp_exttype, &sadb_alg);
                DBG(DBG_CRYPT, DBG_log("kernel_alg_proc_read() alg_id=%d, "
                                       "alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
                                       "ret=%d",
                                       sadb_alg.sadb_alg_id,
                                       sadb_alg.sadb_alg_ivlen,
                                       sadb_alg.sadb_alg_minbits,
                                       sadb_alg.sadb_alg_maxbits,
                                       ret));
            }
        default:
            continue;
        }
    }
    fclose(fp);
    return 0;
}

/*
 *          Load kernel_alg arrays pluto's SADB_REGISTER
 *           user by pluto/kernel.c
 */

void
kernel_alg_register_pfkey(const struct sadb_msg *msg_buf, int buflen)
{
    /*
     *          Trick: one 'type-mangle-able' pointer to
     *          ease offset/assign
     */
    union {
        const struct sadb_msg *msg;
        const struct sadb_supported *supported;
        const struct sadb_ext *ext;
        const struct sadb_alg *alg;
        const char *ch;
    } sadb;
    int satype;
    int msglen;
    int i=0;
    /*          Initialize alg arrays           */
    kernel_alg_init();
    satype=msg_buf->sadb_msg_satype;
    sadb.msg=msg_buf;
    msglen=sadb.msg->sadb_msg_len*IPSEC_PFKEYv2_ALIGN;
    msglen-=sizeof(struct sadb_msg);
    buflen-=sizeof(struct sadb_msg);
    passert(buflen>0);
    sadb.msg++;
    while(msglen) {
        int supp_exttype=sadb.supported->sadb_supported_exttype;
        int supp_len;
        supp_len=sadb.supported->sadb_supported_len*IPSEC_PFKEYv2_ALIGN;
        DBG(DBG_KLIPS, DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
                               "sadb_msg_len=%d sadb_supported_len=%d",
                               satype==SADB_SATYPE_ESP? "ESP" : "AH",
                               msg_buf->sadb_msg_len,
                               supp_len));
        sadb.supported++;
        msglen-=supp_len;
        buflen-=supp_len;
        passert(buflen>=0);
        for (supp_len-=sizeof(struct sadb_supported);
             supp_len;
             supp_len-=sizeof(struct sadb_alg), sadb.alg++,i++) {

            int ret;
            ret=kernel_alg_add(satype, supp_exttype, sadb.alg);

            DBG(DBG_KLIPS, DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: "
                                   "alg[%d], exttype=%d, satype=%d, alg_id=%d, "
                                   "alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, "
                                   "res=%d, ret=%d",
                                   satype==SADB_SATYPE_ESP? "ESP" : "AH",
                                   i,
                                   supp_exttype,
                                   satype,
                                   sadb.alg->sadb_alg_id,
                                   sadb.alg->sadb_alg_ivlen,
                                   sadb.alg->sadb_alg_minbits,
                                   sadb.alg->sadb_alg_maxbits,
                                   sadb.alg->sadb_alg_reserved,
                                   ret));
                    }
          }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
