/*
 * Dynamic db (proposal, transforms, attributes) handling for IKEv2,
 *         pull data from algoinfo.
 *
 * Copyright (C) 2017: Michael Richardson <mcr@xelerance.com>
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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stddef.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "pluto/defs.h"
#include "packet.h"
#include "pluto/db2_ops.h"
#include "alg_info.h"
#include "oswlog.h"

#include <assert.h>

struct db2_context *alginfo2db2(struct alg_info *ai)
{
  struct db2_context *dc = db2_prop_new(10,10,10);
  int cnt;

  switch(ai->alg_info_protoid) {
  case PROTO_IPSEC_ESP:
    {
      struct esp_info *esp_info;
      ALG_INFO_ESP_FOREACH((struct alg_info_esp *)ai, esp_info, cnt) {
        db2_prop_add(dc, PROTO_IPSEC_ESP, 4);
        db2_trans_add(dc,IKEv2_TRANS_TYPE_ENCR,  esp_info->encryptalg);
        if(esp_info->enckeylen) {
          db2_attr_add(dc, IKEv2_KEY_LENGTH, esp_info->enckeylen);
        }
        db2_trans_add(dc,IKEv2_TRANS_TYPE_INTEG, esp_info->authalg);
        if(esp_info->authkeylen) {
          db2_attr_add(dc, IKEv2_KEY_LENGTH, esp_info->authkeylen);
        }
        db2_prop_close(dc);
      }
    }
    break;

  case PROTO_IPSEC_AH:
    {
      struct esp_info *esp_info;
      ALG_INFO_ESP_FOREACH((struct alg_info_esp *)ai, esp_info, cnt) {
        db2_prop_add(dc, PROTO_IPSEC_AH, 4);
        db2_trans_add(dc,IKEv2_TRANS_TYPE_INTEG, esp_info->authalg);
        if(esp_info->authkeylen) {
          db2_attr_add(dc, IKEv2_KEY_LENGTH, esp_info->authkeylen);
        }
        db2_prop_close(dc);
      }
    }
    break;

  case PROTO_ISAKMP:
    {
      struct ike_info *ike_info;
      ALG_INFO_IKE_FOREACH((struct alg_info_ike *)ai, ike_info, cnt) {
        db2_prop_add(dc, PROTO_ISAKMP, 0);
        db2_trans_add(dc,IKEv2_TRANS_TYPE_PRF,   ike_info->ike_prfalg);
        db2_trans_add(dc,IKEv2_TRANS_TYPE_DH,    ike_info->ike_modp);
        db2_trans_add(dc,IKEv2_TRANS_TYPE_ENCR,  ike_info->ike_ealg);
        if(ike_info->ike_eklen) {
          db2_attr_add(dc, IKEv2_KEY_LENGTH, ike_info->ike_eklen);
        }
        db2_trans_add(dc,IKEv2_TRANS_TYPE_INTEG, ike_info->ike_halg);
        if(ike_info->ike_hklen) {
          db2_attr_add(dc, IKEv2_KEY_LENGTH, ike_info->ike_hklen);
        }
        db2_prop_close(dc);
      }
    }
    break;
  }

  return dc;
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
