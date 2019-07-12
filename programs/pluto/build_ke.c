/*
 * Cryptographic helper function - calculate KE and nonce
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 - 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
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
 * This code was developed with the support of IXIA communications.
 *
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "crypto.h"
#include "rnd.h"
#include "pluto/state.h"
#include "pluto_crypt.h"
#include "oswlog.h"
#include "log.h"
#include "timer.h"

#include "oswcrypto.h"

#ifdef HAVE_LIBNSS
# include <nss.h>
#include  <nspr.h>
# include <pk11pub.h>
# include <keyhi.h>
# include "oswconf.h"
#endif

stf_status build_ke(struct pluto_crypto_req_cont *cn
		    , struct state *st
		    , const struct oakley_group_desc *group
		    , enum crypto_importance importance)
{
    struct pluto_crypto_req rd;
    struct pluto_crypto_req *r = &rd;
    err_t e;
    bool toomuch = FALSE;

    pcr_init(r, pcr_build_kenonce, importance);
    r->pcr_d.kn.oakley_group   = group->group;

    cn->pcrc_serialno = st->st_serialno;
    e= send_crypto_helper_request(r, cn, &toomuch);

    if(e != NULL) {
	loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
	if(toomuch) {
	    return STF_TOOMUCHCRYPTO;
	} else {
	    return STF_FAIL;
	}
    } else if(!toomuch) {
	st->st_calculating = TRUE;
	delete_event(st);
	event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
	return STF_SUSPEND;
    } else {
	/* we must have run the continuation directly, so
	 * complete_v1_state_transition already got called.
	 */
	return STF_INLINE;
    }
}


stf_status build_nonce(struct pluto_crypto_req_cont *cn
		       , struct state *st
		       , enum crypto_importance importance)
{
    struct pluto_crypto_req rd;
    struct pluto_crypto_req *r = &rd;
    err_t e;
    bool toomuch = FALSE;

  pcr_init(r, pcr_build_nonce, importance);

  cn->pcrc_serialno = st->st_serialno;
  e = send_crypto_helper_request(r, cn, &toomuch);

  if(e != NULL) {
      loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
      if(toomuch) {
	  return STF_TOOMUCHCRYPTO;
      } else {
	  return STF_FAIL;
      }
  } else if(!toomuch) {
      st->st_calculating = TRUE;
      delete_event(st);
      event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY, st);
      return STF_SUSPEND;
  } else {
      /* we must have run the continuation directly, so
       * complete_v1_state_transition already got called.
       */
      return STF_INLINE;
  }
}


/*
 * Local Variables:
 * c-basic-offset: 4
 * c-style: pluto
 * End:
 */
