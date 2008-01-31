 /* do PSK operations for IKEv2
 *
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "cookie.h"
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
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "dpd.h"
#include "keys.h"
#include "ipsec_doi.h"	

#ifdef HAVE_OCF
#include "ocf_pk.h"
#endif

/* Send v2CERT and v2 CERT */
stf_status ikev2_send_cert( struct state *st
				  , unsigned int np
                                  , pb_stream *outpbs)
{
    struct ikev2_cert cert;
    /*  flag : to send a certificate request aka CERTREQ */
    bool send_certreq = FALSE; 
    
    cert_t mycert = st->st_connection->spd.this.cert;
    /* [CERT,] [CERTREQ,] [IDr,] */
    
    {
    /* decide the next payload; 
     * send a CERTREQ if auth is RSA and no preloaded RSA public key exists 
     */
    send_certreq = FALSE;
    /* TBD    send_certreq = !has_preloaded_public_key(st);  */
    }
    DBG(DBG_CONTROL
	, DBG_log("has %spreloaded a public key from st"
		  , send_certreq ? "" : "not "));
    DBG(DBG_CONTROL
	, DBG_log("my next payload will %sbe a certificate request"
		  , send_certreq ? "" : "not "));
    
    cert.isac_critical = ISAKMP_PAYLOAD_CRITICAL;
    cert.isac_enc = mycert.type;
    
    if(send_certreq){
        cert.isac_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	cert.isac_np = ISAKMP_NEXT_v2CERTREQ;	
    }
    else {
	cert.isac_np = np;
	/*
	 * If we have a remote id configured in the conn,
	 * we can send it here to signal we insist on it.
	 * if (st->st_connection->spd.that.id)
	 *   cert.isaa_np = ISAKMP_NEXT_v2IDr;
	 */

    }
    
    {
	/*   send own (Initiator CERT)  next payload is CERTREQ */
	pb_stream cert_pbs;
	struct isakmp_cert cert_hd;
	cert_hd.isacert_type = mycert.type;
	
        DBG_log("I am sending my cert");

        if (!out_struct(&cert
                        , &ikev2_certificate_desc
                        , outpbs //AA check this was md
                        , &cert_pbs))
            return STF_INTERNAL_ERROR;
	
        if(mycert.forced) {
	    if (!out_chunk(mycert.u.blob, &cert_pbs, "forced CERT"))
		return STF_INTERNAL_ERROR;
        } else {
	    if (!out_chunk(get_mycert(mycert), &cert_pbs, "CERT"))
		return STF_INTERNAL_ERROR;
        }
        close_output_pbs(&cert_pbs);
    }

#if 0
// TODO 
    if(send_certreq) { 
	/* send CERTREQ  */
	// struct ikev2_certreq certreq;
    }
    
    {
	struct ikev2_id idr;
	/* send IDr */
	idr.isai_np = np;	
    }
#endif

    return STF_OK;
}

bool
doi_send_ikev2_cert_thinking( struct state *st)

/* just for ref copy from ikev1_main.c 
 doi_log_cert_thinking(md , st->st_oakley.auth
			  , mycert.type
			  , st->st_connection->spd.this.sendcert
			  , st->hidden_variables.st_got_certrequest 
			  , send_cert);

static void 
doi_log_cert_thinking(struct msg_digest *md UNUSED
		      , u_int16_t auth
		      , enum ipsec_cert_type certtype
		      , enum certpolicy policy
		      , bool gotcertrequest
		      , bool send_cert)


*/
{
   
    cert_t mycert = st->st_connection->spd.this.cert;
    enum ipsec_cert_type certtype = mycert.type;
    enum certpolicy policy = st->st_connection->spd.this.sendcert;
    bool gotcertrequest = st->hidden_variables.st_got_certrequest;
    bool send_cert	 = FALSE;

    struct connection *c  = st->st_connection;
    
    /* decide to send_cert or not */
    send_cert = (c->policy & POLICY_RSASIG)
	&& mycert.type != CERT_NONE
	&& ((st->st_connection->spd.this.sendcert == cert_sendifasked
	     && st->hidden_variables.st_got_certrequest)
	    || st->st_connection->spd.this.sendcert==cert_alwayssend
	    || st->st_connection->spd.this.sendcert==cert_forcedtype);
   
    /* log the steps led to the decision */

    DBG(DBG_CONTROL
	, DBG_log("IKEv2 thinking about whether to send my certificate:"));

    DBG(DBG_CONTROL
   	, DBG_log("My policy is : %s", prettypolicy(c->policy)));

    DBG(DBG_CONTROL
	, DBG_log("  sendcert: %s and I did%s get a certificate request "
		  , enum_show(&certpolicy_type_names, policy)
		  , gotcertrequest ? "" : " not"));

    DBG(DBG_CONTROL
	, DBG_log("  so %ssend cert.", send_cert ? "" : "do not "));

    if(!send_cert) {
	if(!(c->policy & POLICY_RSASIG))
	    { DBG(DBG_CONTROL, DBG_log("I did not send a certificate because digital signatures are not being used. (PSK)"));
	} else if(certtype == CERT_NONE) {
	    DBG(DBG_CONTROL, DBG_log("I did not send a certificate because I do not have one."));
	} else if(policy == cert_sendifasked) {
	    DBG(DBG_CONTROL, DBG_log("I did not send my certificate because I was not asked to."));
	}
    }     
  
    return send_cert;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
