/* do X.509 operations for IKEv2
 *
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
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
#include "x509more.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "pluto/state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "pluto/server.h"
#include "vendor.h"
#include "dpd.h"
#include "keys.h"
#include "ipsec_doi.h"

/* figure out if we should request a cert for the peer */
bool
doi_send_ikev2_certreq_thinking(struct state *st, enum phase1_role role UNUSED)
{
    bool send_certreq = FALSE;
    bool unknown = TRUE;
    struct connection *c  = st->st_connection;

    /* decide the next payload;
     * send a CERTREQ no preloaded public key exists
     */
    send_certreq = (c->policy & POLICY_RSASIG)
        && !has_preloaded_public_key(st)
        && !st->hidden_variables.st_got_cert_from_peer
        && (st->st_connection->spd.that.ca.ptr != NULL)
	&& x509_get_authcerts_chain();

    DBG(DBG_CONTROL
        , DBG_log("Thinking about sending a certificate request (CERTREQ)");
        DBG_log("  my policy is : %s", prettypolicy(c->policy));
        DBG_log("  my next payload will %sbe a certificate request"
                , send_certreq ? "" : "not "));

    if (send_certreq)
        return TRUE;

    /* report why we are not sending a certreq */

    DBG(DBG_CONTROL
        ,DBG_log("I did not send a certificate request (CERTREQ) because"));
    if(!(c->policy & POLICY_RSASIG)) {
        DBG(DBG_CONTROL
            ,DBG_log("  RSA digital signatures are not being used. (PSK)"));
        unknown = FALSE;
    }
    if(has_preloaded_public_key(st)) {
        DBG(DBG_CONTROL
            , DBG_log(" has a preloaded a public for that end in st"));
        unknown = FALSE;
    }
    if(st->hidden_variables.st_got_cert_from_peer) {
        DBG(DBG_CONTROL
            , DBG_log("  already received a CERT from peer"));
        unknown = FALSE;
    }
    if(!(st->st_connection->spd.that.ca.ptr != NULL)) {
        DBG(DBG_CONTROL
            , DBG_log("  no known CA for the other end"));
        unknown = FALSE;
    }
    if(!(x509_get_authcerts_chain())) {
        DBG(DBG_CONTROL
            , DBG_log("  no CA certs available for validation"));
        unknown = FALSE;
    }

    /* no reason we are aware of */

    if (unknown) {
        DBG(DBG_CONTROL,
            DBG_log(" we reached an unexpected state - a bad day? "
                    "I don't feel like sending a certificate request (CERTREQ)"));
    }

    return FALSE;
}


/* Send v2CERT and v2 CERT */
stf_status
ikev2_send_cert( struct state *st, struct msg_digest *md
		, enum phase1_role role
		, unsigned int np, pb_stream *outpbs)
{
    stf_status stf;
    struct ikev2_cert cert;

    /*  flag : to send a certificate request aka CERTREQ */
    bool send_certreq = doi_send_ikev2_certreq_thinking(st, role);

    cert_t mycert = st->st_connection->spd.this.cert;

    cert.isac_critical = ISAKMP_PAYLOAD_NONCRITICAL;
    if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
        openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
        cert.isac_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
    }

    cert.isac_enc = mycert.type;

    if(send_certreq){
        cert.isac_critical = ISAKMP_PAYLOAD_NONCRITICAL;
        if(DBGP(IMPAIR_SEND_BOGUS_ISAKMP_FLAG)) {
            openswan_log(" setting bogus ISAKMP_PAYLOAD_OPENSWAN_BOGUS flag in ISAKMP payload");
            cert.isac_critical |= ISAKMP_PAYLOAD_OPENSWAN_BOGUS;
        }
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

    /*   send own (Initiator CERT) */
    {
	pb_stream cert_pbs;

        DBG_log("I am sending my certificate");

        pbs_set_np(outpbs, ISAKMP_NEXT_v2CERT);
        if (!out_struct(&cert, &ikev2_certificate_desc
                        , outpbs , &cert_pbs))
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

    /* send CERTREQ  */
    if(send_certreq) {
	DBG(DBG_CONTROL
	    , DBG_log("going to send a certreq"));
	stf = ikev2_send_certreq(st, md, role, np, outpbs);
	if (stf != STF_OK) {
            DBG(DBG_CONTROL
                , DBG_log("sending CERTREQ failed with %s",
                          stf_status_name(stf)));
            return stf;
        }
    }
    return STF_OK;
}

stf_status
ikev2_send_certreq( struct state *st, struct msg_digest *md UNUSED
		    , enum phase1_role role UNUSED
		    , unsigned int np, pb_stream *outpbs)
{
    struct end *that = &st->st_connection->spd.that;
    chunk_t *that_ca = &that->ca;
    const x509cert_t *cacert;
    chunk_t allCAs = { NULL, 0 };
    size_t newlen;
    unsigned CAcnt = 0;
    bool success;

    /* if there is a "rightcert=..." then I send CERTREQ with that cert's Authority keyid */

    if (that->cert_filename && that->cert.type == CERT_X509_SIGNATURE) {
        if (that->cert.u.x509->authKeyID.ptr) {
            DBG(DBG_CONTROL,
                DBG_log("have cert '%s', send CERTREQ with Auth Key ID",
                        that->cert_filename));


            pbs_set_np(outpbs, ISAKMP_NEXT_v2CERTREQ);
            if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
                                         that->cert.u.x509->authKeyID,
                                         outpbs, np))
                return STF_INTERNAL_ERROR;

            return STF_OK;

        } else {
            DBG(DBG_CONTROL,
                DBG_log("have cert '%s' without Auth Key ID, will use CA by name",
                        that->cert_filename));
            that_ca = &st->st_connection->spd.that.ca;
        }
    }

    /* if there is a "rightca=..." then I send CERTREQ with the CA's keyid */

    if (that_ca->ptr) {
        cacert = get_authcert(*that_ca, empty_chunk, empty_chunk, AUTH_CA);
        if (cacert) {
            char buf[256];
            dntoa(buf, sizeof(buf), cacert->subject);
            DBG(DBG_CONTROL,
                DBG_log("have CA '%s', send CERTREQ with CA's Key ID", buf));

            pbs_set_np(outpbs, ISAKMP_NEXT_v2CERTREQ);
            if (!ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
                                         cacert->subjectKeyID,
                                         outpbs, np))
                return STF_INTERNAL_ERROR;

            return STF_OK;
        }
    }

    /* if neither is given then I send CERTREQ with the keyid(s) of all known CA's (/etc/ipsec.d/cacerts/...) */

    for(cacert = x509_get_authcerts_chain(); cacert; cacert = cacert->next) {

        if (!cacert->authority_flags & AUTH_CA)
            continue;

        newlen = allCAs.len + cacert->subjectKeyID.len;

        allCAs.ptr = realloc(allCAs.ptr, newlen);

        memcpy(allCAs.ptr + allCAs.len, cacert->subjectKeyID.ptr,
               cacert->subjectKeyID.len);

        allCAs.len = newlen;

        CAcnt ++;
    }

    DBG(DBG_CONTROL,
        DBG_log("send CERTREQ with all %d known CA's KeyID", CAcnt));

    pbs_set_np(outpbs, ISAKMP_NEXT_v2CERTREQ);
    success = ikev2_build_and_ship_CR(CERT_X509_SIGNATURE,
                                         allCAs,
                                         outpbs, np);

    if (allCAs.ptr) {
        free(allCAs.ptr);
        allCAs.ptr = NULL;
    }

    if (!success)
        return STF_INTERNAL_ERROR;

    return STF_OK;
}

/* just for ref copy from ikev1_main.c

     doi_log_cert_thinking(md , st->st_oakley.auth
			  , mycert.type
			  , st->st_connection->spd.this.sendcert
			  , st->hidden_variables.st_got_certrequest
			  , send_cert);

     doi_log_cert_thinking(struct msg_digest *md UNUSED
	  	      , u_int16_t auth
		      , enum ipsec_cert_type certtype
		      , enum certpolicy policy
		      , bool gotcertrequest
		      , bool send_cert)
*/

bool
doi_send_ikev2_cert_thinking(struct state *st)
{
    cert_t mycert = st->st_connection->spd.this.cert;
    enum ipsec_cert_type certtype = mycert.type;
    enum certpolicy certpolicy = st->st_connection->spd.this.sendcert;
    bool send_cert	 = FALSE;

    struct connection *c  = st->st_connection;

    /* decide to send_cert or not */
    send_cert = (c->policy & POLICY_RSASIG)
        && mycert.type != CERT_NONE
        && ((certpolicy == cert_sendifasked
             && st->hidden_variables.st_got_certrequest)
            || certpolicy==cert_alwayssend
            || certpolicy==cert_forcedtype);

    /* log the steps led to the decision */

    DBG(DBG_CONTROL
	, DBG_log("IKEv2 thinking whether to send my certificate:"));

    DBG(DBG_CONTROL
   	, DBG_log(" my policy has %s RSASIG, the policy is : %s",
		     (c->policy & POLICY_RSASIG) ? "" : "no",
		     prettypolicy(c->policy)));

    DBG(DBG_CONTROL,
	bool gotcertrequest = st->hidden_variables.st_got_certrequest;
	DBG_log(" sendcert: %s and I did%s get a certificate request "
		  , enum_show(&certpolicy_type_names, certpolicy)
		  , gotcertrequest ? "" : " not")
       );

    DBG(DBG_CONTROL, DBG_log(" so %ssend cert.", send_cert ? "" : "do not "));

    if(!send_cert) {
	if(!(c->policy & POLICY_RSASIG))
	    { DBG(DBG_CONTROL, DBG_log("I did not send a certificate because digital signatures are not being used. (PSK)"));
	} else if(certtype == CERT_NONE) {
	    DBG(DBG_CONTROL, DBG_log("I did not send a certificate because I do not have one."));
	} else if(certpolicy == cert_sendifasked) {
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
