/* Support of X.509 keys
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2004-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2006 Matthias Haas" <mh@pompase.net>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"
#include "oswconf.h"

#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "pluto/connections.h"
#include "hostpair.h"
#include "pluto/state.h"
#include "whack.h"
#include "fetch.h"
#include "ocsp.h"
#include "pkcs.h"
#include "kernel.h"
#include "x509more.h"
#include "oswkeys.h"
/*
 * Decode the CERT payload of Phase 1.
 */
void
decode_cert(struct msg_digest *md)
{
    struct payload_digest *p;
    const struct osw_conf_options *oco = osw_init_options();

    for (p = md->chain[ISAKMP_NEXT_CERT]; p != NULL; p = p->next)
    {
        struct state *st = md->st;
	struct isakmp_cert *const cert = &p->payload.cert;
	chunk_t blob;
	time_t valid_until;
	blob.ptr = p->pbs.cur;
	blob.len = pbs_left(&p->pbs);
	if (cert->isacert_type == CERT_X509_SIGNATURE)
	{
	    x509cert_t cert2 = empty_x509cert;
	    if (parse_x509cert(blob, 0, &cert2))
	    {
		if (verify_x509cert(&cert2, oco->strict_crl_policy, &valid_until))
		{
		    DBG(DBG_X509 | DBG_PARSING,
			DBG_log("Public key validated")
		    )
			add_x509_public_key_to_list(&st->st_keylist, NULL, &cert2, valid_until, DAL_SIGNED, NULL);
		}
		else
		{
		    plog("X.509 certificate rejected");
		}
		free_generalNames(cert2.subjectAltName, FALSE);
		free_generalNames(cert2.crlDistributionPoints, FALSE);
	    }
	    else
		plog("Syntax error in X.509 certificate");
	}
	else if (cert->isacert_type == CERT_PKCS7_WRAPPED_X509)
	{
	    x509cert_t *cert2 = NULL;

	    if (parse_pkcs7_cert(blob, &cert2))
		store_x509certs(&cert2, oco->strict_crl_policy);
	    else
		plog("Syntax error in PKCS#7 wrapped X.509 certificates");
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "ignoring %s certificate payload",
		   enum_show(&cert_type_names, cert->isacert_type));
	    DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
	}
    }
}

/* Decode IKEV2 CERT Payload */

void
ikev2_decode_cert(struct msg_digest *md)
{
    struct payload_digest *p;
    struct state *st = md->st;
    unsigned certnum = 0;
    const struct osw_conf_options *oco = osw_init_options();

    if (st->st_clonedfrom != 0) {
        st = state_with_serialno(st->st_clonedfrom);
    }

    for (p = md->chain[ISAKMP_NEXT_v2CERT]; p != NULL; p = p->next)
    {
	struct ikev2_cert *const v2cert = &p->payload.v2cert;
	chunk_t blob;
	time_t valid_until;
	blob.ptr = p->pbs.cur;
	blob.len = pbs_left(&p->pbs);
	if (v2cert->isac_enc == CERT_X509_SIGNATURE)
	{
	    x509cert_t cert2 = empty_x509cert;
	    if (parse_x509cert(blob, 0, &cert2))
	    {
		if (verify_x509cert(&cert2, oco->strict_crl_policy, &valid_until))
		{
                    char sbuf[ASN1_BUF_LEN];
                    dntoa(sbuf, ASN1_BUF_LEN, cert2.subject);
                    openswan_log("%u: validated X509 certificate: '%s', added to trusted database"
                                 , certnum, sbuf);
		    DBG(DBG_X509 | DBG_PARSING,
			DBG_log("Public key validated")
                        );
                    /* insert it to the state's cache, not the global cache */
                    add_x509_public_key_to_list(&st->st_keylist, NULL, &cert2
                                                , valid_until, DAL_SIGNED, NULL);
		}
		else
		{
		    plog("X.509 certificate rejected");
		}
		free_generalNames(cert2.subjectAltName, FALSE);
		free_generalNames(cert2.crlDistributionPoints, FALSE);
	    }
	    else
		plog("Syntax error in X.509 certificate");
	}
	else if (v2cert->isac_enc == CERT_PKCS7_WRAPPED_X509)
	{
	    x509cert_t *cert2 = NULL;

	    if (parse_pkcs7_cert(blob, &cert2)) {
                char sbuf[ASN1_BUF_LEN];
                dntoa(sbuf, ASN1_BUF_LEN, cert2->subject);
                openswan_log("%u: validated pkcs7 certificate: '%s', added to trusted database"
                             , certnum, sbuf);
		store_x509certs(&cert2, oco->strict_crl_policy);
            }
	    else
		plog("Syntax error in PKCS#7 wrapped X.509 certificates");
	}
	else
	{
	    loglog(RC_LOG_SERIOUS, "%u: ignoring %s certificate payload"
                   , certnum
		   , enum_show(&ikev2_cert_type_names, v2cert->isac_enc));
	    DBG_cond_dump_chunk(DBG_PARSING, "CERT:\n", blob);
	}

        certnum++;
    }
}



/*
 * Decode the CR payload of Phase 1.
 */
void
ikev1_decode_cr(struct msg_digest *md, generalName_t **requested_ca_names)
{
    struct payload_digest *p;

    for (p = md->chain[ISAKMP_NEXT_CR]; p != NULL; p = p->next)
    {
	struct isakmp_cr *const cr = &p->payload.cr;
	chunk_t ca_name;

	ca_name.len = pbs_left(&p->pbs);
	ca_name.ptr = (ca_name.len > 0)? p->pbs.cur : NULL;

	DBG_cond_dump_chunk(DBG_PARSING, "CR", ca_name);

	if (cr->isacr_type == CERT_X509_SIGNATURE)
	{

	    if (ca_name.len > 0)
	    {
		generalName_t *gn;

		if (!is_asn1(ca_name))
		    continue;

		gn = alloc_thing(generalName_t, "generalName");
		clonetochunk(ca_name, ca_name.ptr,ca_name.len, "ca name");
		gn->kind = GN_DIRECTORY_NAME;
		gn->name = ca_name;
		gn->next = *requested_ca_names;
		*requested_ca_names = gn;
	    }

	    DBG(DBG_PARSING | DBG_CONTROL,
		char buf[IDTOA_BUF];
		dntoa_or_null(buf, IDTOA_BUF, ca_name, "%any");
		DBG_log("requested CA: '%s'", buf);
	    )
	}
	else
	    loglog(RC_LOG_SERIOUS, "ignoring %s certificate request payload",
		   enum_show(&cert_type_names, cr->isacr_type));
    }
}

/*
 * Decode the IKEv2 CR payload of Phase 1.
 */
void
ikev2_decode_cr(struct msg_digest *md, generalName_t **requested_ca_hashes)
{
    struct payload_digest *p;

    for (p = md->chain[ISAKMP_NEXT_v2CERTREQ]; p != NULL; p = p->next)
    {
        struct ikev2_certreq *const cr = &p->payload.v2certreq;
        chunk_t all_keys, key;
        u_char *end_keys;

        all_keys.len = pbs_left(&p->pbs);
        all_keys.ptr = (all_keys.len > 0)? p->pbs.cur : NULL;

        DBG_cond_dump_chunk(DBG_PARSING, "CR", all_keys);

        if (cr->isacertreq_enc != CERT_X509_SIGNATURE) {
            loglog(RC_LOG_SERIOUS, "ignoring %s certificate request payload",
                   enum_show(&ikev2_cert_type_names, cr->isacertreq_enc));
            DBG_log("ignoring %s certificate request payload",
                    enum_show(&ikev2_cert_type_names, cr->isacertreq_enc));
            continue;
        }

        if (!all_keys.len)
            continue;

        /* chop it up into SHA1 key IDs */

        end_keys = all_keys.ptr + all_keys.len;
        key.len = SHA1_DIGEST_SIZE;
        for (key.ptr = all_keys.ptr; key.ptr < end_keys; key.ptr += key.len) {
            size_t remaining;
            generalName_t *gn;

            remaining = end_keys - key.ptr;
            if (key.len > remaining)
                continue;

            gn = alloc_thing(generalName_t, "generalName");
            clonetochunk(gn->name, key.ptr, key.len, "ca keyid");
            /* NOTE: this is an abuse of the generalName structure since we are
             * actually storing key IDs not names, maybe a new type or a
             * completely new structure is needed */
            gn->kind = GN_OTHER_NAME;
            gn->next = *requested_ca_hashes;
            *requested_ca_hashes = gn;

            DBG(DBG_PARSING | DBG_CONTROL,
                DBG_dump_chunk("requested CA keyID", key);
            )
        }
    }
}

bool
build_and_ship_CR(u_int8_t type, chunk_t ca, pb_stream *outs, u_int8_t np)
{
    pb_stream cr_pbs;
    struct isakmp_cr cr_hd;
    cr_hd.isacr_np = np;
    cr_hd.isacr_type = type;

    /* build CR header */
    if (!out_struct(&cr_hd, &isakmp_ipsec_cert_req_desc, outs, &cr_pbs))
	return FALSE;

    if (ca.ptr != NULL)
    {
	/* build CR body containing the distinguished name of the CA */
	if (!out_chunk(ca, &cr_pbs, "CA"))
	    return FALSE;
    }
    close_output_pbs(&cr_pbs);
    return TRUE;
}

bool
ikev2_build_and_ship_CR(u_int8_t type, chunk_t keyIDs, pb_stream *outs, u_int8_t np)
{
    pb_stream cr_pbs;
    struct ikev2_certreq  cr_hd;
    cr_hd.isacertreq_critical =  ISAKMP_PAYLOAD_NONCRITICAL;
    cr_hd.isacertreq_np= np;
    cr_hd.isacertreq_enc = type;

    /* locate the CA */

    if (keyIDs.ptr == NULL) {
        DBG(DBG_X509, DBG_log("failed to send CERTREQ, no CA keyIDs specified"));
        return FALSE;
    }

    /* build CR header */
    if (!out_struct(&cr_hd, &ikev2_certificate_req_desc, outs, &cr_pbs)) {
        DBG(DBG_X509, DBG_log("failed to send CERTREQ, out_struct() failed"));
	return FALSE;
    }

    /* build CR body containing the SHA1 hashes of the CA keys */
    if (!out_chunk(keyIDs, &cr_pbs, "CA")) {
        DBG(DBG_X509, DBG_log("failed to send CERTREQ, out_chunk() failed"));
        return FALSE;
    }

    close_output_pbs(&cr_pbs);
    return TRUE;
}

bool
collect_rw_ca_candidates(struct msg_digest *md, generalName_t **top)
{
    const struct osw_conf_options *oco = osw_init_options();
    struct connection *d = find_host_connection(ANY_MATCH, &md->iface->ip_addr
                                                , oco->pluto_port500
                                                , KH_ANY
                                                ,(ip_address*)NULL, md->sender_port, LEMPTY, LEMPTY, NULL);

    for (; d != NULL; d = d->IPhp_next)
    {
	/* must be a road warrior connection */
	if (d->kind == CK_TEMPLATE && !(d->policy & POLICY_OPPO)
	&& d->spd.that.ca.ptr != NULL)
	{
	    generalName_t *gn;
	    bool new_entry = TRUE;

	    for (gn = *top; gn != NULL; gn = gn->next)
	    {
		if (same_dn(gn->name, d->spd.that.ca))
		{
		    new_entry = FALSE;
		    break;
		}
	    }
	    if (new_entry)
	    {
		gn = alloc_thing(generalName_t, "generalName");
		gn->kind = GN_DIRECTORY_NAME;
		gn->name = d->spd.that.ca;
		gn->next = *top;
		*top = gn;
	    }
	}
    }
    return *top != NULL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
