/* IKEv1 assymetric crypto routines for use with NSS.
 *
 * Copyright (C) 2001-2015 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2008 Ilia Sotnikov
 * Copyright (C) 2009 Seong-hun Lim
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 *
 * (I figure the above people had something to do with NSS code)
 */
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>		/* for gettimeofday */
#include <gmp.h>
#include <resolv.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "pluto/state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "pluto/connections.h"	/* needs id.h */
#include "hostpair.h"
#include "pluto/keys.h"
#include "keys.h"
#include "packet.h"
#include "demux.h"	/* needs packet.h */
#include "adns.h"	/* needs <resolv.h> */
#include "dnskey.h"	/* needs keys.h and adns.h */
#include "kernel.h"	/* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "pluto/server.h"
#include "pluto/spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "pkcs.h"
#include "plutoalg.h"
#include "pluto_crypt.h"
#include "ike_alg.h"
#include "oswcrypto.h"
#include "ikev1.h"

/*
 * replaces try_RSA_signature_v1()
 *
 * Check a Main Mode RSA Signature against computed hash using
 * RSA public key k, using NSS.
 *
 * As a side effect, on success, the public key is copied into the
 * state object to record the authenticator.
 *
 * Can fail because wrong public key is used or because hash disagrees.
 * We distinguish because diagnostics should also.
 *
 * The result is NULL if the Signature checked out.
 * Otherwise, the first character of the result indicates
 * how far along failure occurred.  A greater character signifies
 * greater progress.
 *
 * Classes:
 * 0	reserved for caller
 * 1	SIG length doesn't match key length -- wrong key
 * 2-8	malformed ECB after decryption -- probably wrong key
 * 9	decrypted hash != computed hash -- probably correct key
 * 10   NSS error
 * 11   NSS error
 * 12   NSS error
 *
 * Although the math should be the same for generating and checking signatures,
 * it is not: the knowledge of the private key allows more efficient (i.e.
 * different) computation for encryption.
 */
err_t
try_RSA_signature_v1(const u_char hash_val[MAX_DIGEST_LEN], size_t hash_len
                         , const pb_stream *sig_pbs, struct pubkey *kr
                         , struct state *st)
{
    const u_char *sig_val = sig_pbs->cur;
    size_t sig_len = pbs_left(sig_pbs);
    const struct RSA_public_key *k = &kr->u.rsa;

    /* decrypt the signature -- reversing RSA_sign_hash */
    if (sig_len != k->k)
    {
	/* XXX notification: INVALID_KEY_INFORMATION */
	return "1" "SIG length does not match public key length";
    }

    err_t ugh = RSA_signature_verify_nss (k,hash_val,hash_len,sig_val,sig_len);
    if(ugh!=NULL) {
	return ugh;
    }

    /* Success: copy successful key into state.
     * There might be an old one if we previously aborted this
     * state transition.
     */
    unreference_key(&st->st_peer_pubkey);
    st->st_peer_pubkey = reference_key(kr);

    return NULL;    /* happy happy */
}
