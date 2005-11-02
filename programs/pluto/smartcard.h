/* Support of smartcards and cryptotokens
 * Copyright (C) 2003 Christoph Gysin, Simon Zwahlen, Zuercher Hochschule Winterthur
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
 * RCSID $Id: smartcard.h,v 1.3 2004/06/14 01:46:03 mcr Exp $
 */

#ifndef _SMARTCARD_H
#define _SMARTCARD_H

#define SCX_TOKEN		"%smartcard"
#define SCX_DEFAULT_ID		"45"
#define SCX_DEFAULT_READER	0
#define SCX_CERT_CACHE_INTERVAL	60 /* seconds */
#define SCX_MAX_PIN_TRIALS	3

/* smartcard record */

typedef struct smartcard smartcard_t;

struct smartcard{
    smartcard_t *next;
    time_t      last_load;
    cert_t	last_cert;
    int		count;
    u_int	reader;
    char        *id;
    chunk_t	pin;
    bool	valid;
};

extern smartcard_t* scx_parse_reader_id(const char *reader_id);
extern bool scx_establish_context(u_int card_reader);
extern bool scx_load_cert(smartcard_t *sc, cert_t * cert);
extern bool scx_verify_pin(smartcard_t *sc);
extern void scx_share(smartcard_t *sc);
extern bool scx_sign_hash(smartcard_t *sc, const u_char *in, size_t inlen
    , u_char *out, size_t outlen);
extern bool scx_get_pin(smartcard_t *sc, int whackfd);
extern size_t scx_get_keylength(smartcard_t *sc);
extern smartcard_t* scx_add(smartcard_t *smartcard);
extern smartcard_t* scx_get(x509cert_t *cert);
extern void scx_release(smartcard_t *sc);
extern void scx_release_context(void);
extern void scx_free_pin(chunk_t *pin);
extern void scx_free(smartcard_t *sc);
extern void scx_list(bool utc);

#endif /* _SMARTCARD_H */
