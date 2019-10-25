/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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

#include "oswalloc.h"
#include "constants.h"
#include "id.h"
#include "openswan/ipsec_policy.h"
#include "sha2.h"
#include "secrets.h"
#include "oswlog.h"

enum myid_state myid_state = MYID_UNKNOWN;
struct id myids[MYID_SPECIFIED+1];	/* %myid */

const struct id *resolve_myid(const struct id *id)
{
  if((id)->kind == ID_MYID) {
    return &myids[myid_state];
  } else {
    return (id);
  }
}


void calc_ckaid(char *ckaid_print_buf, size_t ckaid_print_buf_len
                , const unsigned char *key, const unsigned int keylen)
{
    unsigned char key_ckaid[CKAID_BUFSIZE];

    /* maybe #ifdef SHA2 ? */
    /* calculate the hash of the public key, using SHA-2 */
    sha256_hash_buffer(key, keylen, key_ckaid, sizeof(key_ckaid));

    datatot(key_ckaid, sizeof(key_ckaid), 'G',
            ckaid_print_buf, ckaid_print_buf_len);
}

void log_ckaid(const char *fmt, const unsigned char *key, unsigned int keylen)
{
    char ckaid_print_buf[CKAID_PRINT_BUF_LEN];

    calc_ckaid(ckaid_print_buf, sizeof(ckaid_print_buf), key, keylen);
    DBG_log(fmt, ckaid_print_buf);
}


