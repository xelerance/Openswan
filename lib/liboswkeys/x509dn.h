/* Support of X.509 certificates and CRLs
 *
 * Copyright (C) 2003-2013 Michael C Richardson <mcr@xelerance.com>
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

#ifndef _X509_DN_H

/* Maximum length of ASN.1 distinquished name */
#define ASN1_BUF_LEN	      512

#define BASIC_CONSTRAINTS_CA	1
#define BASIC_CONSTRAINTS_ROOF	4

#define TIME_UTC		0
#define TIME_GENERALIZED	2
#define TIME_ROOF		4

#define GN_OBJ_OTHER_NAME	 0
#define GN_OBJ_RFC822_NAME	 2
#define GN_OBJ_DNS_NAME		 4
#define GN_OBJ_X400_ADDRESS	 6
#define GN_OBJ_DIRECTORY_NAME	 8
#define GN_OBJ_EDI_PARTY_NAME	10
#define GN_OBJ_URI		12
#define GN_OBJ_IP_ADDRESS	14
#define GN_OBJ_REGISTERED_ID	16
#define GN_OBJ_ROOF		18

extern void update_chunk(chunk_t *ch, int n);
extern err_t init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next);
extern err_t get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid, chunk_t *value
                          , asn1_t *type, bool *next);

#define _X509_DN_H
#endif
