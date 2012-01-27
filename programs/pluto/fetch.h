/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
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

extern void wake_fetch_thread(const char *who);
extern void init_crl_fetch(void);
extern void add_distribution_points(const generalName_t *newPoints
    , generalName_t **distributionPoints);
extern void add_fetch_request(chunk_t issuer, const generalName_t *gn);
extern void free_fetch_requests(void);
extern void list_distribution_points(const generalName_t *gn);
extern void list_fetch_requests(bool utc);

struct ocsp_location; /* forward declaration of ocsp_location defined in ocsp.h */

extern void init_fetch(void);
extern void free_crl_fetch(void);
extern void free_ocsp_fetch(void);
extern void add_crl_fetch_request(chunk_t issuer, const generalName_t *gn);
extern void add_ocsp_fetch_request(struct ocsp_location *location, chunk_t serialNumber);
extern void list_crl_fetch_requests(bool utc);
extern void list_ocsp_fetch_requests(bool utc);


