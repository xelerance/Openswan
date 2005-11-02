/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2000-2003 Andreas Steffen, Zuercher Hochschule Winterthur
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
 * RCSID $Id: fetch.h,v 1.2 2003/10/31 02:37:51 mcr Exp $
 */

extern void wake_fetch_thread(const char *who);
extern void init_crl_fetch(void);
extern void add_distribution_points(const generalName_t *newPoints
    , generalName_t **distributionPoints);
extern void add_fetch_request(chunk_t issuer, const generalName_t *gn);
extern void free_fetch_requests(void);
extern void list_distribution_points(const generalName_t *gn);
extern void list_fetch_requests(bool utc);

#ifdef X509_FETCH
extern void lock_crl_list(const char *who);
extern void unlock_crl_list(const char *who);
extern void lock_cacert_list(const char *who);
extern void unlock_cacert_list(const char *who);
#else
#define lock_crl_list(who) /* nothing */
#define unlock_crl_list(who) /* nothing */
#define lock_cacert_list(who) /* nothing */
#define unlock_cacert_list(who) /* nothing */
#endif
