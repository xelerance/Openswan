/* misc. universal things
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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
 * RCSID $Id: defs.h,v 1.36 2004/05/27 00:39:59 mcr Exp $
 */

#include "oswalloc.h"

#ifdef KLIPS
# define USED_BY_KLIPS	/* ignore */
#else
# define USED_BY_KLIPS	UNUSED
#endif

#ifdef DEBUG
# define USED_BY_DEBUG	/* ignore */
#else
# define USED_BY_DEBUG	UNUSED
#endif

#ifdef SMARTCARD
# define USED_BY_SMARTCARD /* ignore */
#else
# define USED_BY_SMARTCARD UNUSED
#endif

/* type of serial number of a state object
 * Needed in connections.h and state.h; here to simplify dependencies.
 */
typedef unsigned long so_serial_t;
#define SOS_NOBODY	0	/* null serial number */
#define SOS_FIRST	1	/* first normal serial number */

/* display a date either in local or UTC time */
extern char* timetoa(const time_t *time, bool utc, char *buf, size_t blen);

/* warns a predefined interval before expiry */
extern const char* check_expiry(time_t expiration_date,
    int warning_interval, bool strict);

#define MAX_PROMPT_PASS_TRIALS	5
#define PROMPT_PASS_LEN		64

/* struct used to prompt for a secret passphrase
 * from a console with file descriptor fd
 */
typedef struct {
    char secret[PROMPT_PASS_LEN];
    bool prompt;
    int fd;
} prompt_pass_t;

/* no time defined in time_t */
#define UNDEFINED_TIME	0

/* size of timetoa string buffer */
#define TIMETOA_BUF	30

/* filter eliminating the directory entries '.' and '..' */
typedef struct dirent dirent_t;
extern int file_select(const dirent_t *entry);

/* cleanly exit Pluto */

extern void exit_pluto(int /*status*/) NEVER_RETURNS;


/* zero all bytes */
#define zero(x) memset((x), '\0', sizeof(*(x)))

/* are all bytes 0? */
extern bool all_zero(const unsigned char *m, size_t len);


/* some MP utilities */

#include <gmp.h>

extern void n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen);
extern chunk_t mpz_to_n(const MP_INT *mp, size_t bytes);

/* var := mod(base ** exp, mod), ensuring var is mpz_inited */
#define mpz_init_powm(flag, var, base, exp, mod) { \
    if (!(flag)) \
	mpz_init(&(var)); \
    (flag) = TRUE; \
    mpz_powm(&(var), &(base), &(exp), (mod)); \
    }


/* pad_up(n, m) is the amount to add to n to make it a multiple of m */
#define pad_up(n, m) (((m) - 1) - (((n) + (m) - 1) % (m)))
