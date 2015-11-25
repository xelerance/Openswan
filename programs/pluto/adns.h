/* Pluto Asynchronous DNS Helper Program's Header
 * Copyright (C) 2002  D. Hugh Redelmeier.
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

#ifndef _ADNS_H
#define _ADNS_H

#include <resolv.h>
#include <netdb.h>

/* The interface in RHL6.x and BIND distribution 8.2.2 are different,
 * so we build some of our own :-(
 */

# ifndef NS_MAXDNAME
#   define NS_MAXDNAME 1025
# endif

# ifndef NS_PACKETSZ
#   define NS_PACKETSZ 512
# endif

/* protocol version */

#define ADNS_Q_MAGIC (((((('d' << 8) + 'n') << 8) + 's') << 8) + 4)
#define ADNS_A_MAGIC (((((('d' << 8) + 'n') << 8) + 's') << 8) + 128 + 4)

/* note: both struct adns_query and struct adns_answer must start with
 * size_t len;
 */

struct adns_query {
    size_t len;
    unsigned int qmagic;
    unsigned long serial;
    sa_family_t addr_family;
    lset_t debugging;	/* only used #ifdef DEBUG, but don't want layout to change */
    char name_buf[NS_MAXDNAME + 2];
    int type;	                   /* T_KEY or T_TXT or T_A (also AAAA) */
};

#define ADNS_ANS_SIZE NS_PACKETSZ * 10
struct adns_answer {
    size_t len;
    unsigned int amagic;
    unsigned long serial;
    struct adns_continuation *continuation;
    int result;
    int h_errno_val;
    u_char ans[ADNS_ANS_SIZE];   /* very probably bigger than necessary */
};

enum helper_exit_status {
    HES_CONTINUE = -1,	/* not an exit */
    HES_OK = 0,	/* all's well that ends well (perhaps EOF) */
    HES_INVOCATION,	/* improper invocation */
    HES_IO_ERROR_SELECT,	/* IO error in select() */
    HES_MALLOC,	/* malloc failed */
    HES_IO_ERROR_IN,	/* error reading pipe */
    HES_IO_ERROR_OUT,	/* error reading pipe */
    HES_PIPE,	/* pipe(2) failed */
    HES_SYNC,	/* answer from worker doesn't match query */
    HES_FORK,	/* fork(2) failed */
    HES_RES_INIT,	/* resolver initialization failed */
    HES_BAD_LEN,	/* implausible .len field */
    HES_BAD_MAGIC,	/* .magic field wrong */
};

/* used in unit testing */
extern int serialize_addr_info(struct addrinfo *result
                               , u_char *ansbuf
                               , int     ansbuf_len);
/* used in unit testing and dnskey.c */
extern struct addrinfo *deserialize_addr_info(u_char *ansbuf
                                              , int     ansbuf_len);

extern void osw_freeaddrinfo(struct addrinfo *ai);

extern int adns_main(bool debugval);
#endif /* _ADNS_H */
