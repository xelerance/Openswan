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
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifndef HOST_NAME_MAX	/* POSIX 1003.1-2001 says <unistd.h> defines this */
# define HOST_NAME_MAX	255 /* upper bound, according to SUSv2 */
#endif

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "openswan/passert.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"

/*  Note that there may be as many as six IDs that are temporary at
 *  one time before unsharing the two ends of a connection. So we need
 *  at least six temporary buffers for DER_ASN1_DN IDs.
 *  We rotate them. Be careful!
 */
#define	MAX_BUF		6

unsigned char*
temporary_cyclic_buffer(void)
{
    static unsigned char buf[MAX_BUF][IDTOA_BUF]; /*MAX_BUF internal buffers */
    static int counter = 0;			/* cyclic counter */

    if (++counter == MAX_BUF) counter = 0;	/* next internal buffer */
    return buf[counter];			/* assign temporary buffer */
}

/* Convert textual form of id into a (temporary) struct id.
 * Note that if the id is to be kept, unshare_id_content will be necessary.
 */
err_t
atoid(char *src, struct id *id, bool myid_ok)
{
    err_t ugh = NULL;

    *id = empty_id;

    if (myid_ok && streq("%myid", src))
    {
	id->kind = ID_MYID;
    }
    else if (streq("%fromcert", src))
    {
	id->kind = ID_FROMCERT;
    }
    else if (streq("%none", src))
    {
	id->kind = ID_NONE;
    }
    else if (strchr(src, '=') != NULL)
    {
	/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN */
	id->kind = ID_DER_ASN1_DN;
	id->name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
	id->name.len = 0;
	/* convert from LDAP style or openssl x509 -subject style to ASN.1 DN
	 * discard optional @ character in front of DN
	 */
	ugh = atodn((*src == '@')?src+1:src, &id->name);
    }
    else if (strchr(src, '@') == NULL)
    {
	if (streq(src, "%any") || streq(src, "0.0.0.0"))
	{
	    /* any ID will be accepted */
	    id->kind = ID_NONE;
	}
	else
	{
	   /* !!! this test is not sufficient for distinguishing address families.
	    * We need a notation to specify that a FQDN is to be resolved to IPv6.
	    */
	   const struct af_info *afi = strchr(src, ':') == NULL
	? &af_inet4_info: &af_inet6_info;

	   id->kind = afi->id_addr;
	   ugh = ttoaddr(src, 0, afi->af, &id->ip_addr);
	}
    }
    else
    {
	if (*src == '@')
	{
	    if (*(src+1) == '#')
	    {
		/* if there is a second specifier (#) on the line
		 * we interprete this as ID_KEY_ID
		 */
		id->kind = ID_KEY_ID;
		id->name.ptr = (unsigned char *)src;
		/* discard @~, convert from hex to bin */
		ugh = ttodata(src+2, 0, 16, (char *)id->name.ptr
			      , strlen(src), &id->name.len);
	    }
	    else if (*(src+1) == '~')
	    {
		/* if there is a second specifier (~) on the line
		* we interprete this as a binary ID_DER_ASN1_DN
		*/
		id->kind = ID_DER_ASN1_DN;
		id->name.ptr = (unsigned char *)src;
		/* discard @~, convert from hex to bin */
		ugh = ttodata(src+2, 0, 16, (char *)id->name.ptr
			      , strlen(src), &id->name.len);
	    }
	    else if (*(src+1) == '[')
	    {
		/* if there is a second specifier ([) on the line
		 * we interprete this as a text ID_KEY_ID, and we remove
		 * a trailing ", if there is one.
		 */
		int len = strlen(src+2);

		id->kind = ID_KEY_ID;
		id->name.ptr = (unsigned char *)src+2;

                /* Start of name.ptr is srv+2 so len is 2 smaller than the
                 * length of src and the terminator character is at
                 * src[len+2].  Therefore, the last character is src[len+1]
                 */
		if(src[len+1]==']')
		{
		    src[len+1]='\0';
		    len--;
		}
		id->name.len = len;
	    }
	    else
	    {
		id->kind = ID_FQDN;
		id->name.ptr = (unsigned char *)src+1;	/* discard @ */
		id->name.len = strlen(src)-1;
	    }
	}
	else
	{
	    /* We leave in @, as per DOI 4.6.2.4
	     * (but DNS wants . instead).
	     */
	    id->kind = ID_USER_FQDN;
	    id->name.ptr = (unsigned char *)src;
	    id->name.len = strlen(src);
	}
    }
    return ugh;
}


/*
 *  Converts a binary key ID into hexadecimal format
 */
static int
keyidtoa(char *dst, size_t dstlen, chunk_t keyid)
{
    int n = datatot(keyid.ptr, keyid.len, 'x', dst, dstlen);
    return ((n < (int)dstlen)? n : (int)dstlen) - 1;
}

void
iptoid(const ip_address *ip, struct id *id)
{
    *id = empty_id;

    switch (addrtypeof(ip))
    {
    case AF_INET:
	id->kind = ID_IPV4_ADDR;
	break;
    case AF_INET6:
	id->kind = ID_IPV6_ADDR;
	break;
    default:
	bad_case(addrtypeof(ip));
    }
    id->ip_addr = *ip;
}

int
idtoa(const struct id *id, char *dst, size_t dstlen)
{
    int n;

    id = resolve_myid(id);
    switch (id->kind)
    {
    case ID_MYID:
	n = snprintf(dst, dstlen, "%s", "%myid");
	break;
    case ID_FROMCERT:
	n = snprintf(dst, dstlen, "%s", "%fromcert");
	break;
    case ID_NONE:
	n = snprintf(dst, dstlen, "%s", "(none)");
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	if(isanyaddr(&id->ip_addr)) {
	    dst[0]='\0';
	    strncat(dst, "%any", dstlen);
	    n = strlen(dst);
	} else {
	    n = (int)addrtot(&id->ip_addr, 0, dst, dstlen) - 1;
	}
	break;
    case ID_FQDN:
	n = snprintf(dst, dstlen, "@%.*s", (int)id->name.len, id->name.ptr);
	break;
    case ID_USER_FQDN:
	n = snprintf(dst, dstlen, "%.*s", (int)id->name.len, id->name.ptr);
	break;
    case ID_DER_ASN1_DN:
	n = dntoa(dst, dstlen, id->name);
	break;
    case ID_KEY_ID:
	passert(dstlen > 4);
	dst[0]='@';
	dst[1]='#';
	dstlen-=2; dst+=2;
	n = keyidtoa(dst, dstlen, id->name);
	n+= 2;
	break;
    default:
	n = snprintf(dst, dstlen, "unknown id kind %d", id->kind);
	break;
    }

    /* "Sanitize" string so that log isn't endangered:
     * replace unprintable characters with '?'.
     */
    if (n > 0)
    {
	for ( ; *dst != '\0'; dst++)
	    if (!isprint(*dst))
		*dst = '?';
    }

    return n;
}

/* Replace the shell metacharacters ', \, ", `, and $ in a character string
 * by escape sequences consisting of their octal values
 */
void
escape_metachar(const char *src, char *dst, size_t dstlen)
{
    while (*src != '\0' && dstlen > 4)
    {
	switch (*src)
	{
	case '\'':
	case '\\':
	case '"':
	case '`':
	case '$':
	    sprintf(dst,"\\%s%o", (*src < 64)?"0":"", *src);
	    dst += 4;
	    dstlen -= 4;
	    break;
	default:
	    *dst++ = *src;
	    dstlen--;
	}
	src++;
    }
    *dst = '\0';
}

/*
 * Remove all shell metacharacters ', \, ", `, and $ in a character string
 */
void
remove_metachar(const unsigned char *src, char *dst, size_t dstlen)
{
    bool changed = FALSE;

    passert(dstlen >= 1);
    while (*src != '\0' && dstlen > 1)
    {
	if((*src >= '0' && *src <= '9')
	   || (*src >= 'a' && *src <= 'z')
	   || (*src >= 'A' && *src <= 'Z')
	   || *src == '_')
	{
	    *dst++ = *src;
	    dstlen--;
	}
	else
	{
	    changed = TRUE;
	}
	src++;
    }
    *dst = '\0';
    if (changed)
	openswan_log("Warning: XAUTH username changed from '%s' to '%s'",src,dst);
}


/* Make private copy of string in struct id.
 * This is needed if the result of atoid is to be kept.
 */
void
unshare_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	id->name.ptr = clone_bytes(id->name.ptr, id->name.len, "keep id name");
	/* Somehow assert we have a valid id here? */
	break;
    case ID_MYID:
    case ID_FROMCERT:
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	bad_case(id->kind);
    }
}

void
free_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	freeanychunk(id->name);
	break;
    case ID_MYID:
    case ID_FROMCERT:
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	bad_case(id->kind);
    }
}

/* is this a "match anything" id */
bool
any_id(const struct id *a)
{
    a = resolve_myid(a);

    switch (a->kind)
    {
    case ID_NONE:
	return TRUE;	/* wildcard */

    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
		return isanyaddr(&a->ip_addr);

    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
		return FALSE;

    default:
	bad_case(a->kind);
    }
    /* NOTREACHED */
    return FALSE;
}

/* compare two struct id values */
bool
same_id(const struct id *a, const struct id *b)
{
    a = resolve_myid(a);
    b = resolve_myid(b);

    if(b->kind == ID_NONE || a->kind==ID_NONE) {
	return TRUE;    /* it's the wildcard */
    }

    if (a->kind != b->kind)
	return FALSE;

    switch (a->kind)
    {
    case ID_NONE:
	return TRUE;	/* repeat of above for completeness */

    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	return sameaddr(&a->ip_addr, &b->ip_addr);

    case ID_FQDN:
    case ID_USER_FQDN:
	/* assumptions:
	 * - case should be ignored
	 * - trailing "." should be ignored (even if the only character?)
	 */
	{
	    size_t al = a->name.len
		, bl = b->name.len;

	    while (al > 0 && a->name.ptr[al - 1] == '.')
		al--;
	    while (bl > 0 && b->name.ptr[bl - 1] == '.')
		bl--;
	    return al == bl
		&& strncasecmp((char *)a->name.ptr
			       , (char *)b->name.ptr, al) == 0;
	}

    case ID_DER_ASN1_DN:
	return same_dn(a->name, b->name);

    case ID_KEY_ID:
	return a->name.len == b->name.len
	    && memcmp(a->name.ptr, b->name.ptr, a->name.len) == 0;

    default:
	bad_case(a->kind);
    }
    /* NOTREACHED */
    return FALSE;
}

/* compare two struct id values, DNs can contain wildcards */
bool
match_id(const struct id *a, const struct id *b, int *wildcards)
{

    bool match;

    if (b->kind == ID_NONE)
    {
	*wildcards = MAX_WILDCARDS;
	match = TRUE;
	goto done;
    }

    if (a->kind != b->kind) {
	match = FALSE;
	goto done;
    }

    if (a->kind == ID_DER_ASN1_DN) {
	match = match_dn(a->name, b->name, wildcards);
    }
    else
    {
	*wildcards = 0;
	match = same_id(a, b);
    }

 done:
    DBG(DBG_CONTROLMORE,
	{
	    char abuf[IDTOA_BUF];
	    char bbuf[IDTOA_BUF];

	    idtoa(a, abuf, IDTOA_BUF);
	    idtoa(b, bbuf, IDTOA_BUF);
	    DBG_log("   match_id a=%s", abuf);
	    DBG_log("            b=%s", bbuf);
	    DBG_log("   results  %s", match ? "matched" : "fail");
	}
	);

    return match;
}

/* count the numer of wildcards in an id */
int
id_count_wildcards(const struct id *id)
{
    int count;
    char idbuf[IDTOA_BUF];

    count = 0;

    switch (id->kind)
    {
    case ID_NONE:
	count = MAX_WILDCARDS;
	break;
    case ID_DER_ASN1_DN:
	count = dn_count_wildcards(id->name);
	break;
    default:
	count = 0;
	break;
    }

    idtoa(id, idbuf, IDTOA_BUF);
    DBG(DBG_CONTROL,
	DBG_log("counting wild cards for %s is %d"
		, idbuf
		, count));

    return count;
}

/* ip_str: a simple to use variant of addrtot.
 * It stores its result in a static buffer.
 * This means that newer calls overwrite the storage of older calls.
 * Note: this is not used in any of the logging functions, so their
 * callers may use it. (this is here for unit testing)
 */
const char *pluto_ip_str(const ip_address *src)
{
    static char buf[ADDRTOT_BUF];

    addrtot(src, 0, buf, sizeof(buf));
    return buf;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
