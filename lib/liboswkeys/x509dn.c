/* Support of X.509 certificates and CRLs
 * Copyright (C) 2000 Andreas Hess, Patric Lichtsteiner, Roger Wegmann
 * Copyright (C) 2001 Marco Bertossa, Andreas Schleiss
 * Copyright (C) 2002 Mario Strasser
 * Copyright (C) 2000-2013 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2013 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
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
#include <limits.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswtime.h"
#include "mpzfuncs.h"
#include "id.h"
#include "asn1.h"
#include "oid.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "secrets.h"
#include "md5.h"
#include "sha1.h"
#ifdef USE_SHA2
# include "sha2.h"
#endif

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
# include <keyhi.h>
# include <secerr.h>
# include "oswconf.h"
#endif

/* coding of X.501 distinguished name */

typedef struct {
    const char *name;
    chunk_t oid;
    u_char type;
} x501rdn_t;


/* X.501 acronyms for well known object identifiers (OIDs) */

static u_char oid_ND[]  = {0x02, 0x82, 0x06, 0x01,
			   0x0A, 0x07, 0x14};
static u_char oid_UID[] = {0x09, 0x92, 0x26, 0x89, 0x93,
			   0xF2, 0x2C, 0x64, 0x01, 0x01};
static u_char oid_DC[]  = {0x09, 0x92, 0x26, 0x89, 0x93,
			   0xF2, 0x2C, 0x64, 0x01, 0x19};
static u_char oid_CN[]  = {0x55, 0x04, 0x03};
static u_char oid_S[]   = {0x55, 0x04, 0x04};
static u_char oid_SN[]  = {0x55, 0x04, 0x05};
static u_char oid_C[]   = {0x55, 0x04, 0x06};
static u_char oid_L[]   = {0x55, 0x04, 0x07};
static u_char oid_ST[]  = {0x55, 0x04, 0x08};
static u_char oid_O[]   = {0x55, 0x04, 0x0A};
static u_char oid_OU[]  = {0x55, 0x04, 0x0B};
static u_char oid_T[]   = {0x55, 0x04, 0x0C};
static u_char oid_D[]   = {0x55, 0x04, 0x0D};
static u_char oid_N[]   = {0x55, 0x04, 0x29};
static u_char oid_G[]   = {0x55, 0x04, 0x2A};
static u_char oid_I[]   = {0x55, 0x04, 0x2B};
static u_char oid_ID[]  = {0x55, 0x04, 0x2D};
static u_char oid_E[]   = {0x2A, 0x86, 0x48, 0x86, 0xF7,
			   0x0D, 0x01, 0x09, 0x01};
static u_char oid_UN[]  = {0x2A, 0x86, 0x48, 0x86, 0xF7,
			   0x0D, 0x01, 0x09, 0x02};
static u_char oid_TCGID[] = {0x2B, 0x06, 0x01, 0x04, 0x01, 0x89,
			     0x31, 0x01, 0x01, 0x02, 0x02, 0x4B};

static const x501rdn_t x501rdns[] = {
  {"ND"           , {oid_ND,     7}, ASN1_PRINTABLESTRING},
  {"UID"          , {oid_UID,   10}, ASN1_PRINTABLESTRING},
  {"DC"           , {oid_DC,    10}, ASN1_PRINTABLESTRING},
  {"CN"           , {oid_CN,     3}, ASN1_PRINTABLESTRING},
  {"S"            , {oid_S,      3}, ASN1_PRINTABLESTRING},
  {"SN"           , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"serialNumber" , {oid_SN,     3}, ASN1_PRINTABLESTRING},
  {"C"            , {oid_C,      3}, ASN1_PRINTABLESTRING},
  {"L"            , {oid_L,      3}, ASN1_PRINTABLESTRING},
  {"ST"           , {oid_ST,     3}, ASN1_PRINTABLESTRING},
  {"O"            , {oid_O,      3}, ASN1_PRINTABLESTRING},
  {"OU"           , {oid_OU,     3}, ASN1_PRINTABLESTRING},
  {"T"            , {oid_T,      3}, ASN1_PRINTABLESTRING},
  {"D"            , {oid_D,      3}, ASN1_PRINTABLESTRING},
  {"N"            , {oid_N,      3}, ASN1_PRINTABLESTRING},
  {"G"            , {oid_G,      3}, ASN1_PRINTABLESTRING},
  {"I"            , {oid_I,      3}, ASN1_PRINTABLESTRING},
  {"ID"           , {oid_ID,     3}, ASN1_PRINTABLESTRING},
  {"E"            , {oid_E,      9}, ASN1_IA5STRING},
  {"Email"        , {oid_E,      9}, ASN1_IA5STRING},
  {"emailAddress" , {oid_E,      9}, ASN1_IA5STRING},
  {"UN"              , {oid_UN,     9}, ASN1_IA5STRING},
  {"unstructuredName", {oid_UN,     9}, ASN1_IA5STRING},
  {"TCGID"        , {oid_TCGID, 12}, ASN1_PRINTABLESTRING}
};

#define X501_RDN_ROOF   24

static void format_chunk(chunk_t *ch, const char *format, ...) PRINTF_LIKE(2);

static void
format_chunk(chunk_t *ch, const char *format, ...)
{
    if (ch->len > 0) {
        size_t len = ch->len;
        va_list args;
        va_start(args, format);
        int ret = vsnprintf((char *)ch->ptr, len, format, args);
        va_end(args);
        if (ret < 0 || ret > len) {
            ch->ptr += len;
            ch->len = 0;
        } else {
            ch->ptr += ret;
            ch->len -= ret;
        }
    }
}


/*
 *  Pointer is set to the first RDN in a DN
 */
err_t
init_rdn(chunk_t dn, chunk_t *rdn, chunk_t *attribute, bool *next)
{
    *rdn = empty_chunk;
    *attribute = empty_chunk;

    /* a DN is a SEQUENCE OF RDNs */

    if (*dn.ptr != ASN1_SEQUENCE)
    {
	return "DN is not a SEQUENCE";
    }

    rdn->len = asn1_length(&dn);

    if (rdn->len == ASN1_INVALID_LENGTH)
       return "Invalid RDN length";

    rdn->ptr = dn.ptr;

    /* are there any RDNs ? */
    *next = rdn->len > 0;

    return NULL;
}

/*
 *  Fetches the next RDN in a DN
 */
err_t
get_next_rdn(chunk_t *rdn, chunk_t * attribute, chunk_t *oid, chunk_t *value
, asn1_t *type, bool *next)
{
    chunk_t body;

    /* initialize return values */
    *oid   = empty_chunk;
    *value = empty_chunk;

    /* if all attributes have been parsed, get next rdn */
    if (attribute->len <= 0)
    {
	/* an RDN is a SET OF attributeTypeAndValue */
	if (*rdn->ptr != ASN1_SET)
	    return "RDN is not a SET";

	attribute->len = asn1_length(rdn);

        if (attribute->len == ASN1_INVALID_LENGTH)
            return "Invalid attribute length";

	attribute->ptr = rdn->ptr;

	/* advance to start of next RDN */
	rdn->ptr += attribute->len;
	rdn->len -= attribute->len;
    }

    /* an attributeTypeAndValue is a SEQUENCE */
    if (*attribute->ptr != ASN1_SEQUENCE)
 	return "attributeTypeAndValue is not a SEQUENCE";

    /* extract the attribute body */
    body.len = asn1_length(attribute);


    if (body.len == ASN1_INVALID_LENGTH)
        return "Invalid attribute body length";


    body.ptr = attribute->ptr;

    /* advance to start of next attribute */
    attribute->ptr += body.len;
    attribute->len -= body.len;

    /* attribute type is an OID */
    if (*body.ptr != ASN1_OID)
	return "attributeType is not an OID";

    /* extract OID */
    oid->len = asn1_length(&body);

    if (oid->len == ASN1_INVALID_LENGTH)
        return "Invalid attribute OID length";


   oid->ptr = body.ptr;

    /* advance to the attribute value */
    body.ptr += oid->len;
    body.len -= oid->len;

    /* extract string type */
    *type = *body.ptr;

    /* extract string value */
    value->len = asn1_length(&body);

    if (value->len == ASN1_INVALID_LENGTH)
        return "Invalid attribute string length";

    value->ptr = body.ptr;

    /* are there any RDNs left? */
    *next = rdn->len > 0 || attribute->len > 0;

    return NULL;
}

/*
 *  Parses an ASN.1 distinguished name int its OID/value pairs
 */
static err_t
dn_parse(chunk_t dn, chunk_t *str)
{
    chunk_t rdn, oid, attribute, value;
    asn1_t type;
    int oid_code;
    bool next;
    bool first = TRUE;
    err_t ugh;

    if(dn.ptr == NULL) {
	format_chunk(str, "(empty)");
	return NULL;
    }
    ugh = init_rdn(dn, &rdn, &attribute, &next);

    if (ugh != NULL) /* a parsing error has occured */
        return ugh;

    while (next)
    {
	ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

	if (ugh != NULL) /* a parsing error has occured */
	    return ugh;

	if (first)		/* first OID/value pair */
	    first = FALSE;
	else			/* separate OID/value pair by a comma */
	    format_chunk(str, ", ");

	/* print OID */
	oid_code = known_oid(oid);
	if (oid_code == OID_UNKNOWN)	/* OID not found in list */
	    hex_str(oid, str);
	else
	    format_chunk(str, "%s", oid_names[oid_code].name);

	/* print value */
	format_chunk(str, "=%.*s", (int)value.len, value.ptr);
    }
    return NULL;
}

/*
 *  Count the number of wildcard RDNs in a distinguished name
 */
int
dn_count_wildcards(chunk_t dn)
{
    chunk_t rdn, attribute, oid, value;
    asn1_t type;
    bool next;
    int wildcards = 0;

    err_t ugh = init_rdn(dn, &rdn, &attribute, &next);

    if (ugh != NULL) /* a parsing error has occured */
        return -1;

    while (next)
    {
	ugh = get_next_rdn(&rdn, &attribute, &oid, &value, &type, &next);

	if (ugh != NULL) /* a parsing error has occured */
	    return -1;
	if (value.len == 1 && *value.ptr == '*')
	    wildcards++; /* we have found a wildcard RDN */
    }
    return wildcards;
}

/*
 * Prints a binary string in hexadecimal form
 */
void
hex_str(chunk_t bin, chunk_t *str)
{
    u_int i;
    format_chunk(str, "0x");
    for (i=0; i < bin.len; i++)
	format_chunk(str, "%02X", *bin.ptr++);
}


/*  Converts a binary DER-encoded ASN.1 distinguished name
 *  into LDAP-style human-readable ASCII format
 */
int
dntoa(char *dst, size_t dstlen, chunk_t dn)
{
    err_t ugh = NULL;
    chunk_t str;

    str.ptr = (unsigned char*)dst;
    str.len = dstlen;
    ugh = dn_parse(dn, &str);

    if (ugh != NULL) /* error, print DN as hex string */
    {
	DBG(DBG_PARSING,
	    DBG_log("error in DN parsing: %s", ugh));
	str.ptr = (unsigned char *)dst;
	str.len = dstlen;
	hex_str(dn, &str);
    }
    return (int)(dstlen - str.len);
}

/*
 * Same as dntoa but prints a special string for a null dn
 */
int
dntoa_or_null(char *dst, size_t dstlen, chunk_t dn, const char* null_dn)
{
    if (dn.ptr == NULL)
	return snprintf(dst, dstlen, "%s", null_dn);
    else
	return dntoa(dst, dstlen, dn);
}

/*  Converts an LDAP-style human-readable ASCII-encoded
 *  ASN.1 distinguished name into binary DER-encoded format
 */
err_t
atodn(char *src, chunk_t *dn)
{
  /* finite state machine for atodn */

    typedef enum {
	SEARCH_OID =	0,
	READ_OID =	1,
	SEARCH_NAME =	2,
	READ_NAME =	3,
        UNKNOWN_OID =	4
    } state_t;

    u_char oid_len_buf[3];
    u_char name_len_buf[3];
    u_char rdn_seq_len_buf[3];
    u_char rdn_set_len_buf[3];
    u_char dn_seq_len_buf[3];

    chunk_t asn1_oid_len     = { oid_len_buf,     0 };
    chunk_t asn1_name_len    = { name_len_buf,    0 };
    chunk_t asn1_rdn_seq_len = { rdn_seq_len_buf, 0 };
    chunk_t asn1_rdn_set_len = { rdn_set_len_buf, 0 };
    chunk_t asn1_dn_seq_len  = { dn_seq_len_buf,  0 };
    chunk_t oid  = empty_chunk;
    chunk_t name = empty_chunk;

    int whitespace  = 0;
    int rdn_seq_len = 0;
    int rdn_set_len = 0;
    int rdn_len     = 0;
    int dn_seq_len  = 0;
    int pos         = 0;

    err_t ugh = NULL;

    u_char *dn_ptr = dn->ptr + 4;
    size_t max_len = dn->len - 4;
    state_t state = SEARCH_OID;

    do
    {
        switch (state)
	{
	case SEARCH_OID:
	    if (*src != ' ' && *src != '/' && *src !=  ',')
	    {
		oid.ptr = (unsigned char *)src;
		oid.len = 1;
		state = READ_OID;
	    }
	    break;
	case READ_OID:
	    if (*src != ' ' && *src != '=')
		oid.len++;
	    else
	    {
		for (pos = 0; pos < X501_RDN_ROOF; pos++)
		{
		    if (strlen(x501rdns[pos].name) == oid.len &&
			strncasecmp(x501rdns[pos].name, (char *)oid.ptr, oid.len) == 0)
			break; /* found a valid OID */
		}
		if (pos == X501_RDN_ROOF)
		{
		    ugh = "unknown OID in ID_DER_ASN1_DN";
		    state = UNKNOWN_OID;
		    break;
		}
		code_asn1_length(x501rdns[pos].oid.len, &asn1_oid_len);

		/* reset oid and change state */
		oid = empty_chunk;
		state = SEARCH_NAME;
	    }
	    break;
	case SEARCH_NAME:
	    if (*src != ' ' && *src != '=')
	    {
		name.ptr = (unsigned char *)src;
		name.len = 1;
		whitespace = 0;
		state = READ_NAME;
	    }
	    break;
	case READ_NAME:
	    if (*src != ',' && *src != '/' && *src != '\0')
	    {
		name.len++;
		if (*src == ' ')
		    whitespace++;
		else
		    whitespace = 0;
	    }
	    else
	    {
		name.len -= whitespace;
		code_asn1_length(name.len, &asn1_name_len);

		/* compute the length of the relative distinguished name sequence */
		rdn_seq_len = 1 + asn1_oid_len.len + x501rdns[pos].oid.len +
			      1 + asn1_name_len.len + name.len;
		code_asn1_length(rdn_seq_len, &asn1_rdn_seq_len);

		/* compute the length of the relative distinguished name set */
		rdn_set_len = 1 + asn1_rdn_seq_len.len + rdn_seq_len;
		code_asn1_length(rdn_set_len, &asn1_rdn_set_len);

		/* compute the length of the relative distinguished name */
		rdn_len = 1 + asn1_rdn_set_len.len + rdn_set_len;

		/* do we have sufficient buffer_space */
		if (dn_seq_len + rdn_len > max_len)
		{
		    ugh = "insufficient buffer space for atodn()";
		    break;
		}

		/* encode the relative distinguished name */
		*dn_ptr++ = ASN1_SET;
		chunkcpy(dn_ptr, asn1_rdn_set_len);
		*dn_ptr++ = ASN1_SEQUENCE;
		chunkcpy(dn_ptr, asn1_rdn_seq_len);
		*dn_ptr++ = ASN1_OID;
		chunkcpy(dn_ptr, asn1_oid_len);
		chunkcpy(dn_ptr, x501rdns[pos].oid);
		/* encode the ASN.1 character string type of the name */
		*dn_ptr++ = (x501rdns[pos].type == ASN1_PRINTABLESTRING
		    && !is_printablestring(name))? ASN1_T61STRING : x501rdns[pos].type;
		chunkcpy(dn_ptr, asn1_name_len);
		chunkcpy(dn_ptr, name);

		/* accumulate the length of the distinguished name sequence */
		dn_seq_len += rdn_len;

		/* reset name and change state */
		name = empty_chunk;
		state = SEARCH_OID;
	    }
	    break;
	case UNKNOWN_OID:
	    break;
	}
    } while (*src++ != '\0' && ugh == NULL);

    /* complete the distinguished name sequence*/
    code_asn1_length(dn_seq_len, &asn1_dn_seq_len);
    dn->ptr += 3 - asn1_dn_seq_len.len;
    dn->len =  1 + asn1_dn_seq_len.len + dn_seq_len;
    dn_ptr = dn->ptr;
    *dn_ptr++ = ASN1_SEQUENCE;
    chunkcpy(dn_ptr, asn1_dn_seq_len);

    return ugh;
}

#ifdef X509DN_MAIN

#include <stdio.h>

#if 0
#define	MAX_BUF		6
extern unsigned char *cyclic_buffers[MAX_BUF][IDTOA_BUF](void);
extern unsigned char *cyclic_canary(void);
#endif
extern bool verify_cyclic_buffer(void);
extern void reset_cyclic_buffer(void);

void regress(void);
char *progname = "x509dn_regress";
void exit_tool(int num) { exit(num);}


int
main(int argc, char *argv[])
{
	ip_said sa;
	char buf[100];
	char buf2[100];
	const char *oops;
	size_t n;

        chunk_t name;

	name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
	name.len = IDTOA_BUF;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s {ahnnn@aaa|-r}\n", argv[0]);
		exit(2);
	}

	if (strcmp(argv[1], "-r") == 0) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}

	oops = atodn(argv[1], &name);

	if (oops != NULL) {
		fprintf(stderr, "%s: conversion failed: %s\n", argv[0], oops);
		exit(1);
	}
	n = dntoa(buf, sizeof(buf), name);
	if (n > sizeof(buf)) {
            fprintf(stderr, "%s: reverse conv ", argv[0]);
		fprintf(stderr, " failed: need %ld bytes, have only %ld\n",
						(long)n, (long)sizeof(buf));
		exit(1);
	}
	printf("%s\n", buf);

	exit(0);
}

struct rtab {
	int format;
	char *input;
	char *output;			/* NULL means error expected */
} rtab[] = {
	{0, "cn=John Doe,dc=example,dc=com,ou=Xelerance",
            "CN=John Doe, DC=example, DC=com, OU=Xelerance"},
	{0, NULL,			NULL}
};

void
regress(void)
{
	struct rtab *r;
	int status = 0;
	ip_said sa;
	char in[100];
	char buf[100];
	const char *oops;
	size_t n;
        chunk_t name;

        set_debugging(DBG_ALL);

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);

                reset_cyclic_buffer();

                name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
                name.len = IDTOA_BUF;

                oops = atodn(in, &name);

		if (oops != NULL && r->output == NULL)
			{}		/* okay, error expected */
		else if (oops != NULL) {
			printf("`%s' ttosa failed: %s\n", r->input, oops);
			status = 1;
		} else if (r->output == NULL) {
			printf("`%s' atodn succeeded unexpectedly\n",
                               r->input);
			status = 1;
		} else {
                    n = dntoa(buf, sizeof(buf), name);
                    if (n > sizeof(buf)) {
                        printf("`%s' dntoa failed:  need %ld\n",
                               r->input, (long)n);
                        status = 1;
                    } else if (strcmp(r->output, buf) != 0) {
                        printf("`%s' gave `%s', expected `%s'\n",
                               r->input, buf, r->output);
                        status = 1;
                    }
		}
                if(!verify_cyclic_buffer()) {
                    printf("overran buffer\n");
                    status = 1;
                }
	}
	exit(status);
}

#endif /* ATODN_MAIN */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * compile-command: "cd ../../testing/lib/libopenswan && make one TEST=x509dn; cat lib-x509dn/OUTPUT/x509dn.txt"
 * End:
 */

