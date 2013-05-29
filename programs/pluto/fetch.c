/* Dynamic fetching of X.509 CRLs
 * Copyright (C) 2002 Stephane Laroche <stephane.laroche@colubris.com>
 * Copyright (C) 2002-2004 Andreas Steffen, Zuercher Hochschule Winterthur
 * Copyright (C) 2003-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>
#include <string.h>

#ifdef LIBCURL
#include <curl/curl.h>
#endif

#include <openswan.h>

#ifdef LDAP_VER
#define LDAP_DEPRECATED 1
#include <ldap.h>
#endif

#include "constants.h"
#include "defs.h"
#include "log.h"
#include "id.h"
#include "asn1.h"
#include "pem.h"
#include "x509.h"
#include "whack.h"
#include "ocsp.h"
#include "fetch.h"
#include "oswtime.h"

#ifdef LIBCURL
#define LIBCURL_UNUSED
#else
#define LIBCURL_UNUSED UNUSED
#endif

#define FETCH_CMD_TIMEOUT	5	/* seconds */

typedef struct fetch_req fetch_req_t;

struct fetch_req {
  fetch_req_t   *next;
  time_t        installed;
  int           trials;
  chunk_t       issuer;
  generalName_t *distributionPoints;
};

fetch_req_t empty_fetch_req = {
   NULL    , /* next */
         0 , /* installed */
         0 , /* trials */
  {NULL, 0}, /* issuer */
   NULL      /* distributionPoints */
};

/* chained list of crl fetch requests */
static fetch_req_t *crl_fetch_reqs  = NULL;

/* chained list of ocsp fetch requests */
static ocsp_location_t *ocsp_fetch_reqs = NULL;

static pthread_t thread;
static pthread_mutex_t certs_and_keys_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t authcert_list_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t crl_list_mutex        = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ocsp_cache_mutex      = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t crl_fetch_list_mutex  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t ocsp_fetch_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fetch_wake_mutex      = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  fetch_wake_cond       = PTHREAD_COND_INITIALIZER;

#define BUF_LEN		512

/*
 * lock access to my certs and keys
 */
void
lock_certs_and_keys(const char *who)
{
    pthread_mutex_lock(&certs_and_keys_mutex);
    DBG(DBG_CONTROLMORE,
	DBG_log("certs and keys locked by '%s'", who)
    )
}

/*
 * unlock access to my certs and keys
 */
void
unlock_certs_and_keys(const char *who)
{
    DBG(DBG_CONTROLMORE,
	DBG_log("certs and keys unlocked by '%s'", who)
    )
    pthread_mutex_unlock(&certs_and_keys_mutex);
}

/*
 * lock access to the chained authcert list
 */
void
lock_authcert_list(const char *who)
{
    pthread_mutex_lock(&authcert_list_mutex);
    DBG(DBG_CONTROLMORE,
	DBG_log("authcert list locked by '%s'", who)
    )
}

/*
 * unlock access to the chained authcert list
 */
void
unlock_authcert_list(const char *who)
{
    DBG(DBG_CONTROLMORE,
	DBG_log("authcert list unlocked by '%s'", who)
    )
    pthread_mutex_unlock(&authcert_list_mutex);
}

/*
 * lock access to the chained crl list
 */
void
lock_crl_list(const char *who)
{
    pthread_mutex_lock(&crl_list_mutex);
    DBG(DBG_CONTROLMORE,
	DBG_log("crl list locked by '%s'", who)
    )
}

/*
 * unlock access to the chained crl list
 */
void
unlock_crl_list(const char *who)
{
    DBG(DBG_CONTROLMORE,
	DBG_log("crl list unlocked by '%s'", who)
    )
    pthread_mutex_unlock(&crl_list_mutex);
}

/*
 * lock access to the ocsp cache
 */
extern void
lock_ocsp_cache(const char *who)
{
    pthread_mutex_lock(&ocsp_cache_mutex);
    DBG(DBG_CONTROLMORE,
	DBG_log("ocsp cache locked by '%s'", who)
    )
}

/*
 * unlock access to the ocsp cache
 */
extern void
unlock_ocsp_cache(const char *who)
{
    DBG(DBG_CONTROLMORE,
	DBG_log("ocsp cache unlocked by '%s'", who)
    )
    pthread_mutex_unlock(&ocsp_cache_mutex);
}

/*
 * lock access to the chained crl fetch request list
 */
static void
lock_crl_fetch_list(const char *who)
{
    pthread_mutex_lock(&crl_fetch_list_mutex);
    DBG(DBG_CONTROLMORE,
	DBG_log("crl fetch request list locked by '%s'", who)
    )
}

/*
 * unlock access to the chained crl fetch request list
 */
static void
unlock_crl_fetch_list(const char *who)
{
    DBG(DBG_CONTROLMORE,
	DBG_log("crl fetch request list unlocked by '%s'", who)
    )
    pthread_mutex_unlock(&crl_fetch_list_mutex);
}

/*
 * lock access to the chained ocsp fetch request list
 */
static void
lock_ocsp_fetch_list(const char *who)
{
    pthread_mutex_lock(&ocsp_fetch_list_mutex);
    DBG(DBG_CONTROLMORE,
	DBG_log("ocsp fetch request list locked by '%s'", who)
    )
}

/*
 * unlock access to the chained ocsp fetch request list
 */
static void
unlock_ocsp_fetch_list(const char *who)
{
    DBG(DBG_CONTROLMORE,
	DBG_log("ocsp fetch request list unlocked by '%s'", who)
    )
    pthread_mutex_unlock(&ocsp_fetch_list_mutex);
}

/*
 * wakes up the sleeping fetch thread
 */
void
wake_fetch_thread(const char *who)
{
    if (crl_check_interval > 0)
    {
	DBG(DBG_CONTROLMORE,
	    DBG_log("fetch thread wake call by '%s'", who)
	)
#ifdef HAVE_THREADS
	pthread_mutex_lock(&fetch_wake_mutex);
	pthread_cond_signal(&fetch_wake_cond);
	pthread_mutex_unlock(&fetch_wake_mutex);
#endif
    }
}

/*
 *  free the dynamic memory used to store fetch requests
 */
static void
free_fetch_request(fetch_req_t *req)
{
    pfree(req->issuer.ptr);
    free_generalNames(req->distributionPoints, TRUE);
    pfree(req);
}

#ifdef LIBCURL
/*
 * writes data into a buffer
 * needed for libcurl
 */
static size_t
write_buffer(void *ptr, size_t size, size_t nmemb, void *data)
{
    size_t realsize = size * nmemb;
    chunk_t *mem = (chunk_t*)data;

    mem->ptr = (u_char *)realloc(mem->ptr, mem->len + realsize);
    if (mem->ptr) {
        memcpy(&(mem->ptr[mem->len]), ptr, realsize);
        mem->len += realsize;
    }
    return realsize;
}
#endif

/*
 * fetches a binary blob from a url with libcurl
 */
static err_t
fetch_curl(chunk_t url LIBCURL_UNUSED, chunk_t *blob LIBCURL_UNUSED)
{
#ifdef LIBCURL
    char errorbuffer[CURL_ERROR_SIZE] = "";
    char *uri;
    chunk_t response = empty_chunk;
    CURLcode res;

    /* get it with libcurl */
    CURL *curl = curl_easy_init();

    if (curl != NULL)
    {
        /* we need a null terminated string for curl */
        uri = alloc_bytes(url.len + 1, "null terminated url");
        memcpy(uri, url.ptr, url.len);
        *(uri + url.len) = '\0';

        DBG(DBG_CONTROL,
            DBG_log("Trying cURL '%s'", uri)
        )

        curl_easy_setopt(curl, CURLOPT_URL, uri);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_buffer);
        curl_easy_setopt(curl, CURLOPT_FILE, (void *)&response);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &errorbuffer);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, FETCH_CMD_TIMEOUT);


        res = curl_easy_perform(curl);

        if (res == CURLE_OK)
        {
            blob->len = response.len;
            blob->ptr = alloc_bytes(response.len, "curl blob");
            memcpy(blob->ptr, response.ptr, response.len);
        }
        else
        {
            plog("fetching uri (%s) with libcurl failed: %s", uri, errorbuffer);
        }
        curl_easy_cleanup(curl);
        pfree(uri);
        /* not using freeanychunk because of realloc (no leak detective) */
        curl_free(response.ptr);
    }
    return strlen(errorbuffer) > 0 ? "libcurl error" : NULL;
#else
    return "not compiled with libcurl support";
#endif
}


#ifdef LDAP_VER
/*
 * parses the result returned by an ldap query
 */
static err_t
parse_ldap_result(LDAP * ldap, LDAPMessage *result, chunk_t *blob)
{
    err_t ugh = NULL;

    LDAPMessage * entry = ldap_first_entry(ldap, result);

    if (entry != NULL)
    {
	BerElement *ber = NULL;
	char *attr;

	attr = ldap_first_attribute(ldap, entry, &ber);

	if (attr != NULL)
	{
	    struct berval **values = ldap_get_values_len(ldap, entry, attr);

	    if (values != NULL)
	    {
		if (values[0] != NULL)
		{
		    blob->len = values[0]->bv_len;
		    blob->ptr = alloc_bytes(blob->len, "ldap blob");
		    memcpy(blob->ptr, values[0]->bv_val, blob->len);
		    if (values[1] != NULL)
		    {
			plog("warning: more than one value was fetched from LDAP URL");
		    }
		}
		else
		{
		    ugh = "no values in attribute";
		}
		ldap_value_free_len(values);
	    }
	    else
	    {
		ugh = ldap_err2string(ldap_result2error(ldap, entry, 0));
	    }
	    ldap_memfree(attr);
	}
	else
	{
	    ugh = ldap_err2string(ldap_result2error(ldap, entry, 0));
	}
	ber_free(ber, 0);
    }
    else
    {
	ugh = ldap_err2string(ldap_result2error(ldap, result, 0));
    }
    return ugh;
}

/*
 * fetches a binary blob from an ldap url
 */
static err_t
fetch_ldap_url(chunk_t url, chunk_t *blob)
{
    LDAPURLDesc *lurl;
    err_t ugh = NULL;
    int rc;

    char *ldap_url = alloc_bytes(url.len + 1, "ldap query");

    sprintf(ldap_url,"%.*s", (int)url.len, url.ptr);

    DBG(DBG_CONTROL,
	DBG_log("Trying LDAP URL '%s'", ldap_url)
    )

    rc = ldap_url_parse(ldap_url, &lurl);
    pfree(ldap_url);

    if (rc == LDAP_SUCCESS)
    {
	LDAP *ldap = ldap_init(lurl->lud_host, lurl->lud_port);

	if (ldap != NULL)
	{
	    int ldap_version = (LDAP_VER == 2)? LDAP_VERSION2 : LDAP_VERSION3;
	    struct timeval timeout;

	    timeout.tv_sec  = FETCH_CMD_TIMEOUT;
	    timeout.tv_usec = 0;
	    ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
	    ldap_set_option(ldap, LDAP_OPT_NETWORK_TIMEOUT, &timeout);

	    rc = ldap_simple_bind_s(ldap, NULL, NULL);

	    if (rc == LDAP_SUCCESS)
	    {
		LDAPMessage *result;

		timeout.tv_sec = FETCH_CMD_TIMEOUT;
		timeout.tv_usec = 0;

		rc = ldap_search_st(ldap, lurl->lud_dn
					, lurl->lud_scope
					, lurl->lud_filter
					, lurl->lud_attrs
					, 0, &timeout, &result);

		if (rc == LDAP_SUCCESS)
		{
		    ugh = parse_ldap_result(ldap, result, blob);
		    ldap_msgfree(result);
		}
		else
		{
		    ugh = ldap_err2string(rc);
		}
	    }
	    else
	    {
		ugh = ldap_err2string(rc);
	    }
	    ldap_unbind_s(ldap);
	}
	else
	{
	    ugh = "ldap init";
	}
	ldap_free_urldesc(lurl);
    }
    else
    {
	ugh = ldap_err2string(rc);
    }
    return ugh;
}
#else
static err_t
fetch_ldap_url(chunk_t url UNUSED
	       , chunk_t *blob UNUSED)
{
    return "LDAP URL fetching not activated in pluto source code";
}
#endif

/*
 * fetch an ASN.1 blob coded in PEM or DER format from a URL
 */
static err_t
fetch_asn1_blob(chunk_t url, chunk_t *blob)
{
    err_t ugh = NULL;

    if (url.len >= 4 && strncasecmp(url.ptr, "ldap", 4) == 0)
    {
	ugh = fetch_ldap_url(url, blob);
    }
    else
    {
	ugh = fetch_curl(url, blob);
    }
    if (ugh != NULL)
	return ugh;

    if (is_asn1(*blob))
    {
	DBG(DBG_PARSING,
	    DBG_log("  fetched blob coded in DER format")
	)
    }
    else
    {
	bool pgp = FALSE;

	ugh = pemtobin(blob, NULL, "", &pgp);
	if (ugh == NULL)
	{
	    if (is_asn1(*blob))
	    {
		DBG(DBG_PARSING,
		    DBG_log("  fetched blob coded in PEM format")
		)
	    }
	    else
	    {
		ugh = "Blob coded in unknown format";
		pfree(blob->ptr);
	    }
	}
	else
	{
	    pfree(blob->ptr);
	}
    }
    return ugh;
}

/*
 * try to fetch the crls defined by the fetch requests
 */
static void
fetch_crls(void)
{
    fetch_req_t *req;
    fetch_req_t **reqp;

    lock_crl_fetch_list("fetch_crls");
    req  =  crl_fetch_reqs;
    reqp = &crl_fetch_reqs;

    while (req != NULL)
    {
	bool valid_crl = FALSE;
	chunk_t blob = empty_chunk;
	generalName_t *gn = req->distributionPoints;

	while (gn != NULL)
	{
	    err_t ugh = fetch_asn1_blob(gn->name, &blob);

	    if (ugh != NULL)
	    {
		plog("fetch failed:  %s", ugh);
	    }
	    else
	    {
		chunk_t crl_uri;
		clonetochunk(crl_uri, gn->name.ptr, gn->name.len, "crl uri");
		if (insert_crl(blob, crl_uri))
		{
		    DBG(DBG_CONTROL,
			DBG_log("we have a valid crl")
		    )
		    valid_crl = TRUE;
		    break;
		}
	    }
	    gn = gn->next;
	}

	if (valid_crl)
	{
	    /* delete fetch request */
	    fetch_req_t *req_free = req;

	    req   = req->next;
	    *reqp = req;
	    free_fetch_request(req_free);
	}
	else
	{
	    /* try again next time */
	    req->trials++;
	    reqp = &req->next;
	    req  =  req->next;
	}
    }
    unlock_crl_fetch_list("fetch_crls");
}

static void
fetch_ocsp_status(ocsp_location_t* location LIBCURL_UNUSED)
{
#ifdef LIBCURL
    chunk_t request;
    chunk_t response = empty_chunk;

    CURL* curl;
    CURLcode res;

    request = build_ocsp_request(location);

    DBG(DBG_CONTROL,
    	DBG_log("sending ocsp request to location '%.*s'"
	    , (int)location->uri.len, location->uri.ptr)
    )
    DBG(DBG_RAW,
	DBG_dump_chunk("OCSP request", request)
    )

    /* send via http post using libcurl */
    curl = curl_easy_init();

    if (curl != NULL)
    {
	char errorbuffer[CURL_ERROR_SIZE];
	struct curl_slist *headers = NULL;
	char* uri = alloc_bytes(location->uri.len+1, "ocsp uri");

	/* we need a null terminated string for curl */
	memcpy(uri, location->uri.ptr, location->uri.len);
	*(uri + location->uri.len) = '\0';

	/* set content type header */
	headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_URL, uri);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_buffer);
	curl_easy_setopt(curl, CURLOPT_FILE, (void *)&response);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.ptr);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.len);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &errorbuffer);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, FETCH_CMD_TIMEOUT);


	res = curl_easy_perform(curl);

	if (res == CURLE_OK)
	{
	    DBG(DBG_CONTROL,
		DBG_log("received ocsp response")
	    )
	    DBG(DBG_RAW,
		DBG_dump_chunk("OCSP response", response)
	    )
	    parse_ocsp(location, response);
	}
	else
	{
	    plog("failed to fetch ocsp status (%s): %s", uri, errorbuffer);
	}
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
	pfree(uri);
	/* not using freeanychunk because of realloc (no leak detective) */
	curl_free(response.ptr);
    }
    freeanychunk(location->nonce);
    freeanychunk(request);

    /* increment the trial counter of the unresolved fetch requests */
    {
	ocsp_certinfo_t *certinfo = location->certinfo;

	while (certinfo != NULL)
	{
	    certinfo->trials++;
	    certinfo = certinfo->next;
	}
    }
    return;
#else
    plog("ocsp error: pluto wasn't compiled with libcurl support");
#endif
}

/*
 * try to fetch the necessary ocsp information
 */
static void
fetch_ocsp(void)
{
    ocsp_location_t *location;

    lock_ocsp_fetch_list("fetch_ocsp");
    location = ocsp_fetch_reqs;

    /* fetch the ocps status for all locations */
    while (location != NULL)
    {
	if (location->certinfo != NULL)
	    fetch_ocsp_status(location);
	location = location->next;
    }

    unlock_ocsp_fetch_list("fetch_ocsp");
}

static void*
fetch_thread(void *arg UNUSED)
{
    struct timespec wait_interval;

    DBG(DBG_CONTROL,
	DBG_log("fetch thread started")
    )

#ifdef HAVE_THREADS
    pthread_mutex_lock(&fetch_wake_mutex);
#endif
    while(1)
    {
	int status;

	wait_interval.tv_nsec = 0;
	wait_interval.tv_sec = time(NULL) + crl_check_interval;

	DBG(DBG_CONTROL,
	    DBG_log("next regular crl check in %ld seconds", crl_check_interval)
	)
	status = pthread_cond_timedwait(&fetch_wake_cond, &fetch_wake_mutex
					, &wait_interval);

	if (status == ETIMEDOUT)
	{
	    DBG(DBG_CONTROL,
		DBG_log(" ");
		DBG_log("*time to check crls and the ocsp cache")
	    )
	    check_ocsp();
	    check_crls();
	}
	else
	{
	    DBG(DBG_CONTROL,
		DBG_log("fetch thread was woken up")
	    )
	}
	fetch_ocsp();
	fetch_crls();
    }
}

/*
 * initializes curl and starts the fetching thread
 */
void
init_fetch(void)
{
    int status;

    if (crl_check_interval > 0)
    {
#ifdef LIBCURL
	/* init curl */
	status = curl_global_init(CURL_GLOBAL_NOTHING);
	if (status != 0)
	{
	    plog("libcurl could not be initialized, status = %d", status);
	}
#endif
	status = pthread_create( &thread, NULL, fetch_thread, NULL);
	if (status != 0)
	{
	    plog("fetching thread could not be started, status = %d", status);
	}
    }
}

void
free_crl_fetch(void)
{
   lock_crl_fetch_list("free_crl_fetch");

    while (crl_fetch_reqs != NULL)
    {
	fetch_req_t *req = crl_fetch_reqs;
	crl_fetch_reqs = req->next;
	free_fetch_request(req);
    }

    unlock_crl_fetch_list("free_crl_fetch");

#ifdef LIBCURL
    if (crl_check_interval > 0)
    {
	/* cleanup curl */
	curl_global_cleanup();
    }
#endif
}

/*
 * free the chained list of ocsp requests
 */
void
free_ocsp_fetch(void)
{
    lock_ocsp_fetch_list("free_ocsp_fetch");
    free_ocsp_locations(&ocsp_fetch_reqs);
    unlock_ocsp_fetch_list("free_ocsp_fetch");
}


/*
 * add additional distribution points
 */
void
add_distribution_points(const generalName_t *newPoints ,generalName_t **distributionPoints)
{
    while (newPoints != NULL)
    {
	bool add = TRUE;
	generalName_t *gn = *distributionPoints;

	while (gn != NULL)
	{
	    if (gn->kind == newPoints->kind &&
		gn->name.len == newPoints->name.len &&
		memcmp(gn->name.ptr, newPoints->name.ptr, gn->name.len) == 0)
	    {
		/* distribution point already present, skip to next entry */
		add = FALSE;
		break;
	    }
	    gn = gn->next;
	}

	if (add)
	{
	    /* clone additional distribution point */
	    gn = clone_thing(*newPoints, "generalName");
	    clonetochunk(gn->name, newPoints->name.ptr, newPoints->name.len
		, "crl uri");

	    /* insert additional CRL distribution point */
	    gn->next = *distributionPoints;
	    *distributionPoints = gn;
	}
	newPoints = newPoints->next;
    }
}

/*
 * add a crl fetch request to the chained list
 */
void
add_crl_fetch_request(chunk_t issuer, const generalName_t *gn)
{
    fetch_req_t *req;

    lock_crl_fetch_list("add_crl_fetch_request");
    req = crl_fetch_reqs;

    while (req != NULL)
    {
	if (same_dn(issuer, req->issuer))
	{
	    /* there is already a fetch request */
	    DBG(DBG_CONTROL,
		DBG_log("crl fetch request already exists")
	    )

	    /* there might be new distribution points */
	    add_distribution_points(gn, &req->distributionPoints);

	    unlock_crl_fetch_list("add_crl_fetch_request");
	    return;
	}
	req = req->next;
    }
    /* create a new fetch request */
    req = alloc_thing(fetch_req_t, "fetch request");
    *req = empty_fetch_req;

    /* note current time */
    req->installed = time(NULL);

    /* clone issuer */
    clonetochunk(req->issuer, issuer.ptr, issuer.len, "issuer dn");

    /* copy distribution points */
    add_distribution_points(gn, &req->distributionPoints);

    /* insert new fetch request at the head of the queue */
    req->next = crl_fetch_reqs;
    crl_fetch_reqs = req;

    DBG(DBG_CONTROL,
	DBG_log("crl fetch request added")
    )
    unlock_crl_fetch_list("add_crl_fetch_request");
}

/*
 * add an ocsp fetch request to the chained list
 */
void
add_ocsp_fetch_request(ocsp_location_t *location, chunk_t serialNumber)
{
    ocsp_certinfo_t certinfo;

    certinfo.serialNumber = serialNumber;

    lock_ocsp_fetch_list("add_ocsp_fetch_request");
    add_certinfo(location, &certinfo, &ocsp_fetch_reqs, TRUE);
    unlock_ocsp_fetch_list("add_ocsp_fetch_request");
}

/*
 * list all distribution points
 */
void
list_distribution_points(const generalName_t *gn)
{
    bool first_gn = TRUE;

    while (gn != NULL)
    {
	whack_log(RC_COMMENT, "       %s '%.*s'", (first_gn)? "distPts:"
	    : "        ", (int)gn->name.len, gn->name.ptr);
	first_gn = FALSE;
	gn = gn->next;
    }
}

/*
 *  list all fetch requests in the chained list
 */
void
list_crl_fetch_requests(bool utc)
{
    fetch_req_t *req;

    lock_crl_fetch_list("list_crl_fetch_requests");
    req = crl_fetch_reqs;

    if (req != NULL)
    {
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of CRL fetch requests:");
	whack_log(RC_COMMENT, " ");
    }

    while (req != NULL)
    {
	u_char buf[BUF_LEN];
	char tbuf2[TIMETOA_BUF];

	whack_log(RC_COMMENT, "%s, trials: %d"
		  , timetoa(&req->installed, utc, tbuf2, sizeof(tbuf2))
		  , req->trials);
	dntoa(buf, BUF_LEN, req->issuer);
	whack_log(RC_COMMENT, "       issuer:  '%s'", buf);
	list_distribution_points(req->distributionPoints);
	req = req->next;
    }
    unlock_crl_fetch_list("list_crl_fetch_requests");
}

void
list_ocsp_fetch_requests(bool utc)
{
    lock_ocsp_fetch_list("list_ocsp_fetch_requests");
    list_ocsp_locations(ocsp_fetch_reqs, TRUE, utc, FALSE);
    unlock_ocsp_fetch_list("list_ocsp_fetch_requests");

}
