/* misc functions to get compile time and runtime options
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
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

#ifndef _OSW_CONF_H
#define _OSW_CONF_H

#include "constants.h"

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
#endif

struct paththing {
  char    *path;
  size_t   path_space;
};


struct osw_conf_options {
    char *rootdir;                /* default is "" --- used for testing */
    char *confdir;                /* "/etc" */
    char *conffile;               /* "/etc/ipsec.conf" */
    char *confddir;               /* "/etc/ipsec.d" */
    char *vardir;                 /* "/var/run/pluto" */
    char *policies_dir;           /* "/etc/ipsec.d/policies" */
    char *acerts_dir;             /* "/etc/ipsec.d/acerts" */
    char *cacerts_dir;            /* "/etc/ipsec.d/cacerts" */
    char *crls_dir;               /* "/etc/ipsec.d/crls" */
    char *private_dir;            /* "/etc/ipsec.d/private" */
    char *certs_dir;              /* "/etc/ipsec.d/certs" */
    char *aacerts_dir;            /* "/etc/ipsec.d/aacerts" */
    char *ocspcerts_dir;          /* "/etc/ipsec.d/ocspcerts" */
    char *ctlbase;                /* where to put control socket */
    char *ocspuri;                /* URL for OCSP server */
    char *virtual_private;        /* a list of acceptable proposals behind NAT44 */

    char pluto_lock[1024];
    bool pluto_lock_created;
    char *pluto_shared_secrets_file;

    /** by default pluto sends certificate requests to its peers */
    bool no_cr_send;

    /** by default the CRL policy is lenient */
    bool strict_crl_policy;

    /** by default pluto does not check crls dynamically */
    long crl_check_interval;

    /** by default pluto sends no cookies in ikev2 or ikev1 aggrmode */
    /** if true, then have pluto IKEv2, R1, demand cookie */
    bool force_busy;

    /* orient will accept that both ends have and, but may differ by port */
    bool orient_same_addr_ok;

    /* should pluto fork into the background? */
    bool fork_desired;

    /* turn off retransmits, so no need for timers */
    bool no_retransmits;

    /* Note the serial number, and release any connections with
     * the same peer ID but different peer IP address.
     */
    bool uniqueIDs;                 /* --uniqueids? */

    u_int16_t pluto_port500;	    /* Pluto's port (usually 500) */
    u_int16_t pluto_port4500;	    /* Pluto's NAT port (usually 4500) */
    bool can_do_IPcomp;             /* can system actually perform IPCOMP? */

    /* whether or not to use klips */
    enum kernel_interface kern_interface;

    bool   log_to_stderr_desired;
    bool   log_with_timestamp_desired;

    char *base_perpeer_logdir;    /* where to write log files by IP */
    bool   log_to_perpeer;        /* if true, also log */

    bool   log_to_stderr; 	/* should log go to stderr? */
    bool   log_to_syslog;	/* should log go to syslog? */
    bool   log_with_timestamp;  /* some people want timestamps, but we
				   don't want those in our test output */

    u_int16_t secctx_attr_value;

    bool nat_traversal;
    bool nat_t_spf;
    unsigned int keep_alive;
    bool force_keepalive;

    /* where (directory), and if to dump core */
    char *coredir;
    int nhelpers;
    char *pluto_listen;
};

#ifdef HAVE_LIBNSS
typedef struct {
    enum {
      PW_NONE = 0,      /* no password */
      PW_FROMFILE = 1,  /* password data in a text file */
      PW_PLAINTEXT = 2, /* password data in the clear in memory buffer */
      PW_EXTERNAL = 3   /* external source, user will be prompted */
    } source ;
    char *data;
} secuPWData;
#endif

extern struct osw_conf_options *osw_init_options(void);
extern void osw_conf_free_oco(void);
extern const struct osw_conf_options *osw_init_ipsecdir(const char *ipsec_dir);
extern const struct osw_conf_options *osw_init_rootdir(const char *root_dir);

#ifdef HAVE_LIBNSS
extern secuPWData *osw_return_nss_password_file_info(void);
extern char *getNSSPassword(PK11SlotInfo *slot, PRBool retry, void *arg);
extern bool Pluto_IsFIPS(void);
#endif

#endif /* _OSW_ALLOC_H_ */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
