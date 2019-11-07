#ifndef _X509_LISTS
#include "x509.h"
#include "pgp.h"

struct pubkey_list;
struct pubkey;

extern void add_x509_public_key_to_list(struct pubkey_list **pl
                                        , struct id *keyid
				, x509cert_t *cert, time_t until
                                        , enum dns_auth_level dns_auth_level
                                        , struct pubkey **p_key);


extern void add_x509_altnames_to_list(struct pubkey_list **pl
                                   , const generalName_t *gn
                                   , x509cert_t *cert
                                   , time_t until
				, enum dns_auth_level dns_auth_level);


extern x509cert_t *x509certs;
extern x509crl_t  *x509crls;
extern pgpcert_t *pgpcerts;

#define _X509_LISTS
#endif
