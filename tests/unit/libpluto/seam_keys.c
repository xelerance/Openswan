#ifndef __seam_keys_c__
#define __seam_keys_c__

/* keymgmt.c SEAM */
void load_preshared_secrets(int whackfd) {}
chunk_t mysecret = { .ptr="abcd", .len=4 };
const chunk_t *get_preshared_secret(const struct connection *c) { return &mysecret; }

struct private_key_stuff f1;
const struct private_key_stuff *get_RSA_private_key(const struct connection *c) {
    return &f1;
}
void list_public_keys(bool utc, bool check_pub_keys) {}
void list_psks(void) {}

err_t add_public_key(const struct id *id
		     , enum dns_auth_level dns_auth_level
		     , enum pubkey_alg alg
		     , const chunk_t *key
		     , struct pubkey_list **head) { return NULL; /* no error */ }


void transfer_to_public_keys(struct gw_info *gateways_from_dns
			     , struct pubkey_list **keys) {}

struct pubkey_list *pluto_pubkeys = NULL;	/* keys from ipsec.conf */
struct secret *pluto_secrets = NULL;

/*
 *  find a public key by ckaid
 */
struct pubkey *find_public_keys(unsigned char ckaid[CKAID_BUFSIZE])
{
  return NULL;
}

struct pubkey *find_key_by_string(const char *key_hex)
{
  return NULL;
}

struct pubkey *osw_get_public_key_by_end(struct end *him)
{
  return NULL;
}
bool has_private_rawkey(struct pubkey *pk)
{
  return FALSE;
}
#endif
