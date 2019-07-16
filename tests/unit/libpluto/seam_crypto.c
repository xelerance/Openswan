#include "pluto/crypto.h"

void
init_crypto(void)
{
  /* NOTHING for NOW */
}

const struct oakley_group_desc unset_group = {0, NULL, NULL, 0};      /* magic signifier */

const struct oakley_group_desc *
lookup_group(enum ikev2_trans_type_dh group)
{
  return &unset_group;
}


bool ike_alg_enc_present(int ealg, unsigned int keysize) { return TRUE; }
bool ikev1_alg_integ_present(int halg, unsigned int keysize)  { return TRUE; }
bool ikev2_alg_integ_present(int halg, unsigned int keysize)  { return TRUE; }
bool ike_alg_prf_present(int halg)  { return TRUE; }
bool ike_alg_group_present(int modpid) { return TRUE; }

bool ikev1_alg_enc_ok(int ealg, unsigned key_len, struct alg_info_ike *alg_info_ike, const char **n, char *m, size_t len) { return TRUE; }
bool ike_alg_enc_ok(int ealg, unsigned key_len, struct alg_info_ike *alg_info_ike, const char **n, char *m, size_t len) { return TRUE; }
bool ike_alg_ok_final(int ealg, unsigned key_len, int aalg, unsigned int group, struct alg_info_ike *alg_info_ike) { return TRUE; }


int dntoa(char *dst, size_t dstlen, chunk_t dn) { return 0; }
err_t atodn(char *src, chunk_t *dn) { return "FAIL"; }
bool match_dn(chunk_t a, chunk_t b, int *wildcards) { return FALSE; }
int dn_count_wildcards(chunk_t dn) { return 0; }
bool same_dn(chunk_t a, chunk_t b) { return FALSE; }

void sha256_hash_buffer(const unsigned char *ib, int ile, unsigned char *ob, int ole) {}
void calculate_rsa_ckaid(osw_public_key *pub) {}
rsa_privkey_t* load_rsa_private_key(const char* filename
                                    , int verbose
                                    , prompt_pass_t *pass) { return NULL; }







