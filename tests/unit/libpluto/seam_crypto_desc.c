#include "ike_alg.h"

void do_crypt_abort(u_int8_t *dat         /* encrypts and decrypts *INPLACE */
		     , size_t datasize
		     , u_int8_t *key
		     , size_t key_size
		     , u_int8_t *iv
		     , bool enc)
{
  abort();
}
void do_hash_init_abort(void *ctx) { abort(); }
void do_hash_update_abort(void *ctx, const u_char *b, size_t s) { abort(); }
void do_hash_final_abort(u_int8_t *out, void *ctx) { abort(); }

struct ike_integ_desc h1 = {
 .common = { .name = "hello", .officname = "there" },
 .hash_init   = do_hash_init_abort,
 .hash_update = do_hash_update_abort,
 .hash_final  = do_hash_final_abort

};

struct ike_encr_desc e1 = {
 .common = { .name = "encrypt", .officname = "funfun" },
 .do_crypt = do_crypt_abort
};

struct ike_integ_desc *crypto_get_hasher(enum ikev2_trans_type_integ alg)
{
  return &h1;
}
struct ike_encr_desc *crypto_get_encrypter(enum ikev2_trans_type_encr ealg)
{
  return &e1;
}

struct ike_alg *ike_alg_ikev2_find(enum ikev2_trans_type algo_type
			     , enum ikev2_trans_type_encr algo_v2id
			     , unsigned keysize)
{
  return &e1.common;
}

struct ike_alg *ike_alg_ikev1_find(enum ikev2_trans_type algo_type
			     , unsigned algo_id
			     , unsigned keysize)
{
  return &e1.common;
}
