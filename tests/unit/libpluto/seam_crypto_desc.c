#include "ike_alg.h"

struct hash_desc h1 = {
 .common = { .name = "hello", .officname = "there" },

};

struct encrypt_desc e1 = {
 .common = { .name = "encrypt", .officname = "funfun" },
};

struct hash_desc *crypto_get_hasher(oakley_hash_t alg)
{
  return &h1;
}
struct encrypt_desc *crypto_get_encrypter(int alg)
{
  return &e1;
}
