#ifndef __seam_crypt_c__
#define __seam_crypt_c__
#include "pluto_crypt.h"
struct pluto_crypto_req_cont *continuation = NULL;


struct pluto_crypto_req rd;
struct pluto_crypto_req *crypto_req = &rd;

void run_one_continuation(struct pluto_crypto_req *r)
{
  struct pluto_crypto_req_cont *cn = continuation;
  continuation = NULL;

  if(cn) {
    (*cn->pcrc_func)(cn, r, NULL);
  } else {
    fprintf(stderr, "should have found a continuation, but none was found\n");
  }
}

void run_continuation(struct pluto_crypto_req *r)
{
  while(continuation != NULL) {
    run_one_continuation(r);
  }
}

#endif
