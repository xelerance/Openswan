#ifndef _SHA1_H_
#define _SHA1_H_

#include "constants.h"

/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#ifdef HAVE_LIBNSS
# include <nss.h>
# include <pk11pub.h>
#endif

#ifndef SHA1_DIGEST_SIZE
#define SHA1_DIGEST_SIZE 20
#endif


typedef struct {
#ifdef HAVE_LIBNSS
    PK11Context* ctx_nss;
#else
    u_int32_t state[5];
    u_int32_t count[2];
    unsigned char buffer[64];
#endif
} SHA1_CTX;

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[64]);
void SHA1Init(void * context);
void SHA1Update(void* context, const unsigned char* data, long unsigned len);
void SHA1Final(unsigned char digest[SHA1_DIGEST_SIZE], void* context);

#endif /* _SHA1_H_ */
