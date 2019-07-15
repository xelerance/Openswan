/*
 *  sha512.c
 *
 *  Written by Jari Ruusu, April 16 2001
 *
 *  Copyright 2001 by Jari Ruusu.
 *  Redistribution of this file is permitted under the GNU Public License.
 */

#ifdef __KERNEL__
# include <linux/string.h>
# include <linux/types.h>
#else
# include <string.h>
# include <sys/types.h>
#  include <pk11pub.h>
#  include "oswlog.h"
#endif
#include "sha2.h"

/* Define one or more of these. If none is defined, you get all of them */
#if !defined(SHA256_NEEDED)&&!defined(SHA512_NEEDED)&&!defined(SHA384_NEEDED)
# define SHA256_NEEDED  1
# define SHA512_NEEDED  1
# define SHA384_NEEDED  1
#endif

#define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define R(x,y)      ((y) >> (x))

#if defined(SHA256_NEEDED)
void sha256_init(sha256_context *ctx)
{
    DBG(DBG_CRYPT, DBG_log("NSS: sha256 init start"));
    SECStatus status;
    ctx->ctx_nss = NULL;
    ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA256);
    PR_ASSERT(ctx->ctx_nss!=NULL);
    status=PK11_DigestBegin(ctx->ctx_nss);
    PR_ASSERT(status==SECSuccess);
    DBG(DBG_CRYPT, DBG_log("NSS: sha256 init end"));
}

#define S(x,y)      (((y) >> (x)) | ((y) << (32 - (x))))
#define uSig0(x)    ((S(2,(x))) ^ (S(13,(x))) ^ (S(22,(x))))
#define uSig1(x)    ((S(6,(x))) ^ (S(11,(x))) ^ (S(25,(x))))
#define lSig0(x)    ((S(7,(x))) ^ (S(18,(x))) ^ (R(3,(x))))
#define lSig1(x)    ((S(17,(x))) ^ (S(19,(x))) ^ (R(10,(x))))


void sha256_write(sha256_context *ctx, const unsigned char *datap, int length)
{
	SECStatus status = PK11_DigestOp(ctx->ctx_nss, datap, length);
	PR_ASSERT(status==SECSuccess);
	DBG(DBG_CRYPT, DBG_log("NSS: sha256 write end"));
}

void sha256_hash_buffer(const unsigned char *ib, int ile, unsigned char *ob, int ole)
{
    sha256_context ctx;

    if(ole < 1) return;
    memset(ob, 0, ole);
    if(ole > 32) ole = 32;
    sha256_init(&ctx);
    sha256_write(&ctx, ib, ile);
    unsigned int length;
    SECStatus status=PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
    PR_ASSERT(length==ole);
    PR_ASSERT(status==SECSuccess);
    PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
    DBG(DBG_CRYPT, DBG_log("NSS: sha256 final end"));
}

#endif

#if defined(SHA512_NEEDED)
void sha512_init(sha512_context *ctx)
{
    DBG(DBG_CRYPT, DBG_log("NSS: sha512 init start"));
    SECStatus status;
    ctx->ctx_nss = NULL;
    ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA512);
    PR_ASSERT(ctx->ctx_nss!=NULL);
    status = PK11_DigestBegin(ctx->ctx_nss);
    PR_ASSERT(status==SECSuccess);
    DBG(DBG_CRYPT, DBG_log("NSS: sha512 init end"));
}
#endif

#if defined(SHA512_NEEDED) || defined(SHA384_NEEDED)
#undef S
#undef uSig0
#undef uSig1
#undef lSig0
#undef lSig1
#define S(x,y)      (((y) >> (x)) | ((y) << (64 - (x))))
#define uSig0(x)    ((S(28,(x))) ^ (S(34,(x))) ^ (S(39,(x))))
#define uSig1(x)    ((S(14,(x))) ^ (S(18,(x))) ^ (S(41,(x))))
#define lSig0(x)    ((S(1,(x))) ^ (S(8,(x))) ^ (R(7,(x))))
#define lSig1(x)    ((S(19,(x))) ^ (S(61,(x))) ^ (R(6,(x))))
void sha512_write(sha512_context *ctx, const unsigned char *datap, int length)
{
       SECStatus status=PK11_DigestOp(ctx->ctx_nss, datap, length);
	PR_ASSERT(status==SECSuccess);
       DBG(DBG_CRYPT, DBG_log("NSS: sha512 write end"));
}
void sha512_hash_buffer(const unsigned char *ib, int ile, unsigned char *ob, int ole)
{
    sha512_context ctx;

    if(ole < 1) return;
    memset(ob, 0, ole);
    if(ole > 64) ole = 64;
    sha512_init(&ctx);
    sha512_write(&ctx, ib, ile);
    unsigned int length;
    SECStatus status = PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
    PR_ASSERT(length==ole);
    PR_ASSERT(status==SECSuccess);
    PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
    DBG(DBG_CRYPT, DBG_log("NSS: sha512 final end"));
}
#endif

#if defined(SHA384_NEEDED)
void sha384_init(sha512_context *ctx)
{
    DBG(DBG_CRYPT, DBG_log("NSS: sha384 init start"));
    SECStatus status;
    ctx->ctx_nss = NULL;
    ctx->ctx_nss = PK11_CreateDigestContext(SEC_OID_SHA384);
    PR_ASSERT(ctx->ctx_nss!=NULL);
    status=PK11_DigestBegin(ctx->ctx_nss);
    PR_ASSERT(status==SECSuccess);
    DBG(DBG_CRYPT, DBG_log("NSS: sha384 init end"));
}

void sha384_hash_buffer(const unsigned char *ib, int ile, unsigned char *ob, int ole)
{
    sha512_context ctx;

    if(ole < 1) return;
    memset(ob, 0, ole);
    if(ole > 48) ole = 48;
    sha384_init(&ctx);
    unsigned int length;
    SECStatus status = PK11_DigestOp(ctx.ctx_nss, ib, ile);
    PR_ASSERT(status==SECSuccess);
    status=PK11_DigestFinal(ctx.ctx_nss, ob, &length, ole);
    PR_ASSERT(length==ole);
    PR_ASSERT(status==SECSuccess);
    PK11_DestroyContext(ctx.ctx_nss, PR_TRUE);
    DBG(DBG_CRYPT, DBG_log("NSS: sha384 init end"));
}
#endif
