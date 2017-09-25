#ifndef _IKE_ALG_H
#define _IKE_ALG_H

#include "constants.h"
#include "gmp.h"
/* forward reference */
struct connection;

struct ike_alg {
    const char *name;
    const char *officname;
    enum ikev2_trans_type algo_type;
    u_int16_t algo_id;                     /* IKEv1 number */
    enum ikev2_trans_type_encr algo_v2id;
    struct ike_alg *algo_next;
};

struct ike_encr_desc {
    struct ike_alg common;
    size_t   enc_ctxsize;
    size_t   enc_blocksize;
/* Is this always true?  usually with CBC methods. Maybe not with others */
#define iv_size enc_blocksize
    unsigned keydeflen;
    unsigned keymaxlen;
    unsigned keyminlen;
    void (*do_crypt)(u_int8_t *dat         /* encrypts and decrypts *INPLACE */
		     , size_t datasize
		     , u_int8_t *key
		     , size_t key_size
		     , u_int8_t *iv
		     , bool enc);
};

typedef void (*hash_update_t)(void *, const u_char *, size_t) ;

struct ike_integ_desc {
    struct ike_alg common;
    size_t hash_key_size;          /* in bits */
    size_t hash_ctx_size;
    size_t hash_digest_len;
    size_t hash_integ_len;        /*truncated output len when used as an integrity algorithm in IKEV2*/
    void (*hash_init)(void *ctx);
    hash_update_t hash_update;
    void (*hash_final)(u_int8_t *out, void *ctx);
};

/* for now, the API is identical */
#define ike_prf_desc ike_integ_desc

struct ike_dh_desc {
    struct ike_alg common;
    const MP_INT  *generator;
    const MP_INT  *modulus;
};

struct alg_info_ike; /* forward reference */
struct alg_info_esp;

struct db_context * ike_alg_db_new(struct alg_info_ike *ai, lset_t policy);
void ike_alg_show_status(void);
void ike_alg_show_connection(struct connection *c, const char *instance);

#define IKE_EALG_FOR_EACH(a) \
	for(a=ike_alg_base[IKEv2_TRANS_TYPE_ENCR];a;a=a->algo_next)
#define IKE_HALG_FOR_EACH(a) \
	for(a=ike_alg_base[IKEv2_TRANS_TYPE_INTEG];a;a=a->algo_next)
#define IKE_PRFALG_FOR_EACH(a) \
	for(a=ike_alg_base[IKEv2_TRANS_TYPE_PRF];a;a=a->algo_next)
#define IKE_DH_ALG_FOR_EACH(idx) for(idx = 0; idx != oakley_group_size; idx++)

#ifdef IKEV1
extern bool ikev1_alg_enc_present(int ealg, unsigned int keysize);
extern bool ikev1_alg_enc_ok(int ealg, unsigned key_len, struct alg_info_ike *alg_info_ike, const char **, char *, size_t);

/* these routines lookup algorithms by IKEv1 algorithm number */
extern struct ike_alg *ike_alg_ikev1_find(enum ikev2_trans_type algo_type
                                          , unsigned algo_id
                                          , unsigned keysize);
static inline struct ike_encr_desc *ikev1_alg_get_encr(int alg)
{
    return (struct ike_encr_desc *) ike_alg_ikev1_find(IKEv2_TRANS_TYPE_ENCR, alg, 0);
}

static inline struct ike_integ_desc *ikev1_crypto_get_hasher(unsigned int alg)
{
    return (struct ike_integ_desc *) ike_alg_ikev1_find(IKEv2_TRANS_TYPE_INTEG, alg, 0);
}

static inline struct ike_prf_desc *ikev1_crypto_get_prf(unsigned int alg)
{
    return (struct ike_prf_desc *) ike_alg_ikev1_find(IKEv2_TRANS_TYPE_PRF, alg, 0);
}
#endif

bool ikev1_alg_integ_present(int halg, unsigned int keysize);
bool ike_alg_enc_present(int ealg, unsigned int keysize);
bool ikev2_alg_integ_present(int halg, unsigned int keysize);
bool ike_alg_prf_present(int halg);

bool ike_alg_group_present(int modpid);
bool ike_alg_enc_ok(int ealg, unsigned key_len, struct alg_info_ike *alg_info_ike, const char **, char *, size_t);
bool ike_alg_ok_final(int ealg, unsigned key_len, int aalg, unsigned int group, struct alg_info_ike *alg_info_ike);

int ike_alg_init(void);

/*
 *	This could be just OAKLEY_XXXXXX_ALGORITHM, but it's
 *	here with other name as a way to assure that the
 *	algorithm hook type is supported (detected at compile time)
 */
extern struct ike_alg *ike_alg_base[IKEv2_TRANS_TYPE_COUNT+1];
int ike_alg_add(struct ike_alg *, bool quiet);
int ike_alg_register_enc(struct ike_encr_desc *e);
int ike_alg_register_integ(struct ike_integ_desc *a);
int ike_alg_register_prf(struct ike_prf_desc *a);
struct ike_alg *ike_alg_ikev2_find(enum ikev2_trans_type algo_type
				   , enum ikev2_trans_type_encr algo_v2id
				   , unsigned keysize);

static __inline__ struct ike_encr_desc *ike_alg_get_encr(int alg)
{
    return (struct ike_encr_desc *) ike_alg_ikev2_find(IKEv2_TRANS_TYPE_ENCR, alg, 0);
}
static __inline__ struct ike_integ_desc *ike_alg_get_integ(enum ikev2_trans_type_integ halg)
{
    return (struct ike_integ_desc *) ike_alg_ikev2_find(IKEv2_TRANS_TYPE_INTEG, halg, 0);
}
static __inline__ struct ike_prf_desc *ike_alg_get_prf(enum ikev2_trans_type_prf prfalg)
{
	return (struct ike_prf_desc *) ike_alg_ikev2_find(IKEv2_TRANS_TYPE_PRF, prfalg, 0);
}
static __inline__ struct ike_dh_desc *ike_alg_get_dh(int alg)
{
	return (struct ike_dh_desc *) ike_alg_ikev2_find(IKEv2_TRANS_TYPE_DH, alg, 0);
}
const struct oakley_group_desc * ike_alg_pfsgroup(struct connection *c, lset_t policy);

enum alg_desired_maximum {
    SADB_NOLIMIT     = 1,
    SADB_ONEPROPOSAL = 2,
    SADB_ONEDH_ONLY  = 3,
};

extern struct db_sa *ikev2_sadb_from_alg(struct alg_info_ike *ai
                                         ,enum alg_desired_maximum maxtrans);

extern struct db_sa *ikev2_kernel_alg_makedb(lset_t policy
				       , struct alg_info_esp *ei
				       , bool logit);

extern struct db_sa *kernel_alg_makedb(lset_t policy
				       , struct alg_info_esp *ei
                                       , enum phase1_role role);

/* used if USE_SHA2 set, which is now default */
extern int ike_alg_sha2_init(void);
/* Translate from IKEv1->IKEv2 */
extern enum ikev2_trans_type_integ ikev1toikev2integ(enum oakley_hash_t num);

#endif /* _IKE_ALG_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
