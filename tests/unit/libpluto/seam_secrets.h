#ifndef __seam_secrets_h__
#define __seam_secrets_h__

struct seam_chunk {
	unsigned char *ptr;
	unsigned int len;
};

struct seam_secrets {
  const char *secrets_name;
	/* config */

	u_int16_t        oakleygroup;
	oakley_auth_t    auth;
	enum oakley_hash_t hash;
	enum phase1_role role;

	/* intermediate */

	struct seam_chunk gi;
	struct seam_chunk gr;
	struct seam_chunk ni;
	struct seam_chunk nr;
	struct seam_chunk icookie;
	struct seam_chunk rcookie;
	struct seam_chunk secret;
        struct seam_chunk secretr;

	/* results */

	struct seam_chunk shared;
	struct seam_chunk skeyseed;
	struct seam_chunk skey_d;
	struct seam_chunk skey_ai;
	struct seam_chunk skey_ar;
	struct seam_chunk skey_ei;
	struct seam_chunk skey_er;
	struct seam_chunk skey_pi;
	struct seam_chunk skey_pr;

  /* IKEv1 only */
        struct seam_chunk new_iv;
        struct seam_chunk enc_key;
};

/* Various test cases will define their own SECRETS macro, and common seam code
 * will use SS() to access the above structure members.
 *
 * See seam_gi_sha1.c for example of SECRETS being defined.
 *
 * See seam_ikev2_sendI1.c for example of using SS get access to data.
 */
#undef SECRETS
#define SS(member) ((SECRETS)->member)

static inline void seam_chunk_set(struct seam_chunk *c,
				const unsigned char *ptr,
				unsigned int len)
{
	c->ptr = (void*)ptr;
	c->len = len;
}

#define seam_set_static_array(ss,chunk_name,array) \
	seam_chunk_set(&(ss)->chunk_name, \
		     array, sizeof(array))

#define SEAM_SECRETS_DECLARE(SS,_oakleygroup,_auth,_hash,_role,...) \
	struct seam_secrets SS = { \
          .secrets_name = #SS, \
		.oakleygroup = _oakleygroup, \
		.auth = _auth, \
		.hash = _hash, \
		.role = _role, \
		##__VA_ARGS__ \
	}

#define __SS_SET(prefix,part) \
	.part = { .ptr = prefix##_##part, .len = sizeof(prefix##_##part) }

#define SEAM_SECRETS_DECLARE_USING_PREFIX_ARRAYS(SS,_oakleygroup,_auth,_hash,_role,prefix,...) \
	SEAM_SECRETS_DECLARE(SS,_oakleygroup,_auth,_hash,_role, \
		\
		__SS_SET(prefix,gi), \
		__SS_SET(prefix,gr), \
		__SS_SET(prefix,ni), \
		__SS_SET(prefix,nr), \
		__SS_SET(prefix,icookie), \
		__SS_SET(prefix,rcookie), \
		__SS_SET(prefix,secret), \
		__SS_SET(prefix,secretr), \
		\
		__SS_SET(prefix##_results,shared), \
		__SS_SET(prefix##_results,skeyseed), \
		__SS_SET(prefix##_results,skey_d), \
		__SS_SET(prefix##_results,skey_ai), \
		__SS_SET(prefix##_results,skey_ar), \
		__SS_SET(prefix##_results,skey_ei), \
		__SS_SET(prefix##_results,skey_er), \
		__SS_SET(prefix##_results,skey_pi), \
		__SS_SET(prefix##_results,skey_pr), \
		__SS_SET(prefix##_results,new_iv), \
		__SS_SET(prefix##_results,enc_key), \
		\
		##__VA_ARGS__ \
	)

#endif

