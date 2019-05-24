/*
 * Algorithm info parsing and creation functions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Updated Michael Richardson Copyright 2017 <mcr@xelerance.com> for IKEv2
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#ifndef ALG_INFO_H
#define ALG_INFO_H

#include "constants.h"

/* this structure is private to the kernel implementation */
struct kernel_alg_info;

struct esp_info {
        bool     esp_default;
	u_int8_t transid;	/* ESP transform (AES, 3DES, etc.)*/
	u_int16_t auth;		/* AUTH */
	u_int32_t enckeylen;	/* keylength for ESP transform (bytes)*/
	u_int32_t authkeylen;	/* keylength for AUTH (bytes)*/
	u_int8_t encryptalg;	/* normally  encryptalg=transid */
	u_int16_t authalg;	/* normally  authalg=auth+1
				 * Paul: apparently related to magic at
				 * lib/libopenswan/alg_info.c alg_info_esp_aa2sadb() */
    int pfs_group;          /* IKEv1 thing */

    /*
     * these are filled in when the kernel module is asked if the algorithm
     * given in esp_info can be satified.
     */
    struct pluto_sadb_alg *encr_info;
    struct pluto_sadb_alg *auth_info;
    struct pluto_sadb_alg *compress_info;
};

struct ike_info {
    bool      ike_default;
    u_int16_t ike_ealg;	      /* encrytion algorithm - bit 15set for reserved*/
    u_int8_t  ike_halg;       /* hash algorithm */
    u_int8_t  ike_prfalg;     /* prf algorithm (IKEv2) */
    size_t    ike_eklen;      /* how many bits (of key) required by encryption algo */
    size_t    ike_hklen;      /* how many bits (of key) required by hash algo */
    enum ikev2_trans_type_dh ike_modp;  /* which modp group to use */
};

#define ALG_INFO_COMMON \
	int alg_info_cnt;		\
	int ref_cnt;			\
	unsigned alg_info_flags;	\
	unsigned alg_info_protoid

struct alg_info {
	ALG_INFO_COMMON;
};

struct alg_info_esp {
	ALG_INFO_COMMON;
	struct esp_info esp[64];
	int esp_pfsgroup;
};

struct alg_info_ike {
	ALG_INFO_COMMON;
	struct ike_info ike[64];
};

typedef void alg_info_adder(struct alg_info *alg_info
                            , enum ikev2_trans_type_encr  ealg_id, int ek_bits
                            , enum ikev2_trans_type_integ aalg_id, int ak_bits
                            , enum ikev2_trans_type_prf   prfalg_id UNUSED
                            , enum ikev2_trans_type_dh    modp_id);

#define ESPTOINFO(X) (struct alg_info *)X
#define IKETOINFO(X) (struct alg_info *)X

/* transition to these names */
#define esp_ealg_id transid
#define esp_aalg_id auth
#define esp_ealg_keylen enckeylen	/* bits */
#define esp_aalg_keylen authkeylen	/* bits */

/*	alg_info_flags bits */
#define ALG_INFO_F_STRICT	0x01

extern enum ipsec_authentication_algo
alg_info_esp_aa2sadb(enum ikev1_auth_attribute auth);
int alg_info_esp_sadb2aa(int sadb_aalg);
enum ikev1_auth_attribute
alg_info_esp_v2tov1aa(enum ikev2_trans_type_integ ti);

void alg_info_free(struct alg_info *alg_info);
void alg_info_addref(struct alg_info *alg_info);
void alg_info_delref(struct alg_info **alg_info);
struct alg_info_esp * alg_info_esp_create_from_str(const char *alg_str
						   , err_t *err_p);

struct alg_info_esp * alg_info_ah_create_from_str(const char *alg_str
						  , err_t *err_p);

struct alg_info_ike * alg_info_ike_create_from_str(const char *alg_str
						   , err_t *err_p);

/* generate list of defaults (all permutations) */
extern struct alg_info_ike *alg_info_ike_defaults(void);
extern struct alg_info_esp *alg_info_esp_defaults(void);

int alg_info_parse(const char *str);
int alg_info_snprint(char *buf, int buflen
		     , struct alg_info *alg_info);

void alg_info_snprint_ike(char *buf, size_t buflen, struct alg_info_ike *alg_info);
extern char *alg_info_snprint_ike2(struct ike_info *ike_info
                                   , int eklen, int aklen
                                   , int *usedsize
                                   , char *buf
                                   , int buflen);

#define ALG_INFO_ESP_FOREACH(ai, ai_esp, i) \
	for (i=(ai)->alg_info_cnt,ai_esp=(ai)->esp; i--; ai_esp++)
#define ALG_INFO_IKE_FOREACH(ai, ai_ike, i) \
	for (i=(ai)->alg_info_cnt,ai_ike=(ai)->ike; i--; ai_ike++)

extern int alg_enum_search_prefix (enum_names *ed, const char *prefix, const char *str, int str_len);
extern int alg_enum_search_ppfix (enum_names *ed, const char *prefix
				  , const char *postfix, const char *str
				  , int str_len);

struct parser_context;
struct oakley_group_desc;
extern int alg_info_parse_str (struct alg_info *alg_info
			       , const char *alg_str
			       , const char **err_p
			       , void (*parser_init)(struct parser_context *p_ctx)
                               , alg_info_adder alg_info_add
                               , const struct oakley_group_desc *(*lookup_group)(enum ikev2_trans_type_dh group));

/* translations between IKEv1 and IKEv2 */
/* this could be table driven */
extern int v2tov1_encr(enum ikev2_trans_type_encr encr);
extern enum ikev2_trans_type_encr v1tov2_encr(int encr);
extern int v2tov1_encr_child(enum ikev2_trans_type_encr encr);
extern int v2tov1_integ(enum ikev2_trans_type_integ v2integ);
enum ikev2_trans_type_integ v1tov2_integ(int integ);
extern int v2tov1_integ_child(enum ikev2_trans_type_integ v2integ);


#endif /* ALG_INFO_H */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
