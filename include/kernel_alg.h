/*
 * Kernel runtime algorithm handling interface definitions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * kernel_alg.h,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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

#ifndef _KERNEL_ALG_H
#define _KERNEL_ALG_H
#include "openswan/pfkeyv2.h"

struct kernel_alg_info;

/* this needs to be unified with kernel_alg_info */
struct pluto_sadb_alg {
  struct sadb_alg          kernel_sadb_alg;   /* data from the kernel
                                                 as to capabilities */
  struct kernel_alg_info  *kernel_alg_info;   /* private to the kernel
                                                 implementation */
  enum   ikev2_trans_type        exttype;   /* encryption or integrity
                                               (aka alg_type) */
  enum   ikev2_trans_type_encr   encr_id;   /* this IKEv2 algorithm number */
  enum   ikev2_trans_type_integ  integ_id;  /* ditto */

  /* this is a hold-over from IKEv1 infested code */
  uint8_t		         sadb_alg_id;
  uint8_t		         sadb_alg_ivlen;
  uint16_t	                 sadb_alg_minbits;
  uint16_t	                 sadb_alg_maxbits;
};
struct sadb_msg; /* forward definition */

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(const struct sadb_msg *msg, int buflen);

struct alg_info;
struct esp_info;
struct alg_info_ike;
struct alg_info_esp;
/* call this before anything else */
extern void kernel_alg_init(void);
/* ESP interface */
extern struct pluto_sadb_alg *kernel_alg_esp_sadb_alg(int alg_id);
extern struct pluto_sadb_alg *kernel_alg_esp_sadb_aalg(int alg_id);
extern int kernel_alg_esp_ivlen(int alg_id);
/* returns bool success if esp encrypt alg is present  */
extern err_t kernel_alg_esp_enc_ok(int alg_id, unsigned int key_len, struct alg_info_esp *nfo);
extern bool kernel_alg_esp_ok_final(int ealg, unsigned int key_len, int aalg, struct alg_info_esp *alg_info);

/* returns encrypt keylen in BYTES for esp enc alg passed */
extern int kernel_alg_esp_enc_keylen(int alg_id);

/* returns bool success if esp auth alg is present  */
extern err_t kernel_alg_esp_auth_ok(int auth, struct alg_info_esp *nfo);
extern err_t kernel_alg_ah_auth_ok(int auth,struct alg_info_esp *alg_info);


/* returns auth keylen in BYTES for esp auth alg passed */
extern int kernel_alg_esp_auth_keylen(enum ikev2_trans_type_integ authnum);
extern int kernel_alg_ah_auth_keylen(enum ikev2_trans_type_integ authnum);

/* returns 0 if read ok from /proc/net/pf_key_supported */
extern int kernel_alg_proc_read(void);

/* get sadb_alg for passed args */
extern const struct pluto_sadb_alg * kernel_alg_sadb_alg_get(int satype, int exttype, int alg_id);

struct db_prop;
extern struct db_context * kernel_alg_db_new(struct alg_info_esp *ai
					     , lset_t policy
					     , bool logit);

/* returns pointer to static buffer, no reentrant */
extern bool kernel_alg_ikev2_esp_info(struct esp_info *ei
                                      , enum ikev2_trans_type_encr sadb_ealg
                                      , u_int16_t keylen
                                      , enum ikev2_trans_type_integ sadb_aalg);

extern struct esp_info *kernel_alg_esp_info(u_int8_t transid
					    , u_int16_t keylen
					    , u_int16_t auth);

/* indexed by kernel algorithm number */
extern struct pluto_sadb_alg esp_aalg[];
extern struct pluto_sadb_alg esp_ealg[];
extern int esp_ealg_num;
extern int esp_aalg_num;

#define ESP_EALG_VALID(algo)   ((algo)<=K_SADB_EALG_MAX)
#define ESP_EALG_PRESENT(algo) (ESP_EALG_VALID(algo) && (esp_ealg[(algo)].kernel_sadb_alg.sadb_alg_id!=0))
#define ESP_EALG_FOR_EACH(algo) \
	for (algo=1; algo <= K_SADB_EALG_MAX; algo++) \
		if (ESP_EALG_PRESENT(algo))
#define ESP_EALG_FOR_EACH_UPDOWN(algo) \
	for (algo=K_SADB_EALG_MAX; algo >0 ; algo--) \
		if (ESP_EALG_PRESENT(algo))
#define ESP_AALG_VALID(algo)   ((algo)<=SADB_AALG_MAX)
#define ESP_AALG_PRESENT(algo) (ESP_AALG_VALID(algo) && (esp_aalg[(algo)].kernel_sadb_alg.sadb_alg_id!=0))
#define ESP_AALG_FOR_EACH(algo) \
	for (algo=1; algo <= SADB_AALG_MAX; algo++) \
		if (ESP_AALG_PRESENT(algo))
#define ESP_AALG_FOR_EACH_UPDOWN(algo) \
	for (algo=SADB_AALG_MAX; algo >0 ; algo--) \
		if (ESP_AALG_PRESENT(algo))

/* used by test skaffold -- sadb_alg as if it came from kernel */
extern int kernel_alg_add(int satype, int exttype
			  , const struct sadb_alg *sadb_alg);

extern enum ikev2_trans_type_integ kernelalg2ikev2(enum ipsec_authentication_algo kernel_integ);

#endif /* _KERNEL_ALG_H */
