/*	db_ops.h,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp	*/
#ifndef _DB_OPS_H
#define _DB_OPS_H

#include "spdb.h"

/*
 * from RFC7296, section 3.3:
 *
 * SA Payload
 *    |
 *    +--- Proposal #1 ( Proto ID = ESP(3), SPI size = 4,
 *    |     |            7 transforms,      SPI = 0x052357bb )
 *    |     |
 *    |     +-- Transform ENCR ( Name = ENCR_AES_CBC )
 *    |     |     +-- Attribute ( Key Length = 128 )
 *    |     |
 *    |     +-- Transform ENCR ( Name = ENCR_AES_CBC )
 *    |     |     +-- Attribute ( Key Length = 192 )
 *    |     |
 *    |     +-- Transform ENCR ( Name = ENCR_AES_CBC )
 *    |     |     +-- Attribute ( Key Length = 256 )
 *    |     |
 *    |     +-- Transform INTEG ( Name = AUTH_HMAC_SHA1_96 )
 *    |     +-- Transform INTEG ( Name = AUTH_AES_XCBC_96 )
 *    |     +-- Transform ESN ( Name = ESNs )
 *    |     +-- Transform ESN ( Name = No ESNs )
 *    |
 *    +--- Proposal #2 ( Proto ID = ESP(3), SPI size = 4,
 *          |            4 transforms,      SPI = 0x35a1d6f2 )
 *          |
 *          +-- Transform ENCR ( Name = AES-GCM with a 8 octet ICV )
 *          |     +-- Attribute ( Key Length = 128 )
 *          |
 *          +-- Transform ENCR ( Name = AES-GCM with a 8 octet ICV )
 *          |     +-- Attribute ( Key Length = 256 )
 *          |
 *          +-- Transform ESN ( Name = ESNs )
 *          +-- Transform ESN ( Name = No ESNs )
 *
 *
 */

/*
 * 	Main db object, (quite proposal "oriented")
 */
struct db2_context {
  struct db_v2_prop prop;	/* proposal buffer (not pointer) */
  struct db_v2_prop_conj *conj0;
  int                     max_conj;	/* size of conj  list */
  struct db_v2_prop_conj *conj_cur;

  struct db_v2_trans     *trans0;  /* transf. list, dynamically sized */
  int                     max_trans;    /* size of trans list */
  struct db_v2_trans *trans_cur;  /* current transform ptr */

  struct db_v2_attr *attrs0;	  /* attr. list, dynamically sized */
  struct db_v2_attr *attrs_cur;	  /* current attribute ptr */
  int max_attrs;	          /* size of attrs list */
};

/*
 * 	Allocate a new db object
 */
struct db2_context * db2_prop_new(u_int8_t protoid
                                  , int max_conj
                                  , int max_trans
                                  , int max_attrs);

/* Initialize object for proposal building  */
int db2_prop_init(struct db2_context *ctx
                  , u_int8_t protoid
                  , int max_conj
                  , int max_trans
                  , int max_attrs);

/*	Free all resourses for this db */
void db2_destroy(struct db2_context *ctx);

/*	Start a new transform */
int db2_trans_add(struct db2_context *ctx, u_int8_t transid);

/*	Add a new attribute by copying db_attr content */
int db2_attr_add(struct db2_context *db_ctx, const struct db_attr *attr);

/*	Add a new attribute by value */
int db2_attr_add_values(struct db2_context *ctx
                       , u_int16_t type
                       , u_int16_t val);

/*	Get proposal from db object */
static __inline__ struct db2_prop *db2_prop_get(struct db2_context *ctx) {
	return &ctx->prop;
}
/*	Show stats (allocation, etc) */
int db2_ops_show_status(void);

extern void db2_print(struct db2_context *ctx);

#endif /* _DB_OPS_H */
