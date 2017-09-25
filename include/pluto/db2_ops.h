/*	db_ops.h,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp	*/
#ifndef _DB2_OPS_H
#define _DB2_OPS_H

#include "pluto/spdb.h"

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
 *    +--- Proposal #1 ( Proto ID = AH(2), SPI size = 4,
 *    |     |            7 transforms,      SPI = 0x052357bb )
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
struct db2_context * db2_prop_new(int max_conj
                                  , int max_trans
                                  , int max_attrs);

/* (re-)initialize object for proposal building, returns 1 if everything okay
 * not needed if just called db2_prop_new.
 */
int db2_prop_init(struct db2_context *ctx
                  , int max_conj
                  , int max_trans
                  , int max_attrs);

/*	Clear out a db object */
void db2_destroy(struct db2_context *ctx);


/*	Free a db object itself, and things contained in it */
void db2_free(struct db2_context *ctx);

/*      Start with a new proposal */
int db2_prop_add(struct db2_context *ctx, u_int8_t protoid, u_int8_t spisize);

/*      Then add an alternative to a propsal */
int db2_prop_alternative(struct db2_context *ctx, u_int8_t protoid);

/*	Start a new transform */
int db2_trans_add(struct db2_context *ctx, u_int8_t transid, u_int8_t value);

/*	Add a new attribute by value */
int db2_attr_add(struct db2_context *ctx
                 , u_int16_t type
                 , u_int16_t val);

/*	Start a new transform */
void db2_prop_close(struct db2_context *ctx);

/*	Get proposal from db object */
static __inline__ struct db_v2_prop *db2_prop_get(struct db2_context *ctx) {
	return &ctx->prop;
}
/*	Show stats (allocation, etc) */
int db2_ops_show_status(void);

extern void db2_print(struct db2_context *ctx);
extern void sa_v2_print(struct db_sa *sa);

struct alg_info_ike;  /* forward reference */
struct alg_info_esp;  /* forward reference */
extern struct db_sa *alginfo2parent_db2(struct alg_info_ike *ai);
extern struct db_sa *alginfo2child_db2(struct alg_info_esp *ai);

#endif /* _DB2_OPS_H */
