
/*
 *	Creates a new alg_info by parsing passed string
 */
struct parser_context {
  unsigned state, old_state;
  unsigned protoid;
  char ealg_buf[16];
  char aalg_buf[16];
  char prfalg_buf[16];
  char modp_buf[16];
  int (*ealg_getbyname)(const char *const str, int len, unsigned int *auxp);
  int (*aalg_getbyname)(const char *const str, int len, unsigned int *auxp);
  int (*prfalg_getbyname)(const char *const str, int len, unsigned int *auxp);
  int (*modp_getbyname)(const char *const str, int len, unsigned int *auxp);
  char *ealg_str;
  char *aalg_str;
  char *prfalg_str;
  char *modp_str;
  int eklen;
  int aklen;
  bool ealg_permit;
  bool aalg_permit;
  int ch;
  const char *err;
};

enum parser_state_esp {
        ST_INI,         /* parse esp= string */
	ST_INI_AA,      /* parse ah= string */
	ST_EA,		/* encrypt algo   */
	ST_EA_END,
	ST_EK,		/* enc. key length */
	ST_EK_END,
	ST_AA,		/* auth algo */
	ST_AA_END,
	ST_AK,		/* auth. key length */
	ST_AK_END,
        ST_PRF,
        ST_PRF_END,
	ST_MODP,	/* modp spec */
	ST_FLAG_STRICT,
	ST_END,
	ST_EOF,
	ST_ERR
};

/* exported for unit tests only */
extern int ealg_getbyname(const char *const str, int len, unsigned int *auxp);
extern int aalg_getbyname(const char *const str, int len, unsigned int *auxp);
extern int modp_getbyname(const char *const str, int len, unsigned int *auxp);

struct alg_info; /* forward reference */
extern void alg_info_esp_add (struct alg_info *alg_info,
                              int ealg_id, int ek_bits,
                              int aalg_id, int ak_bits,
                              int prfalg_id UNUSED,
                              int modp_id);
extern void alg_info_ah_add (struct alg_info *alg_info,
                             int ealg_id, int ek_bits,
                             int aalg_id, int ak_bits,
                             int prfalg_id UNUSED,
                             int modp_id);

