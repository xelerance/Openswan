struct connection;

/* status info */
extern void kernel_alg_show_status(void);
void kernel_alg_show_connection(struct connection *c, const char *instance);

struct ike_info;
#define IKEALGBUF_LEN strlen("00000_000-00000_000-00000")
extern char *alg_info_snprint_ike1(struct ike_info *ike_info
				   , int eklen, int aklen
				   , char *buf, int buflen);
