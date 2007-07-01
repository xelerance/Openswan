char *progname;

/* LINK seams */
void exit_log(const char *msg, ...)
{
    abort();
}

void exit_tool(int status)
{
    exit(status);
}

void exit_pluto(int status)
{
    exit(status);
}

void whack_log(int rc, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stderr, "RC=%u ", rc);
    vfprintf(stderr, msg, args);
    va_end(args);
}

void flush_pending_by_connection(struct connection *c) {}
void delete_states_by_connection(struct connection *c, bool relations) {}
void unroute_connection(struct connection *c) {}
void release_cert(cert_t cert) {}
bool trap_connection(struct connection *c) { return TRUE; }
void free_ietfAttrList(ietfAttrList_t* list) {}
void extra_debugging(const struct connection *c) {}
void perpeer_logfree(struct connection *c) {}
void add_pgp_public_key(pgpcert_t *cert , time_t until, enum dns_auth_level dns_auth_level) {}
pgpcert_t*pluto_add_pgpcert(pgpcert_t *cert) { return NULL; }
void add_x509_public_key(x509cert_t *cert , time_t until
			 , enum dns_auth_level dns_auth_level) {}
x509cert_t*add_x509cert(x509cert_t *cert) { return NULL; }

struct alg_info_ike *alg_info_ike_create_from_str (const char *alg_str, const char **err_p) {
    return NULL;
}
struct db_sa *kernel_alg_makedb(lset_t policy, struct alg_info_esp *ei, bool logit) {
    return NULL;
}
void free_sa(struct db_sa *f) {}
bool orient(struct connection *c) { return TRUE; }

/* ac.c SEAM */
void decode_groups(char *groups, ietfAttrList_t **listp) {}
void load_acerts(void) {}
void list_acerts(bool utc) {}
void list_groups(bool utc) {}

void gw_addref(struct gw_info *gw) {}
void gw_delref(struct gw_info **gwp) {}

bool in_pending_use(struct connection *c) { return FALSE; }
bool states_use_connection(struct connection *c) { return FALSE; }

err_t add_public_key(const struct id *id
		     , enum dns_auth_level dns_auth_level
		     , enum pubkey_alg alg
		     , const chunk_t *key
		     , struct pubkey_list **head) { return NULL; /* no error */ }


void transfer_to_public_keys(struct gw_info *gateways_from_dns
			     , struct pubkey_list **keys) {}

err_t start_adns_query(const struct id *id	/* domain to query */
		       , const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
		       , int type	/* T_TXT or T_KEY, selecting rr type of interest */
		       , cont_fn_t cont_fn
		       , struct adns_continuation *cr) {
    return NULL;   /* no error */
    /* SHOULD call continuation immediately with "NOT FOUND" */
}

/* state.c SEAM */
struct state *state_with_serialno(so_serial_t sn) { return NULL; }
void delete_state(struct state *st) {}
void delete_states_by_peer(ip_address *peer) {}

/* log.c SEAM */
void close_peerlog(void) {}
void daily_log_reset(void) {}

/* dnskey.c SEAM */
void reset_adns_restart_count(void) {}

/* server.c SEAM */
void find_ifaces(void) {}

/* keys.c SEAM */
void load_preshared_secrets(int whackfd) {}
chunk_t mysecret = { .ptr="abcd", .len=4 };
const chunk_t *get_preshared_secret(const struct connection *c) { return &mysecret; }

struct RSA_private_key f1;
const struct RSA_private_key *get_RSA_private_key(const struct connection *c) {
    return &f1;
}
void list_public_keys(bool utc) {}
void list_psks(void) {}

/* x509.c SEAM */
void load_crls(void) {}
void list_certs(bool utc) {}
void list_authcerts(const char *caption, u_char auth_flags, bool utc) {}
void list_crls(bool utc, bool strict) {}

/* timer.c SEAM */
void timer_list(void) {}

/* initiate.c SEAM */
void initiate_connection(const char *name, int whackfd
			 , lset_t moredebug
			 , enum crypto_importance importance) {}
void initiate_ondemand(const ip_address *our_client
		       , const ip_address *peer_client
		       , int transport_proto UNUSED
		       , bool held
		       , int whackfd
		       , err_t why) {}
void terminate_connection(const char *nm) {}
void show_status(void) {}


/* xauth.c SEAM */
oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth)
{ return 0; }






struct iface_port  *interfaces = NULL;	/* public interfaces */
struct connection *cur_connection = NULL;
enum kernel_interface kern_interface = NO_KERNEL;
u_int16_t pluto_port = 500;	/* Pluto's port */
bool can_do_IPcomp=TRUE;
bool nat_traversal_enabled=TRUE;
int whack_log_fd = NULL_FD;
struct pubkey_list *pluto_pubkeys = NULL;	/* keys from ipsec.conf */
bool listening = TRUE;
bool strict_crl_policy = FALSE;

/* efence defines */
extern int EF_DISABLE_BANNER;
extern int EF_ALIGNMENT;
extern int EF_PROTECT_BELOW;
extern int EF_PROTECT_FREE;
extern int EF_ALLOW_MALLOC_0;
extern int EF_FREE_WIPES;

void readwhackmsg(char *infile)
{
    int   len;
    int   iocount;
    FILE *record;
    char *infile;
    char  b1[8192];
    u_int32_t plen;

    if((record = fopen(infile, "r")) == NULL) {
	    perror(infile);
	    exit(9);
    }

    /* okay, eat first line, it's a comment, but log it. */
    fgets(b1, sizeof(b1), record);
    printf("Pre-amble: %s", b1);
    
    plen=0;
    while((iocount=fread(&plen, 4, 1, record))==1) {
	u_int32_t a[2];
	err_t ugh = NULL;
        struct whackpacker wp;
	struct whack_message m1;
	int abuflen;

	fread(&a, 4, 2, record);  /* eat time stamp */
	
	/* account for this header we just consumed */
	plen -= 12;

	/* round up to multiple of 4 */
	abuflen = (plen + 3) & ~0x3;

	if(abuflen > sizeof(m1)) {
	    fprintf(stderr, "whackmsg file has too big a record=%u > %u\n", abuflen, sizeof(m1));
	    exit(6);
	}

	if((iocount=fread(&m1, abuflen, 1, record)) != 1) {
	    if(feof(record)) break;
	    perror(infile);
	    exit(5);
	}
	
	if(plen <= 4) {
	    /* empty message */
	    continue;
	}

        wp.msg = &m1;
        wp.n   = plen;
        wp.str_next = m1.string;
        wp.str_roof = (unsigned char *)&m1 + plen;

        if ((ugh = unpack_whack_msg(&wp)) != NULL)
        {
            fprintf(stderr, "failed to parse whack msg: %s\n", ugh);
	    continue;
	}

	m1.keyval.ptr = wp.str_next;    /* grab chunk */

	/*
	 * okay, we have plen bytes in b1, so turn it into a whack
	 * message, and call whack_handle.
	 */
	whack_process(NULL_FD, m1);
    }

    if(iocount != 0 || !feof(record)) {
	perror(infile);
    }
	
    exit(0);
}
