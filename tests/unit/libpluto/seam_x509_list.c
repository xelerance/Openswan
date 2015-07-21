/** by default pluto does not check crls dynamically */
long crl_check_interval = 0;

/* fetch.c SEAM */
void list_crl_fetch_requests(bool utc) {}

/* ac.c SEAM */
void decode_groups(char *groups, ietfAttrList_t **listp) {}
void load_acerts(void) {}
void list_acerts(bool utc) {}
void list_groups(bool utc) {}
void free_ietfAttrList(ietfAttrList_t* list) {}

/* x509.c SEAM */
void list_certs(bool utc) {}
void list_authcerts(const char *caption, u_char auth_flags, bool utc) {}
void list_crls(bool utc, bool strict) {}

