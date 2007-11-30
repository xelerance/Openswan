
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
