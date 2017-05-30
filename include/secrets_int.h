
enum field_type { PRIVATE, MODULUS, PUBLIC_E };
struct fld {
  const char *name;
  enum field_type type;
  size_t      offset;
};

extern const struct fld RSA_private_field[];
extern const int RSA_private_field_count;
