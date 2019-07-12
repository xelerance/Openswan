/* structure for use by constant->name array. This is private to constants.c and friends. */
struct enum_names {
    unsigned long en_first;  /* first value in range */
    unsigned long en_last;   /* last value in range (inclusive) */
    const char *const *en_names;
    const struct enum_names *en_next_range;	/* descriptor of next range */
};

struct enum_and_keyword_names {
  enum_names                 *official_names;
  struct keyword_enum_values  aliases;
};
