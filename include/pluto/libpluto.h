
/*
 * endclient will format the end->client data, if the end has a
 * a client defined, but will otherwise show %any if not.
 * port takes 5 chars, protocol takes 3 chars, plus 2 for seperators, and null.
 *
 */
extern size_t endclienttot(const struct end *end, char *buf, size_t buflen);
#define	ENDCLIENTTOT_BUF	(SUBNETTOT_BUF+5+3+2+1)
