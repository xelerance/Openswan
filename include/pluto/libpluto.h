
/*
 * endclient will format the end->client data, if the end has a
 * a client defined, but will otherwise show %any if not.
 * future versions will include the port and protocol numbers.
 *
 */
extern size_t endclienttot(struct end *end, char *buf, size_t buflen);
#define	ENDCLIENTTOT_BUF	(SUBNETTOT_BUF)
