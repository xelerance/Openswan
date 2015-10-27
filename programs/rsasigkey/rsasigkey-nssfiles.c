/*#define NUM_KEYSTROKES 120*/
#define RAND_BUF_SIZE 60

#define GEN_BREAK(e) rv=e; break;

/* getModulus - returns modulus of the RSA public key */
SECItem *getModulus(SECKEYPublicKey *pk) { return &pk->u.rsa.modulus; }

/* getPublicExponent - returns public exponent of the RSA public key */
SECItem *getPublicExponent(SECKEYPublicKey *pk) { return &pk->u.rsa.publicExponent; }

/* Caller must ensure that dst is at least item->len*2+1 bytes long */
void SECItemToHex(const SECItem * item, char * dst)
{
    if (dst && item && item->data) {
	unsigned char * src = item->data;
	unsigned int    len = item->len;
	for (; len > 0; --len, dst += 2) {
		sprintf(dst, "%02x", *src++);
	}
	*dst = '\0';
    }
}

/*
 * hexOut - prepare hex output, guaranteeing even number of digits
 * The current OpenSWAN conversion routines expect an even digit count,
 * but the is no guarantee the data will have such length.
 * hexOut is like hexout but takes a SECItem *.
 */
char *hexOut(SECItem *data)
{
    unsigned i;
    static char hexbuf[3 + MAXBITS/4 + 1];
    char *hexp;

    memset(hexbuf, 0, 3 + MAXBITS/4 + 1);
    for (i = 0, hexp = hexbuf+3; i < data->len; i++, hexp += 2) {
	sprintf(hexp, "%02x", data->data[i]);
    }
    *hexp='\0';

    hexp = hexbuf+1;
    hexp[0] = '0';
    hexp[1] = 'x';

    return hexp;
}

/* UpdateRNG - Updates NSS's PRNG with user generated entropy. */
void UpdateNSS_RNG(void)
{
    SECStatus rv;
    unsigned char buf[RAND_BUF_SIZE];
    getrandom(RAND_BUF_SIZE, buf);
    rv = PK11_RandomUpdate(buf, sizeof buf);
    assert(rv == SECSuccess);
    memset(buf, 0, sizeof buf);
}

/*  Returns the password passed in in the text file.
 *  Uses the password once and nulls it out the prevent
 *  PKCS11 from calling us forever.
 */
char *GetFilePasswd(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    char* phrases, *phrase;
    PRFileDesc *fd;
    PRInt32 nb;
    const char *pwFile = (const char *)arg;
    int i;
    const long maxPwdFileSize = 4096;
    char* tokenName = NULL;
    int tokenLen = 0;

    if (!pwFile) {
	return 0;
    }

    if (retry) {
	return 0;  /* no good retrying - the files contents will be the same */
    }

    phrases = PORT_ZAlloc(maxPwdFileSize);

    if (!phrases) {
	return 0; /* out of memory */
    }

    fd = PR_Open(pwFile, PR_RDONLY, 0);
    if (!fd) {
	fprintf(stderr, "No password file \"%s\" exists.\n", pwFile);
	PORT_Free(phrases);
	return NULL;
    }
    nb = PR_Read(fd, phrases, maxPwdFileSize);

    PR_Close(fd);

    if (nb == 0) {
	fprintf(stderr,"password file contains no data\n");
	PORT_Free(phrases);
	return NULL;
    }

    if (slot) {
	tokenName = PK11_GetTokenName(slot);
	if (tokenName) {
	    tokenLen = PORT_Strlen(tokenName);
	}
    }
    i = 0;
    do {
	int startphrase = i;
	int phraseLen;
	/* handle the Windows EOL case */
	while (phrases[i] != '\r' && phrases[i] != '\n' && i < nb) i++;
	/* terminate passphrase */
	phrases[i++] = '\0';
	/* clean up any EOL before the start of the next passphrase */
	while ( (i<nb) && (phrases[i] == '\r' || phrases[i] == '\n')) {
		phrases[i++] = '\0';
	}
	/* now analyze the current passphrase */
	phrase = &phrases[startphrase];
	if (!tokenName)
		break;
	if (PORT_Strncmp(phrase, tokenName, tokenLen)) continue;
	phraseLen = PORT_Strlen(phrase);
	if (phraseLen < (tokenLen+1)) continue;
	if (phrase[tokenLen] != ':') continue;
	phrase = &phrase[tokenLen+1];
	break;
    } while (i<nb);

    phrase = PORT_Strdup((char*)phrase);
    PORT_Free(phrases);
    return phrase;
}

char *GetModulePassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
    secuPWData *pwdata = (secuPWData *)arg;
    secuPWData pwnull = { PW_NONE, 0 };
    secuPWData pwxtrn = { PW_EXTERNAL, "external" };
    char *pw;

    if (pwdata == NULL) {
	pwdata = &pwnull;
    }

    if (PK11_ProtectedAuthenticationPath(slot)) {
	pwdata = &pwxtrn;
    }
    if (retry && pwdata->source != PW_NONE) {
	fprintf(stderr, "%s: Incorrect password/PIN entered.\n", me);
	return NULL;
    }

    switch (pwdata->source) {
	case PW_FROMFILE:
		/* Instead of opening and closing the file every time, get the pw
		* once, then keep it in memory (duh).
		*/
		pw = GetFilePasswd(slot, retry, pwdata->data);
		pwdata->source = PW_PLAINTEXT;
		pwdata->data = strdup(pw);
		/* it's already been dup'ed */
		return pw;
	case PW_PLAINTEXT:
		return strdup(pwdata->data);
	default: /* cases PW_NONE and PW_EXTERNAL not supported */
		fprintf(stderr, "Unknown or unsupported case in GetModulePassword");
		break;
    }

    fprintf(stderr, "%s: Password check failed:  No password found.\n", me);
    return NULL;
}
