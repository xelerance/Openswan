/*
 * RSA signature key generation
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com> 
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com> 
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <openswan.h>
#include <gmp.h>

#ifdef HAVE_LIBNSS
  /* nspr */
# include <prerror.h>
# include <prinit.h>
# include <prmem.h>
# include <plstr.h>
  /* nss */
# include <key.h>
# include <keyt.h>
# include <nss.h>
# include <pk11pub.h>
# include <seccomon.h>
# include <secerr.h>
# include <secport.h>
# include <time.h>

# include "constants.h"
# include "oswalloc.h"
# include "oswlog.h"
# include "oswconf.h"

# ifdef FIPS_CHECK
#  include <fipscheck.h>
# endif
#endif

#ifndef DEVICE
/* To the openwrt people: Do not change /dev/random to /dev/urandom. The
 * /dev/random device is ONLY used for generating long term keys, which
 * should NEVER be done with /dev/urandom. If people use X.509, PSK or
 * even raw RSA keys generated on other systems, changing this will have
 * 0 effect. It's better to fail or bail out of generating a key, then
 * generate a bad one.
 */
#define	DEVICE	"/dev/random"
#endif
#ifndef MAXBITS
#define	MAXBITS	20000
#endif

/* the code in getoldkey() knows about this */
#define	E	3		/* standard public exponent */

#ifdef HAVE_LIBNSS
/*#define F4	65537*/	/* preferred public exponent, Fermat's 4th number */
char usage[] = "rsasigkey [--verbose] [--random device] [--configdir dir] [--password password] nbits [--hostname host] [--noopt] [--rounds num]";
#else
char usage[] = "rsasigkey [--verbose] [--random device] nbits [--hostname host] [--noopt] [--rounds num]";
char usage2[] = "rsasigkey [--verbose] --oldkey filename";
#endif
struct option opts[] = {
  {"verbose",	0,	NULL,	'v',},
  {"random",	1,	NULL,	'r',},
  {"rounds",	1,	NULL,	'p',},
  {"oldkey",	1,	NULL,	'o',},
  {"hostname",	1,	NULL,	'H',},
  {"noopt",	0,	NULL,	'n',},
  {"help",		0,	NULL,	'h',},
  {"version",	0,	NULL,	'V',},
#ifdef HAVE_LIBNSS
  {"configdir",        1,      NULL,   'c' },
  {"password", 1,      NULL,   'P' },
#endif
  {0,		0,	NULL,	0,}
};
int verbose = 0;		/* narrate the action? */
char *device = DEVICE;		/* where to get randomness */
int nrounds = 30;		/* rounds of prime checking; 25 is good */
mpz_t prime1;			/* old key's prime1 */
mpz_t prime2;			/* old key's prime2 */
char outputhostname[1024];	/* hostname for output */
int do_lcm = 1;			/* use lcm(p-1, q-1), not (p-1)*(q-1) */

char me[] = "ipsec rsasigkey";	/* for messages */

/* forwards */
int getoldkey(char *filename);
#ifdef HAVE_LIBNSS
void rsasigkey(int nbits, char *configdir, char *password);
#else
void rsasigkey(int nbits, int useoldkey);
#endif
void initprime(mpz_t var, int nbits, int eval);
void initrandom(mpz_t var, int nbits);
void getrandom(size_t nbytes, unsigned char *buf);
unsigned char *bundle(int e, mpz_t n, size_t *sizep);
char *conv(unsigned char *bits, size_t nbytes, int format);
char *hexout(mpz_t var);
void report(char *msg);

#ifdef HAVE_LIBNSS

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
#endif /* HAVE_LIBNSS */

/*
 - main - mostly argument parsing
 */
int main(int argc, char *argv[])
{
	int opt;
	extern int optind;
	extern char *optarg;
	int errflg = 0;
	int i;
	int nbits;
	char *oldkeyfile = NULL;
#ifdef HAVE_LIBNSS
	char *configdir = NULL; /* where the NSS databases reside */
	char *password = NULL;  /* password for token authentication */
#endif

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF)
		switch (opt) {
		case 'v':	/* verbose description */
			verbose = 1;
			break;
		case 'r':	/* nonstandard /dev/random */
			device = optarg;
			break;
		case 'p':	/* number of prime-check rounds */
			nrounds = atoi(optarg);
			if (nrounds <= 0) {
				fprintf(stderr, "%s: rounds must be > 0\n", me);
				exit(2);
			}
			break;
		case 'o':	/* reformat old key */
			oldkeyfile = optarg;
			break;
		case 'H':	/* set hostname for output */
			strcpy(outputhostname, optarg);
			break;
		case 'n':	/* don't optimize the private key */
			do_lcm = 0;
			break;
		case 'h':	/* help */
			printf("Usage:\t%s\n", usage);
#ifndef HAVE_LIBNSS
			printf("\tor\n");
			printf("\t%s\n", usage2);
#endif
			exit(0);
			break;
		case 'V':	/* version */
			printf("%s %s\n", me, ipsec_version_code());
			exit(0);
			break;
#ifdef HAVE_LIBNSS
		case 'c':       /* nss configuration directory */
			configdir = optarg;
			break;
		case 'P':       /* token authentication password */
			password = optarg;
			break;
#endif
		case '?':
		default:
			errflg = 1;
			break;
		}
#ifdef HAVE_LIBNSS
	if (errflg || optind != argc-1) {
		printf("Usage:\t%s\n", usage);
		exit(2);
	}
#else
	if (errflg || optind != ((oldkeyfile != NULL) ? argc : argc-1)) {
		printf("Usage:\t%s\n", usage);
		printf("\tor\n");
		printf("\t%s\n", usage2);
		exit(2);
	}
#endif

	if (outputhostname[0] == '\0') {
		i = gethostname(outputhostname, sizeof(outputhostname));
		if (i < 0) {
			fprintf(stderr, "%s: gethostname failed (%s)\n",
				me,
				strerror(errno));
			exit(1);
		}
	}

	if (oldkeyfile == NULL) {
		assert(argv[optind] != NULL);
		nbits = atoi(argv[optind]);
	} else
		nbits = getoldkey(oldkeyfile);

	if (nbits <= 0) {
		fprintf(stderr, "%s: invalid bit count (%d)\n", me, nbits);
		exit(1);
	} else if (nbits > MAXBITS) {
		fprintf(stderr, "%s: overlarge bit count (max %d)\n", me,
								MAXBITS);
		exit(1);
	} else if (nbits % (CHAR_BIT*2) != 0) {	/* *2 for nbits/2-bit primes */
		fprintf(stderr, "%s: bit count (%d) not multiple of %d\n", me,
						nbits, (int)CHAR_BIT*2);
		exit(1);
	}

#ifdef HAVE_LIBNSS
	rsasigkey(nbits, configdir, password);
#else
	rsasigkey(nbits, (oldkeyfile == NULL) ? 0 : 1);
#endif
	exit(0);
}

/*
 - getoldkey - fetch an old key's primes
 */
int				/* nbits */
getoldkey(filename)
char *filename;
{
#ifdef OLD_GCC
	fprintf(stderr, "%s: getoldkey is broken\n", me);
	exit(1);
#else
	FILE *f;
	char line[MAXBITS/2];
	char *p;
	char *value;
	static char pube[] = "PublicExponent:";
	static char pubevalue[] = "0x03";
	static char pr1[] = "Prime1:";
	static char pr2[] = "Prime2:";
#	define	STREQ(a, b)	(strcmp(a, b) == 0)
	int sawpube = 0;
	int sawpr1 = 0;
	int sawpr2 = 0;
	int nbits;
	char fsin[2];
	fsin[0]='-'; /*file stdin*/
	fsin[1]='\0';

	nbits = 0;
 
	if (STREQ(filename, fsin))
		f = stdin;
	else
		f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "%s: unable to open file `%s' (%s)\n", me,
						filename, strerror(errno));
		exit(1);
	}
	if (verbose)
		fprintf(stderr, "getting old key from %s...\n", filename);

	while (fgets(line, sizeof(line), f) != NULL) {
		p = line + strlen(line) - 1;
		if (*p != '\n') {
			fprintf(stderr, "%s: over-long line in file `%s'\n",
							me, filename);
			exit(1);
		}
		*p = '\0';

		p = line + strspn(line, " \t");		/* p -> first word */
		value = strpbrk(p, " \t");		/* value -> after it */
		if (value != NULL) {
			*value++ = '\0';
			value += strspn(value, " \t");
			/* value -> second word if any */
		}

		if (value == NULL || *value == '\0') {
			/* wrong format */
		} else if (STREQ(p, pube)) {
			sawpube = 1;
			if (!STREQ(value, pubevalue)) {
				fprintf(stderr, "%s: wrong public exponent (`%s') in old key\n",
					me, value);
				exit(1);
			}
		} else if (STREQ(p, pr1)) {
			if (sawpr1) {
				fprintf(stderr, "%s: duplicate `%s' lines in `%s'\n",
					me, pr1, filename);
				exit(1);
			}
			sawpr1 = 1;
			nbits = (strlen(value) - 2) * 4 * 2;
			if (mpz_init_set_str(prime1, value, 0) < 0) {
				fprintf(stderr, "%s: conversion error in reading old prime1\n",
					me);
				exit(1);
			}
		} else if (STREQ(p, pr2)) {
			if (sawpr2) {
				fprintf(stderr, "%s: duplicate `%s' lines in `%s'\n",
					me, pr2, filename);
				exit(1);
			}
			sawpr2 = 1;
			if (mpz_init_set_str(prime2, value, 0) < 0) {
				fprintf(stderr, "%s: conversion error in reading old prime2\n",
					me);
				exit(1);
			}
		}
	}
	
	if (f != stdin)
		fclose(f);

	if (!sawpube || !sawpr1 || !sawpr2) {
		fprintf(stderr, "%s: old key missing or incomplete\n", me);
		exit(1);
	}

	assert(sawpr1);		/* and thus nbits is known */
	return(nbits);
#endif
}

/*
 - rsasigkey - generate an RSA signature key
 * e is fixed at 3, without discussion.  That would not be wise if these
 * keys were to be used for encryption, but for signatures there are some
 * real speed advantages.
 */

#ifdef HAVE_LIBNSS
/* Generates an RSA signature key using nss.
 * Curretly e is fixed at 3, but we may change that.  We may
 * use F4 if preformance doesn't degrade much realative to 3.
 * Notice that useoldkey is not yet supported.
 */
void
rsasigkey(int nbits, char *configdir, char *password)
{
    SECStatus rv;
    PRBool nss_initialized          = PR_FALSE;
    PK11RSAGenParams rsaparams      = { nbits, (long) E };
    secuPWData  pwdata              = { PW_NONE, NULL };
    PK11SlotInfo *slot              = NULL;
    SECKEYPrivateKey *privkey       = NULL;
    SECKEYPublicKey *pubkey         = NULL;
    unsigned char *bundp            = NULL;
    mpz_t n;
    mpz_t e;
    size_t bs;
    char n_str[3 + MAXBITS/4 + 1];
    char buf[100];
    time_t now = time((time_t *)NULL);

    mpz_init(n);
    mpz_init(e);

    pwdata.source = password ? PW_PLAINTEXT : PW_NONE;
    pwdata.data = password ? password : NULL;

    do {
	if (!configdir) {
		fprintf(stderr, "%s: configdir is required\n", me);
		return;
	}

	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);
	snprintf(buf, sizeof(buf), "%s",configdir);
	if ((rv = NSS_InitReadWrite(buf)) != SECSuccess) {
		fprintf(stderr, "%s: NSS_InitReadWrite returned %d\n", me, PR_GetError());
		break;
	}
#ifdef FIPS_CHECK
	if (PK11_IsFIPS() && !FIPSCHECK_verify(NULL, NULL)) {
		printf("FIPS integrity verification test failed.\n");
		exit(1);
	}
#endif 

	if (PK11_IsFIPS() && !password) {
		fprintf(stderr, "%s: On FIPS mode a password is required\n", me);
		break;
	}

	PK11_SetPasswordFunc(GetModulePassword);
	nss_initialized = PR_TRUE;

	/* Good for now but someone may want to use a hardware token */
	slot = PK11_GetInternalKeySlot();
	/* In which case this may be better */
	/* slot = PK11_GetBestSlot(CKM_RSA_PKCS_KEY_PAIR_GEN, password ? &pwdata : NULL); */
	/* or the user may specify the name of a token. */

	/*if (PK11_IsFIPS() || !PK11_IsInternal(slot)) {
		rv = PK11_Authenticate(slot, PR_FALSE, &pwdata);
		if (rv != SECSuccess) {
			fprintf(stderr, "%s: could not authenticate to token '%s'\n",
				me, PK11_GetTokenName(slot));
			GEN_BREAK(SECFailure);
		}
	}*/

	/* Do some random-number initialization. */
	UpdateNSS_RNG();
	/* Log in to the token */
	if (password) {
	    rv = PK11_Authenticate(slot, PR_FALSE, &pwdata);
	    if (rv != SECSuccess) {
		fprintf(stderr, "%s: could not authenticate to token '%s'\n",
			me, PK11_GetTokenName(slot));
		GEN_BREAK(SECFailure);
	    }
	}
	privkey = PK11_GenerateKeyPair(slot
		, CKM_RSA_PKCS_KEY_PAIR_GEN, &rsaparams, &pubkey
		, PR_TRUE, password ? PR_TRUE : PR_FALSE, &pwdata);
	/* inTheToken, isSensitive, passwordCallbackFunction */
	if (!privkey) {
		fprintf(stderr, "%s: key pair generation failed: \"%d\"\n", me, PORT_GetError());
		GEN_BREAK(SECFailure);
	}

	/*privkey->wincx = &pwdata;*/
	PORT_Assert(pubkey != NULL);
	fprintf(stderr, "Generated RSA key pair using the NSS database\n");
       
	SECItemToHex(getModulus(pubkey), n_str);
	assert(!mpz_set_str(n, n_str, 16));

	/* and the output */
	/* note, getoldkey() knows about some of this */
	report("output...\n");          /* deliberate extra newline */
	printf("\t# RSA %d bits   %s   %s", nbits, outputhostname, ctime(&now));
                                                       /* ctime provides \n */
	printf("\t# for signatures only, UNSAFE FOR ENCRYPTION\n");
	bundp = bundle(E, n, &bs);
	printf("\t#pubkey=%s\n", conv(bundp, bs, 's')); /* RFC2537ish format */
	printf("\tModulus: %s\n", hexOut(getModulus(pubkey)));
	printf("\tPublicExponent: %s\n", hexOut(getPublicExponent(pubkey)));

	SECItem *ckaID=PK11_MakeIDFromPubKey(getModulus(pubkey));
	if(ckaID!=NULL) {
		printf("\t# everything after this point is CKA_ID in hex format when using NSS\n");
		printf("\tPrivateExponent: %s\n", hexOut(ckaID));
		printf("\tPrime1: %s\n", hexOut(ckaID));
		printf("\tPrime2: %s\n", hexOut(ckaID));
		printf("\tExponent1: %s\n", hexOut(ckaID));
		printf("\tExponent2: %s\n", hexOut(ckaID));
		printf("\tCoefficient: %s\n", hexOut(ckaID));
		printf("\tCKAIDNSS: %s\n", hexOut(ckaID));
		SECITEM_FreeItem(ckaID, PR_TRUE);
	}

	} while(0);

    if (privkey) SECKEY_DestroyPrivateKey(privkey);
    if (pubkey) SECKEY_DestroyPublicKey(pubkey);    

    if (nss_initialized) {
	(void) NSS_Shutdown();
    }
    (void) PR_Cleanup();
}
#else
void
rsasigkey(nbits, useoldkey)
int nbits;
int useoldkey;			/* take primes from old key? */
{
	mpz_t p;
	mpz_t q;
	mpz_t n;
	mpz_t e;
	mpz_t d;
	mpz_t q1;			/* temporary */
	mpz_t m;			/* internal modulus, (p-1)*(q-1) */
	mpz_t t;			/* temporary */
	mpz_t exp1;
	mpz_t exp2;
	mpz_t coeff;
	unsigned char *bundp;
	size_t bs;
	int success;
	time_t now = time((time_t *)NULL);

	/* the easy stuff */
	if (useoldkey) {
		mpz_init_set(p, prime1);
		mpz_init_set(q, prime2);
	} else {
		initprime(p, nbits/2, E);
		initprime(q, nbits/2, E);
	}
	mpz_init(t);
	if (mpz_cmp(p, q) < 0) {
		report("swapping primes so p is the larger...");
		mpz_set(t, p);
		mpz_set(p, q);
		mpz_set(q, t);
	}
	report("computing modulus...");
	mpz_init(n);
	mpz_mul(n, p, q);		/* n = p*q */
	mpz_init_set_ui(e, E);

	/* internal modulus */
	report("computing lcm(p-1, q-1)...");
	mpz_init_set(m, p);
	mpz_sub_ui(m, m, 1);
	mpz_init_set(q1, q);
	mpz_sub_ui(q1, q1, 1);
	mpz_gcd(t, m, q1);		/* t = gcd(p-1, q-1) */
	mpz_mul(m, m, q1);		/* m = (p-1)*(q-1) */
	if (do_lcm)
		mpz_divexact(m, m, t);		/* m = lcm(p-1, q-1) */
	mpz_gcd(t, m, e);
	assert(mpz_cmp_ui(t, 1) == 0);	/* m and e relatively prime */

	/* decryption key */
	report("computing d...");
	mpz_init(d);
	success = mpz_invert(d, e, m);
	assert(success);		/* e has an inverse mod m */
	if (mpz_cmp_ui(d, 0) < 0)
		mpz_add(d, d, m);
	assert(mpz_cmp(d, m) < 0);

	/* the speedup hacks */
	report("computing exp1, exp1, coeff...");
	mpz_init(exp1);
	mpz_sub_ui(t, p, 1);
	mpz_mod(exp1, d, t);		/* exp1 = d mod p-1 */
	mpz_init(exp2);
	mpz_sub_ui(t, q, 1);
	mpz_mod(exp2, d, t);		/* exp2 = d mod q-1 */
	mpz_init(coeff);
	mpz_invert(coeff, q, p);	/* coeff = q^-1 mod p */
	if (mpz_cmp_ui(coeff, 0) < 0)
		mpz_add(coeff, coeff, p);
	assert(mpz_cmp(coeff, p) < 0);

	/* and the output */
	/* note, getoldkey() knows about some of this */
	report("output...\n");		/* deliberate extra newline */
	printf("\t# RSA %d bits   %s   %s", nbits, outputhostname, ctime(&now));
							/* ctime provides \n */
	printf("\t# for signatures only, UNSAFE FOR ENCRYPTION\n");
	bundp = bundle(E, n, &bs);
	printf("\t#pubkey=%s\n", conv(bundp, bs, 's'));	/* RFC2537ish format */
	printf("\tModulus: %s\n", hexout(n));
	printf("\tPublicExponent: %s\n", hexout(e));
	printf("\t# everything after this point is secret\n");
	printf("\tPrivateExponent: %s\n", hexout(d));
	printf("\tPrime1: %s\n", hexout(p));
	printf("\tPrime2: %s\n", hexout(q));
	printf("\tExponent1: %s\n", hexout(exp1));
	printf("\tExponent2: %s\n", hexout(exp2));
	printf("\tCoefficient: %s\n", hexout(coeff));
}
#endif

#ifndef HAVE_LIBNSS
/*
 - initprime - initialize an mpz_t to a random prime of specified size
 * Efficiency tweak:  we reject candidates that are 1 higher than a multiple
 * of e, since they will make the internal modulus not relatively prime to e.
 */
void
initprime(var, nbits, eval)
mpz_t var;
int nbits;			/* known to be a multiple of CHAR_BIT */
int eval;			/* value of e; 0 means don't bother w. tweak */
{
	unsigned long tries;
	size_t len;
#	define	OKAY(p)	(eval == 0 || mpz_fdiv_ui(p, eval) != 1)

	initrandom(var, nbits);
	assert(mpz_fdiv_ui(var, 2) == 1);	/* odd number */

	report("looking for a prime starting there (can take a while)...");
	tries = 1;
	while (!( OKAY(var) && mpz_probab_prime_p(var, nrounds) )) {
		mpz_add_ui(var, var, 2);
		tries++;
	}

	len = mpz_sizeinbase(var, 2);
	assert(len == (size_t)nbits || len == (size_t)(nbits+1));
	if (len == (size_t)(nbits+1)) {
		report("carry out occurred (!), retrying...");
		mpz_clear(var);
		initprime(var, nbits, eval);
		return;
	}
	if (verbose)
		fprintf(stderr, "found it after %lu tries.\n", tries);
}

/*
 - initrandom - initialize an mpz_t to a random number, specified bit count
 * Converting via hex is a bit weird, but it's the best route GMP gives us.
 * Note that highmost and lowmost bits are forced on -- highmost to give a
 * number of exactly the specified length, lowmost so it is an odd number.
 */
void
initrandom(var, nbits)
mpz_t var;
int nbits;			/* known to be a multiple of CHAR_BIT */
{
	size_t nbytes = (size_t)(nbits / CHAR_BIT);
	static unsigned char bitbuf[MAXBITS/CHAR_BIT];
	static char hexbuf[2 + MAXBITS/4 + 1];
	size_t hsize = sizeof(hexbuf);

	assert(nbytes <= sizeof(bitbuf));
	getrandom(nbytes, bitbuf);
	bitbuf[0] |= 01 << (CHAR_BIT-1);	/* force high bit on */
	bitbuf[nbytes-1] |= 01;			/* force low bit on */
	if (datatot(bitbuf, nbytes, 'x', hexbuf, hsize) > hsize) {
		fprintf(stderr, "%s: can't-happen buffer overflow\n", me);
		exit(1);
	}
	if (mpz_init_set_str(var, hexbuf, 0) < 0) {
		fprintf(stderr, "%s: can't-happen hex conversion error\n", me);
		exit(1);
	}
}
#endif

/*
 - getrandom - get some random bytes from /dev/random (or wherever)
 */
void
getrandom(nbytes, buf)
size_t nbytes;
unsigned char *buf;			/* known to be big enough */
{
	size_t ndone;
	int dev;
	ssize_t got;

	dev = open(device, 0);
	if (dev < 0) {
		fprintf(stderr, "%s: could not open %s (%s)\n", me,
						device, strerror(errno));
		exit(1);
	}

	ndone = 0;
	if (verbose)
		fprintf(stderr, "getting %d random bytes from %s...\n", (int) nbytes,
							device);
	while (ndone < nbytes) {
		got = read(dev, buf + ndone, nbytes - ndone);
		if (got < 0) {
			fprintf(stderr, "%s: read error on %s (%s)\n", me,
						device, strerror(errno));
			exit(1);
		}
		if (got == 0) {
			fprintf(stderr, "%s: eof on %s!?!\n", me, device);
			exit(1);
		}
		ndone += got;
	}

	close(dev);
}

/*
 - hexout - prepare hex output, guaranteeing even number of digits
 * (The current FreeS/WAN conversion routines want an even digit count,
 * but mpz_get_str doesn't promise one.)
 */
char *				/* pointer to static buffer (ick) */
hexout(var)
mpz_t var;
{
	static char hexbuf[3 + MAXBITS/4 + 1];
	char *hexp;

	mpz_get_str(hexbuf+3, 16, var);
	if (strlen(hexbuf+3)%2 == 0)	/* even number of hex digits */
		hexp = hexbuf+1;
	else {				/* odd, must pad */
		hexp = hexbuf;
		hexp[2] = '0';
	}
	hexp[0] = '0';
	hexp[1] = 'x';

	return hexp;
}

/*
 - bundle - bundle e and n into an RFC2537-format lump
 * Note, calls hexout.
 */
unsigned char *				/* pointer to static buffer (ick) */
bundle(e, n, sizep)
int e;
mpz_t n;
size_t *sizep;
{
	char *hexp = hexout(n);
	static unsigned char bundbuf[2 + MAXBITS/8];
	const char *er;
	size_t size;

	assert(e <= 255);
	bundbuf[0] = 1;
	bundbuf[1] = e;
	er = ttodata(hexp, 0, 0, (char *)bundbuf+2, sizeof(bundbuf)-2, &size);
	if (er != NULL) {
		fprintf(stderr, "%s: can't-happen bundle convert error `%s'\n",
								me, er);
		exit(1);
	}
	if (size > sizeof(bundbuf)-2) {
		fprintf(stderr, "%s: can't-happen bundle overflow (need %d)\n",
								me, (int) size);
		exit(1);
	}
	if (sizep != NULL)
		*sizep = size + 2;
	return bundbuf;
}

/*
 - conv - convert bits to output in specified format
 */
char *				/* pointer to static buffer (ick) */
conv(bits, nbytes, format)
unsigned char *bits;
size_t nbytes;
int format;			/* datatot() code */
{
	static char convbuf[MAXBITS/4 + 50];	/* enough for hex */
	size_t n;

	n = datatot(bits, nbytes, format, convbuf, sizeof(convbuf));
	if (n == 0) {
		fprintf(stderr, "%s: can't-happen convert error\n", me);
		exit(1);
	}
	if (n > sizeof(convbuf)) {
		fprintf(stderr, "%s: can't-happen convert overflow (need %d)\n",
								me, (int) n);
		exit(1);
	}
	return convbuf;
}

/*
 - report - report progress, if indicated
 */
void
report(msg)
char *msg;
{
	if (!verbose)
		return;
	fprintf(stderr, "%s\n", msg);
}
