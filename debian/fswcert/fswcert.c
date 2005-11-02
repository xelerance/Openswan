/* Certificate and Private Key Format Conversions for FreeS/WAN
 *
 * Copyright (C) 2000 Andreas Gruenbacher, <a.gruenbacher@computer.org>
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

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <termio.h>

#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>

struct option long_options[] = {
	{"certificate",   0, 0, 'c'},
	{"key",           0, 0, 'k'},
	{"left",          0, 0, 'l'},
	{"right",         0, 0, 'r'},
	{"type",          1, 0,  1 },
	{"format",        1, 0,  2 },
	{"quiet",         0, 0, 'q'},
	{"directory",     1, 0, 'C'},
	{"version",       0, 0, 'v'},
	{"help",          0, 0, 'h'},
	{NULL,            0, 0,  0 }
};

int prompt_for_passwords = 0;
const char *peer_prefix = NULL;
int opt_quiet = 0;
const char *input_file = NULL;

#define DUMP_CERTIFICATE	1
#define DUMP_KEY		2
int opt_what = 0;

BIO *bio_err = NULL;

enum input_file_type { IN_PKCS12 = 1, IN_X509 = 2, IN_RSA = 3 };
enum input_format { FORMAT_ASN1 = 1, FORMAT_PEM = 3 };

void print_errors(int ssl, const char *fmt, ...)
{
	if (fmt) {
		va_list args;
	
		va_start(args, fmt);
		if (input_file)
			fprintf(stderr, "%s: ", input_file);
		fprintf(stderr, "Error ");
		vfprintf(stderr, fmt, args);
		fprintf(stderr, "\n");
		va_end(args);
	}
	if (ssl && !opt_quiet)
		ERR_print_errors(bio_err);
}

const char *read_password(void)
{
	static char password[1024];
	struct termio saved, no_echo;

	printf("Password: ");

	(void) ioctl(0, TCGETA, &saved);
	no_echo = saved;
	no_echo.c_lflag &= ~ECHO;
	(void) ioctl(0, TCSETA, &no_echo);
	fgets(password, sizeof(password), stdin);
	(void) ioctl(0, TCSETA, &saved);
	puts("");

	if (strchr(password, '\n'))
		*strchr(password, '\n') = '\0';
	return password;
}

void BN_print_0(BIGNUM *num)
{
	int bits = BN_num_bits(num);

	if ((bits-1) % 8 <= 3)
		putchar('0');
	BN_print_fp(stdout, num);
}

#define print(what, num) do { \
	printf("\t%s 0x", what); \
	BN_print_0(num); \
	putchar('\n'); \
	} while(0)

int dump_rsa_private_key(RSA *rsa)
{
	if (rsa->d == NULL) {
		print_errors(0, "no private exponent");
		return 1;
	}
	if (opt_what & DUMP_KEY) {
		printf(": RSA {\n");
		print("Modulus:        ", rsa->n);
		print("PublicExponent: ", rsa->e);
		print("PrivateExponent:", rsa->d);
		print("Prime1:         ", rsa->p);
		print("Prime2:         ", rsa->q);
		print("Exponent1:      ", rsa->dmp1);
		print("Exponent2:      ", rsa->dmq1);
		print("Coefficient:    ", rsa->iqmp);
                printf("  }\n");
	}
	return 0;
}

#undef print

int dump_x509_certificate(X509 *x509)
{
	BUF_MEM *subject;
	EVP_PKEY *pkey;
	RSA *rsa;
	int i, error = 0;
	
	if (!x509->cert_info || !x509->cert_info->subject ||
            !x509->cert_info->subject->bytes) {
		fprintf(stderr, "Certificate contains no subject\n");
		return 1;
	}
	subject = &x509->cert_info->subject->bytes[0];

	if (opt_what & DUMP_CERTIFICATE) {
		printf("\t%sid=@~", peer_prefix);
		for (i = 0; i < subject->length; i++)
			printf("%02X", (unsigned char)subject->data[i]);
		printf("\n");
	}

	pkey = X509_get_pubkey(x509);
	if (pkey == NULL) {
		print_errors(1, "getting public key");
		return 1;
	}
	if (pkey->type != EVP_PKEY_RSA) {
		print_errors(0, "not an RSA public key");
		error = 1;
		goto cleanup;
	}
	rsa = pkey->pkey.rsa;
	
	if (opt_what & DUMP_CERTIFICATE) {
		int bytes = BN_num_bytes(rsa->e);
		printf("\t%srsasigkey=0x%02X", peer_prefix, bytes);
		BN_print_0(rsa->e);
		BN_print_0(rsa->n);
		putchar('\n');
	}

cleanup:
	EVP_PKEY_free(pkey);
	return 0;
}

int read_pkcs12_safebag(PKCS12_SAFEBAG *bag, const char *password)
{
	PKCS8_PRIV_KEY_INFO *p8;
	EVP_PKEY *pkey;
	X509 *x509;
	RSA *rsa;
	int error = 0;
	
	switch (M_PKCS12_bag_type(bag)) {
		case NID_keyBag:
			p8 = bag->value.keybag;
			pkey = EVP_PKCS82PKEY(p8);
			if (!pkey) {
				print_errors(1, "grabbing private key");
				return 1;
			}
			rsa = EVP_PKEY_get1_RSA(pkey);
			EVP_PKEY_free(pkey);
			if (!rsa) {
				print_errors(1, "getting RSA key");
				return 1;
			}
			error = dump_rsa_private_key(rsa);
			RSA_free(rsa);
			break;

		case NID_pkcs8ShroudedKeyBag:
			p8 = M_PKCS12_decrypt_skey(bag, password, -1);
			if (!p8) {
				print_errors(1, "decrypting private key");
				return 1;
			}
			pkey = EVP_PKCS82PKEY(p8);
			PKCS8_PRIV_KEY_INFO_free(p8);
			if (!pkey) {
				print_errors(1, "grabbing private key");
				return 1;
			}
			rsa = EVP_PKEY_get1_RSA(pkey);
			EVP_PKEY_free(pkey);
			if (!rsa) {
				print_errors(1, "getting RSA private key");
				return 1;
			}
			error = dump_rsa_private_key(rsa);
			RSA_free(rsa);
			break;

		case NID_certBag:
			if (M_PKCS12_cert_bag_type(bag) != NID_x509Certificate){
				print_errors(0, "not an X.509 certificate");
				return 1;
			}
			/* only dump the key's certificate */
			if (!PKCS12_get_attr(bag, NID_localKeyID))
				return 0;
			x509 = M_PKCS12_certbag2x509(bag);
			if (!x509) {
				print_errors(1, "grabbing certificate");
				return 1;
			}
			if (dump_x509_certificate(x509))
				return 1;
			X509_free(x509);
			break;

		default:
			break; /* other bag entry */
	}
	return error;
}

int read_pkcs12_file(BIO *bio_in)
{
	const char *password = "\0";
	PKCS12 *p12;
	STACK /* _OF(PKCS7) */ *asafes = NULL;
	PKCS7 *p7;
	int i;

	p12 = d2i_PKCS12_bio (bio_in, NULL);
	if (!p12) {
		print_errors(1, "reading PKCS12 file");
		return 1;
	}
	if (!PKCS12_verify_mac(p12, password, 0)) {
		if (prompt_for_passwords)
			password = read_password();
		if (!prompt_for_passwords ||
		    !PKCS12_verify_mac(p12, password, -1)) {
			print_errors(1, "verifying MAC: wrong password?");
			return 1;
		}
	}

	/* Unpack PKCS12 file */
	asafes = M_PKCS12_unpack_authsafes (p12);
	if (!asafes) {
		print_errors(1, "unpacking PKCS12 file");
		return 1;
	}
	for (i = 0; i < sk_num(asafes); i++) {
		int bagnid, j;
		STACK /* _OK(PKCS12) */ *bags;

		p7 = (PKCS7 *) sk_value(asafes, i);
		bagnid = OBJ_obj2nid(p7->type);
		if (bagnid == NID_pkcs7_data)
			bags = M_PKCS12_unpack_p7data(p7);
		else if (bagnid == NID_pkcs7_encrypted)
			bags = M_PKCS12_unpack_p7encdata(p7, password, -1);
		else
			continue;
		if (!bags) {
			print_errors(1, "unpacking PKCS12 file");
			return 1;
		}
		for (j = 0; j < sk_num(bags); j++) {
			PKCS12_SAFEBAG *bag =
				(PKCS12_SAFEBAG *)sk_value(bags, j);
			if (read_pkcs12_safebag(bag, password))
				return 1;
		}
		sk_pop_free(bags, PKCS12_SAFEBAG_free);
	}
	sk_pop_free(asafes, PKCS7_free);
	return 0;
}

int read_x509_file(BIO *bio_in, enum input_format input_format)
{
	X509 *x509 = NULL;
	int error;

	if (input_format == FORMAT_PEM)
		x509 = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
	else if (input_format == FORMAT_ASN1)
		x509 = d2i_X509_bio(bio_in, NULL);
	if (!x509) {
		print_errors(1, "reading X509 certificate");
		return 1;
	}
	error = dump_x509_certificate(x509);
	X509_free(x509);

	return error;
}

int read_rsa_file(BIO *bio_in, enum input_format input_format)
{
	RSA *rsa = NULL;
	int error;

	if (input_format == FORMAT_PEM)
		rsa = PEM_read_bio_RSAPrivateKey(bio_in, NULL, NULL, NULL);
	else if (input_format == FORMAT_ASN1)
		rsa = d2i_RSAPrivateKey_bio(bio_in, NULL);
	if (!rsa) {
                print_errors(1, "reading RSA private key");
                return 1;
        }
	error = dump_rsa_private_key(rsa);
	RSA_free(rsa);
	return error;
}

int main(int argc, char *argv[])
{
	enum input_file_type input_file_type = 0;
	enum input_format input_format = 0;
	int error = 0, opt;

	prompt_for_passwords = isatty(0) && isatty(1);

	while ((opt = getopt_long(argc, argv, "cklrqC:hv",
	                          long_options, NULL)) != -1) {
		switch(opt) {
			case 1:  /* input file type */
				if (!strcmp(optarg, "pkcs12"))
					input_file_type = IN_PKCS12;
				else if (!strcmp(optarg, "x509"))
					input_file_type = IN_X509;
				else if (!strcmp(optarg, "rsa"))
					input_file_type = IN_RSA;
				else
					goto synopsis;
				break;

			case 2:  /* input format */
				if (!strcmp(optarg, "PEM"))
					input_format = FORMAT_PEM;
				else if (!strcmp(optarg, "DER"))
					input_format = FORMAT_ASN1;
				else
					goto synopsis;
				break;

			case 'c':  /* certificate */
				opt_what |= DUMP_CERTIFICATE;
				if (!input_file_type)
					input_file_type = IN_X509;
				break;

			case 'k':  /* key */
				opt_what |= DUMP_KEY;
				if (!input_file_type)
					input_file_type = IN_RSA;
				break;

			case 'l':  /* left */
				if (!opt_what)
					opt_what = DUMP_CERTIFICATE;
				peer_prefix = "left";
				break;

			case 'r':  /* right */
				if (!opt_what)
					opt_what = DUMP_CERTIFICATE;
				peer_prefix = "right";
				break;

			case 'C':  /* change directory */
				if (chdir(optarg) && errno) {
					perror(optarg);
					error = 1;
				}
				break;

			case 'v':  /* print version and exit */
				printf("%s " VERSION "\n", argv[0]);
				return 0;

			case 'q':  /* quiet */
				opt_quiet = 1;
				break;

			default:
				goto synopsis;
		}
	}
	if (peer_prefix == NULL)
		peer_prefix = "";

	if (optind+1 != argc || !opt_what)
		goto synopsis;

	if (!input_file_type)
		input_file_type = IN_X509;
	if (!input_format)
		input_format = FORMAT_PEM;

	if (opt_quiet)
		dup2(1,2);  /* stderr is stdout (awk hack) */

	ERR_load_crypto_strings();
	SSLeay_add_all_algorithms();
	bio_err = BIO_new_fp (stderr, BIO_NOCLOSE);
	
	while (optind < argc) {
		BIO *bio_in;

		input_file = argv[optind];
		bio_in = BIO_new_file(input_file, "rb");
		if (!bio_in) {
			perror(input_file);
			error = 1;
		} else {
			if (input_file_type == IN_PKCS12)
				error |= read_pkcs12_file(bio_in);
			else if (input_file_type == IN_X509)
				error |= read_x509_file(bio_in, input_format);
			else if (input_file_type == IN_RSA)
				error |= read_rsa_file(bio_in, input_format);
			BIO_free(bio_in);
		}
		optind++;
	}

	BIO_free(bio_err);

	return error;

synopsis:
	fprintf(stderr, "SYNOPSIS: %s --cert|--key [--left|--right] "
	        "options file\n", argv[0]);
	if (!opt_quiet) {
		fprintf(stderr, "\t-c --cert\tprint certificate data\n"
		        "\t-k --key\tprint private RSA key data\n"
		        "\t-l --left\tleft-side parameters for ipsec.conf\n"
		        "\t-r --right\tright-side parameters for ipsec.conf\n"
		        "\t   --type=[x509|rsa|pkcs12]\tselect input file type\n"
		        "\t   --format=[PEM|DER]\tselect input file format\n"
		        "\t-C --directory=dir\tchange into dir first\n"
		        "\t-q --quiet\tsingle line error messages to stdout\n");
	}
	return error;
}

