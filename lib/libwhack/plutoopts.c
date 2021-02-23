/* Handle Pluto Options
 * Copyright (C) 2021  Michael Richardson
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <openswan.h>

#include "sysdep.h"
#include "constants.h"
#include "openswan/ipsec_policy.h"
#include "oswtime.h"
#include "oswalloc.h"
#include "whack.h"
#include "oswconf.h"
#include "oswlog.h"
#include "pluto/vendor.h"
#include "pluto/defs.h"
#include "pluto/server.h"
#include "pluto/log.h"

#include "qcbor/qcbor_encode.h"
#include "qcbor/qcbor_decode.h"

extern err_t whack_cbor_magic_header(QCBOREncodeContext *qec);

#define OK(x) ugh = (x); if(ugh) goto bad

/** usage - print help messages
 *
 * @param mess String - alternate message to print
 */
void pluto_usage(const char *mess)
{
    if (mess != NULL && *mess != '\0')
	fprintf(stderr, "%s\n", mess);
    fprintf(stderr
	, "Usage: pluto  "
	    "[--help] "
	    "[--version] "
	    "[--optionsfrom <filename>] "
	    "\n\t"
	    "[--nofork] "
	    "[--stderrlog] "
	    "[--plutostderrlogtime] "
	    "[--force_busy] "
	    "\n\t"
	    "[--nocrsend] "
	    "[--strictcrlpolicy] "
	    "[--crlcheckinterval] "
	    "[--ocspuri] "
	    "[--uniqueids] "
            "[--noretransmits] "
            "[--built-withlibnss] "
	    "\n\nIPsec stack options\n\t"
	    "[--use-auto] "
	    "[--use-klips] "
	    "[--use-netkey] "
	    "[--use-mast] "
	    "[--use-bsdkame] "
	    "[--use-nostack]"         /* old --no_klips */
            "\n\nConnection options\n\t"
	    "[--interface <ifname|ifaddr>] "
	    "[--ikeport <port-number>] "
	    "[--listen <ifaddr>] "
	    "\n\nFile/Directory settings\n\t"
	    "[--ctlbase <path>] "
	    "\n\t"
	    "[--perpeerlogbase <path>] [--perpeerlog] "
	    " \n\t"
	    "[--coredir <dirname>]"
	    "\n\t"
	    "[--secretsfile <secrets-file>] "
	    "[--ipsecdir <ipsec-dir>] "
	    "\n\t"
	    "[--nhelpers <number>] "
	    " \n\t"
	    "[--secctx_attr_value <number>]  "
#ifdef HAVE_LABELED_IPSEC
            "(available)  "
#else
            "(unavailable)  "
#endif

#ifdef DEBUG
	    " \n\nDebug Options\n\t"
	    "[--debug-none] "
	    "[--debug-all] "
	    "\n\t"
	    "[--debug-raw] "
	    "[--debug-crypt] "
	    "[--debug-crypto] "
	    "[--debug-parsing] "
	    "[--debug-emitting] "
	    "\n\t"
	    "[--debug-control] "
	    "[--debug-lifecycle] "
	    "[--debug-klips] "
	    "[--debug-netkey] "
	    "[--debug-x509] "
	    "[ --debug-nat-t] "
#ifndef NAT_TRAVERSAL
            "(unavailable) "
#endif
	    "\n\t"
	    "[--debug-dns] "
	    "[--debug-oppo] "
	    "[--debug-oppoinfo] "
	    "[--debug-dpd] "
	    "[ --debug-private] "
	    "[ --debug-pfkey] "
            "\n\t"
#endif
#ifdef NAT_TRAVERSAL
	    " \n\t"
	    "[--nat_traversal] [--keep_alive <delay_sec>] "
	    " \n\t"
            "[--force_keepalive] [--disable_port_floating] "
	   " \n\t"
#endif
	   "[--virtual_private <network_list>] "
	    "\n"
	"Openswan %s\n"
	, ipsec_version_code());
    exit(mess == NULL? 0 : 1);	/* not exit_pluto because we are not initialized yet */
}

err_t pluto_options_process(int argc, char **argv, chunk_t *encode_opts)
{
    QCBOREncodeContext qec;
    QCBORError e;
    err_t ugh;

    UsefulBuf into = {encode_opts->ptr, (unsigned long)encode_opts->len};
    QCBOREncode_Init(&qec, into);

    OK(whack_cbor_magic_header(&qec));

    QCBOREncode_OpenMap(&qec);
    QCBOREncode_OpenMapInMapN(&qec, WHACK_OPTIONS);

    /* handle arguments */
    for (;;)  {
#	define DBG_OFFSET 256
        static const struct option long_opts[] =
            {
             /* name, has_arg, flag, val */
             { "help", no_argument, NULL, 'h' },
             { "version", no_argument, NULL, 'v' },
             { "optionsfrom", required_argument, NULL, '+' },
             { "nofork", no_argument, NULL, 'd' },
             { "stderrlog", no_argument, NULL, 'e' },
             { "plutostderrlogtime", no_argument, NULL, 't' },
             { "noklips", no_argument, NULL, 'n' },
             { "use-nostack",  no_argument, NULL, 'n' },
             { "use-none",     no_argument, NULL, 'n' },
             { "force_busy", no_argument, NULL, 'D' },
             { "nocrsend", no_argument, NULL, 'c' },
             { "strictcrlpolicy", no_argument, NULL, 'r' },
             { "crlcheckinterval", required_argument, NULL, 'x'},
             { "ocsprequestcert", required_argument, NULL, 'q'},
             { "ocspuri", required_argument, NULL, 'o'},
             { "uniqueids", no_argument, NULL, 'u' },
             { "useklips",  no_argument, NULL, 'k' },
             { "use-klips",  no_argument, NULL, 'k' },
             { "use-auto",  no_argument, NULL, 'G' },
             { "usenetkey", no_argument, NULL, 'K' },
             { "use-netkey", no_argument, NULL, 'K' },
             { "use-mast",   no_argument, NULL, 'M' },
             { "use-mastklips",   no_argument, NULL, 'M' },
             { "use-bsdkame",   no_argument, NULL, 'F' },
             { "interface", required_argument, NULL, 'i' },
             { "listen", required_argument, NULL, 'L' },
             { "ikeport", required_argument, NULL, 'p' },
             { "ctlbase", required_argument, NULL, 'b' },
             { "secretsfile", required_argument, NULL, 's' },
             { "foodgroupsdir", required_argument, NULL, 'f' },
             { "perpeerlogbase", required_argument, NULL, 'P' },
             { "perpeerlog", no_argument, NULL, 'l' },
             { "noretransmits", no_argument, NULL, 'R' },
             { "coredir", required_argument, NULL, 'C' },
             { "ipsecdir", required_argument, NULL, 'f' },
             { "ipsec_dir", required_argument, NULL, 'f' },
#ifdef NAT_TRAVERSAL
             { "nat_traversal", no_argument, NULL, '1' },
             { "keep_alive", required_argument, NULL, '2' },
             { "force_keepalive", no_argument, NULL, '3' },
             { "disable_port_floating", no_argument, NULL, '4' },
             { "debug-nat_t", no_argument, NULL, '5' },
             { "debug-nattraversal", no_argument, NULL, '5' },
             { "debug-nat-t", no_argument, NULL, '5' },
#endif
             { "virtual_private", required_argument, NULL, '6' },
             { "nhelpers", required_argument, NULL, 'j' },

             { "built-withlibnss", no_argument, NULL, '7' },

             /* might not be enabled, but always accept the option */
             { "secctx_attr_value", required_argument, NULL, 'w' },
#ifdef DEBUG
             { "debug-none", no_argument, NULL, 'N' },
             { "debug-all", no_argument, NULL, 'A' },

             { "debug-raw", no_argument, NULL, DBG_RAW + DBG_OFFSET },
             { "debug-crypt", no_argument, NULL, DBG_CRYPT + DBG_OFFSET },
             { "debug-crypto", no_argument, NULL, DBG_CRYPT + DBG_OFFSET },
             { "debug-parsing", no_argument, NULL, DBG_PARSING + DBG_OFFSET },
             { "debug-emitting", no_argument, NULL, DBG_EMITTING + DBG_OFFSET },
             { "debug-control", no_argument, NULL, DBG_CONTROL + DBG_OFFSET },
             { "debug-lifecycle", no_argument, NULL, DBG_LIFECYCLE + DBG_OFFSET },
             { "debug-klips", no_argument, NULL, DBG_KLIPS + DBG_OFFSET },
             { "debug-netkey", no_argument, NULL, DBG_NETKEY + DBG_OFFSET },
             { "debug-dns", no_argument, NULL, DBG_DNS + DBG_OFFSET },
             { "debug-oppo", no_argument, NULL, DBG_OPPO + DBG_OFFSET },
             { "debug-oppoinfo", no_argument, NULL, DBG_OPPOINFO + DBG_OFFSET },
             { "debug-controlmore", no_argument, NULL, DBG_CONTROLMORE + DBG_OFFSET },
             { "debug-dpd", no_argument, NULL, DBG_DPD + DBG_OFFSET },
             { "debug-x509", no_argument, NULL, DBG_X509 + DBG_OFFSET },
             { "debug-private", no_argument, NULL, DBG_PRIVATE + DBG_OFFSET },
             { "debug-pfkey", no_argument, NULL, DBG_PFKEY + DBG_OFFSET },

             { "impair-delay-adns-key-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_KEY_ANSWER + DBG_OFFSET },
             { "impair-delay-adns-txt-answer", no_argument, NULL, IMPAIR_DELAY_ADNS_TXT_ANSWER + DBG_OFFSET },
             { "impair-bust-mi2", no_argument, NULL, IMPAIR_BUST_MI2 + DBG_OFFSET },
             { "impair-bust-mr2", no_argument, NULL, IMPAIR_BUST_MR2 + DBG_OFFSET },
             { "impair-sa-creation", no_argument, NULL, IMPAIR_SA_CREATION + DBG_OFFSET },
             { "impair-die-oninfo", no_argument, NULL, IMPAIR_DIE_ONINFO + DBG_OFFSET },
             { "impair-jacob-two-two", no_argument, NULL, IMPAIR_JACOB_TWO_TWO + DBG_OFFSET },
             { "impair-major-version-bump", no_argument, NULL, IMPAIR_MAJOR_VERSION_BUMP + DBG_OFFSET },
             { "impair-minor-version-bump", no_argument, NULL, IMPAIR_MINOR_VERSION_BUMP + DBG_OFFSET },
             { "impair-retransmits", no_argument, NULL, IMPAIR_RETRANSMITS + DBG_OFFSET },
             { "impair-send-bogus-isakmp-flag", no_argument, NULL, IMPAIR_SEND_BOGUS_ISAKMP_FLAG + DBG_OFFSET },
#endif
             { 0,0,0,0 }
	    };
	/* Note: we don't like the way short options get parsed
	 * by getopt_long, so we simply pass an empty string as
	 * the list.  It could be "hvdenp:l:s:" "NARXPECK".
	 */
	int c = getopt_long(argc, argv, "", long_opts, NULL);

	/** Note: "breaking" from case terminates loop */
	switch (c)
            {
            case EOF:	/* end of flags */
                break;

            case 0: /* long option already handled */
                continue;

            case ':':	/* diagnostic already printed by getopt_long */
            case '?':	/* diagnostic already printed by getopt_long */
                return "";

            case 'h':	/* --help */
                return "";

            case 'C':
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_COREDIR, optarg);
                break;

            case 'v':	/* --version */
                {
                    printf("%s%s\n", ipsec_version_string(),
                           compile_time_interop_options);
                }
                exit(0);	/* not exit_pluto because we are not initialized yet */
                break;	/* not actually reached */

            case 'j':	/* --nhelpers */
                if (optarg == NULL || !(isdigit(optarg[0]) || optarg[0]=='-')) {
                    return "missing number of pluto helpers";
                }

                {
                    char *endptr;
                    long count = strtol(optarg, &endptr, 0);

                    if (*endptr != '\0' || endptr == optarg
                        || count < -1) {
                        return "<nhelpers> must be a positive number, 0 or -1";
                    }
                    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_NHELPERS, count);
                }
                continue;

            case 'w':	/* --secctx_attr_value*/
                if (optarg == NULL || !isdigit(optarg[0])) {
                    return "missing (positive integer) value of secctx_attr_value (needed only if using labeled ipsec)";
                }

                {
                    char *endptr;
                    long value = strtol(optarg, &endptr, 0);

                    if (*endptr != '\0' || endptr == optarg
                        || (value != SECCTX && value !=10) ) {
                        return "<secctx_attr_value> must be a positive number (32001 by default, 10 for backward compatibility, or any other future number assigned by IANA)";
                    }
                    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_SECCTX, value);
                }
                continue;

            case 'd':	/* --nofork*/
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_FORKDESIRED, FALSE);
                continue;

            case 'e':	/* --stderrlog */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_STDERR_DESIRED, TRUE);
                continue;

            case 't':	/* --plutostderrlogtime */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_LOG_WITH_TIMESTAMP, TRUE);
                continue;

            case 'G':       /* --use-auto */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KERN_INTERFACE, AUTO_PICK);
                continue;

            case 'k':       /* --use-klips */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KERN_INTERFACE, USE_KLIPS);
                continue;

            case 'L':	/* --listen ip_addr */
                {
                    ip_address lip;
                    err_t e = ttoaddr(optarg,0,0,&lip);
                    if(e) {
                        openswan_log("invalid listen argument ignored: %s\n",e);
                    } else {
                        QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_LISTENADDR, optarg);
                        openswan_log("bind() will be filtered for %s\n", optarg);
                    }
                }
                continue;

            case 'M':       /* --use-mast */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KERN_INTERFACE, USE_MASTKLIPS);
                continue;

            case 'F':       /* --use-bsdkame */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KERN_INTERFACE, USE_BSDKAME);
                continue;

            case 'K':       /* --use-netkey */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KERN_INTERFACE, USE_NETKEY);
                continue;

            case 'n':	/* --use-nostack */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_KERN_INTERFACE, NO_KERNEL);

                /* this permits interfaces to match even if ports do not, so
                 * that pluto can be tested against another pluto, all on
                 * 127.0.0.1
                 */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_SAME_ADDR_OK, TRUE);
                continue;

            case 'D':	/* --force_busy */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_FORCE_BUSY, TRUE);
                continue
                    ;

            case 'c':	/* --nocrsend */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_CERT_SEND, TRUE);
                continue
                    ;

            case 'r':	/* --strictcrlpolicy */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_STRICT_CRL_POLICY, TRUE);
                continue
                    ;

            case 'R':
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_NO_RETRANSMITS, TRUE);
                continue;

            case 'x':	/* --crlcheckinterval <time>*/
                if (optarg == NULL || !isdigit(optarg[0])) {
                    return "missing interval time";
                }

                {
                    char *endptr;
                    long interval = strtol(optarg, &endptr, 0);

                    if (*endptr != '\0' || endptr == optarg
                        || interval <= 0) {
                        return "<interval-time> must be a positive number";
                    }
                    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_CRL_CHECK_INTERVAL, interval);
                }
                continue
                    ;

            case 'o':	/* --ocspuri */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_OCSPURI, optarg);
                continue;

            case 'u':	/* --uniqueids */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_UNIQUE_IDS, TRUE);
                continue;

            case 'i':	/* --interface <ifname|ifaddr> */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_USE_INTERFACE, optarg);
                continue;

                /*
                 * This option does not really work, as this is the "left"
                 * site only, you also need --to --ikeport again later on
                 * It will result in: yourport -> 500, still not bypassing filters
                 */
            case 'p':	/* --ikeport <portnumber> */
                if (optarg == NULL || !isdigit(optarg[0])) {
                    return "missing port number";
                }
                {
                    char *endptr;
                    long port = strtol(optarg, &endptr, 0);

                    if (*endptr != '\0' || endptr == optarg
                        || port <= 0 || port > (0x10000-4000)) {
                        return "<port-number> must be a number between 1 and 61535 (nat port: port-number+4000)";
                    }
                    QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_IKE_PORT, port);
                }
                continue;

            case 'b':	/* --ctlbase <path> */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_CTRL_BASE, optarg);
                continue;

            case 's':	/* --secretsfile <secrets-file> */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_SHARED_SECRETS_FILE, optarg);
                continue;

            case 'f':	/* --ipsecdir <ipsec-dir> */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_IPSEC_DIR, optarg);
                continue;

            case 'N':	/* --debug-none */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_SET_DEBUGGING, DBG_NONE);
                continue;

            case 'A':	/* --debug-all */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_SET_DEBUGGING, DBG_ALL);
                continue;

            case 'P':       /* --perpeerlogbase */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_PERPEER_LOGDIR, optarg);
                continue;

            case 'l':
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_PERPEER_ENABLED,TRUE);
                continue;

            case '1':	/* --nat_traversal */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_NAT_TRAVERSAL, TRUE);
                continue;
            case '2':	/* --keep_alive */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_NAT_KEEP_ALIVE, atoi(optarg));
                continue;
            case '3':	/* --force_keepalive */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_NAT_FORCE_KEEP_ALIVE, TRUE);
                continue;
            case '4':	/* --disable_port_floating */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_NAT_PORT_FLOAT, FALSE);
                continue;
            case '5':	/* --debug-nat_t */
                QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_ADD_DEBUGGING, DBG_NATT);
                continue;

            case '6':	/* --virtual_private */
                QCBOREncode_AddSZStringToMapN(&qec, WHACK_OPT_VIRTUAL_PRIVATE, optarg);
                continue;

            default:
                if (c >= DBG_OFFSET)
                    {
                        QCBOREncode_AddInt64ToMapN(&qec, WHACK_OPT_ADD_DEBUGGING,
                                                   (c - DBG_OFFSET));
                        continue;
                    }
                bad_case(c);
            }
	break;
    }
    if (optind != argc) {
    bad:
	return "unexpected argument";
    }

    QCBOREncode_CloseMap(&qec);    /* closes the WHACK_OPTIONS MAP */
    QCBOREncode_CloseMap(&qec);

    {
        size_t outlen = 0;

        /* close the array */
        e = QCBOREncode_FinishGetSize(&qec, &outlen);
        if(e != QCBOR_SUCCESS) {
            ugh = builddiag("encoding failed: qcbor error %d", e);
            return ugh;
        }
        encode_opts->len = outlen;
    }

    return NULL;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
