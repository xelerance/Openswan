/* error logging functions
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2005-2007 Michael Richardson
 * Copyright (C) 2006-2010 Bart Trojanowski
 * Copyright (C) 2008-2010 Paul Wouters
 * Copyright (C) 2008-2010 David McCullough.
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>	/* used only if MSG_NOSIGNAL not defined */
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <openswan.h>
#include "openswan/pfkeyv2.h"

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "log.h"
#include "server.h"
#include "state.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "kernel.h"	/* needs connections.h */
#include "whack.h"	/* needs connections.h */
#include "timer.h"
#include "kernel_alg.h"
#include "ike_alg.h"
#include "plutoalg.h"
#include "virtual.h" /* for show_virtual_private */

#ifndef NO_DB_OPS_STATS
#define NO_DB_CONTEXT
#include "db_ops.h"
#endif

/* close one per-peer log */
static void perpeer_logclose(struct connection *c);	/* forward */


bool
    log_to_stderr = TRUE,	/* should log go to stderr? */
    log_to_syslog = TRUE,	/* should log go to syslog? */
    log_to_perpeer= FALSE,	/* should log go to per-IP file? */
    log_did_something=TRUE;     /* set if we wrote something recently */


bool
    logged_txt_warning = FALSE;  /* should we complain about finding KEY? */

/* should we complain when we find no local id */
bool
    logged_myid_fqdn_txt_warning = FALSE,
    logged_myid_ip_txt_warning   = FALSE,
    logged_myid_fqdn_key_warning = FALSE,
    logged_myid_ip_key_warning   = FALSE;

/* may include trailing / */
const char *base_perpeer_logdir = PERPEERLOGDIR;
static int perpeer_count = 0;

/* what to put in front of debug output */
char debug_prefix = '|';

/*
 * used in some messages to distiguish
 * which pluto is which, when doing unit testing
 * gets set by "use_interface" in server.c, if it is going to be changed.
 * Is used by pluto_helpers in their process-title.
 * could be used by debug routines as well, but is not yet.
 */
const char *pluto_ifn_inst = "";

/* from sys/queue.h -> NOW private sysdep.h. */
static CIRCLEQ_HEAD(,connection) perpeer_list;


/* Context for logging.
 *
 * Global variables: must be carefully adjusted at transaction boundaries!
 * If the context provides a whack file descriptor, messages
 * should be copied to it -- see whack_log()
 */
int whack_log_fd = NULL_FD;	/* only set during whack_handle() */
struct state *cur_state = NULL;	/* current state, for diagnostics */
struct connection *cur_connection = NULL;	/* current connection, for diagnostics */
const ip_address *cur_from = NULL;	/* source of current current message */
u_int16_t cur_from_port;	/* host order */

void
pluto_init_log(void)
{
    set_exit_log_func(exit_log);
    if (log_to_stderr)
	setbuf(stderr, NULL);
    if (log_to_syslog)
	openlog("pluto", LOG_CONS | LOG_NDELAY | LOG_PID, LOG_AUTHPRIV);

    CIRCLEQ_INIT(&perpeer_list);
}

/* format a string for the log, with suitable prefixes.
 * A format starting with ~ indicates that this is a reprocessing
 * of the message, so prefixing and quoting is suppressed.
 */
static void
fmt_log(char *buf, size_t buf_len, const char *fmt, va_list ap)
{
    bool reproc = *fmt == '~';
    size_t ps;
    struct connection *c = cur_state != NULL ? cur_state->st_connection
	: cur_connection;

    buf[0] = '\0';
    if (reproc)
	fmt++;	/* ~ at start of format suppresses this prefix */
    else if (c != NULL)
    {
	/* start with name of connection */
	char *const be = buf + buf_len;
	char *bp = buf;

	snprintf(bp, be - bp, "\"%s\"", c->name);
	bp += strlen(bp);

	/* if it fits, put in any connection instance information */
	if (be - bp > CONN_INST_BUF)
	{
	    fmt_conn_instance(c, bp);
	    bp += strlen(bp);
	}

	if (cur_state != NULL)
	{
	    /* state number */
	    snprintf(bp, be - bp, " #%lu", cur_state->st_serialno);
	    bp += strlen(bp);
	}
	snprintf(bp, be - bp, ": ");
    }
    else if (cur_from != NULL)
    {
	/* peer's IP address */
	/* Note: must not use ip_str() because our caller might! */
	char ab[ADDRTOT_BUF];

	(void) addrtot(cur_from, 0, ab, sizeof(ab));
	snprintf(buf, buf_len, "packet from %s:%u: "
	    , ab, (unsigned)cur_from_port);
    }

    ps = strlen(buf);
    vsnprintf(buf + ps, buf_len - ps, fmt, ap);
    if (!reproc)
	(void)sanitize_string(buf, buf_len);
}

void
close_peerlog(void)
{
    /* exit if the circular queue has not been initialized */
    if (perpeer_list.cqh_first == NULL)
        return;

    /* end of circular queue is given by pointer to "HEAD" */
    while (perpeer_list.cqh_first != (void *)&perpeer_list)
	perpeer_logclose(perpeer_list.cqh_first);
}

void
close_log(void)
{
    if (log_to_syslog)
	closelog();

    close_peerlog();
}

static void
perpeer_logclose(struct connection *c)
{
    /* only free/close things if we had used them! */
    if (c->log_file != NULL)
    {
	passert(perpeer_count > 0);

	CIRCLEQ_REMOVE(&perpeer_list, c, log_link);
	perpeer_count--;
	fclose(c->log_file);
	c->log_file=NULL;
    }
}

void
perpeer_logfree(struct connection *c)
{
    perpeer_logclose(c);
    if (c->log_file_name != NULL)
    {
	pfree(c->log_file_name);
	c->log_file_name = NULL;
	c->log_file_err = FALSE;
    }
}

/* attempt to arrange a writeable parent directory for <path>
 * Result indicates success.  Failure will be logged.
 *
 * NOTE: this routine must not call our own logging facilities to report
 * an error since those routines are not re-entrant and such a call
 * would be recursive.
 */
static bool
ensure_writeable_parent_directory(char *path)
{
    /* NOTE: a / in the first char of a path is not like any other.
     * That is why the strchr starts at path + 1.
     */
    char *e = strrchr(path + 1, '/');	/* end of directory prefix */
    bool happy = TRUE;

    if (e != NULL)
    {
	/* path has an explicit directory prefix: deal with it */

	/* Treat a run of slashes as one.
	 * Remember that a / in the first char is different.
	 */
	while (e > path+1 && e[-1] == '/')
	    e--;

	*e = '\0';	/* carve off dirname part of path */

	if (access(path, W_OK) == 0)
	{
	    /* mission accomplished, with no work */
	}
	else if (errno != ENOENT)
	{
	    /* cannot write to this directory for some reason
	     * other than a missing directory
	     */
	    syslog(LOG_CRIT, "can not write to %s: %s", path, strerror(errno));
	    happy = FALSE;
	}
	else
	{
	    /* missing directory: try to create one */
	    happy = ensure_writeable_parent_directory(path);
	    if (happy)
	    {
		if (mkdir(path, 0750) != 0)
		{
		    syslog(LOG_CRIT, "can not create dir %s: %s"
			, path, strerror(errno));
		    happy = FALSE;
		}
	    }
	}

	*e = '/';	/* restore path to original form */
    }
    return happy;
}

/* open the per-peer log
 *
 * NOTE: this routine must not call our own logging facilities to report
 * an error since those routines are not re-entrant and such a call
 * would be recursive.
 */
static void
open_peerlog(struct connection *c)
{
    /* syslog(LOG_INFO, "opening log file for conn %s", c->name); */

    if (c->log_file_name == NULL)
    {
	char peername[ADDRTOT_BUF], dname[ADDRTOT_BUF];
	int  peernamelen, lf_len;

	addrtot(&c->spd.that.host_addr, 'Q', peername, sizeof(peername));
	peernamelen = strlen(peername);

	/* copy IP address, turning : and . into / */
	{
	    char ch, *p, *q;

	    p = peername;
	    q = dname;
	    do {
		ch = *p++;
		if (ch == '.' || ch == ':')
		    ch = '/';
		*q++ = ch;
	    } while (ch != '\0');
	}

	lf_len = peernamelen * 2
	    + strlen(base_perpeer_logdir)
	    + sizeof("//.log")
	    + 1;
	c->log_file_name = alloc_bytes(lf_len, "per-peer log file name");

#if 0
	fprintf(stderr, "base dir |%s| dname |%s| peername |%s|"
		, base_perpeer_logdir, dname, peername);
#endif
	snprintf(c->log_file_name, lf_len, "%s/%s/%s.log"
		 , base_perpeer_logdir, dname, peername);

	/* syslog(LOG_DEBUG, "conn %s logfile is %s", c->name, c->log_file_name); */
    }

    /* now open the file, creating directories if necessary */

    c->log_file_err = !ensure_writeable_parent_directory(c->log_file_name);
    if (c->log_file_err)
	return;

    c->log_file = fopen(c->log_file_name, "a");
    if (c->log_file == NULL)
    {
	if (c->log_file_err)
	{
	    syslog(LOG_CRIT, "logging system can not open %s: %s"
		   , c->log_file_name, strerror(errno));
	    c->log_file_err = TRUE;
	}
	return;
    }

    /* look for a connection to close! */
    while (perpeer_count >= MAX_PEERLOG_COUNT)
    {
	/* can not be NULL because perpeer_count > 0 */
	passert(perpeer_list.cqh_last != (void *)&perpeer_list);

	perpeer_logclose(perpeer_list.cqh_last);
    }

    /* insert this into the list */
    CIRCLEQ_INSERT_HEAD(&perpeer_list, c, log_link);
    passert(c->log_file != NULL);
    perpeer_count++;
}

/* log a line to cur_connection's log */
static void
peerlog(const char *prefix, const char *m)
{
    if (cur_connection == NULL)
    {
	/* we can not log it in this case. Oh well. */
	return;
    }

    if (cur_connection->log_file == NULL)
    {
	open_peerlog(cur_connection);
    }

    /* despite our attempts above, we may not be able to open the file. */
    if (cur_connection->log_file != NULL)
    {
	char datebuf[32];
	time_t n;
	struct tm *t;

	time(&n);
	t = localtime(&n);

	strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %T", t);
	fprintf(cur_connection->log_file, "%s %s%s\n", datebuf, prefix, m);

	/* now move it to the front of the list */
	CIRCLEQ_REMOVE(&perpeer_list, cur_connection, log_link);
	CIRCLEQ_INSERT_HEAD(&perpeer_list, cur_connection, log_link);
    }
}


int
openswan_log(const char *message, ...)
{
    va_list args;
    char m[LOG_WIDTH];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    log_did_something=TRUE;

    if (log_to_stderr)
	fprintf(stderr, "%s\n", m);
    if (log_to_syslog)
	syslog(LOG_WARNING, "%s", m);
    if (log_to_perpeer)
	peerlog("", m);

    whack_log(RC_LOG, "~%s", m);

    return 0;
}

void
loglog(int mess_no, const char *message, ...)
{
    va_list args;
    char m[LOG_WIDTH];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    log_did_something=TRUE;

    if (log_to_stderr)
	fprintf(stderr, "%s\n", m);
    if (log_to_syslog)
	syslog(LOG_WARNING, "%s", m);
    if (log_to_perpeer)
	peerlog("", m);

    whack_log(mess_no, "~%s", m);
}

void
openswan_log_errno_routine(int e, const char *message, ...)
{
    va_list args;
    char m[LOG_WIDTH];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    log_did_something=TRUE;

    if (log_to_stderr)
	fprintf(stderr, "ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
    if (log_to_syslog)
	syslog(LOG_ERR, "ERROR: %s. Errno %d: %s", m, e, strerror(e));
    if (log_to_perpeer)
    {
	peerlog(strerror(e), m);
    }

    whack_log(RC_LOG_SERIOUS
	, "~ERROR: %s. Errno %d: %s", m, e, strerror(e));
}

void
exit_log(const char *message, ...)
{
    va_list args;
    char m[LOG_WIDTH];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    log_did_something=TRUE;

    if (log_to_stderr)
	fprintf(stderr, "FATAL ERROR: %s\n", m);
    if (log_to_syslog)
	syslog(LOG_ERR, "FATAL ERROR: %s", m);
    if (log_to_perpeer)
	peerlog("FATAL ERROR: ", m);

    whack_log(RC_LOG_SERIOUS, "~FATAL ERROR: %s", m);

    exit_pluto(1);
}

void
openswan_exit_log_errno_routine(int e, const char *message, ...)
{
    va_list args;
    char m[LOG_WIDTH];	/* longer messages will be truncated */

    va_start(args, message);
    fmt_log(m, sizeof(m), message, args);
    va_end(args);

    log_did_something=TRUE;

    if (log_to_stderr)
	fprintf(stderr, "FATAL ERROR: %s. Errno %d: %s\n", m, e, strerror(e));
    if (log_to_syslog)
	syslog(LOG_ERR, "FATAL ERROR: %s. Errno %d: %s", m, e, strerror(e));
    if (log_to_perpeer)
	peerlog(strerror(e), m);

    whack_log(RC_LOG_SERIOUS
	, "~FATAL ERROR: %s. Errno %d: %s", m, e, strerror(e));

    exit_pluto(1);
}

void
openswan_log_abort(const char *file_str, int line_no)
{
	loglog(RC_LOG_SERIOUS, "ABORT at %s:%d", file_str, line_no);
	abort();
}

/* emit message to whack.
 * form is "ddd statename text" where
 * - ddd is a decimal status code (RC_*) as described in whack.h
 * - text is a human-readable annotation
 */
#ifdef DEBUG
static volatile sig_atomic_t dying_breath = FALSE;
#endif

void
whack_log(int mess_no, const char *message, ...)
{
    int wfd = whack_log_fd != NULL_FD ? whack_log_fd
	: cur_state != NULL ? cur_state->st_whack_sock
	: NULL_FD;

    if (wfd != NULL_FD
#ifdef DEBUG
    || dying_breath
#endif
    )
    {
	va_list args;
	char m[LOG_WIDTH];	/* longer messages will be truncated */
	int prelen = snprintf(m, sizeof(m), "%03d ", mess_no);

	passert(prelen >= 0);

	va_start(args, message);
	fmt_log(m+prelen, sizeof(m)-prelen, message, args);
	va_end(args);

#if DEBUG
	if (dying_breath)
	{
	    /* status output copied to log */
	    if (log_to_stderr)
		fprintf(stderr, "%s\n", m + prelen);
	    if (log_to_syslog)
		syslog(LOG_WARNING, "%s", m + prelen);
	    if (log_to_perpeer)
		peerlog("", m);
	}
#endif

	if (wfd != NULL_FD)
	{
	    /* write to whack socket, but suppress possible SIGPIPE */
	    size_t len = strlen(m);
#ifdef MSG_NOSIGNAL	/* depends on version of glibc??? */
	    m[len] = '\n';	/* don't need NUL, do need NL */
	    (void) send(wfd, m, len + 1, MSG_NOSIGNAL);
#else /* !MSG_NOSIGNAL */
	    int r;
	    struct sigaction act
		, oldact;

	    m[len] = '\n';	/* don't need NUL, do need NL */
	    act.sa_handler = SIG_IGN;
	    sigemptyset(&act.sa_mask);
	    act.sa_flags = 0;	/* no nothing */
	    r = sigaction(SIGPIPE, &act, &oldact);
	    passert(r == 0);

	    (void) write(wfd, m, len + 1);

	    r = sigaction(SIGPIPE, &oldact, NULL);
	    passert(r == 0);
#endif /* !MSG_NOSIGNAL */
	}
    }
}

/* Debugging message support */

#ifdef DEBUG
void
openswan_switch_fail(int n, const char *file_str, unsigned long line_no)
{
    char buf[30];

    snprintf(buf, sizeof(buf), "case %d unexpected", n);
    passert_fail(buf, file_str, line_no);
    /* NOTREACHED */
}

void
passert_fail(const char *pred_str, const char *file_str, unsigned long line_no)
{
    /* we will get a possibly unplanned prefix.  Hope it works */
    loglog(RC_LOG_SERIOUS, "ASSERTION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
    if (!dying_breath)
    {
	dying_breath = TRUE;
	show_status();
    }
    /* exiting correctly doesn't always work */
    openswan_log_abort(file_str, line_no);
}

void
pexpect_log(const char *pred_str, const char *file_str, unsigned long line_no)
{
    /* we will get a possibly unplanned prefix.  Hope it works */
    loglog(RC_LOG_SERIOUS, "EXPECTATION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
}

lset_t
    base_debugging = DBG_NONE,	/* default to reporting nothing */
    cur_debugging =  DBG_NONE;

void
extra_debugging(const struct connection *c)
{
    if(c == NULL)
    {
	reset_debugging();
	return;
    }

    if (c!= NULL && c->extra_debugging != 0)
    {
	openswan_log("extra debugging enabled for connection: %s"
	    , bitnamesof(debug_bit_names, c->extra_debugging & ~cur_debugging));
	set_debugging(cur_debugging | c->extra_debugging);
    }

    /*
     * if any debugging is no, make sure that we log the connection
     * we are processing, because it may not be clear in later debugging.
     */
    if(cur_debugging) {
	    char b1[CONN_INST_BUF];
	    fmt_conn_instance(c, b1);
	    DBG_log("processing connection %s%s"
		    , c->name, b1);
    }

}

void
set_debugging(lset_t deb)
{
    cur_debugging = deb;

    if(kernel_ops!=NULL && kernel_ops->set_debug!=NULL) {
	(*kernel_ops->set_debug)(cur_debugging, DBG_log, openswan_log);
    }
}

/* log a debugging message (prefixed by "| ") */

int
DBG_log(const char *message, ...)
{
    va_list args;
    char m[LOG_WIDTH];	/* longer messages will be truncated */

    va_start(args, message);
    vsnprintf(m, sizeof(m), message, args);
    va_end(args);

    /* then sanitize anything else that is left. */
    (void)sanitize_string(m, sizeof(m));

    if (log_to_stderr)
	fprintf(stderr, "%c %s\n", debug_prefix, m);
    if (log_to_syslog)
	syslog(LOG_DEBUG, "%c %s", debug_prefix, m);
    if (log_to_perpeer) {
	char prefix[3];
	prefix[0]=debug_prefix;
	prefix[1]=' ';
	prefix[2]='\n';
	peerlog(prefix, m);
    }

    return 0;
}

/* dump raw bytes in hex to stderr (for lack of any better destination) */

void
openswan_DBG_dump(const char *label, const void *p, size_t len)
{
#   define DUMP_LABEL_WIDTH 20	/* arbitrary modest boundary */
#   define DUMP_WIDTH	(4 * (1 + 4 * 3) + 1)
    char buf[DUMP_LABEL_WIDTH + DUMP_WIDTH];
    char *bp, *bufstart;
    const unsigned char *cp = p;

    bufstart = buf;

    if (label != NULL && label[0] != '\0')
    {
	/* Handle the label.  Care must be taken to avoid buffer overrun. */
	size_t llen = strlen(label);

	if (llen + 1 > sizeof(buf))
	{
	    DBG_log("%s", label);
	}
	else
	{
	    strcpy(buf, label);
	    if (buf[llen-1] == '\n')
	    {
		buf[llen-1] = '\0';	/* get rid of newline */
		DBG_log("%s", buf);
	    }
	    else if (llen < DUMP_LABEL_WIDTH)
	    {
		bufstart = buf + llen;
	    }
	    else
	    {
		DBG_log("%s", buf);
	    }
	}
    }

    bp = bufstart;
    do {
	int i, j;

	for (i = 0; len!=0 && i!=4; i++)
	{
	    *bp++ = ' ';
	    for (j = 0; len!=0 && j!=4; len--, j++)
	    {
		static const char hexdig[] = "0123456789abcdef";

		*bp++ = ' ';
		*bp++ = hexdig[(*cp >> 4) & 0xF];
		*bp++ = hexdig[*cp & 0xF];
		cp++;
	    }
	}
	*bp = '\0';
	DBG_log("%s", buf);
	bp = bufstart;
    } while (len != 0);
#   undef DUMP_LABEL_WIDTH
#   undef DUMP_WIDTH
}

#endif /* DEBUG */

void
show_status(void)
{
    show_kernel_interface();
    show_ifaces_status();
    show_myid_status();
    show_debug_status();
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
    show_virtual_private();
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
#ifdef KERNEL_ALG
    kernel_alg_show_status();
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
#endif
#ifdef IKE_ALG
    ike_alg_show_status();
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
#endif
#ifndef NO_DB_OPS_STATS
    db_ops_show_status();
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
#endif
    show_connections_status();
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
    show_states_status();
#ifdef KLIPS
    whack_log(RC_COMMENT, BLANK_FORMAT);	/* spacer */
    show_shunt_status();
#endif
}

/*
 * a routine that attempts to schedule itself daily.
 *
 */

void
daily_log_reset(void)
{
    /* now perform actions */
    logged_txt_warning = FALSE;

    logged_myid_fqdn_txt_warning = FALSE;
    logged_myid_ip_txt_warning   = FALSE;
    logged_myid_fqdn_key_warning = FALSE;
    logged_myid_ip_key_warning   = FALSE;
}

void
daily_log_event(void)
{
    struct tm *ltime;
    time_t n, interval;

    /* attempt to schedule oneself to midnight, local time
     * do this by getting seconds in the day, and delaying
     * by 86400 - hour*3600+minutes*60+seconds.
     */
    time(&n);
    ltime = localtime(&n);
    interval = (24 * 60 * 60)
      - (ltime->tm_sec
	 + ltime->tm_min  * 60
	 + ltime->tm_hour * 3600);

    event_schedule(EVENT_LOG_DAILY, interval, NULL);

    daily_log_reset();
}

#ifdef HAVE_STATSD
/*
 * we store runtime info for stats/status this way,
 * you may be able to do something similar using these hooks
 */

struct log_conn_info {
	struct connection *conn;
	struct state *ignore;		/* ignore this state */

	/* best completed state of connection */

	enum {
		tun_down=0,
		tun_phase1,
		tun_phase1up,
		tun_phase15,
		tun_phase2,
		tun_up
	} tunnel;

	/* best uncompleted state info for each phase */

	enum {
		p1_none=0,
		p1_init,
		p1_encrypt,
		p1_auth,
		p1_up,
		p1_down
	} phase1;

	enum {
		p2_none=0,
		p2_neg,
		p2_up,
	} phase2;
};

/*
 * we need to make sure we do not saturate the stats daemon
 * so we track what we have told it in a long (triple)
 */
#define	LOG_CONN_STATSVAL(lci) \
	((lci)->tunnel | ((lci)->phase1 << 4) | ((lci)->phase2 << 8))

static void
connection_state(struct state *st, void *data)
{
	struct log_conn_info *lc = data;

	if (!st || st == lc->ignore || !st->st_connection || !lc->conn)
		return;

	if (st->st_connection != lc->conn) {
		if (lc->conn->host_pair != st->st_connection->host_pair ||
			!same_peer_ids(lc->conn, st->st_connection, NULL))
		    return;
		/* phase1 is shared with another connnection */
	}

	/* ignore undefined states (ie., just deleted) */
	if (st->st_state == STATE_UNDEFINED)
		return;

	if (IS_PHASE1(st->st_state)) {
		if (lc->tunnel < tun_phase1)
			lc->tunnel = tun_phase1;
		if (IS_ISAKMP_SA_ESTABLISHED(st->st_state)) {
			if (lc->tunnel < tun_phase1up)
				lc->tunnel = tun_phase1up;
			lc->phase1 = p1_up;
		} else {
			if (lc->phase1 < p1_init)
				lc->phase1 = p1_init;
			if (IS_ISAKMP_ENCRYPTED(st->st_state) && lc->phase1 < p1_encrypt)
				lc->phase1 = p1_encrypt;
			if (IS_ISAKMP_AUTHENTICATED(st->st_state) && lc->phase1 < p1_auth)
				lc->phase1 = p1_auth;
		}
	} else lc->phase1 = p1_down;

	/* only phase one shares across connections, so we can quit now */
	if (st->st_connection != lc->conn)
		return;

	if (IS_PHASE15(st->st_state)) {
		if (lc->tunnel < tun_phase15)
			lc->tunnel = tun_phase15;
	}

	if (IS_QUICK(st->st_state)) {
		if (lc->tunnel < tun_phase2)
			lc->tunnel = tun_phase2;
		if (IS_IPSEC_SA_ESTABLISHED(st->st_state)) {
		   	if (lc->tunnel < tun_up)
				lc->tunnel = tun_up;
			lc->phase2 = p2_up;
		} else {
		   	if (lc->phase2 < p2_neg)
				lc->phase2 = p2_neg;
		}
	}
}

void
log_state(struct state *st, enum state_kind new_state)
{
	char buf[1024];
	struct log_conn_info lc;
	struct connection *conn;
	const char *tun = NULL, *p1 = NULL, *p2 = NULL;
	enum state_kind save_state;


	if (!st || !st->st_connection || !st->st_connection->name) {
		DBG(DBG_CONTROLMORE, DBG_log("log_state() called without state"));
		return;
	}

	conn = st->st_connection;
	if (!conn) {
		DBG(DBG_CONTROLMORE, DBG_log("log_state() called without st->st_connection (this line cannot fire)"));
		return;
	}

	DBG(DBG_CONTROLMORE, DBG_log("log_state called for state update for connection %s ", conn->name));
	memset(&lc, 0, sizeof(lc));
	lc.conn = conn;
	save_state = st->st_state;
	st->st_state = new_state;
	for_each_state((void *)connection_state, &lc);
	st->st_state = save_state;

	if (conn->statsval == (IPsecSAref2NFmark(st->st_ref) | LOG_CONN_STATSVAL(&lc))) {
		DBG(DBG_CONTROLMORE, DBG_log("log_state for connection %s state change signature (%d) matches last one - skip logging", conn->name, conn->statsval));
		return;
	}
	conn->statsval = IPsecSAref2NFmark(st->st_ref) | LOG_CONN_STATSVAL(&lc);
	DBG(DBG_CONTROLMORE, DBG_log("log_state set state change signature for connection %s to %d", conn->name, conn->statsval));

	switch (lc.tunnel) {
	case tun_phase1:  tun = "phase1";  break;
	case tun_phase1up:tun = "phase1up";break;
	case tun_phase15: tun = "phase15"; break;
	case tun_phase2:  tun = "phase2";  break;
	case tun_up:      tun = "up";      break;
	case tun_down:    tun = "down";    break; /* not set anywhere, default */
	default:          tun = "unchanged"; break;
	}

	switch (lc.phase1) {
	case p1_init:     p1 = "init";     break;
	case p1_encrypt:  p1 = "encrypt";  break;
	case p1_auth:     p1 = "auth";     break;
	case p1_up:       p1 = "up";       break;
	case p1_down:       p1 = "down";   break;
	default:          p1 = "unchanged";  break;
	}

	switch (lc.phase2) {
	case p2_neg:      p2 = "neg";      break;
	case p2_up:       p2 = "up";       break;
	default:          p2 = "down";     break;
	}
	DBG(DBG_CONTROLMORE, DBG_log("log_state calling openswan-statsd for connection %s with tunnel(%s) phase1(%s) phase2(%s)", conn->name, tun, p1, p2));

	snprintf(buf, sizeof(buf), "/bin/openswan-statsd "
			"%s ipsec-tunnel-%s if_stats /proc/net/dev/%s \\; "
			"%s ipsec-tunnel-%s tunnel %s \\; "
			"%s ipsec-tunnel-%s phase1 %s \\; "
			"%s ipsec-tunnel-%s phase2 %s \\; "
			"%s ipsec-tunnel-%s nfmark-me/him 0x%x/0x%x",

			conn->interface ? "push" : "drop", conn->name,
					conn->interface ? conn->interface->ip_dev->id_vname : "",
			tun ? "push" : "drop", conn->name, tun ? tun : "",
			p1  ? "push" : "drop", conn->name, p1  ? p1  : "",
			p2  ? "push" : "drop", conn->name, p2  ? p2  : "",
			(st->st_ref || st->st_refhim) ? "push" : "drop", conn->name,
				st->st_ref == IPSEC_SAREF_NA ? IPSEC_SAREF_NA
				: st->st_ref == IPSEC_SAREF_NULL ? 0u
				: IPsecSAref2NFmark(st->st_ref) | IPSEC_NFMARK_IS_SAREF_BIT
				,
				st->st_refhim == IPSEC_SAREF_NA ? IPSEC_SAREF_NA
				: st->st_refhim == IPSEC_SAREF_NULL ? 0u
				: IPsecSAref2NFmark(st->st_refhim) | IPSEC_NFMARK_IS_SAREF_BIT
		);
	system(buf);
	DBG(DBG_CONTROLMORE, DBG_log("log_state for connection %s completed", conn->name));
}

#endif

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
