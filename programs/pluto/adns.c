/* Pluto Asynchronous DNS Helper Program -- for internal use only!
 * Copyright (C) 2002  D. Hugh Redelmeier.
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

/* This program executes as multiple processes.  The Master process
 * receives queries (struct adns_query messages) from Pluto and distributes
 * them amongst Worker processes.  These Worker processes are created
 * by the Master whenever a query arrives and no existing Worker is free.
 * At most MAX_WORKERS will be created; after that, the Master will queue
 * queries until a Worker becomes free.  When a Worker has an answer from
 * the resolver, it sends the answer as a struct adns_answer message to the
 * Master.  The Master then forwards the answer to Pluto, noting that
 * the Worker is free to accept another query.
 *
 * The protocol is simple: Pluto sends a sequence of queries and receives
 * a sequence of answers.  select(2) is used by Pluto and by the Master
 * process to decide when to read, but writes are done without checking
 * for readiness.  Communications is via pipes.  Since only one process
 * can write to each pipe, messages will not be interleaved.  Fixed length
 * records are used for simplicity.
 *
 * Pluto needs a way to indicate to the Master when to shut down
 * and the Master needs to indicate this to each worker.  EOF on the pipe
 * signifies this.
 *
 * The interfaces between these components are considered private to
 * Pluto.  This allows us to get away with less checking.  This is a
 * reason to use pipes instead of TCP/IP.
 *
 * Although the code uses plain old UNIX processes, it could be modified
 * to use threads.  That might reduce resource requirements.  It would
 * preclude running on systems without thread-safe resolvers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/socket.h>
#define __USE_GNU       /* enables additional EAI_* */
#include <netdb.h>	/* for h_errno and getaddrinfo */

#include <openswan.h>
#include <oswlog.h>

/* GCC magic! */
#ifdef GCC_LINT
# define UNUSED __attribute__ ((unused))
#else
# define UNUSED /* ignore */
#endif

#include "setproctitle.h"
#include "constants.h"
#include "adns.h"	/* needs <resolv.h> */
#include "osw_select.h"
#include "oswalloc.h"

/* shared by all processes */

static bool debug = FALSE;

/* Read a variable-length record from a pipe (and no more!).
 * First bytes must be a size_t containing the length.
 * HES_CONTINUE if record read
 * HES_OK if EOF
 * HES_IO_ERROR_IN if errno tells the tale.
 * Others are errors.
 */
static enum helper_exit_status
read_pipe(int fd, unsigned char *stuff, size_t minlen, size_t maxlen)
{
    size_t n = 0;
    size_t goal = minlen;

    do {
	ssize_t m = read(fd, stuff + n, goal - n);

	if (m == -1)
	{
	    if (errno != EINTR)
	    {
		openswan_log("Input error on pipe: %s", strerror(errno));
		return HES_IO_ERROR_IN;
	    }
	}
	else if (m == 0)
	{
	    return HES_OK;	/* treat empty message as EOF */
	}
	else
	{
	    n += m;
	    if (n >= sizeof(size_t))
	    {
		goal = *(size_t *)(void *)stuff;
		if (goal < minlen || maxlen < goal)
		{
		    if (debug)
			fprintf(stderr, "%lu : [%lu, %lu]\n"
			    , (unsigned long)goal
			    , (unsigned long)minlen, (unsigned long)maxlen);
		    return HES_BAD_LEN;
		}
	    }
	}
    } while (n < goal);

    return HES_CONTINUE;
}

/* Write a variable-length record to a pipe.
 * First bytes must be a size_t containing the length.
 * HES_CONTINUE if record written
 * Others are errors.
 */
static enum helper_exit_status
write_pipe(int fd, const unsigned char *stuff)
{
    size_t len = *(const size_t *)(const void *)stuff;
    size_t n = 0;

    setproctitle(progname, "answering");
    do {
	ssize_t m = write(fd, stuff + n, len - n);

	if (m == -1)
	{
	    /* error, but ignore and retry if EINTR */
	    if (errno != EINTR)
	    {
		openswan_log("Output error from master: %s", strerror(errno));
		return HES_IO_ERROR_OUT;
	    }
	}
	else
	{
	    n += m;
	}
    } while (n != len);
    return HES_CONTINUE;
}

/**************** worker process ****************/

/* The interface in RHL6.x and BIND distribution 8.2.2 are different,
 * so we build some of our own :-(
 */

/* Support deprecated interface to allow for older releases of the resolver.
 * Fake new interface!
 * See resolver(3) bind distribution (should be in RHL6.1, but isn't).
 * __RES was 19960801 in RHL6.2, an old resolver.
 */

#undef OLD_RESOLVER

#if (__RES) <= 19960801
# define OLD_RESOLVER	1
#endif

#ifdef __UCLIBC__
#define OLD_RESOLVER 1
#endif

#ifdef OLD_RESOLVER

# define res_ninit(statp) res_init()
# define res_nquery(statp, dname, class, type, answer, anslen) \
    res_query(dname, class, type, answer, anslen)
# define res_nclose(statp) res_close()

#define statp  ((struct __res_state *)(&_res))

#else /* !OLD_RESOLVER */

static struct __res_state my_res_state /* = { 0 } */;
static res_state statp = &my_res_state;

#endif /* !OLD_RESOLVER */

#define SIZEOF_PREAMBLE sizeof(ai->ai_addrlen)+sizeof(ai->ai_protocol)+sizeof(ai->ai_family)
int serialize_addr_info(struct addrinfo *result
                        , u_char *ansbuf
                        , int     ansbuf_len)
{
    volatile unsigned int size_left = ansbuf_len;
    struct addrinfo *ai;

#define SERIALIZE_THING_LEN(thing, thing_size) do {   \
        memcpy(ansbuf, thing, thing_size); \
        ansbuf     += thing_size; \
        size_left  -= thing_size; } while(0)
#define SERIALIZE_THING(thing) SERIALIZE_THING_LEN(thing, sizeof(*thing))

    /* start by counting how many there are */
    for(ai=result; ai!=NULL; ai = ai->ai_next) {
        if(size_left > (SIZEOF_PREAMBLE+ai->ai_addrlen)) {
            SERIALIZE_THING(&ai->ai_protocol);
            SERIALIZE_THING(&ai->ai_family);
            SERIALIZE_THING(&ai->ai_addrlen);
            SERIALIZE_THING_LEN(ai->ai_addr, ai->ai_addrlen);
        }
    }
#undef SERIALIZE_THING
#undef SERIALIZE_THING_LEN

    return (ansbuf_len - size_left);
}

/*
 * undo above encoding, and return an object mostly just like getaddrinfo()
 */
struct addrinfo *deserialize_addr_info(u_char *ansbuf
                                       , int     ansbuf_len)
{
    unsigned int size_left = ansbuf_len;
    struct addrinfo *ai1, *ai, **ainext;

#define DESERIALIZE_THING_LEN(thing, thing_size) do {   \
        memcpy(thing, ansbuf, thing_size);        \
        ansbuf     += thing_size; \
        size_left  -= thing_size; } while(0)
#define DESERIALIZE_THING(thing) DESERIALIZE_THING_LEN(thing, sizeof(*thing))

    ai = NULL;
    ai1= NULL;
    ainext = &ai;
    /* deserialize until nothing can be got out of it */
    while(size_left >= SIZEOF_PREAMBLE) {
        struct addrinfo t1;
	zero(&t1);

        DESERIALIZE_THING(&t1.ai_protocol);
        DESERIALIZE_THING(&t1.ai_family);
        DESERIALIZE_THING(&t1.ai_addrlen);

        if(size_left >= t1.ai_addrlen
           && t1.ai_addrlen < 1024         /* impose arbitrary big maximum */
           && t1.ai_addrlen > 0) {
            ai1 = alloc_thing(*ai1, "addrinfo");
            zero(ai1);
            if(ainext) *ainext = ai1;
            *ai1 = t1;

            ai1->ai_addr = alloc_bytes(ai1->ai_addrlen, "addrinfo sockaddr");
            if(ai->ai_addr) {
                DESERIALIZE_THING_LEN(ai1->ai_addr, ai1->ai_addrlen);
            }
        }
        if(ai1->ai_addr == NULL) {
            openswan_log("failed to allocated %d bytes in deserialize_addr_info", ai->ai_addrlen);
            break;
        }
        ainext = &ai1->ai_next;
    }
#undef DESERIALIZE_THING
#undef DESERIALIZE_THING_LEN
    return ai;
}

/* this routine is needed because above routine uses alloc_bytes, rather than malloc */
void osw_freeaddrinfo(struct addrinfo *ai)
{
    struct addrinfo *ain = NULL;
    while(ai != NULL) {
        ain = ai->ai_next;
        pfreeany(ai->ai_addr);
        pfree(ai);
        ai  = ain;
    }
}

static int
worker(int qfd, int afd)
{
    setproctitle(progname, "worker");
    {
	int r = res_ninit(statp);

	if (r != 0)
	{
	    openswan_log("cannot initialize resolver");
	    return HES_RES_INIT;
	}
#ifndef OLD_RESOLVER
	statp->options |= RES_ROTATE;
#endif
	statp->options |= RES_DEBUG;
    }

    for (;;)
    {
	struct adns_query q;
	struct adns_answer a;
        struct addrinfo *result;
        struct addrinfo hints;
        int s;
        char status[1024+16]; // this must shut up GCC

	enum helper_exit_status r = read_pipe(qfd, (unsigned char *)&q
	    , sizeof(q), sizeof(q));

	if (r != HES_CONTINUE)
	    return r;	/* some kind of exit */

	if (q.qmagic != ADNS_Q_MAGIC)
	{
	    openswan_log("error in input from master: bad magic");
	    return HES_BAD_MAGIC;
	}

	a.amagic = ADNS_A_MAGIC;
	a.serial = q.serial;

        snprintf(status, sizeof(status), "query: %s", q.name_buf);
        setproctitle(progname, status);

        switch(q.type) {
        case ns_t_txt:
        case ns_t_key:
            a.result = res_nquery(statp, q.name_buf, ns_c_in, q.type, a.ans, sizeof(a.ans));
            switch(h_errno) {
            case NO_DATA:
                a.h_errno_val = EAI_NODATA;
                break;
            case HOST_NOT_FOUND:
                a.h_errno_val = EAI_NONAME;
                break;
            case TRY_AGAIN:
                a.h_errno_val = EAI_AGAIN;
                break;
            default:
            case NO_RECOVERY:
                a.h_errno_val = EAI_SYSTEM;
                break;
            }
            break;

        case ns_t_a:
            /* actually, use getaddrinfo() to do lookup, which does A and AAAA */
            hints.ai_family = q.addr_family;     /* Allow IPv4 or IPv6 */
            hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
            hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
            hints.ai_protocol = 0;          /* Any protocol */
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;

            s = getaddrinfo(q.name_buf, NULL, &hints, &result);
            switch(s) {
            case 0: /* success! */
                a.result = serialize_addr_info(result, a.ans, ADNS_ANS_SIZE);
                break;

                /* not found */
            case EAI_NONAME:
            case EAI_NODATA:
                a.h_errno_val = s;
                a.result = -1;
                break;

            default:
                openswan_log("adns lookup: %s a/aaaa lookup error: %s"
                             , q.name_buf, gai_strerror(s));
                a.h_errno_val = s;
                a.result = -1;
                break;
            }
        }
        a.len = offsetof(struct adns_answer, ans) + (a.result < 0? 0 : a.result);

#ifdef DEBUG
	if (((q.debugging & IMPAIR_DELAY_ADNS_KEY_ANSWER) && q.type == ns_t_key)
	|| ((q.debugging & IMPAIR_DELAY_ADNS_TXT_ANSWER) && q.type == ns_t_txt))
	    sleep(30);	/* delay the answer */
#endif

	/* write answer, possibly a bit at a time */
	r = write_pipe(afd, (const unsigned char *)&a);

	if (r != HES_CONTINUE)
	    return r;	/* some kind of exit */
    }
}

/**************** master process ****************/

bool eof_from_pluto = FALSE;
#define PLUTO_QFD	0	/* queries come on stdin */
#define PLUTO_AFD	1	/* answers go out on stdout */

#ifndef MAX_WORKERS
# define MAX_WORKERS 10	/* number of in-flight queries */
#endif

struct worker_info {
    int qfd;	/* query pipe's file descriptor */
    int afd;	/* answer pipe's file descriptor */
    pid_t pid;
    bool busy;
};

static struct worker_info wi[MAX_WORKERS];
static struct worker_info *wi_roof = wi;

/* request FIFO */

struct query_list {
    struct query_list *next;
    struct adns_query aq;
};

static struct query_list *oldest_query = NULL;
static struct query_list *newest_query;	/* undefined when oldest == NULL */
static struct query_list *free_queries = NULL;

static bool
spawn_worker(void)
{
    int qfds[2];
    int afds[2];
    pid_t p;

    if (pipe(qfds) != 0 || pipe(afds) != 0)
    {
	openswan_log("pipe(2) failed: %s", strerror(errno));
	exit(HES_PIPE);
    }

    wi_roof->qfd = qfds[1];	/* write end of query pipe */
    wi_roof->afd = afds[0];	/* read end of answer pipe */

    p = fork();
    if (p == -1)
    {
	/* fork failed: ignore if at least one worker exists */
	if (wi_roof == wi)
	{
	    openswan_log("fork(2) error creating first worker: %s", strerror(errno));
	    exit(HES_FORK);
	}
	close(qfds[0]);
	close(qfds[1]);
	close(afds[0]);
	close(afds[1]);
	return FALSE;
    }
    else if (p == 0)
    {
	/* child */
	struct worker_info *w;

	close(PLUTO_QFD);
	close(PLUTO_AFD);
	/* close all master pipes, including ours */
	for (w = wi; w <= wi_roof; w++)
	{
	    close(w->qfd);
	    close(w->afd);
	}
	_exit(worker(qfds[0], afds[1]));
    }
    else
    {
	/* parent */
	struct worker_info *w = wi_roof++;

	w->pid = p;
	w->busy = FALSE;
	close(qfds[0]);
	close(afds[1]);
	return TRUE;
    }
}

static void
send_eof(struct worker_info *w)
{
    pid_t p;
    int status;

    close(w->qfd);
    w->qfd = NULL_FD;

    close(w->afd);
    w->afd = NULL_FD;

    /* reap child */
    p = waitpid(w->pid, &status, 0);
    /* ignore result -- what could we do with it? */
    if(p == -1) {
	    openswan_log("waitpid(2) failed, ignored");
    }
}

static void
forward_query(struct worker_info *w)
{
    struct query_list *q = oldest_query;

    if (q == NULL)
    {
	if (eof_from_pluto)
	    send_eof(w);
    }
    else
    {
	enum helper_exit_status r
	    = write_pipe(w->qfd, (const unsigned char *) &q->aq);

	if (r != HES_CONTINUE)
	    exit(r);

	w->busy = TRUE;

	oldest_query = q->next;
	q->next = free_queries;
	free_queries = q;
    }
}

static void
query(void)
{
    struct query_list *q = free_queries;
    enum helper_exit_status r;
    setproctitle(progname, "processing query");
    /* find an unused queue entry */
    if (q == NULL)
    {
	q = malloc(sizeof(*q));
	if (q == NULL)
	{
	    openswan_log("malloc(3) failed");
	    exit(HES_MALLOC);
	}
    }
    else
    {
	free_queries = q->next;
    }

    r = read_pipe(PLUTO_QFD, (unsigned char *)&q->aq
	, sizeof(q->aq), sizeof(q->aq));

    if (r == HES_OK)
    {
	/* EOF: we're done, except for unanswered queries */
	struct worker_info *w;

	eof_from_pluto = TRUE;
	q->next = free_queries;
	free_queries = q;

	/* Send bye-bye to unbusy processes.
	 * Note that if there are queued queries, there won't be
	 * any non-busy workers.
	 */
	for (w = wi; w != wi_roof; w++)
	    if (!w->busy)
		send_eof(w);
    }
    else if (r != HES_CONTINUE)
    {
	exit(r);
    }
    else if (q->aq.qmagic != ADNS_Q_MAGIC)
    {
	openswan_log("error in query from Pluto: bad magic");
	exit(HES_BAD_MAGIC);
    }
    else
    {
	struct worker_info *w;

	/* got a query */

	/* add it to FIFO */
	q->next = NULL;
	if (oldest_query == NULL)
	    oldest_query = q;
	else
	    newest_query->next = q;
	newest_query = q;

	/* See if any worker available */
	for (w = wi; ; w++)
	{
	    if (w == wi_roof)
	    {
		/* no free worker */
		if (w == wi + MAX_WORKERS)
		    break;	/* no more to be created */
		/* make a new one */
		if (!spawn_worker())
		    break;	/* cannot create one at this time */
	    }
	    if (!w->busy)
	    {
		/* assign first to free worker */
		forward_query(w);
		break;
	    }
	}
    }
    return;
}

static void
answer(struct worker_info *w)
{
    struct adns_answer a;
    enum helper_exit_status r = read_pipe(w->afd, (unsigned char *)&a
	, offsetof(struct adns_answer, ans), sizeof(a));

    if (r == HES_OK)
    {
	/* unexpected EOF */
	openswan_log("unexpected EOF from worker");
	exit(HES_IO_ERROR_IN);
    }
    else if (r != HES_CONTINUE)
    {
	exit(r);
    }
    else if (a.amagic != ADNS_A_MAGIC)
    {
	openswan_log("Input from worker error: bad magic");
	exit(HES_BAD_MAGIC);
    }
    else
    {
	/* pass the answer on to Pluto */
	enum helper_exit_status rs
	    = write_pipe(PLUTO_AFD, (const unsigned char *) &a);

	if (rs != HES_CONTINUE)
	    exit(rs);
        setproctitle(progname, "<idle>");
	w->busy = FALSE;
	forward_query(w);
    }
}

/* assumption: input limited; accept blocking on output */
static int
master(void)
{
    for (;;)
    {
	osw_fd_set readfds;
	int maxfd = PLUTO_QFD;		/* approximate lower bound */
	int ndes = 0;
	struct worker_info *w;

	OSW_FD_ZERO(&readfds);
	if (!eof_from_pluto)
	{
	    OSW_FD_SET(PLUTO_QFD, &readfds);
	    ndes++;
	}
	for (w = wi; w != wi_roof; w++)
	{
	    if (w->busy)
	    {
		OSW_FD_SET(w->afd, &readfds);
		ndes++;
		if (maxfd < w->afd)
		    maxfd = w->afd;
	    }
	}

	if (ndes == 0)
	    return HES_OK;	/* done! */

	do {
            setproctitle(progname, "<idle>");
            ndes = osw_select(maxfd + 1, &readfds, NULL, NULL, NULL);
	} while (ndes == -1 && errno == EINTR);
	if (ndes == -1)
	{
	    openswan_log("select(2) error: %s", strerror(errno));
	    exit(HES_IO_ERROR_SELECT);
	}
	else if (ndes > 0)
	{
	    if (OSW_FD_ISSET(PLUTO_QFD, &readfds))
	    {
		query();
		ndes--;
	    }
	    for (w = wi; ndes > 0 && w != wi_roof; w++)
	    {
		if (w->busy && OSW_FD_ISSET(w->afd, &readfds))
		{
		    answer(w);
		    ndes--;
		}
	    }
	}
    }
}

int adns_main(int debugval)
{
  progname = "_pluto_adns";  /* stupid const pointers */

  setproctitle(progname, "<idle>");

  debug = debugval;
  return master();
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

