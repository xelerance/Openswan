#ifndef _OSW_SELECT_H_
#define _OSW_SELECT_H_ 1
/*
 * Overlay the system select call to handle many more FD's than
 * an fd_set can hold.
 * David McCullough <david_mccullough@securecomputing.com>
 */

#include <sys/select.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * allow build system to override the limit easily
 */

#ifndef OSW_FD_SETSIZE
#define OSW_FD_SETSIZE	8192
#endif

#define OSW_NFDBITS   (8 * sizeof (long int))
#define OSW_FDELT(d)  ((d) / OSW_NFDBITS)
#define OSW_FDMASK(d) ((long int) 1 << ((d) % OSW_NFDBITS))
#define OSW_FD_SETCOUNT	((OSW_FD_SETSIZE + OSW_NFDBITS - 1) / OSW_NFDBITS)

typedef struct {
	long int	__osfds_bits[OSW_FD_SETCOUNT];
} osw_fd_set;

#define OSW_FDS_BITS(set) ((set)->__osfds_bits)

#define OSW_FD_ZERO(set) \
	do { \
		unsigned int __i; \
		osw_fd_set *__arr = (set); \
		for (__i = 0; __i < OSW_FD_SETCOUNT; __i++) \
			OSW_FDS_BITS (__arr)[__i] = 0; \
	} while(0)

#define OSW_FD_SET(d, s)     (OSW_FDS_BITS (s)[OSW_FDELT(d)] |= OSW_FDMASK(d))
#define OSW_FD_CLR(d, s)     (OSW_FDS_BITS (s)[OSW_FDELT(d)] &= ~OSW_FDMASK(d))
#define OSW_FD_ISSET(d, s)   ((OSW_FDS_BITS (s)[OSW_FDELT(d)] & OSW_FDMASK(d)) != 0)

#define osw_select(max, r, f, e, t) \
		select(max, (fd_set *)(r), (fd_set *)(f), (fd_set *)(e), t)

#endif /* _OSW_SELECT_H_ */
