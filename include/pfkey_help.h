#ifndef _PFKEY_HELP_H
#define _PFKEY_HELP_H

/* opens a pfkey socket, or dumps to stderr the reason why it failed */
extern int pfkey_open_sock_with_error(void);

extern void pfkey_write_error(int writeerror, int err);

#endif /* _PFKEY_HELP_H */



