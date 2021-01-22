/* replacement for openswan.h */
#ifndef _LIBOPENSWAN_H
#define _LIBOPENSWAN_H
#include "openswan.h"

extern int ikev2_highorder_zerobits(ip_address b);
extern int ikev2_calc_iprangediff(ip_address low, ip_address high);
extern const char *family2str(unsigned int family);

#endif /* _LIBOPENSWAN_H */




