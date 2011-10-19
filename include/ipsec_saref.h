/* Older patches used 22/23, but the kernel started using those, so we
 * bumped it to 30/31. Make sure you use the same number in the kernel
 * SAref patches and in the xl2tpd 'saref refinfo ' option
 */

#ifndef IP_IPSEC_REFINFO
/* #define IP_IPSEC_REFINFO 22 */
#define IP_IPSEC_REFINFO 30
#endif

#ifndef IP_IPSEC_BINDREF
/* #define IP_IPSEC_BINDREF 23 */
#define IP_IPSEC_BINDREF 31
#endif

