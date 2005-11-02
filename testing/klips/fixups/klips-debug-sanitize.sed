s/pid=\([0-9]*\)\./pid=987./
s/(pid=\([0-9]*\))/(pid=987)/
s/0p[A-Fa-f0-9]\{8\}/0pDEADF00D/g
s/0p0x[A-Fa-f0-9]\{8\}/0pDEADF00D/g
s/data:[0-9A-Fa-f ][0-9A-Fa-f]:.*$/data:/
/klips_debug:pfkey_destroy_socket: pfkey_skb contents:.*/d
/2: .*destructor:0p/d
/klips_debug:ipsec_sadb_cleanup: removing all SArefFreeList entries from circulation./d
/klips_debug:ipsec_sadb_init: initialising main table./d
/^012345$/d
/klips_info:ipsec_init: KLIPS startup, FreeS\/WAN IPSec version: .*/d
/klips_info:pfkey_cleanup: shutting down PF_KEY domain sockets./d
/klips_info:cleanup_module: ipsec module unloaded./d

