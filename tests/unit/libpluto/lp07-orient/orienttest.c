#include "orienttest_head.c"
#define init_local_interface(X) init_parker_interface(X)
#define init_fake_secrets() do {} while(0)
#include "orienttest_main.c"
