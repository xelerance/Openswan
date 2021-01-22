#define LEAK_DETECTIVE
#define AGGRESSIVE 1
#define XAUTH 1
#define PRINT_SA_DEBUG 1
#define DEBUG 1
#include <stdlib.h>

#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "pluto/defs.h"
#include "pluto/db_ops.h"
#include "pluto/db2_ops.h"
#include "pluto/state.h"
#include "alg_info.h"

#include "sysqueue.h"
#include "pluto/connections.h"
#include "kernel.h"
#include "../seam_kernel.c"
#include "../seam_ipcomp.c"
#include "../seam_log.c"
#include "../seam_keys.c"
#include "../seam_whack.c"
