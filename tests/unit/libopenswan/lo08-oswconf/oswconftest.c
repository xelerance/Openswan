#define DEBUG
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include "openswan.h"
#include "openswan/passert.h"
#include "constants.h"
#include "oswalloc.h"
#include "oswlog.h"
#include "oswconf.h"

const char *progname;

void exit_tool(int stat)
{
    exit(stat);
}

int main(int argc, char *argv[])
{
    tool_init_log();
    progname = argv[0];

    struct osw_conf_options *oco = osw_init_options();

    struct osw_conf_options *also = osw_conf_clone(oco);
    osw_conf_free_oco(oco);
    osw_conf_free_oco(also);

    report_leaks();
    tool_close_log();
    exit(0);
}

/*
 * Local Variables:
 * c-style: pluto
 * c-basic-offset: 4
 * End:
 */
