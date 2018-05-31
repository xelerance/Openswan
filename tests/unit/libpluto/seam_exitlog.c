#ifndef __seam_exitlog_c__
#define __seam_exitlog_c__
/* LINK seams */
void exit_log(const char *msg, ...)
{
    osw_abort();
}

void exit_tool(int status)
{
    exit(status);
}

void exit_pluto(int status)
{
    exit(status);
}

#endif
