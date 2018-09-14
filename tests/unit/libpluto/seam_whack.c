#ifndef __seam_whack_c__
#define __seam_whack_c__
void whack_log(int rc, const char *msg, ...)
{
    va_list args;

    va_start(args, msg);
    fprintf(stderr, "RC=%u ", rc);
    vfprintf(stderr, msg, args);
    putc('\n', stderr);
    va_end(args);
}

#endif
