#include <mini.h>

#if 0 // def ENABLE_RECORD
void record(const char *fmt, ...)
{
    static char   buf[1024];

    va_list       args;
    char         *p, *q;

    /* console_lock can be acquired recursively from __printk_ratelimit(). */

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);        

    p = buf;
}
#endif
