#include "common.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#define RATELOG_INTERVAL_MS 5000

uint64_t ufw_mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

uint64_t ufw_realtime_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec;
}

void ufw_log(const char *level, const char *fmt, ...)
{
    struct timespec ts;
    struct tm tm;
    char tbuf[32];
    va_list ap;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(stderr, "%s.%03ld [%s] ", tbuf, ts.tv_nsec / 1000000L, level);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

int ufw_set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;
    return 0;
}

void ufw_ratelog_reset(struct ufw_ratelog *rl)
{
    rl->next_ms = 0;
    rl->count = 0;
}

void ufw_ratelog_emit(struct ufw_ratelog *rl, const char *level, const char *fmt, ...)
{
    uint64_t now = ufw_mono_ms();
    char msg[256];
    va_list ap;

    rl->count++;
    if (now < rl->next_ms)
        return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (rl->count > 1)
        ufw_log(level, "%s (%llu times since the last output)", msg, (unsigned long long)rl->count);
    else
        ufw_log(level, "%s", msg);
    rl->count = 0;
    rl->next_ms = now + RATELOG_INTERVAL_MS;
}
