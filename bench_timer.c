
#include <sys/time.h>
#include <stdio.h>

#include "bench_timer.h"

static double g_t1 = 0;
static double migrate_global_t1 = 0;
static double blockmigration_global_t1 = 0;

static double gettimeofday_sec(void)
{
    struct timeval tv;
    unsigned long msec;
    gettimeofday(&tv, NULL);
    msec = (tv.tv_sec * 1000.0) + (unsigned long)(tv.tv_usec / 1000.0);
    return (double)msec / 1000.0;
}

void set_migrate_global_timer(void)
{
    migrate_global_t1 = gettimeofday_sec();
}

double stop_migrate_global_timer(void)
{
    double g_t2 = gettimeofday_sec();
    return g_t2 - migrate_global_t1;
}

void set_blockmigration_global_timer(void)
{
    blockmigration_global_t1 = gettimeofday_sec();
}

double stop_blockmigration_global_timer(void)
{
    double g_t2 = gettimeofday_sec();
    return g_t2 - blockmigration_global_t1;
}

void settimer(void)
{
    g_t1 = gettimeofday_sec();
}

double stoptimer(void)
{
    double g_t2 = gettimeofday_sec();
    return (g_t2 - g_t1);
}

