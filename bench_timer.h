
#ifndef _BENCH_TIMER_H_
#define _BENCH_TIMER_H_

void set_migrate_global_timer(void);
double stop_migrate_global_timer(void);
void set_blockmigration_global_timer(void);
double stop_blockmigration_global_timer(void);
void settimer(void);
double stoptimer(void);

#endif
