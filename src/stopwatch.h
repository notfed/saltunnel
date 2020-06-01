//
//  stopwatch.h
//  saltunnel
//

#ifndef stopwatch_h
#define stopwatch_h

#include <time.h>

typedef struct stopwatch {
    struct timespec time_started;
} stopwatch;

void stopwatch_start(stopwatch* sw);
long stopwatch_elapsed_us(stopwatch* sw);

#endif /* stopwatch_h */
