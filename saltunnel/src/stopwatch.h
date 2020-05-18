//
//  stopwatch.h
//  saltunnel
//

#ifndef stopwatch_h
#define stopwatch_h

#include <sys/time.h>

typedef struct stopwatch {
    struct timeval time_started;
} stopwatch;

void stopwatch_start(stopwatch* sw);
long stopwatch_elapsed(stopwatch* sw);

#endif /* stopwatch_h */
