//
//  stopwatch.c
//  saltunnel
//

#include "stopwatch.h"
#include "log.h"

#include <time.h>

void stopwatch_start(stopwatch* stopwatch) {
    clock_gettime(CLOCK_MONOTONIC, &stopwatch->time_started);
}

long stopwatch_elapsed_us(stopwatch* stopwatch) {
    struct timespec time_now;
    clock_gettime(CLOCK_MONOTONIC, &time_now);
    return (time_now.tv_sec  - stopwatch->time_started.tv_sec)*1000000l
         + (time_now.tv_nsec - stopwatch->time_started.tv_nsec)/1000l;
}
