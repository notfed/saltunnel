//
//  stopwatch.c
//  saltunnel
//

#include "stopwatch.h"
#include "log.h"

void stopwatch_start(stopwatch* stopwatch) {
    gettimeofday(&stopwatch->time_started, NULL);
}
long stopwatch_elapsed(stopwatch* stopwatch) {
    struct timeval time_now;
    gettimeofday(&time_now, NULL);
    
    struct timeval time_elapsed;
    timersub(&time_now, &stopwatch->time_started, &time_elapsed);
    
    return time_elapsed.tv_sec*1000000+time_elapsed.tv_usec;
}
