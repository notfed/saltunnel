//
//  stopwatch.h
//  saltunnel2
//
//  Created by Jay Sullivan on 1/26/20.
//  Copyright © 2020 Jay Sullivan. All rights reserved.
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
