//
//  cryptostream_worker.h
//  saltunnel2
//
//  Created by Jay Sullivan on 1/26/20.
//  Copyright © 2020 Jay Sullivan. All rights reserved.
//

#ifndef cryptostream_worker_h
#define cryptostream_worker_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

typedef struct cryptostream_worker_thread {
    
   struct pthread_barrier_t* barrier;
   void (*work)(void);
    
} cryptostream_worker_thread;

#endif /* cryptostream_worker_h */
