//
//  config.h
//  saltunnel
//
//  A collection of compile-time configuration options.
//

#ifndef config_h
#define config_h

#ifndef SALTUNNEL_PUMP_THREADS
#define SALTUNNEL_PUMP_THREADS 2
#endif

#ifndef THREADPOOL_POOLS
#define THREADPOOL_POOLS 1
#endif

#ifndef THREADPOOL_THREAD_COUNT
#define THREADPOOL_THREAD_COUNT 4
#endif

extern int config_connection_timeout_ms;
extern int config_max_connections;

#endif /* config_h */
