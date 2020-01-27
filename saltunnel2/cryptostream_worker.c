//
//  cryptostream_worker.c
//  saltunnel2
//
//  Created by Jay Sullivan on 1/26/20.
//  Copyright © 2020 Jay Sullivan. All rights reserved.
//

#include "cryptostream_worker.h"
//
//static pthread_t initialize_worker_thread(cryptostream* ingress)
//{
//    pthread_t pt = saltunnel_thread("speer1",&context1_ingress, &context1_egress);
//    saltunnel_thread_context* c = calloc(1,sizeof(saltunnel_thread_context));
//    c->thread_name = thread_name;
//    c->ingress = ingress;
//    c->egress = egress;
//    pthread_t thread;
//    pthread_create(&thread, NULL, saltunnel_thread_inner, (void*)c)==0 || oops_fatal("pthread_create failed");
//    return thread;
//}
//static pthread_t initialize_worker_threads(cryptostream* ingress)
//{
//    pthread_t saltunnel_thread_1 = saltunnel_thread("speer1",&context1_ingress, &context1_egress);
//    saltunnel_thread_context* c = calloc(1,sizeof(saltunnel_thread_context));
//    c->thread_name = thread_name;
//    c->ingress = ingress;
//    c->egress = egress;
//    pthread_t thread;
//    pthread_create(&thread, NULL, saltunnel_thread_inner, (void*)c)==0 || oops_fatal("pthread_create failed");
//    return thread;
//}
