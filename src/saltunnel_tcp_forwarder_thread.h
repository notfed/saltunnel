//
//  saltunnel_tcp_forwarder_thread.h
//  saltunnel
//
//  When a saltunnel TCP forwarder (either client or server) receives a
//  connection, this will be called, which will spawn a thread to proceed with
//  the saltunnel protocol.
//

#ifndef saltunnel_tcp_forwarder_thread_h
#define saltunnel_tcp_forwarder_thread_h

#include "cryptostream.h"
#include "saltunnel_kx.h"
#include "concurrentlist.h"

#include <pthread.h>

typedef struct connection_thread_context {
    cryptostream ingress;
    cryptostream egress;
    clienthi clienthi_plaintext_pinned;
    serverhi serverhi_plaintext_pinned;
    unsigned char long_term_key[32];
    unsigned char my_sk[32];
    unsigned char their_pk[32];
    unsigned char session_shared_keys[96]; // Client = [0..32), Server = [32..64), Tmp  = [64..96)
    const char* dest_ip;
    const char* dest_port;
    int src_fd;
    int dest_fd;
    // Thread-tracking variables
    concurrentlist* active_thread_list;
    concurrentlist* joinable_thread_list;
    concurrentlist_entry* active_thread_list_entry;
    pthread_t thread;
    // Server-vs-client dependent variables
    const char* log_name;
    int is_server;
} connection_thread_context;

pthread_t handle_connection(connection_thread_context* ctx);

#endif /* saltunnel_tcp_forwarder_thread_h */
