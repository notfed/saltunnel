//
//  saltunnel_tcp_client_forwarder_h
//  saltunnel
//
//  Enters an infinite loop, listening for connections (from the "from"
//  endpoint). Upon receiving a connection request, spawns a thread which
//  connects to the "to" endpoint, and proceeds with the saltunnel protocol
//  between both endpoints.
//

#ifndef saltunnel_tcp_client_forwarder_h
#define saltunnel_tcp_client_forwarder_h

#include <pthread.h>

int saltunnel_tcp_client_forwarder(unsigned char* long_term_shared_key,
                         const char* from_ip,
                         const char* from_port,
                         const char* to_ip,
                         const char* to_port);

pthread_t saltunnel_tcp_client_forwarder_async(unsigned char* long_term_shared_key,
                                               const char* from_ip, const char* from_port,
                                               const char* to_ip, const char* to_port);

#endif /* saltunnel_tcp_client_forwarder_h) */
