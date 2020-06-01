//
//  saltunnel_tcp_server_forwarder.h
//  saltunnel
//
//  Enters an infinite loop, listening for connections (from the "from"
//  endpoint). Upon receiving a connection request, spawns a thread which
//  connects to the "to" endpoint, and proceeds with the saltunnel protocol
//  between both endpoints.
//

#ifndef saltunnel_tcp_server_forwarder_h
#define saltunnel_tcp_server_forwarder_h

#include "cache.h"

int saltunnel_tcp_server_forwarder(
                         cache *table,
                         unsigned char* long_term_shared_key,
                         const char* from_ip,
                         const char* from_port,
                         const char* to_ip,
                         const char* to_port);
                         
#endif /* saltunnel_tcp_server_forwarder_h */
