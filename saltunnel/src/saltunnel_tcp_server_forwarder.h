//
//  saltunnel_tcp_server_forwarder.h
//  saltunnel
//

#include "cache.h"

#ifndef saltunnel_tcp_server_forwarder_h
#define saltunnel_tcp_server_forwarder_h

int saltunnel_tcp_server_forwarder(
                         cache *table,
                         unsigned char* long_term_shared_key,
                         const char* from_ip,
                         const char* from_port,
                         const char* to_ip,
                         const char* to_port);
    
#endif /* saltunnel_tcp_server_forwarder_h */
