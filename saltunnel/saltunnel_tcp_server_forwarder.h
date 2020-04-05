//
//  saltunnel_tcp_server_forwarder.h
//  saltunnel
//

#include "hashtable.h"

#ifndef saltunnel_tcp_server_h
#define saltunnel_tcp_server_h

int saltunnel_tcp_server_forwarder(
                         hashtable *table,
                         unsigned char* long_term_shared_key,
                         const char* from_ip,
                         const char* from_port,
                         const char* to_ip,
                         const char* to_port);
    
#endif /* saltunnel_tcp_server.h */
