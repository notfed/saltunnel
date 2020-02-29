//
//  saltunnel_tcp_client.h
//  saltunnel
//

#ifndef saltunnel_tcp_client_h
#define saltunnel_tcp_client_h

int saltunnel_tcp_client_forwarder(unsigned char* long_term_shared_key,
                         const char* from_ip,
                         const char* from_port,
                         const char* to_ip,
                         const char* to_port);

#endif /* saltunnel_tcp_client_h */
