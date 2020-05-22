//
//  saltunnel_mx.h
//  saltunnel
//

#ifndef saltunnel_mx_h
#define saltunnel_mx_h

int exchange_messages_serial(cryptostream *ingress, cryptostream *egress);
int exchange_messages_parallel(cryptostream *ingress, cryptostream *egress);

#endif /* saltunnel_mx_h */
