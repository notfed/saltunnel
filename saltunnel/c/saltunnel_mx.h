//
//  saltunnel_mx.h
//  saltunnel
//

#ifndef saltunnel_mx_h
#define saltunnel_mx_h

void exchange_messages_serial(cryptostream *ingress, cryptostream *egress);
void exchange_messages_parallel(cryptostream *ingress, cryptostream *egress);

#endif /* saltunnel_mx_h */
