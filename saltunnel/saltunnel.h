//
//  saltunnel_common.h
//  saltunnel2
//

#ifndef saltunnel_h
#define saltunnel_h

#include "cryptostream.h"

void exchange_messages_serial(cryptostream *ingress, cryptostream *egress, unsigned char* key);
void exchange_messages_parallel(cryptostream *ingress, cryptostream *egress, unsigned char* key);
void saltunnel(cryptostream* ingress, cryptostream* egress);

#endif /* saltunnel_common_h */