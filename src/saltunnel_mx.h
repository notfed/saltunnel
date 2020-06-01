//
//  saltunnel_mx.h
//  saltunnel
//
//  Enters a loop which exchanges messages between ingress and egress. The loop
//  exits when both sides of the connection have closed.
//

#ifndef saltunnel_mx_h
#define saltunnel_mx_h

#include "cryptostream.h"

#define DIRECTION_EGRESS  0b00000001
#define DIRECTION_INGRESS 0b00000010
#define DIRECTION_BOTH    0b00000011

int saltunnel_mx(cryptostream* ingress, cryptostream* egress);

int exchange_messages_serial(cryptostream *ingress, cryptostream *egress, int direction);
int exchange_messages_parallel(cryptostream *ingress, cryptostream *egress);

#endif /* saltunnel_mx_h */
