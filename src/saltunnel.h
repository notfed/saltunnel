//
//  saltunnel.h
//  saltunnel
//
//  This is the core, non-thread-polluted, saltunnel message handler which,
//  given 4 file descriptors, will proceed to pump messages back and forth
//  between them, and returning only after all file descriptors have closed.
//

#ifndef saltunnel_h
#define saltunnel_h

#include "cryptostream.h"

void saltunnel_init(void);
int saltunnel_mx(cryptostream* ingress, cryptostream* egress);

#endif /* saltunnel_h */
