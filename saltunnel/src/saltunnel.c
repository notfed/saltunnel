//
//  saltunnel.c
//  saltunnel
//

#include "saltunnel.h"
#include "saltunnel_mx.h"
#include "config.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

void saltunnel(cryptostream* ingress, cryptostream* egress) {

//    // Input Long-term Key (For now, just hard-coding to [0..31])
//    unsigned char long_term_key[32] = {0};
//    for(int i = 0; i<32;  i++)
//        long_term_key[i] = i;
//
//    // Key Exchange
//    unsigned char session_key[32] = {0};
//    exchange_session_key(ingress, egress, long_term_key, session_key);
    
    // Message Exchange
    if(SALTUNNEL_PUMP_THREADS==1)
        exchange_messages_serial(ingress, egress);
    else if(SALTUNNEL_PUMP_THREADS==2)
        exchange_messages_parallel(ingress, egress);
    else
        oops_fatal("assertion failed");
}
