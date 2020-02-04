//
//  saltunnel_common.c
//  saltunnel2
//

#include "saltunnel.h"
#include "config.h"
#include "cryptostream.h"
#include "log.h"
#include "oops.h"
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

static void exchange_key(cryptostream *ingress, cryptostream *egress, unsigned char* key) {
    // TODO: Perform steps to agree on key
    //       For now, just hard-coding to [0..31].
    for(int i = 0; i<32;  i++)
        key[i] = i;
}

void saltunnel(cryptostream* ingress, cryptostream* egress)
{
    unsigned char key[32] = {0};
    
    // Key Exchange
    exchange_key(ingress, egress, key);
    
    // Message Exchange
    if(SALTUNNEL_PUMP_THREADS==1)
        exchange_messages_serial(ingress, egress, key);
    else if(SALTUNNEL_PUMP_THREADS==2)
        exchange_messages_parallel(ingress, egress, key);
    else
        oops_fatal("assertion failed");
}
