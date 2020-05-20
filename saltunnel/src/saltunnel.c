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
    if(SALTUNNEL_PUMP_THREADS==1)
        exchange_messages_serial(ingress, egress);
    else if(SALTUNNEL_PUMP_THREADS==2)
        exchange_messages_parallel(ingress, egress);
    else
        oops_error("assertion failed: SALTUNNEL_PUMP_THREADS must be either '1' or '2'");
}
