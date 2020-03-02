//
//  saltunnel_server.c
//  saltunnel
//

#include <stdio.h>
#include "sodium.h"
#include "oops.h"
#include "saltunnel_tcp_server_forwarder.h"

void error_usage() {
    oops_fatal("saltunnel-server: usage: saltunnel-server <key-file> <from-host>:<from-port> <to-host>:<to-port>");
}

int main(int argc, char * argv[])
{
    // Seed random bytes
    try(sodium_init())
    || oops_fatal("sodium init");
    
    // Validate argc
     if(argc!=3) error_usage();
    
    // Read key
    unsigned char key[32] = {0}; // TODO
    
    // Determine arguments
    char* from_colon = strchr(argv[1], ':');
    if(from_colon==0) error_usage();
    *from_colon = 0;
    const char* from_host = argv[1];
    const char* from_port = from_colon+1;
    
    char* to_colon = strchr(argv[2], ':');
    if(to_colon==0) error_usage();
    *to_colon = 0;
    const char* to_host = argv[1];
    const char* to_port = to_colon+1;
    
    // Call saltunnel
    if(saltunnel_tcp_server_forwarder(key, from_host, from_port, to_host, to_port))
        oops_fatal("fatal error");
        
    return 0;
}
