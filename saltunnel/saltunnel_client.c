//
//  saltunnel_client.c
//  saltunnel
//

#include <stdio.h>
#include "sodium.h"
#include "oops.h"
#include "saltunnel_tcp_client_forwarder.h"

void error_usage() {
    fprintf(stderr,"saltunnel-server: %s: usage: saltunnel-server <key-file> <from-host>:<from-port> <to-host>:<to-port>\n");
    exit(1);
}

int main(int argc, char * argv[])
{
    // Seed random bytes
    try(sodium_init())
    || oops_fatal("sodium init");
    
    // Validate argc
     if(argc!=4) error_usage();
    
    // Read key
    const char* key_path = argv[1];
    unsigned char key[32] = {0}; // TODO
    
    // Determine arguments
    char* from_colon = strchr(argv[2], ':');
    if(from_colon==0) error_usage();
    *from_colon = 0;
    const char* from_host = argv[2];
    const char* from_port = from_colon+1;
    
    char* to_colon = strchr(argv[3], ':');
    if(to_colon==0) error_usage();
    *to_colon = 0;
    const char* to_host = argv[3];
    const char* to_port = to_colon+1;
    
    // Call saltunnel
    if(saltunnel_tcp_client_forwarder(key, from_host, from_port, to_host, to_port))
        oops_fatal("fatal error");
    
    return 0;
}
