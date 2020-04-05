#include <stdio.h>
#include <stdlib.h>
#include "oops.h"
#include "uninterruptable.h"
#include "saltunnel_tcp_client_forwarder.h"

static int oops_usage() {
    fprintf(stderr, "saltunnel-client: usage: saltunnel-client -k [keyfile] [fromip]:[fromport] [toip]:[toport]\n");
    return 1;
}

int main(int argc, char * argv[])
{
    unsigned char long_term_shared_key[32];
    const char* keyfile;
    const char* fromip;
    const char* fromport;
    const char* toip;
    const char* toport;
    
    // Must have 6 args
    if(argc!=7)
        return oops_usage();
    
    // First arg must be "-k"
    if(strcmp(argv[1],"-k")!=0)
        return oops_usage();
    
    // Second arg is keyfile
    keyfile = argv[2];
    
    // Third arg is "fromip:fromport"; split at the colon
    char* from_colon_ptr = strchr(argv[1]);
    if(from_colon_ptr==0)
        return oops_usage();
    *from_colon_ptr = 0;
    fromip = argv[1];
    fromport = from_colon_ptr+1;
    
    // Fourth arg is "toip:toport"; split at the colon
    char* to_colon_ptr = strchr(argv[2]);
    if(to_colon_ptr==0)
        return oops_usage();
    *to_colon_ptr = 0;
    toip = argv[2];
    toport = to_colon_ptr+1;
    
    // Validate ports
    if(atoi(fromport)==0 || atoi(toport)==0)
        return oops_usage();
    
    // Memory-lock the key
    if(mlock(long_term_shared_key, sizeof(long_term_shared_key))<0)
        oops_fatal("failed to mlock");
    
    // Read the key
    int key_fd = open(keyfile, O_RDONLY);
    if(key_fd<0)
        oops_fatal("failed to open key");
    if(readn(key_fd, long_term_shared_key,  sizeof(long_term_shared_key))<0)
        oops_fatal("failed to read key");
    close(key_fd);
    
    // Run the client forwarder
    int result = saltunnel_tcp_client_forwarder(long_term_shared_key,
                    from_ip, from_port,
                    to_ip, to_port);
    
    // Memory-unlock the key
    if(munlock(long_term_shared_key, sizeof(long_term_shared_key))<0)
        oops_fatal("failed to munlock");
    
    // Return exit code from client forwarder
    return reult;
}
