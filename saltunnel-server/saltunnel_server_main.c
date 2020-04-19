#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sodium.h>
#include "oops.h"
#include "uninterruptable.h"
#include "saltunnel_tcp_server_forwarder.h"
#include "hashtable.h"

static void oops_usage() {
    fprintf(stderr, "saltunnel-server: usage: saltunnel-server -k <keyfile> <fromip>:<fromport> <toip>:<toport>\n");
    exit(2);
}

static hashtable table = {0};

int main(int argc, char * argv[])
{
    // Seed random bytes
    try(sodium_init())
    || oops_fatal("sodium init");
    
    // Must have 1+6 args
    if(argc!=7)
        oops_usage();
    
    // Parse keyfile
    if(strcmp(argv[1],"-k")!=0)
        oops_usage();
    const char* keyfile = argv[2];
    
    // Parse [fromip]:[fromport]
    char* from_colon = strchr(argv[3], ':');
    if(from_colon==0) oops_usage();
    *from_colon = 0;
    const char* from_host = argv[3];
    const char* from_port = from_colon+1;
    
    // Parse [toip]:[toport]
    char* to_colon = strchr(argv[4], ':');
    if(to_colon==0) oops_usage();
    *to_colon = 0;
    const char* to_host = argv[4];
    const char* to_port = to_colon+1;
    
    // Read the key
    unsigned char key[32];
    if(mlock(key, sizeof(key))<0)
        oops_fatal("failed to mlock");
    int key_fd = open(keyfile, O_RDONLY);
    if(key_fd<0)
        oops_fatal("failed to open key");
    if(readn(key_fd, (char*)key,  sizeof(key))<0)
        oops_fatal("failed to read key");
    close(key_fd);

    // Run the client forwarder
    saltunnel_tcp_server_forwarder(&table, key, from_host, from_port, to_host, to_port);
    
    // The server forwarder never return
    oops_fatal("fatal error");
    return 1;
}
