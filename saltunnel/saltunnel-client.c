#include "src/saltunnel_tcp_client_forwarder.h"
#include "src/log.h"
#include "src/oops.h"
#include "src/rwn.h"
#include "src/math.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sodium.h>

static void oops_usage() {
    fprintf(stderr, "saltunnel-client: usage: saltunnel-client -k <keyfile> <fromip>:<fromport> <toip>:<toport>\n");
    exit(2);
}

int main(int argc, char * argv[])
{
    
    // Parse arguments via getopt
    int opt;
    int verbosity = 0;
    const char* keyfile = 0;
    int keyfile_provided = 0;

    while ((opt = getopt(argc, argv, "vk:")) != -1) {
        switch (opt) {
        case 'v':
            verbosity++;
            break;
        case 'k':
            keyfile = optarg;
            keyfile_provided = 1;
            break;
        default:
            oops_usage();
        }
    }

    // Make sure we got exactly 2 positional args and 1 key
    int pos_arg_i = optind;
    int pos_arg_c = argc - optind;
    if(pos_arg_c != 2 || !keyfile)
        oops_usage();

    // Set verbosity level
    log_level = 2 - MAX(0,MIN(2,verbosity));

    // Parse [fromip]:[fromport]
    const char * first_arg_ptr = argv[pos_arg_i+0];
    char* from_colon = strchr(first_arg_ptr, ':');
    if(from_colon==0) oops_usage();
    *from_colon = 0;
    const char* from_host = first_arg_ptr;
    const char* from_port = from_colon+1;
    
    // Parse [toip]:[toport]
    const char * second_arg_ptr = argv[pos_arg_i+1];
    char* to_colon = strchr(second_arg_ptr, ':');
    if(to_colon==0) oops_usage();
    *to_colon = 0;
    const char* to_host = second_arg_ptr;
    const char* to_port = to_colon+1;
    
    // Read the key
    unsigned char key[32];
    if(mlock(key, sizeof(key))<0)
        oops_warn_sys("failed to mlock key");
    int key_fd = open(keyfile, O_RDONLY);
    if(key_fd<0)
        oops_warn_sys("failed to open key");
    if(readn(key_fd, (char*)key, sizeof(key))<0)
        oops_error_sys("failed to read key");
    if(close(key_fd)<0)
        oops_error_sys("failed to close fd");

    // Seed random bytes
    try(sodium_init())
    || oops_error("failed to initialize libsodium");
    
    // Run the client forwarder
    if(saltunnel_tcp_client_forwarder(key, from_host, from_port, to_host, to_port)<0)
        return 1;

    // Exit successfully
    return 0;
}

