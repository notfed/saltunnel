//
//  saltunnel.c
//  saltunnel
//

#include "src/saltunnel.h"
#include "src/saltunnel_tcp_client_forwarder.h"
#include "src/saltunnel_tcp_server_forwarder.h"
#include "src/log.h"
#include "src/oops.h"
#include "src/rwn.h"
#include "src/math.h"
#include "src/config.h"
#include "src/cache.h"
#include "src/csprng.h"
#include "src/keyfile.h"

#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

static cache table = {0};

static const char* usage_str = "\
usage: saltunnel client [-t <timeout>] [-m <maxconns>] -k <keyfile> <fromip>:<fromport> <toip>:<toport>\n\
       saltunnel server [-t <timeout>] [-m <maxconns>] -k <keyfile> <fromip>:<fromport> <toip>:<toport>\n\
       saltunnel key generate <keyfile>\n\
       saltunnel key import <keyfile>\n\
       saltunnel key export <keyfile>\n";

static int oops_usage() {
    fprintf(stderr, "%s", usage_str);
    return 2;
}

#define str_equals(a, b) (strcmp(a,b)==0)

static int main_client_or_server(int argc, const char* argv[], int is_server) {
    if(argc<5)
        return oops_usage();
    
    // Parse arguments via getopt
    int opt;
    int verbosity = 0;
    const char* keyfile = 0;
    int keyfile_provided = 0;
    int maxconns = 100;

    while ((opt = getopt(argc, (char*const*)argv, "vt:m:k:")) != -1) {
        switch (opt) {
        case 'v':
            verbosity++;
            break;
        case 'k':
            keyfile = optarg;
            keyfile_provided = 1;
            break;
        case 'm':
            maxconns = atoi(optarg);
            break;
        case 't': {
            float connection_timeout_s ;
            if(sscanf(optarg, "%f", &connection_timeout_s)>=0 && connection_timeout_s>=0) {
                config_connection_timeout_ms = (int)(connection_timeout_s*1000);
            }
            break;
        }
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

    // Read the key file
    unsigned char key[32];
    if(keyfile_read(keyfile, key)<0)
        oops_error_sys("failed to read key");

    // Run the forwarder
    if(!is_server) {
        saltunnel_tcp_client_forwarder(key, from_host, from_port, to_host, to_port);
    } else  {
        saltunnel_tcp_server_forwarder(&table, key, from_host, from_port, to_host, to_port);
    }
    return 1;
}

static int main_key(int argc, const char * argv[]) {
    if(argc<3)
        return oops_usage();
    
    const char* arg_command = argv[1];
    const char* arg_keyfile = argv[2];
    
    if(str_equals("generate",arg_command)) {
        return keyfile_generate(arg_keyfile)<0 ? 1 : 0;
    } else if (str_equals("import",arg_command)) {
        return keyfile_import(arg_keyfile)<0 ? 1 : 0;
    } else if (str_equals("export",arg_command)) {
        return keyfile_export(arg_keyfile)<0 ? 1 : 0;
    } else {
        return oops_usage();
    }
}

int main(int argc, const char * argv[])
{
    
    // Verify and shift arguments
    if(argc<2)
        return oops_usage();
    argc = argc-1;
    argv = &argv[1];
    
    // Initialize a few things
    saltunnel_init();
    
    // Parse arguments
    const char* arg_command = argv[0];
    
    if(str_equals("version",arg_command)
    || str_equals("-version",arg_command)
    || str_equals("--version",arg_command))
    {
        printf("0.0.1\n");
        return 0;
    } else if(str_equals("key",arg_command)) {
        return main_key(argc, argv);
    } else if(str_equals("client",arg_command)) {
        return main_client_or_server(argc, argv, 0);
    } else if(str_equals("server",arg_command)) {
        return main_client_or_server(argc, argv, 1);
    } else {
        return oops_usage();
    }
}
