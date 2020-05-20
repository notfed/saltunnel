//
//  log.test.c
//  saltunnel
//

#include "log.test.h"
#include "log.h"
#include "oops.h"
#include "uint32.h"
#include <stdint.h>
#include <unistd.h>

void log_test() {
    {
        char log_name[256];
        char* log_filename_from_macro = "test.c";
        int len = sizeof("test.c");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_error("log test, assertion 1 failed");
    }
    {
        char log_name[256];
        char* log_filename_from_macro = "/a/b/c/test.c";
        int len = sizeof("/a/b/c/test.c");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_error("log test, assertion 2 failed");
    }
    {
        char log_name[256];
        char* log_filename_from_macro = "C:\\Program Files (x86)\\log\\ger\\test.c";
        int len = sizeof("C:\\Program Files (x86)\\log\\ger\\test.c");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_error("log test, assertion 2 failed");
    }
    {
        char log_name[256];
        char* log_filename_from_macro = "test";
        int len = sizeof("test");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_error("log test, assertion 2 failed");
    }
}
