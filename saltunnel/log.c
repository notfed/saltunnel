//
//  log.c
//  saltunnel2
//

#include "log.h"
#include <stdio.h>
#include <string.h>

static void strncpy_boring(char *output, char* src, int maxlen) {
    for(int i = 0; i < maxlen; i++) {
        output[i] = src[i];
        if(src[i] == 0) return;
    }
}

char* log_filename_idempotent_fill(char* log_name, char* log_filename_from_macro, int len, char* log_name_filled) {
    if(!*log_name_filled) {
        char result[256];
        result[255] = 0;
        
        // Point to the last slash of path (if any), plus 1
        char* last_slash = strrchr(log_filename_from_macro, '/');
        if(last_slash == 0) last_slash = log_filename_from_macro;
        else if(last_slash[1]!=0) last_slash++;
        
        // Point to the last backslash of path (if any), plus 1
        char* last_backslash = strrchr(log_filename_from_macro, '\\');
        if(last_backslash == 0) last_backslash = log_filename_from_macro;
        else if(last_backslash[1]!=0) last_backslash++;
        
        // Find the latter of last_slash or last_backslash
        if(last_backslash>last_slash) last_slash = last_backslash;
        
        // Copy the str now pointed to by last_slash
        strncpy(result,last_slash,255);
        
        // After that, point to the first period
        char* first_dot = memchr(result, '.', 255);
        
        // If there was a period, null it out
        if(first_dot!=0) {
            first_dot[0]=0;
        }
        
        // Copy the final result to log_name
        strncpy_boring(log_name, result, 255);
        
        *log_name_filled = 1;
    }
    return log_name;
}

static __thread char log_thread_name[64] = " [ main ]:";

void log_set_thread_name(const char* str)
{
    snprintf(log_thread_name,63," [%s]:",str);
}

const char* log_get_thread_name_formatted()
{
    return log_thread_name;
}
