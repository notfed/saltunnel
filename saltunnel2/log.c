//
//  log.c
//  saltunnel2
//
//  Created by Jay Sullivan on 12/21/19.
//  Copyright © 2019 Jay Sullivan. All rights reserved.
//

#include "log.h"
#include <stdio.h>
#include <string.h>

char* log_filename_idempotent_fill(char* log_name, char* log_filename_from_macro, int len, char* log_name_filled) {
    if(!*log_name_filled) {
        
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
        
        // Use the str now pointed to by last_slash
        strncpy(log_name,last_slash,256);
        
        // After that, point to the first period
        char* first_dot = strchr(log_name, '.');
        
        // If there was a period, null it out
        if(first_dot!=0) {
            first_dot[0]=0;
        }
        
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
