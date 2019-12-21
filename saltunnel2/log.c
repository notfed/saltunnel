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

char* log_filename_idempotent_fill(char* log_name, char* log_filename_from_macro, int len, int* log_name_filled) {
    if(!*log_name_filled) {
        strcpy(log_name,log_filename_from_macro);
        char* dot = strchr(log_name, '.');
        if(dot!=0) {
            *dot=0;
        }
        *log_name_filled = 1;
    }
    return log_name;
}
