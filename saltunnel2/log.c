//
//  log.c
//  saltunnel2
//
//  Created by Jay Sullivan on 12/21/19.
//  Copyright © 2019 Jay Sullivan. All rights reserved.
//

#include <stdio.h>

void log_filename_idempotent_fill(char* log_filename, char* log_filename_from_macro, int len, int* log_filename_filled) {
    if(!*log_filename_filled) {
        strcpy(log_filename,log_filename_from_macro);
        char* dot = strchr(log_filename, '.');
        if(dot!=0) {
            *dot=0;
        }
        *log_filename_filled = 1;
    }
}
