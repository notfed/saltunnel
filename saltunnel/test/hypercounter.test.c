//
//  hypercounter.test.c
//  saltunnel
//

#include "hypercounter.test.h"

#include "hypercounter.h"
#include "oops.h"

void hypercounter_tests() {
    
    unsigned char zeros[16] = {0};
    
    // Generate hypercounter 1
    unsigned char machine_id_1[16] = {0};
    unsigned char monotonic_time_1[8] = {0};
    if(hypercounter(machine_id_1, monotonic_time_1)<0) oops_error("failed to generate hypercounter");
    
    // Generate hypercounter 2
    unsigned char machine_id_2[16] = {0};
    unsigned char monotonic_time_2[8] = {0};
    if(hypercounter(machine_id_2, monotonic_time_2)<0) oops_error("failed to generate hypercounter");
    
    // Ensure both machine ids non-zero and equal
    if(memcmp(machine_id_1, zeros, 16)==0) oops_error("hypercounter generated a zero machine_id");
    if(memcmp(machine_id_1, machine_id_2, 16)!=0) oops_error("hypercounter generated two different machine_ids");

    // Ensure both monotonic_times are different
    if(memcmp(monotonic_time_1, zeros, 8)==0) oops_error("hypercounter generated a zero montonic_time");
    if(memcmp(monotonic_time_1, monotonic_time_2, 8)==0) oops_error("hypercounter generated two equal monotonic_times");
    
}

