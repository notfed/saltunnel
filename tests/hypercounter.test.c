//
//  hypercounter.test.c
//  saltunnel
//

#include "hypercounter.test.h"
#include "hypercounter.h"
#include "oops.h"

#include <assert.h>

void hypercounter_tests() {
    
    unsigned char zeros[16] = {0};
    
    // Generate hypercounter 1
    unsigned char machine_id_1[16] = {0};
    unsigned char monotonic_time_1[8] = {0};
    assert(hypercounter(machine_id_1, monotonic_time_1)==0);
    
    // Generate hypercounter 2
    unsigned char machine_id_2[16] = {0};
    unsigned char monotonic_time_2[8] = {0};
    assert(hypercounter(machine_id_2, monotonic_time_2)==0);
    
    // Ensure both machine ids non-zero and equal
    assert(memcmp(machine_id_1, zeros, 16)!=0);
    assert(memcmp(machine_id_1, machine_id_2, 16)==0);

    // Ensure both monotonic_times are different
    assert(memcmp(monotonic_time_1, zeros, 8)!=0);
    assert(memcmp(monotonic_time_1, monotonic_time_2, 8)!=0);
    
}

