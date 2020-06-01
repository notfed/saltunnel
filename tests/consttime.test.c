//
//  consttime.test.c
//  saltunnel-test
//

#include "consttime.test.h"
#include "consttime.h"
#include "oops.h"

#include <string.h>
#include <assert.h>

void consttime_tests() {
    unsigned char buf8_1[8] = {1,2,3,4,5,6,7,8};
    unsigned char buf8_2[8] = {1,2,3,4,5,6,7,8};
    unsigned char buf8_3[8] = {1,2,2,4,5,6,7,8};
    assert( consttime_are_equal(buf8_1, buf8_2, 8));
    assert(!consttime_are_equal(buf8_2, buf8_3, 8));
    
    unsigned char buf16_1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char buf16_2[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    unsigned char buf16_3[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,14,16};
    assert( consttime_are_equal(buf16_1, buf16_2, 16));
    assert(!consttime_are_equal(buf16_2, buf16_3, 16));
    
    unsigned char buf32_1[32]; for(int i=0;i<32;i++) buf32_1[i] = i+1;
    unsigned char buf32_2[32]; for(int i=0;i<32;i++) buf32_2[i] = i+1;
    unsigned char buf32_3[32]; for(int i=0;i<32;i++) buf32_3[i] = i+1; buf32_3[10] = 2;
    assert( consttime_are_equal(buf32_1, buf32_2, 32));
    assert(!consttime_are_equal(buf32_2, buf32_3, 32));
}
