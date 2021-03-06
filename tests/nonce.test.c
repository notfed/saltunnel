//
//  nonce.test.c
//  saltunnel
//

#include "nonce.test.h"
#include "nonce.h"
#include "oops.h"
#include "string.h"

#include <assert.h>

void nonce_tests() {
    
    nonce8 nonce_0 = {0,0,0,0,0,0,0,0};
    nonce8 nonce_tmp = {0,0,0,0,0,0,0,0};
    
    // 0 -> 1
    nonce8_increment_by(nonce_0, nonce_tmp, 1);
    nonce8 nonce_1 = {1,0,0,0,0,0,0,0};
    assert(memcmp(nonce_tmp, nonce_1, sizeof(nonce_tmp))==0);
    
    // 1 -> 2
    nonce8_increment_by(nonce_tmp, nonce_tmp, 1);
    nonce8 nonce_2 = {2,0,0,0,0,0,0,0};
    assert(memcmp(nonce_tmp, nonce_2, sizeof(nonce_tmp))==0);
    
    // 2 -> 255
    nonce8_increment_by(nonce_tmp, nonce_tmp, 253);
    nonce8 nonce_255 = {255,0,0,0,0,0,0,0};
    assert(memcmp(nonce_tmp, nonce_255, sizeof(nonce_tmp))==0);
    
    // 255 -> 256
    nonce8_increment_by(nonce_tmp, nonce_tmp, 1);
    nonce8 nonce_256 = {0,1,0,0,0,0,0,0};
    assert(memcmp(nonce_tmp, nonce_256, sizeof(nonce_tmp))==0);
    
}
