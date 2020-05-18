//
//  nonce.c
//  saltunnel
//

#include "nonce.h"
#include "uint64.h"
#include <string.h>
#include <stdint.h>

void nonce8_clear(nonce8 nonce) {
    memset(nonce, 0, 8);
}

void nonce8_copy(nonce8 nonce_from, nonce8 nonce_to) {
    memcpy(nonce_to, nonce_from, 8);
}

void nonce8_increment(nonce8 nonce_from, nonce8 nonce_to) {
    nonce8_increment_by(nonce_from, nonce_to, 1);
}

void nonce8_increment_by(nonce8 nonce_from, nonce8 nonce_to, int by) {
    uint64_t tmp;
    uint64_unpack((char*)nonce_from, &tmp);
    tmp += by;
    uint64_pack((char*)nonce_to, tmp);
}

void nonce24_clear(nonce24 nonce) {
    memset(nonce, 0, 24);
}

void nonce24_copy(nonce24 nonce_from, nonce24 nonce_to) {
    memcpy(nonce_to, nonce_from, 24);
}
