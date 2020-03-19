//
//  nonce.c
//  saltunnel2
//

#include "nonce.h"
#include <string.h>
#include <stdint.h>

void nonce8_clear(nonce8 nonce) {
    memset(nonce, 0, 8);
}

// Optimize
void nonce8_copy(nonce8 nonce_from, nonce8 nonce_to) {
    memcpy(nonce_to, nonce_from, 8);
}

void nonce8_increment(nonce8 nonce_from, nonce8 nonce_to) {
    unsigned char carry = 1;
    for(int i = 0; i < 8; i++) {
        nonce_to[i] = nonce_from[i] + carry;
        carry &= (nonce_from[i] == 0);
    }
}

// TODO: Optimize
void nonce8_increment_by(nonce8 nonce_from, nonce8 nonce_to, int by) {
    nonce8 tmp;
    nonce8_copy(nonce_from, tmp);
    for(int i = 0; i < by; i++)
        nonce8_increment(tmp, tmp);
    nonce8_copy(tmp, nonce_to);
}

void nonce24_clear(nonce24 nonce) {
    memset(nonce, 0, 24);
}

// Optimize
void nonce24_copy(nonce24 nonce_from, nonce24 nonce_to) {
    memcpy(nonce_to, nonce_from, 24);
}
