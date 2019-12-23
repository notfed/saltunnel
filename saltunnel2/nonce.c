//
//  nonce.c
//  saltunnel2
//

#include "nonce.h"

void nonce8_clear(nonce8 nonce) {
    for(int i = 0; i < 8; i++) {
        nonce[i] = 0;
    }
}

void nonce8_increment(nonce8 nonce) {
    unsigned char carry = 1;
    for(int i = 0; i < 8; i++) {
        nonce[i] += carry;
        carry &= (nonce[i] == 0);
    }
}

void nonce24_clear(nonce24 nonce) {
    for(int i = 0; i < 24; i++) {
        nonce[i] = 0;
    }
}

void nonce24_increment(nonce24 nonce) {
    unsigned char carry = 1;
    for(int i = 0; i < 24; i++) {
        nonce[i] += carry;
        carry &= (nonce[i] == 0);
    }
}
