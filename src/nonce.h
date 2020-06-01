//
//  nonce.h
//  saltunnel
//
//  Functions for manipulating 8-byte and 24-byte nonces.
//

#ifndef nonce_h
#define nonce_h

typedef unsigned char nonce8[8];
typedef unsigned char nonce24[24];

void nonce8_clear(nonce8);
void nonce8_copy(nonce8,nonce8);
void nonce8_increment(nonce8,nonce8);
void nonce8_increment_by(nonce8,nonce8,int);

void nonce24_clear(nonce24);
void nonce24_copy(nonce24,nonce24);

#endif /* nonce_h */
