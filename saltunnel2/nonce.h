//
//  nonce.h
//  saltunnel2
//

#ifndef nonceh_h
#define nonceh_h

typedef unsigned char nonce8[8];

void nonce8_new(nonce8);
void nonce8_increment(nonce8);

#endif /* nonce_h */
