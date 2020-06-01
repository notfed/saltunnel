//
//  saltunnel_crypto.h
//  saltunnel
//
//  Project-wide single reference point for all cryptographic primitives.
//

#ifndef saltunnel_crypto_h
#define saltunnel_crypto_h

#include <sodium.h>

#define crypto_hash32             crypto_hash_sha256

#define crypto_stream8            crypto_stream_salsa20
#define crypto_stream8_xor        crypto_stream_salsa20_xor
#define crypto_stream24           crypto_stream_xsalsa20
#define crypto_stream24_xor       crypto_stream_xsalsa20_xor

#define crypto_onetimeauth        crypto_onetimeauth_poly1305
#define crypto_onetimeauth_verify crypto_onetimeauth_poly1305_verify
#define crypto_scalarmult_base    crypto_scalarmult_curve25519_base
#define crypto_scalarmult         crypto_scalarmult_curve25519

int crypto_box_keypair_csprng(
                    unsigned char *pk,
                    unsigned char *sk);

#define crypto_box_keypair        crypto_box_keypair_csprng

int crypto_crypto_box_curve25519xsalsa20poly1305_keypair_custom(
                    unsigned char *pk,
                    unsigned char *sk);

int crypto_hash16(unsigned char h[16],
                  const unsigned char *m,
                  unsigned long long mlen);

int crypto_secretbox8(unsigned char *c,
                      const unsigned char *m,
                      unsigned long long mlen,
                      const unsigned char *n,
                      const unsigned char *k);

int crypto_secretbox8_open(unsigned char *m,
                           const unsigned char *c,
                           unsigned long long clen,
                           const unsigned char *n,
                           const unsigned char *k);

int crypto_secretbox24(unsigned char *c,
                       const unsigned char *m,
                       unsigned long long mlen,
                       const unsigned char *n,
                       const unsigned char *k);

int crypto_secretbox24_open(unsigned char *m,
                            const unsigned char *c,
                            unsigned long long clen,
                            const unsigned char *n,
                            const unsigned char *k);


#endif /* saltunnel_crypto_h */
