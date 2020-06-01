//
//  saltunnel_crypto.c
//  saltunnel
//

#include "saltunnel_crypto.h"
#include "csprng.h"

#include <string.h>

int crypto_box_keypair_csprng(
                    unsigned char *pk,
                    unsigned char *sk) 
{
    csprng(sk,32);
    return crypto_scalarmult_base(pk,sk);
}

int crypto_hash16(unsigned char h[16],
                  const unsigned char *m,
                  unsigned long long mlen)
{
    unsigned char h_tmp[32];
    crypto_hash32(h_tmp, m, mlen);
    memcpy(h,h_tmp,16);
    return 0;
}

int
crypto_secretbox8(unsigned char *c, const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *n,
                                  const unsigned char *k)
{
    int i;
    if (mlen < 32) return -1;
    crypto_stream8_xor(c, m, mlen, n, k);
    crypto_onetimeauth(c + 16, c + 32, mlen - 32, c);
    for (i = 0; i < 16; ++i)  c[i] = 0;
    return 0;
}

int
crypto_secretbox8_open(unsigned char *m, const unsigned char *c,
                                       unsigned long long clen,
                                       const unsigned char *n,
                                       const unsigned char *k)
{
    unsigned char subkey[32];
    int i;
    if (clen < 32) return -1;
    crypto_stream8(subkey, 32, n, k);
    if (crypto_onetimeauth_verify(c + 16, c + 32, clen - 32, subkey) != 0) return -1;
    crypto_stream8_xor(m, c, clen, n, k);
    for (i = 0; i < 32; ++i) m[i] = 0;
    return 0;
}

int crypto_secretbox24(
  unsigned char *c,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *n,
  const unsigned char *k
)
{
  int i;
  if (mlen < 32) return -1;
  crypto_stream24_xor(c,m,mlen,n,k);
  crypto_onetimeauth(c + 16,c + 32,mlen - 32,c);
  for (i = 0;i < 16;++i) c[i] = 0;
  return 0;
}

int crypto_secretbox24_open(
  unsigned char *m,
  const unsigned char *c,unsigned long long clen,
  const unsigned char *n,
  const unsigned char *k
)
{
  unsigned char subkey[32];
  int i;
  if (clen < 32) return -1;
  crypto_stream24(subkey,32,n,k);
  if (crypto_onetimeauth_verify(c + 16,c + 32,clen - 32,subkey) != 0) return -1;
  crypto_stream24_xor(m,c,clen,n,k);
  for (i = 0;i < 32;++i) m[i] = 0;
  return 0;
}
