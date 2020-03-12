#include "uint64.h"

#include <stdint.h>

void uint64_pack(char s[8], uint64_t u)
{
    s[0] = u & 255; u >>= 8;
    s[1] = u & 255; u >>= 8;
    s[2] = u & 255; u >>= 8;
    s[3] = u & 255; u >>= 8;
    s[4] = u & 255; u >>= 8;
    s[5] = u & 255; u >>= 8;
    s[6] = u & 255;
    s[7] = u >> 8;
}

void uint64_pack_big(char s[8], uint64_t u)
{
    s[7] = u & 255; u >>= 8;
    s[6] = u & 255; u >>= 8;
    s[5] = u & 255; u >>= 8;
    s[4] = u & 255; u >>= 8;
    s[3] = u & 255; u >>= 8;
    s[2] = u & 255; u >>= 8;
    s[1] = u & 255;
    s[0] = u >> 8;
}

void uint64_unpack(char s[8], uint64_t *u)
{
    uint64 result;

    result =  (unsigned char) s[7]; result <<= 8;
    result += (unsigned char) s[6]; result <<= 8;
    result += (unsigned char) s[5]; result <<= 8;
    result += (unsigned char) s[4]; result <<= 8;
    result += (unsigned char) s[3]; result <<= 8;
    result += (unsigned char) s[2]; result <<= 8;
    result += (unsigned char) s[1]; result <<= 8;
    result += (unsigned char) s[0];

    *u = result;
}

void uint64_unpack_big(char s[8], uint64_t *u)
{
  uint64 result;

  result =  (unsigned char) s[0]; result <<= 8;
  result += (unsigned char) s[1]; result <<= 8;
  result += (unsigned char) s[2]; result <<= 8;
  result += (unsigned char) s[3]; result <<= 8;
  result += (unsigned char) s[4]; result <<= 8;
  result += (unsigned char) s[5]; result <<= 8;
  result += (unsigned char) s[6]; result <<= 8;
  result += (unsigned char) s[7];

  *u = result;
}
