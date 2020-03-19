//
//  uint16.c
//  saltunnel2
//

#include "uint16.h"
#include <stdint.h>

void uint16_pack(char s[2],uint16_t u)
{
  s[0] = u & 255;
  s[1] = u >> 8;
}

void uint16_pack_big(char s[2],uint16_t u)
{
  s[1] = u & 255;
  s[0] = u >> 8;
}

void uint16_unpack(char s[2],uint16_t *u)
{
  uint16_t result;

  result = (unsigned char) s[1];
  result <<= 8;
  result += (unsigned char) s[0];

  *u = result;
}

void uint16_unpack_big(char s[2],uint16_t *u)
{
  uint16_t result;

  result = (unsigned char) s[0];
  result <<= 8;
  result += (unsigned char) s[1];

  *u = result;
}
