//
//  uint32.h
//  saltunnel
//

#ifndef uint32_h
#define uint32_h

#include <stdint.h>

void uint32_pack(char *,uint32_t);
void uint32_pack_big(char *,uint32_t);
void uint32_unpack(char *,uint32_t *);
void uint32_unpack_big(char *,uint32_t *);

#endif  /* uint32_h */
