//
//  uint64.h
//  saltunnel
//

#ifndef uint64_h
#define uint64_h

#include <stdint.h>

void uint64_pack(char *,uint64_t);
void uint64_pack_big(char *,uint64_t);
void uint64_unpack(char *,uint64_t *);
void uint64_unpack_big(char *,uint64_t *);

#endif  /* uint64_h */
