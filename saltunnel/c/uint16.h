//
//  uint16.h
//  saltunnel2
//

#ifndef uint16_h
#define uint16_h

#include <stdint.h>

extern void uint16_pack(char *,uint16_t);
extern void uint16_pack_big(char *,uint16_t);
extern void uint16_unpack(char *,uint16_t *);
extern void uint16_unpack_big(char *,uint16_t *);

#endif /* uint16_h */
