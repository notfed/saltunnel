//
//  uint16.h
//  saltunnel2
//

#ifndef uint16_h
#define uint16_h

typedef unsigned short uint16;

extern void uint16_pack(char *,uint16);
extern void uint16_pack_big(char *,uint16);
extern void uint16_unpack(char *,uint16 *);
extern void uint16_unpack_big(char *,uint16 *);

#endif /* uint16_h */
