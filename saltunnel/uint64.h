//
//  uint64.h
//  saltunnel2
//

#ifndef uint64_h
#define uint64_h

typedef unsigned long long uint64;

void uint64_pack(char *,uint64);
void uint64_pack_big(char *,uint64);
void uint64_unpack(char *,uint64 *);
void uint64_unpack_big(char *,uint64 *);

#endif
