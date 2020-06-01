//
//  csprng.h
//  saltunnel
//
//  Thread-safe, fast, cryptographically-secure pseudo-random number generator.
//

#ifndef csprng_h
#define csprng_h

#include <stdint.h>

void csprng_seed(void);
void csprng(uint8_t* output, uint64_t len);

#endif /* csprng_h */
