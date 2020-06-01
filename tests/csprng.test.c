//
//  csprng.test.c
//  saltunnel-test
//

#include "csprng.test.h"
#include "csprng.h"
#include "oops.h"

#include <assert.h>
#include <string.h>

void csprng_tests() {
    unsigned char buf0[70] = {0};
    unsigned char buf1[70] = {0};
    unsigned char buf2[70] = {0};
    csprng(buf1, 70);
    csprng(buf2, 70);
    assert(memcmp(buf0,buf1,70)!=0);
    assert(memcmp(buf0,buf2,70)!=0);
    assert(memcmp(buf1,buf2,70)!=0);
}
