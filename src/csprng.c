//
//  csprng.c
//  saltunnel
//

#include "saltunnel_crypto.h"
#include "oops.h"
#include "rwn.h"
#include "nonce.h"

#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdatomic.h>

static int did_seed = 0;
static unsigned char seed[32] = {0};
static atomic_uint_least64_t main_counter = 0;
static __thread uint64_t nonce[3] = {0};

void csprng_seed()
{
    mlock(seed,32);
    int fd;
    while((fd = open("/dev/urandom",O_RDONLY))==-1) sleep(1);
    while((readn(fd,(char*)seed,32))==-1) sleep(1);
    close(fd);
    main_counter = 1;
    did_seed = 1;
}

void csprng(unsigned char *x,unsigned long long xlen) {
    assert(did_seed);
    if(nonce[0]==0)
        nonce[0] = atomic_fetch_add(&main_counter, 1);
    nonce[1]++;
    crypto_stream24(x,xlen,(unsigned char*)nonce,seed);
}
