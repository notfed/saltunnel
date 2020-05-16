//
//  cryptostream_vector.test.c
//  saltunnel
//

#include "cryptostream_vector.test.h"
#include "cryptostream.h"
#include "oops.h"

void cryptostream_vector_tests() {
    
    unsigned char data[30];
    
    struct iovec vector[] = {
        { .iov_base = &data[0], .iov_len = 10 },
        { .iov_base = &data[10], .iov_len = 10 },
        { .iov_base = &data[20], .iov_len = 10 }
    };
    
    if(vector[0].iov_base != &data[0]) oops_fatal("assertion 10.0.1 failed");
    if(vector[0].iov_len != 10)        oops_fatal("assertion 10.0.2 failed");
    
    if(vector_skip(vector, 0, 3, 0) != 0) oops_fatal("assertion 10.0.3 failed; vector_skip(vector, 3, 0)");
    
    if(vector_skip(vector, 0, 3, 1) != 0) oops_fatal("assertion 10.2.1 failed; vector_skip(vector, 3, 1)");
    if(vector[0].iov_base != &data[1]) oops_fatal("assertion 10.2.2 failed");
    if(vector[0].iov_len  != 9)        oops_fatal("assertion 10.2.3 failed");
    
    if(vector_skip(vector, 0, 3, 8) != 0) oops_fatal("assertion 10.3.1 failed; vector_skip(vector, 3, 8)");
    if(vector[0].iov_base != &data[9]) oops_fatal("assertion 10.3.2 failed");
    if(vector[0].iov_len  != 1)        oops_fatal("assertion 10.3.3 failed");
    
    if(vector_skip(vector, 0, 3, 1) != 1)  oops_fatal("assertion 10.4.1 failed; vector_skip(vector, 3, 1)");
    if(vector[0].iov_base != &data[10]) oops_fatal("assertion 10.4.2 failed");
    if(vector[0].iov_len  != 0)        oops_fatal("assertion 10.4.3 failed");
    
    int buffers_skipped = 0;
    for(int i = 0; i < 20; i+=1)
        buffers_skipped = (int)vector_skip(vector, 0, 3, 1);
    if(buffers_skipped != 1) oops_fatal("assertion 10.5.1 failed; vector_skip(vector, 3, 20)");
    
    if(vector[0].iov_base != &data[10]) oops_fatal("assertion 10.5.2 failed");
    if(vector[0].iov_len  != 0)         oops_fatal("assertion 10.5.3 failed");
    if(vector[1].iov_base != &data[20]) oops_fatal("assertion 10.5.4 failed");
    if(vector[1].iov_len  != 0)         oops_fatal("assertion 10.5.5 failed");
    if(vector[2].iov_base != &data[30]) oops_fatal("assertion 10.5.6 failed");
    if(vector[2].iov_len  != 0)         oops_fatal("assertion 10.5.7 failed");
}
