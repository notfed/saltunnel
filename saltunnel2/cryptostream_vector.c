//
//  cryptostream_vector.c
//  saltunnel2
//

#include "cryptostream.h"
#include "math.h"
#include <unistd.h>
#include <stdio.h>

void vector_reset_plaintext(struct iovec* iovec_array, unsigned char* span, int vec_i) {
    iovec_array[vec_i].iov_base = span + CRYPTOSTREAM_BUFFER_MAXBYTES*(vec_i%CRYPTOSTREAM_BUFFER_COUNT) + 32+2;
    iovec_array[vec_i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_DATA;
}
void vector_reset_ciphertext(struct iovec* iovec_array, unsigned char* span, int vec_i) {
    iovec_array[vec_i].iov_base = span + CRYPTOSTREAM_BUFFER_MAXBYTES*(vec_i%CRYPTOSTREAM_BUFFER_COUNT) + 16;
    iovec_array[vec_i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT;
}

void vector_init(cryptostream *cs) {
    for(int j = 0; j<256; j++) {
        vector_reset_plaintext(cs->plaintext_vector, cs->plaintext, j);
    }
    for(int j = 0; j<256; j++) {
        vector_reset_ciphertext(cs->ciphertext_vector, cs->ciphertext, j);
    }
}

// Skip n bytes, and return how many iovecs have been filled
ssize_t vector_skip(struct iovec *v, size_t vlen, unsigned int n)
{
    int filled=0;
    for(int i = 0; i < vlen; i++) {
        int iov_len_was_zero = (v[i].iov_len==0);
        size_t ncur = MIN(v[i].iov_len, n);
        v[i].iov_len  -= ncur;
        v[i].iov_base += ncur;
        n -= ncur;
        int iov_len_is_zero = (v[i].iov_len==0);
        if(!iov_len_was_zero && iov_len_is_zero) filled++;
        if(n==0) break;
    }
    return filled;
}
