//
//  cryptostream_vector.c
//  saltunnel
//
//  The primary function here is vector_skip.
//
//  vector_skip(struct iovec *v, int start_i, size_t count_i, unsigned int n)
//
//      This is used to 'skip' some specified number of bytes from within an array of 
//      iovec vectors (i.e., used with readv and writev).  In particular, it will jump 
//      to the vector with index 'start_i', and feed the vector 'n' bytes, and will 
//      only keep feeding until 'count_i' vectors have been filled.  
//      Returns how many iovecs have been completely filled.
//  
//

#include "cryptostream.h"
#include "oops.h"
#include "math.h"
#include <unistd.h>
#include <stdio.h>

static int first(int buffer_i) {
    return buffer_i % CRYPTOSTREAM_BUFFER_COUNT;
}
static int second(int buffer_i) {
    return (buffer_i % CRYPTOSTREAM_BUFFER_COUNT)+CRYPTOSTREAM_BUFFER_COUNT;
}

static void vector_reset_plaintext_one(struct iovec* iovec_array, unsigned char* span, int buffer_i) {
    iovec_array[buffer_i].iov_base = span + CRYPTOSTREAM_BUFFER_MAXBYTES*first(buffer_i) + 32+2;
    iovec_array[buffer_i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_DATA;

}

void vector_reset_plaintext(struct iovec* iovec_array, unsigned char* span, int buffer_i) {
    vector_reset_plaintext_one(iovec_array, span, first(buffer_i));
    vector_reset_plaintext_one(iovec_array, span, second(buffer_i));
}

static void vector_reset_ciphertext_one(struct iovec* iovec_array, unsigned char* span, int buffer_i) {
    iovec_array[buffer_i].iov_base = span + CRYPTOSTREAM_BUFFER_MAXBYTES*first(buffer_i) + 16;
    iovec_array[buffer_i].iov_len  = CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT;
}

void vector_reset_ciphertext(struct iovec* iovec_array, unsigned char* span, int buffer_i) {
    vector_reset_ciphertext_one(iovec_array, span, first(buffer_i));
    vector_reset_ciphertext_one(iovec_array, span, second(buffer_i));
}

void vector_buffer_set_len(struct iovec* iovec_array, int buffer_i, int len) {
    iovec_array[first(buffer_i)].iov_len = len;
    iovec_array[second(buffer_i)].iov_len = len;
}

void vector_buffer_set_base(struct iovec* iovec_array, int buffer_i, void* base) {
    iovec_array[first(buffer_i)].iov_base = base;
    iovec_array[second(buffer_i)].iov_base = base;
}


void vector_init(cryptostream *cs) {
    for(int j = 0; j<CRYPTOSTREAM_BUFFER_COUNT*2; j++) {
        vector_reset_plaintext(cs->plaintext_vector, cs->plaintext, j);
    }
    for(int j = 0; j<CRYPTOSTREAM_BUFFER_COUNT*2; j++) {
        vector_reset_ciphertext(cs->ciphertext_vector, cs->ciphertext, j);
    }
}

ssize_t vector_skip(struct iovec *v, int start_i, size_t count_i, unsigned int n)
{
    int filled=0;
    for(int buffer_i = start_i; buffer_i < start_i+count_i; buffer_i++) {
        int iov_len_was_zero = (v[buffer_i].iov_len==0);
        size_t ncur = MIN(v[buffer_i].iov_len, n);
        
        vector_buffer_set_len(v,  buffer_i, (int)(v[buffer_i].iov_len  - ncur));
        vector_buffer_set_base(v, buffer_i, v[buffer_i].iov_base + ncur);
        
        n -= ncur;
        int iov_len_is_zero = (v[buffer_i].iov_len==0);
        if(!iov_len_was_zero && iov_len_is_zero) filled++;
        if(n==0) break;
    }
    return filled;
}
