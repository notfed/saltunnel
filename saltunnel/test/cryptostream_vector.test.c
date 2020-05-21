//
//  cryptostream_vector.test.c
//  saltunnel
//

#include "cryptostream_vector.test.h"
#include "cryptostream.h"
#include "oops.h"

#define die() oops_error("cryptostream_vector_tests: assertion failed");

static void assert_vector(struct iovec vector[3],
                          unsigned char* v1b, int v1l,
                          unsigned char* v2b, int v2l,
                          unsigned char* v3b, int v3l)
{
    vector_skip(vector, 0, 3, 0)==0 || die();
    vector[0].iov_base == v1b  || die();
    vector[0].iov_len  == v1l  || die();
    vector[1].iov_base == v2b  || die();
    vector[1].iov_len  == v2l  || die();
    vector[2].iov_base == v3b  || die();
    vector[2].iov_len  == v3l  || die();
}

void cryptostream_vector_test_incrementing() {
    
    // Initalize Vector = {10,10,10}
    unsigned char data[30] = {0};
    struct iovec vector[CRYPTOSTREAM_BUFFER_COUNT*2] = {0};
    vector[0].iov_base = &data[0];  vector[0].iov_len = 10;
    vector[1].iov_base = &data[10]; vector[1].iov_len = 10;
    vector[2].iov_base = &data[20]; vector[2].iov_len = 10;
    
    // Skip 0     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 0) == 0 || die();
    assert_vector(vector, &data[0], 10, &data[10], 10, &data[20], 10);
    
    // Skip 1     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 1) == 0 || die();
    assert_vector(vector, &data[1], 9, &data[10], 10, &data[20], 10);
    
    // Skip 2     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 2) == 0 || die();
    assert_vector(vector, &data[3], 7, &data[10], 10, &data[20], 10);
    
    // Skip 3     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 3) == 0 || die();
    assert_vector(vector, &data[6], 4, &data[10], 10, &data[20], 10);
    
    // Skip 4     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 4) == 1 || die();
    assert_vector(vector, &data[10], 0, &data[10], 10, &data[20], 10);
    
    // Skip 5     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 5) == 0 || die();
    assert_vector(vector, &data[10], 0, &data[15], 5, &data[20], 10);
    
    // Skip 6     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 6) == 1 || die();
    assert_vector(vector, &data[10], 0, &data[20], 0, &data[21], 9);
    
    // Skip 7     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 7) == 0 || die();
    assert_vector(vector, &data[10], 0, &data[20], 0, &data[28], 2);
    
    // Skip 8 (past end)
    vector_skip(vector, 0, 3, 8) == 1 || die();
    assert_vector(vector, &data[10], 0, &data[20], 0, &data[30], 0);
}

void cryptostream_vector_test_skip_multiple() {
    
    // Initalize Vector = {10,10,10}
    unsigned char data[30] = {0};
    struct iovec vector[CRYPTOSTREAM_BUFFER_COUNT*2] = {0};
    vector[0].iov_base = &data[0];  vector[0].iov_len = 10;
    vector[1].iov_base = &data[10]; vector[1].iov_len = 10;
    vector[2].iov_base = &data[20]; vector[2].iov_len = 10;
    
    // Skip 30     (v, start_i, count_i, n)
    vector_skip(vector, 0, 3, 30) == 3 || die();
    assert_vector(vector, &data[10], 0, &data[20], 0, &data[30], 0);
}

void cryptostream_vector_test_skip_multiple_one_at_a_time() {
    
    // Initalize Vector = {10,10,10}
    unsigned char data[30] = {0};
    struct iovec vector[CRYPTOSTREAM_BUFFER_COUNT*2] = {0};
    vector[0].iov_base = &data[0];  vector[0].iov_len = 10;
    vector[1].iov_base = &data[10]; vector[1].iov_len = 10;
    vector[2].iov_base = &data[20]; vector[2].iov_len = 10;
    
    // Skip 30 
    int sum_of_returns_from_vector_skip = 0;
    for(int i = 0; i<30; i++) {
        sum_of_returns_from_vector_skip += vector_skip(vector, 0, 3, i);
    }
    sum_of_returns_from_vector_skip == 3 || die();
    assert_vector(vector, &data[10], 0, &data[20], 0, &data[30], 0);
}

void cryptostream_vector_tests() {
    cryptostream_vector_test_incrementing();
    cryptostream_vector_test_skip_multiple();
    cryptostream_vector_test_skip_multiple_one_at_a_time();
}
