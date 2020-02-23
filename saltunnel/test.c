//
//  test.c
//  saltunnel2
//
#define _GNU_SOURCE
#include "oops.h"
#include "test.h"
#include "uninterruptable.h"
#include "saltunnel.h"
#include "saltunnel_tcp_server_forwarder.h"
#include "saltunnel_tcp_client_forwarder.h"
#include "sodium.h"
#include "nonce.h"
#include "tcpclient.h"
#include "tcpserver.h"
#include "stopwatch.h"
#include "uninterruptable.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Contains encrypted packet which says "from_net_pipe"
static char test_encpacket[] = {0xee,0xc9,0xdb,0x7b,0x5f,0x37,0x1c,0x9f,0x8c,0x68,0x1d,0x74,0xc3,0xb1,0x0c,0x5b,0x44,0x0e,0x96,0x33,0xf7,0xc7,0xe0,0x5d,0x39,0x20,0x2d,0x7f,0x4c,0x36,0xdb,0xd2,0xe4,0x34,0x74,0xf0,0x47,0xe6,0x28,0x4c,0x6b,0x03,0x4b,0x8d,0x3c,0xc9,0xdf,0x32,0xd5,0x04,0xd3,0x0d,0x96,0x68,0xaf,0x18,0x82,0x62,0xe1,0x13,0x69,0xd9,0xd2,0x3f,0xcd,0xe2,0xe0,0x99,0xaa,0xcf,0x68,0xc3,0xfa,0x8b,0xc8,0x14,0xc8,0x92,0xe8,0x09,0xd8,0xde,0x47,0x96,0x31,0x35,0xd8,0xee,0xb9,0xea,0xfc,0xd8,0x2f,0xc6,0x9e,0x87,0x33,0x22,0x82,0xc7,0xc0,0x60,0xab,0xad,0x03,0x07,0x2a,0x57,0x78,0x13,0x85,0x42,0x29,0x86,0x0e,0x87,0x49,0x8c,0xc5,0x48,0x80,0x5a,0xdb,0x18,0x00,0x57,0x5d,0xfc,0x1d,0xfe,0xe9,0xbd,0x98,0x35,0xb0,0xcb,0x1d,0x9d,0x24,0x53,0x26,0x86,0x4c,0x1e,0x0f,0x1c,0x10,0xcd,0x70,0x29,0x3e,0x5b,0x7b,0x4d,0x2a,0x1a,0xd9,0x36,0x47,0xcd,0xd8,0x73,0xa7,0x91,0x68,0x46,0x9e,0x36,0x75,0x94,0x67,0x62,0x01,0x51,0x5d,0xb1,0x54,0xec,0x04,0xa1,0x90,0x4d,0x57,0x26,0x92,0x15,0x4b,0x34,0x56,0x8b,0xa5,0x9f,0xfd,0xeb,0x24,0x2a,0xdd,0xe1,0x3b,0xff,0x16,0x24,0x27,0x32,0x4e,0xe1,0xf7,0x57,0x00,0x25,0x9f,0xbc,0x54,0x67,0x66,0x53,0xeb,0x3a,0x47,0xdc,0xc6,0x97,0xfd,0x3e,0x64,0x78,0x30,0xd7,0x81,0x87,0x58,0x31,0x33,0xd3,0x59,0xd9,0x10,0xfc,0x28,0xf5,0x9b,0xc3,0x7f,0x95,0xa6,0x2e,0x2c,0x55,0xf1,0x1b,0x52,0x35,0x5b,0x08,0xc5,0xce,0x5a,0xd1,0x59,0x78,0xe6,0x7d,0x7d,0xca,0x77,0xa4,0xc7,0xef,0xad,0x16,0x41,0xd7,0x3d,0xb4,0x50,0xe4,0x6f,0xf1,0x99,0x10,0x21,0x5a,0xe4,0xb7,0xad,0x3b,0xcd,0x7a,0xc9,0x81,0x83,0x0f,0x24,0x36,0x96,0x3c,0xc3,0xe5,0xd8,0x3d,0x1b,0xa5,0x1d,0x7f,0x4d,0xe9,0x35,0x1e,0xc7,0x95,0xa1,0xb9,0xd3,0x9b,0xec,0xe4,0xf5,0x10,0xaf,0xca,0xb1,0x6b,0x1e,0xb7,0xb1,0xb4,0xfc,0xc9,0xff,0xdf,0x23,0x84,0xeb,0x25,0x6d,0x0f,0xb9,0xb8,0x6c,0x0f,0xac,0x21,0xcd,0xb4,0x36,0x99,0x3a,0xc1,0x4b,0x55,0xf6,0x35,0xb1,0x3e,0x6a,0x68,0xbc,0xeb,0x22,0x68,0xbc,0xcd,0x93,0x42,0xc9,0xfd,0xf3,0xf0,0xc4,0x45,0x8c,0xbe,0x40,0xb5,0xc7,0x30,0xa5,0xab,0x4e,0x1e,0x16,0x1a,0x07,0xea,0xc0,0x07,0x47,0xf4,0xee,0x12,0x05,0x78,0x68,0x89,0xfa,0x08,0x6e,0x3f,0x26,0x65,0x34,0x3c,0x62,0x53,0x1d,0xee,0x3d,0xa6,0xc3,0xa9,0x5d,0x78,0x38,0xc5,0x3c,0xb5,0x75,0x0c,0x6f,0x98,0x58,0xb2,0x8d,0x9c,0x3d,0x88,0x37,0x68,0x0b,0xe6,0x19,0xfc,0xe8,0xee,0x26,0x72,0x06,0xbd,0x75,0xe6,0x96,0x75,0xb8,0xe7,0x12,0xab,0xca,0x3b,0x58,0x1e,0x11,0xb1,0x08,0x33,0xe9,0xc7,0xd3,0x5c,0xf2,0x72,0xdd,0x6b,0x67,0xd8,0x05,0x7e,0x99,0xb6,0xe9,0xd4,0xf1,0xf1,0x2d,0x03,0xf3,0x65,0xdd,0x88,0xfb,0xf5,0xb8,0x83,0x04,0xb0,0xae,0x2b,0x86,0xff,0x62,0xc5,0x35,0xce,0x2f,0xd1,0xa0,0x88,0x9e,0xa7,0xab,0x38,0xe8,0x23,0x0a,0xad,0x48,0x0e,0x72,0x61,0x9c,0x34,0x0e,0xa4
};

static unsigned char testkey[32] = {
 0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
} ;

// test1: Can uninterruptably write/read to/from pipes
void test1() {
    // Create two pipes
    int pipe_local[2]; try(pipe(pipe_local)) || oops_fatal("failed to create pipe");
    int pipe_net[2];   try(pipe(pipe_net)) || oops_fatal("failed to create pipe");
        
    // Write "expected value" to both pipes
    const char local_teststr_expected[] = "send_nt_pipe";
    const char net_teststr_expected[] = "send_lc_pipe";
    uninterruptable_writen(write, pipe_local[1], local_teststr_expected, 12);
    uninterruptable_writen(write, pipe_net[1], net_teststr_expected, 12);
    
    // Read "actual value" from both pipes
    char local_teststr_actual[12+1] = {0};
    char net_teststr_actual[12+1]   = {0};
    uninterruptable_read(read, pipe_local[0], local_teststr_actual, 12);
    uninterruptable_read(read, pipe_net[0], net_teststr_actual, 12);
    
    // Assert "expected value" equals "actual value"
    strcmp(local_teststr_expected, local_teststr_actual) == 0 || oops_fatal("local teststr did not match");
    strcmp(net_teststr_expected, net_teststr_actual) == 0 || oops_fatal("net teststr did not match");
}

//
//// test2: saltunnel works with nullcryptostream
//void test2() {
//
//    // Create four "fake files" (i.e., pipes)
//    int pipe_local_read[2];  try(pipe(pipe_local_read))  || oops_fatal("failed to create pipe");
//    int pipe_local_write[2]; try(pipe(pipe_local_write)) || oops_fatal("failed to create pipe");
//    int pipe_net_read[2];    try(pipe(pipe_net_read))    || oops_fatal("failed to create pipe");
//    int pipe_net_write[2];   try(pipe(pipe_net_write))   || oops_fatal("failed to create pipe");
//
//    // Start with "expected value" available in both "readable" pipes
//    const char local_teststr_expected[] = "send_nt_pipe";
//    const char net_teststr_expected[] = "send_lc_pipe";
//    uninterruptable_write(write, pipe_local_read[1], local_teststr_expected, 12); close(pipe_local_read[1]);
//    uninterruptable_write(write, pipe_net_read[1],   net_teststr_expected,   12); close(pipe_net_read[1]);
//
//    // Run saltunnel
//    cryptostream ingress = {
//        .op = cryptostream_identity_feed,
//        .from_fd = pipe_net_read[0],
//        .to_fd = pipe_local_write[1]
//    };
//    cryptostream egress = {
//        .op = cryptostream_identity_feed,
//        .from_fd = pipe_local_read[0],
//        .to_fd = pipe_net_write[1]
//    };
//    saltunnel(&ingress, &egress);
//
//    // Read "actual value" from both "write" pipes
//    char local_teststr_actual[12+1] = {0};
//    char net_teststr_actual[12+1] = {0};
//    uninterruptable_read(read, pipe_local_write[0], local_teststr_actual, 12);
//    uninterruptable_read(read, pipe_net_write[0], net_teststr_actual, 12);
//
//    // Assert "expected value" equals "actual value"
//    strcmp(local_teststr_expected, net_teststr_actual) == 0 || oops_fatal("local teststr did not match");
//    strcmp(net_teststr_expected, local_teststr_actual) == 0 || oops_fatal("net teststr did not match");
//}

// test3: Can encrypt and decrypt
void test3() {
    
    // Arrange
    unsigned char nonce[24] = {0};
    const unsigned char expectedbuf[48] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0abcd1234abcd1234"; // 32 zeros
    unsigned char cipherbuf[48] = {0};
    unsigned char actualbuf[48] = {0};
    
    // Act
    
    // crypto_secretbox:
    // - signature: crypto_secretbox(c,m,mlen,n,k);
    // - input structure:
    //   - [0..32] == zero
    //   - [32..]  == plaintext
    // - output structure:
    //   - [0..16]  == zero
    //   - [16..32] == auth
    //   - [32..]   == ciphertext
    try(crypto_secretbox(cipherbuf,expectedbuf,48,nonce,testkey)) || oops_fatal("failed to encrypt");
    
    //
    // crypto_secretbox_open:
    // - signature: crypto_secretbox_open(m,c,clen,n,k);
    // - input structure:
    //   - [0..16]  == zero
    //   - [16..32] == auth
    //   - [32..]   == ciphertext
    // - output structure:
    //   - [0..32] == zero
    //   - [32..]  == plaintext
    try(crypto_secretbox_open(actualbuf,cipherbuf,48,nonce,testkey)) || oops_fatal("failed to decrypt");
    
    // Assert
    memcmp(expectedbuf,actualbuf,sizeof(expectedbuf)) == 0 || oops_fatal("expected did not match actual");
    
}

void create_test_pipe(int fds[2]) {
    try(pipe(fds)) || oops_fatal("failed to create pipe");
    #ifdef F_SETPIPE_SZ
    try(fcntl(fds[0], F_SETPIPE_SZ, 1048576)) || oops_fatal("failed to configure pipe");
    try(fcntl(fds[1], F_SETPIPE_SZ, 1048576)) || oops_fatal("failed to configure pipe");
    #endif
}

// test4: saltunnel works with cryptostream
void test4() {
    
    // Create four "fake files" (i.e., pipes)
    int pipe_local_read[2];  create_test_pipe(pipe_local_read);
    int pipe_local_write[2]; create_test_pipe(pipe_local_write);
    int pipe_net_read[2];    create_test_pipe(pipe_net_read);
    int pipe_net_write[2];   create_test_pipe(pipe_net_write);
    
    // Start with "expected value" available for reading from net pipe
//    const char net_teststr_expected[] = "from_net_pipe";
    uninterruptable_writen(write, pipe_net_read[1],   test_encpacket,   512); close(pipe_net_read[1]);
    
    // Start with "expected value" available for reading from local pipe
    const char local_teststr_expected[] = "from_lcl_pipe"; 
    uninterruptable_writen(write, pipe_local_read[1], local_teststr_expected, 14); close(pipe_local_read[1]);
    
    // Run saltunnel
    cryptostream ingress = {
//        .op = cryptostream_decrypt_feed,
        .from_fd = pipe_net_read[0],
        .to_fd = pipe_local_write[1]
    };
    cryptostream egress = {
//        .op = cryptostream_encrypt_feed,
        .from_fd = pipe_local_read[0],
        .to_fd = pipe_net_write[1]
    };
    saltunnel(&ingress, &egress);
    
    // Read "actual value" from both "write" pipes
    char local_teststr_actual[14] = {0};
    char net_teststr_actual[512] = {0};
    uninterruptable_read(read, pipe_local_write[0], local_teststr_actual, 14);
    uninterruptable_read(read, pipe_net_write[0], net_teststr_actual, 512) == 512 || oops_fatal("didn't write 512 bytes to net");
    
    // Assert "expected value" equals "actual value"
    strcmp(local_teststr_actual, "from_net_pipe") == 0 || oops_fatal("local teststr did not match");
}

//
//typedef struct saltunnel_thread_context {
//    cryptostream ingress;
//    cryptostream egress;
//} saltunnel_thread_context;
//
//void *saltunnel_peer_thread(void *contextptr)
//{
//    // Get reference to context
//    saltunnel_thread_context* context =
//        (saltunnel_thread_context*)contextptr;
//
//    // Run saltunnel
//    saltunnel(&context->ingress, &context->egress);
//
//    return 0;
//}


void test5() {
    {
        char log_name[256];
        char* log_filename_from_macro = "test.c";
        int len = sizeof("test.c");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_fatal("log test, assertion 1 failed");
    }
    {
        char log_name[256];
        char* log_filename_from_macro = "/a/b/c/test.c";
        int len = sizeof("/a/b/c/test.c");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_fatal("log test, assertion 2 failed");
    }
    {
        char log_name[256];
        char* log_filename_from_macro = "C:\\Program Files (x86)\\log\\ger\\test.c";
        int len = sizeof("C:\\Program Files (x86)\\log\\ger\\test.c");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_fatal("log test, assertion 2 failed");
    }
    {
        char log_name[256];
        char* log_filename_from_macro = "test";
        int len = sizeof("test");
        char log_name_filled = 0;
        
        log_filename_idempotent_fill(log_name, log_filename_from_macro, len, &log_name_filled);
        
        strcmp(log_name, "test") == 0 || oops_fatal("log test, assertion 2 failed");
    }
}

typedef struct saltunnel_thread_context {
    const char* thread_name;
    cryptostream* ingress;
    cryptostream* egress;
} saltunnel_thread_context;

static void* saltunnel_thread_inner(void* v)
{
    saltunnel_thread_context* c = (saltunnel_thread_context*)v;
    log_set_thread_name(c->thread_name);
    saltunnel(c->ingress, c->egress);
    free(v);
    return 0;
}

static pthread_t saltunnel_thread(const char* thread_name, cryptostream* ingress, cryptostream* egress)
{
    saltunnel_thread_context* c = calloc(1,sizeof(saltunnel_thread_context));
    c->thread_name = thread_name;
    c->ingress = ingress;
    c->egress = egress;
    pthread_t thread;
    pthread_create(&thread, NULL, saltunnel_thread_inner, (void*)c)==0 || oops_fatal("pthread_create failed");
    return thread;
}

typedef struct write_thread_context {
    const char* thread_name;
    int fd;
    const char *buf;
    unsigned int len;
} write_thread_context;

static void* write_thread_inner(void* v)
{
    write_thread_context* c = (write_thread_context*)v;
    log_set_thread_name(c->thread_name);
    int w;
//    if(c->len!=65537) oops_fatal("WHAT c->len!=65537"); // TODO: Temporary
//    if(c->buf[65536]!='q') oops_fatal("WHAT c->buf[65536]!=q"); // TODO: Temporary
    w = (int)write(c->fd, c->buf, c->len);
    if(w != c->len) oops_fatal("write");
    try(close(c->fd)) || oops_fatal("close");
    log_debug("write_thread wrote %d bytes to fd %d (and closed it)",(int)w,c->fd);
    free(v);
    return 0;
}

static pthread_t write_thread(const char* thread_name, int fd,const char *buf,unsigned int len)
{
    write_thread_context* c = calloc(1,sizeof(write_thread_context));
    c->thread_name = thread_name;
    c->fd = fd;
    c->buf = buf;
    c->len = len;
    pthread_t thread;
    pthread_create(&thread, NULL, write_thread_inner, (void*)c)==0 || oops_fatal("pthread_create failed");
    return thread;
}

static int first_difference(const char* str1, const char* str2, unsigned int n) {
    for(int i = 0; i < n; i++) {
        if(str1[i] != str2[i])
            return i;
    }
    return -1;
}

// Bidirectional saltunnel test
static void bidirectional_test(const char* from_peer1_local_str, unsigned int from_peer1_local_str_len,
                               const char* from_peer2_local_str, unsigned int from_peer2_local_str_len) {
    
    int peer1_pipe_local_input[2];  create_test_pipe(peer1_pipe_local_input);
    int peer1_pipe_local_output[2]; create_test_pipe(peer1_pipe_local_output);
    
    int peer2_pipe_local_input[2];  create_test_pipe(peer2_pipe_local_input);
    int peer2_pipe_local_output[2]; create_test_pipe(peer2_pipe_local_output);
    
    int peer1_pipe_to_peer2[2];     create_test_pipe(peer1_pipe_to_peer2);
    int peer2_pipe_to_peer1[2];     create_test_pipe(peer2_pipe_to_peer1);
    
    log_debug("created pipe: peer1_pipe_local_input [%2d,%2d]", peer1_pipe_local_input[0], peer1_pipe_local_input[1]);
    log_debug("created pipe: peer1_pipe_local_output[%2d,%2d]", peer1_pipe_local_output[0], peer1_pipe_local_output[1]);
    log_debug("created pipe: peer1_pipe_to_peer2    [%2d,%2d]", peer1_pipe_to_peer2[0], peer1_pipe_to_peer2[1]);
    
    log_debug("created pipe: peer2_pipe_local_input [%2d,%2d]", peer2_pipe_local_input[0], peer2_pipe_local_input[1]);
    log_debug("created pipe: peer2_pipe_local_output[%2d,%2d]", peer2_pipe_local_output[0], peer2_pipe_local_output[1]);
    log_debug("created pipe: peer2_pipe_to_peer1    [%2d,%2d]", peer2_pipe_to_peer1[0], peer2_pipe_to_peer1[1]);
    
    // Start with "expected value" available for reading from peer1's local pipe
    pthread_t write_thread_1 = write_thread("wpeer1", peer1_pipe_local_input[1], from_peer1_local_str, from_peer1_local_str_len);
    
    // Start with "expected value" available for reading from peer2's local pipe
    pthread_t write_thread_2 = write_thread("wpeer2", peer2_pipe_local_input[1], from_peer2_local_str, from_peer2_local_str_len);
    
    // Initialize thread contexts
    cryptostream context1_ingress = {
//        .op = cryptostream_decrypt_feed,
        .from_fd = peer2_pipe_to_peer1[0],
        .to_fd = peer1_pipe_local_output[1],
    };
    cryptostream context1_egress = {
//        .op = cryptostream_encrypt_feed,
        .from_fd = peer1_pipe_local_input[0],
        .to_fd = peer1_pipe_to_peer2[1]
    };
    
    cryptostream context2_ingress = {
//        .op = cryptostream_decrypt_feed,
        .from_fd = peer1_pipe_to_peer2[0],
        .to_fd = peer2_pipe_local_output[1]
    };
    cryptostream context2_egress = {
//        .op = cryptostream_encrypt_feed,
        .from_fd = peer2_pipe_local_input[0],
        .to_fd = peer2_pipe_to_peer1[1]
    };
    
    stopwatch sw;
    stopwatch_start(&sw);
    
    // Spawn saltunnel threads
    pthread_t saltunnel_thread_1 = saltunnel_thread("speer1",&context1_ingress, &context1_egress);
    pthread_t saltunnel_thread_2 = saltunnel_thread("speer2",&context2_ingress, &context2_egress);
    
    // Read from outputs
    
    // Read "actual value" from peer1's local pipe
    log_debug("reading %d bytes from %d", from_peer2_local_str_len, peer1_pipe_local_output[0]);
    char* from_peer1_local_str_actual = calloc(from_peer2_local_str_len+1,sizeof(char));
    try(uninterruptable_readn(peer1_pipe_local_output[0], from_peer1_local_str_actual, from_peer2_local_str_len)) || oops_fatal("read");
    
    // Read "actual value" from peer2's local pipe
    log_debug("reading %d bytes from %d", from_peer1_local_str_len, peer2_pipe_local_output[0]);
    char* from_peer2_local_str_actual = calloc(from_peer1_local_str_len+1,sizeof(char));
    try(uninterruptable_readn(peer2_pipe_local_output[0], from_peer2_local_str_actual, from_peer1_local_str_len)) || oops_fatal("read");
    
    // Clean up threads
    try(pthread_join(write_thread_1, NULL)) || oops_fatal("pthread_join");
    try(pthread_join(write_thread_2, NULL)) || oops_fatal("pthread_join");
    try(pthread_join(saltunnel_thread_1, NULL)) || oops_fatal("pthread_join");
    try(pthread_join(saltunnel_thread_2, NULL)) || oops_fatal("pthread_join");
    
    long elapsed = stopwatch_elapsed(&sw);
    log_info("test8 saltunnel took %dus (%d MBps)", (int)elapsed, (int)((from_peer1_local_str_len+from_peer2_local_str_len)/elapsed));

    // Compare actual peer1 local data
    int cmp1 = memcmp(from_peer2_local_str,from_peer1_local_str_actual,from_peer2_local_str_len);
    if(cmp1 != 0) {
        int d = first_difference(from_peer2_local_str, from_peer1_local_str_actual, from_peer2_local_str_len);
        const char* s1 = from_peer2_local_str+d;
        const char* s2 = from_peer1_local_str_actual+d;
        log_fatal("str differed ('%c'!='%c') at index %d",*s1,*s2,d);
        log_fatal("bidirectional test (%d,%d) failed: peer1 strs differed",from_peer1_local_str_len,from_peer2_local_str_len);
        _exit(1);
    }
    
    // Compare actual peer2 local data
    int cmp2 = memcmp(from_peer1_local_str,from_peer2_local_str_actual,from_peer1_local_str_len);
    if(cmp2 != 0) {
        int d = first_difference(from_peer1_local_str, from_peer2_local_str_actual, from_peer1_local_str_len);
        const char* s1 = from_peer1_local_str+d;
        const char* s2 = from_peer2_local_str_actual+d;
        log_fatal("str differed ('%c'!='%c') at index %d",*s1,*s2,d);
        log_fatal("bidirectional test (%d,%d) failed: peer1 strs differed",from_peer1_local_str_len,from_peer2_local_str_len);
        _exit(1);
    }
    
    // Clean up memory
    free(from_peer1_local_str_actual);
    free(from_peer2_local_str_actual);
    
    // Clean up pipes // TODO: Not needed?
    close(peer1_pipe_local_input[0]);  close(peer1_pipe_local_input[1]);
    close(peer1_pipe_local_output[0]); close(peer1_pipe_local_output[1]);
    close(peer1_pipe_to_peer2[0]);     close(peer1_pipe_to_peer2[1]);
    close(peer2_pipe_local_input[0]);  close(peer2_pipe_local_input[1]);
    close(peer2_pipe_local_output[0]); close(peer2_pipe_local_output[1]);
    close(peer2_pipe_to_peer1[0]);     close(peer2_pipe_to_peer1[1]);

    log_info("bidirectional test (%d,%d) passed",from_peer1_local_str_len,from_peer2_local_str_len);
}

// Bidirectional saltunnel test
void test6() {
    
    const char from_peer1_local_str[] = "from_peer1_local";
    const char from_peer2_local_str[] = "from_peer2_local";
    
    bidirectional_test(from_peer1_local_str, strlen(from_peer1_local_str)+1,
                       from_peer2_local_str, strlen(from_peer2_local_str)+1);
}

// Bidirectional saltunnel test; multi-packet
void test7() {
    
    char from_peer1_local_str[700];
    char from_peer2_local_str[700];
    for(int i = 0; i < sizeof(from_peer1_local_str); i++) {
        from_peer1_local_str[i] = i+1;
        from_peer2_local_str[i] = i+1;
    }

        bidirectional_test(from_peer1_local_str, 1,
                           from_peer2_local_str, sizeof(from_peer2_local_str));
//    bidirectional_test(from_peer1_local_str, sizeof(from_peer1_local_str),
//                       from_peer2_local_str, sizeof(from_peer2_local_str));
}

// Bidirectional saltunnel test; multi-packet, various sizes
void test8_for(int i) {
    log_debug("---- testing with %d bytes ----", i);
    
    int peer1n = i;
    int peer2n = i;
        
    char* from_peer1_local_str = calloc(peer1n,1);
    char* from_peer2_local_str = calloc(peer2n,1);
    
    for(int c = 0; c < i; c++) {
        from_peer1_local_str[c] = (c%19==4||c%19==9||c%19==14) ? '-' : 'a'+((c/19)%26);
        from_peer2_local_str[c] = from_peer1_local_str[c];
    }
    
    bidirectional_test(from_peer1_local_str, peer1n,
                       from_peer2_local_str, peer2n); // TODO: 0 should be peer2n
    
    free(from_peer1_local_str);
    free(from_peer2_local_str);
}
void test8() {
//    
//    test8_for(1000000);
//    return;
//    
    int edges[] = {
        CRYPTOSTREAM_BUFFER_COUNT,
        CRYPTOSTREAM_BUFFER_MAXBYTES_CIPHERTEXT,
        CRYPTOSTREAM_BUFFER_MAXBYTES,
        CRYPTOSTREAM_BUFFER_MAXBYTES_PLAINTEXT,
        CRYPTOSTREAM_BUFFER_MAXBYTES_DATA,
        CRYPTOSTREAM_SPAN_MAXBYTES_DATA,
        CRYPTOSTREAM_SPAN_MAXBYTES_PLAINTEXT,
        CRYPTOSTREAM_SPAN_MAXBYTES_CIPHERTEXT,
        CRYPTOSTREAM_SPAN_MAXBYTES,
        CRYPTOSTREAM_SPAN_MAXBYTES_DATA + CRYPTOSTREAM_BUFFER_MAXBYTES_DATA + 1,
        (2*CRYPTOSTREAM_SPAN_MAXBYTES_DATA) + CRYPTOSTREAM_BUFFER_MAXBYTES_DATA + 1,
        1000000
    };
    int multipliers[] = { 1, 2, 3, 10 };
    int adders[] = { 0, -2, -1, 1, 2 };
    
    int edges_len = sizeof(edges)/sizeof(edges[0]);
    int multipliers_len = sizeof(multipliers)/sizeof(multipliers[0]);
    int adders_len = sizeof(adders)/sizeof(adders[0]);
    
    for(int e = 0; e<edges_len; e++) {
        for(int m = 0; m<multipliers_len; m++) {
            for(int a = 0; a<adders_len; a++) {
                int i = edges[e] * multipliers[m] + adders[a];
                log_info("bidirectional_test (%d = %d * %d + %d) started", i, edges[e], multipliers[m], adders[a]);
                if(i>0) test8_for(i);
            }
        }
    }
    
    
}


static void run(void (*the_test)(void), const char *test_name) {
    log_debug("%s: started...", test_name);
    the_test();
    log_debug("%s: succeeded.", test_name);
}

static int calculate_filled_buffers(int start, int end, int buffersize) {
    return end/buffersize - (start-1+buffersize)/buffersize;
}

void test9() {
    if(calculate_filled_buffers(5,15,10)!=0) oops_fatal("failed test9.1");
    if(calculate_filled_buffers(5,25,10)!=1) oops_fatal("failed test9.2");
    if(calculate_filled_buffers(5,35,10)!=2) oops_fatal("failed test9.3");
    
    if(calculate_filled_buffers(0,10,10)!=1) oops_fatal("failed test9.4");
    if(calculate_filled_buffers(1,10,10)!=0) oops_fatal("failed test9.5");
    if(calculate_filled_buffers(0,11,10)!=1) oops_fatal("failed test9.6");
    
    if(calculate_filled_buffers(10,11,10)!=0) oops_fatal("failed test9.7");
    if(calculate_filled_buffers(10,19,10)!=0) oops_fatal("failed test9.8");
    if(calculate_filled_buffers(10,20,10)!=1) oops_fatal("failed test9.9");
    if(calculate_filled_buffers(10,21,10)!=1) oops_fatal("failed test9.10");
    if(calculate_filled_buffers(10,29,10)!=1) oops_fatal("failed test9.11");
    if(calculate_filled_buffers(10,30,10)!=2) oops_fatal("failed test9.12");
}


// Bidirectional saltunnel test; multi-packet
void test10() {
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
//      if(vector_skip(vector, 3, 20) != 2) oops_fatal("assertion 10.5.1 failed; vector_skip(vector, 3, 20)");
    if(buffers_skipped != 1) oops_fatal("assertion 10.5.1 failed; vector_skip(vector, 3, 20)");
    
    if(vector[0].iov_base != &data[10]) oops_fatal("assertion 10.5.2 failed");
    if(vector[0].iov_len  != 0)         oops_fatal("assertion 10.5.3 failed");
    if(vector[1].iov_base != &data[20]) oops_fatal("assertion 10.5.4 failed");
    if(vector[1].iov_len  != 0)         oops_fatal("assertion 10.5.5 failed");
    if(vector[2].iov_base != &data[30]) oops_fatal("assertion 10.5.6 failed");
    if(vector[2].iov_len  != 0)         oops_fatal("assertion 10.5.7 failed");
}


/* Test 11: TCP Layer */

typedef struct saltunnel_forwarder_thread_context {
    int client_or_server; // client=0, servertcp_server_=1
    const char* from_ip;
    const char* from_port;
    const char* to_ip;
    const char* to_port;
} saltunnel_forwarder_thread_context;
static void* saltunnel_forwarder_thread_inner(void* v)
{
    saltunnel_forwarder_thread_context* c = (saltunnel_forwarder_thread_context*)v;
    if(c->client_or_server==0) {
        log_set_thread_name("cfwd");
        saltunnel_tcp_client_forwarder(c->from_ip, c->from_port, c->to_ip, c->to_port);
    } else {
        log_set_thread_name("sfwd");
        saltunnel_tcp_server_forwarder(c->from_ip, c->from_port, c->to_ip, c->to_port);
    }
    free(v);
    return 0;
}
static pthread_t saltunnel_forwarder_thread(int client_or_server,
                         const char* from_ip,
                         const char* from_port,
                         const char* to_ip,
                         const char* to_port)
{
    saltunnel_forwarder_thread_context* c = calloc(1,sizeof(saltunnel_forwarder_thread_context));
    c->client_or_server = client_or_server;
    c->from_ip = from_ip;
    c->from_port = from_port;
    c->to_ip = to_ip;
    c->to_port = to_port;
    pthread_t thread;
    pthread_create(&thread, NULL, saltunnel_forwarder_thread_inner, (void*)c)==0 || oops_fatal("pthread_create failed");
    return thread;
}


typedef struct tcpstub_server_write_context {
    const char* ip;
    const char* port;
    const char *writemsg;
    const char *readmsg;
} tcpstub_server_write_context;
static void* tcpstub_server_write_inner(void* v)
{
    tcpstub_server_write_context* c = (tcpstub_server_write_context*)v;
    const char* ip = c->ip;
    const char* port = c->port;
    const char *writemsg = c->writemsg;
    const char *readmsg = c->readmsg;
    
    // Create a TCP server
    tcpserver_options options = {
     .OPT_TCP_NODELAY = 1,
     .OPT_SO_REUSEADDR = 1,
//     .OPT_TCP_FASTOPEN = 1
    };
    int tcpserver = tcpserver_new(ip, port, options);
    if(tcpserver<0)
        oops_fatal("failed to create TCP server");
    
    // Accept a connection
    log_info("(TCPSTUB SERVER) WAITING FOR ACCEPT ON %s:%s", ip, port);
    int fd_conn = tcpserver_accept(tcpserver);
    if(fd_conn<0)
        oops_fatal("failed to establish TCP connection");
    log_info("(TCPSTUB SERVER) ACCEPTED ON %s:%s", ip, port);
    
    // ---- Write a message ----
    int wlen = (int)strlen(writemsg);
    log_info("(TCPSTUB SERVER) WRITING %d BYTES.",wlen);
    int wrc = (int)write(fd_conn, writemsg, wlen); // TODO: Change to readn.  Just testing.
    if(wrc<0) oops_fatal("failed to read");
    if(wrc != wlen) { log_info("partial write (%d/%d)", wrc, wlen); oops_fatal("..."); }
    log_info("(TCPSTUB SERVER) WROTE %d BYTES TO CONNECTION", wlen);
    
    // ---- Read a message ----
    char actual_readmsg[512] = {0};
    int rlen = (int)strlen(readmsg);
    log_info("(TCPSTUB SERVER) READING %d BYTES.",rlen);
    int rrc = (int)read(fd_conn, actual_readmsg, rlen); // TODO: Change to readn.  Just testing.
    if(rrc<0) oops_fatal("failed to read");
    if(rrc != rlen) { log_info("partial read (%d/%d)", rrc, rlen); oops_fatal("..."); }
    log_info("(TCPSTUB SERVER) READ %d BYTES FROM CONNECTION", rrc);
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_info("(TCPSTUB SERVER) successfully read CORRECT message");
    else
        oops_fatal("(TCPSTUB SERVER) readmsg differed");
    
    // Clean up
    try(close(fd_conn)) || oops_fatal("failed to close TCP connection");
    try(close(tcpserver)) || oops_fatal("failed to close TCP server");
    
    free(v);
    return 0;
}
static pthread_t tcpstub_server_writer_reader(const char* ip,
                                      const char* port,
                                      const char *writemsg,
                                      const char *readmsg)
{
    tcpstub_server_write_context* c = calloc(1,sizeof(tcpstub_server_write_context));
    c->ip = ip;
    c->port = port;
    c->readmsg = readmsg;
    c->writemsg = writemsg;
    pthread_t thread;
    pthread_create(&thread, NULL, tcpstub_server_write_inner, (void*)c)==0 || oops_fatal("pthread_create failed");
    return thread;
}
static void tcpstub_client_writer_reader(const char* ip, const char* port, const char* writemsg, const char* readmsg)
{
    char actual_readmsg[512] = {0};
    
    for(int tries_left=10000; tries_left>0; tries_left--) {
        if(tries_left==0)
            oops_fatal("failed to connect too many times");
            
        // Create a TCP client
        tcpclient_options options = {
         .OPT_TCP_NODELAY = 1,
         //.OPT_TCP_FASTOPEN = 1
        };
        
        int tcpclient = tcpclient_new(ip, port, options);
        
        // If connection was refused, try to connect again
        if(tcpclient<0 && errno == ECONNREFUSED) {
            log_info("(TCPSTUB CLIENT) CONNECTION REFUSED (TO %s:%s), TRYING AGAIN...", ip, port);
            usleep(10000); errno = 0;
            continue;
        }
        // Any other error is test failure
        if(tcpclient<0)
            oops_fatal("failed to establish TCP connection");
        
        log_info("(TCPSTUB CLIENT) CONNECTION SUCCEEDED (TO %s:%s).", ip, port);
        
        // ---- Write a message ----
        int wlen = (int)strlen(writemsg);
        log_info("(TCPSTUB CLIENT) WRITING %d BYTES.",wlen);
        int wrc = (int)write(tcpclient, writemsg, wlen); // TODO: Change to readn.  Just testing.
        if(wrc<0) oops_fatal("failed to read");
        if(wrc != wlen) { log_info("partial write (%d/%d)", wrc, wlen); oops_fatal("..."); }
        log_info("(TCPSTUB SERVER) WROTE %d BYTES TO CONNECTION", wlen);
        
        // ---- Read a message ----
        int rlen = (int)strlen(readmsg);
        log_info("(TCPSTUB CLIENT) READING %d BYTES.",rlen);
        int rrc = (int)read(tcpclient, actual_readmsg, rlen); // TODO: Change to readn.  Just testing.
        if(rrc<0) oops_fatal("failed to read");
        if(rrc != rlen) { log_info("partial read (%d/%d)", rrc, rlen); oops_fatal("..."); }
        log_info("(TCPSTUB CLIENT) READ %d BYTES FROM CONNECTION", rrc);
        
        // Clean up
        try(close(tcpclient)) || oops_fatal("failed to close socket");
        break;
    }
    log_info("(TCPSTUB CLIENT) connection succeeded");
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_info("(TCPSTUB CLIENT) successfully read CORRECT message");
    else
        oops_fatal("(TCPSTUB CLIENT) readmsg differed");
}

// TCP Server test
void test11() {
    
    // Arrange  Threads
    
    // Writer Server:
    tcpstub_server_writer_reader("127.0.0.1", "3270",
                          "this string from TCP server stub to client stub",
                          "this string from TCP client stub to server stub");
    
    // Server Forwarder Thread:
    pthread_t thread1 = saltunnel_forwarder_thread(1, "127.0.0.1", "3260", "127.0.0.1", "3270");

    // Client Forwarder Thread:
    pthread_t thread2 = saltunnel_forwarder_thread(0, "127.0.0.1", "3250", "127.0.0.1", "3260");
    
    // Reader Client:
    tcpstub_client_writer_reader("127.0.0.1", "3250",
                                 "this string from TCP client stub to server stub",
                                 "this string from TCP server stub to client stub");
    log_info("test11 assertion successfully completed");
    
    // Clean up
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
//    pthread_kill(thread1, SIGKILL);
//    pthread_kill(thread2, SIGKILL);
}

int test() {
    
    log_info("test suite started");
//    run(test1, "test1");
//    run(test2, "test2");
//    run(test3, "test3");
//    run(test4, "test4");
//    run(test5, "test5");
//    run(test6, "test6");
//    run(test7, "test7");
//    run(test8, "test8");  // <<
//    run(test9,"test9");
//    run(test10,"test10");
    run(test11, "test11");
    
    log_info("all tests passed");
    return 0;
}
