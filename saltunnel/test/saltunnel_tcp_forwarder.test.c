//
//  saltunnel_tcp_forwarder.test.c
//  saltunnel
//

#define _GNU_SOURCE
#include "saltunnel_tcp_forwarder.test.h"
#include "oops.h"
#include "rwn.h"
#include "rwn.test.h"
#include "saltunnel.h"
#include "saltunnel_tcp_server_forwarder.h"
#include "saltunnel_tcp_client_forwarder.h"
#include "sodium.h"
#include "nonce.h"
#include "tcpclient.h"
#include "tcpserver.h"
#include "stopwatch.h"
#include "rwn.h"
#include "log.h"
#include "log.test.h"
#include "cache.test.h"
#include "nonce.test.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static unsigned char testkey[32] = {
 0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89
} ;

typedef struct saltunnel_forwarder_thread_context {
    int client_or_server; // client=0, servertcp_server_=1
    const char* from_ip;
    const char* from_port;
    const char* to_ip;
    const char* to_port;
} saltunnel_forwarder_thread_context;

static cache table = {0};

static void* saltunnel_forwarder_thread_inner(void* v)
{
    saltunnel_forwarder_thread_context* c = (saltunnel_forwarder_thread_context*)v;
    if(c->client_or_server==0) {
        log_set_thread_name("cfwd");
        saltunnel_tcp_client_forwarder(testkey, c->from_ip, c->from_port, c->to_ip, c->to_port);
    } else {
        log_set_thread_name("sfwd");
        try(cache_clear(&table)) || oops_fatal("error");
        saltunnel_tcp_server_forwarder(&table, testkey, c->from_ip, c->from_port, c->to_ip, c->to_port);
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
     .OPT_TCP_FASTOPEN = 1
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
    
    // ---- Signal EOF ----
    if(shutdown(fd_conn, SHUT_WR)<0)
        oops_fatal("failed to shutdown");
    
    // ---- Receive EOF ----
    if(read(fd_conn, actual_readmsg, rlen)!=0)
        oops_fatal("expected EOF from socket");
    
    // Clean up
    try(close(fd_conn)) || oops_fatal("failed to close TCP connection");
    try(close(tcpserver)) || oops_fatal("failed to close TCP server");
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_info("(TCPSTUB SERVER) successfully read CORRECT message");
    else
        oops_fatal("(TCPSTUB SERVER) readmsg differed from expected");
    
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
    
    for(int tries_left=100; tries_left>0; tries_left--) {
        if(tries_left==0)
            oops_fatal("failed to connect too many times");
            
        // Create a TCP client
        tcpclient_options options = {
         .OPT_TCP_NODELAY = 1,
//         .OPT_TCP_FASTOPEN = 1
        };
        
        int tcpclient = tcpclient_new(ip, port, options);
        
        // If connection was refused, try to connect again
        if(tcpclient<0 && errno == ECONNREFUSED) {
            log_info("(TCPSTUB CLIENT) CONNECTION REFUSED (TO %s:%s), TRYING AGAIN...", ip, port);
            usleep(50000); errno = 0;
            continue;
        }
        // Any other error is test failure
        if(tcpclient<0)
            oops_fatal("failed to establish TCP connection");
        
        log_info("(TCPSTUB CLIENT) CONNECTION SUCCEEDED (TO %s:%s).", ip, port);
        
        // ---- Read a message ----
        int rlen = (int)strlen(readmsg);
        log_info("(TCPSTUB CLIENT) READING %d BYTES.",rlen);
        int rrc = (int)read(tcpclient, actual_readmsg, rlen); // TODO: Change to readn.  Just testing.
        if(rrc<0) oops_fatal("failed to read");
        if(rrc != rlen) { log_info("(TCPSTUB CLIENT) partial read (%d/%d)", rrc, rlen); oops_fatal("..."); }
        log_info("(TCPSTUB CLIENT) READ %d BYTES FROM CONNECTION", rrc);
        
        // ---- Write a message ----
        int wlen = (int)strlen(writemsg);
        log_info("(TCPSTUB CLIENT) WRITING %d BYTES.",wlen);
        int wrc = (int)write(tcpclient, writemsg, wlen); // TODO: Change to readn.  Just testing.
        if(wrc<0) oops_fatal("failed to read");
        if(wrc != wlen) { log_info("partial write (%d/%d)", wrc, wlen); oops_fatal("..."); }
        log_info("(TCPSTUB CLIENT) WROTE %d BYTES TO CONNECTION", wlen);
        
        // ---- Signal EOF ----
        if(shutdown(tcpclient, SHUT_WR)<0)
            oops_fatal("failed to shutdown");
        
        // ---- Receive EOF ----
        if(read(tcpclient, actual_readmsg, rlen)!=0)
            oops_fatal("expected EOF from socket");
        
        // Clean up
        try(close(tcpclient)) || oops_fatal("failed to close socket");
        break;
    }
    log_info("(TCPSTUB CLIENT) connection succeeded");
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_info("(TCPSTUB CLIENT) successfully read CORRECT message");
    else
        oops_fatal("(TCPSTUB CLIENT) readmsg differed from expected");
}

// TCP Server test
void saltunnel_tcp_forwarder_tests() {
    
    // Arrange  Threads
    
    // Server Writer-Reader Thread:
    pthread_t thread1 = tcpstub_server_writer_reader("127.0.0.1", "3270",
                          "this string from TCP server stub to client stub.",
                          "this string from TCP client stub to server stub");
    
    // Server Forwarder Thread:
    pthread_t thread2 = saltunnel_forwarder_thread(1, "127.0.0.1", "3260", "127.0.0.1", "3270");

    // Client Forwarder Thread:
    pthread_t thread3 = saltunnel_forwarder_thread(0, "127.0.0.1", "3250", "127.0.0.1", "3260");
    
    // Client Writer-Reader:
    tcpstub_client_writer_reader("127.0.0.1", "3250",
                                 "this string from TCP client stub to server stub",
                                 "this string from TCP server stub to client stub.");
    log_info("test11 assertion successfully completed");
    
    // Clean up
    pthread_kill(thread1, 0);
    pthread_kill(thread2, 0);
    pthread_kill(thread3, 0);
//    pthread_kill(thread1, SIGKILL);
//    pthread_kill(thread2, SIGKILL);
}
