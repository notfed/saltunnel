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
        try(cache_clear(&table)) || oops_error("error");
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
    pthread_create(&thread, NULL, saltunnel_forwarder_thread_inner, (void*)c)==0 || oops_error("pthread_create failed");
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
        oops_error("failed to create TCP server");
    
    // Accept a connection
    log_trace("TCP stub server: waiting for accept on %s:%s", ip, port);
    int fd_conn = tcpserver_accept(tcpserver);
    if(fd_conn<0)
        oops_error("failed to establish TCP connection");
    log_trace("TCP stub server: accepted on %s:%s", ip, port);
    
    // ---- Write a message ----
    int wlen = (int)strlen(writemsg);
    log_trace("TCP stub server: writing %d bytes.",wlen);
    int wrc = (int)writen(fd_conn, writemsg, wlen);
    if(wrc<0) oops_error("failed to read");
    if(wrc != wlen) { log_error("partial write (%d/%d)", wrc, wlen); exit(1); }
    log_trace("TCP stub server: wrote %d bytes to connection", wlen);
    
    // ---- Read a message ----
    char actual_readmsg[512] = {0};
    int rlen = (int)strlen(readmsg);
    log_trace("TCP stub server: reading %d bytes.",rlen);
    int rrc = (int)readn(fd_conn, actual_readmsg, rlen);
    if(rrc<0) oops_error("failed to read");
    if(rrc != rlen) { log_error("partial read (%d/%d)", rrc, rlen); exit(1);} // TODO: Allow oops to take varargs
    log_trace("TCP stub server: read %d bytes from connection", rrc);
    
    // ---- Signal EOF ----
    if(shutdown(fd_conn, SHUT_WR)<0)
        oops_error("failed to shutdown");
    
    // ---- Receive EOF ----
    if(read(fd_conn, actual_readmsg, rlen)!=0)
        oops_error("expected EOF from socket");
    
    // Clean up
    try(close(fd_conn)) || oops_error("failed to close TCP connection");
    try(close(tcpserver)) || oops_error("failed to close TCP server");
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_trace("TCP stub server: successfully read correct message");
    else
        oops_error("TCP stub server: readmsg differed from expected");
    
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
    pthread_create(&thread, NULL, tcpstub_server_write_inner, (void*)c)==0 || oops_error("pthread_create failed");
    return thread;
}

static void tcpstub_client_writer_reader(const char* ip, const char* port, const char* writemsg, const char* readmsg)
{
    char actual_readmsg[512] = {0};
    
    for(int tries_left=100; tries_left>0; tries_left--) {
        if(tries_left==0)
            oops_error("failed to connect too many times");
            
        // Create a TCP client
        tcpclient_options options = {
         .OPT_TCP_NODELAY = 1,
         .OPT_CONNECT_TIMEOUT = 10000
//         .OPT_TCP_FASTOPEN = 1
        };
        
        int tcpclient = tcpclient_new(ip, port, options);
        
        // If connection was refused, try to connect again
        if(tcpclient<0 && errno == ECONNREFUSED) {
            log_trace("TCP stub client: connection refused (to %s:%s), trying again...", ip, port);
            usleep(50000); errno = 0;
            continue;
        }
        // Any other error is test failure
        if(tcpclient<0)
            oops_error("failed to establish TCP connection");
        
        log_trace("TCP stub client: connection succeeded (to %s:%s).", ip, port);
        
        // ---- Read a message ----
        int rlen = (int)strlen(readmsg);
        log_trace("TCP stub client: reading %d bytes.",rlen);
        int rrc = (int)readn(tcpclient, actual_readmsg, rlen);
        if(rrc<0) oops_error("failed to read");
        if(rrc != rlen) { log_error("TCP stub client: partial read (%d/%d)", rrc, rlen); exit(1); }
        log_trace("TCP stub client: read %d bytes from connection", rrc);
        
        // ---- Write a message ----
        int wlen = (int)strlen(writemsg);
        log_trace("TCP stub client: writing %d bytes.",wlen);
        int wrc = (int)writen(tcpclient, writemsg, wlen);
        if(wrc<0) oops_error("failed to read");
        if(wrc != wlen) { log_error("partial write (%d/%d)", wrc, wlen); exit(1); }
        log_trace("TCP stub client: wrote %d bytes to connection", wlen);
        
        // ---- Signal EOF ----
        if(shutdown(tcpclient, SHUT_WR)<0)
            oops_error("failed to shutdown");
        
        // ---- Receive EOF ----
        if(read(tcpclient, actual_readmsg, rlen)!=0)
            oops_error("expected EOF from socket");
        
        // Clean up
        try(close(tcpclient)) || oops_error("failed to close socket");
        break;
    }

    log_trace("TCP stub client: connection succeeded");
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_trace("TCP stub client: successfully read correct message");
    else
        oops_error("TCP stub client: readmsg differed from expected");

    usleep(1000); // TODO: Wait synchronously for TCP threads to finish
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
    
    // Kill the ever-running forwarder threads
    pthread_kill(thread1, 0);
    pthread_kill(thread2, 0);
    pthread_kill(thread3, 0);
}
