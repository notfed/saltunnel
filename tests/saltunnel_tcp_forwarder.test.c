//
//  saltunnel_tcp_forwarder.test.c
//  saltunnel
//

#define _GNU_SOURCE
#include "saltunnel_tcp_forwarder.test.h"
#include "oops.h"
#include "rwn.h"
#include "rwn.test.h"
#include "saltunnel_mx.h"
#include "saltunnel_tcp_server_forwarder.h"
#include "saltunnel_tcp_client_forwarder.h"
#include "nonce.h"
#include "tcpclient.h"
#include "tcpserver.h"
#include "stopwatch.h"
#include "rwn.h"
#include "log.h"
#include "log.test.h"
#include "cache.test.h"
#include "nonce.test.h"
#include "cache.h"

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
#include <pthread.h>

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

static void cleanup_close(void* v) { int fd = *(int*)(v); if(fd>=0) close(fd); }

static void* saltunnel_forwarder_thread_inner(void* v)
{
    pthread_cleanup_push(free, v);
    saltunnel_forwarder_thread_context* c = v;
    if(c->client_or_server==0) {
        log_set_thread_name("cfwd");
        saltunnel_tcp_client_forwarder(testkey, c->from_ip, c->from_port, c->to_ip, c->to_port);
    } else {
        log_set_thread_name("sfwd");
        cache_clear(&table);
        saltunnel_tcp_server_forwarder(&table, testkey, c->from_ip, c->from_port, c->to_ip, c->to_port);
    }
    pthread_cleanup_pop(1);
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
    pthread_create(&thread, NULL, saltunnel_forwarder_thread_inner, c)==0 || oops_error("pthread_create failed");
    return thread;
}

typedef struct tcpstub_server_write_context {
    int server_socket;
    const char *writemsg;
    const char *readmsg;
} tcpstub_server_write_context;

static void* tcpstub_server_write_inner(void* v)
{
    pthread_cleanup_push(free, v);
    log_set_thread_name(" ss ");

    tcpstub_server_write_context* c = v;
    int server_socket = c->server_socket;
    const char *writemsg = c->writemsg;
    const char *readmsg = c->readmsg;
    
    // Accept a connection
    log_trace("TCP stub server: waiting for accept on %s:%s", ip, port);
    tcpserver_options options = {0};
    int fd_conn = tcpserver_accept(server_socket, options);
    if(fd_conn<0)
        oops_error_sys("failed to establish TCP connection");
    log_trace("TCP stub server: accepted on %s:%s", ip, port);
    
    // Create a cleanup handler to close the fd
    pthread_cleanup_push(cleanup_close, &fd_conn);
    
    // ---- Write a message ----
    int wlen = (int)strlen(writemsg);
    log_trace("TCP stub server: writing %d bytes.",wlen);
    int wrc = (int)writen(fd_conn, writemsg, wlen);
    if(wrc<0) oops_error_sys("failed to write");
    if(wrc != wlen) { log_error("partial write (%d/%d)", wrc, wlen); exit(1); }
    log_trace("TCP stub server: wrote %d bytes to connection", wlen);
    
    // ---- Read a message ----
    char actual_readmsg[512] = {0};
    int rlen = (int)strlen(readmsg);
    log_trace("TCP stub server: reading %d bytes.",rlen);
    int rrc = (int)readn(fd_conn, actual_readmsg, rlen);
    if(rrc<0) oops_error_sys("failed to read");
    if(rrc != rlen) { log_error("partial read (%d/%d)", rrc, rlen); exit(1);} // TODO: Allow oops to take varargs
    log_trace("TCP stub server: read %d bytes from connection", rrc);
    
    // ---- Signal EOF ----
    if(shutdown(fd_conn, SHUT_WR)<0)
        oops_error_sys("failed to shutdown");
    
    // ---- Receive EOF ----
    if(read(fd_conn, actual_readmsg, rlen)!=0)
        oops_error_sys("expected EOF from socket");
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_trace("TCP stub server: successfully read correct message");
    else
        oops_error("TCP stub server: readmsg differed from expected");
    
    // Close the fd
    pthread_cleanup_pop(1);
    
    // Free the thread context
    pthread_cleanup_pop(1);
    return 0;
}

static pthread_t tcpstub_server_writer_reader(int server_socket,
                                      const char *writemsg,
                                      const char *readmsg)
{
    tcpstub_server_write_context* c = calloc(1,sizeof(tcpstub_server_write_context));
    c->server_socket = server_socket;
    c->readmsg = readmsg;
    c->writemsg = writemsg;
    pthread_t thread;
    pthread_create(&thread, NULL, tcpstub_server_write_inner, c)==0 || oops_error("pthread_create failed");
    return thread;
}

static int tcpstub_client_writer_reader_connect(const char* ip, const char* port)
{        
    for(int tries_left=0; tries_left<100; tries_left++) {
        tcpclient_options options = {
            .OPT_TCP_NODELAY = 1,
            .OPT_CONNECT_TIMEOUT = 10000
        };
            
        int tcpclient = tcpclient_new(ip, port, options);
        
        // If connection was refused, try to connect again
        if(tcpclient<0 && errno == ECONNREFUSED) {
            log_info("connection refused (to %s:%s), trying again...", ip, port);
            usleep(50000);
            errno = 0;
            continue;
        }
        // Any other error is test failure
        if(tcpclient<0)
            return oops_warn_sys("failed to establish TCP connection");
        
        log_trace("TCP stub client: connection succeeded (to %s:%s).", ip, port);
        return tcpclient;
    }
    return oops_warn("failed to connect too many times");
}

static void tcpstub_client_writer_reader(const char* ip, const char* port, const char* writemsg, const char* readmsg)
{
    char actual_readmsg[512] = {0};
    
    // Create a TCP client
    int tcpclient = tcpstub_client_writer_reader_connect(ip,port);
    if(tcpclient<0) return;

    // Create a cleanup handler to close the fd
    pthread_cleanup_push(cleanup_close, &tcpclient);
    
    // ---- Read a message ----
    int rlen = (int)strlen(readmsg);
    log_trace("TCP stub client: reading %d bytes.",rlen);
    int rrc = (int)readn(tcpclient, actual_readmsg, rlen);
    if(rrc<0) oops_error_sys("failed to read");
    if(rrc != rlen) { log_error("TCP stub client: partial read (%d/%d)", rrc, rlen); exit(1); }
    log_trace("TCP stub client: read %d bytes from connection", rrc);
    
    // ---- Write a message ----
    int wlen = (int)strlen(writemsg);
    log_trace("TCP stub client: writing %d bytes.",wlen);
    int wrc = (int)writen(tcpclient, writemsg, wlen);
    if(wrc<0) oops_error_sys("failed to write");
    if(wrc != wlen) { log_error("partial write (%d/%d)", wrc, wlen); exit(1); }
    log_trace("TCP stub client: wrote %d bytes to connection", wlen);
    
    // ---- Signal EOF ----
    if(shutdown(tcpclient, SHUT_WR)<0)
        oops_error_sys("failed to shutdown");
    
    // ---- Receive EOF ----
    if(read(tcpclient, actual_readmsg, rlen)!=0)
        oops_error_sys("expected EOF from socket");

    log_trace("TCP stub client: connection succeeded");
    
    // Assert that what we read is valid
    if(strcmp(actual_readmsg,readmsg)==0)
        log_trace("TCP stub client: successfully read correct message");
    else
        oops_error("TCP stub client: readmsg differed from expected");

    // Close the fd
    pthread_cleanup_pop(1);
}

// TCP Server test
void saltunnel_tcp_forwarder_tests() {

    cache_clear(&table);

    // Create a TCP server
    tcpserver_options options = {
    .OPT_TCP_NODELAY = 1,
    .OPT_SO_REUSEADDR = 1
    };
    int server_writer_socket = tcpserver_new("127.0.0.1", "3270", options);
    if(server_writer_socket<0)
        oops_error("failed to create TCP server");
    
    // Server Stub Thread:
    pthread_t thread1 = tcpstub_server_writer_reader(server_writer_socket,
                        "this string from TCP server stub to client stub.",
                        "this string from TCP client stub to server stub");
    
    // Server Forwarder Thread:
    pthread_t thread2 = saltunnel_forwarder_thread(1, "127.0.0.1", "3260", "127.0.0.1", "3270");

    // Client Forwarder Thread:
    pthread_t thread3 = saltunnel_forwarder_thread(0, "127.0.0.1", "3250", "127.0.0.1", "3260");
    
    // Client Stub:
    tcpstub_client_writer_reader("127.0.0.1", "3250",
                                "this string from TCP client stub to server stub",
                                "this string from TCP server stub to client stub.");
    log_info("----tcp_forwarder_test succeeded; exiting child process...----");

    // Join with the server stub
    pthread_join(thread1, NULL);
    pthread_cancel(thread2);
    pthread_cancel(thread3);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);

    if(close(server_writer_socket)<0) oops_error_sys("failed to close socket");

    cache_clear(&table);
    
}
