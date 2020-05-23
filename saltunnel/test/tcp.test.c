//
//  tcp.test.c
//  saltunnel-test
//

#include "tcp.test.h"
#include "tcpserver.h"
#include "tcpclient.h"
#include "oops.h"
#include "rwn.h"

#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>

static void exchange_server(int server_conn) {
    // Write a byte
    if(writen(server_conn, "s", 1)<0) oops_error_sys("failed to write a byte to server_conn");
    // Read a byte
    char tmp = -1;
    if(readn(server_conn, &tmp, 1)<0) oops_error_sys("failed to read a byte from server_conn");
    if(tmp!='c') oops_error_sys("read wrong byte from server_conn");
    // Close
    if(shutdown(server_conn, SHUT_WR)<0) oops_error_sys("failed to close server_conn");
    // Read EOF marker
    if(read(server_conn, &tmp, 1)!=0) oops_error_sys("failed to read EOF from server_conn");
}

static void exchange_client(int client_conn) {
    // Write a byte
    if(writen(client_conn, "c", 1)<0) oops_error_sys("failed to write a byte to client_conn");
    // Read a byte
    char tmp = -1;
    if(readn(client_conn, &tmp, 1)<0) oops_error_sys("failed to read a byte from client_conn");
    if(tmp!='s') oops_error_sys("read wrong byte from client_conn");
    // Close
    if(shutdown(client_conn, SHUT_WR)<0) oops_error_sys("failed to close client_conn");
    // Read EOF marker
    if(read(client_conn, &tmp, 1)!=0) oops_error_sys("failed to read EOF from client_conn");
}

static void* tcpserver_test_thread(void* v) {
    // Extract the Server Socket
    int server_socket = *(int*)(v);
    // Listen for Connection
    int conn = tcpserver_accept(server_socket);
    // Exchange
    exchange_server(conn);
    // Close Server Socket (client was already closed);
    if(close(server_socket)<0) oops_error_sys("failed to close server socket");
    return 0;
}

static void tcp_test_happy_path() {
    // Create TCP server
    tcpserver_options server_options = { .OPT_TCP_NODELAY = 1, .OPT_SO_REUSEADDR = 1 };
    int server_socket = tcpserver_new("127.0.0.1", "11625", server_options);
    if(server_socket<0) oops_error_sys("failed to listen to 127.0.0.1:11625");
    
    // Listen for connections and Perform Server-Side Test (in separate thread)
    pthread_t serverthread;
    pthread_create(&serverthread, NULL, tcpserver_test_thread, &server_socket)==0 || oops_error_sys("pthread_create failed");
    
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 500 };
    int client_socket = tcpclient_new("127.0.0.1", "11625", client_options);
    if(client_socket<0) oops_error_sys("failed to listen to connect to 127.0.0.1:11625");
    
    // Perform Client-Side Test
    exchange_client(client_socket);
    
    // Wait for server thread to complete
    pthread_join(serverthread, 0);
    
}


static void tcp_test_connect_to_unused_port() {
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 500 };
    oops_should_warn();
    int client_socket = tcpclient_new("127.0.0.1", "11625", client_options);
    oops_should_error();
    if( !(client_socket<0 && errno==ECONNREFUSED) ) oops_error("expected 'Connection refused'");
    else log_warn("(the above warning is normal and expected during this test)");
}

static void tcp_test_connect_to_bad_ip() {
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 500 };
    oops_should_warn();
    int client_socket = tcpclient_new("192.0.2.0", "11625", client_options);
    oops_should_error();
    if( !(client_socket<0 && errno==ETIMEDOUT) ) oops_error("expected 'Operation timed out'");
    else log_warn("(the above warning is normal and expected during this test)");
}

void tcp_tests() {
    tcp_test_happy_path();
    tcp_test_connect_to_unused_port();
    tcp_test_connect_to_bad_ip();
}
    
