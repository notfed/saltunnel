//
//  tcp.test.c
//  saltunnel-test
//

#include "tcp.test.h"
#include "tcpserver.h"
#include "tcpclient.h"
#include "oops.h"
#include "rwn.h"

#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>

static void exchange_server(int server_conn) {
    // Write a byte
    assert(writen(server_conn, "s", 1)==1);
    // Read a byte
    char tmp = -1;
    assert(readn(server_conn, &tmp, 1)==1);
    assert(tmp=='c');
    // Close
    assert(shutdown(server_conn, SHUT_WR)==0);
    // Read EOF marker
    assert(read(server_conn, &tmp, 1)==0);
    assert(close(server_conn)==0);
}

static void exchange_client(int client_conn) {
    // Write a byte
    assert(writen(client_conn, "c", 1)==1);
    // Read a byte
    char tmp = -1;
    assert(readn(client_conn, &tmp, 1)==1);
    assert(tmp=='s');
    // Close
    assert(shutdown(client_conn, SHUT_WR)==0);
    // Read EOF marker
    assert(read(client_conn, &tmp, 1)==0);
    assert(close(client_conn)==0);
}

static void* tcpserver_test_thread(void* v) {
    // Extract the Server Socket
    int server_socket = *(int*)(v);
    // Listen for Connection
    tcpserver_options server_options = {0};
    int conn = tcpserver_accept(server_socket, server_options);
    // Exchange
    exchange_server(conn);
    // Close Server Socket (client was already closed);
    assert(close(server_socket)==0);
    return 0;
}

static void tcp_test_happy_path(const char* hostname) {
    // Create TCP server
    tcpserver_options server_options = { .OPT_TCP_NODELAY = 1, .OPT_SO_REUSEADDR = 1 };
    int server_socket = tcpserver_new("127.0.0.1", "11625", server_options);
    if(server_socket<0) oops_error_sys("failed to listen to 127.0.0.1:11625");
    
    // Listen for connections and Perform Server-Side Test (in separate thread)
    pthread_t serverthread;
    assert(pthread_create(&serverthread, NULL, tcpserver_test_thread, &server_socket)==0);
    
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 25 };
    if(hostname==NULL)
        hostname = "127.0.0.1";
    int client_socket = tcpclient_new(hostname, "11625", client_options);
    if(client_socket<0) oops_error_sys("failed to connect to 127.0.0.1:11625");
    
    // Perform Client-Side Test
    exchange_client(client_socket);
    
    // Wait for server thread to complete
    pthread_join(serverthread, 0);
    
}

static void tcp_test_happy_path_with_127_0_0_1() {
    tcp_test_happy_path("127.0.0.1");
}

static void tcp_test_happy_path_with_localhost() {
    tcp_test_happy_path("localhost");
}

static void tcp_test_connect_to_invalid_hostname() {
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 300 };
    int client_socket = tcpclient_new("hopefully_this_isnt_a_real_hostname", "11625", client_options);
    if(client_socket<0 && errno!=EHOSTUNREACH) oops_error("expected 'Unknown host'");
    else oops_warn("(the above warning is normal and expected during this test)");
}

static void tcp_test_connect_to_bad_subnet() {
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 300 };
    int client_socket = tcpclient_new("192.0.2.0", "11625", client_options);
    if(client_socket<0 && errno!=ETIMEDOUT && errno!=EHOSTUNREACH && errno!=ENETUNREACH)
      oops_error_sys("expected 'Operation timed out' or 'Network is unreachable'");
    else  log_warn("(the above warning is normal and expected during this test)");
}

static void tcp_test_connect_to_unused_port() {
    // Create TCP client
    tcpclient_options client_options = { .OPT_TCP_NODELAY = 1, .OPT_CONNECT_TIMEOUT = 300 };
    int client_socket = tcpclient_new("127.0.0.1", "47", client_options); // NOTE: Assumes port 47 is never used
    if(client_socket<0 && errno!=ECONNREFUSED) oops_error("expected 'Connection refused'");
    else log_warn("(the above warning is normal and expected during this test)");
}

void tcp_tests() {
    tcp_test_happy_path_with_127_0_0_1();
    tcp_test_happy_path_with_localhost();
    tcp_test_connect_to_invalid_hostname(); // TODO
    tcp_test_connect_to_bad_subnet();
    tcp_test_connect_to_unused_port();
}
    
