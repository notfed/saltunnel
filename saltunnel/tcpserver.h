//
//  tcpserver.h
//  saltunnel
//

#ifndef tcpserver_h
#define tcpserver_h

typedef struct tcpserver_options {
    // Boolean Parameters (0 or 1)
    int OPT_TCP_NODELAY : 1;
    int OPT_SO_REUSEADDR : 1;
    int OPT_TCP_DEFER_ACCEPT : 1;
    int OPT_TCP_FASTOPEN : 1;
    int OPT_NONBLOCK : 1;
    // Valued Parameters
    unsigned short OPT_SO_RCVLOWAT;
} tcpserver_options;

int tcpserver_new(const char* ip, const char* port, tcpserver_options options);
int tcpserver_accept(int s);
int tcpserver_accept_nonblock(int s);

#endif /* tcpserver_h */
