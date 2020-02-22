//
//  tcpserver.h
//  saltunnel
//

#ifndef tcpserver_h
#define tcpserver_h

typedef struct tcpserver_options {
    // Boolean Parameters (0 or 1)
    char OPT_TCP_NODELAY;
    char OPT_SO_REUSEADDR;
    char OPT_TCP_DEFER_ACCEPT;
    char OPT_TCP_FASTOPEN;
    char OPT_NONBLOCK;
    // Valued Parameters
    unsigned short OPT_SO_RCVLOWAT;
} tcpserver_options;

int tcpserver_new(const char* ip, const char* port, tcpserver_options options);
int tcpserver_accept(int s);
int tcpserver_accept_nonblock(int s);

#endif /* tcpserver_h */
