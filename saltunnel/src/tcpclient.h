//
//  tcpclient.h
//  saltunnel
//

#ifndef tcpclient_h
#define tcpclient_h

#define BOOL int
typedef struct tcpclient_options {
    // Boolean Parameters (0 or 1)
    int OPT_TCP_NODELAY : 1;
    int OPT_TCP_FASTOPEN : 1;
    int OPT_NONBLOCK : 1;
    // Valued Parameters
    unsigned short OPT_SO_SNDLOWAT;
    unsigned int OPT_CONNECT_TIMEOUT;
} tcpclient_options;

int tcpclient_new(const char* ip, const char* port, tcpclient_options options);

#endif /* tcpclient_h */
