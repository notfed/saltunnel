//
//  tcpclient.h
//  saltunnel
//

#ifndef tcpclient_h
#define tcpclient_h

#define BOOL int
typedef struct tcpclient_options {
    // Boolean Parameters (0 or 1)
    char OPT_TCP_NODELAY;
    char OPT_TCP_FASTOPEN;
    char OPT_NONBLOCK;
    // Valued Parameters
    unsigned short OPT_SO_SNDLOWAT;
} tcpclient_options;

int tcpclient_new(const char* ip, const char* port, tcpclient_options options);

#endif /* tcpclient_h */
