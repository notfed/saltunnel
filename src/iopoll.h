//
//  iopoll.h
//  saltunnel
//
//  Encapsulates (a minimal number of features of) kqueue and epoll.
//

#ifndef iopoll_h
#define iopoll_h

#ifdef __linux__
#define HAS_EPOLL
#else
#define HAS_KQUEUE
#endif

#ifdef HAS_KQUEUE
#include <sys/event.h>
typedef struct kevent iopoll_event;
#else
#include <sys/epoll.h>
typedef struct epoll_event iopoll_event;
#endif

int iopoll_create(void);
int iopoll_add(int epollfd, int fd_to_add, void* data);
int iopoll_add_oneshot(int epollfd, int fd_to_add, void* data);
int iopoll_delete(int epollfd, int fd_to_remove);
int iopoll_wait(int q, iopoll_event* eventlist, int eventlist_count, int timeout_ms);
void* iopoll_event_get_data(iopoll_event* e);
int iopoll_event_did_error(iopoll_event* e);

#endif /* iopoll_h */
