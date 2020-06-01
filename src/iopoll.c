//
//  saltunnel_tcp_server_forwarder_kqueue.c
//  saltunnel
//

#include "iopoll.h"

#include <time.h>

#ifdef HAS_KQUEUE

int iopoll_create() {
    return kqueue();
}

int iopoll_add(int kq, int fd_to_add, void* data) {
    struct kevent event;
    EV_SET(&event, fd_to_add, EVFILT_READ, EV_ADD, 0, 0, data);
    return kevent(kq, &event, 1, 0, 0, 0);
    
}

int iopoll_add_oneshot(int kq, int fd_to_add, void* data) {
    struct kevent event;
    EV_SET(&event, fd_to_add, EVFILT_READ, EV_ADD|EV_ONESHOT, 0, 0, data);
    return kevent(kq, &event, 1, 0, 0, 0);
}

int iopoll_delete(int kq, int fd_to_remove) {
    struct kevent event;
    EV_SET(&event, fd_to_remove, EVFILT_READ, EV_DELETE, 0, 0, 0);
    return kevent(kq, &event, 1, 0, 0, 0);
}

int iopoll_wait(int kq, iopoll_event* eventlist, int eventlist_count, int timeout_ms) {
    struct timespec timeout_ts = {
        .tv_sec = (timeout_ms+1) / 1000,
        .tv_nsec = ((timeout_ms+1) % 1000) * 1000000
    };
    return kevent(kq, 0, 0, eventlist, eventlist_count, (timeout_ms>=0 ? &timeout_ts : 0));
}

void* iopoll_event_get_data(iopoll_event* e) {
    return e->udata;
}

int iopoll_event_did_error(iopoll_event* e) {
    return e->flags & EV_ERROR;
}

#else /* HAS_KQUEUE */

int iopoll_create() {
    return epoll_create1(EPOLL_CLOEXEC);
}

int iopoll_add(int epollfd, int fd_to_add, void* data) {
    struct epoll_event register_connection_read_event = { .events = EPOLLIN, .data = { .ptr = data } };
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd_to_add, &register_connection_read_event);
}

int iopoll_add_oneshot(int epollfd, int fd_to_add, void* data) {
    struct epoll_event register_connection_read_event = { .events = EPOLLIN|EPOLLONESHOT, .data = { .ptr = data } };
    return epoll_ctl(epollfd, EPOLL_CTL_ADD, fd_to_add, &register_connection_read_event);
}

int iopoll_delete(int epollfd, int fd_to_remove) {
    struct epoll_event register_connection_read_event = { .events = EPOLLIN };
    return epoll_ctl(epollfd, EPOLL_CTL_DEL, fd_to_remove, &register_connection_read_event);
}

int iopoll_wait(int q, iopoll_event* eventlist, int eventlist_count, int timeout_ms) {
    return epoll_wait(q, eventlist, eventlist_count, timeout_ms);
}

void* iopoll_event_get_data(iopoll_event* e) {
    return e->data.ptr;
}

int iopoll_event_did_error(iopoll_event* e) {
    return e->events & (EPOLLHUP|EPOLLERR);
}

#endif /* HAS_KQUEUE */
