//
//  main.c
//  saltunnel2
//

#include "oops.h"
#include "test.h"
#include "threadpool.h"
#include <stdio.h>
#include <errno.h>

#include <unistd.h>

int main(int argc, const char * argv[]) {
    threadpool_init(&tp1);
    threadpool_init(&tp2);
    test();
    threadpool_shutdown(&tp1);
    threadpool_shutdown(&tp2);
    return 0;
}
