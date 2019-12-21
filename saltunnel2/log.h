//
//  log.h
//  saltunnel2
//

#ifndef log_h
#define log_h

#include <stdio.h>
 
#define LOG_0(level)               !error
#define LOG_1(level,x1)             fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: %s\n", __LINE__, x1)
#define LOG_2(level,x1,x2)          fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2)
#define LOG_3(level,x1,x2,x3)       fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3)
#define LOG_4(level,x1,x2,x3,x4)    fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4)
#define LOG_5(level,x1,x2,x3,x4,x5) fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4, x5)
#define LOG_6(level,x1,x2,x3,x4,x5) fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4, x5, x6)
#define LOG_7(level,x1,x2,x3,x4,x5) fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4, x5, x6, x7)
#define LOG_8(level,x1,x2,x3,x4,x5) fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4, x5, x6, x7, x8)
#define LOG_9(level,x1,x2,x3,x4,x5) fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4, x5, x6, x7, x8, x9)
#define LOG_10(level,x1,x2,x3,x4,x5) fprintf(stderr, "saltunnel: " level ": " __FILE_NAME__ ":%d: " x1 "\n", __LINE__, x2, x3, x4, x5, x6, x7, x8, x10)
 
#define FUNC_CHOOSER(_f1, _f2, _f3, _f4, _f5, _f6, _f7, _f8, _f9, _f10, _f11, ...) _f11
#define FUNC_RECOMPOSER(argsWithParentheses) FUNC_CHOOSER argsWithParentheses
#define CHOOSE_FROM_ARG_COUNT(...) FUNC_RECOMPOSER((__VA_ARGS__, LOG_10, LOG_9, LOG_8, LOG_7, LOG_6, LOG_5, LOG_4, LOG_3, LOG_2, LOG_1, ))
#define NO_ARG_EXPANDER() ,,,,,LOG_0
#define MACRO_CHOOSER(...) CHOOSE_FROM_ARG_COUNT(NO_ARG_EXPANDER __VA_ARGS__ ())

#define log_debug(...) MACRO_CHOOSER(__VA_ARGS__)("debug",__VA_ARGS__)
#define log_info(...) MACRO_CHOOSER(__VA_ARGS__)("info",__VA_ARGS__)
#define log_warn(...) MACRO_CHOOSER(__VA_ARGS__)("warn",__VA_ARGS__)
#define log_fatal(...) MACRO_CHOOSER(__VA_ARGS__)("fatal",__VA_ARGS__)

#endif /* log_h */
