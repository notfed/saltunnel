//
//  oops.h
//  saltunnel2
//

#ifndef oops_h
#define oops_h

#define try(rc) (rc>=0)

int oops_fatal(char*);
int oops_warn(char*);

#endif /* oops_h */
