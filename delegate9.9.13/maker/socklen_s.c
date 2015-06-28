/*
#define _YSOCKET_H   // don't include ysocket.h in vsocket.h
#include "vsocket.h"
*/
#include <sys/types.h>
#include <sys/socket.h>
#define X_SA struct sockaddr

#ifndef X_SAL
#if defined(__hpux__) && defined(_XOPEN_SOURCE_EXTENDED)
#define X_SAL socklen_t
#else
#define X_SAL int
#endif
#endif

int Xgetsockopt(int s,int e,int n,void *v,int *l){
	X_SAL rl; int code;
	rl = *l; code = getsockopt(s,e,n,(char*)v,&rl);
	*l = rl; return code;
}
int Xgetsockname(int s,X_SA *a,int *l){
	X_SAL rl; int code;
	rl = *l; code = getsockname(s,a,&rl);
	*l = rl; return code;
}
int Xgetpeername(int s,X_SA *a,int *l){
	X_SAL rl; int code;
	rl = *l; code = getpeername(s,a,&rl);
	*l = rl; return code;
}
int Xaccept(int s,X_SA *a,int *l){
	X_SAL rl; int code;
	rl = *l; code = accept(s,a,&rl);
	*l = rl; return code;
}
int Xrecvfrom(int s,void *b,size_t z,int f,X_SA *a,int *l){
	X_SAL rl; int code;
	rl = *l; code = recvfrom(s,(char*)b,z,f,a,&rl);
	*l = rl; return code;
}
