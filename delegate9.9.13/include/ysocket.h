#ifndef _YSOCKET_H
#define _YSOCKET_H

#ifdef _MSC_VER
#include <winsock2.h> /* for fd_set */
#include "ywinsock.h"
#endif

typedef struct sockaddr *_SAP;
int _SOCKET(int,int,int);
int _BIND(int,_SAP,int);
int _LISTEN(int,int);
int _ACCEPT(int,_SAP,int*);
int _CONNECT(int,const _SAP,int);
int _SENDTO(int,const void*,unsigned int,int,_SAP,unsigned int);
int _RECVFROM(int,void*,unsigned int,int,_SAP,int*);
int _SEND(int,const void*,unsigned int,int);
int _RECV(int,void*,unsigned int,int);
int _GETSOCKOPT(int,int,int,void *,int*);
int _SETSOCKOPT(int,int,int,const void *,int);
int _SELECT(int,fd_set*,fd_set*,fd_set*,struct timeval*);
int _GETHOSTNAME(char*,unsigned int);
int _SHUTDOWN(int,int);

#ifdef __APPLE__
int recvDarwin(int s,void *b,int l,int f,FL_PAR);
#define recv(s,b,l,f) recvDarwin(s,b,l,f,FL_ARG)
#endif

#define STD_HOSTENT
#define gethostbyname	_GETHOSTBYNAME
#define gethostbyaddr	_GETHOSTBYADDR


#ifdef _MSC_VER

int _GETSOCKNAME(int s,_SAP,int *l);
int _GETPEERNAME(int s,_SAP,int *l);


/*
#define socket		_SOCKET
*/
#define bind		_BIND
#define listen		_LISTEN
/*
#define accept		_ACCEPT
*/
#define connect		_CONNECT
#define shutdown	_SHUTDOWN

#define select		_SELECT

#define send		_SEND
#define recv		_RECV
#define sendto		_SENDTO
#define recvfrom	_RECVFROM

#define getsockname	_GETSOCKNAME
#define getpeername	_GETPEERNAME

#define setsockopt	_SETSOCKOPT
#define getsockopt	_GETSOCKOPT

#define gethostname	_GETHOSTNAME
#else /* !_MSC_VER */

#define bind(s,a,l)	_BIND(s,a,l)
#define accept(s,a,l)	_ACCEPT(s,a,l)
#define connect(s,a,l)	_CONNECT(s,a,l)

#endif /* _MSC_VER */

#define PS_IN     001
#define PS_PRI    002
#define PS_OUT    004
#define PS_ERR    010
#define PS_HUP    020
#define PS_NVAL   040
#define PS_ERRORS 070

#endif /* _YSOCKET_H */
