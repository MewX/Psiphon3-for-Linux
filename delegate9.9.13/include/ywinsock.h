#ifndef FD_SETSIZE
#if UNDER_CE
#define FD_SETSIZE	64
#else
#define FD_SETSIZE	256
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

struct hostent *gethostbyname2(const char *name,int af);
int Inet_pton(int af,const char *src,void *dst);
#define inet_pton(af,src,dst) Inet_pton(af,src,dst)
