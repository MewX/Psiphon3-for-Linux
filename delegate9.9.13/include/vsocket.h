#ifndef _VSOCKET_H
#define _VSOCKET_H

#include "ystring.h"

typedef unsigned /* long -- bad for DEC-ALPHA */ INETADDRV4;
extern INETADDRV4 _inet_addrV4(PCStr(addr));
#define INADDR_None	((INETADDRV4)-1)
#define inet_addrV4(a)	_inet_addrV4(a)
#define inet_ntoaV4I(i)	_inet_ntoaV4I(i)

int xinet_pton(int af,const char *src,void *dst);

#ifdef _MSC_VER /*{*/
#include "ywinsock.h"
#include "ysocket.h"
#define SELF_AF_UNIX
#define SELF_RESOLV_H

#ifndef EISCONN /*{*/
#define EISCONN		WSAEISCONN
#define EALREADY	WSAEALREADY
#define EMSGSIZE	WSAEMSGSIZE
#define EWOULDBLOCK	WSAEWOULDBLOCK
#define EINPROGRESS	WSAEINPROGRESS
#define ECONNREFUSED	WSAECONNREFUSED
#ifndef EFAULT
#define EFAULT		WSAEFAULT
#endif
#define ENETUNREACH	WSAENETUNREACH
#define EHOSTUNREACH	WSAEHOSTUNREACH
#define ETIMEDOUT	WSAETIMEDOUT
#define EADDRNOTAVAIL	WSAEADDRNOTAVAIL
#define EADDRINUSE	WSAEADDRINUSE
#endif /*}*/

#else /*}else (UNIX){*/

#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
/*
#ifdef __osf__
*/
#if defined(__osf__) || defined(sun)
#define gethostbyname2(name,af) ((af==AF_INET)?gethostbyname(name):NULL)
#define WITHOUT_GETHOSTBYNAME2 1
#endif

#ifdef __EMX__ /*{*/
#define TCPIPV4
#ifndef MAXSOCKETS
#define MAXSOCKETS 2048
#endif
#define SELECT_WIDTH(fd)	(fd+3)
#endif /*}*/


#if defined(__CYGWIN__) || defined(__MINGW32__) /*{*/
#define SO_SNDBUF	0x1001
#define SO_RCVBUF	0x1002
#define SO_TYPE		0x1008
#define SELF_AF_UNIX
#define SELF_RESOLV_H
#else /*}{*/
#ifndef IPPROTO_TCP
#include <sys/param.h>
#endif
#endif /*}*/

#include <sys/time.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include "ysocket.h" /* must be after <sys/socket.h> */

#ifdef NeXT
#include <netinet/in_systm.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#if !(defined(__CYGWIN__) || defined(__MINGW32__))
#include <netinet/tcp.h>
#include <sys/un.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif

/*#######################################################*/
int Xgetsockopt(int,int,int,void*,int*);
int Xgetsockname(int,struct sockaddr*,int*);
int Xgetpeername(int,struct sockaddr*,int*);
int Xrecvfrom(int,void*,size_t,int,struct sockaddr*,int*);
int Xaccept(int s,struct sockaddr *a,int *l);

#define getsockopt	Xgetsockopt
#define getsockname	Xgetsockname
#define getpeername	Xgetpeername
#define recvfrom	Xrecvfrom
/*#######################################################*/

#endif /* } _MSC_VER */

#ifdef SELF_AF_UNIX
struct sockaddr_un {
	short	sun_family;	/* AF_UNIX */
	char	sun_path[108];	/* path name */
};
#endif

#if defined(AF_INET6) && !defined(IPPROTO_IPV6) \
 && defined(__linux__) /* RedHat6 */
#define IPPROTO_IPV6  IPPROTO_IPV6  /* defined only in enum */
#define sin6_scope_id sin6_flowinfo /* without scope_id */
#endif

#if !defined(_MSC_VER) || _MSC_VER < 1400 /* before VC2005 {*/
/*
#if !defined(AF_INET6) || !defined(IPPROTO_IPV6)
*/
#if !defined(AF_INET6) || !defined(IPPROTO_IPV6) || !defined(NI_NUMERICHOST)
#ifndef AF_INET6
#define AF_INET6 ((unsigned int)-6)
#endif
struct in6_addr {
	unsigned char addr8[16];
};

/* "sin6_family" might be "short" in sockaddr_in for IPv4
 * without "sin_len", so it should be not be referred for portability
 */
struct sockaddr_in6 { 
	unsigned char   sin6_len;
	unsigned char   sin6_family;
	unsigned short  sin6_port;
	unsigned int    sin6_flowinfo;
	struct in6_addr sin6_addr;
	unsigned int    sin6_scope_id;
}; 
struct addrinfo {
	int	ai_flags;
	int	ai_family;
	int	ai_socktype;
	int	ai_protocol;
   unsigned int	ai_addrlen;
	char	*ai_canonname;
struct sockaddr *ai_addr;
struct addrinfo *ai_next;
};
#define gethostbyname2(name,af) ((af==AF_INET)?gethostbyname(name):NULL)
#define WITHOUT_GETHOSTBYNAME2 2
#define inet_pton(af,src,dst) -1
#define inet_ntop(af,src,dst,siz) NULL
#define getaddrinfo(host,serv,hint,res) -1
#define getnameinfo(sa,salen,host,hlen,serv,slen,flags) -1
#define freeaddrinfo(ai) -1
#define AI_NUMERICHOST 4
#define IPPROTO_IPV6 41
#define NI_NUMERICHOST 1 /* 2 on BSD, but ignored anyway */
#endif

#endif /*}*/

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY -1
#endif

struct hostent *EX_GETHOSTBYNAME(PCStr(name));         /* system's standard resolver */
struct hostent *EX_GETHOSTBYADDR(PCStr(addr),int,int); /* system's standard resolver */
struct hostent *_GETHOSTBYNAME(PCStr(name));         /* resolvy */
struct hostent *_GETHOSTBYADDR(PCStr(addr),int,int); /* resolvy */

#ifdef SELF_RESOLV_H
#ifndef _RESOLV_H_
#define	_RESOLV_H_

#define MAXDNAME 		128
#define	MAXNS			3
#define	MAXDFLSRCH		3
#define	MAXDNSRCH		6
#define	LOCALDOMAINPARTS	2
#define	RES_TIMEOUT		5
#define	MAXRESOLVSORT		10
#define	RES_MAXNDOTS		15

typedef struct sockaddr_in _SIN;

struct state {
	long	options;
	int	nscount;
	_SIN	nsaddr_list[MAXNS];
	char   *dnsrch[MAXDNSRCH+1];
	char	defdname[MAXDNAME];
};

#define RES_INIT	0x00000001
#define RES_DEBUG	0x00000002
#define RES_RECURSE	0x00000040
#define RES_DEFNAMES	0x00000080
#define RES_DNSRCH	0x00000200

#endif /* !_RESOLV_H */
#endif /* _SELF_RESOLV_H */
#endif /* _VSOCKET_H */


#ifndef SELECT_WIDTH
#define SELECT_WIDTH(fd)	(fd+1)
#endif


#include <errno.h>
#ifndef EISCONN
#define EISCONN		-101
#endif
#ifndef EINPROGRESS
#define EINPROGRESS	-102
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED	-103
#endif
#ifndef ENETUNREACH
#define ENETUNREACH	-104
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH	-105
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT	-106
#endif
#ifndef EADDRINUSE
#define EADDRINUSE	-107
#endif
#ifndef EACCES
#define EACCES		-108
#endif
#ifndef ECONNRESET
#define ECONNRESET	-109
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK	-110
#endif
#ifndef EFAULT
#define EFAULT		-111
#endif

#ifndef _VADDR_H
#ifndef _VSADDR_DEFINED_
#define _VSADDR_DEFINED_
typedef union {
struct sockaddr	_sa;
	int	_sab[32]; /* enough size to hold sockaddr_un */
} VSAddr;
#endif
#endif

typedef struct sockaddr *SAP;
#define IPV6_ADDRLENG	20

int   VSA_afunix(VSAddr *sap,PVStr(host),int size);
int   VSA_addrisANY(VSAddr *sap);
int   VSA_addr(VSAddr *sap);
int   VSA_addrX(VSAddr *sap,unsigned int ap[4]);
int   VSA_cto_(char addr[]);
int   VSA_getsockname(VSAddr *vsa,int sock);
int   VSA_getpeername(VSAddr *vsa,int sock);
const char *VSA_ntoa(VSAddr *sap);
const char *VSA_htoa(struct hostent *hp);
const char *VSA_ltoa(const unsigned char *addr,int len,int type);
int   VSA_aptosa(VSAddr *sa,PCStr(addrport));
int   VSA_satoap(VSAddr *sa,PVStr(addrport));
int   VSA_port(VSAddr *sap);
char *VSA_xtoap(VSAddr *sa,PVStr(buf),int siz);
int   VSA_strisaddr(PCStr(addr));
int   VSA_isaddr(VSAddr *sap);
int   VSA_stosa(VSAddr *sap,int atype,PCStr(socks));
int   VSA_btosa(VSAddr *sap,int atype,unsigned char *baddr,int port);
void  VSA_setport(VSAddr *sap,int port);
int   VSA_atosa(VSAddr *sa,int port,PCStr(addr));
int   VSA_htosa(VSAddr *sap,int port,struct hostent *hp,int hi);
int   VSA_size(VSAddr *sap);
int   VSA_comp(VSAddr *vsa1,VSAddr *vsa2);
int   VSA_atob(PCStr(aaddr),PVStr(baddrb),int *btypep);
int   VSA_decomp(VSAddr *sap,const char **baddr,int *btype,const char **bport);
int   VSA_islocal(VSAddr *vsa);
int   VSA_6to4(VSAddr *vsa);
int   VSA_addrcomp(VSAddr *vsa1,VSAddr *vsa2);
void  VSA_addrcopy(VSAddr *dst,VSAddr *src);
void  VSA_prftp(VSAddr *sap,PVStr(mport));
void  VSA_ftptosa(void *sap,PCStr(port));
int   VSA_dnstosa(void *sap,int port,PCStr(revaddr));
void  VSA_zero(VSAddr *sap);
const char *VSA_hostlocal();
int   isinetAddr(PCStr(saddr));
int   sock_isv6(int sock);
int   VSA_af(VSAddr *sap);

int   SOCKS_recvfrom(int sock,PVStr(buf),int len,int flags,SAP from,int *fromlen);
int   SOCKS_sendto(int sock,PCStr(buf),int len,int flags,SAP to,int tolen);
void  SOCKS_udpclose(int msock);

int   socks_addservers();
int   SOCKS_udpassoc(int msock,VSAddr *me,VSAddr *rme);
int   SOCKS_udpassocsock(int sock,PCStr(lhost),int lport,PVStr(rhost),int *rport);
int   RecvFrom(int sock,char buf[],int len,PVStr(froma),int *fromp);
int   SendTo(int sock,PCStr(buf),int len,PCStr(host),int port);

#include "dgctx.h"
int   GetViaSocks(DGCTX,PCStr(host),int port);
int   acceptViaSocks(int sock,PVStr(rhost),int *rport);
int   bindViaSocks(DGCTX,PCStr(dsthost),int dstport,PVStr(rhost),int *rport);
int   ConnectViaYYMUX(DGCTX,void *cty,int relay_input);
int   ConnectViaSocks(DGCTX,int relay_input);
int   connectViaSocks(DGCTX,PCStr(dsthost),int dstport,PVStr(rhost),int *rport);
int   connectViaSocksX(DGCTX,PCStr(skhost),int skport,PCStr(opts),PCStr(dsthost),int dstport);

int   SocketOf(int fd);
int   VSocket(DGCTX,PCStr(command),int sock,PVStr(local),PVStr(remote),PCStr(options));
