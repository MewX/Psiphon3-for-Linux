/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	inets.c (INET Socket manipulation)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	March94	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "ystring.h"
#include "vsignal.h"
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */
#include "vaddr.h"
#include "dglib.h"
#include "fpoll.h"
#include "file.h"
#include "proc.h"
#include "log.h"

const char *IPV4MAPV6 = "__0";

#define SETsockopt(s,l,o,v,n)	Setsockopt(s,l,o,(char*)v,n)
#define Recvfrom(s,b,z,f,n,l)	recvfrom(s,b,z,f,n,l)

int RES_next_res(PCStr(where),int ri,PVStr(res),PVStr(arg));
int RES_conf(PCStr(path));
int RES_ns(PCStr(nslist));
void RES_af(PCStr(af));
void RES_verify(PCStr(verify));
void RES_roundrobin(PCStr(hosts));
int RES_timeout(int timeout);

char *RES_confidSet_FL(FL_PAR,PCStr(wh),PVStr(prev));
int RES_orderSet_FL(FL_PAR,PCStr(order));
int RES_orderGet_FL(FL_PAR,PVStr(order));
int RES_orderPush_FL(FL_PAR,PCStr(order),int flags);
int RES_orderPop_FL(FL_PAR);

#define RES_confidSet(wh) RES_confidSet_FL(FL_ARG,wh,VStrNULL)
#define RES_orderSet(order) RES_orderSet_FL(FL_ARG,order)
#define RES_orderGet(order) RES_orderGet_FL(FL_ARG,order)
#define RES_orderPush(order,flags) RES_orderPush_FL(FL_ARG,order,flags)
#define RES_orderPop()      RES_orderPop_FL(FL_ARG)
#define RES_ALONE   0
#define RES_ADDLAST 1

int hostlocal2path(PCStr(host),PVStr(path),int size);
void inetNtoa(int addr,PVStr(saddr));
int VSA_comp(VSAddr *vsa1,VSAddr *vsa2);
void inet_itoaV4(int iaddr,PVStr(saddr));
int setsockSHARE(int sock,int onoff);
int connectTOX(int sock,SAP addr,int leng,int timeout,PVStr(cstat));

int server_open_un(PCStr(what),PVStr(path),int nlisten);
int client_open_un(PCStr(what),PCStr(path),int timeout);
int client_open_unX(PCStr(what),int sock,PCStr(path),int timeout);

int ViaVSAPassociator(int sock);
int VSAPgetsockname(DGC*Conn,int rsock,PVStr(sockname));
int CTX_VSAPbind(DGC*Conn,PVStr(sockname),int nlisten);

int fromTunnel(DGC*Conn,int sock);
int connectViaTunnel(DGC*xConn,PCStr(proto),PCStr(host),int port);
int VSA_getViaSocks(DGC*Conn,PCStr(host),int port,VSAddr *vlocal);
int toTunnel(DGC*Conn);
int SRCIFfor(DGC*Conn,PCStr(proto),PCStr(rhost),int rport,PVStr(lhost),int *lport);

#define CONNECT_POLLOUT

#ifdef UNDER_CE
#define NHOSTS 1024 /* single persistent process with slow external cache */
#else
#define NHOSTS 256
#endif
typedef struct {
	int	hc_index;
	int	hc_freeable;
	int	hc_freq;
	int	hc_predef;
	int	hc_predefa; /* address referred in the config. parameters */
	int	hc_mtime;
	int	hc_atime;
	int	hc_shuffled; /* initial shuffling done */
	int	hc_errors;
	int	hc_slide;
	int	hc_shifted;
 struct hostent	hc_hostent;
	int	hc_okngcnt;
	int	hc_conntime;
} Hostent;

#define NIFTO	32
typedef struct {
	VAddr	if_dest;
	VAddr	if_mask;
	VAddr	if_ifto;
} IfTo;

#ifdef NONEMPTYARRAY
#define ie_inets_errmsgBASE	ie_inets_errmsg
#define ie_myFQDN_unknownBASE	ie_myFQDN_unknown
#endif

typedef struct {
	xMStr(	ie_inets_errmsg,1024);
     sigjmp_buf	ie_jmpEnv;
	int	ie_NHosts;
       Hostent *ie_HostsCache[NHOSTS]; /**/
  const	char   *ie_myFQDN;
	xMStr(	ie_myFQDN_unknown,32);
	int	ie_ADDRLIST_RR;
	AMStr(	ie_inAddrs,8,64);
	int	ie_inAddrx;
	FILE   *ie_res_logf;
	int	ie_gotsig;
  const	char   *ie_SRCHOST;
	int	ie_SRCPORT;
	IfTo  **ie_iftoV;
	int	ie_iftoN;
	int	ie_CACHE_ONLY;
	int	ie_HOSTS_PREDEF;
	double	ie_resStart;
	int	ie_REUSE;
	int	ie_REUSEPORT;
	int	ie_SHUTDOWN;
	int	ie_DO_SHUFFLE; /* round-robin in the current implementation */
	int	ie_NO_CONNCTRL;
} InetsEnv;
static InetsEnv *inetsEnv;
#define IE	inetsEnv[0]

#define inets_errmsg	IE.ie_inets_errmsg
/**/
#define jmpEnv		IE.ie_jmpEnv
#define NHosts		IE.ie_NHosts
#define HostsCache	IE.ie_HostsCache
#define myFQDN		IE.ie_myFQDN
#define myFQDN_unknown	IE.ie_myFQDN_unknown
/**/
#define ADDRLIST_RR	IE.ie_ADDRLIST_RR
#define inAddrs		IE.ie_inAddrs
/**/
#define inAddrx		IE.ie_inAddrx
#define res_logf	IE.ie_res_logf
#define gotsig		IE.ie_gotsig
#define SRCHOST		IE.ie_SRCHOST
#define SRCPORT		IE.ie_SRCPORT
#define iftoV		IE.ie_iftoV
#define iftoN		IE.ie_iftoN
#define CACHE_ONLY	IE.ie_CACHE_ONLY
#define HOSTS_PREDEF	IE.ie_HOSTS_PREDEF
#define resStart	IE.ie_resStart
#define REUSE		IE.ie_REUSE
#define REUSEPORT	IE.ie_REUSEPORT
#define SHUTDOWN	IE.ie_SHUTDOWN
#define DO_SHUFFLE	IE.ie_DO_SHUFFLE
#define CONNCTRL	(IE.ie_NO_CONNCTRL == 0)

void minit_inets(){
	if( inetsEnv == 0 ){
		inetsEnv = NewStruct(InetsEnv);
		REUSE = 1;
		SHUTDOWN = 1;
	}
}

int addrIsWildcard(PCStr(addr)){
	if( strcaseeq(addr,"__") ) return 1;
	if( strcaseeq(addr,"0.0.0.0") ) return 1;
	if( strcaseeq(addr,IPV4MAPV6) ) return 1;
	return 0;
}

#undef  sv1log
#define sv1log syslog_ERROR

#define RESOLVERS_SIZ	512

extern struct _resolv_errmsg { defQStr(resolv_errmsg); } resolv_errmsg;

int CTX_defSockOpts(DGC*,PCStr(name),PCStr(spec),int neg);
static scanListFunc conf1(PCStr(conf))
{	const char *name;
	CStr(nameb,32);
	const char *val;
	int neg;

	val = wordscanY(conf,AVStr(nameb),sizeof(nameb),"^:");
	if( *val == ':' )
		val++;
	if( strncasecmp(nameb,"no",2) == 0 ){
		neg = 1;
		name = nameb + 2;
	}else{
		neg = 0;
		name = nameb;
	}
	if( strcaseeq(name,"reuse") ){
		REUSE = !neg;
	}else
	if( strcaseeq(name,"share") ){
		REUSEPORT = !neg;
	}
	else
	if( strcaseeq(name,"shut") ){
		SHUTDOWN = !neg;
	}
	else
	if( strcaseeq(name,"connctrl") ){
		IE.ie_NO_CONNCTRL = neg;
	}
	else{
		CTX_defSockOpts(MainConn(),name,val,neg);
	}
	return 0;
}
int setREUSEADDR(int on)
{	int reuse;

	reuse = REUSE;
	REUSE = on;
	return reuse;
}
void scan_SOCKOPT(DGC*ctx,PCStr(conf))
{
	scan_commaList(conf,0,scanListCall conf1);
}

extern int IPV6_unify4mapped;
int IPV6_v6also = 0;
int IPV6_v4also = 0;
static scanListFunc ipconf1(PCStr(conf))
{	const char *name;
	CStr(nameb,32);
	const char *val;
	int neg;

	val = wordscanY(conf,AVStr(nameb),sizeof(nameb),"^:");
	if( *val == ':' )
		val++;
	if( streq(nameb,"4map") ){
		if( streq(val,"no") )
			IPV6_unify4mapped = 0;
		else	IPV6_unify4mapped = 1;
	}else
	if( streq(nameb,"6also") ){
		if( streq(val,"no") )
			IPV6_v6also = 0;
		else	IPV6_v6also = 1;
	}else
	if( streq(nameb,"4also") ){
		if( streq(val,"no") )
			IPV6_v4also = 0;
		else	IPV6_v4also = 1;
	}
	return 0;
}
void scan_IPV6(DGC*ctx,PCStr(conf))
{
	scan_commaList(conf,0,scanListCall ipconf1);
}


/*###################### LIBRARY BEGIN ################################*/

int getFQDN(PCStr(name),PVStr(fqdn)){
	struct hostent *hp;

	/* SPECIAL HOST NAME IN DeleGate */
	if( strcmp(name,"-")==0 || strcmp(name,"-.-")==0 ){
		Xovstrcpy(AVStr(fqdn),name);
		return 0;
	}
	if( strcmp(name,"localhost") == 0 ){
		Xovstrcpy(AVStr(fqdn),name);
		return 1;
	}
	RES_orderPush("D",RES_ALONE);
	hp = gethostbyname(name);
	RES_orderPop();
	if( hp != NULL ){
		strcpy(fqdn,hp->h_name);
		return 1;
	}
	if( name != fqdn )
		strcpy(fqdn,name);
	return 0;
}
int gethostFQDN(PVStr(fqdn),int size)
{	CStr(host,1024);

	gethostname(host,sizeof(host));
	return getFQDN(host,AVStr(fqdn));
}
void getPrimName(PCStr(host),PVStr(prim))
{	struct hostent *hp;

	/* SPECIAL HOST NAME IN DeleGate */
	if( strcmp(host,"-")==0 || strcmp(host,"-.-")==0 )
		strcpy(prim,host);
	else
	if( hp = gethostbyname(host) )
		strcpy(prim,hp->h_name);
	else	strcpy(prim,host);
}

int fshutdown(FILE *fp,int force)
{
	if( SHUTDOWN == 0 && force == 0 )
		return -1;

	if( !file_ISSOCK(fileno(fp)) )
		return -1;

	fflush(fp);
	shutdown(fileno(fp),1);
	/* close(fileno(fp)); ... to do closesocket() on Win32 */
	return 0;
}
/*
int ShutdownSocket(int sock){
	return shutdown(sock,2);
}
*/

/*###################### LIBRARY END ##################################*/

#ifndef LIBRARY

extern int refreshWinStatus;
static struct {
	MStr(rt_msg,512);
} ResTrace;
static refQStr(RTptr,ResTrace.rt_msg);
int getResTrace(PVStr(trace)){
	refQStr(tp,trace);
	if( ResTrace.rt_msg[0] ){
		Rsprintf(tp,"%s",ResTrace.rt_msg);
	}
	return ResTrace.rt_msg[0];
}
int RES_TRACE;
void putResTrace(PCStr(fmt),...){
	static int ntrace;
	VARGS(16,fmt);
	if( RES_TRACE == 0 )
		return;
	if( RTptr == 0 ){
		RTptr = ResTrace.rt_msg;
	}
	if( sizeof(ResTrace.rt_msg) - (RTptr - ResTrace.rt_msg) < 80 ){
		ovstrcpy(ResTrace.rt_msg,ResTrace.rt_msg+80);
		RTptr = ResTrace.rt_msg + strlen(ResTrace.rt_msg);
	}
	Rsprintf(RTptr,"(%02d)",++ntrace%100);
	Rsprintf(RTptr,fmt,VA16);
}

int LIN_TIMEOUT = 30;
int DNS_TIMEOUT = 10;
int ACC_TIMEOUT = 10;
int CON_TIMEOUT = 10;
int CON_INTERVAL = 10;
int CON_RETRY = 2;
ConnStat ConnStats[NUM_CONNSTAT];


static int HOSTS_CACHE_LIFE_MIN = 10;
static int HOSTS_CACHE_LIFE_MAX = 0;
static int HOSTS_CACHE_UNKNOWN_MAX = 30;
extern int RES_CACHE_DISABLE;
extern int RES_HC_EXPIRE;

static void sigALRM(int sig){ siglongjmpX(jmpEnv,SIGALRM); }
static void sigPIPE(int sig){ siglongjmpX(jmpEnv,SIGPIPE); }

const char *stripHostPrefix(PCStr(host)){
	const char *ohost;
	const char *dp;

	if( host[0] != '_' )
		return host;

	ohost = host;
	while( strncmp(host,"_-",2) == 0 ){
		if( dp = strchr(host+2,'.') ){
			host = dp+1;
		}else{
			sv1log("#EMPTY#stripHostPrefix(%s)\n",ohost);
			break;
		}
	}
	return host;
}
int getHostPrefix(PCStr(host),const char **rhost,PVStr(prefix)){
	const char *ohost = host;
	host = stripHostPrefix(host);
	if( host == ohost ){
		return 0;
	}
	if( prefix ){
		XStrncpy(BVStr(prefix),ohost,host-ohost+1);
	}
	if( rhost ){
		*rhost = host;
	}
	return 1;
}
typedef struct {
	int	cx_isset;     /* set by CMAP=x:ConnOut or _-ConnOut-x.host */
	int	cx_numretry;  /* _-ConnOut-R-T-I */
	int	cx_timeout1;
	int	cx_interval;
	int	cx_dstport;   /* _-Port-9980.x.x.x.x */
	int	cx_setSRCIF;
	int	cx_dontroute; /* _-DontRoute{,IfBound,IfNotBound} */
} ConnCtrl;
static int setConnOut(ConnCtrl *CX,int self,PCStr(conf)){
	int nr,to,iv;
	nr = to = iv = -1;
	sscanf(conf,"%d-%d-%d",&nr,&to,&iv);
	if( 0 < nr && nr < 10 || (self && 0 <= nr) ){ CX->cx_numretry = nr; }
	if( 0 < to && to < 30 || (self && 0 <= to) ){ CX->cx_timeout1 = to; }
	if( 3 < iv && iv < 30 || (self && 0 <= iv) ){ CX->cx_interval = iv; }
	return 0;
}
int initConnCtrl(ConnCtrl *CX,PCStr(hostname),int self){
	IStr(conf,256);

	bzero(CX,sizeof(ConnCtrl));
	CX->cx_numretry = CON_RETRY;
	CX->cx_timeout1 = CON_TIMEOUT;
	CX->cx_interval = CON_INTERVAL;

	if( CONNCTRL == 0 ){
		return -1;
	}

	/* SOCKOPT=conn-retry:R */
	/* SOCKOPT=conn-timeout:T */
	/* SOCKOPT=conn-interval:I */

	/* CMAP=2-10-10:ConnOut:proto:dst:src */
	/* should match with REAL_HOST=hostname */
	if( 0 <= find_CMAP(MainConn(),"ConnOut",AVStr(conf)) ){
		CX->cx_isset |= 2;
		setConnOut(CX,1,conf);
		sv1log("##CMAP-ConnOut[%s] (%d %d %d)\n",conf,
			CX->cx_numretry,CX->cx_timeout1,CX->cx_interval);
	}

	/* host=_-ConnOut-2-10-10.host */
	if( self /* or SOCKOPT=allowctl:ConnOut:proto:dst:src */ )
	if( getHostPrefix(hostname,0,AVStr(conf)) )
	if( strncaseeq(conf,"_-ConnOut-",10) ){
		CX->cx_isset |= 4;
		setConnOut(CX,self,conf+10);
		sv1log("##%s (%d %d %d)\n",hostname,
			CX->cx_numretry,CX->cx_timeout1,CX->cx_interval);
	}

	/* SOCKOPT=dontroute:ifbound,ifnotbound:proto:dst:src */
	/* CMAP=-:DontRoute:proto:dst:src */
	if( 0 <= find_CMAP(MainConn(),"DontRoute",AVStr(conf)) ){
		CX->cx_dontroute = 1;
	}
	return CX->cx_isset;
}

int connectViaCCSV(int sock,SAP addr,int leng,int timeout,PVStr(cstat));
int connectTOY(int sock,SAP addr,int leng,int timeout,PVStr(cstat)){
	int rcode = -2 ;
	if( EccEnabled() ){
		rcode = connectViaCCSV(sock,addr,leng,timeout,BVStr(cstat));
	}
	if( rcode == -2 ){
		rcode = connectTOX(sock,addr,leng,timeout,BVStr(cstat));
	}
	return rcode;
}
#define connectTOX connectTOY

#ifdef CONNECT_POLLOUT
/*
int Bconnect(int s,VSAddr *name,int namelen,PVStr(cstat))
*/
int BconnectX(PCStr(wh),int s,VSAddr *name,int namelen,PVStr(cstat),int tmout)
{	int rcode;
	double Start,Elapse;
	CStr(hp,512);
	int CON_TIMEOUT = tmout;

	Start = Time();
	strcpy(cstat,wh);
	rcode = connectTOX(s,(SAP)name,namelen,CON_TIMEOUT*1000,BVStr(cstat));
	if( rcode != 0 && errno == ETIMEDOUT ){
		Elapse = Time() - Start;
		if( getConnectFlags(wh) & COF_TERSE ){
		}else
		daemonlog("E","*** CON_TIMEOUT: %4.2f/%ds -> %s\n",
			Elapse,CON_TIMEOUT,VSA_xtoap(name,AVStr(hp),sizeof(hp)));
		CONNERR_TIMEOUT = 1;
	}
	if( streq(cstat,wh) ){
		clearVStr(cstat);
	}
	return rcode;
}
#else
/*
int Bconnect(int s,VSAddr *name,int namelen,PVStr(cstat))
*/
int BconnectX(PCStr(wh),int s,VSAddr *name,int namelen,PVStr(cstat),int tmout)
{	int rcode;
	int timer;
	double Start;
	CStr(hp,512);
	int CON_TIMEOUT = tmout;

	if( CON_TIMEOUT ){
		timer = pushTimer("Bconnect",sigALRM,CON_TIMEOUT);
		Start = Time();
		if( sigsetjmpX(jmpEnv,1) != 0 ){
			if( getConnectFlags(wh) & COF_TERSE ){
			}else
			daemonlog("E","*** CON_TIMEOUT: %4.2f/%ds -> %s\n",
				Time()-Start,CON_TIMEOUT,
				VSA_xtoap(name,AVStr(hp),sizeof(hp)));
			popTimer(timer);
			CONNERR_TIMEOUT = 1;
			errno = ETIMEDOUT;
			return -1;
		}
	}

	rcode = connect(s,(SAP)name,namelen);

	if( CON_TIMEOUT )
		popTimer(timer);

	return rcode;
}
/*
int connectTIMEOUT(int fd,void *name,int namelen);
int Bconnect(int s,VSAddr *name,int namelen,PVStr(cstat))
{	int rcode;
	rcode = connectTIMEOUT(s,name,namelen);
	return rcode;
}
*/
#endif
#define Bconnect(w,s,n,l,r) BconnectX(w,s,n,l,r,CON_TIMEOUT)

int connectV(int s,void *name,int namelen){
	int rcode;
	rcode = connect(s,(SAP)name,namelen);
	return rcode;
}

int RESOLV_UNKNOWN;
extern int ERROR_RESTART;
struct hostent *Dgethostbyname(PCStr(name))
{	struct hostent *ht;
	int fd;

	if( name[0] == 0 )
		return NULL;
	if( strncmp(name,"--",2) == 0 ) /* --Cant-GetPeerName */
		return NULL;
	if( streq(name,"?") )
		return NULL;
	name = stripHostPrefix(name);

if( strchr(name,'%') ){
	CStr(xname,512);
	sv1log("## unescape host-name before gethostbyname: %s\n",name);
	nonxalpha_unescape(name,AVStr(xname),0);
	name = xname;
}

	/*
	if( inet_addrV4(name) != -1 ){
		sv1log("#### simulate INCONSISTENT DNS\n");
		return NULL;
	}
	*/

	/* SPECIAL HOST NAME IN DeleGate */
	if( strcmp(name,"-")==0 || strcmp(name,"-.-")==0 )
		return NULL;
	if( strcmp(name,"*")==0 )
		return NULL;

	fd = nextFD();
	ht = NULL;

	if( ht == NULL ){
		Verbose("gethostbyname(%s).\n",name);
		ht = gethostbyname(name);
	}
	if( ht == NULL ){
		RESOLV_UNKNOWN++;
		if( ERROR_RESTART )
		sv1log("eRESTART unknown*%d gethostbyname(%s)\n",
			RESOLV_UNKNOWN,name);
		iLog("--E unknown gethostname(%s)",name);
	}
	usedFD(fd);
	return ht;
}
struct hostent *Dgethostbyaddr(PCStr(addr),int len,int type)
{	struct hostent *ht;
	int fd;

	if( *(int*)addr == 0 || *(int*)addr == -1 )
		return NULL;
	addr = stripHostPrefix(addr);

	fd = nextFD();
	ht = gethostbyaddr(addr,len,type);

	usedFD(fd);
	return ht;
}
static struct hostent *Dgethostbynameaddr(PCStr(name),PCStr(addr),int len,int type)
{
	if( name != NULL )
		return Dgethostbyname(name);
	else	return Dgethostbyaddr(addr,len,type);
}

static int res_dommatch(PCStr(hlid),PCStr(dom)){
	int match;
	int sco;
	CStr(xdom,MaxHostNameLen);

	if( sizeof(xdom) <= 1+strlen(dom) ){
		sv1log("too long res_dommatch((%d)%s)\n",(int)strlen(dom),dom);
		return 0;
	}
	sprintf(xdom,"-%s",dom); /* "-" to disable Resolvy in matchPath1 */
	sco = CACHE_ONLY; /* to make sure not to call Revoly */
	CACHE_ONLY = 1;
	match = matchPath1(atoi(hlid),"",xdom,0);
	CACHE_ONLY = sco;
	return match;
}
int HL2VSA(int hlid,int port,int mac,VSAddr va[]);
static int res_vsaddrs(PCStr(hlid),int mac,VSAddr av[]){
	int ac;
	ac = HL2VSA(atoi(hlid),53,mac,av);
	return ac;
}
extern int (*RES_hlmatch)(PCStr(hlist),PCStr(dom));
extern int (*RES_hltovsa)(PCStr(hlist),int ac,VSAddr av[]);

static scanListFunc order1(PCStr(typespec),PVStr(order)){
	CStr(typespecb,1024);
	CStr(argb,256);
	const char *av[4];
	const char *type;
	const char *arg;
	const char *doms;
	const char *clients;
	int map;

	strcpy(typespecb,typespec);
	av[0] = av[1] = av[2] = av[3] = "";
	list2vect(typespecb,':',4,av);
	type = av[0];
	arg = av[1];
	doms = av[2];
	clients = av[3];

	if( strcasecmp(type,"cache") == 0 )
		strcat(order,"C");
	else
	if( strcasecmp(type,"file") == 0 )
	{
		strcat(order,"F");
		if( arg[0] == 0 ){
		}else
		if( strlen(arg) == 1 && (*doms == '/' || *doms == '\\') ){
			/* file:X:/path */
			sprintf(argb,"%s:%s",arg,doms);
			arg = argb;
			av[2] = av[3] = "";
			list2vect(clients,':',2,&av[2]);
			doms = av[2];
			clients = av[3];
		}else{
			CStr(path,1024);
		strcpy(argb,arg);
		newPath(AVStr(argb));
			if( File_is(argb) ){
				if( !isFullpath(argb) ){
					IGNRETS getcwd(path,sizeof(path));
					Xsprintf(TVStr(path),"/%s",argb);
					iLog("RESOLV=file:%s=%s",arg,path);
					strcpy(argb,path);
				}
			}else{
				/* should retrieve DGROOT/xxx/yyy too ... */
				if( fullpathLIB(arg,"r",AVStr(path)) ){
					iLog("RESOLV=file:%s=%s",arg,path);
					strcpy(argb,path);
				}
			}
		arg = argb;
		}
	}
	else
	if( strcasecmp(type,"nis") == 0 )
		strcat(order,"N");
	else
	if( strcasecmp(type,"dns") == 0 )
	{
		strcat(order,"D");
		if( arg[0] ){
			map = makePathList("RESOLV",arg);
			sprintf(argb,"$%d",map);
			arg = argb;
		}
		RES_hltovsa = res_vsaddrs;
	}
	else
	if( strcasecmp(type,"sys") == 0 )
		strcat(order,"S");
	else
	if( strcasecmp(type,"unknown") == 0 )
		strcat(order,"U");

	if( arg[0] )
		Xsprintf(TVStr(order),":%s",arg);
	if( doms[0] ){
		map = makePathList("RESOLV",doms);
		if( arg[0] == 0 )
			Xsprintf(TVStr(order),":");
		Xsprintf(TVStr(order),"#%d",map);
		RES_hlmatch = res_dommatch;
	}
	if( clients[0] ){
		map = makePathList("RESOLV",clients);
		if( clients[0] == 0 )
			Xsprintf(TVStr(order),":");
		Xsprintf(TVStr(order),"<%d",map);
		RES_hlmatch = res_dommatch;
	}
	if( arg[0] || doms[0] ){
		Xsprintf(TVStr(order),",");
	}
	return 0;
}

extern int (*RES_log)(int,...);
static void res_log(int which,int byname,PCStr(name),char *rv[],PCStr(cname))
{	double Now;

	Now = Time();
	if( which == 0 )
		resStart = Now;
	else{
		fprintf(res_logf,"%.3f %.4f %d %c %s\n",
			Now,Now-resStart,Getpid(),which,name);
		fflush(res_logf);
	}
}

void RES_prorder(PCStr(resolvers),PVStr(resolv))
{	int ri;
	const char *res;
	CStr(res1,128);
	CStr(arg,128);
	refQStr(rp,resolv); /**/

	for( ri = 0; ri = RES_next_res(resolvers,ri,AVStr(res1),AVStr(arg)); ){
		switch( res1[0] ){
		case 'C': res = "cache"; break;
		case 'F': res = "file"; break;
		case 'N': res = "nis"; break;
		case 'D': res = "dns"; break;
		case 'S': res = "sys"; break;
		default: res = res1; break;
		}
		if( rp != resolv )
			setVStrPtrInc(rp,',');
		strcpy(rp,res);
		rp += strlen(rp);
	}
	setVStrEnd(rp,0);
}
static int scan_RES_EXPIRE(PCStr(exp)){
	double ext,onmem,dnsrr;

	if( exp == 0 ){
		return -1;
	}
	ext = onmem = dnsrr = -9;
	sscanf(exp,"%lf/%lf/%lf",&ext,&onmem,&dnsrr);
	if( 0 <= ext ){
		RES_HC_EXPIRE = (int)ext;
	}
	return 0;
}

extern int TIMEOUT_RES_UP_WAIT;
int CTX_getGatewayFlags(DGC*ctx);
const char *DELEGATE_getEnv(PCStr(name));
static const char *RES_AUTO_DFLT = "+";

static void waitResolver(PCStr(resl));
void init_myname(PCStr(RESOLV));
void init_resolv(PCStr(resolv),PCStr(conf),PCStr(ns),PCStr(af),PCStr(verify),PCStr(rr),PCStr(debug),PCStr(log))
{
	IStr(order,RESOLVERS_SIZ);
	strcpy(order,"SYS");

	if( debug != NULL )
		RES_debug(debug);
	if( rr != NULL )
		RES_roundrobin(rr);
	if( af != 0 )
		RES_af(af);

	if( log != NULL ){
		if( res_logf = fopen(log,"a") ){
			setCloseOnExec(fileno(res_logf));
			RES_log = (int(*)(int,...))res_log;
		}
	}
	scan_RES_EXPIRE(DELEGATE_getEnv("RES_EXPIRE"));

	if( resolv != NULL && streq(resolv,RES_AUTO_DFLT) ){
		/* 9.9.7 to be set default in init_myname() */
	}else
	if( resolv != NULL ){
		const char *roe;

		truncVStr(order);
		scan_commaList(resolv,0,scanListCall order1,AVStr(order));
		InitLog("## RES_ORDER=%s\n",order);
		RES_orderSet(order);
		RES_confidSet("RESOLV");
		if( *resolv == 0 )
			CACHE_ONLY = 1;
		if( roe = getenv("RES_ORDER") ){
			/* 9.9.7 RES_ORDER should be consistent with RESOLV
			 * since it overwrites RESOLV in resconf.c:RES_init(),
			 * but RES_ORDER with internal status as "D:$1" must
			 * not be exported to be referred by siblings which
			 * do not inherit the internal status of this one.
			 */
			sv1log("--unsetenv RES_ORDER=%s (RESOLV=%s)\n",
				roe,order);
			unsetenv("RES_ORDER");
		}
	}
	if( conf != NULL )
		RES_conf(conf);
	if( ns != NULL )
		RES_ns(ns);
	if( verify != NULL )
		RES_verify(verify);

	if( CTX_getGatewayFlags(MainConn()) & GW_COMMAND ){
		/* 9.9.7 avoid delay in resolver testing for each -Function */
		if( DELEGATE_getEnv("RES_WAIT") == 0 ){
			/* if RES_WAIT=... is not specified */
			/* no delay in resolver testing */
			TIMEOUT_RES_UP_WAIT = 0;
		}
		if( resolv == 0 ){
			/* if RESOLV=... is not specified */
			/* no delay in retrieving the name of this host */
			resolv = "";
		}
	}
	waitResolver(order);
	init_myname(resolv);
}

static void shuffle_addrlist(struct hostent *hp)
{	const char *haddr;
	const char *haddr0;
	int hi;

	if( hp->h_addr_list[0] == NULL || hp->h_addr_list[1] == NULL )
		return;

	if( ADDRLIST_RR ){
		haddr0 = hp->h_addr_list[0];
		for( hi = 0; haddr = hp->h_addr_list[hi+1]; hi++ )
			hp->h_addr_list[hi] = hp->h_addr_list[hi+1];
		hp->h_addr_list[hi] = (char*)haddr0;
	}
}
extern int CHILD_SERNO;
static void shift_addrlist(struct hostent *hp)
{	int na,sn,si;

	for( na = 0; hp->h_addr_list[na]; na++ )
		;
	if( na < 2 )
		return;
	sn = CHILD_SERNO % na;
	if( sn == 0 )
		return;
	for( si = 0; si < sn; si++ )
		shuffle_addrlist(hp);
}

static int findName1(struct hostent *hp,PCStr(name))
{	const char *name1;
	int ai;

	if( hp->h_name )
		if( strcasecmp(name,hp->h_name) == 0 )
			return 1;

	if( hp->h_aliases )
	for( ai = 0; name1 = hp->h_aliases[ai]; ai++ )
		if( strcasecmp(name,name1) == 0 )
			return 1;
	return 0;
}
static int findAddr1(struct hostent *hp,PCStr(addr),int len,int type)
{	int ai;
	const char *addr1;

	for( ai = 0; addr1 = hp->h_addr_list[ai]; ai++ )
		if( memcmp(addr,addr1,len) == 0 )
			return 1;
	return 0;
}

static CriticalSec hostsCSC;
static void movelast_addrList(PCStr(wh),double Elp,int fd,Hostent *Hp,struct hostent *hp,const char *haddr){
	int an,ai,ao,ax;
	const char *addrx;
	const char *addr1;

	if( hp->h_addr_list[0] == 0 || hp->h_addr_list[1] == 0 ){
		return;
	}
	for( an = 0; hp->h_addr_list[an]; an++ );
	if( numthreads() ){
		setupCSC("shift_addrlist",hostsCSC,sizeof(hostsCSC));
		enterCSC(hostsCSC);
	}
	ao = 0;
	ax = 0;
	for( ai = 0; ai < an; ai++ ){
		if( hp->h_addr_list[ai] == haddr ){
			LOGX_tcpConSorted++;
			ax = ai;
		}else{
			hp->h_addr_list[ao++] = hp->h_addr_list[ai];
		}
	}
	if( ao < an ){
		hp->h_addr_list[ao] = (char*)haddr;
	}
	if( ax < an-1 ){
		IStr(alist,256);
		refQStr(ap,alist);
		int li;
		const unsigned char *up;
		int lty0;

		if( Hp )
		Hp->hc_errors++;
		up = (unsigned char*)haddr;
		sprintf(ap,"[%d.%d.%d.%d]",up[0],up[1],up[2],up[3]);
		for( li = 0; li < 4 && ax +li < an; li++ ){
			ap += strlen(ap);
			up = (unsigned char*)hp->h_addr_list[ax+li];
			sprintf(ap," %d.%d.%d.%d",
				up[0],up[1],up[2],up[3]);
		}
		lty0 = LOG_type0;
		LOG_type0 = 0;
		daemonlog("F","addr-list [%s %.2f %d] %X %s (%d) %d/%d %s\n",
			wh,Elp,fd,
			p2i(Hp),hp->h_name?hp->h_name:"",Hp?Hp->hc_errors:0,
			ax,an,alist);
		LOG_type0 = lty0;
	}
	if( numthreads() ){
		leaveCSC(hostsCSC);
	}
}
static void shift_addrlistLocked(struct hostent *hp){
	if( numthreads() ){
		setupCSC("shift_addrlist",hostsCSC,sizeof(hostsCSC));
		enterCSC(hostsCSC);
	}
	shift_addrlist(hp);
	if( numthreads() ){
		leaveCSC(hostsCSC);
	}
}
#define shift_addrlist(hp) shift_addrlistLocked(hp)

static int isinlist(char *sv[],const char *s1,int len){
	int si;
	const char *sc;
	for( si = 0; sc = sv[si]; si++ ){
		if( 0 < len ){
			if( bcmp(s1,sc,len) == 0 ){
				return si+1;
			}
		}else{
			if( strcasecmp(s1,sc) == 0 ){
				return si+1;
			}
		}
	}
	return 0;
}
/* test if h1 is a subset of h2 */
#define MOD_HNCASE	1
#define MOD_ALIASES	2
#define MOD_ADDRLIST	4
int hostentsubset(struct hostent *hp1,struct hostent *hp2,int *difp){
	int ai;
	const char *a1,*a2;
	int alen;
	int dif = 0;
	int match;
	int sx;

	if( hp1->h_addrtype == hp2->h_addrtype )
	if( hp1->h_length   == hp2->h_length )
	if( strcaseeq(hp1->h_name,hp2->h_name) )
	{
		alen = hp1->h_length;
		for( ai = 0; a1 = hp1->h_addr_list[ai]; ai++ ){
			if( sx = isinlist(hp2->h_addr_list,a1,alen) ){
				if( sx != ai+1 ){
unsigned char *up = (unsigned char*)a1;
sv1log("##addr-list %X[%d] %X[%d] %d.%d.%d.%d\n",
p2i(hp1),ai,p2i(hp2),sx,up[0],up[1],up[2],up[3]);
					dif |= MOD_ADDRLIST;
				}
			}else{
				return 0;
			}
		}
		for( ai = 0; a1 = hp1->h_aliases[ai]; ai++ ){
			if( sx = isinlist(hp2->h_aliases,a1,0) ){
				if( sx != ai+1 ){
					dif |= MOD_ALIASES;
				}
			}else{
				return 0;
			}
		}
		*difp = dif;
		return 1;
	}
	return 0;
}
Hostent *findHostentInCache(struct hostent *ahp,struct hostent **chp,int *difp){
	Hostent *Hp = 0;
	struct hostent *hp;
	int hi;

	for( hi = 0; hi < NHosts; hi++ ){
		Hp = HostsCache[hi];
		hp = &Hp->hc_hostent;
		if( hostentsubset(ahp,hp,difp) ){
			*chp = hp;
			return Hp;
		}
	}
	return 0;
}

static Hostent *findHostCachex(PCStr(name),PCStr(addr),int len,int type);
static Hostent *findHostCache(PCStr(name),PCStr(addr),int len,int type)
{	Hostent *hp;

	if( numthreads() ){
		setupCSC("findHostCache",hostsCSC,sizeof(hostsCSC));
		enterCSC(hostsCSC);
	}
	hp = findHostCachex(name,addr,len,type);
	if( numthreads() ){
		leaveCSC(hostsCSC);
	}
	return hp;
}
static Hostent *findHostCachex(PCStr(name),PCStr(addr),int len,int type)
{	int hi,ai,freq;
	Hostent *Hp;
	struct hostent *hp;

	for( hi = 0; hi < NHosts; hi++ ){
		Hp = HostsCache[hi];
		hp = &Hp->hc_hostent;
		if( name ){
			if( findName1(hp,name) )
				goto found;
		}else{
			if( findAddr1(hp,addr,len,type) )
				goto found;
		}
	}
	return 0;
found:
	Hp->hc_atime = time(NULL);
	freq = Hp->hc_freq += 1;
/*
	if( name )
		Verbose("*** HIT[%d] gethostbyname(%s)\n",freq,name);
	else	Verbose("*** HIT[%d] gethostbyaddr(): %s\n",freq,hp->h_name);
*/
	return Hp;
}
static Hostent *findHostCacheByaddr(PCStr(aaddr)){
	VSAddr sab;
	const char *baddr;
	int bsize,btype;
	Hostent *Hp;

	VSA_atosa(&sab,0,aaddr);
	bsize = VSA_decomp(&sab,&baddr,&btype,NULL);
	Hp = findHostCache(NULL,baddr,bsize,btype);
	return Hp;
}
static const char **addAliases(struct hostent *hp,int mac,const char *aliasesb[],PCStr(name))
{	int ai;
	const char *name1;

	if( name == 0 )
		return (const char**)hp->h_aliases;

	if( findName1(hp,name) )
		return (const char**)hp->h_aliases;

	for( ai = 0; name1 = hp->h_aliases[ai]; ai++ ){
		if( mac-1 <= ai )
			break;
		aliasesb[ai] = (char*)name1;
	}
	aliasesb[ai++] = (char*)name;
	aliasesb[ai] = 0;
	return aliasesb;
}

/*
 * TODO: chache should be normalized so that only N to 1 correspondence
 *       (N names to an address) are included, to make update easy ???
 */
static char *dump_HOST1(PVStr(hosts),struct hostent *hp);

static struct hostent *addHostCachex(PCStr(name),const char *const*aliases,int type,int len,const char *const*addrlist);
static struct hostent *addHostCache(PCStr(name),const char *const*aliases,int type,int len,const char *const*addrlist)
{	struct hostent *hp;

	if( numthreads() ){
		setupCSC("addHostCache",hostsCSC,sizeof(hostsCSC));
		enterCSC(hostsCSC);
	}
	hp = addHostCachex(name,aliases,type,len,addrlist);
	if( numthreads() ){
		leaveCSC(hostsCSC);
	}
	return hp;
}
static struct hostent *addHostCachex(PCStr(name),const char *const*aliases,int type,int len,const char *const*addrlist)
{	struct hostent *chp;
	int na,ai;
	Hostent *He;
	CStr(hosts,2048);

	chp = NULL;

	/*
	 *  chp = first occurence of entry which include
	 *        name, aliases, or addrlist in it, if exists.
	 */

	if( chp == NULL && NHosts < NHOSTS ){
		if( lSINGLEP() ){
			He = (Hostent*)malloc(sizeof(Hostent));
			bzero(He,sizeof(Hostent));
			He->hc_freeable = 1;
		}else
		He = NewStruct(Hostent);
		He->hc_index = NHosts;
		HostsCache[NHosts++] = He;
		He->hc_predef = HOSTS_PREDEF;
		He->hc_mtime = time(NULL);
		He->hc_atime = He->hc_mtime;
		chp = &He->hc_hostent;
		LOGX_resEnt = NHosts;
	}
	if( chp != NULL ){
		chp->h_name = stralloc(name);
		chp->h_aliases = (char**)dupv((const char**)aliases,0);
		chp->h_addrtype = type;
		chp->h_length = len;
		chp->h_addr_list = (char**)dupv((const char**)addrlist,len);
		dump_HOST1(AVStr(hosts),chp);
		Verbose("HOSTS[%d]=%s %s\n",He->hc_index,hosts,He->hc_predef?"(PREDEF)":"");
		return chp;
	}
	return 0;
}
static struct hostent *dupHost(struct hostent *hp){
	struct hostent *chp;
	chp = (struct hostent*)malloc(sizeof(struct hostent));
	chp->h_name = stralloc(hp->h_name);
	chp->h_aliases = (char**)dupv((const char**)hp->h_aliases,0);
	chp->h_length = hp->h_length;
	chp->h_addrtype = hp->h_addrtype;
	chp->h_addr_list = (char**)dupv((const char**)hp->h_addr_list,hp->h_length);
	return chp;
}
static void freeHost(struct hostent *hp){
	free((char*)hp->h_name);
	freev(hp->h_aliases);
	freev(hp->h_addr_list);
	free(hp);
}

static int replaceHostCache(PCStr(name),PCStr(addr),int len,int type, int now,Hostent *Hp,struct hostent *hp)
{	const char *hname;
	const char *addrlistb[2]; /**/
	const char **addrlist;
	int addrleng;
	int addrtype;
	struct hostent *chp = &Hp->hc_hostent;
	int replaced;

	if( hp ){
		if( name && hp->h_name )
		if( strcmp(name,hp->h_name) != 0 ){
			sv1log("HOSTS[%d] cache can't be overwritten: %s->%s\n",
				Hp->hc_index,name,hp->h_name);
			Hp->hc_mtime = now;
			return 0;
		}
		if( hp->h_length != chp->h_length )
		/* and if this entry is created by an inverse retrieval ... */
		{
			sv1log("HOSTS[%d] cache can't be replaced: %s %d->%d\n",
				Hp->hc_index,hp->h_name,
				chp->h_length,hp->h_length);
			Hp->hc_mtime = now;
			return 0;
		}
		hname = hp->h_name;
		addrlist = (const char**)hp->h_addr_list;
		addrleng = hp->h_length;
		addrtype = hp->h_addrtype;
	}else{
		addrlist = addrlistb;
		if( name ){
			hname = name;
			addrlist[0] = 0;
			addrleng = 4;
			addrtype = AF_INET;
		}else{
			hname = "";
			addrlist[0] = (char*)addr;
			addrlist[1] = 0;
			addrleng = len;
			addrtype = len==4?AF_INET:AF_INET6;
		}
	}
	replaced = 0;
	if( name ){
		/*
		if( chp->h_addr_list[0] && addrlist[0] == 0 ){
			sv1log("#### INCONSISTENT but don't clear cache: %s\n",name);
		}else
		*/
		if( cmpv((const char**)chp->h_addr_list,addrlist,addrleng) ){
			freev(chp->h_addr_list);
			chp->h_addr_list = (char**)dupv(addrlist,addrleng);
			chp->h_addrtype = addrtype;
			chp->h_length = addrleng;
			replaced = 1;
		}
	}else{
		if( strcmp(chp->h_name,hname) != 0 ){
			free((char*)chp->h_name);
			chp->h_name = stralloc(hname);
			replaced = 1;
		}
	}
	if( replaced ){
		sv1log("HOSTS[%d] cache by-%s of '%s' replaced (age=%d)\n",
			Hp->hc_index,
			name?"name":"addr",name?name:hname,now-Hp->hc_mtime);
	}
	Hp->hc_mtime = now;
	return 1;
}

static struct hostent *addHostCacheOk(struct hostent *hp,PCStr(name),PCStr(func),double Start)
{	const char **aliases;
	const char *aliasesb[1024]; /**/

	daemonlog("D","*** %s: %s / %4.2f secs. has_alias:%d\n",
		func,hp->h_name,Time()-Start,
		(hp->h_aliases[0] ? 1:0));

	aliases = addAliases(hp,elnumof(aliasesb),aliasesb,name);
	return addHostCache(hp->h_name,aliases,hp->h_addrtype,hp->h_length,(const char**)hp->h_addr_list);
}
static char *dumpAddr(PVStr(aaddr),PCStr(sba),int len,int type){
	Sprintf(BVStr(aaddr),"%s",VSA_ltoa((unsigned char*)sba,len,type));
	return Sprintf(BVStr(aaddr),"%s",VSA_ltoa((unsigned char*)sba,len,type));
}
static char *scanAddrX(PCStr(aaddr),PVStr(ba),int *lenp,int *typp){
	int typ,len;
	CStr(bab,IPV6_ADDRLENG);
	len = VSA_atob(aaddr,AVStr(bab),&typ);
	if( len <= 0 )
		return 0;
	Bcopy(bab,ba,len);
	*lenp = len;
	*typp = typ;
	return (char*)ba;
}

static void dumpAddrs(struct hostent *hp,PVStr(addrlist))
{
	const char *addr;
	int ai;

	setVStrEnd(addrlist,0);
	if( hp->h_addr_list[0] ){
		refQStr(lp,addrlist); /**/
		if( hp->h_addr_list[1] )
			lp = Sprintf(AVStr(lp),"{");
		for( ai = 0; addr = hp->h_addr_list[ai]; ai++ ){ 
			if( 0 < ai )
				lp = Sprintf(AVStr(lp),",");
			lp = dumpAddr(AVStr(lp),hp->h_addr_list[ai],hp->h_length,hp->h_addrtype);
		}
		if( hp->h_addr_list[1] )
			lp = Sprintf(AVStr(lp),"}");
	}
}
static char *dump_HOST1(PVStr(hosts),struct hostent *hp)
{	int ai;
	const char *name;
	refQStr(sp,hosts); /**/

	if( hp->h_aliases[0] ){
		sp = Sprintf(AVStr(sp),"{");
		sp = Sprintf(AVStr(sp),"%s",hp->h_name);
		for( ai = 0; name = hp->h_aliases[ai]; ai++ )
		sp = Sprintf(AVStr(sp),",%s",name);
		sp = Sprintf(AVStr(sp),"}");
	}else	sp = Sprintf(AVStr(sp),"%s",hp->h_name);
	sp = Sprintf(AVStr(sp),"/");
	dumpAddrs(hp,AVStr(sp));
	return (char*)sp + strlen(sp);
}
int dump_HOSTS(PVStr(hosts))
{	int hi;
	refQStr(sp,hosts); /**/

	if( numthreads() ){
		setupCSC("dump_HOSTS",hostsCSC,sizeof(hostsCSC));
		enterCSC(hostsCSC);
	}
	setVStrEnd(hosts,0);
	for( hi = 0; hi < NHosts; hi++ ){
		if( 0 < hi )
			sp = Sprintf(AVStr(sp),",");
		sp = dump_HOST1(AVStr(sp),&HostsCache[hi]->hc_hostent);
	}
	if( ADDRLIST_RR ){
		if( 0 < NHosts )
			sp = Sprintf(AVStr(sp),",");
		strcpy(sp,"*/*/RR");
	}
	if( numthreads() ){
		leaveCSC(hostsCSC);
	}
	return NHosts;
}
int dumpHostCache(FILE *tc){
	int hi,hn;
	Hostent *Hp;
	struct hostent *hp;
	IStr(sts,128);
	IStr(its,128);
	IStr(hosts,1024);
	int age;
	int idle;
	int now = time(0);

	hn = 0;
	for( hi = 0; hi < NHosts; hi++ ){
		Hp = HostsCache[hi];
		hp = &Hp->hc_hostent;
		if( hp ){
			hn++;
			age = now - Hp->hc_mtime;
			idle = now - Hp->hc_atime;
			sprintf(sts,"%5d:%02d",age/60,age%60);
			sprintf(its,"%2d:%02d",idle/60,idle%60);
			dump_HOST1(AVStr(hosts),hp);
			fprintf(tc,"[%3d][%3d]%s%s %s %4d %s",hi,Hp->hc_index,
				Hp->hc_predefa?"C":Hp->hc_predef?"P":"+",
				sts,its,Hp->hc_freq,hosts);
			if( Hp->hc_errors ) fprintf(tc," E%d",Hp->hc_errors);
			fprintf(tc,"\n");
		}
	}
	return hn;
}
static int sorti(Hostent **e1,Hostent **e2){
	return (*e2)->hc_atime - (*e1)->hc_atime;
}
int SortCachedHosts(){
	setupCSC("SortCachedHosts",hostsCSC,sizeof(hostsCSC));
	enterCSC(hostsCSC);
	qsort(HostsCache,NHosts,sizeof(Hostent*),(sortFunc)sorti);
	leaveCSC(hostsCSC);
	return 0;
}
int ExpireCachedHosts(int mexp,int iexp){
	int ci,cj;
	Hostent *Hp;
	int now = time(0);
	IStr(hosts,1024);
	int age,idle;

	setupCSC("ExpireCachedHosts",hostsCSC,sizeof(hostsCSC));
	enterCSC(hostsCSC);
	cj = 0;
	for( ci = 0; ci < NHosts; ci++ ){
		if( Hp = HostsCache[ci] ){
			age = now - Hp->hc_mtime;
			idle = now - Hp->hc_atime;
			if( Hp->hc_predef || Hp->hc_predefa ){
			}else
			if( mexp < age || iexp < idle ){
				dump_HOST1(AVStr(hosts),&Hp->hc_hostent);
				sv1log("expired CachedHosts[%d] %d %d %s\n",
					ci,age,idle,hosts);
				if( Hp->hc_freeable ){
					free(Hp);
				}
				continue;
			}else{
			}
			HostsCache[cj++] = Hp;
		}
	}
	if( cj < NHosts ){
		sv1log("expired CachedHosts Fil=%d/%d/%d\n",cj,
			NHosts,NHOSTS);
		NHosts = cj;
	}
	leaveCSC(hostsCSC);
	return 0;
}
static int find_HOSTSx(PCStr(hosts));
static int find_HOSTS(PCStr(hosts))
{	int rcode;
 
	if( numthreads() ){
		setupCSC("find_HOSTS",hostsCSC,sizeof(hostsCSC));
		enterCSC(hostsCSC);
	}
	rcode = find_HOSTSx(hosts);
	if( numthreads() ){
		leaveCSC(hostsCSC);
	}
	return rcode;
}
static int find_HOSTSx(PCStr(hosts))
{	int hi;
	CStr(hosts1,2048);

	for( hi = 0; hi < NHosts; hi++ ){
		dump_HOST1(AVStr(hosts1),&HostsCache[hi]->hc_hostent);
		if( strcmp(hosts,hosts1) == 0 )
			return 1;
	}
	return 0;
}
/*
static int list2v(xPVStr(slist),int mac,const char *vlist[],int isaddr)
*/
/*
static int list2v(xPVStr(slist),int mac,const char *vlist[],int *isaddr)
*/
static int list2v(xPVStr(slist),int mac,const char *vlist[],int *len,int *typ)
{	int ni = 0;
	const char *dp;
	const char *tp;
	ACStr(alist,128,32);
	int lengs[128];
	int len1 = 4;
	int lenx = 4;
	int typx = 0;

	if( slist[0] == '{' || strchr(slist,',') ){
		refQStr(np,slist); /**/
		if( slist[0] == '{' ){
			np = slist + 1;
			if( tp = strchr(np,'}') )
				truncVStr(tp);
		}else	np = slist;

		for(; np; np = (char*)dp){
			if( mac-1 <= ni ){
				fprintf(stderr,"list2v:too many elements\n");
				break;
			}
			if( dp = strchr(np,',') ){
				truncVStr(dp); dp++;
			}
			Verbose("[%d] %s\n",ni,np);
			if( typ != NULL )
			{
				scanAddrX(np,EVStr(alist[ni]),&len1,typ);
				if( len ) *len = len1;
				if( lenx < len1 ) lenx = len1;
				if( *typ == AF_INET6 ) typx = AF_INET6;
				lengs[ni] = len1;
				ni++;
			}
			else{
			vlist[ni++] = np;
			}
		}
		vlist[ni] = 0;
		if( typ != NULL ){
			refQStr(ap,slist);
			int nj;
			for( nj = 0; nj < ni; nj++ ){
				len1 = lengs[nj];
				vlist[nj] = ap;
				if( len1 < lenx ){
					bzero((char*)ap,lenx);
					ap += 10;
					setVStrPtrInc(ap,0xFF);
					setVStrPtrInc(ap,0xFF);
					Bcopy(alist[nj],ap,len1);
					ap += 8;
				}else{
					Bcopy(alist[nj],ap,lenx);
					ap += lenx;
				}
			}
			if( typx ){
				if( typ ) *typ = typx;
				if( len ) *len = lenx;
			}
		}
	}else{
		Verbose("[-] %s\n",slist);
		/*
		if( isaddr )
		*/
		if( typ != NULL )
		{
			slist = scanAddrX(slist,AVStr(slist),len,typ);
		}
		vlist[0] = slist;
		vlist[1] = 0;
		ni = 1;
	}
	return ni;
}

static scanListFunc gethostbyname1(PCStr(name),xPVStr(addrb))
{	struct hostent *hp;

	if( hp = Dgethostbyname(name) ){
		if( *addrb != 0 ){
			addrb += strlen(addrb);
			setVStrElem(addrb,0,',');
			addrb++;
		}
		dumpAddrs(hp,AVStr(addrb));
		if( *addrb == 0 ){
			fprintf(stderr,"gethostbyname1:overlfow?\n");
			return -1;
		}
	}
	return 0;
}
static void gethostbynames(PCStr(names),PVStr(addrb))
{	CStr(nameb,0x4000);

	setVStrEnd(addrb,0);
	strcpy(nameb,names);
	scan_commaListL(nameb,0,scanListCall gethostbyname1,AVStr(addrb));
}
static scanListFunc addhost1(PCStr(nameaddr))
{	CStr(namesb,512);
	refQStr(names,namesb); /**/
	refQStr(addrs,namesb);
	CStr(addrb,512);
	const char *opts;
	const char *addrlist[64]; /**/
	const char *namelist[64]; /**/
	const char **aliases;
	int len,typ;

	if( find_HOSTS(nameaddr) )
		return 0;

	if( strcmp(nameaddr,"CACHE_ONLY") == 0){
		CACHE_ONLY = 1;
		goto EXIT;
	}

	if( strlen(nameaddr) < sizeof(namesb) ){
		strcpy(names,nameaddr);
	}else{
		setQStr(names,stralloc(nameaddr),strlen(nameaddr)+1);
		cpyQStr(addrs,names);
	}
	if( addrs = strchr(names,'/') ){
		setVStrPtrInc(addrs,0);
		if( opts = strchr(addrs+1,'/') ){
			truncVStr(opts); opts++;
		}
	}else	opts = 0;
	if( strcmp(nameaddr,"*/*/RR") == 0 ){
		ADDRLIST_RR = 1;
		goto EXIT;
	}

	if( addrs == 0 ){
		gethostbynames(names,AVStr(addrb));
		if( addrb[0] == 0 )
			goto EXIT;
		addrs = addrb;
		cpyQStr(addrs,addrb);
	}

	if( list2v(AVStr(names),elnumof(namelist),namelist,0,0) <= 0 )
		goto EXIT;
	typ = len = 0;
	if( list2v(AVStr(addrs),elnumof(addrlist),addrlist,&len,&typ) <= 0 )
		goto EXIT;

	if( namelist[0] )
		aliases = &namelist[1];
	else	aliases = &namelist[0];
	if( typ )
		addHostCache(namelist[0],aliases,typ,len,addrlist);
	else	addHostCache(namelist[0],aliases,AF_INET,4,addrlist);

EXIT:
	if( names != namesb )
		free((char*)names);
	return 0;
}
void scan_HOSTS(DGC*_,PCStr(hosts))
{
	HOSTS_PREDEF = 1;
	scan_commaList(hosts,0,scanListCall addhost1);
	HOSTS_PREDEF = 0;
}

static struct hostent *gethostbyNameAddrNocache(PCStr(name),PCStr(addr),int len,int type)
{	struct hostent *hp;

	if( 0 < RES_timeout(DNS_TIMEOUT) ){
		hp = Dgethostbynameaddr(name,addr,len,type);
	}else{
		/* this code is not used actually */
		vfuncp sPIPE;
		int timer;

		sPIPE = Vsignal(SIGPIPE,sigPIPE);
		timer = pushTimer("gethostbyNameAddr",sigALRM,DNS_TIMEOUT);
		if( (gotsig = sigsetjmpX(jmpEnv,1)) == 0 )
			hp = Dgethostbynameaddr(name,addr,len,type);
		else	hp = 0;
		signal(SIGPIPE,sPIPE);
		popTimer(timer);
	}
	LOGX_resRet++;
	if( hp == 0 ){
		LOGX_resUnk++;
	}
	return hp;

}
int RES_CACHEONLY(int flag)
{	int oflag;

	oflag = CACHE_ONLY;
	CACHE_ONLY = flag;
	return oflag;
}

int IsInetaddr(PCStr(addr))
{
	return addr != NULL && VSA_strisaddr(addr);
}
static int expireUnknown(Hostent *Hp,PCStr(wh),PCStr(name)){
	int byname = (name != 0);
	struct hostent *hp;
	int expired = 0;
	int now;
	int age;

	if( Hp == 0 )
		return 0;

	now = time(0);
	age = now - Hp->hc_mtime;
	hp = &Hp->hc_hostent;

	if(  byname && hp->h_addr_list[0] == 0
	 || !byname && hp->h_name[0] == 0
	)
	if( HOSTS_CACHE_UNKNOWN_MAX < age ){
		putResTrace("{%s:%s-disabled/%d:%s%s}",
			hp->h_name[0]?hp->h_name:"?",
			wh,age,
			hp->h_name[0]?"H":"-",
			hp->h_addr_list[0]?"A":"-"
		);
		expired = 2;
	}
	if( expired ){
		if( !lSINGLEP() && !ismainthread() ){
			/* 9.9.1 to suppress refresh in sub-threads,
			 * especially in TSwatcher
			 */
			Verbose("## ign expUnk (%s) byn=%d exp=%d\n",
				wh,byname,expired);
			return 0;
		}
	}
	return expired;
}

static CriticalSec resCSC;
static int findHostCacheExp(PCStr(name),PCStr(addr),int len,int type,int now,int nocache,struct hostent **hpp,Hostent **Hpp){
	Hostent *Hp;
	struct hostent *hp = 0;
	int valid = 0;
	int expired = 0;
	int age = 0;

	Hp = findHostCache(name,addr,len,type);
	if( Hp == 0 ){
		goto EXIT;
	}

	hp = &Hp->hc_hostent;
	if( Hp->hc_predef ){
	}else
	if( HOSTS_expired && Hp->hc_mtime < HOSTS_expired ){
		sv1log("expired HOSTS: %d %d %s\n",
			HOSTS_expired - Hp->hc_mtime,now - Hp->hc_mtime,
			hp->h_name?hp->h_name:"");
		expired = 1;
	}else{
		age = now - Hp->hc_mtime;
		if( nocache ){
			if( HOSTS_CACHE_LIFE_MIN < age )
			if( lSINGLEP() && age < 300 ){
			}else{
				expired = 1;
			}
		}else{
			if( HOSTS_CACHE_LIFE_MAX )
			if( HOSTS_CACHE_LIFE_MAX < age )
				expired = 1;
		}
		if( Hp->hc_okngcnt < 0 ){
			/* ignore the internal cache caused connect() error */
			expired = 1;
		}
		if( expired == 0 ){
			if( expireUnknown(Hp,"icache",name) )
				expired = 2;
		}
	}
	if( expired ){
	}else{
		valid = 1;
		if( hp->h_name[0] == 0 || hp->h_addr_list[0] == 0 ){
			/* this is a cached Unknown entry */
			hp = NULL;
		}else{
			if( DO_SHUFFLE )
			if( ADDRLIST_RR && Hp->hc_shuffled == 0 ){
				shift_addrlist(hp);
				Hp->hc_shuffled = 1;
			}
		}
	}
EXIT:
	*hpp = hp;
	*Hpp = Hp;
	return valid;
}
static struct {
	int R_hit0;
	int R_hit1;
	int R_busy;
	int R_miss;
	int R_updating;
} ReSt;
void dumpResStat(FILE *out){
	porting_dbg("Resolver: Hit=%d+%d Bsy=%d Mis=%d Fil=%d",
		ReSt.R_hit0,ReSt.R_hit1,ReSt.R_busy,
		ReSt.R_miss,
		NHosts
	);
}
int CachedHosts(int *siz){
	if( siz ) *siz = NHOSTS;
	return NHosts;
}
static struct hostent *gethostbyNameAddrX(int cache_only,int nocache,PCStr(name),PCStr(addr),int len,int type,int now,Hostent *Hp,struct hostent **cachedhpp);
#define gethostbyNameAddr(co,nm,ad,ln,ty) gethostbyNameAddrY(co,nm,ad,ln,ty,0)
static struct hostent *gethostbyNameAddrY(int cache_only,PCStr(name),PCStr(aaddr),int alen,int atype,Hostent **Hpp)
{	struct hostent *hp;
	int nocache;
	VSAddr sab;
	const char *addr = (char*)aaddr; /* VC++ does not allocate omitted argument */
	int len = alen;
	int type = atype;
	struct hostent *cachedhp = 0;
	int now;
	Hostent *Hp = 0;
	int updated;
	double Start;

	if( Hpp ) *Hpp = 0;
	if( name != NULL && *name == 0 ){
		Verbose("gethostbyNameAddr(empty)\n");
		return NULL;
	}

	LOGX_resReq++;
	Start = Time();

	if( name != NULL ){
		/* not to cache _-attr. into HOSTS cache */
		if( getHostPrefix(name,&name,VStrNULL) ){
		}
	}

	if( name != NULL && strtailstr(name,VSA_hostlocal()) )
		name = VSA_hostlocal();

	if( name && isinetAddr(name) ){
		VSA_atosa(&sab,0,name);
		len = VSA_decomp(&sab,&addr,&type,NULL);
		if( 2 <= LOGLEVEL )
		daemonlog("D","*** gethostbyname(%s) -> byaddr(%d,%d)\n",
			name,len,type);
		name = 0;
	}

	nocache = RES_CACHE_DISABLE;
	if( cache_only || CACHE_ONLY )
		nocache = 0;

	now = time(NULL);
	if( findHostCacheExp(name,addr,len,type,now,nocache,&hp,&Hp) ){
		ReSt.R_hit0++;
		LOGX_resHit++;
		goto EXIT;
	}
	if( cache_only || CACHE_ONLY )
	{
		hp = NULL;
		goto EXIT;
	}

	updated = 0;
	if( numthreads() ){
		updated = ReSt.R_updating;
		setupCSC("gethostbyNA",resCSC,sizeof(resCSC));
		enterCSC(resCSC);
		if( updated ){
			ReSt.R_busy++;
		}
	}
	if( updated
	&&( findHostCacheExp(name,addr,len,type,now,nocache,&hp,&Hp) ) ){
		ReSt.R_hit1++;
		LOGX_resHit++;
	}else{
		ReSt.R_miss++;
		ReSt.R_updating = 1;
		hp = gethostbyNameAddrX(cache_only,nocache,name,addr,len,type,
			now,Hp,&cachedhp);
		ReSt.R_updating = 0;
	}
	if( numthreads() ){
		leaveCSC(resCSC);
	}

EXIT:
	if( Hpp ) *Hpp = Hp;
	if( hp == NULL ){
		CONNERR_CANTRESOLV = 1;
	}
	LOGX_resTime += (int)(1000*(Time()-Start));
	if( lMULTIST() ){
		/* 9.8.2 with multi-threads, must not use hostent data in the
		 * common buffer of gethostbyxxxx(), so use the copy in cache.
		 */
		if( cachedhp ){
			return cachedhp;
		}
	}
	return hp;
}
static struct hostent *gethostbyNameAddrX(int cache_only,int nocache,PCStr(name),PCStr(addr),int len,int type,int now,Hostent *Hp,struct hostent **cachedhpp)
{	struct hostent *hp;
	struct hostent *chp;
	struct hostent *cachedhp = 0;
	double Start;
	CStr(func,1024);
	int rexpire;
	Hostent *CHp;
	int dif;

	Start = Time();
	setVStrEnd(resolv_errmsg.resolv_errmsg,0);

	rexpire = RES_HC_EXPIRE;
	if( nocache ){
		/* disalbling DNS cache for HTTP reload might be too heavy
		 * for large number of inline images loaded parallelly
		 */
		if( isWindowsCE() || lSINGLEP() ){
			if( name == 0 ){
				RES_HC_EXPIRE = 600;
			}else
			RES_HC_EXPIRE = 60;
		}else
		RES_HC_EXPIRE = 5;
		RES_CACHE_DISABLE = 0;
	}
	if( Hp && Hp->hc_okngcnt < 0 ){
		/* refresh the external cache caused connect() error */
		RES_HC_EXPIRE = -1;
	}
	if( RES_HC_EXPIRE != -1 ){
		if( expireUnknown(Hp,"xcache",name) ){
			RES_HC_EXPIRE = -1;
		}
	}
	hp = gethostbyNameAddrNocache(name,addr,len,type);
	if( hp == 0 ){
		putResTrace("{%s%s,exp=%d,nc=%d/%d,%.2f}",
			hp?"h":"-",Hp?"H":"-",
			RES_HC_EXPIRE,RES_CACHE_DISABLE,nocache,
			Time()-Start);
	}

	RES_HC_EXPIRE = rexpire;
	if( nocache ){
		RES_CACHE_DISABLE = nocache;
	}

	if( name != NULL )
		sprintf(func,"gethostbyname(%s)",name);
	else	sprintf(func,"gethostbyaddr(%s)",VSA_ltoa((unsigned char*)addr,len,type));

	if( hp == NULL )
	if( name != NULL && !IsInetaddr(name) || 1 < Time()-Start )
		daemonlog("E","%s unknown[%4.2fs] %s\n",func,
			Time()-Start,resolv_errmsg.resolv_errmsg);

	if( gotsig ){
		if( gotsig == SIGALRM )
			sv1log("*** TIMEOUT %s: %d secs.\n",func,DNS_TIMEOUT);
		else	sv1log("*** SIGPIPE on %s to DNS.\n",func);
	}else{
		if( Hp ){
			LOGX_resUpd++;
			if( hp == 0 ){
				/* don't erase the cache on refresh error */
				const char *oname;
				oname = Hp->hc_hostent.h_name;
				if( oname == 0 ) oname = "?";
				porting_dbg("-- RES update error (%s) %s",
					oname,name?name:"(addr)");
				Hp->hc_mtime = time(0);
				goto EXIT;
			}
			if( lSINGLEP() || lFXNUMSERV() || lHOSTSUPD() )
			if( CHp = findHostentInCache(hp,&chp,&dif) ){
				cachedhp = chp;
				CHp->hc_mtime = now;
				sv1log("## updated diff=%X\n",dif);
				/* should re-order accoding to hp */
				goto EXIT;
			}
			if( replaceHostCache(name,addr,len,type,now,Hp,hp) ){
				/* cachedhp = Hp->hc_hostnet; */
				goto EXIT;
			}
		}
		if( hp == 0 ){
			const char *aliases[2]; /**/
			const char *addrlist[2]; /**/
			int addrleng;

			if( name ){
				addrlist[0] = 0;
				addrleng = 4;
			}else{
				addrlist[0] = (char*)addr;
				addrleng = len;
				name = "";
			}
			aliases[0] = 0;
			addrlist[1] = 0;
			chp = addHostCache(name,aliases,type,addrleng,addrlist);
		}else{
			chp = addHostCacheOk(hp,name,func,Start);
			cachedhp = chp;
		}
	}
EXIT:
	*cachedhpp = cachedhp;
	return hp;
}

static char *satoa(VSAddr *sa,PVStr(host))
{	const char *addr;

	if( addr = VSA_ntoa(sa) )
		return strcpy(host,addr);
	else	return strcpy(host,"(AF_UNIX)");
}
static char *saton(VSAddr *sa,PVStr(host))
{	struct hostent *hp;
	const char *baddr;
	int blen,btype;

	if( VSA_afunix(sa,AVStr(host),128) )
		return (char*)host;

	blen = VSA_decomp(sa,&baddr,&btype,NULL);
	hp = gethostbyNameAddr(0,NULL,baddr,blen,btype);
	if( hp != 0 )
		return strcpy(host,hp->h_name);
	else	return satoa(sa,AVStr(host));
}
void printSock(VSAddr *sa,PVStr(sockname),PCStr(form))
{	const char *addr;
	const char *fp;
	char fc;
	CStr(host,512);
	refQStr(sp,sockname); /**/

	for( fp = form; fc = *fp; fp++ ){
	    assertVStr(sockname,sp+1);
	    if( fc != '%' ){
		setVStrPtrInc(sp,fc);
		continue;
	    }
	    fp++;
	    switch( *fp ){
		default: sp = Sprintf(AVStr(sp),"%%%c",*fp); break;
		case '%': setVStrPtrInc(sp,fc); break;
		case 'A': sp = Sprintf(AVStr(sp),"%s",satoa(sa,AVStr(host))); break;
		case 'H': sp = Sprintf(AVStr(sp),"%s",saton(sa,AVStr(host))); break;
		case 'P': sp = Sprintf(AVStr(sp),"%d",VSA_port(sa)); break;
	    }
	}
	XsetVStrEnd(AVStr(sp),0);
}

const char *gethostbyAddr(PCStr(addr),PVStr(host))
{	VSAddr sab;

	VSA_atosa(&sab,0,addr);
	return saton(&sab,AVStr(host));
}
static void setFIFOaddr(VSAddr *sap)
{
	VSA_atosa(sap,1,"127.0.0.1");
}

int sockAFUNIX(int sock)
{	VSAddr name;
	int leng;

	leng = sizeof(VSAddr);
	if( getsockname(sock,(SAP)&name,&leng) != 0 )
		return 0;
	return VSA_afunix(&name,VStrNULL,0);
}
static int xgetpeername(int sock,SAP name,int *lenp)
{	int slen,rcode;

	slen = *lenp;
	rcode = getpeername(sock,(SAP)name,lenp);
	if( rcode == 0 && *lenp <= 2 && VSA_afunix((VSAddr*)name,VStrNULL,0) )
	{
		*lenp = slen;
		rcode = getsockname(sock,(SAP)name,lenp);
	}
	return rcode;
}
#undef getpeername
/*
#ifdef __cplusplus
#define getpeername(s,n,l) xgetpeername(s,n,l)
#else
*/
#define getpeername xgetpeername
/*
#endif
*/

typedef int (*NFUNCP)(int,struct sockaddr*,int*);
static int gethostpeerName(int sock,PVStr(sockname),PCStr(form),NFUNCP func)
{	VSAddr sab;
	int rcode;
	int addrlen;

	VSA_atosa(&sab,0,"0.0.0.0");
	addrlen = sizeof(VSAddr);

	if( (*func)(sock,(struct sockaddr*)&sab,&addrlen) == 0 ){
		if( addrlen == 0 && file_isfifo(sock) )
			setFIFOaddr(&sab);

		printSock(&sab,AVStr(sockname),form);
		return 1;
	}else{
		strcpy(sockname,"?");
		return 0;
	}
}
int VA_gethostpeerNAME(int sock,PVStr(name),VAddr *Vaddr,NFUNCP func)
{	VSAddr sab;
	int addrlen;

	VSA_atosa(&sab,0,"0.0.0.0");
	addrlen = sizeof(VSAddr);

	if( (*func)(sock,(struct sockaddr*)&sab,&addrlen) == 0 ){
		if( addrlen == 0 && file_isfifo(sock) )
			setFIFOaddr(&sab);

		if(Vaddr){
			*Vaddr = AddrZero;
			Vaddr->a_type = VSA_addrX(&sab,Vaddr->a_ints.a_int);
			Vaddr->a_port = VSA_port(&sab);
			if( Vaddr->a_port == 0 && Vaddr->a_type == AF_INET ){
				Vaddr->a_flags |= VA_SOCKPAIR;
				Verbose("VA_get%sname(%d) for socketpair\n",
					func==getsockname?"sock":"peer",sock);
			}
		}
		if(name) printSock(&sab,AVStr(name),"%H");
		if(name){
			if( strtailstrX(name,".in-addr.arpa",1)
			 || strtailstrX(name,".ip6.int",1) ){
				CStr(oname,MaxHostNameLen);
				strcpy(oname,name);
				printSock(&sab,AVStr(name),"%A");
				sv1log("IGN-addr-name: %s [%s]\n",oname,name);
			}
		}
		return 1;
	}else{
		sv1tlog("FATAL: get{host|peer}name(%d) failed, errno=%d\n",
			sock,errno);
		if(Vaddr) *Vaddr = AddrNull;
		if(name) strcpy(name,"?");
		return 0;
	}
}
int gethostName(int sock,PVStr(sockname),PCStr(form))
{
	return gethostpeerName(sock,AVStr(sockname),form,getsockname);
}
int getpeerName(int sock,PVStr(sockname),PCStr(form))
{	int rcode;
	int sresolv;

	RES_orderPush("D",RES_ADDLAST);
	rcode = gethostpeerName(sock,AVStr(sockname),form,getpeername);
	RES_orderPop();
	return rcode;
}
int getpeersNAME(int sock,PVStr(name),PVStr(saddr),int *portp);
int getpeerAddr(int sock,PVStr(saddr))
{	int port;

	if( getpeersNAME(sock,VStrNULL,AVStr(saddr),&port) )
		return port;
	strcpy(saddr,"255.255.255.255");
	return -1;
}
int VA_getpeerNAME(int sock,VAddr *Vaddr)
{
	CStr(name,256);
	int siz;
	int len;
	int port;

	port = VA_gethostpeerNAME(sock,AVStr(name),Vaddr,getpeername);
	siz = sizeof(Vaddr->a_name);
	len = strlen(name);
	if( siz <= len ){
		daemonlog("F","Truncated long name %d < %d [%s]\n",siz,len,name);
		ovstrcpy(name,name+len-siz+1);
	}
	strcpy(Vaddr->a_name,name);
	return port;
}
int gethostAddr(int sock,PVStr(saddr))
{
	if( gethostName(sock,AVStr(saddr),"%A") )
		return sockPort(sock);
	else	return 0;
}
int VA_gethostNAME(int sock,VAddr *Vaddr)
{
	return VA_gethostpeerNAME(sock,AVStr(Vaddr->a_name),Vaddr,getsockname);
}
int gethostNAME(int sock,PVStr(name))
{	VAddr addr;

	if( VA_gethostpeerNAME(sock,AVStr(name),&addr,getsockname) )
		return addr.a_port;
	else	return 0;
}
int getpeerNAME(int sock,PVStr(name))
{	int rcode;
	int sresolv;
	VAddr addr;

	RES_orderPush("D",RES_ADDLAST);
	rcode = VA_gethostpeerNAME(sock,AVStr(name),&addr,getpeername);
	RES_orderPop();

	if( rcode )
		return addr.a_port;
	else	return 0;
}
int getpeersNAME(int sock,PVStr(name),PVStr(saddr),int *portp)
{	int rcode;
	VAddr addr;

	rcode = VA_gethostpeerNAME(sock,AVStr(name),&addr,getpeername);
	if( rcode ){
		if( portp ) *portp = addr.a_port;
		inetNtoa(htonl(addr.I3),AVStr(saddr));
	}
	return rcode;
}
const char *VA_inetNtoah(VAddr *Vaddr,PVStr(saddr))
{
	if( Vaddr->a_type == AF_INET6 || Vaddr->I0 || Vaddr->I1 || Vaddr->I2 ){
		int a4[4];
		int i;
		for( i = 0; i < 4; i++ )
			a4[i] = htonl(Vaddr->a_ints.a_int[i]);
		strcpy(saddr,VSA_ltoa((const unsigned char*)a4,16,AF_INET6));
	}else{
		inetNtoa(htonl(Vaddr->I3),AVStr(saddr));
	}
	return saddr;
}
int getorigdst(int sock,struct sockaddr *dst,int *dstlen);
int VA_getodstNAME(int sock,VAddr *Vaddr){
	return VA_gethostpeerNAME(sock,AVStr(Vaddr->a_name),Vaddr,getorigdst);
}

static int Accept(int sock,int isServer,int lockfd,PVStr(sockname))
{	int clsock;
	VSAddr sab;
	int addrlen;

	LOGX_tcpAcc++;

	addrlen = sizeof(VSAddr);
	clsock =  accept(sock,(SAP)&sab,&addrlen);

	if( clsock < 0 ){
		sv1log("## FATAL Accept(%d)=%d e%d\n",sock,clsock,errno);
	}else
	if( 0 <= clsock && addrlen == 0 ){
		sv1log("#### accept addrlen==0 [%d]\n",clsock);
		close(clsock);
		clsock = -1;
	}else
	if( sockname ){
		VSA_xtoap(&sab,AVStr(sockname),128);
	}
	return clsock;
}
/*
 *	a valid (non-negative) lockfd means that parallel accept() should
 *	be mutually excluded, and accept() should be protected from
 *	(SIGALRM) interrupt.
 */
#define sockport \
	(sprintf(sockportb,"[%d]:%d",sock,sockPort(sock)),sockportb)

int serverPid();
int accPollIn(int sock,int tmsec){
	int remto,to1,nready;
	for( remto = tmsec; 0 < remto; remto -= to1 ){
		if( 1000 < remto )
			to1 = 1000;
		else	to1 = remto;
		if( !procIsAlive(serverPid()) ){
			sv1log("--accPollIn(%d,%d/%d) exit svpid=%d\n",
				sock,remto,tmsec,serverPid());
			return -3;
		}
		if( nready = PollIn(sock,to1) )
			return nready;
	}
	return 0;
}
int ACCEPT1(int sock,int isServer,int lockfd,int timeout,PVStr(sockname))
{	int clsock;
	int NB;
	CStr(sockportb,32);

	if( lockfd < 0 && timeout == 0 )
		return Accept(sock,isServer,lockfd,AVStr(sockname));

	clsock = -1;

	if( 0 <= lockfd && lock_exclusiveTO(lockfd,timeout*1000,NULL) != 0 ){
		sv1log("## accept(%s) failed locking, errno=%d\n",sockport,errno);
		goto EXIT;
	}

	/*
	if( PollIn(sock,timeout*1000) <= 0 )
	*/
	if( accPollIn(sock,timeout*1000) <= 0 )
	{
		sv1log("## accept(%s) failed polling, errno=%d\n",sockport,errno);
		clsock = -3;
	}
	else{
		clsock = Accept(sock,isServer,lockfd,AVStr(sockname));
		if( clsock < 0 ){
			sv1log("## FAILED accept(%s)=%d, errno=%d\n",
				sockport,clsock,errno);
			clsock = -2;
		}else
		Verbose("## accept(%s)=%d\n",sockport,clsock);
	}

	if( 0 <= lockfd )
		lock_unlock(lockfd);

EXIT:
	return clsock;
}
int ACCEPT(int sock,int isServer,int lockfd,int timeout)
{
	return ACCEPT1(sock,isServer,lockfd,timeout,VStrNULL);
}

static int newsocket(PCStr(what),int d,int t,int p)
{	int sock;

	sock = socket(d,t,p);
	if( sock < 0 ){
		int serrno;
		serrno = errno;
		sv1tlog("FATAL: socket(%s) failed, errno=%d\n",what,errno);
		errno = serrno;
	}
	return sock;
}
int newSocket(PCStr(what),PCStr(opts)){
	int sock;
	int af = AF_INET;
	int ty = SOCK_STREAM;
	int pr = 0;
	int li = 32;

	if( isinList(opts,"udp") ) ty = SOCK_DGRAM;
	sock = socket(af,ty,pr);
	return sock;
}

void set_SRCPORT(PCStr(host),int port)
{
	if( streq(host,"*") )
		SRCHOST = "";
	else	SRCHOST = host;
	SRCPORT = port;
}
static int bind_inets(int sock,VSAddr *sap,int nlisten,int lport);
const char *isCLIFHOST(DGC*Conn,PCStr(host));
int print_SRCIF(PVStr(hostport),PCStr(host),int port);
void bind_SRCPORT(int sock)
{	CStr(sockname,256);
	VSAddr Vaddr;
	int rcode;
	IStr(hostport,MaxHostNameLen);

	if( SRCHOST == 0 )
		return;
	if( SRCHOST[0] == 0 && SRCPORT == 0 )
		return;

	setsockREUSE(sock,1);
	print_SRCIF(AVStr(hostport),SRCHOST,SRCPORT);
/*
	bind_insock(sock,SRCHOST,SRCPORT);
*/
	if( isCLIFHOST(MainConn(),SRCHOST) ){
		const char *CTX_clif_host(DGC*Conn);
		const char *clif;
		DGC *MainConn();
		int on = 1;
		int rcode;

		clif = CTX_clif_host(MainConn());
		VSA_atosa(&Vaddr,0,gethostaddr(clif));
		bind_inets(sock,&Vaddr,0,SRCPORT);
		gethostName(sock,AVStr(sockname),"%A:%P");
		sv1log("[%d] source port = %s:%d = %s\n",sock,clif,SRCPORT,sockname);
		if( streq(SRCHOST,"dontroute.clif.-") ){
			rcode = SETsockopt(sock,SOL_SOCKET,SO_DONTROUTE,&on,sizeof(on));
			sv1log("#### [%s] dontroute = %d\n",clif,rcode);
		}
		return;
	}
	if( *SRCHOST )
		VSA_atosa(&Vaddr,0,gethostaddr(SRCHOST));
	else	VSA_atosa(&Vaddr,0,"0.0.0.0");
	rcode =
	bind_inets(sock,&Vaddr,0,SRCPORT);

	gethostName(sock,AVStr(sockname),"%A:%P");
	sv1log("[%d] source port = %s = %s\n",sock,hostport,sockname);

	/*
	if( strheadstrX(SRCHOST,"-dontroute.",0) ){
	*/
	if( strheadstrX(SRCHOST,"_-DontRoute.",1)
	 || strheadstrX(SRCHOST,"_-DontRouteIfBound.",1) && rcode == 0
	 || strheadstrX(SRCHOST,"_-DontRouteIfNotBound.",1) && rcode != 0
	){
	int on = 1;
	int rcode;
	rcode = SETsockopt(sock, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on));
	Verbose("#### [%s] dontroute = %d\n",sockname,rcode);
	}
}
double SVHELLO_TIMEOUT;

/*
 * 9.6.0 retry connection to a server on known hosts (in PORXY, MOUNT, or so)
 * which might fail due to temporary shortage of the backlog of TCP conn. que.
 */
int ConRetried;
static int ConRetry(int sock,VSAddr *sap,PCStr(what),PCStr(portname),PCStr(hostname),int port,int ntry){
	int delay;
	const char *baddr;
	int bsize,btype;
	Hostent *Hp;

	if( getConnectFlags(what) & COF_DONTRETRY ){
		return 0;
	}
	if( CON_RETRY <= ntry+1 )
		return 0;
	if( VSA_af(sap) == AF_UNIX )
		return 0;

	bsize = VSA_decomp(sap,&baddr,&btype,NULL);
	Hp = findHostCache(NULL,baddr,bsize,btype);
	if( Hp == 0 || Hp->hc_predef == 0 && Hp->hc_predefa == 0 ){
		Hp = findHostCache(hostname,NULL,0,0);
		if( Hp == 0 || Hp->hc_predef == 0 )
			return 0;
	}
	/* port number should be tested too ... */

	ConRetried++;
	delay = 500 + ntry*200;
	porting_dbg("connect(%d) REFUSED*%d, retry after %dms ...",
		sock,ntry+1,delay);
	Verbose("connect(%d) REFUSED*%d, retry after %dms (%s) %s://%s:%d\n",
		sock,ntry+1,delay, what,portname,hostname,port);
	return delay;
}

static int sockopen1X(int asock,VSAddr *sap,PCStr(what),PCStr(portname),PCStr(hostname),Hostent *Hp)
{	int sock = -9; /* for the case (cx_numretry <= 0) */
	int rcode = -9;
	int iport = -9;
	int salen;
	CStr(aaddr,256);
	CStr(remote,256);
	CStr(local,256);
	double Time(),Start;
	int af;
	int ntry;
	IStr(cstat,256);

	ConnCtrl CXbuf,*CX = &CXbuf;
	initConnCtrl(CX,hostname,0);

	af = AF_INET;
	if( VSA_strisaddr(VSA_ntoa(sap)) == AF_INET6 ){
		af = AF_INET6;
	}
	Start = Time();

    /*
    for( ntry = 0; ntry < CON_RETRY; ntry++ ){
    */
    for( ntry = 0; ntry < CX->cx_numretry; ntry++ ){
	if( CONNCTRL && CX->cx_isset ){
		if( 0 < ntry ){
			if( CX->cx_interval ){
				sleep(CX->cx_interval);
			}
		}
	}
	if( 0 <= asock )
		sock = asock;
	else	sock = newsocket(what,af,SOCK_STREAM,0);
	if( sock < 0 )
		return -1;

	strcpy(aaddr,VSA_ntoa(sap));
	iport = VSA_port(sap);
	salen = VSA_size(sap);

	Verbose("%s connect %s://%s:%d\n",what,portname,hostname,iport);

	/*
	TODO in 10.X, SOCKOPT=dontroute:proto:dst:src
	set_DONTROUTE(sock,sap,what,portname,hostname);
	*/
	if( CONNCTRL && CX->cx_dontroute ){
		int on = 1;
		int rcode;
		rcode = SETsockopt(sock,SOL_SOCKET,SO_DONTROUTE,&on,sizeof(on));
		sv1log("#### [%s] DontRoute = %d\n",hostname,rcode);
	}
	bind_SRCPORT(sock);

	if( CONNCTRL && CX->cx_isset ){
		rcode = BconnectX(what,sock,sap,salen,AVStr(cstat),CX->cx_timeout1);
	}else
	rcode = Bconnect(what,sock,sap,salen,AVStr(cstat));
	if( asock < 0 && rcode < 0 && errno == ECONNREFUSED ){
		int ds;
		if( ntry+1 < CON_RETRY )
		if( ds = ConRetry(sock,sap,what,portname,hostname,iport,ntry) ){
			close(sock);
			sock = -1;
			msleep(ds);
			continue;
		}
	}
	if( asock < 0 && rcode < 0 && errno == ETIMEDOUT ){
		if( ntry+1 < CON_RETRY )
		if( IsConnected(sock,NULL) ){
		/*
		if( lCONRETRY() || IsConnected(sock,NULL) ){
		*/
			/* packet lost ? on Windows under heavy load */
			porting_dbg("connect(%d) retry ...",sock);
			close(sock);
			sock = -1;
			continue;
		}
	}
	if( CONNCTRL && CX->cx_isset ){
		if( rcode < 0 && 0 < CX->cx_numretry ){
			if( asock < 0 ){
				close(sock);
			}
			continue;
		}
	}
	if( 0 < ntry && rcode == 0 ){
		porting_dbg("connect(%d) retry*%d OK (%.3f) errno=%d",sock,
			ntry+1,Time()-Start,errno);
	}
	break;
    }
	inets_errmsg[0] = 0;
	if( rcode != 0 ){
		if( errno == ECONNREFUSED) CONNERR_REFUSED = 1;
		if( errno == ENETUNREACH ) CONNERR_UNREACH = 1;
		if( errno == EHOSTUNREACH) CONNERR_UNREACH = 1;
		if( errno == ETIMEDOUT   ) CONNERR_TIMEOUT = 1;
		
		if( errno == EISCONN || errno == EINPROGRESS )
			return sock;
		sprintf(inets_errmsg,
			"[%d] %s connect failed (%s) %s/%s:%d [%4.2fs] errno=%d",
				sock,what,af==AF_INET6?"IPv6":"IPv4",
				hostname,aaddr,iport, Time()-Start,errno);
		if( getConnectFlags(what) & COF_TERSE ){
		}else
		sv1log("%s\n",inets_errmsg);
		if( sock != asock )
			close(sock);
		return -1;
	}
	getpeerName(sock,AVStr(remote),"%A:%P");
	gethostName(sock,AVStr(local),"%A:%P");
	daemonlog("I","%s connected [%d] {%s <- %s} [%4.3fs]\n",
		what,sock,remote,local, Time()-Start);

	if( 0 < SVHELLO_TIMEOUT ){
		int timeout = (int)(SVHELLO_TIMEOUT*1000);
		if( timeout == 0 )
			timeout = 1;
		if( PollIn(sock,timeout) <= 0 ){
			close(sock);
			sock = -1;
			daemonlog("E","%s hello from server timedout\n",remote);
		}
	}

	return sock;
}
static int DISABLE_ERR_CONN = 120;
static int sockopen1(int asock,VSAddr *sap,PCStr(what),PCStr(portname),PCStr(hostname),Hostent *Hp){
	int csock;

	if( lSINGLEP() )
	if( Hp ){
		int now,elp;
		now = time(0);
		if( Hp->hc_okngcnt <= -5 ){
			elp = now - Hp->hc_conntime;
			if( elp < DISABLE_ERR_CONN ){
				porting_dbg("-- sockopen1 disabled %d/%d %s",
					elp,DISABLE_ERR_CONN,hostname);
				return -1;
			}
			Hp->hc_okngcnt = 0;
		}
		Hp->hc_conntime = time(0);
	}

	csock = sockopen1X(asock,sap,what,portname,hostname,0);

	if( Hp ){
		if( csock < 0 ){
			if( 0 < Hp->hc_okngcnt )
				Hp->hc_okngcnt = -1;
			else	Hp->hc_okngcnt--;
		}else{
			if( Hp->hc_okngcnt < 0 )
				Hp->hc_okngcnt = 1;
			else	Hp->hc_okngcnt++;
		}
	}
	return csock;
}
static int sockopens(int asock,int port,Hostent *Hp,struct hostent *hp,PCStr(what),PCStr(portname),PCStr(hostname))
{	int hi,hj;
	VSAddr sab;
	const char *haddr;
	const char *haddrs[128];
	int csock = -1;
	int hn,ho,hx;
	double Start;
	double Elp;
	struct hostent he;

	hn = 0;
	for( hi = 0; haddr = hp->h_addr_list[hi]; hi++ ){
		hn++;
		haddrs[hi] = haddr;
		if( elnumof(haddrs) <= hn )
			break;
	}
	he = *hp;
	he.h_addr_list = (char**)haddrs;

	if( lCONNSCAT() && Hp ){
		ho = getthreadgix(0) % 3;
		/*
		ho = Hp->hc_slide++ % 3;
		*/
	}else
	if( ADDRLIST_RR ){
		ho = ((int)(Time()*100)) % hn;
	}else{
		ho = 0;
	}

	for( hj = 0; hj < hn; hj++ ){
		hx = (ho+hj)%hn;
		haddr = haddrs[hx];
		VSA_htosa(&sab,port,&he,hx);
		if( VSA_af(&sab) == AF_INET6 ){
			const char *caddr = VSA_ntoa(&sab);
			if( VSA_strisaddr(caddr) != AF_INET6 ){
				/* IPv4 address in ::FFFF:x.x.x.x */
				VSA_atosa(&sab,VSA_port(&sab),caddr);
			}
		}
		Start = Time();
		csock = sockopen1(asock,&sab,what,portname,hostname,Hp);
		Elp = Time() - Start;

		if( csock < 0 || 0.5 < Elp ){
			IStr(saddr,128);
			VSA_xtoap(&sab,AVStr(saddr),sizeof(saddr));
			if( 0.5 < Elp )
			if( getConnectFlags(what) & COF_TERSE ){
			}else
			porting_dbg("-- SLOW-CONN[%d]%s %.2fs %d/%d/%d %s %s",
				csock,0<=asock?"+":" ",Elp,hx,ho,hn,
				Hp?"+":"-",saddr);

			if( Hp == 0 ){
			}else
			if( csock < 0 || Hp->hc_shifted < hn && 2.0 < Elp ){
				Hp->hc_okngcnt = 0;
				Hp->hc_shifted++;
				movelast_addrList("SLOW",Elp,csock,Hp,hp,
					haddrs[hx]);
			}
		}
		if( 0 <= csock )
			break;
	}
	return csock;
}

int gethostintMin(PCStr(host))
{	struct hostent *hp;
	VSAddr sab;
	const char *baddr;
	int btype,bsize;
	int ai;
	unsigned int addr,addr1;

	if( VSA_strisaddr(host) ){
		VSA_atosa(&sab,0,host);
		bsize = VSA_decomp(&sab,&baddr,&btype,NULL);
		hp = gethostbyNameAddr(0,NULL,baddr,bsize,btype);
	}else{
		hp = gethostbyNameAddr(0,host,NULL,0,0);
	}
	if( hp != NULL ){
		addr = 0xFFFFFFFF;
		for( ai = 0; hp->h_addr_list[ai]; ai++ ){
			VSA_htosa(&sab,0,hp,ai);
			addr1 = VSA_addr(&sab);
			if( addr1 < addr )
				addr = addr1;
		}
		return htonl(addr);
	}
	return -1;
}
static const char *_gethostaddr(PCStr(host),int cache_only)
{	struct hostent *hp;

	if( VSA_strisaddr(host) )
		return host;

	if( CONNCTRL ){
		const char *addr;
		if( (addr = stripHostPrefix(host)) != host )
		if( VSA_strisaddr(addr) ){
			return addr;
		}
	}

	if( hp = gethostbyNameAddr(cache_only,host,NULL,0,0) )
		return VSA_htoa(hp);

	return 0;
}
const char *gethostaddr(PCStr(host)){
	return _gethostaddr(host,0);
}
const char *gethostaddrX(PCStr(host)){
	const char *addr;
	if( addr = _gethostaddr(host,0) )
		return addr;
	else{
		sv1log("gethostaddrX unknown (%s) -> 255.255.255.255\n",host);
		return "255.255.255.255";
	}
}
const char *gethostaddr_fromcache(PCStr(host)){
	return _gethostaddr(host,1);
}

static int getHost_nbo(int cacheonly,PCStr(host),PVStr(primname),VSAddr*vsa);
static int __gethostint_nbo(int cacheonly,PCStr(host),PVStr(primname))
{
	return getHost_nbo(cacheonly,host,BVStr(primname),NULL);
}
static int getHost_nbo(int cacheonly,PCStr(host),PVStr(primname),VSAddr*vsa)
{	struct hostent *hp;
	VSAddr sab;
	int iaddr;
	int isAddr;
	int found;

/*
	iaddr = inet_addrV4(host);
	if( iaddr != -1 && primname == NULL )
		return iaddr;
*/

	isAddr = VSA_strisaddr(host);
	found = 0;
	if( isAddr && primname == NULL ){
		VSA_atosa(&sab,0,host);
		found = 1;
	}else
	if( hp = gethostbyNameAddr(cacheonly,host,NULL,0,0) ){
		if( primname != NULL )
			strcpy(primname,hp->h_name);
		VSA_htosa(&sab,0,hp,0);
		/*
		iaddr = htonl(VSA_addr(&sab));
		*/
		found = 2;
	}
	else
	if( isAddr ){
		/* leave primname unchanged ? */
		VSA_atosa(&sab,0,host);
		found = 3;
	}
	if( vsa ){
		if( found ){
			*vsa = sab;
		}
		return found;
	}
	if( found )
		return htonl(VSA_addr(&sab));
	else	return -1;
	/*
	return iaddr;
	*/
}
int VSA_getbyname(int cacheonly,PCStr(host),int port,VSAddr *vsa){
	int i4;
	IStr(primname,MaxHostNameLen);

	i4 = getHost_nbo(cacheonly,host,AVStr(primname),vsa);
	if( i4 != -1 ){
		VSA_setport(vsa,port);
		return i4;
	}else{
		return -1;
	}
}

int gethostint_nboV4(PCStr(host))
{
	return __gethostint_nbo(0,host,VStrNULL);
}
int VA_gethostint_nbo(PCStr(host),VAddr *Vaddr);
int strNetaddr(PCStr(host),PVStr(net))
{	VAddr Hosta;
	int hosti;

	VA_gethostint_nbo(host,&Hosta);
	hosti = ntohl(Hosta.I3);
	switch( (hosti >> 24) & 0xC0 ){
		case 0x00: hosti &= 0xFF000000; break;
		case 0x80: hosti &= 0xFFFF0000; break;
		case 0xC0: hosti &= 0xFFFFFF00; break;
	}
	if( net != NULL )
		sprintf(net,"%d.%d.%d.%d",
			0xFF&(hosti>>24),
			0xFF&(hosti>>16),
			0xFF&(hosti>>8),
			0xFF&(hosti));

	return htonl(hosti);
}

/*
 * true only when gethostbyXXX() is OK
 */
int hostIsResolvable(PCStr(host))
{
	return gethostintMin(host) != -1;
}
/*
 * true also when the host name is IP-address string
 */
int IsResolvable(PCStr(host))
{
	return VA_gethostint_nbo(host,NULL);
}
int VA_gethostint_nbo(PCStr(host),VAddr *Vaddr)
{	int a1;
	VAddr vab;
	VSAddr sab;
	int found;

	if( Vaddr == 0 )
		Vaddr = &vab;
	if( found = getHost_nbo(0,host,VStrNULL,&sab) ){
		*Vaddr = AddrZero;
		Vaddr->a_type = VSA_addrX(&sab,Vaddr->a_ints.a_int);
	}else	*Vaddr = AddrNull;
	return found;
}

int VA_atoVAddr(PCStr(aaddr),VAddr *Vaddr){
	VAddr Vaddrb;
	if( Vaddr == NULL )
		Vaddr = &Vaddrb;
	*Vaddr = AddrZero;
	if( xinet_pton(AF_INET6,aaddr,&Vaddr->a_ints.a_int) == 1 ){
		Vaddr->I0 = ntohl(Vaddr->I0);
		Vaddr->I1 = ntohl(Vaddr->I1);
		Vaddr->I2 = ntohl(Vaddr->I2);
		Vaddr->I3 = ntohl(Vaddr->I3);
		Vaddr->a_type = AF_INET6;
		return 1;
	}
	return 0;
}

int VA_gethostVAddr(int cacheonly,PCStr(host),PVStr(primname),VAddr *Vaddr)
{	int a1;
	VAddr vab;
	VSAddr sab;
	int found;

	if( Vaddr == 0 )
		Vaddr = &vab;
	found = getHost_nbo(cacheonly,host,AVStr(primname),&sab);
	if( found ){
		*Vaddr = AddrZero;
		Vaddr->a_type = VSA_addrX(&sab,Vaddr->a_ints.a_int);
	}else	*Vaddr = AddrNull;
	return found;
}
int VA_strtoVAddr(PCStr(saddr),VAddr *Vaddr)
{	int a1;

	a1 = inet_addrV4(saddr);
	if( a1 == -1 ){
		if( VA_atoVAddr(saddr,Vaddr) ){
			return 1;
		}
		if( Vaddr )
			*Vaddr = AddrNull;
		return 0;
	}else{
		if( Vaddr ){
			*Vaddr = AddrZero;
			Vaddr->I3 = ntohl(a1);
		}
		return 1;
	}
}

void VA_setVAddr(VAddr *Vaddr,PCStr(addr),int port,int remote)
{
	VA_strtoVAddr(addr,Vaddr);
	wordscanX(addr,AVStr(Vaddr->a_name),sizeof(Vaddr->a_name));
	Vaddr->a_port = port;
	if( remote )
		Vaddr->a_flags |= VA_REMOTE;
}

static int ipv4cmp(PCStr(a1),PCStr(a2))
{	int ai;

	for( ai = 0; ai < 4; ai++ )
		if( a1[ai] != a2[ai] )
			return 1;
	return 0;
}

/*
 * return non-zero if hp2 includes some element which is not
 * included in hp1.
 */
int hostentcmp(struct hostent *hp1,struct hostent *hp2)
{	const char *a1;
	const char *a2;
	int n1,n2;
	int diff;

	for( n1 = 0; hp1->h_addr_list[n1]; n1++ );
	for( n2 = 0; hp2->h_addr_list[n2]; n2++ );
	if( n1 < n2 )
		return 1;

	for( n2 = 0; a2 = hp2->h_addr_list[n2]; n2++ ){
		for( n1 = 0; a1 = hp1->h_addr_list[n1]; n1++ )
			if( ipv4cmp(a2,a1) == 0 )
				break;
		if( a1 == NULL )
			return 1;
	}
	return 0;
}

int __connectServer(int sock,PCStr(what),PCStr(portname),PCStr(hostname),int iport)
{	struct hostent *hp;
	Hostent *Hp = 0;
	VSAddr sab,*sap = &sab;
	CStr(hostnameb,MaxHostNameLen);
	const char *aaddr;
	CStr(path,1024);

	if( hostlocal2path(hostname,AVStr(path),sizeof(path)) ){
		sv1log("## connect %s ...\n",path);
		hostname = path;
	}

	if( hostname != NULL && isFullpath(hostname) ){
		sock = client_open_unX(what,sock,hostname,0);
		return sock;
	}

/*
	if( sock < 0 && ViaVSAPassociator(-1) && strncmp(portname,"VSAP",4) != 0 ){
		CStr(sockname,MaxHostNameLen);
		CStr(peername,MaxHostNameLen);
		sockname[0] = 0;
		sprintf(peername,"%s:%d",hostname,iport);
		sock = VSAPconnect(AVStr(sockname),AVStr(peername));
		if( 0 <= sock ){
			sv1log("#### connected via TELEPORT\n");
			return sock;
		}
		sv1log("#### connection via TELEPORT failed.\n");
	}
*/

	VSA_atosa(sap,iport,"0.0.0.0");
	inets_errmsg[0] = 0;

	if( hostname == NULL || hostname[0] == 0 ){
		hostname = hostnameb;
		strcpy(hostnameb,"localhost");
		if( !IsResolvable(hostnameb) )
			gethostname(hostnameb,sizeof(hostnameb));
	}

	if( VSA_strisaddr(hostname) ){
		VSA_atosa(sap,iport,hostname);
		return sockopen1(sock,sap,what,portname,hostname,0);
	}
	if( CONNCTRL ){
		const char *addr;
		if( (addr = stripHostPrefix(hostname)) != hostname )
		if( VSA_strisaddr(addr) ){
			VSA_atosa(sap,iport,addr);
			return sockopen1(sock,sap,what,portname,hostname,0);
		}
	}

	DO_SHUFFLE = 1;
	hp = gethostbyNameAddrY(0,hostname,NULL,0,0,&Hp);
	DO_SHUFFLE = 0;
	if( hp ){
		int nsock;
		struct hostent *nhp;

		nsock = sockopens(sock,iport,Hp,hp,what,portname,hostname);
		if( 0 <= nsock )
			return nsock;
/*
if( !nonblocking ){
	nhp = gethostbyNameAddrNocache(hostname);
	if( 0 < hostentcmp(hp,nhp) ){
		nsock = sockopens(sock,iport,nhp,what,portname,hostname);
		sv1log("## connect(%s) retried without hosts cache = %d\n",
			hostname,nsock);
		return nsock;
	}
}
*/
		return -1;
	}else
	if( aaddr = gethostaddr(hostname) ){
		VSA_atosa(sap,iport,aaddr);
		return sockopen1(sock,sap,what,portname,hostname,0);
	}else{
		CONNERR_CANTRESOLV = 1;
		sprintf(inets_errmsg,"%s unknown host '%s'",what,hostname);
		sv1log( "%s\n",inets_errmsg);
		return -1;
	}
}
int connectServer(PCStr(what),PCStr(portname),PCStr(hostname),int iport)
{
	return __connectServer(-1,what,portname,hostname,iport);
}
int client_open(PCStr(what),PCStr(portname),PCStr(hostname),int iport)
{
	return __connectServer(-1,what,portname,hostname,iport);
}

int hostaf(PCStr(hostname)){
	VSAddr sab;
	int af;

	if( isFullpath(hostname) )
		af = AF_UNIX;
	else
	if( getHost_nbo(0,hostname,VStrNULL,&sab) ){
		af = VSA_af(&sab);
	}else	af = AF_INET;
	return af;
}

int bind_insock(int sock,PCStr(host),int port);
int UDP_client_open1(PCStr(what),PCStr(portname),PCStr(hostname),int iport,PCStr(lhost),int lport)
{	int asock,rsock;
	CStr(path,256);

	if( hostlocal2path(hostname,AVStr(path),sizeof(path)) ){
		sv1log("## UDP connect %s = %s ...\n",hostname,path);
		hostname = path;
	}
	asock = socket(hostaf(hostname),SOCK_DGRAM,0);
/*
	if( isFullpath(hostname) )
		asock = socket(AF_UNIX,SOCK_DGRAM,0);
	else
	asock = socket(AF_INET,SOCK_DGRAM,0);
*/
	sv1log("UDP_client_open[%d] %s://%s:%d ...\n",asock,portname,hostname,iport);
	if( 0 <= lport )
		bind_insock(asock,lhost,lport);
	rsock = __connectServer(asock,what,portname,hostname,iport);
	if( rsock < 0 )
		close(asock);
	return rsock;
}
int UDP_client_open(PCStr(what),PCStr(portname),PCStr(hostname),int iport)
{
	return UDP_client_open1(what,portname,hostname,iport,NULL,-1);
}

int hostIFfor1(PVStr(hostIF),int udp,PCStr(proto),PCStr(rhost),int rport);
int hostIFfor(PCStr(rhost),PVStr(hostIF))
{
	if( hostIFfor1(AVStr(hostIF),1,"time",rhost,37) )
		return 1;
	if( hostIFfor1(AVStr(hostIF),0,"time",rhost,37) )
		return 1;
	if( hostIFfor1(AVStr(hostIF),0,"echo",rhost,7) )
		return 1;
	if( hostIFfor1(AVStr(hostIF),0,"domain",rhost,53) )
		return 1;
	if( hostIFfor1(AVStr(hostIF),0,"http",rhost,80) )
		return 1;
	return 0;
}
int hostIFfor1(PVStr(hostIF),int udp,PCStr(proto),PCStr(rhost),int rport)
{	int sock;

	setVStrEnd(hostIF,0);
	if( udp )
		sock = UDP_client_open("checkIF-UDP",proto,rhost,rport);
	else	sock = client_open("checkIF-TCP",proto,rhost,rport);

	if( 0 <= sock ){
		gethostNAME(sock,AVStr(hostIF));
		close(sock);
		if( hostIF[0] && strcmp(hostIF,"0.0.0.0") != 0 )
			return 1;
	}
	return 0;
}

int hostIFfor0(PVStr(hostIF),int udp,PCStr(proto),PCStr(rhost),int rport,int dontroute)
{	int sock,on;
	VSAddr sab;
	const char *aaddr;
	int alen,got;

	aaddr = gethostaddr(rhost);
	if( aaddr == NULL )
		return 0;
	alen = VSA_atosa(&sab,rport,aaddr);

	got = 0;
	sock = socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0);

	if( dontroute ){
		on = 1;
		SETsockopt(sock, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on));
	}
	if( connect(sock,(SAP)&sab,alen) == 0 )
		got = gethostAddr(sock,AVStr(hostIF));
	close(sock);
	return got;
}
int VSA_netcomp(VSAddr *vsa1,VSAddr *vsa2);
int isinSameSegment(VSAddr *vsa1,VSAddr *vsa2){
	if( VSA_af(vsa1) == AF_INET ){
		if( VSA_netcomp(vsa1,vsa2) == 0 ){
			return 1;
		}
	}
	return 0;
}
int DontRouteSocket(int sock,int on){
	int rcode;
	rcode = SETsockopt(sock,SOL_SOCKET,SO_DONTROUTE,&on,sizeof(on));
	return rcode;
}
int BindSocket(int sock,VSAddr *vsa,int port){
	int rcode;
	rcode = bind_inets(sock,vsa,0,port);
	Verbose("BindSocket(%d)=%d %s:%d\n",sock,rcode,VSA_ntoa(vsa),VSA_port(vsa));
	return rcode;
}

int MAX_BUFF_SOCKSEND = 0x4000;
int MAX_BUFF_SOCKRECV = 0x10000;
/*
int MAX_BUFF_SOCKRECV = 0x4000;
*/
void std_setsockopt(int sock)
{	int bsize;
	int On = 1, No = 0;

	SETsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &No, sizeof(No));
	bsize = MAX_BUFF_SOCKRECV;
	if( 0 < SOCK_SNDBUF_MAX && SOCK_SNDBUF_MAX < bsize ){
		bsize = SOCK_SNDBUF_MAX;
	}
	SETsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bsize,sizeof(bsize));
	bsize = MAX_BUFF_SOCKSEND;
	SETsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bsize,sizeof(bsize));
}

const char *ext_binder = "dgbind";
const char *binder_path;
int bindViaSudo(int sock,VSAddr *sap,int len);
int WaitXXX(int mode,int *sigp,int *statp);

int Bind(int sock,VSAddr *sap,int len)
{	const char *av[8]; /**/
	CStr(ab,256);
	refQStr(ap,ab); /**/
	CStr(path,1024);
	const char *host;
	int port,ac,rcode;
	int pid,xpid,xsig,xcode;

	rcode = bind(sock,(SAP)sap,len);
	if( rcode != 0 && errno == EACCES && INHERENT_fork() ){
		int serrno;
		serrno = errno;
		rcode = bindViaSudo(sock,sap,len);
		errno = serrno;
	}
	if( rcode != 0 && errno == EACCES && INHERENT_fork() ){
		int serrno;
		serrno = errno;

		if( binder_path == 0 ){
			strcpy(path,ext_binder);
			if( fullpathSUCOM(ext_binder,"r",AVStr(path)) == 0 ){
				sv1log("## command not found: %s\n",ext_binder);
				errno = serrno;
				return rcode;
			}
			sv1log("## dgbind = %s\n",path);
			binder_path = stralloc(path);
		}

		ac = 0;
		host = VSA_ntoa(sap);
		port = VSA_port(sap);
		av[ac++] = ap; strcpy(ap,ext_binder); ap += strlen(ap)+1;
		av[ac++] = ap; sprintf(ap,"%d",sock); ap += strlen(ap)+1;
		av[ac++] = ap; sprintf(ap,"%d",port); ap += strlen(ap)+1;
		av[ac++] = ap; strcpy(ap,host); ap += strlen(ap)+1;
		av[ac] = 0;

		/*
		if( fork() == 0 ){
		*/
		if( (pid = fork()) == 0 ){
			Execvp("Bind",binder_path,av);
			exit(-1);
		}
		/*
		wait(0);
		*/
		xcode = 0;
		xpid = WaitXXX(0,&xsig,&xcode);
		if( pid == xpid && xcode != 0 ){
			syslog_ERROR("pid=%d sig=%d code=%d\n",xpid,xsig,xcode);
		}
		if( 0 < sockPort(sock) ){
			rcode = 0;
			errno = 0;
		}
		else
		if( pid == xpid && xcode != 0 && xcode != 255 ){
			errno = xcode;
		}
		else	errno = serrno;
	}
	return rcode;
}
#undef bind
#define bind(s,n,l)	Bind(s,(VSAddr*)n,l)

static int ftp_conndata0(VSAddr *src,VSAddr *dst,VSAddr *laddr,int lport)
{	int sock;
	CStr(sockname,256);
	CStr(peername,256);
	int iport;
	int salen;
	int af;
	double Start = Time();
	IStr(cstat,256);

	if( src == NULL ){
		af = AF_INET;
	}else
	if( VSA_size(src) == sizeof(struct sockaddr_in6) )
		af = AF_INET6;
	else	af = AF_INET;
	sock = newsocket("ftp-data-con",af,SOCK_STREAM,0);
	if( sock == -1 ){
		sv1log("ftp_conndata: cannot create socket: %d.\n",errno);
		return -1;
	}

	if( src && (VSA_addr(src) || VSA_port(src)) ){
		setsockREUSE(sock,1);
		setsockSHARE(sock,1);
		salen = VSA_size(src);
		if( lFTPDATA_NOBIND() ){
			/* 9.9.5 immediate retry to reuse the same src-dst
			 * ports pair (ex. for LIST after RETR in WWW client)
			 * will fail or be blocked
			 */
		}else
		if( laddr == NULL || bind_inets(sock,laddr,0,lport) != 0 )
		if( bind(sock,(SAP)src,salen) != 0 ){
			const char *nladdr = laddr==NULL?"NLLL":VSA_ntoa(laddr);
			const char *nsrc = VSA_ntoa(src);
			/*
			sv1log("## ftp-conndata: NOT bound#1 err=%d\n",errno);
			 */
			sv1log("## ftp-conndata: NOT bound#1 err=%d [%s][%s]:%d\n",
				errno,nladdr,nsrc,VSA_port(src));
			VSA_setport(src,0);
			if( bind(sock,(SAP)src,salen) != 0 )
			sv1log("## ftp-conndata: NOT bound#2 err=%d\n",errno);
		}
	}

	printSock(dst,AVStr(peername),"%H/%A:%P");
	salen = VSA_size(dst);
	gethostName(sock,AVStr(sockname),"%A:%P");
	Verbose("FTP-DATA %s <= %s ...\n",peername,sockname);
	if( Bconnect("ftp-data",sock,dst,salen,AVStr(cstat)) != 0 ){
		close(sock);
		sv1log("ftp_conndata: connection refused %s->%s, errno=%d\n",
			sockname,peername,errno);
		return -1;
	}
	gethostName(sock,AVStr(sockname),"%A:%P");
	/*
	sv1log("ftp_conndata: connected %s->%s [%d]\n",sockname,peername,sock);
	*/
	daemonlog("E","ftp_conndata: connected %s->%s [%d](%.1f)\n",
		sockname,peername,sock,Time()-Start);
	return sock;
}
static int ftp_conndata(VSAddr *src,VSAddr *dst,VSAddr *laddr,int lport)
{	int rcode;

	rcode = ftp_conndata0(src,dst,laddr,lport);
	if( rcode == -1 && src && VSA_port(src) )
	if( laddr && lport == 0xFFFF0000 ){
		sv1log("#{ver9.9.4} don't retry without port# with SRCIF\n");
		/* 9.9.4 don't retry the port number of explicit automatic
		 * allocation with SRCIF as SRCIF="*:0:ftp-data-pasv-src"
		 */
	}else
	if( lFTPDATA_NOBIND() ){
		/* 9.9.4 this retrial was introduced in 6.1.14 for PASV */
	}else
	/*if( errno == ECONNREFUSED )*/
	{
		sv1log("ftp_conndata: retry without port# (%d)\n",
			VSA_port(src));
		VSA_setport(src,0);
		rcode = ftp_conndata0(src,dst,laddr,lport);
	}
	return rcode;
}

/*
 *	REUSE ON to restart server immediately.
 */

int S_ADDRNOTAVAIL;
int set_listenX(int sock,int nlisten);
static int bind_inet(int sock,VSAddr *sap,int nlisten)
{	int salen,rcode;
	const char *msg;
	CStr(hp,512);

	SETsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&REUSE,sizeof(REUSE));
	if( REUSEPORT )
		setsockSHARE(sock,1);
	salen = VSA_size(sap);
	rcode = bind(sock,(SAP)sap,salen);

	S_ADDRNOTAVAIL = 0;
	if( rcode != 0 ){
		switch( errno ){
		case EADDRINUSE: msg = "(the port is used by others)"; break;
		case EACCES:	 msg = "(you are not permitted user)"; break;
		case EADDRNOTAVAIL:
				S_ADDRNOTAVAIL = 1;
				msg = "(not a local port)";
				break;
		default:	 msg = ""; break;
		}
		VSA_xtoap(sap,AVStr(hp),sizeof(hp));
		svlog("bind_inet(%d,%s) failed: ERRNO=%d %s\n",sock,hp,errno,msg);
		return -1;
	}
	if( nlisten < 0 ) /* UDP bind */
		return rcode;

	if( nlisten == 0 ) /* don't start listen here */
		return 0;

	return set_listenX(sock,nlisten);
}

double BIND_TIMEOUT;
double BIND_TIMEOUT1; /* to override BIND_TIMEOUT temporarily */
double BINDENTER_TIMEOUT = 5; /* for binding entrances on restart */

static int bind_inets(int sock,VSAddr *sap,int nlisten,int lport)
{	int p1,p2,inc,xtry;
	int p0;
	int rcode = -1;

	double Start = Time();
	double timeout;
	if( BIND_TIMEOUT1 < 0 )
		timeout = -1;
	else
	if( 0 < BIND_TIMEOUT1 )
		timeout = BIND_TIMEOUT1;
	else	timeout = BIND_TIMEOUT;

	if( lport == 0xFFFF0000 ){
		p1 = p2 = 0;
	}else
	if( lport & 0xFFFF0000 ){
		p1 = (lport >> 16) & 0xFFFF;
		p2 = lport & 0xFFFF;
	}else{
		p1 = p2 = lport;
	}
	inc = p1 < p2 ? 1 : -1;

	p0 = p1;
	for( xtry = 0; xtry < 128; xtry++ ){
		VSA_setport(sap,p1);
		if( (rcode = bind_inet(sock,sap,nlisten)) == 0 )
		{
			/*
			return 0;
			*/
			rcode = 0;
			break;
		}
		if( p1 == p2 )
		{
			if( Time()-Start < timeout ){
				msleep(100);
				continue;
			}
			break;
		}
		p1 += inc;
		/* if( p2 < p1 ) p1 = p0; */
	}
	if( 0 < timeout ){
		IStr(port,128);
		VSA_satoap(sap,AVStr(port));
		daemonlog(rcode==0?"E":"F","Bind_inets(%s)*%d %.3f/%.2f %s\n",
			port,xtry,Time()-Start,timeout,
			rcode==0?"BOUND":"FAILED");
	}
	return rcode;
}

int set_listenX(int sock,int nlisten)
{	int rcode;

	if( nlisten <= 0 )
		return -1;

	rcode = listen(sock,nlisten);

	if( rcode == 0 )
		Verbose("listen(%d,%d) OK.\n",sock,nlisten);
	else	svlog("listen(%d,%d) failed: ERRNO=%d\n",sock,nlisten,errno);
	return rcode;
}

int bind_insock(int sock,PCStr(host),int port)
{	VSAddr sab;
	int rcode;
	const char *aaddr;
	int salen;

	if( host != NULL && host[0] != 0 )
		aaddr = gethostaddr(host);
	else	aaddr = NULL;
	if( aaddr == NULL )
		aaddr = "0.0.0.0";

	VSA_atosa(&sab,port,aaddr);
	salen = VSA_size(&sab);
	errno = 0;
	rcode = bind(sock,(SAP)&sab,salen);
	sv1log("bind_insock(%d,%s,%d) = %d, errno=%d\n",sock,host?host:"",port,
		rcode,errno);
	return rcode;
}

int connectTimeout(int sock,PCStr(host),int port,int timeout)
{	struct hostent *hp;
	VSAddr sab;
	int salen;
	int rcode;
	IStr(cstat,256);

	VSA_atosa(&sab,0,"255.255.255.255");
	if( VSA_strisaddr(host) ){
		VSA_atosa(&sab,port,host);
	}else{
		if( hp = gethostbyNameAddr(0,host,NULL,0,0) )
			VSA_htosa(&sab,port,hp,0);
		else	sv1log("ERROR: connectTimeout(%s) unknown host\n",host);
	}
	if( VSA_isaddr(&sab)  ){
		salen = VSA_size(&sab);
		rcode = connectTOX(sock,(SAP)&sab,salen,timeout,AVStr(cstat));
		return rcode;
	}
	close(sock);
	return -1;
}

int bindSock(int sock,PCStr(portname),int af,xPVStr(hostname),int portnum,int nlisten);

typedef int (*isFUNC)(PCStr(fmt),...);
int server_open(PCStr(portname),xPVStr(hostname),int portnum,int nlisten)
{	isFUNC logf;
	int rcode;
	int sock;
	int salen;
	CStr(path,1024);
	int af;

	if( hostlocal2path(hostname,AVStr(path),sizeof(path)) ){
		sv1log("## bind %s ...\n",path);
		setPStr(hostname,path,sizeof(path));
	}

	if( hostname != NULL && hostname[0] == '/' )
	{
		if( REUSE )
			unlink(path);
		return server_open_un(portname,AVStr(hostname),nlisten);
	}

	/* dolog = streq(portname,"RESPDIST"); */
	if( hostname && strcmp(hostname,"localhost") == 0 && portnum == 0 )
		logf = A_sv1vlog;
	else	logf = A_sv1log;

	(*logf)("server_open(%s,%s:%d,listen=%d)\n",
		portname,hostname?hostname:"*",portnum,nlisten);

	af = AF_INET;
	if( 0 < AF_INET6 ){
		if( IPV6_v6also
		 || hostname != NULL && streq(hostname,"*")
		 || hostname != NULL && hostaf(hostname) == AF_INET6
		 || hostname != NULL && VSA_strisaddr(hostname) == AF_INET6
		){
			af = AF_INET6;
		}
	}

RETRY:
	switch( nlisten ){
		case -1: sock = newsocket(portname,af,SOCK_DGRAM,0); break;
		default: sock = newsocket(portname,af,SOCK_STREAM,0);
	}

	if( sock < 0 )
	{
		if( af == AF_INET6 )
		if( streq(hostname,"*") ){
			af = AF_INET;
			goto RETRY;
		}
		return -1;
	}
	sock = bindSock(sock,portname,af,BVStr(hostname),portnum,nlisten);
	return sock;
}
int bindSock(int sock,PCStr(portname),int af,xPVStr(hostname),int portnum,int nlisten){
	isFUNC logf;
	VSAddr sab;
	struct hostent *hp;

	logf = A_sv1log;
	if( af < 0 )
		af = AF_INET;

	if( af == AF_INET6 ){
		int on,err;
		if( streq(hostname,"*") )
			on = 0;
		else
		if( streq(hostname,IPV4MAPV6) )
			on = 0;
		else
		if( IPV6_v4also || IPV6_v6also )
			on = 0;
		else	on = 1;
		err = SETsockopt(sock,IPPROTO_IPV6,IPV6_V6ONLY,&on,sizeof(on));
		sv1log("## V6ONLY=%s %s\n",on?"ON":"OFF",err?"ERROR":"OK");
	}
	if( streq(hostname,"*") )
		setVStrEnd(hostname,0);

	if( af == AF_INET6 )
		VSA_atosa(&sab,0,"::");
	else
	VSA_atosa(&sab,0,"0.0.0.0");
	if( hostname != NULL && hostname[0] != 0 ){
		if( VSA_strisaddr(hostname) ){
			VSA_atosa(&sab,0,hostname);
			(*logf)("server_open: %s:%d\n",hostname,portnum);
		}else
		if( hp = gethostbyNameAddr(0,hostname,NULL,0,0) ){
			VSA_htosa(&sab,0,hp,0);
			(*logf)("server_open: %s:%d\n",hostname,portnum);
		}
		else{
			if( !VSA_strisaddr(hostname) ){
				sv1log("ERROR: hostname unknown: %s\n",hostname);
				close(sock);
				return -1;
			}
			VSA_atosa(&sab,0,hostname);
		}
	}
	VSA_setport(&sab,portnum);
	if( bind_inets(sock,&sab,nlisten,portnum) != 0 ){
		close(sock);
		sv1log("server_open() failed\n");
		return -1;
	}
	if( portnum == 0 ){
		(*logf)("server_open(%s,%s:%d/%d) BOUND\n",portname,
			hostname?hostname:"*",portnum,sockPort(sock));
	}else
	(*logf)("server_open(%s,%s:%d) BOUND\n",portname,hostname?hostname:"*",portnum);
	return sock;
}
int bindSocket(int sock,PCStr(host),int port){
	VSAddr sab;
	int salen;
	const char *aaddr;
	int rcode;

	aaddr = gethostaddr(host);
	if( aaddr == NULL )
		return -1;
	salen = VSA_atosa(&sab,port,aaddr);
	rcode = bind(sock,(SAP)&sab,salen);
	return rcode;
}

int find_openport(PCStr(what),PCStr(host),int port,int nlisten)
{	int fd,portx;
	CStr(hostx,MaxHostNameLen);
	const char *addr;
	CStr(hostb,64);

	if( *host == 0 )
		host = "0.0.0.0";
	else{
		if( addr = gethostaddr(host) ){
			strcpy(hostb,addr);
			host = hostb;
		}else	host = "0.0.0.0";
	}
	for( fd = 0; fd < FD_SETSIZE; fd++ ){
		if( (portx = gethostAddr(fd,AVStr(hostx))) <= 0 )
			continue;

		if( portx == port && hostcmp(host,hostx) == 0 ){
			int isudp = isUDPsock(fd);
			if( (nlisten<0 && !isudp) || (0<nlisten && isudp) )
				continue;
			sv1log("FOUND: %s [%d] %s:%d\n",what,fd,hostx,port);
			return fd;
		}
	}
	return -1;
}
int findopen_port(PCStr(what),PVStr(host),int port,int nlisten)
{	int sock;

	sock = find_openport(what,host,port,nlisten);
	if( sock < 0 )
		sock = server_open(what,AVStr(host),port,nlisten);
	return sock;
}

void adduniqlist(int mac,const char *names[],PCStr(name1))
{	int nx;
	const char *cname;

	for( nx = 0; cname = names[nx] ; nx++ ){
		if( strcasecmp(cname,name1) == 0 )
			return;
	}
	if( mac <= nx ){
		return;
	}
	names[nx++] = stralloc(name1);
	names[nx] = NULL;
}
static void adduniqlist_host(int mac,const char *names[],struct hostent *hp)
{	int nx;

	if( hp->h_name )
		adduniqlist(mac,names,hp->h_name);

	if( hp->h_aliases )
	for( nx = 0; hp->h_aliases[nx]; nx++ )
		adduniqlist(mac,names,hp->h_aliases[nx]);
}

int sethostcache(PCStr(host),int mark_predef)
{	VSAddr sab;
	const char *aaddr;
	const char *baddr;
	int blen,btype;
	struct hostent *chp,*hp;
	CStr(sorder,RESOLVERS_SIZ);
	CStr(order1,RESOLVERS_SIZ);
	int ox;
	const char *aliases[128]; /**/
	int found,nx;
	int predef_sav;
	Hostent *Hp;

	if( Hp = findHostCache(host,NULL,0,0) )
	if( Hp->hc_predef )
	{
		/* 9.0.6 don't repeat in OnetimeServer or on Windows */
		return 1;
	}

	found = -1;
	predef_sav = HOSTS_PREDEF;
	HOSTS_PREDEF = mark_predef;

	aaddr = gethostaddr(host);
	if( aaddr == NULL )
		goto EXIT;
	VSA_atosa(&sab,0,aaddr);
	blen = VSA_decomp(&sab,&baddr,&btype,NULL);

	chp = gethostbyNameAddr(1,NULL,baddr,blen,btype);
	if( chp == NULL )
		goto EXIT;

	aliases[0] = aliases[1] = 0;
	adduniqlist_host(elnumof(aliases),aliases,chp);

	found = 0;
	RES_orderGet(AVStr(sorder));

	/*
	 * Try gather host name aliases in all of available resolvers.
	 * Maybe this is necessary to make revese-MOUNT work well...
	 */
	for( ox = 0; ox = RES_next_res(sorder,ox,AVStr(order1),VStrNULL); ){
		if( order1[0] == 'C' /* cache */ ){
			/* Maybe cache is the first alternative in resolvers
			 * so the result found above is that of the cache ...
			 */
			continue;
		}
		if( order1[0] == 'S' /* sys */ ){
			/* Some system (Windows, Solaris, ...) would block
			 * long time in system's standard gethostbyXXXX() ...
			 */
			continue;
		}

		RES_orderPush(order1,RES_ALONE);

		hp = gethostbyNameAddrNocache(NULL,baddr,blen,btype);

		if( hp != NULL ){
			adduniqlist_host(elnumof(aliases),aliases,hp);
			found++;
		}
	}

	chp->h_aliases = (char**)dupv((const char**)&aliases[1],0);

	for( nx = 0; aliases[nx]; nx++ )
		free((char*)aliases[nx]);

	RES_orderPop();

/*{ CStr(hosts,4096); dump_HOSTS(hosts); fprintf(stderr,"%s\n",hosts); }*/

EXIT:
	HOSTS_PREDEF = predef_sav;
	return found;
}
void sethostcache_predef(PCStr(name),PCStr(addr),int len,int type)
{	Hostent *Hp;
	CStr(hosts,2048);

	if( Hp = findHostCache(name,addr,len,type) )
    {
	if( !Hp->hc_predef ){
		dump_HOST1(AVStr(hosts),&Hp->hc_hostent);
		Verbose("HOSTS[%d]=%s marked PREDEF\n",Hp->hc_index,hosts);
		Hp->hc_predef = 1;
	}
    }else{
	if( name != NULL && VSA_strisaddr(name) ){
		if( Hp = findHostCacheByaddr(name) ){
			Hp->hc_predefa = 1;
		}
	}
    }
}

int getpeerVSAddr(int sock,VSAddr *vsa){
	int addrlen;
	addrlen = sizeof(VSAddr);
	bzero(vsa,sizeof(VSAddr));
	return getpeername(sock,(SAP)vsa,&addrlen);
}
int getsockVSAddr(int sock,VSAddr *vsa){
	int addrlen;
	addrlen = sizeof(VSAddr);
	bzero(vsa,sizeof(VSAddr));
	return getsockname(sock,(SAP)vsa,&addrlen);
}
int newsockBound(int osock,int udp,VSAddr *vsa){
	VSAddr ovsa;
	int nsock;
	int rcode;
	int alen,af;
	const char *addr,*port;
	CStr(cntl,256);
	CStr(name,256);

	if( getsockVSAddr(osock,&ovsa) != 0 ){
		sv1log("ERROR newsockBound(%d) CANT GET ADDR\n",osock);
		return -1;
	}
	alen = VSA_decomp(&ovsa,&addr,&af,&port);
	nsock = newsocket("newsockBound",af,udp?SOCK_DGRAM:SOCK_STREAM,0);
	if( nsock < 0 ){
		sv1log("ERROR newsockBound() CANT GET SOCKET\n");
		return -1;
	}
	*vsa = ovsa;
	VSA_setport(vsa,0);
	rcode = Bind(nsock,vsa,VSA_size(vsa));

	getsockVSAddr(nsock,vsa);
	gethostName(nsock,AVStr(name),"%A:%P");

	printSock(&ovsa,AVStr(cntl),"%A:%P");
	sv1vlog("newsockBound(%s) = %s\n",cntl,name);
	return nsock;
}
int connectVSAddr(int sock,VSAddr *vsa){
	int rcode;
	rcode = connect(sock,(SAP)vsa,VSA_size(vsa));
	return rcode;
}

int sockHostport(int sock,int *portp)
{	int addrlen,addr;
	VSAddr sab;

	addrlen = sizeof(VSAddr);
	bzero(&sab,sizeof(VSAddr));
	if( getsockname(sock,(SAP)&sab,&addrlen) == 0 ){
		if( addrlen == 0 && file_isfifo(sock) )
			setFIFOaddr(&sab);
		if( portp != 0 )
			*portp = VSA_port(&sab);
		addr = VSA_addr(&sab);
		return addr;
	}
	if( portp != 0 )
		*portp = 0;
	return -1;
}
int sockPort(int sock)
{	int port;

	if( sockHostport(sock,&port) != -1 )
		return port;
	else	return 0;
}
int peerHostport(int sock,int *portp)
{	int addrlen;
	int addr;
	VSAddr sab;

	addrlen = sizeof(VSAddr);
	if( getpeername(sock,(SAP)&sab,&addrlen) == 0 ){
		if( addrlen == 0 && file_isfifo(sock) )
			setFIFOaddr(&sab);
		if( portp != 0 )
			*portp = VSA_port(&sab);
		addr = VSA_addr(&sab);
		return addr;
	}
	return -1;
}
int peerPort(int sock)
{	int port;

	if( peerHostport(sock,&port) != -1 )
		return port;
	else	return 0;
}
void peerHostaddrV4(int sock,unsigned char *rhost)
{	int ai;
	int iaddr;

	iaddr = peerHostport(sock,NULL);
	for( ai = 0; ai < 4; ai++ )
		rhost[ai] = (iaddr >> (3-ai)*8) & 0xFF;
}
int sockFromMyself(int sock)
{
	return sockHostport(sock,NULL) == peerHostport(sock,NULL);
}
void flush_socket(int fd)
{
	send(fd,"",0,MSG_OOB);  /* push packets before the timeout */
}

/*
 * Data connection should be via Socks if the control connection is via Socks.
 * Source IP address of data connection should be same with that of control
 * connection, and source port number should be be L-1 where the port number
 * of control connection is L.
 */
int isViaYYMUX(DGC*Conn,int fd,PCStr(proto),PCStr(host),int port);
int connect_ftp_data(DGC*Conn,PCStr(port),int cntrlsock,PCStr(lhost),int lport)
{	VSAddr ldata_addr;
	int lsock;
	CStr(hostnam,128);
	int portnum;
	int r_ina,c_ina,trydirect;
	int addrlen;
	VSAddr srcport_buff,*srcport;
	VSAddr laddrb,*laddr;

	addrlen = sizeof(VSAddr);
	getpeername(cntrlsock,(SAP)&ldata_addr,&addrlen); /* for |||PORT| */
	VSA_ftptosa(&ldata_addr,port);
	strcpy(hostnam,VSA_ntoa(&ldata_addr));
	portnum = VSA_port(&ldata_addr);

	if( toTunnel(Conn) ){
		lsock = connectViaTunnel(Conn,"ftp-data",hostnam,portnum);
		if( 0 <= lsock ){
			return lsock;
		}
	}

	srcport = NULL;
	if( cntrlsock < 0 ){
		trydirect = 1;
	}else{
		r_ina = inet_addrV4(hostnam);
		c_ina = peerHostport(cntrlsock,NULL);
		if( r_ina == c_ina )
			trydirect = 1;
		else	trydirect = 0; /* maybe via Socks */
/* the control connection can be connected via a proxy other than Socks,
 * for example, via CONNECT/HTTP, thus the data connections should be
 * routed following CONNECT parameter like the routing of control
 * connections. 
 */

		addrlen = sizeof(VSAddr);
		if( getsockname(cntrlsock,(SAP)&srcport_buff,&addrlen) == 0 )
		if( addrlen != 0 ){
			srcport = &srcport_buff;
			VSA_setport(srcport,VSA_port(srcport)-1);
		}
	}

	laddr = NULL;
	if( *lhost != 0 || lport != 0 ){
		laddr = &laddrb;
		if( *lhost ){
			VSA_atosa(laddr,0,gethostaddr(lhost));
		}else
		if( srcport )
			*laddr = *srcport;
		else	VSA_atosa(laddr,0,"0.0.0.0");

		if( lport == 0 && srcport )
			lport = VSA_port(srcport);
	}

	lsock = -1;
	if( lsock == -1 && ViaVSAPassociator(cntrlsock) ){
		CStr(sockname,MaxHostNameLen);
		CStr(peername,MaxHostNameLen);
		sockname[0] = 0;

		if( VSAPgetsockname(Conn,cntrlsock,AVStr(sockname)) == 0 ){
			refQStr(dp,sockname); /**/
			int port;
			if( dp = strchr(sockname,':') ){
				dp++;
				/*if( port = atoi(dp) )
					sprintf(dp,"%d",port-1);
				else*/	sprintf(dp,"0");
			}
			sv1log("## FTP/VSAP CONNECT SOCK=%s\n",sockname);
		}

		sprintf(peername,"%s:%d",hostnam,portnum);
		lsock = CTX_VSAPconnect(Conn,AVStr(sockname),AVStr(peername));
	}
	if( lsock == -1 && isViaYYMUX(Conn,cntrlsock,"ftp-data",hostnam,portnum) ){
		set_realserver(Conn,"ftp-data",hostnam,portnum);
		lsock = ConnectViaYYMUX(Conn,NULL,0);
	}

	if( lsock == -1 && trydirect )
		lsock = ftp_conndata(srcport,&ldata_addr,laddr,lport);

	/* GetViaSocks() can be time consuming due to gethostintMin() */
	if( lsock == -1 && GetViaSocks(Conn,hostnam,portnum) )
		lsock = connectViaSocks(Conn,hostnam,portnum,VStrNULL,NULL);

	if( lsock == -1 ){
		int ftpdataViaSSLtunnel(DGC*Conn,PCStr(host),int port);
		lsock = ftpdataViaSSLtunnel(Conn,hostnam,portnum);
	}

	if( lsock == -1 && !trydirect )
		lsock = ftp_conndata(srcport,&ldata_addr,laddr,lport);

	return lsock;
}

int setupDATAviaNAT(DGC *Conn,VSAddr *svsock,VSAddr *svpeer,PVStr(mport));
int bind_ftp_dataX(DGC*Conn,PVStr(mport),PCStr(server),int iport,int cntrlsock,int PASV,PCStr(lhost),int lport);
int bind_ftp_data(DGC*Conn,PVStr(mport),PCStr(server),int iport,int cntrlsock,int PASV,PCStr(lhost),int lport)
{	int sock,sREUSE,sREUSEPORT;

	if( isWindows() ){
	sREUSE = REUSE; REUSE = 0;
	}
	sREUSEPORT = REUSEPORT; REUSEPORT = 0;

	sock = bind_ftp_dataX(Conn,AVStr(mport),server,iport,cntrlsock,PASV,lhost,lport);

	if( isWindows() ){
	REUSE = sREUSE;
	}
	REUSEPORT = sREUSEPORT;
	return sock;
}
int bind_ftp_dataX(DGC*Conn,PVStr(mport),PCStr(server),int iport,int cntrlsock,int PASV,PCStr(lhost),int lport)
{	int dsock;
	const char *aaddr;
	VSAddr svhost,svsock,svpeer,svdata;
	int addrlen;
	CStr(remote,256);
	CStr(local,256);
	int af;

	if( fromTunnel(Conn,cntrlsock) ){
		VSA_atosa(&svsock,0,"127.0.0.1");
		goto BIND;
	}

	if( ViaVSAPassociator(cntrlsock) ){
		CStr(sockname,256);
		int ax[4],bport;

		sockname[0] = 0;
		if( VSAPgetsockname(Conn,cntrlsock,AVStr(sockname)) == 0 ){
			refQStr(dp,sockname); /**/
			if( dp = strchr(sockname,':') )
				Xstrcpy(QVStr(dp+1,sockname),"0");
		}
		sv1log("## FTP/VSAP BIND PASV=%d SOCK=%s\n",PASV,sockname);
		dsock = CTX_VSAPbind(Conn,AVStr(sockname),1);
		if( 0 <= dsock ){
			sscanf(sockname,"%d.%d.%d.%d:%d",
				&ax[0],&ax[1],&ax[2],&ax[3],&bport);
			sprintf(mport,"%d,%d,%d,%d,%d,%d",
				ax[0],ax[1],ax[2],ax[3],
				(bport>>8)&0xFF,bport&0xFF);
			return dsock;
		}
	}

	if( aaddr = gethostaddr(server) ){
		VSA_atosa(&svhost,iport,aaddr);
		VSA_xtoap(&svhost,AVStr(remote),sizeof(remote));
		/*
		sv1log("FTP-control-remote: %s\n",remote);
		*/
		sv1log("FTP-control-remote: %s [%d]\n",remote,cntrlsock);
	}

	addrlen = sizeof(VSAddr);
	if( getsockname(cntrlsock,(SAP)&svsock,&addrlen) != 0 || addrlen == 0 ){
		sv1log("cannot make FTP data port: no control conn-1.\n");
		return -1;
	}
	addrlen = sizeof(VSAddr);
	if( getpeername(cntrlsock,(SAP)&svpeer,&addrlen) != 0 || addrlen == 0 ){
		sv1log("cannot make FTP data port: no control conn-2.\n");
		return -1;
	}

	if( VSA_comp(&svhost,&svpeer) != 0 ){
		/* not connected directly */
		VSAddr vlocal;

		/* it should be direct except for a test
		if( PASV && sockFromMyself(cntrlsock) ){
		}
		 */
		if( VSA_getViaSocks(Conn,server,0,&vlocal) )
		{	CStr(bhost,64);
			int bport;
			VSAddr ba;

			dsock = bindViaSocks(Conn,server,iport,AVStr(bhost),&bport);
			if( 0 <= dsock ){
				if( streq(bhost,"0.0.0.0") ){ /* wild card */
					strcpy(bhost,VSA_ntoa(&vlocal));
					sv1log("BIND 0.0.0.0 -> %s\n",bhost);
				}
				VSA_atosa(&ba,bport,bhost);
				VSA_prftp(&ba,BVStr(mport));
				return dsock;
			}
		}
	}


BIND:
	if( addrlen == sizeof(struct sockaddr_in6) ) /*addrlen of client-sock*/
		af = AF_INET6;
	else	af = AF_INET;
	dsock = newsocket("ftp-data-acc",af,SOCK_STREAM,0);
	/*
	dsock = newsocket("ftp-data-acc",AF_INET,SOCK_STREAM,0);
	*/
	if( dsock < 0 )
		return -1;
	if( *lhost != 0 || lport != 0 ){
		if( *lhost )
			VSA_atosa(&svdata,0,gethostaddr(lhost));
		else{
			svdata = svsock;
			VSA_setport(&svdata,0);
		}
		if( bind_inets(dsock,&svdata,1,lport) == 0 )
			goto BOUND;
	}
	svdata = svsock;

/*
## BUG ? ###################################
this seems the missunderstanding of specification?
this is capable on FreeBSD,
but repetitive lport usage makes remote server wait timeout...
*/
/* V8.0.0 don't use L-1 for PASV
if( VSA_port(&svdata) != 0 )
if( PASV ){
VSA_setport(&svdata,VSA_port(&svdata)-1);
if( bind_inet(dsock,&svdata,1) == 0 ) goto BOUND;
 }
*/
	VSA_setport(&svdata,0);
	if( bind_inet(dsock,&svdata,1) == 0 )
		goto BOUND;

	VSA_atosa(&svdata,0,"0.0.0.0");
	/*
	if( bind_inet(dsock,NULL,1) != 0 ){
	*/
	if( bind_inet(dsock,&svdata,1) != 0 ){
		sv1log("ERROR: Cannot bind.\n");
		close(dsock);
		return -1;
	}
BOUND:
	addrlen = sizeof(VSAddr);
	getsockname(dsock,(SAP)&svdata,&addrlen);

	setupDATAviaNAT(Conn,&svsock,&svpeer,AVStr(mport));
	/*
	{	const char *claddr;
		CStr(gwhost,256);
		int clport,gwport;
 
		claddr = VSA_ntoa(&svpeer);
		clport = VSA_port(&svpeer);
		strcpy(gwhost,claddr);
		if( SRCIFfor(Conn,"tcpbound",claddr,clport,AVStr(gwhost),&gwport) ){
			VSA_prftp(&svsock,BVStr(mport));
			VSA_atosa(&svsock,0,gethostaddr(gwhost));
		}
	}
	*/

	VSA_setport(&svsock,VSA_port(&svdata));
	VSA_prftp(&svsock,BVStr(mport));
	VSA_xtoap(&svsock,AVStr(local),sizeof(local));
	sv1log("FTP-data-local[%d]: %s\n",dsock,local);
	return dsock;
}
int setupDATAviaNAT(DGC *Conn,VSAddr *svsock,VSAddr *svpeer,PVStr(mport)){
	const char *claddr;
	CStr(gwhost,256);
	int clport,gwport;
 
	claddr = VSA_ntoa(svpeer);
	clport = VSA_port(svpeer);
	strcpy(gwhost,claddr);
	if( SRCIFfor(Conn,"tcpbound",claddr,clport,AVStr(gwhost),&gwport) ){
		VSA_prftp(svsock,BVStr(mport));
		VSA_atosa(svsock,0,gethostaddr(gwhost));
		sv1log("--FTPdata [%s]NAT[%s]\n",mport,gwhost);
		return 1;
	}
	return 0;
}
int bound_ftp_data(DGC *Conn,int cntrlsock,int datasock,int epsv,PVStr(mport)){
	int addrlen;
	VSAddr svdata,svsock,svpeer;
	int dataport = 0;
	int viaNAT = 0;
	IStr(vsap,MaxHostNameLen);

	if( mport[0] == 0 ){
		int salen = sizeof(svdata);
		getsockname(datasock,(SAP)&svdata,&salen);
	}else
	if( mport[0] ){
		VSA_ftptosa(&svdata,mport);
		dataport = VSA_port(&svdata);
		sv1log("--FTPdata reuse port# %d [%s]\n",dataport,mport);
	}
	if( dataport <= 0 ){
		dataport = VSA_port(&svdata);
	}
	if( VSAPgetsockname(Conn,cntrlsock,AVStr(vsap)) == 0 ){
		sv1log("FTP DATA via VSAP[%s][%s]\n",mport,vsap);
		VSA_aptosa(&svsock,vsap);
		goto EXIT;
	}

	addrlen = sizeof(VSAddr);
	if( getsockname(datasock,(SAP)&svdata,&addrlen) != 0 || addrlen == 0 ){
		sv1log("cannot setup FTP DATA port: no data conn.\n");
		return -1;
	}
	addrlen = sizeof(VSAddr);
	if( getsockname(cntrlsock,(SAP)&svsock,&addrlen) != 0 || addrlen == 0 ){
		sv1log("cannot setup FTP DATA port: no control conn-1.\n");
		return -1;
	}
	addrlen = sizeof(VSAddr);
	if( getpeername(cntrlsock,(SAP)&svpeer,&addrlen) != 0 || addrlen == 0 ){
		sv1log("cannot setup FTP DATA port: no control conn-2.\n");
		return -1;
	}
	if( viaNAT = setupDATAviaNAT(Conn,&svsock,&svpeer,BVStr(mport)) ){
	}

EXIT:
	if( epsv ){
		sprintf(mport,"|||%d|",dataport);
	}else{
		VSA_setport(&svsock,dataport);
		VSA_prftp(&svsock,BVStr(mport));
	}
	return viaNAT;
}

int UDPaccept(int svsock,int lockfd,int timeout)
{	VSAddr from,svme,xme,peer;
	int salen;
	int clsock;
	int xsock;
	int addrlen;
	int rcc,wcc;
	CStr(buf,0x8000);
	CStr(sfrom,128);
	CStr(speer,128);
	CStr(sme,128);
	int rcode,xtry,rbind,nsvsock;
	int af;

	if( sock_isv6(svsock) )
		af = AF_INET6;
	else	af = AF_INET;

	if( 0 <= lockfd && lock_exclusiveTO(lockfd,timeout*1000,NULL) != 0 ){
		sv1log("## UDP accept failed locking [%d]\n",errno);
		return -1;
	}
	if( PollIn(svsock,1) <= 0 ){
		sv1log("## UDP accept failed polling [%d]\n",errno);
		clsock = -1;
		goto EXIT;
	}

	addrlen = sizeof(VSAddr);
	rcc = Recvfrom(svsock,buf,sizeof(buf),0,(SAP)&from,&addrlen);
	if( rcc <= 0 ){
		sv1log("## UDP accept failed receiving [%d]\n",errno);
		clsock = -1;
		goto EXIT;
	}

	printSock(&from,AVStr(sfrom),"%A:%P");
	sv1log("UDP-SV[%d] ready=%d from=%s\n",svsock,rcc,sfrom);

	addrlen = sizeof(VSAddr);
	rcode = getsockname(svsock,(SAP)&svme,&addrlen);
	setsockREUSE(svsock,1);
	close(svsock);

	clsock = socket(af,SOCK_DGRAM,0);
	if( clsock == svsock ){
		clsock = dup(clsock);
		close(svsock);
	}
	setsockREUSE(clsock,1);

	xme = svme;

	for( xtry = 0; xtry < 10; xtry++ ){
		salen = VSA_size(&xme);
		rcode = bind(clsock,(SAP)&xme,salen);
		if( rcode == 0 )
			break;
		sleep(1);
	}
	if( rcode != 0 ){
		sv1log("UDP accept failed in bind %d\n",errno);
		close(clsock);
		clsock = -1;
		goto EXIT;
	}

	addrlen = sizeof(VSAddr);
	rcode = getsockname(clsock,(SAP)&xme,&addrlen);

	xsock = socket(af,SOCK_DGRAM,0);
	salen = VSA_size(&xme);
	wcc = sendto(xsock,buf,rcc,0,(SAP)&xme,salen);
	close(xsock);

	salen = VSA_size(&from);
	rcode = connect(clsock,(SAP)&from,salen);
	addrlen = sizeof(VSAddr);
	rcode = getpeername(clsock,(SAP)&peer,&addrlen);
	printSock(&peer,AVStr(speer),"%A:%P");

	addrlen = sizeof(VSAddr);
	rcc = Recvfrom(clsock,buf,sizeof(buf),MSG_PEEK,(SAP)&from,&addrlen);
	sv1log("UDP-CL[%d] ready=%d peer=%s\n",clsock,rcc,speer);

	nsvsock = socket(af,SOCK_DGRAM,0);
	setsockREUSE(nsvsock,1);
	for( xtry = 0; xtry < 10; xtry++ ){
		errno = 0;
		salen = VSA_size(&svme);
		rbind = bind(nsvsock,(SAP)&svme,salen);
		if( rbind == 0 )
			break;
		sleep(1);
	}
	if( nsvsock != svsock ){
		dup2(nsvsock,svsock);
		close(nsvsock);
	}

	addrlen = sizeof(VSAddr);
	getsockname(svsock,(SAP)&svme,&addrlen);
	printSock(&svme,AVStr(sme),"%A:%P");
	setsockREUSE(svsock,1);
	sv1log("UDP-SV[%d]: NEW bind=%d %s\n",svsock,rbind,sme);

EXIT:
	if( 0 < lockfd )
		lock_unlock(lockfd);
	return clsock;
}

int SOCKS_udpassoc(int msock,VSAddr *me,VSAddr *rme);
int SOCKS_udpassocsock(int sock,PCStr(lhost),int lport,PVStr(rhost),int *rport)
{	VSAddr me,rme;
	int melen;
	const char *aaddr;

	aaddr = gethostaddr(lhost);
	if( aaddr == NULL )
		return -1;
	VSA_atosa(&me,lport,aaddr);
	if( SOCKS_udpassoc(sock,&me,&rme) != 0 )
		return -1;
	
	strcpy(rhost,VSA_ntoa(&rme));
	*rport = VSA_port(&rme);
	return 0;
}
int sendTo(int sock,PCStr(sto),PCStr(msg),int len)
{	VSAddr sab;
	int salen;
	CStr(aaddr,64);
	int port;
	int wcc;

	port = 0;
	Xsscanf(sto,"%[^:]:%d",AVStr(aaddr),&port);
	if( port == 0 ){
		sv1log("sendTo(%s:%d) ? \n",aaddr,port);
		return -1;
	}

	salen = VSA_atosa(&sab,port,aaddr);
	wcc = sendto(sock,msg,len,0,(SAP)&sab,salen);
	return wcc;
}
int peekfrom(int sock,PVStr(sfrom))
{	CStr(buf,2048);
	VSAddr sab;
	int fromlen;
	int rcc;

	strcpy(sfrom,"0.0.0.0:0");
	fromlen = sizeof(VSAddr);
	rcc = Recvfrom(sock,buf,sizeof(buf),MSG_PEEK,(SAP)&sab,&fromlen);
	if( rcc <= 0 )
		return rcc;

	printSock(&sab,AVStr(sfrom),"%A:%P");
	return rcc;
}
int readfrom(int sock,void *buff,int size,PVStr(sfrom))
{	VSAddr sab;
	int fromlen;
	int rcc;

	strcpy(sfrom,"0.0.0.0:0");
	fromlen = sizeof(VSAddr);
	rcc = Recvfrom(sock,buff,size,0,(SAP)&sab,&fromlen);
	if( rcc <= 0 )
		return rcc;

	printSock(&sab,AVStr(sfrom),"%A:%P");
	return rcc;
}

void GetHostname(PVStr(name),int size)
{	struct hostent *hp;
	CStr(host,MaxHostNameLen);

	if( myFQDN == NULL ){
		gethostname(host,sizeof(host));
		if( hp = gethostbyNameAddr(0,host,NULL,0,0) )
			myFQDN = stralloc(hp->h_name);
		else{
			strcpy(myFQDN_unknown,host);
			myFQDN = myFQDN_unknown;
		}
	}
	strncpy(name,myFQDN,size);
}
int IsMyself(PCStr(host))
{	CStr(myhost,MaxHostNameLen);
	int hosti;

	hosti = gethostintMin(host);
	if( hosti == -1 )
		return 0;

	if( hosti == gethostintMin("localhost") )
		return 1;

	gethostname(myhost,sizeof(myhost));
	if( hosti == gethostintMin(myhost) )
		return 1;

	return 0;
}

int localsocket(int sock)
{	int phosti,pporti;
	int mhosti,mporti;

	phosti = peerHostport(sock,&pporti);
	if( phosti == -1 )
		return 1;

	mhosti = sockHostport(sock,&mporti);
	if( mhosti == -1 )
		return 1;

	if( phosti == mhosti )
		return 1;

	return 0;
}

int hostismyself(PCStr(host),FILE *sockfp)
{	VSAddr sab;
	int salen;
	const char *aaddr;
	int sock,rcode;

	if( __gethostint_nbo(0,"localhost",VStrNULL) == __gethostint_nbo(0,host,VStrNULL) )
		return 1;

	if( sockfp != NULL )
		if( localsocket(fileno(sockfp)) )
			return 1;

	aaddr = gethostaddr(host);
	if( aaddr == NULL )
		return 0;

	sock = socket(AF_INET,SOCK_STREAM,0);
	salen = VSA_atosa(&sab,0,aaddr);
	rcode = bind(sock,(SAP)&sab,salen);
	close(sock);

	if( rcode == 0 )
		return 1;

	return 0;
}

int hostisin(PCStr(host1),PCStr(host2),int nocache){
	struct hostent *hp0,*hp1,*hp2;
	int ai,aj;
	const char *n1,*n2;
	const char *a1,*a2;

	if( hp0 = gethostbyNameAddr(nocache,host1,NULL,0,0) ){
		hp1 = dupHost(hp0);
		if( hp2 = gethostbyNameAddr(nocache,host2,NULL,0,0) )
		if( hp1->h_length == hp2->h_length )
		{
			if( strcaseeq(hp1->h_name,hp2->h_name) ){
				return 1;
			}
			for( aj = 0; n2 = hp2->h_aliases[aj]; aj++ ){
				if( strcaseeq(hp1->h_name,n2) ){
					return 2;
				}
			}
			for( ai = 0; n1 = hp1->h_aliases[ai]; ai++ )
			for( aj = 0; n2 = hp2->h_aliases[aj]; aj++ ){
				if( strcaseeq(n1,n2) ){
					return 3;
				}
			}
			for( ai = 0; a1 = hp1->h_addr_list[ai]; ai++ )
			for( aj = 0; a2 = hp2->h_addr_list[aj]; aj++ ){
				if( bcmp(a1,a2,hp1->h_length) == 0 ){
					return 4;
				}
			}
		}
		freeHost(hp1);
	}
	return 0;
}

int hostcmp(PCStr(host1),PCStr(host2))
{	int hi1,hi2;

	if( strcasecmp(host1,host2) == 0 )
		return 0;

	if( (hi1 = gethostintMin(host1)) != -1 )
	if( (hi2 = gethostintMin(host2)) != -1 )
		if( hi1 == hi2 )
			return 0;
	return 1;
}
int hostcmp_incache(PCStr(host1),PCStr(host2))
{	int co,rcode;

	co = RES_CACHEONLY(1);
	rcode = hostcmp(host1,host2);
	RES_CACHEONLY(co);
	return rcode;
}

const char *VA_inAddr(VAddr *Ia)
{	int ia;

	ia = Ia->I3;
	inAddrx = (inAddrx+1) % 8;
	if( Ia->I0 || Ia->I1 || Ia->I2 ){
		int i4[4];
		i4[0] = htonl(Ia->I0);
		i4[1] = htonl(Ia->I1);
		i4[2] = htonl(Ia->I2);
		i4[3] = htonl(Ia->I3);
		Xstrcpy(EVStr(inAddrs[inAddrx]),
			VSA_ltoa((unsigned char*)&i4,16,AF_INET6));
		return inAddrs[inAddrx];
	}
	Xsprintf(EVStr(inAddrs[inAddrx]),"%d.%d.%d.%d",
		0xFF&(ia>>24),0xFF&(ia>>16),0xFF&(ia>>8),0xFF&ia);
	return inAddrs[inAddrx];
}
int VAtoVSA(VAddr *va,VSAddr *vsa,int port){
	const char *addr;
	addr = VA_inAddr(va);
	VSA_atosa(vsa,va->a_port?va->a_port:port,addr);
	return 1;
}
int VA_resolv(VAddr *vaddr){
	VSAddr vsa;
	const char *baddr;
	int blen;
	int btype;
	struct hostent *hp;

	VAtoVSA(vaddr,&vsa,0);
	blen = VSA_decomp(&vsa,&baddr,&btype,NULL);
	hp = gethostbyNameAddr(0,NULL,baddr,blen,btype);
	if( hp != 0 ){
		vaddr->a_flags |= VA_RSLVINVOK;
		strcpy(vaddr->a_name,hp->h_name);
		return 0;
	}else{
		vaddr->a_flags |= VA_RSLVINVERR;
		return -1;
	}
}

void getpairName(int clsock,PVStr(sockname),PVStr(peername))
{
	gethostName(clsock,AVStr(sockname),"%A:%P");
	getpeerName(clsock,AVStr(peername),"%A:%P");
}

int Socket1(PCStr(what), int sock,PCStr(domain),PCStr(type),PCStr(proto),PVStr(lhost),int lport,PCStr(rhost),int rport, int nlisten,PCStr(opts),int NB)
{	int Domain,Type,Proto;

	if( sock < 0 ){
		if( domain && strcasecmp(domain,"unix") == 0
		 || lhost != NULL && lhost[0] == '/'  )
			Domain = AF_UNIX;
		else	Domain = AF_INET;
		if( type && (strcaseeq(type,"udp")||strcaseeq(type,"dgram")||strcaseeq(proto,"udp")) )
			Type = SOCK_DGRAM;
		else	Type = SOCK_STREAM;
		Proto = 0;
		sock = newsocket(what,Domain,Type,Proto);
		if( sock < 0 )
			return -1;
	}
	if( lhost != NULL && lhost[0] == '/' ){
	}else
	if( lhost != NULL || 0 < lport ){
		if( strcmp(lhost,"*") == 0 )
			setVStrEnd(lhost,0);
		setsockREUSE(sock,1);
		setsockSHARE(sock,1);
		if( bind_insock(sock,lhost,lport) != 0 ){
			close(sock);
			return -1;
		}
	}
	if( 0 < nlisten ){
		if( listen(sock,nlisten) != 0 ){
			close(sock);
			return -1;
		}
	}
	if( rhost != NULL || 0 < rport
	 || rhost != NULL && rhost[0] == '/' ){
		if( NB ) setNonblockingIO(sock,1);
		if( __connectServer(sock,"Socket",what,rhost,rport) < 0 ){
			if( !NB ){
				close(sock);
				return -1;
			}
		}
	}
else{
/* for non-connect operation */
if( NB ) setNonblockingIO(sock,1);
}
	return sock;
}
int Listen(int sock,int backlog)
{
	return listen(sock,backlog);
}

int VA_hostIFto(VAddr *destp,VAddr *maskp,VAddr *Vaddr)
{	CStr(desthost,128);
	CStr(hostif,128);
	VAddr dest0,dest1,hostaddr;
	VAddr host;
	int ii;

	if( iftoV == NULL ){
		iftoV = (IfTo**)StructAlloc(NIFTO*sizeof(IfTo*));
	}
	AddrAND(dest0,(*destp),(*maskp));
	for( ii = 0; ii < iftoN; ii++ ){
		dest1 = iftoV[ii]->if_dest;
		if( AddrEQ(dest1,dest0) ){
			*Vaddr = iftoV[ii]->if_ifto;
			return 1;
		}
	}
	inet_itoaV4(destp->I3,AVStr(desthost));

	if( hostIFfor0(AVStr(hostif),1,"time",desthost,37,0) == 0 ){
		strcpy(hostif,"?");
		host = AddrNull;
	}else{
		host = AddrZero;
		host.I3 = ntohl(inet_addrV4(hostif));
	}

	if( ii < NIFTO ){
		iftoV[ii] = NewStruct(IfTo);
		iftoV[ii]->if_dest = dest0;
		iftoV[ii]->if_ifto = host;
		iftoN = ii+1;
	}
	sv1log("## hostIFto %s < %s (%x)\n",desthost,hostif,maskp->I3);
	*Vaddr = host;
	return 0;
}

int make_HOSTS(PVStr(hosts),PCStr(hostname),int cacheonly)
{	struct hostent *hp;

	if( hp = gethostbyNameAddr(cacheonly,hostname,NULL,0,0) ){
		dump_HOST1(AVStr(hosts),hp);
		return 1;
	}
	return 0;
}

int TIMEOUT_RES_UP_WAIT = 10;
const char *RES_UP_HOST = "WwW.DeleGate.ORG";
const char *DELEGATE_getEnv(PCStr(name));
/*
 * RES_WAIT=seconds[:hostname-or-address]
 * default: RES_WAIT=10:WWW.DeleGate.ORG
 */
void scan_RES_WAIT(DGC*ctx,PCStr(reswait)){
	int wsec;
	CStr(host,256);
	wsec = TIMEOUT_RES_UP_WAIT;
	truncVStr(host);
	wsec = 0;
	Xsscanf(reswait,"%d:%s",&wsec,AVStr(host));
	TIMEOUT_RES_UP_WAIT = wsec;
	if( host[0] ) RES_UP_HOST = stralloc(host);
}
/*
 * waiting should be suppressed with
 *  RESOLV=""
 *  RES_WAIT=0
 */
static int doWait(){
	const char *resolv;
	const char *reswait;

	if( lISCHILD() || lISFUNC() ){
		return 0;
	}
	if( resolv = getenv("RES_ORDER") ){
		if( *resolv == 0 )
			return 0;
	}
	if( resolv = DELEGATE_getEnv("RESOLV") ){
		if( *resolv == 0 )
			return 0;
	}
	if( reswait = DELEGATE_getEnv("RES_WAIT") ){
		scan_RES_WAIT(NULL,reswait);
	}
	if( TIMEOUT_RES_UP_WAIT <= 0 )
		return 0;

	return 1;
}
static void waitResolver(PCStr(resl)){
	int start;
	int retry;
	int exp;

	if( !doWait() ){
		return;
	}

	start = time(0);
	exp = RES_HC_EXPIRE;
	RES_HC_EXPIRE = 1;
	for( retry = 0; ; retry++ ){
		iLog("--- testing resolver[%s] with '%s'",resl,RES_UP_HOST);
		sv1log("... testing resolver[%s] with '%s'\n",resl,RES_UP_HOST);
		sv1log("... you can suppress this test by RES_WAIT=0\n");
		if( 3 < time(0)-start )
		if( !lCONSOLE() && !lTTY() ){
		 porting_dbg("testing resolver[%s] with '%s'",resl,RES_UP_HOST);
		 porting_dbg("you can suppress this test by RES_WAIT=0");
		}
		if( strcaseeq(resl,"SYS") ){
			if( EX_GETHOSTBYNAME(RES_UP_HOST) )
				break;
		}else{
			if( gethostbyname(RES_UP_HOST) )
				break;
		}
		if( TIMEOUT_RES_UP_WAIT < time(0)-start ){
			break;
		}
		sleep(1);
	}
	RES_HC_EXPIRE = exp;
	TIMEOUT_RES_UP_WAIT = 0; /* not to repeat waitResover() in INETD */
}

#ifdef DEBUG_RES_WAIT
#define gethostname(n,z)	ovstrcpy(n,"__unknown__")
#endif

static struct hostent *getMyHostname1(PVStr(myname),int nsize){
	Hostent *Me;
	struct hostent *me = 0;

	strcpy(myname,"_-no-name-_");
	gethostname((char*)myname,nsize);
	InitLog("... gethostname(%s)\n",myname);

	if( Me = findHostCache(myname,NULL,0,0) ){
		return &Me->hc_hostent;
	}
	if( me = EX_GETHOSTBYNAME((char*)myname) ){
		/* put myname by SYS into HOSTS cache */
		me = addHostCacheOk(me,myname,"GETHOSTBYNAME",Time());
		return me;
	}
	return NULL;
}
static struct hostent *getMyHostname(PVStr(myname),int nsize){
	const char *reswait;
	struct hostent *me = 0;
	int retry;
	int start;

	if( me = getMyHostname1(BVStr(myname),nsize) ){
		return me;
	}
	if( !doWait() ){
		return NULL;
	}

	/* waitResolver("SYS"); */
	/* wait the host name to be set after DHCP assignment */

	start = time(0);
	for( retry = 0; ; retry++ ){
		if( TIMEOUT_RES_UP_WAIT*2 < retry ){
			sv1log("### RES_WAIT max retry: %d < %d\n",
				TIMEOUT_RES_UP_WAIT*10,retry);
			break;
		}
		if( me = getMyHostname1(BVStr(myname),nsize) ){
			return me;
		}
		sv1log("### ERROR: can't resolve myname (%s)\n",myname);
		if( lISCHILD() || lISFUNC() ){
			return NULL;
		}
		if( TIMEOUT_RES_UP_WAIT < time(0)-start ){
			sv1log("### RES_WAIT time up: %d < %d\n",
				TIMEOUT_RES_UP_WAIT,(int)(time(0)-start));
			break;
		}
		msleep(500);
	}
	sv1log("### FATAL: can't resolve myname (%s)\n",myname);
	RESOLV_UNKNOWN++;
	return me;
}

int RES_order_default(PVStr(dorder),PCStr(myname),struct hostent *me);
void init_myname(PCStr(RESOLV))
{	CStr(order,RESOLVERS_SIZ);
	CStr(porder,RESOLVERS_SIZ);
	CStr(dresolv,RESOLVERS_SIZ);
	CStr(env,RESOLVERS_SIZ);
	CStr(myname,MaxHostNameLen);
	struct hostent *me;

	scan_HOSTS(0,"localhost/127.0.0.1");
	scan_HOSTS(0,"localhost/__1");
	me = getMyHostname(AVStr(myname),sizeof(myname));


	if( RESOLV != NULL && streq(RESOLV,RES_AUTO_DFLT) ){
		RESOLV = NULL;
	}
	/* V8.0.0 setup default RESOLV */
	if( RESOLV == NULL ){
		RES_order_default(AVStr(order),myname,me);
		if( streq(order,"?") ){
			sv1log("### don't export RESOLV=''\n");
		}else{
		RES_prorder(order,AVStr(dresolv));
		sprintf(env,"RESOLV=%s",dresolv);
		sv1log("export %s (set by default)\n",env);
		putenv(stralloc(env));
		}
	}
}

int RES_order_default(PVStr(dorder),PCStr(myname),struct hostent *me){
	CStr(porder,RESOLVERS_SIZ);
	CStr(origorder,RESOLVERS_SIZ);
	const char *rp;
	CStr(resolv,RESOLVERS_SIZ);
	CStr(env,RESOLVERS_SIZ);
	const char *op;
	CStr(myaddr,64);
	struct hostent *me_dns;
	const char *name;
	const char *ypdomain;
	const char *addr;
	int hi,ai;

	strcpy(porder,"");
	op = getenv("RES_ORDER");
	if( op ){
		RES_orderSet(op);
		RES_confidSet("RES_ORDER");
		strcpy(dorder,op);
		return 0;
	}

	RES_orderGet(AVStr(origorder));
	sv1log("configuring default RESOLV ...\n");
	sv1log("... gethostname()='%s'\n",myname);
	me_dns = 0;
	if( me ){
		dumpAddr(AVStr(myaddr),me->h_addr_list[0],me->h_length,me->h_addrtype);
		sv1log("... SYS: %s -> %s\n",myname,myaddr);
		RES_orderGet(AVStr(porder));
		RES_orderPush("D",RES_ALONE);
		for( ai = 0; addr = me->h_addr_list[ai]; ai++ ){
			me_dns = gethostbyaddr(addr,
				me->h_length,me->h_addrtype);
			if( me_dns ){
				dumpAddr(AVStr(myaddr),addr,me->h_length,me->h_addrtype);
				break;
			}
		}
		RES_orderPop();
	}else{
		RES_orderSet(porder);
	}
	if( me_dns ){
		if( rp = strchr(porder,'S') )
			ovstrcpy((char*)rp,rp+1);
		RES_orderSet(porder);
		sv1log("... DNS: %s -> %s\n",myaddr,me_dns->h_name);
		sv1log("... DNS available\n");
	}
	if( yp_get_default_domain((char**)&ypdomain) == 0 && *ypdomain != 0 ){
		sv1log("... NIS domain: %s\n",ypdomain);
		/* new-140518m detect inactive NIS */ {
			extern double RES_NIS_TIMEOUT;
			double Start = Time();
			struct hostent *hp;
			int NIS_inactive(PCStr(ypdomain),int set);

			if( NIS_inactive(ypdomain,0) ){ /* v9.9.12 new-140823d */
				sv1log("... NIS seems inactive (cached)\n");
				hp = NULL;
				Start = Time() - RES_NIS_TIMEOUT - 1;
			}else{
				RES_orderPush("N",RES_ALONE);
				hp = gethostbyname(myname);
				RES_orderPop();
			}
			if( hp == NULL && (RES_NIS_TIMEOUT < (Time()-Start)) ){
				if( rp = strchr(porder,'N') )
					ovstrcpy((char*)rp,rp+1);
				RES_orderSet(porder);
				sv1log("... NIS not available (seems inactive).\n");
				NIS_inactive(ypdomain,1);
			}
		}
	}else{
		if( rp = strchr(porder,'N') )
			ovstrcpy((char*)rp,rp+1);
		RES_orderSet(porder);
		sv1log("... NIS not available (no default domain)\n");
	}
	if( porder[0] == 0 ){
		RES_orderSet(origorder);
		strcpy(dorder,"?");
		sv1log("### FATAL: RES_ORDER='' -> '%s' (default)\n",origorder);
		iLog("--F RES_ORDER='' -> '%s' (default)",origorder);
		RESOLV_UNKNOWN++;
	}else{
	strcpy(dorder,porder);
	sprintf(env,"RES_ORDER=%s",dorder);
	putenv(stralloc(env));
	sv1log("... export %s\n",env);
	iLog("--- export %s",env);
	}
	RES_confidSet("detected");
	return 1;
}

int Accepts(int ac,const char *av[]){
	double Start = Time();
	double Prev;
	int clsock;
	int prev = 0;
	int ai;
	const char *a1;
	const char *svhost = "127.0.0.1";
	int svport = 9999;
	int af;
	VSAddr saSV;
	int salen;
	int svsock;
	int rcode;
	DGC *Conn = 0;
	int viaSocks = 0;
	IStr(bhost,256);
	int bport = 0;
	IStr(ahost,256);
	int aport;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( strncmp(a1,"-p",2) == 0 )
			svport = atoi(a1+2);
		else
		if( strncmp(a1,"-h",2) == 0 )
			svhost = a1+2;
		else
		if( strneq(a1,"SOCKS=",5) ){
			viaSocks = 1;
		}
	}
	if( viaSocks ){
		Conn = MainConn();
		svsock = bindViaSocks(Conn,svhost,svport,AVStr(bhost),&bport);
		if( 0 <= svsock )
			rcode = 0;
		else	rcode = -1;
		fprintf(stderr,"BindViaSocks=%d [%s:%d]\n",svsock,bhost,bport);
	}else{
	VSA_atosa(&saSV,svport,svhost);
	salen = VSA_size(&saSV);
	af = AF_INET;
	svsock = newsocket("Connects",af,SOCK_STREAM,0);
	setsockREUSE(svsock,1);
	rcode = Bind(svsock,&saSV,salen);
	listen(svsock,10);
	}
	fprintf(stderr,"host: -h%s\n",svhost);
	fprintf(stderr,"port: -p%d [%d]%d\n",svport,svsock,rcode);

	Prev = Start;
	for( ai = 1;; ai++ ){
		if( viaSocks ){
			fprintf(stderr,"AcceptViaSocks ...\n");
			clsock = acceptViaSocks(svsock,AVStr(ahost),&aport);
			fprintf(stderr,"AcceptViaSocks=%d [%s:%d]\n",clsock,ahost,aport);
			svsock = bindViaSocks(Conn,svhost,svport,AVStr(bhost),&bport);
		}else
		clsock = Accept(svsock,1,-1,VStrNULL);
		if( clsock < 0 ){
			fprintf(stderr,"Accepts(%d/%d) errno=%d\n",
				svport,svsock,errno);
			break;
		}
		close(clsock);
		if( (ai % 1000) == 0 ){
			double Now = Time();
			fprintf(stderr,"%6.1f %4.1f %6d %6.1f/s %6d %6.1f/s\n",
				Now-Start,Now-Prev,
				ai-prev,(ai-prev)/(Now-Prev),
				ai,ai/(Now-Start));
			Prev = Now;
			prev = ai;
		}
	}
	return 0;
}

int Connects(int ac,const char *av[]){
	double Start = Time();
	double Prev;
	double Now;
	int clsock;
	int prev = 0;
	int af;
	int ai;
	VSAddr sabL;
	VSAddr sabR;
	int salen;
	int rcode;
	int cerrno;
	const char *a1;
	const char *svhost = "127.0.0.1";
	int svport = 9999;
	int myport = -1;
	int count = 10000;
	double intvl = 0.0005;
	int keepopen = 0;
	int sendreq = 0;
	int nsucc = 0;
	int kfi;
	int kfn;
	int kfdc = 0;
	int kfdv[1024];
	int krdv[1024];
	int nready;
	int nerror = 0;
	int nonblock = 0;
	IStr(cstat,256);

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( strncmp(a1,"-i",2) == 0 )
			sscanf(a1+2,"%lf",&intvl);
		else
		if( strncmp(a1,"-c",2) == 0 )
			count = atoi(a1+2);
		else
		if( strncmp(a1,"-p",2) == 0 )
			svport = atoi(a1+2);
		else
		if( strncmp(a1,"-h",2) == 0 )
			svhost = a1+2;
		else
		if( strncmp(a1,"-k",2) == 0 )
			keepopen = 1;
		else
		if( strncmp(a1,"-q",2) == 0 )
			sendreq = 1;
		else
		if( strncmp(a1,"-b",2) == 0 )
			nonblock = 1;
	}
	fprintf(stderr,"interval: -i%f\n",intvl);
	fprintf(stderr,"count: -c%d\n",count);
	fprintf(stderr,"host: -h%s\n",svhost);
	fprintf(stderr,"port: -p%d\n",svport);
	fprintf(stderr,"FD_SETSIZE=%d\n",FD_SETSIZE);

	Prev = Start;
	VSA_atosa(&sabL,0,"0.0.0.0");
	VSA_atosa(&sabR,svport,svhost);
	salen = VSA_size(&sabR);
	af = AF_INET;
	CON_TIMEOUT = 60;

	kfn = 0;
	for( kfi = 0; kfi < elnumof(kfdv); kfi++ )
		kfdv[kfi] = 0;

	for( ai = 1; ai < count; ai++ ){
		errno = 0;
		clsock = newsocket("Connects",af,SOCK_STREAM,0);
		if( clsock < 0 )
		{
			fprintf(stderr,"-h%s -p%d => %d %d\n",
				svhost,svport,clsock,errno);
			break;
		}

		/*
		setsockREUSE(clsock,1);
		if( 0 < myport ){
			errno = 0;
			rcode = Bind(clsock,&sabL,salen);
			if( rcode < 0 ){
				fprintf(stderr,"Bind(%d) = %d, errno=%d\n",
					myport,rcode,errno);
			}
		}
		*/

		if( nonblock ){
			setNonblockingIO(clsock,1);
		}
		errno = 0;
		rcode = Bconnect("Connects",clsock,&sabR,salen,AVStr(cstat));
		cerrno = errno;
		if( myport < 0 ){
			myport = sockPort(clsock);
			VSA_atosa(&sabL,myport,"0.0.0.0");
		}
		if( (ai % 1000) == 0 ){
			Now = Time();
			myport = sockPort(clsock);
		fprintf(stderr,"%6.1f %4.1f %6d %6.1f/s %6d %6.1f/s #%d\n",
				Now-Start,Now-Prev,
				ai-prev,(ai-prev)/(Now-Prev),
				ai,ai/(Now-Start),myport);
			Prev = Now;
			prev = ai;
		}
		if( keepopen ){
			kfdv[kfn++] = clsock;
			fprintf(stderr,"++ [%4d] %3d fd=%-3d #%d",
				ai,kfn,clsock,sockPort(clsock));
			if( sendreq && !nonblock ){
				setNonblockingIO(clsock,1);
			}

			if( cerrno == EINPROGRESS || cerrno == EWOULDBLOCK ){
				int ready;
				ready = PollOut(clsock,30);
				if( 0 < ready ){
fprintf(stderr," [BLOCK %d %d] ",cerrno,ready);
					rcode = 0;
				}else{
fprintf(stderr," [%d block %d %d] ",cerrno,ready,errno);
					rcode = -1;
				}
			}
			if( rcode < 0 ){
				nerror++;
				fprintf(stderr," (%d) errno=%d ERROR=#%d\n",
					rcode,cerrno,nerror);
				usleep(100000);
				close(clsock);
			}else{
				CStr(req,128);
				nsucc++;
				fprintf(stderr," %4d %.2f\n",
					nsucc,nsucc/(Time()-Start));
				if( sendreq ){
					sprintf(req,"GET / HTTP/1.1\r\n\r\n");
					IGNRETP write(clsock,req,strlen(req));
				}
			}
			if( 0 < kfn && (nready = PollIns(1,kfn,kfdv,krdv)) ){
				CStr(buf,64*1024);
				int rcc;
				int kn;
				int kno;
				for( kfi = 0; kfi < kfn; kfi++ ){
					if( krdv[kfi] == 0 )
						continue;
					rcc = read(kfdv[kfi],buf,sizeof(buf));
					if( rcc <= 0 )
						krdv[kfi] = -2;
				}
				kno = kfn;
				kn = 0;
				for( kfi = 0; kfi < kfn; kfi++ ){
					if( 0 <= krdv[kfi] ){
						kfdv[kn++] = kfdv[kfi];
						continue;
					}
					fprintf(stderr,"-- [%4d] %3d fd=%-3d\n",
						ai,--kno,kfdv[kfi]);
					close(kfdv[kfi]);
				}
				kfn = kn;
			}
		}else{
		close(clsock);
		if( rcode < 0 ){
			fprintf(stderr,"connection failure: errno=%d\n",
				cerrno);
			break;
		}
		}
		if( intvl != 0 )
			usleep((int)(intvl*1000000));
	}
	Now = Time();
	fprintf(stderr,"%6.1f %4.1f %6d %6.1f/s %6d %6.1f/s #%d\n",
		Now-Start,Now-Prev,
		ai-prev,(ai-prev)/(Now-Prev),
		ai,ai/(Now-Start),myport);
	fprintf(stderr,"ERRORS=%d\n",nerror);

sleep(10);

	return 0;
}


static int scanmaca(PCStr(aline),PVStr(maca)){
	const char *ap;
	int a,b,c,d,e,f;
	for( ap = aline; *ap; ap++ ){
	    if( sscanf(ap,"%x:%x:%x:%x:%x:%x",&a,&b,&c,&d,&e,&f) == 6
	     || sscanf(ap,"%x-%x-%x-%x-%x-%x",&a,&b,&c,&d,&e,&f) == 6
	    ){
		sprintf(maca,"%x-%x-%x-%x-%x-%x",a,b,c,d,e,f);
		return 1;
	    }
	}
	return 0;
}
static int axtob(PCStr(cmac),char bd[],int siz){
	int ne;
	int i[6];
	ne = sscanf(cmac,"%x-%x-%x-%x-%x-%x",
		&i[0],&i[1],&i[2],&i[3],&i[4],&i[5]);
	if( ne == 1 ){
		ne = sscanf(cmac,"%x:%x:%x:%x:%x:%x",
			&i[0],&i[1],&i[2],&i[3],&i[4],&i[5]);
	}
	bd[0] = i[0];
	bd[1] = i[1];
	bd[2] = i[2];
	bd[3] = i[3];
	bd[4] = i[4];
	bd[5] = i[5];
	return ne;
}
static int adtob(PCStr(aip4),char bi[],int siz){
	const char *ap;
	int a,b,c,d;
	for( ap = aip4; *ap; ap++ ){
		if( sscanf(ap,"%d.%d.%d.%d",&a,&b,&c,&d) == 4 ){
			bi[0] = a;
			bi[1] = b;
			bi[2] = c;
			bi[3] = d;
			return 4;
		}
	}
	return 0;
}
/*
 * 9.9.8 ARP retriever with cache on shared memory
 *
 * MD5-cache cache of a set of MD5 values (to check a membership)
 * ARP-cache IP address (max 16bytes) to MAC address (6bytes) 
 * Bin-cache binary data (max 16bytes) cache (indexed by MD5)
 */
int AG_CACHE_EXPIRE = 10;
/*
const char *ARP_COMMAND = "arp -n %A";
*/
const char *ARP_COMMAND = "arp %A";
int ARP_CACHE_EXPIRE = 60;
int ARP_CACHE_SIZE = 256;
int MD5_CACHE_EXPIRE = 60;
int MD5_CACHE_SIZE = 256;
MMap *arpMMap;
MMap *md5MMap;
const char *ARP_CACHE = "${ACTDIR}/delegate-arp";
const char *MD5_CACHE = "${ACTDIR}/delegate-md5";
void scan_ARPCONF(DGC*ctx,PCStr(conf)){
	IStr(nam,32);
	IStr(val,256);
	fieldScan(conf,nam,val);
	if( isinListX(nam,"command","c") ){
		ARP_COMMAND = stralloc(val);
	}else
	if( isinListX(nam,"cache-file","c") ){
		ARP_CACHE = stralloc(val);
	}else
	if( isinListX(nam,"cache-size","c") ){
		ARP_CACHE_EXPIRE = atoi(val);
	}else
	if( isinListX(nam,"cache-expire","c") ){
		ARP_CACHE_EXPIRE = atoi(val);
	}else
	{
	}
}
static int scanmaca(PCStr(aline),PVStr(maca));
static int axtob(PCStr(cmac),char bd[],int siz);
static int adtob(PCStr(aip4),char bi[],int siz);
int strCRC32(PCStr(str),int len);
void toMD5X(PCStr(key),int klen,char digest[]);
const char *ACTDIR();
FILE *fopenLIB(PCStr(file),PCStr(mode),PVStr(xpath));
int popenx(PCStr(command),PCStr(mode),FILE *io[2]);
char *getMacAddr(PCStr(ipaddr),PVStr(macaddr));

static struct _agcache {
	MStr(ag_md5b,16); /* MD5(addr-group|addr) */
	MStr(ag_amac,32);
	int	ag_ctime;
	int	ag_match;
} AGcache;

typedef struct _mmc_tag {
	unsigned int mm_count; /* num hits */
	unsigned int mm_atime; /* last access time */
	unsigned int mm_ctime; /* added time */
	unsigned int mm_sline; /* line number in the source */
	unsigned int mm_crc32;
	MStr(mm_key,16);       /* a unique, MD5 value */
	MStr(mm_val,12);
} MmcTag;

enum _BinType {
	BT_IPV4 = 1,
	BT_IPV6 = 2,
	BT_MAC  = 3,
} BinType;

typedef struct _BinEnt {
  unsigned char	b_type[1];  /* IPv4,IPv6,MacAddr */
  unsigned char	b_leng[1];
  unsigned char	b_line[3];  /* line # in the source file */
	char	b_resv[11];
	char	b_data[16];
} BinEnt;

int ipa2macf(PCStr(hostaddr),PVStr(amac),int asiz){
	FILE *io[2];
	IStr(command,256);
	IStr(aline,256);
	int rcc;
	int pid;
	int xpid = -9;

	if( getMacAddr(hostaddr,BVStr(amac)) != amac ){
		strsubst(AVStr(amac),":","-");
		sv1log("--AC-- [%s] %s FOUND\n",hostaddr,amac);
		return 0;
	}

	strcpy(command,ARP_COMMAND);
	strsubst(AVStr(command),"%A",hostaddr);
	if( pid = popenx(command,"r",io) ){
		if( io[1] && io[1] != io[0] ){
			fclose(io[1]);
		}
		bzero(aline,sizeof(aline));
		rcc = fread(aline,1,sizeof(aline)-1,io[0]);
		fclose(io[0]);
		xpid = NoHangWait();
		if( rcc <= 0 || pid != xpid ){
			sv1tlog("--AC--ipa2macf: #### rcc=%d pid=%d xpid=%d\n",
				rcc,pid,xpid);
		}
		if( scanmaca(aline,AVStr(amac)) ){
			sv1log("--AC-- %s [%s] FOUND\n",command,amac);
			return 0;
		}
		sv1log("--AC-- %s [NotFound]\n",command);
	}
	return -1;
}
int MMcacheSetup(PCStr(cachefile),int elnum,int elsiz,MMap **mmap){
	IStr(path,1024);
	FILE *fp;
	int acsize = elnum * elsiz;
	int osize;
	int sz;

	if( *mmap != 0 ){
		return 0;
	}
	strcpy(path,cachefile);
	strsubst(AVStr(path),"${ACTDIR}",ACTDIR());
	fp = fopen(path,"a");
	if( fp == 0 ){
		sv1tlog("--AC-- #### can't open %s\n",path);
		return -1;
	}
	osize = file_size(fileno(fp));
	if( osize < acsize ){
		for( sz = osize; sz < acsize; sz++ ){
			putc(' ',fp);
		}
		fflush(fp);
		sv1tlog("--AC-- expanded %d -> %d/%d/%d\n",osize,
			ftell(fp),File_size(path),acsize);
	}
	fclose(fp);
	if( *mmap == 0 ){
		*mmap = filemmap(path,"r+",0,acsize);
	}
	return 1;
}
int MMcacheClose(MMap **mmap){
	MMap *am;
	if( am = *mmap ){
		*mmap = 0;
		freemmap(am);
		return 1;
	}
	return 0;
}
int arpcacheClose(){
	MMcacheClose(&arpMMap);
	return 0;
}
int md5cacheClose(){
	MMcacheClose(&md5MMap);
	return 0;
}
static MmcTag *getarpCache(int *asize){
	MMcacheSetup(ARP_CACHE,ARP_CACHE_SIZE,sizeof(MmcTag),&arpMMap);
	if( arpMMap == 0 ){
		*asize = 0;
		return 0;
	}
	*asize = ARP_CACHE_SIZE;
	return (MmcTag*)arpMMap->m_addr;
}
static MmcTag *getmd5Cache(int *msize){
	MMcacheSetup(MD5_CACHE,MD5_CACHE_SIZE,sizeof(MmcTag),&md5MMap);
	if( md5MMap == 0 ){
		*msize = 0;
		return 0;
	}
	*msize = MD5_CACHE_SIZE;
	return (MmcTag*)md5MMap->m_addr;
}

static int getMMcache(const char key[16],int exp,PCStr(hostaddr),PVStr(amac),int asiz,MmcTag *mm){
	int now = time(0);
	int ci;
	int atime;
	int count;
	int crc32;
	int ccrc;
	MmcTag ab;

	MmcTag *abuff;
	int asize;
	if( (abuff = getarpCache(&asize)) == 0 ){
		return 0;
	}
	for( ci = 0; ci < asize; ci++ ){
		if( abuff[ci].mm_ctime == 0 ){
			continue;
		}
		ab = abuff[ci];
		if( bcmp(key,ab.mm_key,sizeof(ab.mm_key)) != 0 ){
			continue;
		}

		atime = ab.mm_crc32; ab.mm_atime = 0;
		crc32 = ab.mm_crc32; ab.mm_crc32 = 0;
		count = ab.mm_count; ab.mm_count = 0;
		ccrc = strCRC32((const char*)&ab,sizeof(ab));
		if( crc32 != ccrc ){
			sv1tlog("--AC-- #### CRC error %d/%d\n",ci,asize);
			abuff[ci].mm_ctime = 0;
		}else
		if( ab.mm_ctime+exp < now ){
			Verbose("--AC-- expire %d/%d\n",ci,asize);
			abuff[ci].mm_ctime = 0;
		}else{
			ab.mm_atime = now;
			ab.mm_count = count + 1;
			ab.mm_crc32 = crc32;
			abuff[ci] = ab;
			if( amac ){
				unsigned char *bd = (unsigned char *)ab.mm_val;
				sprintf(amac,"%x-%x-%x-%x-%x-%x",bd[0],bd[1],bd[2],bd[3],bd[4],bd[5]);
			}
			Verbose("--AC-- got %d/%d (%d)\n",ci,asize,count);
			*mm = ab;
			return ci+1;
		}
	}
	return 0;
}
static int putMMcache1(const char key[16],MmcTag *abuf,PCStr(hostaddr),PCStr(amac),int now,int sline){
	MmcTag mm;

	bzero(&mm,sizeof(mm));
	bcopy(key,(char*)mm.mm_key,16);
	mm.mm_ctime = now;
	mm.mm_sline = sline;
	mm.mm_crc32 = 0;
	if( amac ){
		axtob(amac,mm.mm_val,sizeof(mm.mm_val));
	}
	mm.mm_crc32 = strCRC32((const char*)&mm,sizeof(mm));
	*abuf = mm;
	return 0;
}
static int putMMcache(const char key[16],int sline,PCStr(hostaddr),PCStr(amac)){
	int now = time(0);
	int ci;
	int ctime;
	unsigned int oldest = 0;
	int oldest_x = -1;

	MmcTag *abuff;
	int asize;
	if( (abuff = getarpCache(&asize)) == 0 ){
		return 0;
	}
	for( ci = 0; ci < asize; ci++ ){
		ctime = abuff[ci].mm_ctime;
		if( ctime == 0 ){
			Verbose("--AC-- put(%d/%d) %d A\n",ci,asize,ctime);
			putMMcache1(key,&abuff[ci],hostaddr,amac,now,sline);
			return 1;
		}
		if( oldest == 0 || ctime < oldest ){
			oldest = ctime;
			oldest_x = ci;
		}
	}
	if( 0 <= oldest_x && oldest_x < asize ){
		ci = oldest_x;
		Verbose("--AC-- put(%d/%d) %d B %d\n",ci,asize,
			ctime,abuff[ci].mm_ctime);
		putMMcache1(key,&abuff[ci],hostaddr,amac,now,sline);
		return 2;
	}
	return -1;
}
int ipa2macc(PCStr(hostaddr),PVStr(amac),int asiz){
	MmcTag mm;
	IStr(key,16);
	toMD5X(hostaddr,strlen(hostaddr),(char*)key);

	if( getMMcache(key,ARP_CACHE_EXPIRE,hostaddr,AVStr(amac),asiz,&mm) ){
		return 1;
	}
	/* should wait if another one doing it */
	if( ipa2macf(hostaddr,AVStr(amac),asiz) == 0 ){
		if( getMMcache(key,ARP_CACHE_EXPIRE,hostaddr,AVStr(amac),asiz,&mm) ){
			return 2;
		}else{
			putMMcache(key,0,hostaddr,amac);
			return 0;
		}
	}
	return -1;
}

static const char *elemscan(PCStr(s),PCStr(sx),char d[],int dz){
	const char *dx = &d[dz-1];
	for(; s < sx && *s && d < dx; ){
		if( *s == ',' || *s == '}' || *s == '\n' ){
			break;
		}
		*d++ = *s++;
	}
	*d = 0;
	return s;
}
static int addrMatchMmap(PCStr(file),PCStr(m1),PVStr(cmac)){
	int found = 0;
	FILE *fp;
	int mi;
	int len;
	IStr(aline,256);
	IStr(mc,128);

	MMap *mm;
	const char *in;
	const char *ix;
	mm = filemmap(file,"r",0,0);
	if( mm == 0 ){
		sv1tlog("--AC-- matchF #### cannot open file:%s\n",file);
		return 0;
	}
	in = (char*)mm->m_addr;
	ix = &in[mm->m_size];
	for( mi = 0; in < ix; mi++ ){
		in = elemscan(in,ix,(char*)aline,sizeof(aline));
		if( *aline == '#' || *aline == '\r' || *aline == '\n' ){
		}else{
			if( scanmaca(aline,AVStr(mc)) == 0 ){
				sv1log("--AC-- addrGroup #### invalid-mac-addr [%s]\n",aline);
			}
			if( streq(mc,m1) ){
				strcpy(cmac,mc);
				found = mi+1;
				break;
			}
		}
		if( ix <= in ){
			break;
		}
		in++;
	}
	freemmap(mm);
	return found;
}
static int addrMatchList(PCStr(mlist),PCStr(m1),PVStr(cmac)){
	int found = 0;
	const char *mp = mlist;
	IStr(mb,128);
	IStr(mc,128);
	int mi;

	for( mi = 0; ; mi++ ){
		mp = wordScanY(mp,mb,"^,}");
		if( scanmaca(mb,AVStr(mc)) == 0 ){
			sv1tlog("--AC-- addrGroup #### invalid-mac-addr [%s]\n",mb);
		}
		if( streq(mc,m1) ){
			strcpy(cmac,mc);
			found = mi+1;
			break;
		}
		if( *mp != ',' ){
			break;
		}
		mp++;
	}
	return found;
}
static int putBinEnt(FILE *bfp,PCStr(amc),int btype,int ln){
	BinEnt bent;
	int wcc;

	bzero(&bent,sizeof(bent));
	if( btype == BT_MAC ){
		axtob(amc,bent.b_data,sizeof(bent.b_data));
	}else
	if( btype == BT_IPV4 ){
		bcopy(amc,bent.b_data,4);
	}
	bent.b_type[0] = btype;
	bent.b_line[0] = ln >> 16;
	bent.b_line[1] = ln >> 8;
	bent.b_line[2] = ln;
	wcc = fwrite(&bent,1,sizeof(bent),bfp);
	return 0;
}
typedef struct _Md5 {
	int	md_stat;
	MStr(	md_md5x,256);
	MStr(	md_md5b,16);
	MStr(	md_md5a,64);
} Md5;
static int addrMatchFile(PCStr(file),PCStr(iaddr),PCStr(qmac),PVStr(cmac)){
	MmcTag mm;
	int found = 0;
	FILE *bfp = 0;
	FILE *afp = 0;
	int mi;
	int len;
	const char *fname;
	int fmtime = 0;
	IStr(dfile,256);
	IStr(xfile,256);
	IStr(aline,256);
	IStr(amc,128);
	IStr(bin,256);
	IStr(xpath,256);
	IStr(ypath,256);
	BinEnt bent;
	IStr(bd,16);
	IStr(b4,4);
	IStr(i4a,4);
	const unsigned char *bl = (unsigned char*)bent.b_line;
	int bln = 0;
	Md5 md5 = {-9};

	sprintf(dfile,"hosts.d/%s",file);
	afp = fopenLIB(dfile,"r",AVStr(xpath));
	if( afp == NULL ){
		sprintf(xfile,"%s.txt",dfile);
		afp = fopenLIB(xfile,"r",AVStr(xpath));
	}
	if( afp == NULL ){
		sv1tlog("--AC-- matchF #### cannot open: ETCDIR/%s[.txt]\n",
			dfile);
		return 0;
	}
	fmtime = file_mtime(fileno(afp));
	fclose(afp);

	md5.md_stat = startMD5(md5.md_md5x,sizeof(md5.md_md5x));
	if( md5.md_stat == 0 ){
		updateMD5(md5.md_md5x,(char*)&fmtime,sizeof(fmtime));
		updateMD5(md5.md_md5x,xpath,strlen(xpath));
		updateMD5(md5.md_md5x,"\0",1);
		updateMD5(md5.md_md5x,qmac,strlen(qmac));
		updateMD5(md5.md_md5x,"\0",1);
		updateMD5(md5.md_md5x,iaddr,strlen(iaddr));
		finishMD5(md5.md_md5x,md5.md_md5b,md5.md_md5a);
		if( getMMcache(md5.md_md5b,MD5_CACHE_EXPIRE,iaddr,VStrNULL,0,&mm) ){
			Verbose("--AC-- HIT [%s][%s][%s] line=%d\n",md5.md_md5a,iaddr,file,mm.mm_sline);
			return mm.mm_sline;
		}
	}

	axtob(qmac,(char*)bd,sizeof(bd));
	adtob(iaddr,(char*)b4,sizeof(b4));
	strcpy(bin,ACTDIR());
	if( strtailchr(bin) != '/' ){
		strcat(bin,"/");
	}
	if( fname = strrpbrk(file,"/\\") ){
		fname = fname + 1;
	}else{
		fname = file;
	}
	Xsprintf(TVStr(bin),"agrp-%s.bdg",fname);
	if( bfp = fopen(bin,"r") ){
		if( file_mtime(fileno(bfp)) < fmtime ){
			sv1tlog("--AC-- modified [%s]\n",xpath);
		}else{
			for( mi = 0; ; mi++ ){
				if( fread(&bent,sizeof(bent),1,bfp) != 1 ){
					break;
				}
				bln = ((bl[0]<<16)|(bl[1]<<8)|bl[2]) + 1;
				switch( bent.b_type[0] ){
				    case BT_MAC:
					if( bcmp(bd,bent.b_data,6) == 0 ){
						found = bln;
						goto FOUND;
					}
					break;
				    case BT_IPV4:
					if( bcmp(b4,bent.b_data,4) == 0 ){
						found = bln;
						goto FOUND;
					}
					break;
				}
			} FOUND:
			fclose(bfp);
			if( found ){
				if( md5.md_stat == 0 ){
					Verbose("--AC-- PUT [%s][%s][%s]\n",md5.md_md5a,iaddr,file);
					if( getMMcache(md5.md_md5b,MD5_CACHE_EXPIRE,iaddr,VStrNULL,0,&mm) ){
	sv1tlog("--AC-- #### DONT PUT DUP [%s][%s][%s]\n",md5.md_md5a,iaddr,file);
					}else{
						putMMcache(md5.md_md5b,found,iaddr,NULL);
					}
				}
			}
			return found;
		}
	}

	/*
	afp = fopenLIB(dfile,"r",AVStr(xpath));
	if( afp == NULL ){
		sprintf(xfile,"%s.txt",dfile);
		afp = fopenLIB(xfile,"r",AVStr(xpath));
	}
	if( afp == NULL ){
		sv1tlog("--AC-- matchF #### cannot open file:%s\n",dfile);
		return 0;
	}
	*/
	afp = fopenLIB(xpath,"r",AVStr(ypath));
	bfp = fopen(bin,"w");
	for( mi = 0; ; mi++ ){
		if( fgets(aline,sizeof(aline),afp) == NULL ){
			break;
		}
		if( *aline == '#' || *aline == '\r' || *aline == '\n' ){
			continue;
		}
		if( adtob(aline,i4a,sizeof(i4a)) == 4 ){
			if( bfp ){
				putBinEnt(bfp,i4a,BT_IPV4,mi);
			}
			if( bcmp(i4a,b4,4) == 0 ){
				found = mi+1;
				if( bfp == NULL ){
					break;
				}
			}
		}else{
			if( scanmaca(aline,AVStr(amc)) == 0 ){
				sv1tlog("--AC-- addrGroup #### invalid-mac-addr [%s]\n",aline);
			}
			if( strcaseeq(amc,qmac) ){
				strcpy(cmac,amc);
				found = mi+1;
				if( bfp == NULL ){
					break;
				}
			}
			if( bfp ){
				putBinEnt(bfp,amc,BT_MAC,mi);
			}
		}
	}
	fclose(afp);
	if( bfp ){
		sv1log("--AC-- %s <= %s [%d]\n",bin,xpath,mi);
		fclose(bfp);
	}
	return found;
}

#define inAddr(addr)  ((addr)->I3==HEURISTIC_MASK?".":VA_inAddr(addr))
int addrGroup(PCStr(addrpatp),PCStr(hostname),VAddr *hostaddr){
	double St = Time();
	IStr(cmac,256);
	IStr(amac,256);
	IStr(path,256);
	refQStr(pp,path);
	int match = 0;
	int now = time(0);
	IStr(addrpatb,256);
	refQStr(ap,addrpatb);
	int alist = 0;
	const char *flist = 0;

	Md5 md5 = {-9};
	md5.md_stat = startMD5(md5.md_md5x,sizeof(md5.md_md5x));
	if( md5.md_stat == 0 ){
		updateMD5(md5.md_md5x,addrpatp,strlen(addrpatp));
		updateMD5(md5.md_md5x,hostname,strlen(hostname));
		finishMD5(md5.md_md5x,md5.md_md5b,md5.md_md5a);
		if( bcmp(md5.md_md5b,AGcache.ag_md5b,16) == 0 ){
			if( now < AGcache.ag_ctime+AG_CACHE_EXPIRE ){
				match = AGcache.ag_match;
				strcpy(amac,AGcache.ag_amac);
				goto EXIT;
			}
		}
	}

	strcpy(addrpatb,addrpatp);
	if( addrpatb[0] == '{' ){
		ovstrcpy(addrpatb,addrpatb+1);
		alist = 1;
	}
	if( (ap = strtailstr(addrpatb,".ip4.list.-"))
	){
		clearVStr(ap);
		flist = ap+1;
	}
	if( (ap = strtailstr(addrpatb,".mac.list.-"))
	 || (ap = strtailstr(addrpatb,".ima.list.-"))
	){
		clearVStr(ap);
		flist = ap+1;
		if( ipa2macc(inAddr(hostaddr),AVStr(amac),sizeof(amac)) < 0 ){
			sprintf(amac,"0-0-0-0-0-0");
			/*
			return 0;
			*/
		}
	}
	if( strneq(addrpatb,"file=",5) ){
		ovstrcpy(addrpatb,addrpatb+5);
		if( flist == 0 ){
			flist = "";
		}
	}
	if( strneq(addrpatb,"mmap=",5) ){
		Xsscanf(addrpatb+5,"%[^}]",AVStr(path));
		match = addrMatchMmap(path,amac,AVStr(cmac));
	}else
	if( flist ){
		Xsscanf(addrpatb,"%[^}]",AVStr(path));
		strsubst(AVStr(path),"..",":");
		match = addrMatchFile(path,inAddr(hostaddr),amac,AVStr(cmac));
	}else{
		match = addrMatchList(addrpatb,amac,AVStr(cmac));
	}
	if( md5.md_stat == 0 ){
		bcopy(md5.md_md5b,AGcache.ag_md5b,16);
		strcpy(AGcache.ag_amac,amac);
		AGcache.ag_ctime = time(0);
		AGcache.ag_match = match;
	}
EXIT:
	sv1log("--AC--(%.5f) addrGroup[%s][%s][%s][%s] match=%d\n",
		Time()-St,hostname,inAddr(hostaddr),amac,addrpatp,match);
	return match;
}
#endif /* !LIBRARY */
