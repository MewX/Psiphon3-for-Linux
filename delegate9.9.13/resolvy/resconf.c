/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	reshost.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950817	created
//////////////////////////////////////////////////////////////////////#*/

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include "ystring.h"
#include "vsocket.h"
#include "file.h"
#include "log.h"
#include "dns.h"
void SOCKS_addserv(PCStr(dhost),int dport,PCStr(shost),int sport);
int RES_next_res(PCStr(where),int ri,PVStr(res),PVStr(arg));
void set_nameserver(PCStr(domain),PCStr(addr));
void minit_reshost();
int regGetResolvConf(PVStr(buf),PVStr(where));
int connectTO(int sock,SAP addr,int leng,int timeout);
void *callFuncTimeout(int sec,void *xcode,void *(*func)(void*,...),...);

void VSA_copy(VSAddr *dst,VSAddr *src);
int VSA_comp(VSAddr *sa1,VSAddr *sa2);

int DNS_debug;

#if defined(sgi) || defined(__RES) && (19931104 <= __RES)
#define _RSTATE 1
#else
#define _RSTATE 0
#endif

#ifdef RES_STATE
#define RSTATE !_RSTATE
#else
#define RSTATE  _RSTATE
#endif

#if RSTATE
typedef struct __res_state State;
#else
typedef struct state State;
#endif

#if defined(ultrix)
#define NSLIST(sx)	ns_list[sx].addr
#else
#define NSLIST(sx)	nsaddr_list[sx]
#endif

State _RES = {0};
int MIN_ABSNDOTS = 1;

#define MAX_SORTLIST	16
#define ADDRLEN	4
typedef struct {
	char	am_addr[ADDRLEN];
	char	am_mask[ADDRLEN];
} AddrMask;

typedef struct {
	MStr(	re_Resolvers,RESOLVERS_SIZ);
  const char   *re_ResolversPushed[64];
	int	re_ResolversPushedFlags[64];
	AddrMask re_sort_list[MAX_SORTLIST]; /**/
	int	re_Nsortlist;
	MStr(	re__confid,64);
	struct	hostent re_myhost;
	VSAddr	re_selfs[16];
	int	re_selfN;
	int	re_lastRRX[256];
	int	re_F_aton;
  const	char   *re_confpath;
	MStr(	re_resolv_errmsg,1024);
	int	re_ns_stop;
} ResolvyEnv;
static ResolvyEnv *resolvyEnv;
#define RE		resolvyEnv[0]
#define Resolvers	RE.re_Resolvers
/* MStr(Resolvers,re_Resolvers) */
/**/
#define PushedResolvers	RE.re_ResolversPushed
#define PushedResolversFlags	RE.re_ResolversPushedFlags
#define RES_ADDLAST 1
#define sort_list	RE.re_sort_list
#define Nsortlist	RE.re_Nsortlist
#define _confid		RE.re__confid
#define myhost		RE.re_myhost
#define selfs		RE.re_selfs
#define selfN		RE.re_selfN
#define lastRRX		RE.re_lastRRX
#define F_aton		RE.re_F_aton
#define confpath	RE.re_confpath
struct _resolv_errmsg { defQStr(resolv_errmsg); } resolv_errmsg;
#define ns_stop		RE.re_ns_stop

#ifndef RSLV_CONF
#define RSLV_CONF	"/etc/resolv.conf"
#endif

#ifndef HOSTSFILE
#define HOSTSFILE	"/etc/hosts"
#endif

#ifndef NISMAP_NAME
#define NISMAP_NAME	"hosts.byname"
#endif

#ifndef NISMAP_ADDR
#define NISMAP_ADDR	"hosts.byaddr"
#endif

#ifndef RSLV_ORDER
#define RSLV_ORDER	"CFNDS"
#endif

void minit_resconf()
{
	if( resolvyEnv == 0 ){
		resolvyEnv = NewStruct(ResolvyEnv);
		strcpy(Resolvers,RSLV_ORDER);
		setQStr(resolv_errmsg.resolv_errmsg,resolvyEnv->re_resolv_errmsg,sizeof(resolvyEnv->re_resolv_errmsg));
	}
	minit_reshost();
}
int getthreadix();
char *RES_resolvers(PVStr(resolvers))
{
	const char *res;
	const char *pushed;
	int tix = getthreadix();
	if( 0 <= tix && tix < elnumof(PushedResolvers) ){
		if( pushed = PushedResolvers[tix] ){
			if( PushedResolversFlags[tix] & RES_ADDLAST ){
				strcpy(resolvers,Resolvers);
				if( strstr(resolvers,pushed) == 0 )
					strcat(resolvers,pushed);
			}else{
				strcpy(resolvers,pushed);
			}
			return (char*)resolvers;
		}
	}
	strcpy(resolvers,Resolvers);
	return Resolvers;
}
int RES_orderSet_FL(FL_PAR,PCStr(resolvers)){
	strcpy(Resolvers,resolvers);
	return 0;
}
int RES_orderGet_FL(FL_PAR,PVStr(resolvers)){
	strcpy(resolvers,Resolvers);
	return 0;
}
int RES_orderPush_FL(FL_PAR,PCStr(tmpres),int flags){
	int tix = getthreadix();
	if( 0 <= tix && tix < elnumof(PushedResolvers) ){
		PushedResolvers[tix] = tmpres;
		PushedResolversFlags[tix] = flags;
	}else{
	}
	return 0;
}
int RES_orderPop_FL(FL_PAR){
	int tix = getthreadix();
	if( 0 <= tix && tix < elnumof(PushedResolvers) ){
		PushedResolvers[tix] = 0;
	}else{
	}
	return 0;
}

const char *_RSLV_CONF = RSLV_CONF;
const char *_HOSTSFILE = HOSTSFILE;
const char *_NISMAP_NAME = NISMAP_NAME;
const char *_NISMAP_ADDR = NISMAP_ADDR;

const char *RES_VERIFY;
#define VIA_SOCKS	"//"

void RES_getconf(PVStr(buf))
{	refQStr(bp,buf); /**/
	const char *addr;
	const char *dom;
	int ni,si;
	int options;

	sprintf(bp,"RES_ORDER=%s\n",Resolvers); bp += strlen(bp);
	sprintf(bp,"HOSTSFILE=%s\n",_HOSTSFILE); bp += strlen(bp);
	sprintf(bp,"NISMAP_NAME=%s\n",_NISMAP_NAME); bp += strlen(bp);
	sprintf(bp,"NISMAP_ADDR=%s\n",_NISMAP_ADDR); bp += strlen(bp);
	sprintf(bp,"RSLV_CONF=%s\n",_RSLV_CONF); bp += strlen(bp);
	sprintf(bp,"DNS_NSCOUNT=%d\n",_RES.nscount); bp += strlen(bp);
	options = _RES.options & ~(RES_DEBUG);
	sprintf(bp,"DNS_OPTIONS=%d\n",options); bp += strlen(bp);
	sprintf(bp,"DNS_DEFDNAME=%s\n",_RES.defdname); bp += strlen(bp);
	for( ni = 0; ni < _RES.nscount; ni++ ){
		addr = VSA_ntoa((VSAddr*)&_RES.nsaddr_list[ni]);
		sprintf(bp,"DNS_SERVER=%s\n",addr); bp += strlen(bp);
	}
	for( si = 0; dom = _RES.dnsrch[si]; si++ ){
		sprintf(bp,"DNS_SEARCH=%s\n",dom); bp += strlen(bp);
	}
}
char *RES_confid(PVStr(id))
{	CStr(buf,2048);

	if( _confid[0] == 0 ){
		RES_getconf(AVStr(buf));
		toMD5(buf,_confid);
		debug(DBG_CACHE,"#### RES_confid = %s\n%s",_confid,buf);
	}

	strcpy(id,_confid);
	debug(DBG_CACHE,"RES_confid = %s\n",id);
	return (char*)id;
}
#define clear_confid()	_confid[0] = 0;
char *RES_confidSet_FL(FL_PAR,PCStr(wh),PVStr(prev)){
	IStr(oldid,128);
	IStr(newid,128);
	if( prev ){
		strcpy(prev,_confid);
	}
	strcpy(oldid,_confid);
	clear_confid();
	RES_confid(AVStr(newid));
	debug(DBG_FORCE,"confid(%s)[%s]<-[%s]\n",wh,newid,oldid);
	return _confid;
}

static int bindINS(VSAddr *sin,int nlisten)
{	int sock,rcode;
	int sinlen;

	sock = socket(AF_INET,SOCK_STREAM,0);
	sinlen = VSA_size(sin);
	if( bind(sock,(SAP)sin,sinlen) == 0 ){
		listen(sock,nlisten);
		return sock;
	}else{
		close(sock);
		return -1;
	}
}
static int connINS(VSAddr *sin)
{	int sock;
	int sinlen;

	sock = socket(AF_INET,SOCK_STREAM,0);
	sinlen = VSA_size(sin);
	if( connectTO(sock,(struct sockaddr*)sin,sinlen,100) == 0 ){
		return sock;
	}else{
		close(sock);
		return -1;
	}
}

int RES_SYS_TIMEOUT = 3;
static struct hostent *_GethostByname(PCStr(name))
{	struct hostent *hp;
	double St = Time();
	double Et;

	/*
	hp = (struct hostent *)callFuncTimeout(3,NULL,(void*(*)(void*,...))EX_GETHOSTBYNAME,name);
	*/
	hp = (struct hostent *)callFuncTimeout(RES_SYS_TIMEOUT,NULL,(void*(*)(void*,...))EX_GETHOSTBYNAME,name);
	Et = Time() - St;
	if( 3 <= Et ){
		fprintf(stderr,"[%d] slow gethostbyname(%s)=%X [%.2f]\n",getpid(),name,p2i(hp),Et);
		debug(DBG_FORCE,"slow gethostbyname(%s)=%X [%.2f/%d]\n",name,p2i(hp),Et,RES_SYS_TIMEOUT);
	}
	return hp;
}

static struct hostent *getmyhost()
{	CStr(myname,256);
	struct hostent *hp;

	if( myhost.h_name != NULL )
		return &myhost;

	gethostname(myname,sizeof(myname));
	if( hp = _GethostByname(myname) )
		return hp;

	myhost.h_name = stralloc(myname);
	myhost.h_length = 4;
	myhost.h_addr_list = (char**)malloc(sizeof(char*)*2);
	myhost.h_addr_list[0] = (char*)calloc(1,4); /* 0.0.0.0 */
	myhost.h_addr_list[1] = NULL;
	return &myhost;
}

void RES_isself(int mysock)
{	int len;
	VSAddr *self1;

	if( elnumof(selfs) <= selfN )
		return;

	len = sizeof(VSAddr);
	self1 = &selfs[selfN];
	getsockname(mysock,(SAP)self1,&len);
	debug(DBG_ANY,"self [%d] %s\n",selfN,VSA_ntoa(self1));
	selfN++;
}
static int isself1(VSAddr *me,VSAddr *to)
{	int testsock;
	VSAddr sin;

	if( VSA_port(me) != VSA_port(to) )
		return 0;
	if( VSA_addr(me) == VSA_addr(to) )
		return 1;
	if( VSA_addrisANY(to) )
		return 1;
	if(!VSA_addrisANY(me) )
		return 0; /* neither is wild card "0.0.0.0" */

	/* now "me" is wildcard. so check if "to" is directed to "me" */
	if( VSA_addr(to) == inet_addrV4("127.0.0.1") )
		return 1;

	sin = *to;
	VSA_setport(&sin,0);
	testsock = bindINS(&sin,1);
	if( 0 <= testsock  ){
		close(testsock);
		return 1;
	}else	return 0;
}
static int isself(VSAddr *to)
{	int si;

	for( si = 0; si < selfN; si++ )
		if(  isself1(&selfs[si],to) )
			return 1;
	return 0;
}
void RES_nsloopcheck(int mysock)
{	int nsx,nsi,nsj;
	int len;
	VSAddr me,sin;

	len = sizeof(VSAddr);
	getsockname(mysock,(SAP)&me,&len);

	nsx = _RES.nscount;
	for( nsi = 0; nsi < nsx; ){
		VSA_copy(&sin,(VSAddr*)&_RES.NSLIST(nsi));
		if( isself1(&me,&sin) ){
			for( nsj = nsi; nsj < nsx-1; nsj++ )
				VSA_copy((VSAddr*)&_RES.NSLIST(nsj),(VSAddr*)&_RES.NSLIST(nsj+1));
			VSA_zero((VSAddr*)&_RES.NSLIST(nsj));
			_RES.nscount -= 1;
			nsx -= 1;
			debug(DBG_FORCE,"## removed self as NS[%d] %s:%d\n",
				nsi,VSA_ntoa(&sin),VSA_port(&sin));
		}else	nsi++;
	}
}

const char *scanHostport(PCStr(ns),PVStr(nsb),int *portp){
	strcpy(nsb,ns);
	if( strchr(ns,':') ){
		Xsscanf(ns,"%[^:]:%d",BVStr(nsb),portp);
		return nsb;
	}else
	if( strstr(ns,"..") ){
		refQStr(np,nsb);
		strcpy(nsb,ns);
		if( np = strstr(nsb,"..") ){
			setVStrEnd(np,0);
			*portp = atoi(np+2);
			return nsb;
		}
	}
	return ns;
}

void RES_addns(VSAddr *ns);
/*
void RES_socks(PCStr(ns),PCStr(socks));
*/
void RES_socks(VSAddr *nsa,PCStr(socks));
void RES_ns1(State *res,PCStr(ns),PCStr(domain))
{
	VSAddr sin;
	int nsx;
	struct hostent *hp;
	const char *saddr;
	const char *socks;
	const char *cp;
	CStr(nsb,256);
	CStr(ssb,256);
	CStr(nsbp,256);
	int port;

	if( ns_stop )
		return;
	if( *ns == '$' ){
		if( ServerMain )
		debug(DBG_FORCE,"---- RES_ns1(%s) ignored\n",ns);
		/* RES_ORDER=D:$N as an internal format */
		return;
	}
	putResTrace("NS(%s)",ns);
	if( lDNS_SORT() ){
		VSA_atosa(&sin,53,ns);
		if( sizeof(res->NSLIST(nsx)) < VSA_size((VSAddr*)&sin) ){
			/* should not copy IPv6 */
			debug(DBG_FORCE,"#### RES_NS %d/%d %s\n",
				isizeof(res->NSLIST(nsx)),VSA_size((VSAddr*)&sin),
				VSA_ntoa((VSAddr*)&sin));
			RES_addns(&sin);
			return;
		}
	}

	clear_confid();
	nsx = -1;
	if( strcmp(domain,RES_NSDOM0) == 0 ){
		/* reserver the position */
		if( res->nscount < MAXNS ){
			nsx = res->nscount++;
			VSA_zero((VSAddr*)&res->NSLIST(nsx));
		}
	}

	ssb[0] = 0;
	if( socks = strstr(ns,VIA_SOCKS) ){
		strcpy(nsb,ns);
		ns = nsb;
		socks = strstr(ns,VIA_SOCKS);
		truncVStr(socks);
		if( cp = strpbrk(ns,"# \t") )
			truncVStr(cp);
		/*
		Xsscanf(socks+strlen(VIA_SOCKS),"%[-_.0-9A-Z:]",AVStr(ssb));
		*/
		Xsscanf(socks+strlen(VIA_SOCKS),"%[-_.0-9A-Za-z:%%]",AVStr(ssb));
	}

	port = PORT_DNS;
	ns = scanHostport(ns,AVStr(nsbp),&port);
	/*
	if( strchr(ns,':') ){
		Xsscanf(ns,"%[^:]:%d",AVStr(nsbp),&port);
		ns = nsbp;
	}
	*/

	if( VSA_strisaddr(ns) )
		VSA_atosa(&sin,port,ns);
	else
	if( hp = _GethostByname(ns) )
		VSA_htosa(&sin,port,hp,0);
	else
	if( hp = _GETHOSTBYNAME(ns) )
		VSA_htosa(&sin,port,hp,0);
	else	VSA_atosa(&sin,port,"255.255.255.255");

	if( !VSA_isaddr(&sin) ){
		debug(DBG_FORCE,"ERROR: unknown DNS server: %s\n",ns);
		/* remove the reserved slot */
		if( 0 <= nsx ){
			res->nscount--;
			for(; nsx < res->nscount; nsx++ )
				res->NSLIST(nsx) = res->NSLIST(nsx+1);
		}
		return;
	}

	if( isself(&sin) ){
		debug(DBG_FORCE,"## don't add self[%s:%d] as NS\n",
			VSA_ntoa(&sin),VSA_port(&sin));
		return;
	}
	saddr = VSA_ntoa(&sin);
	RES_socks(&sin,ssb);
	/*
	RES_socks(saddr,ssb);
	*/

	if( strcmp(domain,RES_NSDOM0) == 0 ){
	  int nsi;
	  for( nsi = 0; nsi < res->nscount; nsi++ ){
		if( VSA_comp(&sin,(VSAddr*)&res->NSLIST(nsi)) == 0 ){
			debug(DBG_FORCE,"dup. RES_NS[%d]=%s:%d ignored\n",
				nsi,VSA_ntoa(&sin),VSA_port(&sin));
			if( 0 <= nsx && nsx+1 == res->nscount ){
				/* remove the reserved slot */
				res->nscount--;
			}
			return;
		} 
	  }
	  if( 0 <= nsx ){
		if( lDNS_SORT() ){
			RES_addns(&sin);
		}
		VSA_copy((VSAddr*)&res->NSLIST(nsx),&sin);
		debug(DBG_ANY,"        RES_NS[%d]=%s/%s\n",nsx,saddr,domain);
	  }else	debug(DBG_ANY," ignore RES_NS(%d)=%s/%s\n",MAXNS,ns,domain);
	}else{
		debug(DBG_ANY,"        RES_NS[%d]=%s/%s\n",nsx,saddr,domain);
		set_nameserver(domain,saddr);
	}
}

int DNS_connect(PCStr(addr),int port)
{	VSAddr sin;

	VSA_atosa(&sin,port,addr);
	return connINS(&sin);
}

int RES_getns1(int nsi,VSAddr *sin)
{	State *res;

	res = &_RES;
	if( nsi < _RES.nscount ){
		VSA_copy(sin,(VSAddr*)&res->NSLIST(nsi));
		return 1;
	}
	return 0;
}
const char *VSA_ntoa(VSAddr *sap);
int RES_getnslist(PVStr(list)){
	refQStr(lp,list);
	int ni;
	VSAddr sin;
	const char *addr;

	for( ni = 0; ni < _RES.nscount; ni++ ){
		if( RES_getns1(ni,&sin) ){
			if( addr = VSA_ntoa(&sin) ){
				Rsprintf(lp,"%s%s",0<ni?",":"",addr);
			}
		}
	}
	return ni;
}

/* acting as a proxy */
int RES_proxy(){
	if( _RES.nscount == 0 )
		return 0;
	if( strchr(Resolvers,'D') != 0 )
		return 1;
	return 0;
}

int stoBV(PCStr(str),PVStr(buf),int mc,int ez){
	const char *sp = str;
	int sc;
	refQStr(b1,buf); /**/

	for(sc = 0; sc < mc; sc++){
		setQStr(b1,&buf[sc*ez],ez);
		if( 0 ){
		sp = wordscanX(sp,ZVStr(b1,ez),ez);
		}else{
			/* 9.9.8 for search/sortlist delimited by "," */
			while( isspace(*sp) || *sp == '#' || *sp == ',' ){
				sp++;
			}
			sp = wordscanY(sp,ZVStr(b1,ez),ez,"^ \t\r\n#,");
		}
		if( *b1 == 0 )
			break;
	}
	if( *sp != 0 ){
		porting_dbg("##resolv.conf ignored too many elements (%d){%s}",
			mc,str);
	}
	return sc;
}

void RES_scan_sortlist(PCStr(line));
void load_rslvconf(State *res,PCStr(path),int loadns)
{	FILE *fp;
	CStr(line,1024);
	CStr(com,1024);
	CStr(arg,1024);
	const char *dp;
	ACStr(s,8,128);
	int sc,si;

	clear_confid();
	debug(DBG_ANY,"load_rslvconf(%s)\n",path);
	if( strncmp(path,"sh:",3) == 0 )
		fp = popen(path+3,"r");
	else
	if( strncmp(path,"file:",5) == 0 )
		fp = fopen(path+5,"r");
	else	fp = fopen(path,"r");

	if( fp == NULL ){
		CStr(buff,2048);
		CStr(where,256);
		if( regGetResolvConf(AVStr(buff),AVStr(where)) == 0 ){
			fp = TMPFILE("regGetResolvConf");
			fputs(buff,fp);
			fflush(fp);
			fseek(fp,0,0);
			debug(DBG_ANY,"resolv.conf from registory: %s\n%s\n",
				where,buff);
		}
	}

	if( fp == NULL )
		return;

	while( fgets(line,sizeof(line),fp) != NULL ){
	    if( dp = strpbrk(line,"#;") )
		truncVStr(dp);
	    if( Xsscanf(line,"%s %s",AVStr(com),AVStr(arg)) < 2 )
		continue;

	    if( strcmp(com,"debug") == 0 ){
		res->options |=  RES_DEBUG;
	    }else
	    if( strcmp(com,"nameserver") == 0 ){
		if( loadns ){
		    RES_ns1(res,arg,RES_NSDOM0);
		}
	    }else
	    if( strcmp(com,"domain") == 0 ){
		Xstrcpy(EVStr(res->defdname),arg);
		res->options |= RES_DEFNAMES;
	    }else
	    if( strcmp(com,"ndots") == 0 ){
		MIN_ABSNDOTS = atoi(arg);
	    }else
	    if( strcmp(com,"search") == 0 ){
/*
		sc = sscanf (line,"%*s %s %s %s %s %s %s %s %s",s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]);
*/
		sc = stoBV(wordscanX(line,EVStr(s[0]),sizeof(s[0])),ZVStr((char*)s,sizeof(s)),8,128);

		if( loadns && 0 < sc ){
		    Xstrcpy(EVStr(res->defdname),s[0]);
		    for( si = 0; si < MAXDNSRCH && si < sc; si++ ){
			debug(DBG_ANY,"        RES_SRCH[%d] %s\n",si,s[si]);
			res->dnsrch[si] = stralloc(s[si]);
		    }
		    res->dnsrch[sc] = 0;
		    res->options |=  RES_DNSRCH;
		    res->options &= ~RES_DEFNAMES;
		}
	    }else
	    if( strcmp(com,"sortlist") == 0 ){
		RES_scan_sortlist(line);
	    }
	}
	if( strncmp(path,"sh:",3) == 0 )
		pclose(fp);
	else	fclose(fp);
}

static scanListFunc ns1(PCStr(name))
{	CStr(nameb,128);
	const char *domain;

	if( strcaseeq(name,"END.") )
		ns_stop = 1;
	if( ns_stop )
		return 0;

	strcpy(nameb,name);
	if( domain = strchr(nameb,'/') )
		if( domain[1] == '/' )
			domain = strchr(domain+2,'/');
	if( domain ){
		truncVStr(domain); domain++;
	}else	domain = RES_NSDOM0;

	RES_ns1(&_RES,nameb,domain);
	return 0;
}
int RES_ns(PCStr(nslist))
{
	if( nslist )
		scan_commaList(nslist,0,scanListCall ns1);
	return 0;
}
void RES_af(PCStr(af)){
	const char *tp;

	for( tp = af; *tp; tp++ ){
		if( *tp != '4' && *tp != '6' ){
			debug(DBG_FORCE,"unknown RES_AF[%c] %s\n",*tp,af);
			return;
		}
	}
	RES_AF = stralloc(af);
}
void RES_verify(PCStr(verify))
{
	RES_VERIFY = stralloc(verify);
}
void RES_verifyFaiure(PCStr(host),PVStr(badhost))
{	const char *sp;
	char sc;
	refQStr(dp,badhost); /**/

	if( sp = RES_VERIFY ){
		for( ; sc = *sp; sp++ ){
			assertVStr(badhost,dp);
			if( sc == '*' ){
				strcpy(dp,host);
				dp += strlen(dp);
			}else{
				setVStrPtrInc(dp,sc);
			}
		}
	}
	setVStrEnd(dp,0);
}

int RES_debug(PCStr(debug))
{
	if( streq(debug,"0") ){
		_RES.options = 0;
		DNS_debug = 0;
		return 0;
	}
	_RES.options |= RES_DEBUG;
	if( strncmp(debug,"0x",2) == 0 )
	sscanf(debug+2,"%x",&DNS_debug);
	else
	DNS_debug |= atoi(debug);
	return 0;
}
int RES_domain(PCStr(domain))
{
	Xstrcpy(EVStr(_RES.defdname),domain);
	return 0;
}
int RES_order(PCStr(order),xPVStr(porder))
{	int oi;
	CStr(buff,RESOLVERS_SIZ);

	minit_resconf();

	clear_confid();
	if( porder == NULL ){
		setPStr(porder,buff,sizeof(buff));
	}

	strcpy(porder,Resolvers);
	if( order == NULL )
		return 0;

	FStrncpy(Resolvers,order);

	debug(DBG_ANY,"RES_order(%s,%s)\n",Resolvers,porder);
	return 0;
}
int RES_conf(PCStr(path))
{
	if( _RSLV_CONF == confpath )
		free((char*)confpath);
	_RSLV_CONF = confpath = stralloc(path);
	return 0;
}
int RES_hosts(PCStr(path))
{
	_HOSTSFILE = stralloc(path);
	return 0;
}

void RES_add_sortlist1(PCStr(addr),char mask[],int len);
void RES_add_sortlist(const char *addrs[],char *masks[],int len)
{	int sx;

	for( sx = 0; addrs[sx]; sx++)
		RES_add_sortlist1(addrs[sx],masks?masks[sx]:NULL,len);
}
void RES_add_sortlist1(PCStr(addr),char mask[],int len)
{	AddrMask *sp;
	int ai,nm;
	CStr(dmask,32);
	const unsigned char *ua;
	const unsigned char *um;

	if( MAX_SORTLIST <= Nsortlist+1 ){
		debug(DBG_ANY,"!! exceed MAX_SORTLIST[%d]\n",MAX_SORTLIST);
		return;
	}
	if( mask == NULL || mask[0] == 0 ){
		mask = dmask;
		switch( ((int)addr[0] & 0xC0) >> 6 ){
		    case 0:  nm = 1; break;
		    case 2:  nm = 2; break;
		    default: nm = 3; break;
		}
		for( ai = 0; ai < nm ; ai++ )
			mask[ai] = 255;
		for( ; ai < len && ai < sizeof(dmask); ai++ )
			mask[ai] = 0;
	}

	ua = (unsigned char *)addr;
	um = (unsigned char *)mask;
	debug(DBG_ANY,"        sortlist[%d] %d.%d.%d.%d / %d.%d.%d.%d\n",
		Nsortlist,
		ua[0],ua[1],ua[2],ua[3],
		um[0],um[1],um[2],um[3]);

	sp = &sort_list[Nsortlist++];
	for(ai = 0; ai < len; ai++){
		sp->am_addr[ai] = addr[ai];
		sp->am_mask[ai] = mask[ai];
	}
}
void RES_scan_sortlist(PCStr(line))
{	ACStr(s,16,128);
	CStr(addr,32);
	CStr(mask,32);
	int a[16],m[16];
	int sc,si,ai;
	CStr(ba,16);
	CStr(bm,16);
	int len = 4;

	sc = stoBV(wordscanX(line,EVStr(s[0]),sizeof(s[0])),ZVStr((char*)s,sizeof(s)),16,128);

	for( si = 0; si < sc; si++ ){
		addr[0] = mask[0] = 0;
		Xsscanf(s[si],"%[^/]/%s",AVStr(addr),AVStr(mask));
		for( ai = 0; ai < len; ai++ )
			a[ai] = m[ai] = 0;
		sscanf(addr,"%d.%d.%d.%d",&a[0],&a[1],&a[2],&a[3]);
		sscanf(mask,"%d.%d.%d.%d",&m[0],&m[1],&m[2],&m[3]);
		for( ai = 0; ai < len; ai++ ){
			ba[ai] = a[ai]; /**/
			bm[ai] = m[ai]; /**/
		}
		RES_add_sortlist1(ba,bm,len);
	}
}

int RES_ROUNDROBIN = 1;

void RES_roundrobin(PCStr(hosts))
{
	if( strcmp(hosts,"*") == 0 )
		RES_ROUNDROBIN = 1;
	else	RES_ROUNDROBIN = 0;
}

int sort_ipaddrs1(const char *addrs[],PCStr(ap),PCStr(mp));
void sort_ipaddrs(const char *addrs[])
{	int si,sx,hit;

	if( RES_ROUNDROBIN ){
		int sn,si,sx,so,rrx;
		const char *saddrs[256]; /**/
		const unsigned char *a1;

		rrx = 0;
		for( sn = 0; saddrs[sn] = addrs[sn]; sn++ ){
			if( elnumof(saddrs) <= sn ){
				break;
			}
			a1 = (unsigned char *)saddrs[sn];
			rrx += a1[0] + a1[1] + a1[2] + a1[3];
		}
		rrx %= 256;
		sx = lastRRX[rrx] % sn;
		lastRRX[rrx] += 1;
		so = 0;
		for( si = sx; si < sn; si++ )
			addrs[so++] = saddrs[si];
		for( si = 0; si < sx; si++)
			addrs[so++] = saddrs[si];
	}

	hit = 0;
	for( si = 0; si < Nsortlist; si++ ){
		const char *ap;
		const char *mp;
		ap = sort_list[si].am_addr;
		mp = sort_list[si].am_mask;
		hit += sort_ipaddrs1(&addrs[hit],ap,mp);
	}
}

#define btohl(ap) ((ap[0]<<24) | (ap[1]<<16) | (ap[2]<<8) | ap[3])
int sort_ipaddrs1(const char *addrs[],PCStr(sap),PCStr(smp))
{	const unsigned char *ap = (unsigned char *)sap;
	const unsigned char *mp = (unsigned char *)smp;
	const char *cap;
	const char *saddrs[256]; /**/
	CStr(done,1);
	int ciaddr,cimasked;
	int sn,sx,dn,hit,imask;

	ciaddr = btohl(ap);
	imask = btohl(mp);
	cimasked = ciaddr & imask;

	for( sn = 0; addrs[sn]; sn++ )
		;

	dn = 0;
	for( sx = 0; cap = addrs[sx]; sx++ ){
		if( cap != done )
		if( (btohl(cap) & imask) == cimasked ){
			if( elnumof(saddrs) <= dn )
				break;
			saddrs[dn++] = (char*)cap;
			addrs[sx] = done;
		}
	}
	hit = dn;
	for( sx = 0; sx < sn; sx++ )
		if( addrs[sx] != done )
			saddrs[dn++] = addrs[sx];
	for( sx = 0; sx < sn; sx++ )
		addrs[sx] = saddrs[sx];

	debug(DBG_ANY,"sort_ipaddrs(%d.%d.%d.%d/%d.%d.%d.%d) - %d/%d\n",
		ap[0],ap[1],ap[2],ap[3],mp[0],mp[1],mp[2],mp[3],hit,sn);
	return hit;
}
static void res_getoptions(int options,PVStr(soptions))
{
	setVStrEnd(soptions,0);
	if( options & RES_DEBUG    ) strcat(soptions,"DEBUG ");
	if( options & RES_RECURSE  ) strcat(soptions,"RECURSE ");
	if( options & RES_DEFNAMES ) strcat(soptions,"DEFNAMES ");
	if( options & RES_DNSRCH   ) strcat(soptions,"DNSRCH ");
}

int RES_localdns;
void RES_init()
{	const char *env;
	const char *conf;
	CStr(savorder,RESOLVERS_SIZ);
	int loadns;
	struct hostent *hp;
	CStr(options,1024);
	int rx;
	CStr(res1,RESOLVERS_SIZ);
	CStr(arg,RESOLVERS_SIZ);

	putResTrace("Init");
	minit_resconf();

	if( _RES.options & RES_INIT )
		return;
	_RES.options |= RES_INIT;

	if( env = getenv("RES_DEBUG") )
		RES_debug(env);

	if( _RES.options & RES_DEBUG ){
		if( DNS_debug == 0 )
			DNS_debug = DBG_NS;
	}
	debug(DBG_ANY,"RES_init()\n");
	FStrncpy(savorder,Resolvers);
	strcpy(Resolvers,"FND");

	FStrncpy(Resolvers,savorder);
	if( env = getenv("RES_ORDER") )
		FStrncpy(Resolvers,env);
	debug(DBG_ANY,"        RES_ORDER=%s\n",Resolvers);

	for( rx = 0; rx = RES_next_res(Resolvers,rx,AVStr(res1),AVStr(arg)); ){
		if( res1[0] == 'D' && arg[0] != 0 )
			RES_ns1(&_RES,arg,RES_NSDOM0);
	}

	if( env = getenv("RES_NS") )
		RES_ns(env);
	if( env = getenv("RES_VRFY") )
		RES_verify(env);

/*
	loadns = _RES.nscount == 0;
*/
	loadns = 1; /* NSLIST is necessary for resolution of other NS ... */
	if( (conf = getenv("RES_CONF")) == 0 )
		conf = _RSLV_CONF;
	load_rslvconf(&_RES,conf,loadns);

	if( env = getenv("RES_HOSTS") )
		RES_hosts(env);

	if( Nsortlist == 0 )
	if( hp = getmyhost() )
		RES_add_sortlist((const char**)hp->h_addr_list,NULL,hp->h_length);

	if( _RES.nscount == 0 )
	/* registory about DNS should be searched on Windows ... */
	if( hp = getmyhost() ){
		const unsigned char *ap;
		CStr(saddr,32);
		int dnsock;

		ap = (unsigned char*)hp->h_addr_list[0];
		/* ap[3] = 0xFF;  (broad cast in the segment) */
		sprintf(saddr,"%d.%d.%d.%d",ap[0],ap[1],ap[2],ap[3]);

		if( RES_localdns == 0 ){
			if( 0 <= (dnsock = DNS_connect(saddr,PORT_DNS)) ){
				close(dnsock);
				RES_localdns = 1;
				debug(DBG_FORCE,"Found local NS (%s:%d)\n",
					saddr,PORT_DNS);
			}else{
				RES_localdns = -1;
				debug(DBG_FORCE,"No local NS (%s:%d)\n",
					saddr,PORT_DNS);
			}
		}
		if( 0 < RES_localdns )
			RES_ns1(&_RES,saddr,RES_NSDOM0);

	}
	if( (env = getenv("RES_DOMAIN")) || (env = getenv("LOCALDOMAIN")) ){
		Xstrcpy(EVStr(_RES.defdname),env);
		_RES.options &= ~RES_DNSRCH;
		_RES.options |=  RES_DEFNAMES;
	}

	if( _RES.defdname[0] )
		debug(DBG_ANY,"        RES_DOMAIN=%s\n",_RES.defdname);

	res_getoptions(_RES.options,AVStr(options));
	debug(DBG_ANY,"        options = %s\n",options);
}

iFUNCP RES_debugprinter;
int FMT_res_debug(int flag,PCStr(fmt),...)
{	int now;
	VARGS(14,fmt);

	if( flag == DBG_FORCE || _RES.options & RES_DEBUG && DNS_debug & flag ){
		now = time(0);
		if( RES_debugprinter )
			(*RES_debugprinter)(fmt,VA14);
		else{
			fprintf(stderr,"%02d:%02d ",(now%3600)/60,now%60);
			fprintf(stderr,fmt,VA14);
		}
		return 1;
	}else	return 0;
}
int (*RES_log)(int,...);
void res_log(int which,int byname,PCStr(name),char *rv[],PCStr(cname))
{
	if( RES_log )
		(*RES_log)(which,byname,name,rv,cname);
}

static void putNames(struct hostent *hp)
{	const unsigned char *op;
	int hi;

	printf("%s",hp->h_name);
	for( hi = 0; ;hi++){
		op = (unsigned char*)hp->h_aliases[hi];
		if( op == NULL )
			break;
		printf(",%s",op);
	}
}
static void putAddrs(struct hostent *hp)
{	const unsigned char *op;
	int hi;

	for( hi = 0; ; hi++ ){
		op = (unsigned char*)hp->h_addr_list[hi];
		if( op == NULL )
			break;
		if( 0 < hi )
		printf(",");
		/*
		printf("%d.%d.%d.%d",op[0],op[1],op[2],op[3]);
		*/
		printf("%s",VSA_ltoa(op,hp->h_length,hp->h_addrtype));
	}
}

struct hostent *RES_gethost(PCStr(addrhost))
{	struct hostent *hp;
	VSAddr sab;
	int bleng,btype;
	const char *baddr;

	if( VSA_strisaddr(addrhost) ){
		VSA_atosa(&sab,0,addrhost);
		bleng = VSA_decomp(&sab,&baddr,&btype,NULL);
		hp = _GETHOSTBYADDR(baddr,bleng,btype);
	}else{
		hp = _GETHOSTBYNAME(addrhost);
	}
	return hp;
}
void RES_1(int f_aton,FILE *fp,PCStr(arg))
{	struct hostent *hp;

	if( f_aton ){
		if( VSA_strisaddr(arg) ) /* is IP address */
			if( hp = RES_gethost(arg) ){
				printf("%s\n",hp->h_name);
				return;
			}
		printf("%s\n",arg);
		return;
	}
	hp = RES_gethost(arg);

	if( hp ){
		const unsigned char *op;
		int hi;
		putAddrs(hp);
		printf("\t");
		putNames(hp);
		printf("\n");
	}else{
		if( VSA_strisaddr(arg) )
			printf("?\t%s\n",arg);
		else	printf("%s\t?\n",arg);
		/*exit(1);*/
	}
}
int RES_1s(PCStr(addrhost),PVStr(addr_host))
{	struct hostent *hp;
	const unsigned char *op;
	CStr(addr,32);

	if( hp = RES_gethost(addrhost) ){
		op = (unsigned char *)hp->h_addr;
		sprintf(addr,"%d.%d.%d.%d",op[0],op[1],op[2],op[3]);
		sprintf(addr_host,"%s\t%s\n",addr,hp->h_name);
		return 1;
	}
	return 0;
}

extern int RSLV_TIMEOUT;
int RES_timeout(int timeout)
{
	RSLV_TIMEOUT = timeout;
	return 1;
}

/*
void RES_socks(PCStr(ns),PCStr(socks))
*/
void RES_socks(VSAddr *nsa,PCStr(socks))
{	CStr(host,256);
	int port;
	const char *ns;
	int nsport;

	if( *socks == 0 )
		return;

	port = 1080;
	socks = scanHostport(socks,AVStr(host),&port);
	/*
	Xsscanf(socks,"%[^:]:%d",AVStr(host),&port);
	*/
	if( !VSA_strisaddr(host) )
		return;

	ns = VSA_ntoa(nsa);
	nsport = VSA_port(nsa);
	debug(DBG_ANY,"SOCKS=%s:%d:%s..%d\n",host,port,ns,nsport);
	SOCKS_addserv(ns,nsport,host,port);
	/*
	debug(DBG_ANY,"SOCKS=[%s][%s:%d]\n",ns,host,port);
	SOCKS_addserv(ns,PORT_DNS,host,port);
	*/
}

char **res_DNSRCH(){
	if( (_RES.options & RES_DNSRCH) && _RES.dnsrch[0] )
		return _RES.dnsrch;
	else	return NULL;
}
char *res_DEFDNAME(){
	if( (_RES.options & RES_DEFNAMES) && _RES.defdname[0] )
		return _RES.defdname;
	else	return NULL;
}


static void resolv1(PCStr(arg));
void dns_server(int qsock,int rsock);
void DO_INITIALIZE(int ac,const char *av[]);

int resolvy_main(int ac,const char *av[])
{	int ai;
	int itvl;
	const char *arg;

	minit_resconf();
	DO_INITIALIZE(ac,av);

	if( ac <= 1 ){
 fprintf(stderr,
"Usage -- %s [NS=nameserver] { domain-name | ip-address }\n",av[0]);
 fprintf(stderr,
"<ip-address> can be specified as a range like: aa.bb.cc.dd-ee\n");
		exit(-1);
	}
	itvl = 0;
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( strncmp(arg,"-d",2) == 0 ){
			RES_debug(arg+2);
			continue;
		}else
		if( strncmp(arg,"-i",2) == 0 ){
			itvl = atoi(arg+2);
		}else
		if( strcmp(arg,"+n") == 0 ){
			F_aton = 1;
			continue;
		}else
		if( strncmp(arg,"NS=",3) == 0 ){
			RES_ns(arg+3);
		}else
		if( strcmp(arg,"-") == 0 ){
			CStr(line,256);
			while( Fgets(AVStr(line),sizeof(line),stdin) != NULL ){
				RES_1(F_aton,stdout,line);
				fflush(stdout);
			}
		}else
		if( strcmp(arg,"-s") == 0 ){
			dns_server(0,1);
		}else{
			resolv1(arg);
			if( itvl && ai+1 < ac )
				sleep(itvl);
		}
	}
	exit(0);
	return 0;
}
static void resolv1(PCStr(arg))
{	int a1,a2,a3,a41,a42,a4;
	CStr(addr,256);

	if( strneq(arg,"_-",2) ){
		const char *dp;
		if( dp = strchr(arg+2,'.') )
			arg = dp+1;
	}
	if( sscanf(arg,"%d.%d.%d.%d-%d",&a1,&a2,&a3,&a41,&a42) == 5 ){
		for( a4 = a41; a4 < a42; a4++ ){
			sprintf(addr,"%d.%d.%d.%d",a1,a2,a3,a4);
			RES_1(F_aton,stdout,addr);
		}
	}else{
		RES_1(F_aton,stdout,arg);
	}
	fflush(stdout);
}
