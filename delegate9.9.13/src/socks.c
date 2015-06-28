/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	socks.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

	SOCKS=host[:[port][/version][:dstHostList[:srcHostList]]]

History:
	991119	extracted from socks4.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
/*
#include "vaddr.h"
*/
#include "delegate.h"
#include "auth.h"
#include "filter.h" /* STLS */

int SOCKS_startV5(int sock,int command,PCStr(host),int port,PCStr(user),PCStr(pass),PVStr(rhost),int *rport);
int SOCKS_serverV5(DGC*ctx,int fromcl,int tocl,int timeout_ms);
void SOCKS_addserv(PCStr(dhost),int dport,PCStr(shost),int sport);
int SOCKS_recvResponseV5(int sock,int command,PVStr(rhost),int *rport);

int SocksV4_clientStart(int sock,int command,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport,PVStr(xaddr));
void SocksV4_server(DGC*ctx,int _1,int _2,int fromC,int toC);
int SocksV4_isConnectReuqest(PCStr(pack),int leng,int *ver,PVStr(addr),int *port,const char **user);
int SocksV4_acceptViaSocks(int sock,PVStr(rhost),int *rport);

int connectToSox(Connection *Conn,PCStr(wh),PCStr(proto),PCStr(host),int port);

int forwardit(Connection *Conn,int fromC,int relay_input);
int DELEGATE_forwardX(Connection *Conn,PCStr(proto),PCStr(dsthost),int dstport,PCStr(srchost),const char **rproto,AuthInfo **rauth,const char **rhost,int *rport,const char **rpath);

int openServer(Connection *Conn,PCStr(wh),PCStr(proto),PCStr(host),int port){
	int sock;

	if( strneq(proto,"socks",5) ){
		int fw,dofw;
		IStr(clnt,128);
		const char *rproto,*rhost,*rpath;
		AuthInfo *ident;
		int rport;

		if( getClientHostPort(Conn,AVStr(clnt)) == 0 )
			strcpy(clnt,"?");
		fw = DELEGATE_forwardX(Conn,proto,host,port,clnt,
			&rproto,&ident,&rhost,&rport,&rpath);
		if( fw )
		if( rport == port && hostcmp(host,rhost) == 0 ){
			/* loop ? */
		}else{
			Port sv;
			Port sv_dflt;
			sv = Conn->sv;
			sv_dflt = Conn->sv_dflt;
			set_realserver(Conn,proto,host,port);
			dofw = forwardit(Conn,-1,0);
			sock = ToS;
			Conn->sv = sv;
			Conn->sv_dflt = sv_dflt;

 sv1log("####openServer=%d[%d] [%s %s %d]<=[%s %s %d]<=[%s %s %d]\n",
	dofw,sock,DST_PROTO,DST_HOST,DST_PORT,proto,host,port,
	rproto,rhost,rport);

			if( 0 <= sock ){
				return sock;
			}
		}
	}
	if( 0 <= (sock = connectToSox(Conn,"SOCKS","socks",host,port)) ){
		return sock;
	}else	return OpenServer(wh,proto,host,port);
}
#undef OpenServer
#define OpenServer(wh,proto,host,port) openServer(Conn,wh,proto,host,port)

#define SOCKS_PORT	1080
#define SOCKS_CONNECT	1
#define SOCKS_BIND	2
#define SOCKS_ACCEPT	8	/* pseudo command */

typedef struct {
  const	char	*s_Host;
	int	 s_port;
	int	 s_ver;
	int	 s_rslv; /* V4:delegate resolution, V5:resolv in mylsef */
	int	 s_sock;
	int	 s_istmp; /* v9.9.10 fix-140715c is-temporary on stack */
  const char	*s_dsts;
	VSAddr	*s_svaddr;
	VSAddr	*s_svlocal;
} SocksServer;

typedef struct {
  SocksServer  *v_serv;
	int	v_addr;
	int	v_port;
	VSAddr	v_local; /* source address for the destination */
} ViaSocks;
#define NVIAS 64

typedef struct {
	ViaSocks se_viaSocks[NVIAS]; /**/
	MStr(	se_Username,64);
	SocksServer se_sockservs[8]; /**/
	int	se_bind_ver;
	int	se_resolv_bymyself;
} SocksEnv;

static SocksEnv *socksEnv;
#define viaSocks	socksEnv->se_viaSocks
#define Username	socksEnv->se_Username
/**/
#define sockservs	socksEnv->se_sockservs
#define bind_ver	socksEnv->se_bind_ver
#define resolv_bymyself(host)	socksEnv->se_resolv_bymyself

void minit_socks()
{
	if( socksEnv == 0 )
		socksEnv = NewStruct(SocksEnv);
}

/*
 *	SOCKS CLIENT
 */

extern const char *hostmatch_asisaddr;
static void socks_init(DGC*_,PCStr(svhost),PCStr(svportver),PCStr(dsts),PCStr(srcs))
{	int sx;
	const char *opts;
	const char *host1;
	CStr(key,32);
	CStr(map,1024);
	int port;
	int ver = 5;
	IStr(xopts,128);

	if( svhost == 0 || svhost[0] == 0 )
		return;

	port = 0;
	opts = NULL;

	if( svportver ){
		port = atoi(svportver);
		if( opts = strchr(svportver,'/') )
			opts++;
	}
	if( port == 0 )
		port = SOCKS_PORT;
	if( opts != NULL ){
		if( strcmp(opts,"-4") == 0 )
			ver = 4;
		if( strcmp(opts,"-r") == 0 )
			socksEnv->se_resolv_bymyself = 1;

		if( isinListX(opts,"-4","/") )
			ver = 4;
		if( isinListX(opts,"-r","/") )
			socksEnv->se_resolv_bymyself = 1;
	}

	for( sx = 0; host1 = sockservs[sx].s_Host; sx++ ){
		if( host1[0] == 0 )
			break;
		if( sockservs[sx].s_port == port )
		if( hostcmp(sockservs[sx].s_Host,svhost) == 0 )
			return;
	}
	if( elnumof(sockservs) <= sx ){
		return;
	}

	sockservs[sx].s_Host = stralloc(svhost);
	sockservs[sx].s_port = port;
	sockservs[sx].s_ver = ver;
	sockservs[sx].s_svaddr = 0;
	sockservs[sx].s_svlocal = 0;
	sockservs[sx].s_dsts = stralloc(dsts?dsts:"*");

	sprintf(key,"SOCKS-%d",sx);
/*
	sprintf(map,"{%s:%d/-%d}:*:%s:%s",
		svhost,port,ver,dsts?dsts:".socksdst",srcs?srcs:"*");
*/
/*
	sprintf(map,"{%s:%d/-%d}:*:%s,%s:%s,%s",svhost,port,ver,
*/
	sprintf(xopts,"-%d/%s",ver,opts);
	sprintf(map,"{%s:%d/%s}:*:%s,%s:%s,%s",svhost,port,xopts,
			hostmatch_asisaddr,dsts?dsts:".socksdst",
			hostmatch_asisaddr,srcs?srcs:"*");
	scan_CMAP2(_,key,map);
}
static int matchConn(DGC*Conn,int sx,int setCF)
{	CStr(key,32);
	CStr(map,128);
	int found;

	if( Conn->no_dstcheck & 0x8/*NO_SOCKSDST_CHECK*/ ){
		return 1;
	}
	sprintf(key,"SOCKS-%d",sx);
	CTX_pushClientInfo(Conn);
	found = find_CMAP(Conn,key,AVStr(map));
	HL_popClientInfo();
	if( setCF && 0 <= found ){
		ConnectFlags = scanConnectFlags("SOCKS",map,ConnectFlags);
	}
	return 0 <= found;
}
static int matchConnX(DGC*Conn,int sx,PCStr(dstproto),PCStr(dsthost),int dstport)
{	int sav,found;

	sav = 0;
	if( streq(DFLT_PROTO,"socks") && REAL_PROTO[0] == 0 ){
		strcpy(REAL_PROTO,dstproto);
		wordScan(dsthost,REAL_HOST);
		REAL_PORT = dstport;
		sav = 1;
	}
	found = matchConn(Conn,sx,0);
	if( sav ){
		REAL_PROTO[0] = 0;
		REAL_HOST[0] = 0;
		REAL_PORT = 0;
	}
	return found;
}

static int retServ(DGC*Conn,SocksServer *sv,VSAddr *vserv,VSAddr *vlocal){
	if( vserv == 0 && vlocal == 0 ){
		return 0;
	}
	if( vserv && sv->s_svaddr == 0 ){
		const char *addr;
		if( (addr = gethostaddr(sv->s_Host)) == 0 ){
			sv1log("##SOCKS-serv. Unknown %s\n",sv->s_Host);
			bzero(vlocal,sizeof(VSAddr));
			bzero(vserv,sizeof(VSAddr));
			return -1;
		}
		sv->s_svaddr = (VSAddr*)malloc(sizeof(VSAddr));
		VSA_atosa(sv->s_svaddr,sv->s_port,addr);
	}
	if( vlocal ){
		if( sv->s_svlocal )
			*vlocal = *sv->s_svlocal;
		else	bzero(vlocal,sizeof(VSAddr));
	}
	if( vserv ){
		if( sv->s_svaddr )
			*vserv = *sv->s_svaddr;
		else	bzero(vserv,sizeof(VSAddr));
	}
	return 0;
}

/*
static int tobeViaSocks(DGC*Conn)
*/
static SocksServer *tobeViaSocks(DGC*Conn)
{	int sx;

	for( sx = 0; sockservs[sx].s_Host; sx++ ){
		if( matchConn(Conn,sx,0) )
			return &sockservs[sx];
			/*
			return 1;
			*/
	}
	return 0;
}

int VSA_getViaSocks(DGC*Conn,PCStr(host),int port,VSAddr *vlocal);
/*
static int getViaSocks(PCStr(host),int port,VSAddr *vlocal);
*/
static SocksServer *getViaSocks(PCStr(host),int port,VSAddr *vlocal);
int VSA_getViaSocksX(DGC*Conn,PCStr(host),int port,VSAddr *vserv,AuthInfo *au,VSAddr *vlocal);

int GetViaSocks(DGC*Conn,PCStr(host),int port)
{
	return VSA_getViaSocks(Conn,host,port,NULL);
}
int VSA_getViaSocks(DGC*Conn,PCStr(host),int port,VSAddr *vlocal)
{
	return VSA_getViaSocksX(Conn,host,port,NULL,NULL,vlocal);
}
int forwardtoSocks(DGC*Conn,VSAddr *sv);
int VSA_getViaSocksX(DGC*Conn,PCStr(host),int port,VSAddr *vserv,AuthInfo *auth,VSAddr *vlocal)
{	DGC toConn;
	int match,sx;
	SocksServer *sv;

	if( vserv ) bzero(vserv,sizeof(VSAddr));
	if( vlocal) bzero(vlocal,sizeof(VSAddr));
	if( auth  ) bzero(auth,sizeof(AuthInfo));

	/*
	... it should be controlled by tobeViaSocks() ...
	if( hostcmp(host,"localhost") == 0 ){
		Verbose("##NOT ViaSocks-A(localhost)## %s:%d\n",host,port);
		return 0;
	}
	*/
	/*
	if( getViaSocks(host,port,vlocal) ){
	*/
	if( sv = getViaSocks(host,port,vlocal) ){
		retServ(Conn,sv,vserv,vlocal);
		sv1log("##ViaSocks-A(by cache)## %s:%d\n",host,port);
		return 1;
	}
	toConn = *Conn;
	set_realserver(&toConn,DST_PROTO,host,port);
	/*
	if( tobeViaSocks(&toConn) ){
	*/
	if( sv = tobeViaSocks(&toConn) ){
		retServ(Conn,sv,vserv,vlocal);
		sv1log("##ViaSocks-B(by rule)## %s:%d\n",host,port);
		return 1;
	}
	if( forwardtoSocks(&toConn,vserv) ){
		if( auth && toConn.gw.p_auth) *auth = *toConn.gw.p_auth;
		if( vlocal) bzero(vlocal,sizeof(VSAddr));
		sv1log("##ViaSocks-C(by rule)## %s:%d\n",host,port);
		return 1;
	}
	Verbose("##NOT ViaSocks-B## %s:%d\n",host,port);
	return 0;
}
void scan_SOCKS(DGC*_,PCStr(socks))
{	CStr(socksb,1024);
	const char *sv[4]; /**/

	strcpy(socksb,socks);
	sv[0] = sv[1] = sv[2] = sv[3] = 0;
	stoV(socksb,3,sv,':');
	socks_init(_,sv[0],sv[1],sv[2],sv[3]);
}
extern int SOCKS_LOGIN_TIMEOUT;
int socks_addservers(){
	int sx;
	SocksServer *ss;
	const char *host;
	const char *addr;

	/* 9.4.3 this is for UDP but is obsolete
	 * it's halmful for routing from SOCKS to multiple SOCKSes because
	 * it disables selecting an appropriate upstream SOCKS server and
	 * causes forwarding self-generated DNS query to a SOCKS server.
	 */
	Verbose("OBSOLETED socks_addservers() for UDP\n");
	if( streq(iSERVER_PROTO,"socks")
	){
		if( sockservs[0].s_Host )
			return 1;
		else	return 0;
	}

	for( sx = 0; host = sockservs[sx].s_Host; sx++ )
	if( *host )
	{
		ss = &sockservs[sx];
		addr = gethostaddr(host);
		if( addr == NULL )
			addr = host;
		/*
		SOCKS_addserv("*",0,addr,sockservs[sx].s_port);
		*/
		SOCKS_addserv(ss->s_dsts,0,addr,ss->s_port);
	}
	return sx;
}

int WaitCluster(DGC*Conn);
static int socks_startX(DGC*Conn,SocksServer*sv,int command,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport,PVStr(xaddr));
static int socks_start(DGC*Conn,SocksServer*sv,int command,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport,PVStr(xaddr))
{
	int rcode;
	rcode = socks_startX(Conn,sv,command,host,port,user,BVStr(rhost),rport,BVStr(xaddr));
	WaitCluster(Conn);
	return rcode;
}
static int socks_startX(DGC*Conn,SocksServer*sv,int command,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport,PVStr(xaddr))
{	CStr(obuf,128);
	char i;
	int pc,wcc,rep;
	const char *auth;
	CStr(userb,128);
	const char *dp;
	const char *pass;
	CStr(authb,256);
	const char *skhost = sv->s_Host;
	int skport = sv->s_port;
	int ver = sv->s_ver;
	int sock = sv->s_sock;

	if( ver == 5 ){

 if( strchr(host,'%') ){
	CStr(xhost,512);
	const char *addr;
	sv1log("## unescape host-name for SocksV5: %s\n",host);
	if( addr = gethostaddr(host) ){
		strcpy(xhost,addr);
		if( xaddr ) strcpy(xaddr,xhost);
	}else	nonxalpha_unescape(host,AVStr(xhost),0);
	host = xhost;
 }
		/* pass resolved address to SocksV5 client to know which of
		 * multiple IP addresses of the target host is used fot the
		 * connection and to pass it to setViaSocks().
		 */
		/* but this will cause problem when (especially non-FTP) user
		 * expects name resolusions to be done in SocksV5 server ...
		 */
		if( !isinetAddr(host) )
		if( command == SOCKS_CONNECT && xaddr != NULL )
		if( port == 21	/* should be switched using potocol name or
				 * explicit configuration ...
				 */
		 || sv->s_rslv
		 || resolv_bymyself(host) )
		{	const char *addr;
			CStr(addrb,128);
			if( addr = gethostaddr(host) ){
				sv1log("resolved %s[%s]\n",host,addr);
				strcpy(xaddr,addr);
/*
				host = addr;
*/
				/* addr can be overwritten in get_MYAUTH() */
				strcpy(addrb,addr);
				host = addrb;
			}
		}
		pass = NULL;
		if( get_MYAUTH(Conn,AVStr(authb),"socks",skhost,skport) )
			auth = authb;
		else	auth = getenv("SOCKS_AUTH");
		if( auth ){
			dp = wordScanY(auth,userb,"^:");
			user = userb;
			if( *dp == ':' )
				pass = dp + 1;
			else	pass = dp;
		}
		SOCKS_LOGIN_TIMEOUT = LOGIN_TIMEOUT;
		return SOCKS_startV5(sock,command,host,port,user,pass,AVStr(rhost),rport);
	}

	if( resolv_bymyself(host) == 0 && sv->s_rslv == 0 ){
		const char *addr;
		addr = gethostaddr(host);
		if( addr == NULL ){
			sv1log("Don't try Socks for unknown host\n");
			return -1;
		}
		host = addr;
	}
	return
	SocksV4_clientStart(sock,command,host,port,user,AVStr(rhost),rport,AVStr(xaddr));
}

static void setViaSocksX(SocksServer *sv,unsigned int addr,int port,VSAddr *vlocal)
{	ViaSocks *vs;
	int vsx;

	if( addr == -1 )
		return;

	for( vsx = 0; vsx < NVIAS; vsx++ ){
		vs = &viaSocks[vsx];
		if( vs->v_addr == 0 ){
			if( sv->s_istmp ){ /* v9.9.10 fix-140715c */
				SocksServer *nsv;
				nsv = NewStruct(SocksServer);
				*nsv = *sv;
				nsv->s_Host = stralloc(nsv->s_Host);
				nsv->s_istmp = 0;
				sv = nsv;
			}
			vs->v_serv = sv;
			vs->v_addr = addr;
			vs->v_port = port;
			vs->v_local = *vlocal;
			break;
		}
		if( vs->v_addr == addr )
			break;
	}
}
static void setViaSocks(SocksServer *sv,PCStr(host),int port,VSAddr *vlocal)
{
	setViaSocksX(sv,gethostint_nboV4(host),port,vlocal);
	setViaSocksX(sv,gethostintMin(host),port,vlocal);
	setViaSocksX(sv,_inet_addrV4(host),port,vlocal);
}
static SocksServer *getViaSocksX(unsigned int addr,int port,VSAddr *vlocal)
{	ViaSocks *vs;
	int vsx;

	if( addr == -1 )
		return 0;

	for( vsx = 0; vsx < NVIAS; vsx++ ){
		vs = &viaSocks[vsx];
		if( vs->v_addr == 0 )
			break;
		if( vs->v_addr == addr ){
			if( vlocal ) *vlocal = vs->v_local;
			return vs->v_serv;
		}
	}
	return 0;
}
/*
static int getViaSocks(PCStr(host),int port,VSAddr *vlocal)
*/
static SocksServer *getViaSocks(PCStr(host),int port,VSAddr *vlocal)
{
	SocksServer *sv;
	if( sv = getViaSocksX(gethostint_nboV4(host),port,vlocal) ) return sv;
	if( sv = getViaSocksX(gethostintMin(host),port,vlocal) ) return sv;
	if( sv = getViaSocksX(_inet_addrV4(host),port,vlocal) ) return sv;
	/*
	if( getViaSocksX(gethostint_nboV4(host),port,vlocal) ) return 1;
	if( getViaSocksX(gethostintMin(host),port,vlocal) ) return 1;
	if( getViaSocksX(_inet_addrV4(host),port,vlocal) ) return 1;
	*/
	return 0;
}

int newsockBound(int,int,VSAddr*);
int connectVSAddr(int sock,VSAddr *vsa);
int SOCKS_udpassoc0X(DGC*ctx,int ssock,VSAddr *me,VSAddr *rme,AuthInfo *auth);
/*
void setUDPviaSocks(int usock);
*/
int socksudp_start(DGC*Conn,SocksServer *sv){
	const char *aaddr;
	VSAddr me,rme;
	int rcode;
	int usock;

	usock = newsockBound(sv->s_sock,1,&me);
	if( usock < 0 ){
		return -1;
	}
	rcode = SOCKS_udpassoc0X(Conn,sv->s_sock,&me,&rme,GatewayAuth);
	if( rcode == 0 ){
		VSA_satoap(&rme,AVStr(Conn->sv.p_SOCKSADDR));
		connectVSAddr(usock,&rme);
		Conn->sv.p_SOCKSCTL = dup(sv->s_sock);
		dup2(usock,sv->s_sock);
		/*
		setUDPviaSocks(sv->s_sock);
		*/
	}
	close(usock);
	return rcode;
}

static int socks_connect(DGC*Conn,SocksServer *sv,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport)
{	CStr(addr,64);
	VSAddr vlocal;

	if( host == NULL || port == 0 )
		return -1;

	Conn->sv.p_SOCKSCTL = -1;
	if( Conn->sv.p_flags & PF_UDP ){
		Conn->sv.p_flags &= ~PF_UDP;
		return socksudp_start(Conn,sv);
	}

	*addr = 0;
	if( socks_start(Conn,sv,SOCKS_CONNECT,host,port,user,AVStr(rhost),rport,AVStr(addr)))
		return -1;

	if( rhost && rport )
		VSA_atosa(&vlocal,*rport,rhost);
	else	bzero(&vlocal,sizeof(VSAddr));
	setViaSocks(sv,host,port,&vlocal);
	if( *addr != 0 )
		setViaSocks(sv,addr,port,&vlocal);
	return 0;
}

/*
int needSTLS_SVi(Connection *Conn,int server);
int insertTLS_SV(Connection *Conn,int client,int server);
*/
int needSTLS_SVi(Connection *Conn,int server,PCStr(proto));
int insertTLS_SVi(Connection *Conn,int client,int server,PCStr(proto));
int insertCredhy(Connection *Conn,int clsock,int svsock);
int pushFtpServSock(PCStr(wh),Connection *Conn,int svsock);

int SOCKS_STARTTLS_withSV(Connection *Conn,int sock,PCStr(what)){
	int fsv;

	if( 0 <= (fsv = insertCredhy(Conn,ClientSock,sock)) ){
		dup2(fsv,sock);
		close(fsv);
		return 1;
	}
	/*
	if( needSTLS_SV(Conn) ){
	if( needSTLS_SVi(Conn,sock) ){
	 * 9.9.7 needSTLS_SV() and insertTLS_SV() matches with REAL_PROTO which
	 * is not "socks", thus STLS=fsv:REAL_PROTO (not for SOCKS) is inserted
	 * here before the SOCKS negotiation (which is not to be with STLS).
	 */
	if( needSTLS_SVi(Conn,sock,"socks") ){
		if( ServerFlags & PF_STLS_OPT ){
			/* appliy TLS to the payload */
		}else{
			/*
			fsv = insertTLS_SV(Conn,ClientSock,sock);
			*/
			fsv = insertTLS_SVi(Conn,ClientSock,sock,"socks");
			if( 0 <= fsv ){
				pushFtpServSock("SOCKS",Conn,sock);
				sv1log("[%d] SOCKS STLS=fsv (%s)\n",sock,what);
				dup2(fsv,sock);
				close(fsv);
				pushSTLS_FSV(Conn,"socks");
				return 1;
			}
		}
	}
	uncheckSTLS_SV(Conn);
	return 0;
}

static int socks_bind(DGC*Conn,SocksServer *sv,PCStr(host),int port,PCStr(user),PVStr(rhost),int *rport)
{
	bind_ver = sv->s_ver;
	return socks_start(Conn,sv,SOCKS_BIND,host,port,user,AVStr(rhost),rport,VStrNULL);
}
static int bindsocks(DGC*Conn,SocksServer *sv,PCStr(dsthost),int dstport,PCStr(uname),PVStr(rhost),int *rport)
{	int sock;

	sock = OpenServer("BindViaSocks","socks",sv->s_Host,sv->s_port);
	if( sock < 0 )
		return -1;

	SOCKS_STARTTLS_withSV(Conn,sock,"bind");

	sv->s_sock = sock;
	if( socks_bind(Conn,sv,dsthost,dstport,uname,AVStr(rhost),rport) == 0 )
		return sock;
	close(sock);
	return -1;
}
int bindViaSocks(DGC*Conn,PCStr(dsthost),int dstport,PVStr(rhost),int *rport)
{	int sx,sock;
	SocksServer *sv;

	/*
	if( streq(DST_PROTO,"ftp")
	 || strcaseeq(DST_PROTO,"ftps")
	 || strcaseeq(DST_PROTO,"ftp-data")
	)
	if( IsMyself(dsthost) ){
		sv1log("##NOT ViaSocks-F(self)## [%s]%s:%d\n",
			DST_PROTO,dsthost,dstport);
		return -1;
	}
	*/

	getUsernameCached(getuid(),AVStr(Username));
	sv1log("bindViaSocks(%s:%d)[%s]\n",dsthost,dstport,Username);

	if( sv = getViaSocksX(gethostint_nboV4(dsthost),dstport,NULL) ){
		sock = bindsocks(Conn,sv,dsthost,dstport,Username,AVStr(rhost),rport);
		if( 0 <= sock )
			return sock;
	}

	for( sx = 0; sockservs[sx].s_Host; sx++ ){
		/*
		if( !matchConn(Conn,sx) )
		*/
		if( !matchConnX(Conn,sx,"tcprelay",dsthost,dstport) )
			continue;

		sv = &sockservs[sx];
		if( sv->s_Host[0] == 0 || sv->s_port == 0 )
			break;
		sock = bindsocks(Conn,sv,dsthost,dstport,Username,AVStr(rhost),rport);
		if( 0 < sock )
			return sock;
	}
	return -1;
}
int acceptViaSocks(int sock,PVStr(rhost),int *rport)
{	int rep;

	if( bind_ver == 5 )
		return SOCKS_recvResponseV5(sock,SOCKS_ACCEPT,AVStr(rhost),rport);
	else	return SocksV4_acceptViaSocks(sock,AVStr(rhost),rport);
}
/* this function is called when FORWARD=socks://H:P without CONNECT=s */
int connectViaSocksX(DGC*Conn,PCStr(skhost),int skport,PCStr(opts),PCStr(dsthost),int dstport)
{	static SocksServer svb;
	SocksServer *sv = &svb;
	CStr(rhost,128);
	int rport;

	sv->s_sock = OpenServer("ConnectViaSocks","socks",skhost,skport);
	sv->s_Host = stralloc(skhost);
	sv->s_istmp = 0; /* seems must be 1 to make multiple SOCKS work ? */
	sv->s_port = skport;
	sv->s_svaddr = 0;
	sv->s_svlocal = 0;
	sv->s_dsts = stralloc(dsthost);
	sv->s_rslv = 0;
	if( strstr(opts,"-4") )
		sv->s_ver = 4;
	else	sv->s_ver = 5;
	if( strstr(opts,"-r") )
		sv->s_rslv = 1;

	if( 0 <= sv->s_sock ){
		getUsernameCached(getuid(),AVStr(Username));

	/* FORWARD=socks://host:port/ssl or with STLS=fsv:socks */
	SOCKS_STARTTLS_withSV(Conn,sv->s_sock,"connViaSocks");

	if( socks_connect(Conn,sv,dsthost,dstport,Username,AVStr(rhost),&rport)==0 )
			return sv->s_sock;
		close(sv->s_sock);
	}
	return -1;
}
static int connsocks(DGC*Conn,SocksServer *sv,PCStr(dsthost),int dstport,PCStr(uname),PVStr(rhost),int *rport)
{	int sock;

	sock = OpenServer("ConnectViaSocks","socks",sv->s_Host,sv->s_port);
	if( sock < 0 )
		return -1;
	if( CCSV_reusing(Conn,"SOCKS",sock) ){
		return sock;
	}

	SOCKS_STARTTLS_withSV(Conn,sock,"conn");

	sv->s_sock = sock;
	if( socks_connect(Conn,sv,dsthost,dstport,uname,AVStr(rhost),rport) == 0 )
		return sock;
	close(sock);
	return -1;
}
int connectViaSocks(DGC*Conn,PCStr(dsthost),int dstport,PVStr(rhost),int *rport)
{	int sx,sock;
	SocksServer *sv;
	DGC toConn;
	VSAddr sva;
	SocksServer svb;
	int connF;

	getUsernameCached(getuid(),AVStr(Username));
	if( sv = getViaSocksX(gethostint_nboV4(dsthost),dstport,NULL) ){
		sock = connsocks(Conn,sv,dsthost,dstport,Username,AVStr(rhost),rport);
		if( 0 <= sock )
			return sock;
	}

	connF = ConnectFlags;
	for( sx = 0; sockservs[sx].s_Host; sx++ ){
		ConnectFlags = connF;
		if( !matchConn(Conn,sx,1) )
			continue;

		sv = &sockservs[sx];
		if( sv->s_Host[0] == 0 || sv->s_port == 0 )
			break;

		sock = connsocks(Conn,sv,dsthost,dstport,Username,AVStr(rhost),rport);
		if( 0 <= sock )
			return sock;
	}

	toConn = *Conn;
	if( forwardtoSocks(&toConn,&sva) ){
		IStr(Host,MaxHostNameLen);
		bzero(&svb,sizeof(SocksServer));
		sv = &svb;
		sv->s_Host = VSA_ntoa(&sva);
		sv->s_Host = strcpy(Host,sv->s_Host);
		sv->s_istmp = 1; /* v9.9.10 fix-140715c */
		sv->s_port = VSA_port(&sva);
		sock = connsocks(&toConn,sv,dsthost,dstport,Username,
			AVStr(rhost),rport);
		if( 0 <= sock ){
			SOCKS_addserv(dsthost,dstport,sv->s_Host,sv->s_port);
			Conn->sv.p_SOCKSCTL = toConn.sv.p_SOCKSCTL;
			return sock;
		}
	}
	return -1;
}
int ConnectViaSocks(DGC*Conn,int relay_input)
{	int sock;
	CStr(rhost,128);
	int rport;

	if( Conn->co_mask & CONN_NOSOCKS )
		return -1;
	if( 0 <= (sock = connectViaSocks(Conn,DST_HOST,DST_PORT,AVStr(rhost),&rport)) )
		initConnected(Conn,sock,relay_input);
	return sock;
}


static int peekVer(DGC*Conn,PVStr(ibuf),int timeout){
	int rcc;
	setVStrEnd(ibuf,0);
	if( PollIn(FromC,timeout*1000) <= 0 ){
		daemonlog("E","Socks peek timeout (%ds)\n",timeout);
		return -1;
	}
	rcc = recvPeekTIMEOUT(FromC,AVStr(ibuf),1);
	if( rcc != 1 ){
		daemonlog("F","Socks can't peek packet %d %d\n",rcc,errno);
	}
	return rcc;
}
void logReject(Connection *Conn,int self,PCStr(shost),int sport);
static int permitted_socksVX(Connection *Conn,int ver){
	if( strcaseeq(iSERVER_PROTO,"socks4") && ver != 4
	 || strcaseeq(iSERVER_PROTO,"socks5") && ver != 5 ){
		sprintf(Conn->reject_reason,"SocksV%d is not acceptable",ver);
		logReject(Conn,1,Client_Host,Client_Port);
		return 0;
	}
	return 1;
}

/*
 *	SOCKS SERVER
 */
int service_socksA(DGC*Conn);
int service_socks(DGC*Conn)
{
	int rcode;
	rcode = service_socksA(Conn);
	return rcode;
}
int service_socksA(DGC*Conn)
{	CStr(ibuf,16);

	LOGX_appReq++;
	if( !source_permittedX(Conn) ){
		CStr(shost,MaxHostNameLen);
		getClientHostPort(Conn,AVStr(shost));
		daemonlog("F","E-P: No permission: \"%s\" is not allowed (%s)\n",
			shost,Conn->reject_reason);
		if( peekVer(Conn,AVStr(ibuf),2) <= 0 )
			return -1;
		/* send appropriate error message depending on client ver. */
		return -1;
	}
	if( peekVer(Conn,AVStr(ibuf),LOGIN_TIMEOUT) <= 0 )
		return -1;
	if( permitted_socksVX(Conn,ibuf[0]) == 0 ){
		return -1;
	}

	if( ibuf[0] == 5 ){
		extern int IO_TIMEOUT;
		socks_addservers();
		SOCKS_serverV5(Conn,FromC,ToC,IO_TIMEOUT*1000);
		return 0;
	}
	SocksV4_server(Conn,ToS,FromS,FromC,ToC);
	return 0;
}
int isSocksConnect(PCStr(pack),int leng,int *ver,PVStr(addr),int *port,const char **user)
{
	return SocksV4_isConnectReuqest(pack,leng,ver,AVStr(addr),port,user);
}
