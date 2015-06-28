const char *SIGN_vsap_c="{FILESIGN=vsap.c:20141031194212+0900:4c7e06c48ecf966b:Author@DeleGate.ORG:GOpID8DfhbiIeIanckLKa1cursJF9sTBVXkf7jSm/d8UFeSoALejPvwcVPDgK/Axsoptc1FngFeJhIQllxzD2a+nq09TiS1T4yxG4WDhvy+Fa7rRHnwAx11lH3BlDFe+3StRI1FeSlqc8Xf+sl7f17U8izoVQyRyiLKjTqVtXkk=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	vsap.c (virtual socket association protocol)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

    VIRTURAL SOCKET
	+ the address space for association among party is virtural
	+ it seems a normal socket after once connected or associated

	+ communication interface privimitives are compatible with SOCKET
	+ naming is extende to virtual address space AF_URN, AF_ASSOC, ...
	+ accepting at remote host
	+ accepting from multiple ports simultaneously
	+ accepting with priority
	+ multiplexing multiple sessions on a single connection
	+ associate among sockets by the first line from their stream (VIABUS)
	+ URL as a port
	+ TCP / UDP conversion

	- real socket information (Proto,Lhost:Lport,Rhost:Rport) is sent to
	  the OOB channel after a tcp connection is established (NO!)

    REQUEST MESSAGE to the VSAP server
	["VSAP/"version] request-message

    RESPONSE MESSAGE from the VSAP server
	"VSAP/"version code response-message

    CALL BACK MESSAGE from the VSAP server
	"VSAP/"version 100 message
	-- not the response to the request

    REAL SOCKET MANIPULATION
    REQUEST / RESPONSE
	ECHO msg
	   200 [time] msg

	SOCKET domain type proto [options] -- create a new socket with options
	   200 SID created
	   500 error

	SOCKOPT [#SID] options

	BIND [#SID] [HL][:PL][/udp] (default: *:* /tcp)
	   210 SID HL:PL -- bound to the local port HL:PL and assigned SID
	   510 error     -- could not bind.
	BIND /path       -- of AF_UNIX socket
	   210 SID /path -- bound
	   510 error     -- could not bind.

	LISTEN [#SID] Qsize
	   220 listen ok.
	   520 listen failed.

	ACCEPT [#SID]* [-p=N] [-t=N]
	   230 SID HL:PL HR:PR -- accepted from HR:PR to HL:PL
	   530 error
	   - priority -- accept priority at the VSAP server

	CONNECT [#SID] H:P[/udp]
	   240 SID HL:PL HR:PR -- connected from HL:PR to HR:PR
	   540 error
	CONNECT /path
	   240 SID /path
	   540 error
	   - multiple IP address of a host is tried till succeed

	RELAY [#SID]*
	   250 relayed (N bytes)
	   - relay among a connected party
	   - (possiblly with some data conversion)

	PROXY protocol
	   150 start relaying
	   - relay in specified protocol (not as circuit level proxy)

	FORWARD [#SID] HR:PR [TRACE[/app-proto]]
	   260 start forwarding
	   261 done forwarding
	   - accept at HL:PL specified by SID, connect to HR:PR,
	   - then relay between them.

	QUIT

	PERMIT Hs:Ps to Hd:Pd -- access control

    REFLECTOR -- VIABUS like interface
	  RECV virtual-port*
	  SEND virtual-port*
	  RELAY
	     repetivie accepts at any time
	     multi-unicast

    ABSTRACT ASSOCIATION

	BIND service
	  BIND http://server/path/
		   ... MOUNT="/path/* http://realserver/"
	  BIND URN
	  BIND URL ... proxy for the URL
	  BIND news:newsgroups
	  BIND selector (VIABUS/Teleport)
	  BIND tty

	CONNECT service
	  CONNECT http://server/path/
		   ... ?
	  CONNECT /path/of/regula-file ?
	  CONNECT /path/of/command arg-list ?
	  CONNECT URN
	  CONNECT URL
	  CONNECT selector
	  CONNECT news:news-group -- connect to a newsserver with news-group

    MULTIPLEXING
	EOS end-of-streadm notification method

    Naming history ....
	Receptor
	Socker
	VSOCK: Virtual Socket
	CAGP: Circuit-level Application Gateway Protocol
	Associator
	Sucks
	AltSocks
	TelePort2
	VSOP: Virtual Socket Operation Protocol
	RSMAP: Remote Socket MAPper | Sokcet Mediation & Assocation Protocol
	VSMAP
	VSAP: Virtual Socket Association Protocol

History:
	970806	created
TODO:
	- compatible functions with socket() should be provided
	- should be independent of DeleGate
	- compatible binary represented pacekt protocol should be provided
	  which should be upper compatible with Socks
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "delegate.h"
#include "fpoll.h"
#include "file.h"
#include "auth.h"

int service_http(Connection *Conn);
int service_ftp(Connection *Conn);

#define NEWSOCK		-1,NULL,NULL,NULL
#define ANYPORT		NULL,0
#define VStrANYPORT	VStrNULL,0

int acceptedViaVSAP;

#define OK_GENERIC	200
#define OK_BIND		210
#define OK_LISTEN	220
#define OK_ACCEPT	230
#define OK_CONNECT	240
#define OK_RELAYED	250
#define OK_FORWARD1	260
#define OK_FORWARD2	261
#define OK_SET		270
#define OK_BYE		280

#define NO_PERMISSION	410

#define NO_GENERIC	500
#define NO_GENERIC_BYE	501
#define NO_BIND		510
#define NO_LISTEN	520
#define NO_ACCEPT	530
#define NO_CONNECT	540

#define VER	"VSAP/0.1"
const char *VSAP_VER(){ return VER; }

static int SockPrintf(int sock,PCStr(fmt),...)
{	CStr(msg,1024);
	int wcc;
	VARGS(8,fmt);

	sprintf(msg,fmt,VA8);
	wcc = write(sock,msg,strlen(msg));
	daemonlog("D","I-SAY: %s",msg);
	return wcc;
}

/*
 *	SERVER
 */
typedef struct {
	int	a_sock;
	int	a_id;
} ASSOCK;
typedef struct {
	ASSOCK	ve_SvSocks[32]; /**/
	int	ve_SvSockN;
	ASSOCK	ve_ClSocks[32]; /**/
	int	ve_ClSockN;
	int	ve_SockID;
	int	ve_bind_exlock;
	int	ve_bind_nlisten;
} VsapServEnv;
static VsapServEnv *vsapServEnv;
#define SvSocks		vsapServEnv->ve_SvSocks
#define SvSockN		vsapServEnv->ve_SvSockN
#define ClSocks		vsapServEnv->ve_ClSocks
#define ClSockN		vsapServEnv->ve_ClSockN
#define SockID		vsapServEnv->ve_SockID
#define bind_exlock	vsapServEnv->ve_bind_exlock
#define bind_nlisten	vsapServEnv->ve_bind_nlisten


int AcceptViaHTTP(Connection *Conn,int ba,int sock,int timeout,int priority,PCStr(rport),PVStr(sockname),PVStr(peername));
int open_vsap(Connection *Conn,int method);
#define resp_OK VSAP_respOK
int resp_OK(PCStr(resp));
#ifndef OPT_S /*{*/

void minit_vsapsv()
{
	if( vsapServEnv == 0 ){
		vsapServEnv = NewStruct(VsapServEnv);
		bind_exlock = -1;
		bind_nlisten = -1;
	}
}

static int add_clsock(int sock)
{
	if( elnumof(ClSocks) <= ClSockN+1 ){
		return -1;
	}
	ClSockN++;
	ClSocks[ClSockN].a_id = ++SockID;
	ClSocks[ClSockN].a_sock = sock;
	return SockID;
}
static void del_clsock(int sock){
}
static int add_svsock(int sock)
{
	if( elnumof(SvSocks) <= SvSockN+1 ){
		return -1;
	}
	SvSockN++;
	SvSocks[SvSockN].a_id = ++SockID;
	SvSocks[SvSockN].a_sock = sock;
	return SvSockN;
}
static void del_svsock(int sock){
}
static void closeSvSocks()
{	int fi,svsock;

	for( fi = 1; fi <= SvSockN; fi++ ){
		svsock = SvSocks[fi].a_sock;
		close(svsock);
		del_svsock(svsock);
		daemonlog("D","## close SVSOCK %d\n",svsock);
	}
	SvSockN = 0;
}

static int do_connect(int lsock,PCStr(rport),int toC)
{	CStr(host,MaxHostNameLen);
	int port;
	int clsock;
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen);
	int wcc;
	int sockid;

	if( rport[0] == '/' ){
		clsock = client_open_un("vsap",rport,60);
		daemonlog("E","## CLPORT %s [%d]\n",rport,clsock);
		if( clsock < 0 ){
		wcc = SockPrintf(toC,"%s %d not connected\r\n",VER,NO_BIND);
		return -1;
		}
		strcpy(sockname,rport);
		strcpy(peername,rport);
		goto CONNECTED;
	}

	strcpy(host,"127.0.0.1");
	port = 0;
	if( strchr(rport,':') )
		Xsscanf(rport,"%[^:]:%d",AVStr(host),&port);
	else	sscanf(rport,"%d",&port);

	clsock = Socket1("VSAP",lsock,NULL,NULL,NULL,VStrANYPORT,host,port,0,NULL,0);
	if( clsock < 0 ){
		wcc = SockPrintf(toC,"%s %d cannot connect %s\r\n",
			VER,NO_CONNECT,rport);
		return -1;
	}
	getpairName(clsock,AVStr(sockname),AVStr(peername));

CONNECTED:
	sockid = add_clsock(clsock);
	wcc = SockPrintf(toC,"%s %d %d %s %s connected.\r\n",
		VER,OK_CONNECT,sockid,sockname,rport);

	return clsock;
}

static int NewPort(PCStr(lport),PVStr(host),int port,int toC,int nlisten)
{	int timeout1;
	int elapsed;
	int sock;
	int rcode;
	CStr(exlockpath,1024);

	bind_exlock = -1;
	bind_nlisten = -1;

	if( port == 0 ){
		sock = Socket1("VSAP",NEWSOCK,AVStr(host),port,ANYPORT,nlisten,NULL,0);
		return sock;
	}

	bind_exlock = PortLocks(lport,1,AVStr(exlockpath));
	if( bind_exlock < 0 )
		return -1;

	/* don't listen just before accept() not to accept more than
	 * a single connection...
	 */
	bind_nlisten = nlisten;
	nlisten = 0;

	sock = -1;
	timeout1 = 1000;
	for(;;){
		rcode = lock_exclusiveTO(bind_exlock,timeout1,&elapsed);
		if( rcode == 0 ){
			sock = Socket1("VSAP",NEWSOCK,AVStr(host),port,ANYPORT,nlisten,NULL,0);
			break;
		}
		if( elapsed < timeout1 )
			break;
		if( PollIn(toC,1) != 0 )
			break;
	}
	return sock;
}
static int do_bind(int sock,PVStr(lport),PCStr(opts),int *sharedp,PVStr(sockname),int toC)
{	int svsock;
	CStr(host,MaxHostNameLen);
	CStr(ports,256);
	int port;
	int nlisten;
	int wcc;
	int sockid;

	*sharedp = 0;
	host[0] = 0;
	ports[0] = 0;
	port = 0;
	nlisten = 0;

	if( lport[0] == '/' ){
		svsock = server_open_un("vsap",AVStr(lport),1);
		daemonlog("E","## SVPORT %s [%d]\n",lport,svsock);
		if( svsock < 0 ){
		wcc = SockPrintf(toC,"%s %d not bound-1\r\n",VER,NO_BIND);
		return -1;
		}
		strcpy(sockname,lport);
		*sharedp = 1;
		goto BOUND;
	}

	if( strchr(lport,':') )
		Xsscanf(lport,"%[^:]:%s",AVStr(host),AVStr(ports));
	else	Xsscanf(lport,"%s",AVStr(ports));
	port = atoi(ports);

	if( strncmp(opts,"-l=",3) == 0 )
		nlisten = atoi(opts+3);

	daemonlog("D","bind: %s:%d nlisten=%d\n",host,port,nlisten);

	if( 0 <= (svsock = ServSockOf(host,port)) ){
		daemonlog("D","## SVPORT %d\n",svsock);
		*sharedp = 1;
	}else
	if( 0 <= (svsock = ReservedPortSock(host,port)) ){
		daemonlog("D","## RESV_PORT %d\n",svsock);
		*sharedp = 1;
	}else
	if( lSINGLEP()
	 && 0 <= (svsock = findopen_port("VSAP",AVStr(host),port,nlisten)) ){
		daemonlog("D","## SHARED_PORT %d\n",svsock);
		*sharedp = 1;
	}else
	if( 0 <= (svsock = NewPort(lport,AVStr(host),port,toC,nlisten)) ){
		daemonlog("D","## NEW_PORT %d\n",svsock);
		*sharedp = 0;
	}else{
		wcc = SockPrintf(toC,"%s %d not bound-2 %s\r\n",VER,NO_BIND,
			lport);
		return -1;
	}
	gethostName(svsock,AVStr(sockname),"%A:%P");

BOUND:
	sockid = add_svsock(svsock);
	wcc = SockPrintf(toC,"%s %d %d %s bound.\r\n",VER,OK_BIND,
		sockid,sockname);
	return svsock;
}

static int do_accept(PCStr(lport),PCStr(opts),int shared,int priobase,int fromC,int toC)
{	int shlock,exlock;
	CStr(shlockpath,1024);
	CStr(exlockpath,1024);
	CStr(host,1024);
	int port;
	const char *op;
	CStr(opt1,128);
	int rcode;
	int clsock;
	int wcc;
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen);
	int fi,fdv[32],rfv[32],nready;
	int svsock;
	int priority,timeout;
	int start;

	clsock = -1;
	if( SvSockN < 1 ){
		SockPrintf(toC,"%s %d no socket to accept\r\n",VER,NO_ACCEPT);
		return -1;
	}

	/* repeat until accept succeed and authorization OK,
	 * while the client's connection is alive ...
	 */
	shlock = -1;
	host[0] = 0;
	port = 0;
	if( strchr(host,':') )
		Xsscanf(lport,"%[^:]:%d",AVStr(host),&port);
	else	sscanf(lport,"%d",&port);

	priority = 0;
	timeout = 0;
	for( op = wordScan(opts,opt1); *opt1; op = wordScan(op,opt1) ){
		if( strncmp(opt1,"-p=",3) == 0 ){
			priority = atoi(opt1+3);
		}else
		if( strncmp(opt1,"-t=",3) == 0 ){
			timeout = atoi(opt1+3);
		}else	break;
	}
	if( priobase == 0 )
		priority = 0;
	daemonlog("D","accept: priority=%d timeout=%d\n",priority,timeout);

	if( shared ){
		const char *ltype;
		int rem;
		start = time(0L);
		shlock = PortLocks(lport,2,AVStr(shlockpath));
		rcode = -1;
		for(;;){
			if( priority ){
				rcode = lock_exclusiveTO(shlock,1000,NULL);
				ltype = "exclusive";
			}else{	rcode = lock_sharedTO(shlock,1000,NULL);
				ltype = "shared";
			}
			if( !IsAlive(toC) ){
			daemonlog("E","## disconnected during LOCKing\n");
				goto EXIT;
			}
			if( rcode == 0 )
				break;
			if( timeout <= time(0L) - start )
				break;
		}
		rem = timeout - (time(0L) - start);
		if( rcode != 0 && rem <= 0 ){
		daemonlog("E","## accept: timedout during %s LOCKing (%d)\n",
				ltype,timeout);
			goto EXIT;
		}
		daemonlog("D","## accept: %s LOCKed (%d)\n",ltype,timeout-rem);
	}

	daemonlog("D","## START accept at %d (%d ports)\n",port,SvSockN);
	for(;;){
	RETRY:
		fdv[0] = fromC;
		for( fi = 1; fi <= SvSockN; fi++ ){
			fdv[fi] = SvSocks[fi].a_sock;
			if( !shared && 0 < bind_nlisten )
				Listen(fdv[fi],bind_nlisten);
		}

		nready = PollIns(timeout*1000,1+SvSockN,fdv,rfv);
		if( nready <= 0 )
			break;
		if( rfv[0] != 0 && !IsAlive(fromC) )
		{
			daemonlog("E","## disconnected during POLLing\n");
			break;
		}

		svsock = -1;
		for( fi = 1; fi <= SvSockN; fi++ ){
			if( rfv[fi] < 0 )
				goto EXIT;
			if( 0 < rfv[fi] ){
				svsock = fdv[fi];
				break;
			}
		}
		if( svsock < 0 )
			break;

/* not lport but the real port-number of svsock ? */
		exlock = PortLocks(lport,3,AVStr(exlockpath));
		start = time(0L);
		rcode = -1;
		for(;;){
			rcode = lock_exclusiveTO(exlock,1000,NULL);
			if( !IsAlive(toC) ){
			daemonlog("E","## disconnected during ACCEPT LOCKing\n");
				rcode = -1;
				break;
			}
			if( rcode == 0 )
				break;
			if( timeout <= time(0L) - start ){
			daemonlog("E","## timedout during ACCEPT LOCKing\n");
				lock_unlock(exlock);
				goto RETRY;
			}
		}
		if( rcode == 0 ){
			if( PollIn(svsock,1) <= 0 ){
			daemonlog("E","## be snatched during ACCEPT LOCKing\n");
				lock_unlock(exlock);
				goto RETRY;
			}else{
				clsock = ACCEPT(svsock,1,-1,timeout);
			}
		}

		if( !shared )
			closeSvSocks();

		if( 0 <= exlock )
			lock_unlock(exlock);

		if( 0 <= shlock ){
			lock_unlock(shlock);
			shlock = -1;
		}
		break;
	}

EXIT:
	if( !shared )
		closeSvSocks();

	if( 0 <= bind_exlock ){
		lock_unlock(bind_exlock);
		bind_exlock = -1;
	}

	if( clsock < 0 )
		daemonlog("D","## FAILED accept at %d\n",port);

	if( 0 <= shlock )
		lock_unlock(shlock);
	return clsock;
}

static int intcom(PCStr(arg),int src,int dst,int *rccp,int *wccp)
{	int rcc,wcc,rcode;
	CStr(req,1024);

	daemonlog("E","## intcom: %d->d\n",src,dst);
	rcc = RecvLine(src,req,sizeof(req));
	if( rcc <= 0 )
		return -1;
	if( rccp ) *rccp = rcc;
	rcode = 0;
	wcc = SockPrintf(dst,"%s %d interrupted by \"%s\"",VER,OK_ACCEPT,req);
	if( strncasecmp(req,"BREAK",5) == 0 )
		rcode = -1;
	return rcode;
}
static void do_forward(Connection *Conn,PCStr(lport),PCStr(peername),int shared,int svsock,int priority,int fromC,int toC)
{	int cls,svs;
	CStr(host,MaxHostNameLen);
	int port;
	CStr(opt,256);
	CStr(clntname,1024);
	CStr(servname,1024);
	CStr(sockname,1024);

	if( svsock < 0 ){
		SockPrintf(toC,"%s %d no socket to accept\r\n",VER,NO_ACCEPT);
		return;
	}
	SockPrintf(toC,"%s %d forwarding start.\r\n",VER,OK_FORWARD1);

	opt[0] = 0;
	Xsscanf(peername,"%[^:]:%d %s",AVStr(host),&port,AVStr(opt));

	for(;;){
		cls = do_accept(lport,"",shared,priority,fromC,toC);
		if( cls < 0 ){
			if( 0 < PollIn(fromC,1) ){
				if( intcom("",fromC,toC,NULL,NULL) == 0 )
					continue;
				else	break;
			}
			SockPrintf(toC,"%s %d could not accept at %s\r\n",
				VER,NO_ACCEPT,lport);
			break;
		}
		getpairName(cls,AVStr(sockname),AVStr(clntname));
		SockPrintf(toC,"%s %d accepted %s %s\r\n",VER,OK_ACCEPT,
			sockname,clntname);

		svs = Socket1("VSAPdata",NEWSOCK,VStrANYPORT,host,port, 0,NULL,0);
		if( svs < 0 ){
			SockPrintf(toC,"%s %d could not connect to %s\r\n",
				VER,NO_CONNECT,peername);
			break;
		}else{
			if( strstr(opt,"TRACE") ){
				getpairName(svs,AVStr(sockname),AVStr(servname));
				SockPrintf(cls,"%s %d %s %s connected.\r\n",
					VER,OK_CONNECT,sockname,servname);
				SockPrintf(svs,"%s %d %s %s accepted.\r\n",
					VER,OK_ACCEPT,sockname,clntname);
			}
			relay2_cntl(60*1000,cls,svs,svs,cls,fromC,toC,(IFUNCP)intcom,0);
			close(svs);
			SockPrintf(toC,"%s %d relay done.\r\n",VER,OK_RELAYED);
		}
		close(cls);
	}
	SockPrintf(toC,"%s %d forwarding done.\r\n",VER,OK_FORWARD2);
}

static int vsap_permit(Connection *Conn,PCStr(portname))
{	CStr(host,512);
	int port;

	host[0] = 0;
	port = 0;
	if( strchr(portname,':') )
		Xsscanf(portname,"%[^:]:%d",AVStr(host),&port);
	else{
		sscanf(portname,"%d",&port);
	}
	set_realserver(Conn,"vsap",host,port);
	if( service_permitted(Conn,"vsap") )
		return 1;

	SockPrintf(ToC,"%s %d forbidden.\r\n",VER,NO_PERMISSION);
	return 0;
}


int VSAP_isMethod(PCStr(request))
{
	if( strncmp(request,"VSAP/",5) == 0 )
		return 1;
	return 0;
}

extern int IO_TIMEOUT;

int service_vsap(Connection *Conn)
{	CStr(request,1024);
	CStr(reqver,128);
	const char *req;
	int svsock,shared,clsock,rcode;
	CStr(myport,256);
	CStr(sockname,MaxHostNameLen);
	CStr(peername,MaxHostNameLen);
	int wcc,rcc;
	CStr(com,1024);
	CStr(arg,1024);
	const char *argp;
	CStr(opt,32);
	const char *op;
	int timeout;
	int AuthOk;
	FILE *authout;

	minit_vsapsv();
	if( ToS <= 0 || FromS <= 0 ){
		/*
		If the DST_HOST is not local
		connect to the master and simple_relay...
		 */
	}
	if( !isMYSELF(DFLT_HOST) ){
		daemonlog("E","VSAP relaying to %s:%d\n",DFLT_HOST,DFLT_PORT);
		if( ToS < 0 )
			connect_to_serv(Conn,FromC,ToC,0);
		relay_svcl(Conn,FromC,ToC,FromS,ToS);
		close(ToS);
		return 0;
	}

	/*
	timeout = 300;
	*/
	timeout = IO_TIMEOUT;

	shared = 0;
	myport[0] = 0;
	SvSockN = 0;
	ClSockN = 0;
	clsock = -1;
	svsock = -1;
	reqver[0] = 0;

	authout = TMPFILE("VSAP-AUTH");
	if( doAUTH(Conn,NULL,authout,"vsap","-",0,CVStr("user-xxxx:pass-xxxx"),CVStr("host-xxxx"),NULL,NULL) == EOF ){
		AuthOk = 0;
	}else	AuthOk = -1;

	if( ImMaster ){
		sprintf(myport,"%s:%d",DST_HOST,DST_PORT);
	}else
	for(;;){
		if( DDI_fgetsFromCbuf(Conn,AVStr(request),sizeof(request),NULL) == 0 )
		{	int closed = 0;
			for(;;){
				if( PollIn(FromC,1*1000) != 0 )
					break;
				closed |= checkCloseOnTimeout(1);
				if( 0 <= clsock && !IsAlive(clsock) ){
daemonlog("E","## disconnected by peer\n");
SockPrintf(ToC,"%s %d %s.\r\n",VER,NO_GENERIC_BYE,"disconnected by peer");
					close(clsock);del_clsock(clsock);
					goto EXIT;
				}
			}
		if( (rcc = RecvLine(FromC,request,sizeof(request))) <= 0 )
			break;
		}

		daemonlog("D","CLIENT-SAYS: %s",request);
daemonlog("E","CLIENT-SAYS: %s",request);
		req = request;
		if( strncmp(req,"VSAP/",5) == 0 )
			req = wordScan(req,reqver);

		argp = wordScan(req,com);
		arg[0] = 0;
		lineScan(argp,arg);

		if( strcasecmp(com,"AUTH") == 0 ){
			CStr(ahost,MaxHostNameLen);
			ahost[0] = 0;
			if( doAUTH(Conn,NULL,authout,"vsap","-",0,AVStr(arg),AVStr(ahost),NULL,NULL) == EOF ){
			}else{
				AuthOk = 1;
				SockPrintf(ToC,"%s %d OK\r\n",VER,OK_GENERIC);
				continue;
			}
		}
		if( AuthOk == 0 ){
			SockPrintf(ToC,"%s %d forbidden\r\n",VER,NO_PERMISSION);
			sv1log("WITH AUTHORIZER, but NO AUTH from client\n");
			break;
		}

		if( strcasecmp(com,"ECHO") == 0 ){
			CStr(stime,64);
			StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,time(0),0);
			SockPrintf(ToC,"%s %d [%s] %s\r\n",VER,OK_GENERIC,
				stime,arg);
		}else
		if( strcasecmp(com,"CONNECT") == 0 ){
			strcpy(myport,arg);
			if( !vsap_permit(Conn,myport) )
				break;
			clsock = do_connect(svsock,myport,ToC);
			if( clsock < 0 )
				break;
		}else
		if( strcasecmp(com,"BIND") == 0 ){
			CStr(opts,1024);
			opts[0] = 0;
			Xsscanf(arg,"%s %[^\r\n]",AVStr(myport),AVStr(opts));
			if( !vsap_permit(Conn,myport) )
				break;
			svsock = do_bind(-1,AVStr(myport),opts,&shared,AVStr(sockname),ToC);
			if( svsock < 0 )
				break;
		}else
		if( strcasecmp(com,"LISTEN") == 0 ){
			int nlisten = atoi(arg);
			Socket1("VSAP",svsock,NULL,NULL,NULL,VStrANYPORT,ANYPORT,nlisten,NULL,0);
			SockPrintf(ToC,"%s %d listen ok.\r\n",VER,OK_LISTEN);
		}else
		if( strcasecmp(com,"ACCEPT") == 0 ){
			int priority;
			if( Conn->cl_count <= 1 )
				priority = 0;
			else	priority = 1;

			clsock = do_accept(myport,arg,shared,priority,FromC,ToC);
			if( !shared )
				svsock = -1;

			if( clsock < 0 ){
				wcc = SockPrintf(ToC,"%s %d accept fail\r\n",
					VER,NO_ACCEPT);
				break;
			}
			add_clsock(clsock);
			if( myport[0] == '/' ){
				strcpy(sockname,myport);
				strcpy(peername,myport);
			}else	getpairName(clsock,AVStr(sockname),AVStr(peername));
			wcc = SockPrintf(ToC,"%s %d %d %s %s accepted.\r\n",
				VER,OK_ACCEPT,ClSockN,sockname,peername);
		}else
		if( strcasecmp(com,"QUIT") == 0 ){
			SockPrintf(ToC,"%s %d bye.\r\n",VER,OK_BYE);
			break;
		}else
		if( strcasecmp(com,"FORWARD") == 0 ){
			do_forward(Conn,myport,arg,shared,svsock,0,FromC,ToC);
		}else
		if( strcasecmp(com,"RELAY") == 0 ){
/*
-t timeout
 */
			for( op = arg; *op == '-'; ){
				if( strneq(op,"-t=",3) ){
					int to;
					op = numscanX(op+3,AVStr(opt),sizeof(opt));
					to = atoi(opt);
					if( to < timeout )
						timeout = to;
				}else{
					break;
				}
			}

			tcp_relay2(timeout*1000,FromC,clsock,clsock,ToC);
			/*
			set_linger(clsock,10);
			*/
			set_linger(clsock,LIN_TIMEOUT);
			close(clsock);del_clsock(clsock);
			break;
		}else
		if( strcasecmp(com,"PROXY") == 0 ){
			ToS = FromS = ToC;
			ToC = FromC = clsock;
daemonlog("E","##### VSAP switch protocol to '%s'\n",arg);
			if( strcmp(arg,"http")==0 )
				service_http(Conn);
			else
			if( strcmp(arg,"ftp")==0 )
				service_ftp(Conn);
			set_linger(clsock,10);
			close(clsock);del_clsock(clsock);
			break;
		}else
		{
/*
			wcc = write(clsock,req,rcc);
			tcp_relay2(timeout*1000,FromC,clsock,clsock,ToC);
*/
			SockPrintf(ToC,"%s %d %s",VER,NO_GENERIC,request);
		}
	}
EXIT:
	fclose(authout);
	return 0;
}
#endif /*} OPT_S */


/*
 *	CLIENT
 */
#define FOR_CONNECT	1
#define FOR_ACCEPT	2

#define FOR_HTCONNECT	0x10
#define FOR_HTBIND	0x20
#define FOR_HTACCEPT	0x40
#define FOR_HTALL	(FOR_HTCONNECT|FOR_HTBIND|FOR_HTACCEPT)

typedef struct {
  const	char   *r_host;
	int	r_port;
  const	char   *r_hostport;
	char	r_methods; /* CONNECT, ACCEPT */
  const	char   *r_hosts; /* remote client/server hosts to be relayed ? */
} ServerV;
typedef struct {
	ServerV ve_serverV[8];
	int	ve_serverX;
  const	char   *ve_Socknames[256]; /**/
  const	char   *ve_Peernames[256]; /**/
} VsapClntEnv;
static VsapClntEnv *vsapClntEnv;
#define serverV		vsapClntEnv->ve_serverV
#define serverX		vsapClntEnv->ve_serverX
#define Socknames	vsapClntEnv->ve_Socknames
#define Peernames	vsapClntEnv->ve_Peernames


#ifndef OPT_S /*{*/
void minit_vsapcl(){
	if( vsapClntEnv == 0 )
		vsapClntEnv = NewStruct(VsapClntEnv);
}

static scanListFunc vsap1(PCStr(vsap))
{	CStr(host,MaxHostNameLen);
	int port;
	CStr(methods,256);
	int ri;

	if( 8 <= serverX ){
		daemonlog("F","VSAP[%d] %s -- ignored too many conf.\n",
			serverX,vsap);
		return -1;
	}

	host[0] = 0;
	port = 0;
	methods[0] = 0;
	Xsscanf(vsap,"%[^:/]%*[:/]%d%*[/:]%s",AVStr(host),&port,AVStr(methods));
	daemonlog("E","VSAP[%d] %s:%d\n",serverX,host,port);

	serverV[serverX].r_host = stralloc(host);
	serverV[serverX].r_port = port;
	serverV[serverX].r_hostport = stralloc(vsap);

	if( methods[0] == 0 ){
		serverV[serverX].r_methods = FOR_CONNECT | FOR_ACCEPT; 
	}else{
		if( strstr(methods,"CONNECT") )
			serverV[serverX].r_methods |= FOR_CONNECT;
		if( strstr(methods,"ACCEPT") )
			serverV[serverX].r_methods |= FOR_ACCEPT;
		if( isinListX(methods,"HTTP","c") )
			serverV[serverX].r_methods |= FOR_HTALL;
	}
	serverX++;
	return 0;
}
void scan_VSAP(Connection *Conn,PCStr(vsaps))
{
	scan_commaListL(vsaps,0,scanListCall vsap1);
}
int ViaVSAPassociator(int sock)
{	CStr(sockname,1024);
	CStr(peername,1024);
	int ri;

	if( 0 < serverX ){
		if( sock < 0 )
			return 1;
		getpairName(sock,AVStr(sockname),AVStr(peername));
		/*
		for( ri = 0; ri < serverX; ri++ ){
			daemonlog("D","ViaVSAPassociator ? [%s]==[%s,%s]\n",
				serverV[ri].r_hostport,peername,sockname);
		}
		*/
		return 1;
	}
	return 0;
}

int resp_OK(PCStr(resp))
{	CStr(scode,128);

	if( strncmp(resp,VER,sizeof(VER)-1) == 0 )
	if( 0 < Xsscanf(resp,"%*s %s",AVStr(scode)) )
	if( scode[0] == '2' )
		return atoi(scode);
	return 0;
}

int connectViaUpper(Connection *Conn,PCStr(where),PCStr(proto),PCStr(host),int port);
int connect2server(Connection *Conn,PCStr(proto),PCStr(host),int port);
int open_vsap(Connection *Conn,int method)
{	int rsock;
	int ri;
	const char *host;
	int port;

	if( serverX == 0 )
		return -1;

	rsock = -1;
	for( ri = 0; ri < serverX; ri++ ){
		if( acceptedViaVSAP == 0 )
			if( (serverV[ri].r_methods & method) == 0 )
				continue;
		if( method == FOR_HTACCEPT )
		if( serverV[ri].r_methods & FOR_HTACCEPT ){
			return 1;
		}
		host = serverV[ri].r_host;
		port = serverV[ri].r_port;
		rsock = -1;
		if( method & (FOR_HTBIND|FOR_HTCONNECT) ){
			rsock = connectViaUpper(Conn,"VSAP","http",host,port);
		}
		if( rsock < 0 )
		rsock = Socket1("VSAP",NEWSOCK,VStrANYPORT,host,port,0,NULL,0);
		if( 0 <= rsock )
			break;
	}
	if( method & (FOR_HTCONNECT|FOR_HTBIND|FOR_HTACCEPT) ){
		return rsock;
	}
	if( 0 <= rsock ){
		const char *auth;
		CStr(authb,256);
		if( get_MYAUTH(Conn,AVStr(authb),"vsap",host,port) )
			auth = authb;
		else	auth = getenv("VSAP_AUTH");
		if( auth ){
			CStr(resp,256);
			SockPrintf(rsock,"%s AUTH %s\r\n",VER,auth);
			RecvLine(rsock,resp,sizeof(resp));
			daemonlog((char*)(resp_OK(resp)?"D":"E"),"## AUTH: %s",resp);
		}
	}
	return rsock;
}

int gettelesockname(DGC*Conn,PVStr(name));
int getteleportname(DGC*Conn,PVStr(name));
int isNotClientSock(DGC*Conn,int sock){
	if( sock == ServerSock || sock == ToS || sock == FromS
	 || sock != ClientSock && sock != ToC && sock != FromC
	){
		return 1;
	}
	return 0;
}
int VSAPgetsockname(DGC*Conn,int rsock,PVStr(sockname))
{
	if( AccViaHTMUX == 0 ){
		/* 9.9.1 don't use non-HTMUX RIDENT to bind FTP data-conn. */
	}else
	if( isNotClientSock(Conn,rsock) ){
		/* don't use client side RIDENT as a server RIDENT */
	}else{
		if( gettelesockname(Conn,BVStr(sockname)) == 0 ){
			return 0;
		}
	}
	setVStrEnd(sockname,0);
	if( elnumof(Socknames) <= rsock )
		return -1;
	if( 0 <= rsock && Socknames[rsock] != NULL ){
		strcpy(sockname,Socknames[rsock]);
		return 0;
	}
	return -1;
}
int VSAPgetpeername(DGC*Conn,int rsock,PVStr(peername))
{
	if( AccViaHTMUX == 0 ){
		/* 9.9.1 don't use non-HTMUX RIDENT to bind FTP data-conn. */
	}else
	if( isNotClientSock(Conn,rsock) ){
	}else{
		if( getteleportname(Conn,BVStr(peername)) == 0 ){
			return 0;
		}
	}
	setVStrEnd(peername,0);
	if( elnumof(Peernames) <= rsock )
		return -1;
	if( 0 <= rsock && Peernames[rsock] != NULL ){
		strcpy(peername,Peernames[rsock]);
		return 0;
	}
	return -1;
}

int ConnectViaHTTP(Connection *Conn,int sock,int timeout,PVStr(sockname),PVStr(peername));

int CTX_VSAPconnect(Connection *Conn,PVStr(sockname),PVStr(peername))
{	CStr(resp,1024);
	int rsock;
	int cid;
	int acode;

	rsock = open_vsap(Conn,FOR_HTCONNECT);
	if( 0 <= rsock ){
		rsock = ConnectViaHTTP(Conn,rsock,0,
			BVStr(sockname),BVStr(peername));
		if( 0 <= rsock ){
			goto EXIT;
		}
		return -1;
	}
	rsock = open_vsap(Conn,FOR_CONNECT);
	if( rsock < 0 )
		return -1;
	if( elnumof(Socknames) <= rsock ){
		close(rsock);
		return -1;
	}


	if( sockname[0] != 0 ){
		SockPrintf(rsock,"%s BIND %s\r\n",VER,sockname);
		RecvLine(rsock,resp,sizeof(resp));
	}

	SockPrintf(rsock,"%s CONNECT %s\r\n",VER,peername);
	if( RecvLine(rsock,resp,sizeof(resp)) <= 0 ){
		close(rsock);
		return -1;
	}
	daemonlog("D","VSAPd says: %s",resp);
	if( !resp_OK(resp) ){
		close(rsock);
		return -1;
	}

	SockPrintf(rsock,"RELAY\r\n");
	Xsscanf(resp,"%*s %*d %d %s %s connected.",&cid,AVStr(sockname),AVStr(peername));

EXIT:
	sv1log("-- VSAPconnect[%d][%s][%s]\n",rsock,sockname,peername);
	Socknames[rsock] = stralloc(sockname);
	Peernames[rsock] = stralloc(peername);
	return rsock;
}

#endif /*} OPT_S */

/* '"DIGEST-OFF"' */

