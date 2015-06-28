/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	cuseeme.c (CU-SeeMe proxy reflector)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950527	created
//////////////////////////////////////////////////////////////////////#*/
#include "vsocket.h"
#include "delegate.h"
#include "fpoll.h"
int logVERBOSE();


typedef unsigned long U_long;
typedef unsigned short U_short;
typedef unsigned char U_char;

#define SendToB(s,b,l,h,p)	SendTo(s,(char*)b,l,h,p)
#define RecvFromB(s,b,l,h,p)	RecvFrom(s,(char*)b,l,h,p)

#define kGroup			htonS(0)
#define kClient			htonS(1)
#define kReflector		htonS(2)

#define kControlType		htonS(100)
#define kConfigVideoType	htonS(101)
#define kPacketLossReport	htonS(102)
#define kAckType		htonS(103)
#define kOpenConnection		htonS(1)
#define kCloseConnection	htonS(6)

#define WANT_VERSION		0x20

#define INC_NL(v,i)	(v = htonL(ntohL(v)+i))

typedef struct addr {
	short	family;
	U_short	port;
	U_long	addrI;
} Addr;
typedef struct Routing {
	Addr	dest;
	Addr	src;
} Routing;
typedef struct VideoPacketHeader {
	Routing	routing;
	U_long	seqNum;
	short	message;
	short	dataType;
	short	len;
} VideoPacketHeader;
typedef struct OpenContinuePacket {
	VideoPacketHeader	header;
	short	clientCount;
	U_long	seqNum;
	char	name[20]; /**/
	U_char	sendMode;
	U_char	recvMode;
	U_char	flags;
	U_char	version;
} OpenContinuePacket;

/*
 *	Reflector/DeleGate
 */
#define NUM_ROUTER	128
#define NUM_CLIENT	256
#define	CLIENT_TIMEOUT	10

typedef struct {
	Addr	addrA;
	int	routerx;
	MStr(	e_Rhost,17);
	int	Rport;
	int	clientID;
	int	confID;
	int	failed;
	int	lasttime;
	int	disable;
} Client;

typedef struct {
	MStr(	ce_Serverhost,17);
	int	ce_Serverport;
	Client *ce__clients;
	Client *ce__routers;
	int	ce_Clientx;
	int	ce_ClientID;
	int	ce_Routerx;
	FILE   *ce_Save;
	OpenContinuePacket ce_Vctl;
	int	ce_SVsock;
	int	ce_openedReflector;
} CUSeeMeEnv;
static CUSeeMeEnv *cUSeeMeEnv;
#define Serverhost	cUSeeMeEnv->ce_Serverhost
/**/
#define Serverport	cUSeeMeEnv->ce_Serverport
#define _clients	cUSeeMeEnv->ce__clients
#define _routers	cUSeeMeEnv->ce__routers
#define Clientx		cUSeeMeEnv->ce_Clientx
#define ClientID	cUSeeMeEnv->ce_ClientID
#define Routerx		cUSeeMeEnv->ce_Routerx
#define Save		cUSeeMeEnv->ce_Save
#define Vctl		cUSeeMeEnv->ce_Vctl
#define SVsock		cUSeeMeEnv->ce_SVsock
#define openedReflector	cUSeeMeEnv->ce_openedReflector
void minit_cuseeme()
{
	if( cUSeeMeEnv == 0 )
		cUSeeMeEnv = NewStruct(CUSeeMeEnv);
}

static Client *routerp(int rx)
{
	if( _routers == NULL )
		_routers = (Client*)calloc(NUM_ROUTER,sizeof(Client));
	return &_routers[rx];
}
static Client *clientp(int cx)
{
	if( _clients == NULL )
		_clients = (Client*)calloc(NUM_CLIENT,sizeof(Client));
	return &_routers[cx];
}

static int getRouter(PCStr(host),int port)
{	int ri;
	Client *rp;

	for( ri = 1; ri <= Routerx; ri++ ){
		rp = routerp(ri);
		if( strcmp(rp->e_Rhost,host) == 0 && rp->Rport == port )
			return ri;
	}
	rp = routerp(++Routerx);
	sv1log("added route[%d] %s:%d\n",ri,host,port);
	strcpy(rp->e_Rhost,host);
	rp->Rport = port;
	return Routerx;
}
static void addClient(int curtime,PCStr(host),int port,Addr *caddr)
{	int ci;
	Client *ca;
	int routerx;

	routerx = getRouter(host,port);
	for( ci = 1; ci <= Clientx; ci++ ){
		ca = clientp(ci);
		if( ca->addrA.addrI==caddr->addrI && ca->addrA.port==caddr->port ){
			if( routerx != ca->routerx )
				sv1log("moved client#%d [%d/%d]%x:%d via [%d]%s:%d\n",
					ca->clientID,ci,Clientx,
					ll2i(caddr->addrI),ntohS(caddr->port),
					routerx,host,port);
			if( ca->disable )
				sv1log("enabled client#%d [%d/%d]\n",
					ca->clientID,ci,Clientx);

			ca->routerx = routerx;
			ca->failed = 0;
			ca->lasttime = curtime;
			ca->disable = 0;
			return;
		}
	}
	ca = clientp(++Clientx);
	ca->clientID = ++ClientID;

	ca->addrA = *caddr;
	ca->routerx = routerx;
	ca->failed = 0;
	ca->lasttime = curtime;
	ca->disable = 0;

	sv1log("added client#%d [%d/%d]%s:%d via [%d]%s:%d\n",
		ca->clientID,ci,Clientx,
		_inet_ntoaV4I(caddr->addrI),ntohS(caddr->port),routerx,host,port);
}
static void delClient(PCStr(why),int ci)
{	Client *ca;
	int cj;

	ca = clientp(ci);
	sv1log("removed client#%d [%d/%d]: %x (%s)\n",
		ca->clientID,ci,Clientx,ll2i(ca->addrA.addrI),why);
	for( cj = ci; cj <= Clientx; cj++ )
		*clientp(cj) = *clientp(cj+1);
	Clientx--;
}
static int isClient(Addr *caddr)
{	int ci;
	Client *ca;

	for( ci = 1; ci <= Clientx; ci++ ){
		ca = clientp(ci);
		if( caddr->addrI==ca->addrA.addrI && caddr->port==ca->addrA.port )
			return ci;
	}
	return 0;
}
static int activeClients()
{	int ci,nact;
	nact = 0;
	for( ci = 1; ci <= Clientx; ci++ )
		if( !clientp(ci)->disable )
			nact++;
	return nact;
}
static void closeClient(Addr *caddr)
{	int ci;

	if( ci = isClient(caddr) )
		clientp(ci)->disable = 1;
}

static void toClients(int curtime,int svsock,VideoPacketHeader *vp,int len)
{	int ci;
	int wcc;
	Client *ca;
	int timeout;
	Client *rp;

	timeout = curtime - CLIENT_TIMEOUT;

	if( Save != NULL )
		fwrite(vp,len,1,Save);

	for( ci = 1; ci <= Clientx; ci++ ){
		ca = clientp(ci);
		rp = routerp(ca->routerx);

		if( !ca->disable ){
			wcc = SendToB(svsock,vp,len,rp->e_Rhost,rp->Rport);
			if( wcc <= 0 ){
				if( 10 < ca->failed++ ){
					delClient("CANTSEND",ci);
					ci--;
				}
			}
		}
		if( ca->lasttime < timeout ){
			delClient("TIMEOUT",ci);
			ci--;
		}
	}
}
static void dumpPacket(VideoPacketHeader *vp)
{	CStr(dhost,32);
	CStr(shost,32);

	strcpy(dhost,_inet_ntoaV4I(vp->routing.dest.addrI)),
	strcpy(shost,_inet_ntoaV4I(vp->routing.src.addrI)),
fprintf(stderr,
	"PACKET dst=[%d]%s:%d  src=[%d]%s:%d seq=%d msg=%d type=%d len=%d\n",
	ntohS(vp->routing.dest.family),dhost,ntohS(vp->routing.dest.port),
	ntohS(vp->routing.src.family), shost,ntohS(vp->routing.src.port),
	ntohL(vp->seqNum),
	ntohS(vp->message), ntohS(vp->dataType), ntohS(vp->len)
	);
}
static void dumpPakect2(int rcc,int rhost,int rport,VideoPacketHeader *vp)
{
fprintf(stderr,"%d %x:%d  %d.%x:%d >> %d.%x:%d msg=%3d type=%3d len=%3d #%d\n",
	rcc,rhost,rport,
	vp->routing.src.family,
	ll2i(vp->routing.src.addrI),
	vp->routing.src.port,
	vp->routing.dest.family,
	ll2i(vp->routing.dest.addrI),
	vp->routing.dest.port,
	vp->message,
	vp->dataType,
	vp->len,
	ll2i(vp->seqNum)
	);
}

static void dumpVctl(PCStr(sh),int sp)
{	int i;
	const unsigned char *vp;

	fprintf(stderr,"[%s:%d]\n",sh,sp);
	vp = (unsigned char*)&Vctl;
	for( i = 0; i < sizeof(Vctl); i++ ){
		if( i != 0 && i % 16 == 0 )
			fprintf(stderr,"\n");
		fprintf(stderr,"%2x ",vp[i]);
	}
	fprintf(stderr,"\n");
}

static void closeServer(PCStr(serverhost),int serverport)
{
	sv1log("CloseConnection: no client.\n");
	openedReflector = 0;
	INC_NL(Vctl.header.seqNum,1);
	Vctl.header.dataType = kConfigVideoType;
	Vctl.header.message = kCloseConnection;
	/*dumpVctl(serverhost,serverport);*/
	SendToB(SVsock,&Vctl,sizeof(Vctl),serverhost,serverport);
}
static void openServer(PCStr(serverhost),int serverport,VideoPacketHeader *vp)
{
	for(;;){
		sv1log("OpenConnection: confid=%d\n",
			ntohS(vp->routing.dest.port));
		INC_NL(Vctl.header.seqNum,1);
		Vctl.header.dataType = kConfigVideoType;
		Vctl.header.message = kOpenConnection;
		Vctl.header.routing.dest.port = vp->routing.dest.port;
		SendToB(SVsock,&Vctl,sizeof(Vctl),serverhost,serverport);
		if( 0 < PollIn(SVsock,1000) ){
			sv1log("Opened.\n");
			openedReflector = 1;
			break;
		}
		sleep(1);
	}
}

static void getServerAddr(PCStr(myhost),int myport)
{	int retry;
	int wcc,rcc;
	CStr(rhost,17);
	int rport;
	int bgntime;
	VideoPacketHeader vpk;

	Vctl.header.routing.src.family = kClient;
	Vctl.header.routing.src.addrI = _inet_addrV4(myhost);
	Vctl.header.routing.src.port = htonS(myport);

	Vctl.header.routing.dest.family = kReflector;
	Vctl.header.routing.dest.addrI = _inet_addrV4(Serverhost);
	Vctl.header.routing.dest.port = htonS(Serverport);

	Vctl.header.seqNum = htonL(255);
	Vctl.header.message = kOpenConnection;
	Vctl.header.dataType = kConfigVideoType;
	Vctl.header.len = 0;

	if( logVERBOSE() ) dumpPacket((VideoPacketHeader*)&Vctl);
	Vctl.flags = WANT_VERSION;

	bgntime = time(0);
	for( retry = 0; ;retry++ ){
		INC_NL(Vctl.header.seqNum,1);
		Vctl.seqNum = Vctl.header.seqNum;

		/*dumpVctl(serverhost,serverport);*/
		wcc = SendToB(SVsock,&Vctl,sizeof(Vctl),Serverhost,Serverport);
		if( PollIn(SVsock,1000) <= 0 ){
			if( 30 < time(0)-bgntime ){
				sv1log("give up ;-<\n");
				break;
			}
			sv1log("NO RESPONSE FROM %s:%d, retry...\n",
				Serverhost,Serverport);
			continue;
		}
		rcc = RecvFromB(SVsock,&vpk,sizeof(vpk),AVStr(rhost),&rport);
		if( vpk.routing.src.family == kReflector )
		{
			if( logVERBOSE() ) dumpPacket(&vpk);
			sv1log("REFLECTOR: %s:%d -> %s:%d\n",
				Serverhost,Serverport,AVStr(rhost),rport);
			strcpy(Serverhost,rhost);
			Serverport = rport;
			break;
		}
	}
	INC_NL(Vctl.header.seqNum,1);
	Vctl.header.message = kCloseConnection;
	SendToB(SVsock,&Vctl,sizeof(Vctl),Serverhost,Serverport);
	if( logVERBOSE() ) dumpPacket((VideoPacketHeader*)&Vctl);
}

int service_cuseeme(Connection *Conn,int svsock,int myport)
{	CStr(buff,0x8000);
	int rcc;
	VideoPacketHeader *vp;
	CStr(host,128);
	CStr(myhost,17);
	CStr(rhost,17);
	int rport;
	Addr client;
	int ucount,ubytes,dcount,dbytes;
	int bgntime,curtime,nexttime;
	CStr(shost,128); /* socket host if using */
	int sport;
	const char *aaddr;

	minit_cuseeme();

	SVsock = svsock;
	if( (aaddr = gethostaddr(DST_HOST)) == NULL ){
		sv1log("#### ERROR: bad destination host [%s]\n",DST_HOST);
		return -1;
	}
	strcpy(Serverhost,aaddr);
	Serverport = DST_PORT;
	if( hostIFfor1(AVStr(host),1,DST_PROTO,DST_HOST,DST_PORT) == 0 )
	if( hostIFfor(DST_HOST,AVStr(host)) == 0 )
		gethostname(host,sizeof(host));
	/*
	strcpy(myhost,gethostaddr(host));
	*/
	strcpy(myhost,gethostaddrX(host));
	sv1log("myname=%s[%s]\n",host,myhost);

 {
const char *file;

	if( file = getenv("CUIN") ){
		Save = fopen(file,"w");
		fprintf(stderr,"CUIN: %s : %x\n",file,p2i(Save));
	}
 }

	if( 0 < socks_addservers() )
	if( SOCKS_udpassocsock(SVsock,myhost,myport,AVStr(shost),&sport) == 0 ){
		sv1log("via SOCKS: %s:%d -> %s:%d\n",myhost,myport,shost,sport);
		strcpy(myhost,shost);
		myport = sport;
	}

	closeServer(Serverhost,Serverport);
	getServerAddr(myhost,myport);

	ucount = ubytes = 0;
	dcount = dbytes = 0;
	bgntime = time(0);
	nexttime = (bgntime/10+1) * 10;
	vp = (VideoPacketHeader *)buff;

	sv1log("REFLECTOR: %s:%d\n",Serverhost,Serverport);
	for(;;){
		rcc = RecvFromB(SVsock,buff,sizeof(buff),AVStr(rhost),&rport);
		if( rcc < 0 )
			continue;
		/* dumpPacket2(vp); */

		if( vp->routing.src.family == kReflector )
		if( strcmp(Serverhost,rhost) != 0 || Serverport != rport )
		{
			sv1log("REFLECTOR: %s:%d -> %s:%d\n",
				Serverhost,Serverport,rhost,rport);
			strcpy(Serverhost,rhost);
			Serverport = rport;
		}

		curtime = time(0);
		if( strcmp(rhost,Serverhost) == 0 && rport == Serverport ){
			dcount++;
			dbytes += rcc;
			toClients(curtime,SVsock,vp,rcc);
		}else{
			ucount++;
			ubytes += rcc;

			if( vp->message == kCloseConnection ){
				closeClient(&vp->routing.src);
				SendToB(SVsock,vp,rcc,Serverhost,Serverport);

				if( openedReflector && activeClients() == 0 )
					closeServer(Serverhost,Serverport);
			}else{
				if( openedReflector == 0 )
					openServer(Serverhost,Serverport,vp);
				addClient(curtime,rhost,rport,&vp->routing.src);
				SendToB(SVsock,vp,rcc,Serverhost,Serverport);
			}
		}
		if( nexttime <= curtime ){
			double Bps;

			Bps = ((ubytes+dbytes)*8.0)/(curtime-bgntime);
			daemonlog("I","%d clnts, %d/%dup+%d/%ddown, %5.2fKbps\n",
				Clientx,ubytes,ucount,dbytes,dcount,Bps/1000);
			nexttime = (curtime/10+1) * 10;
		}
	}
	return 0;
}
