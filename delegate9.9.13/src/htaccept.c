const char *SIGN_htaccept_c="{FILESIGN=htaccept.c:20141031194213+0900:4b407e4f6e9729aa:Author@DeleGate.ORG:qsSCAlYiRwcCRYUEcFvLX5NuoskS4UQBF+x1OSKb5yAwcWMcBWYYbOhd/sl5hDHSI5reWjA4nah5j/ieNxs//tGC1BEm2DXP7rjg3ewNopKQWodVa1+EzJYowU/+Zc3ubD/ORMjO6t3O7sEqlizVLDRtoI5SQ1HrhugovaOVdas=}";

/*///////////////////////////////////////////////////////////////////////
Copyright (c) 2002-2008 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	htaccept.c (ACCEPT method for circuit level proxing)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	A tentative extension method "ACCEPT" of HTTP, which could
	be used for replacement of BIND command of SOCKS.

	Request:

	   ACCEPT localhost:localport HTTP/1.1
	  +Host: remotehost
	  +Pragma: timeout=seconds
	  +Authorization: ...

	      - localhost and localport can be "*" representing wild-card
	      - all header fields are optional
	      - remotehost can be used to determine
		- forwarding to upstream proxy
		- interface when localhost is "*"
		- access limitation for accept

	Response:

	   HTTP/1.1 100 bound
	   Host: localhost:localport
           Pragma: timeout=seconds

	   HTTP/1.1 200 accepted
	   Host: remotehost:remoteport

	   [bidirectional communication]

	Error:
	   HTTP/1.1 500 could not bound
	   HTTP/1.1 500 accept timedout

	This is enabled with DeleGate paramegers:
		HTTPCONF=methods:+,ACCEPT
		REMIKTTALBE=+,tcprelay
		PORT=8000-8010  // localports to be shared

History:
	020308	created
	080917	supported FTP-data via HTTP-ACCEPT
	080919	supported timeout for port bound dynamically
TODO:
	ACCEPT name
	CONNECT name
	ACCEPT -vhost:port
	CONNECT -vhost:port
	CONNECT http://host:port
	ACCEPT	http://host:port
        ACCEPT http://host:port/path -->> MOUNT="/path/* http://client/*"
//////////////////////////////////////////////////////////////////////#*/
#include "vsocket.h"
#include "delegate.h"
#include "fpoll.h"
#include "http.h"
#include "proc.h"
double MAX_HTMUXSKEW = 5*60;
extern int S_ADDRNOTAVAIL;
int startHTMUX_SV(DGCTX Conn,PCStr(sxver),FILE *tc,PCStr(req),PCStr(head));
int startHTMUX_CL(DGCTX Conn,int sock,PCStr(rport));

extern char OutboundHTMUX[];
#define getFV2(str,fld,buf) getFieldValue2(str,fld,AVStr(buf),sizeof(buf))

#ifndef OPT_S /*{*/
typedef struct {
	int	bp_host[4]; /* IPv4 / IPv6 */
	int	bp_port;
	int	bp_hold;
	int	bp_sock;
	int	bp_made;
	int	bp_last;
	int	bp_nref; /* active reference count */
	int	bp_nque; /* waiting before accept CSC */
    CriticalSec bp_accCSC;
} BoundPort;

static CriticalSec portCSC;
static BoundPort bports[16];
static int wtid;

static void pwatch(){
	int pi;
	BoundPort *Bp;
	int now;
	int idle;

	for(;;){
		now = time(0);
		enterCSC(portCSC);
		for( pi = 0; pi < elnumof(bports); pi++ ){
			Bp = &bports[pi];
			if( Bp->bp_port == 0 )
				continue;
			idle = now - Bp->bp_last;
			Verbose("-- pwatch(%d) [%d]%d idle=%d/%d R%d\n",
				pi,Bp->bp_sock,Bp->bp_port,
				idle,Bp->bp_hold,Bp->bp_nref);
			if( Bp->bp_nref == 0 )
			if( Bp->bp_hold < idle ){
				close(Bp->bp_sock);
				Bp->bp_port = 0;
			sv1tlog("-- pwatch(%d) FREE [%d]%d idle=%d/%d R%d\n",
					pi,Bp->bp_sock,Bp->bp_port,
					idle,Bp->bp_hold,Bp->bp_nref);
			}
		}
		leaveCSC(portCSC);
		sleep(10);
	}
}
int idlethreads();
static int threadPollIns(BoundPort *Bp,int timeout,int fdn,int fdv[],int rdv[]){
	int nready = -1;
	int nith;
	int rem;
	int slp;

	if( timeout == 0 ){
		Verbose("threadPollIns(0,%d)\n",fdn);
		nready = PollIns(0,fdn,fdv,rdv);
		return nready;
	}
	for( rem = timeout; 0 < rem; ){
		if( 3*1000 < rem )
			slp = 3*1000;
		else	slp = rem;
		nready = PollIns(slp,fdn,fdv,rdv);
		if( nready ){
			break;
		}
		rem -= slp;
		nith = idlethreads();
		if( Bp && nith < 5 ){
			sv1tlog("-- busy release (%d/%d) %d/%d [%d]%d\n",
				nith,actthreads(),
				rem,timeout,Bp->bp_sock,Bp->bp_port);
			nready = -2;
			break;
		}
	}
	return nready;
}
int mutexACCEPT(BoundPort *Bp,int bsock,int timeout){
	int asock = -1;
	int ncol;
	double St = Time();

	if( !lSINGLEP() || Bp == 0 ){
		/* non-shared socket */
		asock = ACCEPT(bsock,0,-1,timeout);
		return asock;
	}

	ncol = ++Bp->bp_nque;
	setupCSC("ACCEPT",Bp->bp_accCSC,sizeof(Bp->bp_accCSC));
	if( enterCSCX(Bp->bp_accCSC,timeout*1000) == 0 ){
		if( 0 <= PollIn(bsock,1000) ){
			asock = ACCEPT(bsock,0,-1,timeout);
		}else{
			sv1tlog("## (%d) mutexACCEPT timeout[%d]%d %.2f\n",
				ncol,bsock,timeout,Time()-St);
		}
		leaveCSC(Bp->bp_accCSC);
	}else{
		sv1tlog("## (%d) mutexACCEPT failed mutex[%d] %.2f\n",
			ncol,bsock,Time()-St);
	}
	Bp->bp_nque--;
	return asock;
}
static int addPort(PCStr(host),int port,int sock,int hold,BoundPort **Bpp){
	int pi;
	int px = -1;
	int now = time(0);
	BoundPort *Bp = 0;

	if( hold <= 0 ){
		return -1;
	}
	if( wtid == 0 ){
		wtid = thread_fork(0,0,"PortWatcher",(IFUNCP)pwatch);
	}

	setupCSC("PORT",portCSC,sizeof(portCSC));
	enterCSC(portCSC);
	for( pi = 0; pi < elnumof(bports); pi++ ){
		if( bports[pi].bp_port == port ){
			px = pi;
			break;
		}
		if( px < 0 )
		if( bports[pi].bp_port == 0 ){
			px = pi;
		}
	}
	if( 0 <= px ){
		Bp = &bports[px];
		Bp->bp_port = port;
		Bp->bp_sock = sock;
		Bp->bp_made = now;
		Bp->bp_last = now;
		Bp->bp_hold = hold;
		Bp->bp_nref = 1;
	}
	leaveCSC(portCSC);
	if( Bp ){
		Verbose("-- addPort (%d) [%d]%d %d R%d\n",
			px,sock,port,hold,Bp->bp_nref);
		*Bpp = Bp;
	}else{
		*Bpp = 0;
	}
	return px;
}
static int findopenPort(PVStr(host),int port,int nlisten,int hold,BoundPort **Bpp){
	int bsock;
	enterCSC(portCSC);
	bsock = findopen_port("HTACCEPT",BVStr(host),port,nlisten);
	leaveCSC(portCSC);
	if( 0 < hold ){
		addPort(host,port,bsock,hold,Bpp);
	}
	return bsock;
}
static int getPort(PCStr(host),int port,BoundPort **Bpp){
	int pi;
	int px = -1;
	int sock = -1;
	int now = time(0);
	BoundPort *Bp = 0;

	if( port <= 0 ){
		return -1;
	}

	setupCSC("PORT",portCSC,sizeof(portCSC));
	enterCSC(portCSC);
	for( pi = 0; pi < elnumof(bports); pi++ ){
		if( bports[pi].bp_port == port ){
			px = pi;
			Bp = &bports[pi];
			Bp->bp_nref++;
			break;
		}
	}
	leaveCSC(portCSC);
	if( Bp ){
		sock = Bp->bp_sock;
		Verbose("-- gotPort (%d) [%d]%d %d R%d\n",
			px,sock,Bp->bp_port,Bp->bp_hold,Bp->bp_nref);
		Bp->bp_last = now;
		*Bpp = Bp;
	}else{
		*Bpp = 0;
	}
	return sock;
}
static int freePort(BoundPort *Bp,int sock){
	int pi;
	int now = time(0);

	enterCSC(portCSC);
	for( pi = 0; pi < elnumof(bports); pi++ ){
		if( bports[pi].bp_sock == sock ){
			Bp = &bports[pi];
			Bp->bp_last = now;
			Bp->bp_nref--;
			Verbose("-- freePort(%d) [%d]%d R%d\n",pi,
				sock,Bp->bp_port,Bp->bp_nref);
			break;
		}
	}
	leaveCSC(portCSC);
	return 0;
}

static int pass_incoming(Connection *XConn,PCStr(host),int port,int asock){
	Connection ConnBuf,*Conn = &ConnBuf;
	int ok;

	*Conn = *XConn;
	Client_Port = 0;
	ClientSock = asock;
	VA_getClientAddr(Conn);
	set_realserver(Conn,"incoming",host,port);
	  strcpy(DFLT_PROTO,"incoming");
	ok = service_permitted2(Conn,"incoming",1);
	sv1log("-- %s %s://%s:%d <= %s:%d\n",ok?"Pass":"Stop",
		DST_PROTO,DST_HOST,DST_PORT,Client_Host,Client_Port);
	return ok;
}
int pass_incomingR(Connection *XConn,PCStr(clhost),int clport,PCStr(svhost),int svport){
	Connection ConnBuf,*Conn = &ConnBuf;
	int ok;

	*Conn = *XConn;
	strcpy(Client_Host,clhost);
	Client_Port = clport;
	ClientSock = -1;
	Conn->from_myself = 0;
	set_realserver(Conn,"incoming",svhost,svport);
	  strcpy(DFLT_PROTO,"incoming");
	ok = service_permitted2(Conn,"incoming",1);
	sv1log("-- %s %s://%s:%d <= %s:%d (%s)\n",ok?"Pass":"Stop",
		DST_PROTO,DST_HOST,DST_PORT,Client_Host,Client_Port,
		Conn->reject_reason);
	return ok;
}

int openHTMUXproxy(Connection *Conn,PCStr(port)); 
static int forwardHTMUX(Connection *Conn,int psock,PCStr(req),PCStr(head),PCStr(sxver),FILE *fc,FILE *tc,PCStr(rport)){
	psock = startHTMUX_CL(Conn,psock,rport);
	if( psock < 0 ){
		return -1;
	}
	startHTMUX_SV(Conn,sxver,tc,req,head);
	tcp_relay2(0,FromC,psock,psock,ToC);
	return 1;
}

int HTTP_ACCEPT(Connection *Conn,PCStr(req),PCStr(head),FILE *fc,FILE *tc)
{	CStr(local,MaxHostNameLen);
	CStr(remote,MaxHostNameLen);
	int bsock,asock,timeout,lockfd,rcc;
	int nready,fdn,fdv[2],rdv[2];
	FILE *fs,*ts;
	CStr(ver,32);
	CStr(present,0x1000);
	int pcc;
	int hold = 0;
	IStr(qval,128);
	int csock = -1;
	int rrcc = -1;
	IStr(twh,128);
	double Start = Time();
	BoundPort *Bp = 0;
	int ai;
	int htsox = 0;

	if( getFV2(head,"Port-Hold",qval) ){
		hold = atoi(qval);
	}
	if( getFieldValue2(head,"Host",AVStr(remote),sizeof(remote)) ){
	}else	strcpy(remote,"*:*");
	Xsscanf(req,"%*s %s",AVStr(local));
	timeout = 10*1000;
	sprintf(ver,"HTTP/%s",MY_HTTPVER);

	if( 1 ){
		extern int ACC_TIMEOUT;
		timeout = ACC_TIMEOUT*1000;
		if( lSINGLEP() ){
			/* periodical scheduler is not necessary in this case */
			timeout = timeout * 10;
		}
	}
	if( getFV2(head,"HTMUX-Upgrade",qval) ){
		htsox = 1;
	}

	sv1log("<<<< %s%s",req,head);
	if( htsox ){
		if( ConfigFlags & CF_HTMUX_PROXY)
		if( 0 <= (bsock = openHTMUXproxy(Conn,local)) ){
			forwardHTMUX(Conn,bsock,req,head,qval,fc,tc,local);
			return 0;
		}
		if( streq(local,OutboundHTMUX) ){
			bsock = VSocket(Conn,"NEW",-1,AVStr(local),
				AVStr(remote),"listen=0");
		}else
	bsock = VSocket(Conn,"BIND/HTTP",-1,AVStr(local),AVStr(remote),"listen=20");
	}else
	if( lSINGLEP() ){
		IStr(host,256);
		int port = 0;
		sprintf(twh,"HTACCEPT-%s-binding",local);
		setthread_FL(0,FL_ARG,twh);
		Xsscanf(local,"%[^:]:%d",AVStr(host),&port);
		if( 0 <= (bsock = getPort(host,port,&Bp)) ){
			csock = bsock;
			bsock = dup(bsock);
		}else
		if( 0 <= (bsock = ReservedPortSock(host,port)) ){
		}else
		/*
		if( 0 <= (bsock = findopen_port("HTACC",AVStr(host),port,20)) ){
		*/
		if( 0 <= (bsock = findopenPort(AVStr(host),port,20,hold,&Bp)) ){
			if( 0 < hold ){
			csock = bsock;
			bsock = dup(bsock);
			}
		}
	}else
	bsock = VSocket(Conn,"BIND/HTTP",-1,AVStr(local),AVStr(remote),"listen=1");
	if( bsock < 0 ){
		if( S_ADDRNOTAVAIL ){
			sv1log("%s: should be forwarded to upstream\n",
				local);
		}
		fprintf(tc,"%s 500 could not bound\r\n\r\n",ver);
		rrcc = -2; goto EXIT;
		return -2;
	}
	if( htsox ){
		int beSockMux(DGC*ctx,int sxsock,int insock,PCStr(sxhost),int sxport);
		if( startHTMUX_SV(Conn,qval,tc,req,head) == 0 ){
			ProcTitle(Conn,"htmux:%d",sockPort(bsock));
			beSockMux(Conn,FromC,bsock,CLIF_HOST,CLIF_PORT);
		}
		closeNonReservedPortSock(bsock);
		return 0;
	}
	fprintf(tc,"%s 100 bound\r\n",ver);
	fprintf(tc,"Host: %s\r\n",local);
	gethostName(bsock,AVStr(local),"%A:%P");
	fprintf(tc,"Port-Host: %s\r\n",local);
	fprintf(tc,"\r\n");
	fflush(tc);

ACCEPT:
	fdv[0] = bsock;
	fdv[1] = fileno(fc);
	fdn = 2;
	pcc = 0;
	asock = -1;
	/*
	 * should sorten the timeout when there are many other clients ...
	 */
	/*
	for(;;){
	*/
	for( ai = 0; ai < 30; ai++ ){
		double Stp;

		Stp = Time();
		if( lSINGLEP() ){
			sprintf(twh,"HTACCEPT-%s-polling",local);
			setthread_FL(0,FL_ARG,twh);
		}
		if( lSINGLEP() ){
			nready = threadPollIns(Bp,timeout,fdn,fdv,rdv);
		}else
		nready = PollIns(timeout,fdn,fdv,rdv);
		if( nready <= 0 ){
			closeNonReservedPortSock(bsock);
			if( nready == -2 ){
				fprintf(tc,"%s 503 so busy\r\n\r\n",ver);
			}else
			fprintf(tc,"%s 500 accept timedout\r\n\r\n",ver);
			rrcc = -3; goto EXIT;
			return -3;
		}
		if( rdv[0] != 0 )
		{
			if( lSINGLEP() ){
				sprintf(twh,"HTACCEPT-%s-accepting",local);
				setthread_FL(0,FL_ARG,twh);
				asock = mutexACCEPT(Bp,bsock,timeout);
				if( asock < 0 ){
	sv1tlog("## bsock[%d]%X asock[%d] Stp=%.2f %.2f (%.2f) %s\n",
		bsock,p2i(Bp),asock,Time()-Start,Time()-Stp,timeout/1000.0,local);
					continue;
				}
			}
			break;
		}
		if( rdv[1] != 0 ){
			if( sizeof(present) == pcc ){
				/* stop buffering */
				fdn = 1;
			}
			rcc = read(fdv[1],present+pcc,sizeof(present)-pcc);
			if( 0 < rcc )
				pcc += rcc;
			if( rcc <= 0 ){
				/* disconnection from client */
				closeNonReservedPortSock(bsock);
				rrcc = -4; goto EXIT;
				return -4;
			}
		}
	}
	lockfd = -1;
	if( asock < 0 )
	asock = ACCEPT(bsock,0,lockfd,timeout);
	if( lHTTPACCEPT() ){
		if( 0 <= asock && !pass_incoming(Conn,Client_Host,Client_Port,asock) ){
			close(asock);
			asock = -1;
			goto ACCEPT;
		}
	}
	closeNonReservedPortSock(bsock);
	if( asock < 0 ){
		fprintf(tc,"%s 500 accept failed\r\n\r\n",ver);
		rrcc = -5; goto EXIT;
		return -5;
	}

	gethostName(asock,AVStr(local),"%A:%P");
	getpeerName(asock,AVStr(remote),"%A:%P");
	fprintf(tc,"%s 200 accepted\r\n",ver);
	fprintf(tc,"Port-Host: %s\r\n",local);
	fprintf(tc,"Port-Peer: %s\r\n",remote);
	fprintf(tc,"Host: %s\r\n",remote);
	fprintf(tc,"\r\n");
	fflush(tc);
	sv1tlog("HTACC[%d] %.2f %s <= %s\n",asock,Time()-Start,local,remote);

	fs = fdopen(asock,"r");
	ts = fdopen(asock,"w");
	if( fs == NULL || ts == NULL ){
		fprintf(tc,"%s 500 internal error\r\n\r\n",ver);
		rrcc = -6; goto EXIT;
		return -6;
	}

	if( lSINGLEP() ){
		sprintf(twh,"HTACCEPT-%s-relaying",local);
		setthread_FL(0,FL_ARG,twh);
	}
	if( 0 < pcc )
		IGNRETP write(asock,present,pcc);
	rcc = relayf_svcl(Conn,fc,tc,fs,ts);
	close(asock);
	rrcc = rcc;

EXIT:
	sprintf(twh,"HTACCEPT-END");
	if( 0 <= csock ){
		freePort(Bp,csock);
	}
	return rrcc;
	return rcc;
}

#endif /*} OPT_S */

/* '"DIGEST-OFF"' */
        
