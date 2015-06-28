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
Program:	udprelay
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	961006	created (not functional X-)
	980525	total renewal
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include "vsocket.h"
#include "delegate.h"
#include "fpoll.h"

/*
#define MAXASSOC 256
*/
#define MAXASSOC 32

int UDPRELAY_MAXASSOC = MAXASSOC;
extern int IO_TIMEOUT;
extern int SERVER_TIMEOUT;

int UDPRELAY_RPORT_FIX; /* restrict server's response port to be
			   same with its request (accept) port */

typedef struct {
  const	char   *ua_svhost;	/* symbolic name of AF_INET or AF_UNIX */
unsigned
	short	ua_svport;
  const	char   *ua_clhost;
unsigned
	short	ua_clport;

	int	ua_clsock;
	int	ua_id;
	int	ua_timeout;
	int	ua_ctime;
unsigned int	ua_mtime;
	int	ua_upbytes;
	int	ua_upcnt;
	int	ua_downbytes;
	int	ua_downcnt;
	int	ua_svsock;
	int	ua_svbound; /* 9.9.8 bound, sendto() will fail on BSD */
	int	ua_clpriv; /* cl_clsock is private (maybe TCP) for the client */
	int	ua_svtcp; /* cl_svsock is TCP */
	int	ua_svSOCKS;	
	VSAddr	ua_SOCKSADDR;
} UDP_Assoc;

static UDP_Assoc **uassocv;
static int uaid;

static UDP_Assoc *findUAbysrc(UDP_Assoc *uav[],PCStr(clhost),int clport,PCStr(svhost),int svport)
{	int ai;
	UDP_Assoc *ua;

	for( ai = 0; ua = uav[ai]; ai++ ){
		if( strcmp(ua->ua_clhost,clhost) == 0 )
		if( ua->ua_clport == clport )
			return ua;
	}
	return NULL;
}
static int getUAx(UDP_Assoc *uav[],UDP_Assoc *ua)
{	int ai;
	UDP_Assoc *ua1;

	for( ai = 0; ua1 = uav[ai]; ai++ ){
		if( ua1 == ua )
			return ai;
	}
	return -1;
}
static int longestIdle(UDP_Assoc *uav[])
{	int ai;
	unsigned int mtime;
	int mx;
	UDP_Assoc *ua;

	mtime = 0;
	mx = 0;
	for( ai = 0; ua = uav[ai]; ai++ ){
		if( mtime == 0 || ua->ua_mtime < mtime ){
			mtime = ua->ua_mtime;
			mx = ai;
		}
	}
	return mx;
}
static void msghead(PVStr(msg),PCStr(what),UDP_Assoc *ua,int ux)
{
	sprintf(msg,"UDPRELAY %-5s#%-4d[%d](%2d) %s:%d",
		what,ua->ua_id,ux,ua->ua_svsock,ua->ua_clhost,ua->ua_clport);
}
static int permitted(PCStr(clhost),int clport,PCStr(svhost),int svport)
{
	return service_permitted0(clhost,clport,"udprelay",svhost,svport);
}

void initConnect(Connection *Conn);

static void delUA(UDP_Assoc *uav[],int ux,PCStr(why),int squeeze);
static UDP_Assoc *newUA(Connection *Conn,UDP_Assoc *uav[],PCStr(clhost),int clport,PCStr(svhost),int svport)
{	int ux;
	UDP_Assoc *ua;
	int svsock;
	int rcode;
	CStr(msg,128);
	CStr(lhost,256);
	int lport;
	CStr(local,256);
	CStr(remote,256);
	int SOCKSctl = -1;
	CStr(rh,256);
	int rp;

	rcode = -1;
	if( !permitted(clhost,clport,svhost,svport) )
		return NULL;

	sprintf(local,"*:*");
	sprintf(remote,"%s:%d",svhost,svport);
	Conn->from_cached = 1;
	VA_setClientAddr(Conn,clhost,clport,0);
	Conn->no_dstcheck_proto = serviceport("tcprelay");
	initConnect(Conn);
	setupConnect(Conn);

	ServerFlags |= PF_UDP;
	Conn->sv.p_SOCKSCTL = -1;
	svsock = connectViaSocks(Conn,svhost,svport,AVStr(rh),&rp);
	if( 0 <= svsock ){
		sv1log("via SOCKS UDP:%d@%s CTL:%d\n",svsock,
			Conn->sv.p_SOCKSADDR,Conn->sv.p_SOCKSCTL);
		SOCKSctl = Conn->sv.p_SOCKSCTL;
		goto ADDUA;
	}

	svsock = VSocket(Conn,"CNCT/UDPRELAY",-1,AVStr(local),AVStr(remote),"");
	if( 0 <= svsock ){
/*
		setNonblockingIO("UDPRELAY-SV",svsock,1);
*/
		SetNonblockingIO("UDPRELAY-SV",svsock,1);
		goto ADDUA;
	}

	strcpy(lhost,"*");
	lport = 0;
	SRCIFfor(Conn,"udprelay",svhost,svport,AVStr(lhost),&lport);
	if( strcmp(lhost,"*") == 0 )
		lhost[0] = 0;

	svsock = server_open("UDPRELAY",AVStr(lhost),lport,-1);
	if( svsock < 0 ){
		if( uav[0] == 0 ){
			return NULL;
		}
		ux = longestIdle(uav);
		sv1log("push out longest idle 1 [%d]\n",ux);
		delUA(uav,ux,"NoMoreSocket",1);
		svsock = server_open("UDPRELAY",AVStr(lhost),lport,-1);
		if( svsock < 0 )
			return NULL;
	}

	if( UDPRELAY_RPORT_FIX ){
	rcode = __connectServer(svsock,"UDPRELAY","udprelay",svhost,svport /*,1*/);
	if( rcode < 0 ){
		sv1log("UDPRELAY: connect(%d) error %d\n",svsock,rcode);
		close(svsock);
		return NULL;
	}
	}

ADDUA:
	for( ux = 0; uav[ux]; ux++ )
		;
	if( UDPRELAY_MAXASSOC <= ux ){
		ux = longestIdle(uav);
		sv1log("push out longest idle 2 [%d]\n",ux);
		delUA(uav,ux,"NoMoreClient",0);
	}

	ua = (UDP_Assoc*)calloc(1,sizeof(UDP_Assoc));
	ua->ua_id = ++uaid;
	ua->ua_ctime = time(0);
	ua->ua_clhost = stralloc(clhost);
	ua->ua_clport = clport;
	ua->ua_svsock = svsock;
	ua->ua_svbound = (0 < peerPort(svsock));
	ua->ua_svtcp = !isUDPsock(svsock);
	ua->ua_svhost = stralloc(svhost);
	ua->ua_svport = svport;
	ua->ua_svSOCKS = SOCKSctl;
	VSA_aptosa(&ua->ua_SOCKSADDR,Conn->sv.p_SOCKSADDR);
	uav[ux] = ua;

	msghead(AVStr(msg),"start",ua,ux);
	sv1log("%s > %s:%d\n",msg,svhost,svport);
	return ua;
}
static void delUA(UDP_Assoc *uav[],int ux,PCStr(why),int squeeze)
{	int uy;
	UDP_Assoc *ua;
	CStr(msg,128);

	ua = uav[ux];
	close(ua->ua_svsock);
	if( 0 <= ua->ua_svSOCKS ){
		close(ua->ua_svSOCKS);
	}
	if( ua->ua_clpriv )
		close(ua->ua_clsock);
	msghead(AVStr(msg),"done",ua,ux);
	sv1log("%s > %s:%d (%d/%dup,%d/%ddown,%dsec) %s\n",
		msg,
		ua->ua_svhost,ua->ua_svport,
		ua->ua_upbytes,ua->ua_upcnt,
		ua->ua_downbytes,ua->ua_downcnt,ll2i(time(0)-ua->ua_ctime),why);

	if( squeeze ){
	for( uy = ux; uav[uy]; uy++ )
		uav[uy] = uav[uy+1];
	}
	free((char*)ua->ua_svhost);
	free((char*)ua->ua_clhost);
	free(ua);
}
static int killTimeouts(UDP_Assoc *uav[])
{	int ux,uy,nkill;
	int now;
	UDP_Assoc *ua;

	nkill = 0;
	now = time(0);
	for( ux = 0; ua = uav[ux]; ux++ ){
		if( IO_TIMEOUT < (now - ua->ua_mtime) ){
			nkill++;
			delUA(uav,ux,"IdleTimeOut",1);
		}
	}
	return nkill;
}

int sendToA(int sock,PCStr(buf),int len,int flags,PCStr(host),int port);
int recvFromA(int sock,PVStr(buf),int len,int flags,PVStr(froma),int *fromp);
int SOCKS_sendto0(int sock,PCStr(msg),int len,int flags,VSAddr *to,VSAddr *rme,int isconn,int si);
int Send(int s,PCStr(buf),int len);
static int toServ(UDP_Assoc *ua,PCStr(buff),int rcc,PCStr(svhost),int svport,PCStr(clhost),int clport)
{	int wcc;

	ua->ua_mtime = time(0);
	ua->ua_upcnt++;
	ua->ua_upbytes += rcc;
	/*
	if( UDPRELAY_RPORT_FIX )
	*/
	if( 0 <= ua->ua_svSOCKS ){
		VSAddr to,*via;
		VSA_atosa(&to,svport,svhost);
		via = &ua->ua_SOCKSADDR;
		wcc = SOCKS_sendto0(ua->ua_svsock,buff,rcc,0,&to,via,1,0);
	}else
	if( ua->ua_svtcp || ua->ua_svbound || UDPRELAY_RPORT_FIX )
		wcc = Send(ua->ua_svsock,buff,rcc);
	else	wcc = sendToA(ua->ua_svsock,buff,rcc,0,svhost,svport);
	/*
	else	wcc = SendTo(ua->ua_svsock,buff,rcc,svhost,svport);
	*/
	if( wcc < 0 ){
		sv1log("##toServ(%d,%d)=%d e%d\n",ua->ua_svsock,rcc,wcc,errno);
	}

	if( clhost == NULL ){
		clhost = ua->ua_clhost;
		clport = ua->ua_clport;
	}
	Verbose("TO SERV#%d: %s:%d %3d> %s:%d\n",
		ua->ua_id,clhost,clport,rcc,svhost,svport);
	return wcc;
}

int socks_addservers();

void udp_relayX(Connection *Conn,int csc,int csv[]);
void udp_relay(Connection *Conn,int clsock)
{	int csv[1];

	csv[0] = clsock;
	udp_relayX(Conn,1,csv);
}
void udp_relayX(Connection *Conn,int csc,int csv[])
{	int svsock;
	int sockv[1024],readyv[1024],sx; /* must be lt/eq FD_SESIZE */
	int nsock; /* number of clients */
	CStr(buff,0x8000);
	int rcc,wcc;
	int nready;
	CStr(ihost,64);
	int iport;
	CStr(svhost,64);
	int svport;
	const char *clhost;
	int clport;
	UDP_Assoc *ua;
	UDP_Assoc *udpav[MAXASSOC*4]; /**/
	int udpxv[MAXASSOC*4];
	int lastrelay,idle;
	const char *aaddr;
	int svportmap;
	int portnumv[64];
	int csi;
	int istcp[MAXASSOC];
	int ccc = 0; /* tcp clients */
	int usocks = 0; /* UDP SOCKS */
	int update = 0;
	int ai;

	/* is this necessary or effective ? */
	socks_addservers();

	if( MAXASSOC < UDPRELAY_MAXASSOC ){
		UDPRELAY_MAXASSOC = MAXASSOC;
	}
	sv1log("MAXIMA=udprelay:%d (max. udp assoc.)\n",UDPRELAY_MAXASSOC);

	if( (aaddr = gethostaddr(DST_HOST)) == NULL ){
		sv1log("#### ERROR: bad destination host [%s]\n",DST_HOST);
		return;
	}
	strcpy(svhost,aaddr);
	svport = DST_PORT;
	svportmap = DFLT_PORTMAP;
	if( svportmap ){
		/* get port numbers of incoming ports ... */
		for( csi = 0; csi < csc; csi++ ){
			portnumv[csi] = sockPort(csv[csi]) + svportmap;
			portnumv[csi] &= ~0x40000000; /* clear IS_PORTMAP */
		}
	}

	expand_fdset(MAXASSOC);
	uassocv = (UDP_Assoc**)calloc(MAXASSOC+1,sizeof(UDP_Assoc*));
	for( csi = 0; csi < csc; csi++ )
		sockv[csi] = csv[csi];
	for( csi = 0; csi < csc; csi++ )
		istcp[csi] = !isUDPsock(sockv[csi]);
	nsock = 0;
	lastrelay = 0;

	for(;;){
UPDATE:
		if( update ){
			int ai;
			update = 0;
			ccc = 0;
			for( ai = 0; ua = uassocv[ai]; ai++ ){
				if( ua->ua_clpriv ){
				udpxv[csc + ccc] = ai;
				udpav[csc + ccc] = ua;
				sockv[csc + ccc++] = ua->ua_clsock;
				}
			}
			nsock = 0;
			for( ai = 0; ua = uassocv[ai]; ai++ ){
				udpxv[csc+ccc + nsock] = ai;
				udpav[csc+ccc + nsock] = ua;
				sockv[csc+ccc + nsock++] = ua->ua_svsock;
			}
			usocks = 0;
			for( ai = 0; ua = uassocv[ai]; ai++ ){
				int ns = csc+ccc+nsock;
				if( 0 <= ua->ua_svSOCKS ){
					udpxv[ns+usocks] = ai;
					udpav[ns+usocks] = ua;
					sockv[ns+usocks] = ua->ua_svSOCKS;
					usocks++;
				}
			}
		}
		/*
		nready = PollIns(10*1000,csc+nsock+ccc,sockv,readyv);
		*/
		nready = PollIns(10*1000,csc+ccc+nsock+usocks,sockv,readyv);
		if( nready < 0 ){
			/*
			sv1log("UDPRELAY: ABORT PollIns(%d) = %d\n",nready);
			*/
			sv1log("UDPRELAY: ABORT PollIns(%d+%d+%d+%d)=%d\n",
				csc,ccc,nsock,usocks,nready);
			for( ai = 0; ai < csc+ccc+nsock+usocks; ai++ ){
				sv1log("[%2d] %d\n",ai,sockv[ai]);
			}
			break;
		}
		if( nready == 0 ){
			idle = time(0) - lastrelay;
			if( SERVER_TIMEOUT && lastrelay )
			if( SERVER_TIMEOUT < idle){
				sv1log("UDPRELAY: SERVER TIMEOUT (idle %ds)\n",
					idle);
				break;
			}
			killTimeouts(uassocv);
			/*
			nsock = getsocks(uassocv,&sockv[csc]);
			*/
			update = 1;
			continue;
		}
		lastrelay = time(0);

		for( sx = 0; sx < csc; sx++ )
		if( 0 < readyv[sx] && istcp[sx] ){
			CStr(local,256);
			CStr(remote,256);
			int clsk;
			strcpy(remote,"*:*");
			strcpy(local,"*:*");
			clsk = VSocket(Conn,"ACPT/",sockv[sx],AVStr(local),AVStr(remote),"");
/*
			setNonblockingIO("UDPRELAY-CL",clsk,1);
*/
			SetNonblockingIO("UDPRELAY-CL",clsk,1);
			iport = getpeerAddr(clsk,AVStr(ihost));
			if( clsk <= 0 || iport <= 0 ){
				sv1log("UDPRELAY: accept() errno=%d\n",errno);
				continue;
			}
			if( svportmap ){
				svport = portnumv[sx];
			}
			ua = newUA(Conn,uassocv,ihost,iport,svhost,svport);
			ua->ua_clsock = clsk;
			ua->ua_clpriv = 1;
			update = 1;
		}else
		if( 0 < readyv[sx] ){
			rcc = recvFromA(sockv[sx],AVStr(buff),sizeof(buff),0,AVStr(ihost),&iport);
			if( rcc <= 0 ){
				sv1log("UDPRELAY: recv() == 0, errno=%d\n",errno);
				break;
			}
			if( svportmap ){
				svport = portnumv[sx];
			}
			ua = findUAbysrc(uassocv,ihost,iport,svhost,svport);
			if( ua == NULL ){
				ua = newUA(Conn,uassocv,ihost,iport,svhost,svport);
				if( ua == NULL ){
					continue;
				}
				ua->ua_clsock = sockv[sx];
				if( ua->ua_svsock < 0 )
					continue;
				/*
				nsock = getsocks(uassocv,&sockv[csc]);
				*/
				update = 1;
			}
			toServ(ua,buff,rcc,svhost,svport,ihost,iport);
			/*
			ua->ua_mtime = time(0);
			ua->ua_upcnt++;
			ua->ua_upbytes += rcc;
			if( UDPRELAY_RPORT_FIX )
				wcc = Send(ua->ua_svsock,buff,rcc);
			else	wcc = SendTo(ua->ua_svsock,buff,rcc,svhost,svport);
			Verbose("TO SERV#%d: %s:%d %3d> %s:%d\n",
				ua->ua_id,ihost,iport,rcc,svhost,svport);
			*/
			if( nready == 1 )
				continue;
		}

		for( sx = csc; sx < csc+ccc; sx++ )
		if( 0 < readyv[sx] ){
			rcc = recv(sockv[sx],buff,sizeof(buff),0);
			if( rcc <= 0 ){
				int ux = getUAx(uassocv,udpav[sx]);
				if( ux < 0 ){
					sv1log("## delUA-CL(%d)?\n",ux);
					continue;
				}
				delUA(uassocv,ux,"TCPreset-CL",1);
				/* here udpxv[] becomes inconsistent */
				update = 1;
			}else{
				ua = udpav[sx];
				toServ(ua,buff,rcc,svhost,svport,NULL,0);
			}
		}

		/*
		for( sx = csc; sx < csc+nsock; sx++ ){
		*/
		for( sx = csc+ccc; sx < csc+ccc+nsock; sx++ ){
			if( readyv[sx] <= 0 )
				continue;
			ua = udpav[sx];
			svsock = sockv[sx];

			if( 0 <= ua->ua_svSOCKS )
			rcc = RecvFrom(svsock,buff,sizeof(buff),AVStr(ihost),&iport);
			else
			rcc = recvFromA(svsock,AVStr(buff),sizeof(buff),0,AVStr(ihost),&iport);

			if( rcc <= 0 ){
				if( ua->ua_svtcp ){
					int ux = getUAx(uassocv,udpav[sx]);
					if( ux < 0 ){
						sv1log("## delUA-SV(%d)?\n",ux);
						continue;
					}
					delUA(uassocv,ux,"TCPreset-SV",1);
					update = 1;
				}
				readyv[sx] = -1;
				continue;
			}

			/*
			ua = findUAbysock(uassocv,svsock);
			*/
			ua->ua_mtime = time(0);
			ua->ua_downcnt++;
			ua->ua_downbytes += rcc;
			clhost = ua->ua_clhost;
			clport = ua->ua_clport;
			/*
			wcc = SendTo(ua->ua_clsock,buff,rcc,clhost,clport);
			*/
			wcc = sendToA(ua->ua_clsock,buff,rcc,0,clhost,clport);

			Verbose("TO CLNT#%d: %s:%d <%-3d %s:%d\n",
				ua->ua_id,clhost,clport,rcc,ihost,iport);
		}
		for( sx = csc+ccc+nsock; sx < csc+ccc+nsock+usocks; sx++ ){
			int ux;
			if( readyv[sx] <= 0 )
				continue;
			ua = udpav[sx];
			ux = getUAx(uassocv,udpav[sx]);
			if( ux < 0 ){
				sv1log("## delUA-CTL(%d)?\n",ux);
				continue;
			}
			sv1log("## detected disconn. by SOCKS CTL [%d]\n",ux);
			delUA(uassocv,ux,"SOCKSCTLreset-SV",1);
			update = 1;
		}
	}
}
int service_udprelay(Connection *Conn)
{
	udp_relay(Conn,FromC);
	return 0;
}

int service_tcprelay(Connection *Conn);
int service_udprelay1(Connection *Conn)
{
	return service_tcprelay(Conn);
}
