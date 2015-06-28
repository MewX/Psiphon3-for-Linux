/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	svport.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	961006	extracted from delegated.c
	961120	moved stuffs about DELEGATE_HOST/PORT from {conf,service}.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "ystring.h"
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */
#include "delegate.h" /* Connection */
#include "fpoll.h"
#include "proc.h"
#include "param.h"

extern int DELEGATE_LISTEN;
#define P_ADMIN	0x40
#define P_SOX	0x80
#define P_YSH	0x20
#define P_OPT	0x0100
#define P_RIDENT	0x0200 /* RIDENT */
#define P_LOCAL		0x0400 /* port on the local host, even with HTMUX=cl */
#define P_REMOTE	0x0800 /* port on the remote host with HTMUX=cl */
#define P_STLS	SVP_STLS /* 0x1000 */
#define P_SSL	SVP_SSL  /* 0x2000 */
#define P_PRIVATE	0x4000 /* not to be inherited on SIGHUP */
#define P_CLOSED	0x8000 /* closed (not to be inherited on SIGHUP) */
#define P_OFF	0x80000000

typedef struct {
	int	 sv_sock;
  const	char	*sv_host;
	int	 sv_port;
	int	 sv_type; /* admin+HTTPS */
	int	 sv_udp;
	int	 sv_tcp; /* ignore DELEGATE_LISTEN (set -1 in UDP protocols) */
	int	 sv_keep; /* keep bound, but don't use to accept */
  const	char	*sv_vsap; /* accepting via VSAP */
	int	 sv_hostA; /* non-wildcard dynamically assigned */
	int	 sv_listen;
} ServerPort;

typedef struct {
	int    pid;
	int    ppid;
	int    time;
} CloseOnTime;

typedef struct {
  const char   *se_serverHostPort;   /* my (maybe pseudo) host:port */
	MStr(	se_serverHostPortV,128);/* serverHostPort set by DELEGATE */
	MStr(	se_serverHost1,128); /* host of primary port */
	int	se_serverPort1;      /* primary port (std I/O by default) */
	int	se_serverPort1Fix;
	ServerPort se_SVPorts[FD_SETSIZE]; /**/
	int	se_SVPortN;
	struct {
		int	port;
		int	sock;
	} se_portsV[128]; /**/
	int	se_portsX;
	int	se_Tio[2];
	CloseOnTime se_cot;
} ServPorts;
static ServPorts *servPorts;
#define serverHostPort	servPorts->se_serverHostPort
#define serverHostPortV	servPorts->se_serverHostPortV
#define serverHost1	servPorts->se_serverHost1
/**/
#define serverPort1	servPorts->se_serverPort1
#define serverPort1Fix	servPorts->se_serverPort1Fix
#define SVPorts		servPorts->se_SVPorts
#define SVPortN		servPorts->se_SVPortN
#define portsV		servPorts->se_portsV
#define portsX		servPorts->se_portsX
#define Tio		servPorts->se_Tio
#define cot		servPorts->se_cot
void minit_ports()
{
	if( servPorts == 0 ){
		servPorts = NewStruct(ServPorts);
		SVPorts[0].sv_sock = -1;
	}
}

#define SvSock(n)	SVPorts[n].sv_sock
#define SvPort(n)	SVPorts[n].sv_port
#define SvType(n)	SVPorts[n].sv_type
#define SvUDP(n)	SVPorts[n].sv_udp
#define SvTCP(n)	SVPorts[n].sv_tcp
#define SvHost(n)	SVPorts[n].sv_host
#define SvHostStr(n)	((SvHost(n) && SvHost(n)[0]) ? SvHost(n) : "")
#define SvKeep(n)	SVPorts[n].sv_keep
#define SvRoute(n)	SVPorts[n].sv_vsap
#define SvRouteStr(n)	(SvRoute(n) == 0 ? "" : SvRoute(n))
#define SvHostA(n)	SVPorts[n].sv_hostA
#define SvListen(n)	SVPorts[n].sv_listen

void sethostnameIF(PCStr(host));
static int scanServPort0(PCStr(host),int port,int type,int sock,PCStr(route))
{	int sx;
	int keep;
	int wasactive;
	int fix; 
	int udp;
	int tcp;

	udp = type & 0x03;
	if( udp == 2 ){
		udp = 0;
		tcp = 1;
	}else	tcp = 0;

	if( fix = host[0] == '-' ){
		/* -P-host:port ... use the port as is for ${PORT} */
		host = host + 1;
	}

	if( port < 0 ){
		port = -port;
		keep = 1;
	}else	keep = 0;

	for( sx = 0; sx < SVPortN; sx++ )
	{
		if( strcmp(SvHostStr(sx),host) == 0 )
		if( SvPort(sx) == port )
		if( SvUDP(sx) == udp )
		if( SvTCP(sx) == tcp )
			break;
	}
	if( sx == SVPortN ){
		if( elnumof(SVPorts) <= SVPortN ){
			return -1;
		}
		SVPortN++;
	}

	/* private-MASTER, exec on SIGHUP, from inetd */
	if( 0 <= sock )
		port = sockPort(sock);

	if( sx == 0 ){
		if( host[0] != 0 )
			sethostnameIF(host);
		if( serverPort1Fix == 0 ){
		if( 0 <= port )
			serverPort1 = port;
		}
		if( fix )
			serverPort1Fix = 1;
	}

	if( SvHost(sx) )
	{
		free((char*)SvHost(sx));
		wasactive = 1;
	}else	wasactive = 0;

	SvHost(sx) = stralloc(host);
	SvPort(sx) = port;
	SvUDP(sx) = udp;
	SvTCP(sx) = tcp;
	if( SvType(sx) & P_OFF ){
		fprintf(stderr,"--OFF [%d] %08X %08X -P%s:%d %s\n",sx,
			SvType(sx),type,host,port,route);
		SvType(sx) |= type;
	}else
	SvType(sx) = type;
	SvKeep(sx) = keep;
	SvRoute(sx) = stralloc(route);

	if( wasactive )
	if( 0 <= SvSock(sx) )
	{
		if( SvSock(sx) == sock ){
			/* 9.5.7 can be with -Fimp -Pxxxx on Win */
		}else
		close(SvSock(sx));
	}
	SvSock(sx) = sock;
	return 0;
}

static scanListFunc scanhostport(PCStr(ports),PCStr(host),int udp,int sock,PCStr(route))
{	int port,port1,port2;

	if( strtailstr(ports,".udp") ){
		udp = 1;
	}
	if( strtailstr(ports,".tcp") ){
		udp = 2; /* v9.9.9 fix-140607b (for service on Windwos) */
	}
	port1 = port2 = 0;
	if( sscanf(ports,"%d-%d",&port1,&port2) == 1 )
		port2 = port1;
	for( port = port1; port <= port2; port++ )
		scanServPort0(host,port,udp,sock,route);
	return 0;
}
extern int AccViaHTMUX;
scanListFunc scanServPort1(PCStr(portspec))
{	int sx;
	CStr(host,128);
	CStr(portname,128);
	CStr(ports,128);
	CStr(mod,128);
	int udp;
	int type = 0;
	int sock;
	CStr(route,128);
	int viasox = 0;
	int stdport = 0;
	IStr(xportspec,1024);
	refQStr(mp,xportspec);
	int itype = 0;

	if( streq(portspec,"-") ){
		serverPort1 = 0;
		return 0;
	}

	portname[0] = 0;
	route[0] = 0;
	host[0] = 0;
	mod[0] = 0;
	ports[0] = 0;
	udp = 0;
	sock = -1;

	if( portspec[0] == ':' )
		portspec++;

	itype = 0;
	if( strchr(portspec,'/') ){
		strcpy(xportspec,portspec);
		portspec = xportspec;
		while( strchr(portspec,'/') ){
			if( mp = strtailstr(portspec,"/rident") ){
				itype |= P_RIDENT;
			}else
			if( mp = strtailstr(portspec,"/private") ){
				itype |= P_PRIVATE;
			}else
			if( mp = strtailstr(portspec,"/local") ){
				itype |= P_LOCAL;
			}else
			if( mp = strtailstr(portspec,"/remote") ){
				itype |= P_REMOTE;
			}else
			if( mp = strtailstr(portspec,"/stls") ){
				itype |= P_STLS;
			}else
			if( mp = strtailstr(portspec,"/ssl") ){
				itype |= P_SSL;
				/* P_SSLOPT for "/-ssl" necessary ? */
			}else{
				break;
			}
			clearVStr(mp);
		}
	}
	Xsscanf(portspec,"%[^@]@%s",AVStr(portname),AVStr(route));
	if( strchr(portname,':') )
		Xsscanf(portname,"%[^:]:%[^/]/%s",AVStr(host),AVStr(ports),AVStr(mod));
	else	Xsscanf(portname,"%[^/]/%s",AVStr(ports),AVStr(mod));

	if( mod[0] ){
		if( strcmp(mod,"admin") == 0 )
			type = 0x40;
		else
		if( strcmp(mod,"sox") == 0 )
			type = P_SOX;
		else
		if( strcmp(mod,"ysh") == 0 )
			type = P_YSH;
		else
		if( strcmp(mod,"udp") == 0 )
			udp = 1;
		else
		if( strcmp(mod,"tcp") == 0 )
			udp = 2;
		else
		if( streq(mod,"off") ){
			type = P_OFF; /* -Qxxxx/off to disable the port */
		}else
		if( stdport = serviceport(mod) ){
		}
		else	sscanf(mod,"%d.%X",&sock,&type); /* sock.type */
		/*
		else	sock = atoi(mod);
		*/
	}

	if( route[0] && strtailstr(route,"/http") ){
		scan_VSAP(NULL,route);
	}else
	if( route[0] ){
		CStr(vsap,256);
		sprintf(vsap,"%s/ACCEPT",route);
		scan_VSAP(NULL,vsap);
	}

	/*
	scan_commaListL(ports,0,scanListCall scanhostport,host,udp,sock,route);
	*/
	type |= itype;
	type |= udp;
	type |= 0xFFFF0000 & (stdport << 16);
	scan_commaListL(ports,0,scanListCall scanhostport,host,type,sock,route);
	return 0;
}

void scanServPort(PCStr(portspecs))
{
	SVPortN = 0;
	scan_commaList(portspecs,0,scanListCall scanServPort1);
}
void scanServPortX(PCStr(portspecs),int init){
	if( init ){
		SVPortN = 0;
	}
	scan_commaList(portspecs,0,scanListCall scanServPort1);
}

int printServPort(PVStr(port),PCStr(prefix),int whole)
{	int sx;
	refQStr(pp,port); /**/
	int nonLocal = 0;
	const char *pb;

	setVStrEnd(port,0);

	cpyQStr(pp,port);
	if( prefix ){
		strcpy(pp,prefix);
		pp += strlen(pp);
	}
	pb = pp;

	if( whole == P_REMOTE ){
		whole = 0;
		nonLocal = 1;
		/*
		 * if there are explicitly marked "/remote" ports,
		 * then use only them for remote ACCEPT.
		 */
		for( sx = 0; sx < SVPortN; sx++ ){
			if( SvType(sx) & P_REMOTE ){
				if( pb < pp )
					setVStrPtrInc(pp,',');
				if( SvHostStr(sx)[0] )
					Rsprintf(pp,"%s:",SvHost(sx));
				else	Rsprintf(pp,"*:");
				Rsprintf(pp,"%d",SvPort(sx));
			}
		}
		if( pb < pp ){
			return 1;
		}
	}
	if( AccViaHTMUX && whole == 0 && nonLocal == 0 ){
		/* find -Qxxx/local shown in the READY banner */
		for( sx = 0; sx < SVPortN; sx++ ){
			if( SvType(sx) & P_LOCAL ){
				if( SvHostStr(sx)[0] )
					Rsprintf(pp,"%s:",SvHost(sx));
				Rsprintf(pp,"%d",SvPort(sx));
				return 1;
			}
		}
	}
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvType(sx) == P_CLOSED ){
			continue;
		}
		if( nonLocal && (SvType(sx) & P_LOCAL) ){
			continue;
		}
		if( pb < pp ){
			setVStrPtrInc(pp,',');
			setVStrEnd(pp,0);
		}

		if( SvHostStr(sx)[0] ){
			sprintf(pp,"%s:",SvHost(sx));
			pp += strlen(pp);
		}

		if( SvKeep(sx) )
			sprintf(pp,"%d",-SvPort(sx));
		else	sprintf(pp,"%d",SvPort(sx));
		pp += strlen(pp);

		if( SvRouteStr(sx)[0] ){
			sprintf(pp,"@%s",SvRoute(sx));
			pp += strlen(pp);
		}

		if( !whole )
			break;

		if( whole < 0 ){ /* for SIGHUP restart on Win32 */
			if( SvType(sx) & 0xFFFF0000 ){
				/* passed to the service process on Win32 */
				sprintf(pp,"/%d.%X",-1,SvType(sx));
				pp += strlen(pp);
				continue;
			}
			if( SvTCP(sx) ){ /* v9.9.9 fix-140607a */
				sprintf(pp,".tcp");
				pp += strlen(pp);
			}
			if( SvUDP(sx) ){ /* v9.9.9 fix-140607a */
				sprintf(pp,".udp");
				pp += strlen(pp);
			}
			if( SvType(sx) & P_ADMIN ){
				sprintf(pp,"/admin");
				pp += strlen(pp);
			}
			if( SvType(sx) & P_YSH ){
				sprintf(pp,"/ysh");
				pp += strlen(pp);
			}
			if( SvType(sx) & P_RIDENT ){
				sprintf(pp,"/rident");
				pp += strlen(pp);
			}
			if( SvType(sx) & P_STLS ){
				sprintf(pp,"/stls");
				pp += strlen(pp);
			}
			if( SvType(sx) & P_SSL ){
				sprintf(pp,"/ssl");
				pp += strlen(pp);
			}
		}
		if( 0 < whole )
		if( 0 <= SvSock(sx) ){
			if( SvType(sx) != 0 ){
				/* sock.type */
				sprintf(pp,"/%d.%X",SvSock(sx),SvType(sx));
			}else
			sprintf(pp,"/%d",SvSock(sx));
			pp += strlen(pp);
		}
	}

	return SVPortN;
}

int numServPorts(){
	return SVPortN;
}

void setServUDP()
{	int sx;

	for( sx = 0; sx < SVPortN; sx++ )
		SvUDP(sx) = 1;
}

int busythreads();
int busysessions();
int askWinOK(PCStr(fmt),...);
void putWinStatus(PCStr(fmt),...);
int VA_gethostVAddr(int cacheonly,PCStr(host),PVStr(primname),VAddr *Vaddr);
const char *VA_inAddr(VAddr *Ia);
int newSocket(PCStr(what),PCStr(opts));
int pingServPorts();
extern int THPAUSE;
int assignServAddr(PCStr(host)){
	int sx;
	int na = 0;
	int ne = 0;
	int sock;
	IStr(addr,128);
	IStr(name,128);
	VAddr Va;
	int wi;
	int nbusy;

	if( *host ){
		if( VA_gethostVAddr(0,host,AVStr(name),&Va) == 0 ){
			return -1;
		}
		strcpy(addr,VA_inAddr(&Va));
	}else{
		bzero(&Va,sizeof(Va));
		strcpy(addr,"");
	}

	THPAUSE = 1;
	/*
	pingServPorts();
	*/
	for( wi = 0; wi < 10; wi++ ){
		nbusy = busysessions();
		if( nbusy == 0 ){
			break;
		}
		putWinStatus("waiting %d active sessions",nbusy);
		sleep(1);
	}
	for( sx = 0; sx < SVPortN; sx++ ){
		if( *SvHostStr(sx) ){
			continue;
		}
		if( host[0] == 0 && SvHostA(sx) == 0 ){
			continue;
		}
		if( host[0] != 0 && SvHostA(sx) == Va.I3 ){
			continue;
		}
		close(SvSock(sx));
		sock = findopen_port("delegate",AVStr(addr),SvPort(sx),
				SvListen(sx));
		if( 0 <= sock ){
			na++;
			SvSock(sx) = sock;
			SvHostA(sx) = Va.I3;
		}else{
			ne++;
		}
	}
	THPAUSE = 0;
	return na;
}

int openLocalServPorts(){
	int sx;
	int nopen = 0;
	int listen;

	for( sx = 0; sx < SVPortN; sx++ ){
		porting_dbg("## (%d) -P%d/%d %X",sx,SvPort(sx),SvSock(sx),
			SvType(sx));
		if( SvType(sx) & P_REMOTE ){
			continue;
		}
		if( 0 <= SvSock(sx) ){
			/* maybe VSAP/HTMUX with RIDENT */
			continue;
		}
		listen = DELEGATE_LISTEN;
		SvSock(sx) = findopen_port("delegate",
			ZVStr((char*)SvHostStr(sx),strlen(SvHostStr(sx))+1),
				SvPort(sx),listen);
	}
	return nopen;
}
extern char funcFimp[];
void openServPorts()
{	int sx;
	CStr(msg,1024);
	int listen;
	int serrno;

	for( sx = 0; sx < SVPortN; sx++ ){
		if( 0 <= SvSock(sx) )
			continue;

		if( SvType(sx) & P_OFF ){
			continue;
		}
		if( SvHostStr(sx)[0] ){
			int fd;
			fd = nextFD();
			IsResolvable(SvHost(sx)); /* enter it to the cache */
			usedFD(fd);
		}

/* check ACTDIR/delegate/pid/PORT and kill if it exist ...
 * by trying fopen "r+" and lock exclusive
 */

		if( SvUDP(sx) )
			listen = -1;
		else
		if( SvTCP(sx) )
			listen = 5; 
		else	listen = DELEGATE_LISTEN;
		SvListen(sx) = listen;

		SvSock(sx) = findopen_port("delegate",
			ZVStr((char*)SvHostStr(sx),strlen(SvHostStr(sx))+1),
				SvPort(sx),listen);
		serrno = errno;

		if( SvSock(sx) < 0 ){
int set_svtrace(int code);
			sprintf(msg,"cannot open server port %s:%d",
				SvHostStr(sx),SvPort(sx));
			ERRMSG("DeleGate: %s\n",msg);
			if( SvType(sx) & P_OPT ){
				continue;
			}
			daemonlog("F","FATAL: %s\n",msg);
			set_svtrace(4);
			if( serrno == EADDRINUSE ){
				ERRMSG("DeleGate: use -r option to restart\n");
			}else
			if( serrno == EACCES ){
				if( geteuid() != 0 ){
int File_is(PCStr(path));
fprintf(stderr,"--------------\n");
fprintf(stderr,"ERROR: Could not open the server port %s:%d\n",
	SvHostStr(sx),SvPort(sx));
fprintf(stderr,"HINT: You can solve it by setting set-uid-on-exec as follows:\n");
fprintf(stderr,"  %% su root -c \"%s %s -m\"\n",
	main_argv[0]?main_argv[0]:EXEC_PATH,funcFimp);
fprintf(stderr,"--------------\n");
				}
			}
			Exit(-1,"DeleGate: %s\n",msg);
		}
	}
}

int closePrivatePorts(){
	int sx;
	int nc = 0;

	for( sx = 0; sx < SVPortN; sx++ ){
		if( (SvType(sx) & P_PRIVATE) == 0 ){
			continue;
		}
		close(SvSock(sx));
		SvSock(sx) = -1;
		SvPort(sx) = 0;
		SvType(sx) = P_CLOSED;
		if( SvHost(sx) ){
			((char*)SvHost(sx))[0] = 0;
		}
		nc++;
	}
	return nc;
}
int closeServPortsX(int clear);
void closeServPorts()
{
	closeServPortsX(1);
}
int closeServPortsX(int clear)
{	int sx;

	for( sx = 0; sx < SVPortN; sx++ ){
		close(SvSock(sx));
		SvSock(sx) = -1;
		if( !clear ){
			continue;
		}
		SvPort(sx) = 0;
		if( SvHost(sx) ){
			((char*)SvHost(sx))[0] = 0;
		}
	}
	if( !clear ){
		return sx;
	}
	SVPortN = 0;
	return sx;
}
int dupclosed_FL(FL_PAR,int fd);
int askWinOK(PCStr(fmt),...);
int dupclosedServPorts(){
	int sx;
	IStr(buf,256);
	refQStr(bp,buf);

	if( 0 ){
		for( sx = 0; sx < SVPortN; sx++ ){
			Rsprintf(bp,"%d/%d ",SvPort(sx),SvSock(sx));
		}
		askWinOK("dupclosed: %s",buf);
	}
	for( sx = 0; sx < SVPortN; sx++ ){
		if( 0 <= SvSock(sx) ){
			dupclosed_FL(FL_ARG,SvSock(sx));
			SvSock(sx) = -1;
		}
	}
	return sx;
}
int pingServPorts(){
	int sx;
	int port;
	int clsock;
	int sn = 0;
	double Start = Time();

	for( sx = 0; sx < SVPortN; sx++ ){
		if( 0 <= SvSock(sx) ){
			port = SvPort(sx);
			clsock = Socket1("ping",-1,NULL,NULL,NULL,
					VStrNULL,0,NULL,0,0,NULL,0);
			if( *SvHostStr(sx) ){
			 if( connectTimeout(clsock,SvHost(sx),port,1) == 0 ){
				sn++;
			 }
			}else
			if( SvHostA(sx) ){
			 VAddr Va;
			 const char *addr;
			 bzero(&Va,sizeof(Va));
			 Va.I3 = SvHostA(sx);
			 addr = VA_inAddr(&Va);
			 putWinStatus("pingServPort[%d] %s:%d",sx,addr,port);
			 if( connectTimeout(clsock,addr,port,1) == 0 ){
				sn++;
			 }
			 if( 3 < Time()-Start ){
				break;
			 }
			}else
			if( connectTimeout(clsock,"127.0.0.1",port,1) == 0 ){
				sn++;
			}
			close(clsock);
		}
	}
	return sn;
}

void closeOnExecServPorts(int set){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( set ){
			setCloseOnExecSocket(SvSock(sx));
		}else{
			clearCloseOnExecSocket(SvSock(sx));
		}
	}
}

void makeEntrance(){
	/*
	if( serverPort1 ){
	*/
	if( 0 < SVPortN ){
		openServPorts();
	}else{
		Socketpair(Tio); /* dummy */
		SvSock(0) = Tio[0];
		SVPortN = 1;
		sv1log("TeleportTunnel[%d]\n",SvSock(0));
	}
}

int getServPorts(int sc,int sv[])
{	int sx,sn;

	sn = 0;
	for( sx = 0; sx < sc && sx < SVPortN; sx++ ){
		sv[sn] = SvSock(sx);
		sn++;
	}
	return sn;
}
int pollServPortX(int timeout,int *rsockv,int *udpv,int *optv,int *typev);
int pollServPort(int timeout,int *rsockv,int *udpv,int *optv)
{
	return pollServPortX(timeout,rsockv,udpv,optv,0);
}
int pollServPortX(int timeout,int *rsockv,int *udpv,int *optv,int *typev)
{	int sx,sxa,rsx;
	int ssockv[FD_SETSIZE],readyv[FD_SETSIZE],nready;
	int sxv[FD_SETSIZE];
	int osx;
	int sock;

	sxa = 0;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvSock(sx) < 0 ){
			/* maybe accepting via VSAP / HTMUX */
		}else
		if( !SvKeep(sx) ){
			sxv[sxa] = sx;
			ssockv[sxa] = SvSock(sx);
			readyv[sxa] = 0;
			sxa++;
		}
	}
	if( optv ){
		for( sx = 0; 0 <= optv[sx]; sx++ ){
			sxv[sxa] = -1;
			ssockv[sxa] = optv[sx];
			readyv[sxa] = 0;
			sxa++;
		}
	}

	if( sxa == 0 ){
		/* maybe closed by CloseOnTimeout */
		sv1log("## pollServPort(%d)/%d NO ServPort TO POLL\n",
			timeout,SVPortN);
		return -2;
	}
	nready = PollIns(timeout,sxa,ssockv,readyv);
	if( nready <= 0 )
		return nready;

	rsx = 0;
	for( sx = 0; sx < sxa; sx++ ){
		if( 0 < readyv[sx] ){
			rsockv[rsx] = ssockv[sx];
			osx = sxv[sx];
			if( 0 <= osx ){
				udpv[rsx] = SvUDP(osx);
				if( typev ) typev[rsx] = SvType(osx);
			}else{
				/* a socket to receive Sticky activity */
				udpv[rsx] = 0;
				if( typev ) typev[rsx] = 0;
			}
			rsx++;
		}
	}
	return nready;
}
int SvSock_withRIDENT(int stype){
	return stype & P_RIDENT;
}

void inetdServPort()
{	int sock,port,osock,oport;

	sock = dup(0);
	setsockREUSE(sock,1);
	port = sockPort(sock);
	oport = SvPort(0);
	osock = SvSock(0);
	svlog("fromInetd/SVsock: %d/%d <= %d/%d\n",port,sock,oport,osock);
	setsid();

	if( oport != port || osock < 0 ){
		LOG_deletePortFile();
		LOG_closeall();
		closeServPorts();
		scanServPort0("",port,isUDPsock(sock),sock,"");
	}
	else	close(sock);
}

static int isNotServPort(PCStr(host),int port)
{	int sx;

	if( SVPortN == 0 ){
		/* can be cleared by with -x or in OnetimeServer or ...
		 * thus cannot determine by -PportList
		 */
		return 0;
	}
	for( sx = 0; sx < SVPortN; sx++ )
	{
		if( SvPort(sx) == port ){
			/* wildcard as 0.0.0.0 or :: must be ignored */
			if( *SvHostStr(sx) ){
				if( hostcmp_incache(SvHost(sx),host) != 0 ){
					continue;
				}
			}
			if( SvKeep(sx) )
				return 1;
			else	return 0;
		}
	}

	return 1;
}

int ServSockOf(PCStr(host),int port)
{	int sx;

	for( sx = 0; sx < SVPortN; sx++ )
		if( SvPort(sx) == port )
			return SvSock(sx);
	return -1;
}

int activeServPort()
{	int nactive,sx;

	nactive = 0;
	for( sx = 0; sx < SVPortN; sx++ )
		if( 0 <= SvSock(sx) )
			if( !SvKeep(sx) )
				nactive++;
	return nactive;
}

int addServPort1(int sock,int port,int priv,int rident){
	IStr(portspec,128);

	sprintf(portspec,"%d/%d",port,sock);
	if( priv ){
		strcat(portspec,"/private");
	}
	if( rident ){
		strcat(portspec,"/rident");
	}
	scanServPort1(portspec);
	sv1log("---###addServPort1()###[%s]\n",portspec);
	return 0;
}
int ServSock()
{
	if( SvSock(0) == -1 )
	if( SvPort(1) && 0 <= SvSock(1) ){
		if( AccViaHTMUX ){
			/* it is natural in VSAP or HTMUX client */
			/* also it might be disabled with -Qxxxx/off */
		}else
		sv1log("---###ServSock()### 0[%d] 1[%d][%d]\n",
			SvSock(0),SvPort(1),SvSock(1));
		return SvSock(1);
	}
	return SvSock(0);
}
int FL_ServSockX(Connection *Conn,FL_PAR){
	if( Conn != 0 && 0 <= AcceptSock ){
		return AcceptSock;
	}else{
		return ServSock();
	}
}

int isServSock(int sock)
{	int sx;

	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvSock(sx) == sock )
			return 1;
	}
	return 0;
}

int portOfSock(int sock){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvSock(sx) == sock )
			return SvPort(sx);
	}
	return 0;
}
int protoOfSock(int sock){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvSock(sx) == sock )
		if( SvType(sx) & 0xFFFF0000 )
			return 0xFFFF & (SvType(sx) >> 16);
	}
	return 0;
}
int withAdminPort(const char **host,int *port){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvType(sx) & P_ADMIN ){
			if( host ) *host = SvHostStr(sx);
			if( port ) *port = SvPort(sx);
			return SvSock(sx);
		}
	}
	return -1;
}
/* 9.9.0 to attach/detach -Qyyy/remote for HTMUX=cl:host:port
 * without affecting exisiting config. by original -Pxxx/admin,
 * the /admin modifier should be SSL-optional if there is HTMUX=cl.
 */
int optionalAdminPortSSL(int port){
	int sx;
	const char *htmux;
	IStr(opts,128);
	int htmuxcl = 0;

	if( htmux = DELEGATE_getEnv(P_HTMUX) ){
		wordScanY(htmux,opts,"^:");
		htmuxcl = isinList(opts,"cl");
	}
	for( sx = 0; sx < SVPortN; sx++ ){
		if( port != SvPort(sx) ){
			continue;
		}
		if( SvType(sx) & P_ADMIN ){
			if( htmuxcl ){
				sv1log("## optAdmin %d [%s] %X\n",
					port,htmux,htmuxcl);
				return 1;
			}
		}
	}
	return 0;
}
int getConsolePort(const char **host,int *port){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvType(sx) & P_YSH ){
			if( host ) *host = SvHostStr(sx);
			if( port ) *port = SvPort(sx);
			return SvSock(sx);
		}
	}
	return -1;
}
int getUserPort1(const char **host,int *port){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( (SvType(sx) & P_YSH) == 0 )
		if( (SvType(sx) & P_ADMIN) == 0 ){
			if( host ) *host = SvHostStr(sx);
			if( port ) *port = SvPort(sx);
			return SvSock(sx);
		}
	}
	/* there is no user-only port */
	return withAdminPort(host,port);
}

/*
 *	close a file descriptor (parallel server's socket for accept)
 *	(1) on specified timeout
 *	(2) after fork
 *	(3) after the death of the parent
 */
void setCloseOnTimeout(int timeout)
{
	if( lSINGLEP() ){ /* single process */
		fprintf(stderr,"----Don't set ClosedOnTimeout(%d)\n",timeout);
		return;
	}
	if( lFXNUMSERV() ){
		sv1log("----Don't set ClosedOnTimeout(%d)\n",timeout);
		return;
	}
	cot.time = time(0) + timeout;
	cot.ppid = getppid();
	cot.pid = getpid();
}
static int _checkCloseOnTimeout(int checktime)
{
	if( cot.time == 0 )
		return 1;

	if( getpid() == cot.pid )
	if( getppid() == cot.ppid )
	if( checktime && time(0) < cot.time )
		return 0;

	closeServPorts();
	sv1log("ClosedOnTimeout(%d): time=%d/%d ppid=%d/%d pid=%d/%d\n",
		checktime,
		itime(0),cot.time,
		getppid(),cot.ppid,
		getpid(),cot.pid);

	bzero(&cot,sizeof(cot));
	return 1;
}
int (*CheckClosed)(int) = _checkCloseOnTimeout;


/*
 *
 */
int addrIsWildcard(PCStr(host));
void sethostnameIF(PCStr(host))
{
	if( addrIsWildcard(host) ){
		syslog_ERROR("[%s] is not set as interface addr.\n",host);
		return;
	}
	strcpy(serverHost1,host);

	if( serverHostPort != NULL )
if( serverHostPort != serverHostPortV )
		free((char*)serverHostPort);
	serverHostPort = stralloc(host);
	/* this seems a bug because of just hostname to "serverHostPort" ...*/
}
int gethostnameIFIF(PVStr(host),int size)
{
	if( serverHost1[0] ){
		strncpy(host,serverHost1,size);
		return 0;
	}
	setVStrEnd(host,0);
	return -1;
}
void gethostnameIF(PVStr(host),int size)
{
	if( gethostnameIFIF(AVStr(host),size) == 0 )
		return;
	GetHostname(AVStr(host),size);
}
void Myhostport(PVStr(myhp),int size)
{
	gethostnameIF(AVStr(myhp),size);
	Xsprintf(TVStr(myhp),":%d",serverPort1);
}

int use_numaddress(Connection *Conn);
int CTX_myhostport(Connection *Conn,PVStr(myhost),int size)
{	const char *delegate;
	int myport;
	const char *addr;

	myport = serverPort1;
	if( delegate = serverHostPort )
		Xsscanf(delegate,"%[^:]:%d",AVStr(myhost),&myport);
	else	gethostnameIF(AVStr(myhost),size);

	if( delegate == 0 || use_numaddress(Conn) ){
		if( addr = gethostaddr(myhost) )
			strcpy(myhost,addr);
	}
	return myport;
}

int forcedIF_HX(Connection *Conn,PCStr(vhostport),PVStr(host))
{	int port;

	if( vhostport && Conn->my_vbase.u_pri == 0 ){
		port = scan_hostport(CLNT_PROTO,vhostport,AVStr(host));
		return port;
	}

	if( Conn->my_vbase.u_host ){
		strcpy(host,Conn->my_vbase.u_host);
		return Conn->my_vbase.u_port;
	}
	if( serverHostPort == serverHostPortV ){
		port = serverPort1;
		Xsscanf(serverHostPort,"%[^:]:%d",AVStr(host),&port);
		return port;
	}
	return 0;
}
int forcedIF_HPX(Connection *Conn,PCStr(vhostport),PVStr(hostport))
{
	if( vhostport && Conn->my_vbase.u_pri == 0 ){
		strcpy(hostport,vhostport);
		return 1;
	}

	if( Conn->my_vbase.u_host ){
		/*
		sprintf(hostport,"%s:%d",
			Conn->my_vbase.u_host,Conn->my_vbase.u_port);
		*/
		strcpy(hostport,Conn->my_vbase.u_hostport);
		return 1;
	}
	if( serverHostPort == serverHostPortV ){
		strcpy(hostport,serverHostPort);
		return 1;
	}
	return 0;
}

int VA_HostPortIFclnt(Connection *Conn,int clsock,PVStr(name),PVStr(addr),VAddr *Vaddr)
{	CStr(addrb,64);

	if( !AddrEQ(Conn->cl_sockHOST,AddrZero) )
		goto EXIT;

	VA_gethostNAME(clsock,&Conn->cl_sockHOST);
	VA_inetNtoah(&Conn->cl_sockHOST,AVStr(addrb));

	Verbose("-- SockHost: [%s] %s:%d\n",
		addrb, Conn->cl_sockHOST.a_name,
		Conn->cl_sockHOST.a_port);

EXIT:
	if( name ) strcpy(name,Conn->cl_sockHOST.a_name);
	if( addr ) VA_inetNtoah(&Conn->cl_sockHOST,AVStr(addr));
	if( Vaddr ) *Vaddr = Conn->cl_sockHOST;
	return Conn->cl_sockHOST.a_port;
}

static int _clientIF(Connection *Conn,PVStr(hostport),xPVStr(host),int clsock,int byaddr)
{	CStr(hostb,MaxHostNameLen);
	CStr(addr,256);
	int port;

	if( host == NULL )
		setPStr(host,hostb,sizeof(hostb));

	if( serverHostPort )
	{
		port = CTX_myhostport(Conn,AVStr(host),sizeof(hostb));
	}
	else{
		/* this code uses "host" as a buffer in the case of "byaddr".
		 * it's not good, especially when the host[] is of small size
		 * just for receive an address ...
		 */
		/* fix-130723a
		port = VA_HostPortIFclnt(Conn,clsock,AVStr(host),AVStr(addr),NULL);
		 */
		IStr(hostbuff,MaxHostNameLen);
		port = VA_HostPortIFclnt(Conn,clsock,AVStr(hostbuff),AVStr(addr),NULL);
		if( byaddr && addr[0] != 0 )
			Xstrcpy(SVStr(host,hostb) host,addr);
		else	Xstrcpy(SVStr(host,hostb) host,hostbuff);
	}
{
	const char *hp;
	if( hp = strchr(host,'%') ){
		/* it is unnecssary to be shown to peer (client), but
		 * it might be necessary in some case.
		 */
		syslog_ERROR("[%s] scope-id ignored\n",host);
		truncVStr(hp);
	}
}
	if( hostport != NULL )
		sprintf(hostport,"%s:%d",host,port);

	return port;
}
int ClientIF_addr(Connection *Conn,int clsock,PVStr(addr))
{
	return _clientIF(Conn,VStrNULL,AVStr(addr),clsock,1);
}
int ClientIF_name(Connection *Conn,int clsock,PVStr(name))
{
	return _clientIF(Conn,VStrNULL,AVStr(name),clsock,0);
}
int ClientIF_HPname(Connection *Conn,PVStr(hostport))
{
	return _clientIF(Conn,AVStr(hostport),VStrNULL,ClientSock,0);
}
int ClientIF_HP(Connection *Conn,PVStr(hostport))
{
	return _clientIF(Conn,AVStr(hostport),VStrNULL,ClientSock,1);
}
int ClientIF_H(Connection *Conn,PVStr(host))
{
	return _clientIF(Conn,VStrNULL,AVStr(host),ClientSock,1);
}
int ClientIF_Hname(Connection *Conn,PVStr(host))
{
	return _clientIF(Conn,VStrNULL,AVStr(host),ClientSock,0);
}

void ServerIF_name(Connection *Conn,PVStr(host))
{
	if( 0 < ToS )
		gethostNAME(ToS,AVStr(host));
	else	gethostname((char*)host,MaxHostNameLen);
}

static int isme(PCStr(myhost),int myport,PCStr(rhost),int rport)
{	int myhosti,rhosti;

	if( rport != myport )
		return 0;

	if( strcasecmp(myhost,rhost) == 0 )
		return 1;

	myhosti = gethostintMin(myhost);
	rhosti = gethostintMin(rhost);

	if( myhosti == -1 || rhosti == -1 )
		return 0; /* maybe safer (resolver seems wrong) */

	if( myhosti == rhosti )
		return 1;

	if( rhosti == 0 ){
		daemonlog("F","INADDR_ANY ? isme(%s)\n",rhost);
		return 1;
	}
	if( serverHost1[0] != 0 ) /* if interface host is limited */
		return 0;
		/* multiple entrance ports should be cared ... */

	return IsMyself(rhost);
}

int IsmyselfX(Connection *Conn,PCStr(rproto),PCStr(rhost),int rport);
static struct {
	MStr(c_proto,32);
	MStr(c_name,MaxHostNameLen);
	int c_port;
	int c_isme;
} IsmeCache;
int Ismyself(Connection *Conn,PCStr(rproto),PCStr(rhost),int rport)
{	int yes;

	if( IsmeCache.c_port == rport
	 && strcaseeq(IsmeCache.c_proto,rproto)
	 && strcaseeq(IsmeCache.c_name,rhost) ){
		goto EXIT;
	}
	yes = IsmyselfX(Conn,rproto,rhost,rport);
	strcpy(IsmeCache.c_proto,rproto);
	strcpy(IsmeCache.c_name,rhost);
	IsmeCache.c_port = rport;
	IsmeCache.c_isme = yes;
EXIT:
	return IsmeCache.c_isme;
}
int IsmyselfX(Connection *Conn,PCStr(rproto),PCStr(rhost),int rport)
{	CStr(myhost,MaxHostNameLen);
	int myport;

	/* Local path cannot be the procol between client / DeleGate ...
	 * (this was temporary patch to avoid being treated as a internal
	 *  URL at httpd.c:HttpToMyself() ...
	 */
	if( localPathProto(rproto) )
		return 0;

	if( isMYSELF(rhost) )
		return 1;

	/* 9.0.0
	 * the interface at which current connection is accepted is me.
	 * this is very likely to be true when acting as an origin server.
	 */
	if( CLIF_PORT == rport && hostcmp(CLIF_HOST,rhost) == 0 ){
		return 1;
	}

	/*
	 * "sock.dir.af-local" for AF_UNIX "/dir/sock" with port number 0xFFFF
	 *  means that port number must not be cared
	 */
	if( strtailstr(rhost,VSA_hostlocal()) ){
		myport = VA_HostPortIFclnt(Conn,ClientSock,AVStr(myhost),VStrNULL,NULL);
		if( myport == 0xFFFF ){
			return isme(myhost,0,rhost,0);
		}
	}

	/*
	 * A virtual address can be given by DELEGATE parameter and is set
	 * to serverHostPort.  The address can be one of followings:
	 *   1. (one of) physical address of myself
	 *   2. (one of) physical address of another server's host:port
	 *   3. pseudo address bound to myself
	 */
	if( serverHostPort != NULL ){
		myport = CTX_myhostport(Conn,AVStr(myhost),sizeof(myhost));
		if( isme(myhost,myport,rhost,rport) )
			return 1;
	}

	/*
	 * In physicall address matching, the server port of the
	 * delegated is one of real ports specified in -Pp1,p2,...
	 */
	if( isNotServPort(rhost,rport) )
		return 0;
	myport = VA_HostPortIFclnt(Conn,ClientSock,AVStr(myhost),VStrNULL,NULL);
	return isme(myhost,myport,rhost,rport);
}

void scan_CALLBACK(PCStr(protolist));
void scan_DELEGATE(Connection *Conn,PCStr(dhps))
{	CStr(hostport,1024);
	CStr(host,1024);
	int port;
	CStr(proto,1024);
	CStr(dst,1024);
	CStr(src,1024);
	int ni;

	if( dhps == NULL )
		return;

	host[0] = 0;
	port = 0;
	proto[0] = dst[0] = src[0] = 0;
	ni = Xsscanf(dhps,"%[^:]:%d:%[^:]:%[^:]:%s",AVStr(host),&port,AVStr(proto),AVStr(dst),AVStr(src));

	if( isMYSELF(host) && Conn != NULL )
		gethostAddr(ClientSock,AVStr(host));
	if( port == 0 )
		port = serverPort1;
	if( proto[0] )
		scan_CALLBACK(proto);

	sprintf(hostport,"%s:%d",host,port);
	/*
	dhps = stralloc(hostport);
	*/
	wordscanX(hostport,AVStr(serverHostPortV),sizeof(serverHostPortV));
	dhps = serverHostPortV;
	xmem_push((void*)&serverHostPort,sizeof(serverHostPort),"DELEGATE",NULL);
	serverHostPort = dhps;
}

static int nonRemotePort1(){
	int sx;
	for( sx = 0; sx < SVPortN; sx++ ){
		if( (SvType(sx) & P_LOCAL) != 0 ){
			return sx;
		}
	}
	for( sx = 0; sx < SVPortN; sx++ ){
		if( (SvType(sx) & P_REMOTE) == 0 ){
			return sx;
		}
	}
	return -1;
}
void printPrimaryPort(PVStr(port))
{
	int sn;
	if( 0 <= (sn = nonRemotePort1()) ){
		refQStr(pp,port);
		if( SvHostStr(sn)[0] )
			Rsprintf(pp,"%s:",SvHost(sn));
		sprintf(pp,"%d",SvPort(sn));
		return;
	}

	if( serverHost1[0] )
		sprintf(port,"%s:%d",serverHost1,serverPort1);
	else	sprintf(port,"%d",serverPort1);
}

int connectToMyself(PCStr(what))
{	int sock;

	if( serverHost1[0] )
		sock = client_open(what,"delegate",serverHost1,serverPort1);
	else	sock = client_open(what,"delegate","localhost",serverPort1);
	return sock;
}

int SERVER_PORT()
{
	return serverPort1;
}
void setSERVER_PORT(PCStr(host),int port,int sock)
{
	if( 0 <= sock )
		scanServPort0(host,port,isUDPsock(sock),sock,"");
	else	scanServPort0(host,port,0,-1,"");
}
void setSERVER_PORTX(PCStr(host),int port,int sock,int stype){
	IStr(route,128);
	int itype;

	if( 0 <= sock ){
		itype = isUDPsock(sock);
		itype |= stype & (P_RIDENT);
		scanServPort0(host,port,itype,sock,route);
	}else{
		scanServPort0(host,port,0,-1,route);
	}
}



/* strip -Pxxx/nnn,yyy/mmm to -Pxxx,yyy */
int stripPortAttrs(PCStr(a1),PVStr(ports)){
	refQStr(pp,ports);
	const char *ap;
	char ac;
	int stripped = 0;

	for( ap = a1; ac = *ap; ap++ ){
		if( ac == '/' ){
			while( ap[1] && ap[1] != ',' )
				ap++;
			stripped++;
			continue;
		}
		setVStrPtrInc(pp,ac);
	}
	setVStrEnd(pp,0);
	return stripped;
}
static scanListFunc scanports(PCStr(hostport))
{	CStr(host,MaxHostNameLen);
	int port1,port2,port;
	int sock;
	int pi;
	const char *dp;
	CStr(mod,32);
	int nlisten;

	host[0] = 0;
	port1 = 0;
	port2 = 0;

	mod[0] = 0;
	if( dp = strchr(hostport,'/') )
		wordScan(dp+1,mod);
	if( dp = strchr(hostport,':') )
		dp = strchr(dp,'.');
	else	dp = strchr(hostport,'.');
	if( dp != NULL )
		wordScan(dp+1,mod);
	nlisten = DELEGATE_LISTEN;
	if( streq(mod,"udp") )
		nlisten = -1;

	if( strchr(hostport,':') )
		Xsscanf(hostport,"%[^:]:%d-%d",AVStr(host),&port1,&port2);
	else	sscanf(hostport,"%d-%d",&port1,&port2);
	if( port2 == 0 )
		port2 = port1;

	for( port = port1; port <= port2; port++ ){
		sock = findopen_port("reservePORT",AVStr(host),port,nlisten);
		if( sock < 0 ){
			fprintf(stderr,"CANNOT BIND PORT %d\r\n",port);
			exit(1);
		}
		if( elnumof(portsV) <= portsX ){
			return -1;
		}
		portsV[portsX].port = port;
		portsV[portsX].sock = sock;
		portsX++;
	}
	return 0;
}
void scan_PORT(Connection *Conn,PCStr(ports))
{
	scan_commaList(ports,0,scanListCall scanports);
}
int getReservedPorts(int pv[],int sv[])
{	int sx;

	for( sx = 0; sx < portsX; sx++ ){
		pv[sx] = portsV[sx].port;
		sv[sx] = portsV[sx].sock;
	}
	return sx;
}
void sendReservedPorts()
{	int sx,si;

	si = 0;
	for( sx = 0; sx < portsX; sx++ ){
		if( portsV[sx].port ){
			setrsvdsock(si++,portsV[sx].sock);
		}
	}
}
int ReservedPortSock(PCStr(host),int port)
{	int sx;

	for( sx = 0; sx < portsX; sx++ )
		if( portsV[sx].port == port )
			return portsV[sx].sock;
	return -1;
}
int closeNonReservedPortSock(int sock)
{	int sx;

	for( sx = 0; sx < portsX; sx++ )
		if( portsV[sx].sock == sock )
			return 0;
	close(sock);
	return 0;
}
void closeReservedPorts()
{	int sx;
	int rcode;

	for( sx = 0; sx < portsX; sx++ ){
		if( portsV[sx].port ){
			rcode =
			close(portsV[sx].sock);
			putfLog("closing PORT=%d (%d)",portsV[sx].port,rcode);
			portsV[sx].port = 0;
			portsV[sx].sock = 0;
		}
	}
	portsX = 0;
}

int strCRC32(PCStr(str),int len);
int myCRC32Salt();
int Gmtoff();
int enBase32(PCStr(src),int slen,PVStr(dst),int dsiz);
int revbits(int ii){
	int i;
	int oi;
	oi = 0;
	for( i = 0; i < 8*sizeof(ii); i++ ){
		if( ii < 0 )
			oi |= (1 << i);
		ii <<= 1;
	}
	return oi;
}
int creyInt32(int val,int dec);
int deBase32(PCStr(src),int slen,PVStr(dst),int dsiz);
void getClientAddrId(Connection *Conn,PVStr(saddr),PVStr(sid));
int deClientId(PCStr(xid),FILE *dbg,PCStr(fmt),PVStr(sdate),PVStr(saddr)){
	CStr(id,32);
	int crc,xcrc;
	const unsigned char *u = (const unsigned char*)id;
	int bi;
	unsigned int i4,d4;
	int clock,day,min,tc;
	CStr(sa,128);
	int err = 0;

	deBase32(xid,strlen(xid),AVStr(id),sizeof(id));
	crc = (id[4] >> 5) & 0x7;
	id[4] &= 0x1F;
	xcrc = creyInt32(strCRC32(id,8),0) & 0x7;
	if( crc != xcrc )
		err = -1;
	if( dbg ){
		fprintf(dbg,"-- %s: CRC %x / %x\n",
			crc==xcrc?"OK":"ERROR",crc,xcrc);
		fprintf(dbg,"-- ");
		for( bi = 0; bi < 8; bi++ )
			fprintf(dbg,"%02X ",u[bi]);
		fprintf(dbg,"\n");
	}
	i4 = u[0]<<24 | u[1]<<16 | u[2]<<8 | u[3];
	d4 = creyInt32(i4,1);

	clock = u[4]<<20 | u[5]<<12 | u[6]<<4 | u[7]>>4;
	clock = revbits(clock << 7);
	day = clock >> 10;
	min = (clock & 0x3FF) * 2;
	tc = day*(24*60*60) + min*60 - Gmtoff();
	if( fmt == NULL )
		fmt = "%Y/%m/%d-%H:%M";
	StrftimeLocal(AVStr(sdate),64,fmt,tc,0);
	sprintf(saddr,"%d.%d.%d.%d",d4>>24,0xFF&(d4>>16),0xFF&(d4>>8),0xFF&d4);
	return err;
}
int makeEmailFP(PVStr(ocrc),PCStr(addr));
int printClientAddrId(int ac,const char *av[]){
	CStr(sdate,128);
	CStr(saddr,128);
	CStr(shost,128);

	if( ac < 2 ){
		return 0;
	}
	if( 2 < ac && streq(av[1],"-m") ){
		makeEmailFP(AVStr(saddr),av[2]);
		printf("%s\n",saddr);
		return 0;
	}
	if( 2 < ac && streq(av[1],"-e") ){
		CStr(saddr,128);
		CStr(sid,128);
		Connection ConnBuf,*Conn = &ConnBuf;
		bzero(Conn,sizeof(Connection));
		VA_strtoVAddr(av[2],Client_VAddr);
		getClientAddrId(Conn,AVStr(saddr),AVStr(sid));
		printf("%s\n",sid);
		return 0;
	}
	deClientId(av[1],stderr,NULL,AVStr(sdate),AVStr(saddr));
	gethostbyAddr(saddr,AVStr(shost));
	printf("%s %s %s\n",sdate,saddr,shost);
	return 0;
}
void getClientAddrId(Connection *Conn,PVStr(saddr),PVStr(sid)){
	VAddr vab;
	VAddr *vap;
	const unsigned char *ua;
	CStr(cla,4);
	int cra;
	int now;
	int clock;
	CStr(bcl,16);
	CStr(scl,16);
	int crc;

	if( TeleportAddr[0] ){
		VA_strtoVAddr(TeleportAddr,&vab);
		vap = &vab;
	}else{
		vap = Client_VAddr;
	}

	setVStrElem(cla,0,0xFF&(vap->I3>>24));
	setVStrElem(cla,1,0xFF&(vap->I3>>16));
	setVStrElem(cla,2,0xFF&(vap->I3>>8));
	setVStrElem(cla,3,0xFF&(vap->I3));
	ua = (const unsigned char*)cla;
	Xsprintf(BVStr(saddr),"%d.%d.%d.%d",ua[0],ua[1],ua[2],ua[3]);

	cra = creyInt32(vap->I3,0);
	setVStrElem(bcl,0,0xFF&(cra>>24));
	setVStrElem(bcl,1,0xFF&(cra>>16));
	setVStrElem(bcl,2,0xFF&(cra>>8));
	setVStrElem(bcl,3,0xFF&(cra>>0));

	/* 60 - 35(32+3) = 25 bits for time clock */
	now = time(0) + Gmtoff();
	/* 15bits for day, 10bits for every 60 seconds */
	clock = (now/(24*60*60))<<10 | 0x3FF & ((now % (24*60*60))/120);
	clock = revbits(clock) >> 7;
/*
fprintf(stderr,"--- %d day, %d min, revclock=%X %X\n",
now/(24*60*60),((now%(24*60*60))/120)*2,
clock,revbits(clock));
*/
	setVStrElem(bcl,4,0x1F&(clock >> 20)); /* 5bits (24-20) */
	setVStrElem(bcl,5,0xFF&(clock >> 12)); /* 8bits (19-12) */
	setVStrElem(bcl,6,0xFF&(clock >>  4)); /* 8bits (11- 4) */
	setVStrElem(bcl,7,0xF0&(clock <<  4)); /* 4bits ( 3- 0) */

	crc = creyInt32(strCRC32(bcl,8),0);
	setVStrElem(bcl,4,bcl[4] | (0x7 & crc) << 5);
/*
for(int i = 0; i < 8; i++) fprintf(stderr,"%02X ",0xFF&bcl[i]);
fprintf(stderr,"\n");
*/

	enBase32(bcl,7*8+4,AVStr(scl),sizeof(scl));
	strtolower(scl,scl);
	Xstrcpy(BVStr(sid),scl);
}
const char *getClientRident(Connection *Conn,PVStr(clntb)){
	const char *clnt;
	if( TeleportHost[0] ){
		if( VSA_strisaddr(TeleportHost) )
			sprintf(clntb,"%s._.%s",TeleportHost,Client_Host);
		else	sprintf(clntb,"%s._.%s",Client_Host,TeleportHost);
		clnt = clntb;
	}else	clnt = Client_Host;
	return clnt;
}

/*
 * SERVER=url:-:-Pport
 */
int getServStat(PCStr(proto),int *act){
	int sx;
	int stdport = serviceport(proto);
	int iport;

	for( sx = 0; sx < SVPortN; sx++ ){
		if( streq(proto,"/admin") ){
			if( SvType(sx) & P_ADMIN ){
				if( act ) *act = (0 <= SvSock(sx));
				return SvPort(sx);
			}
			continue;
		}
		iport = 0xFFFF & (SvType(sx) >> 16);
		if( iport == stdport ){
			if( act ) *act = (0 <= SvSock(sx));
			return SvPort(sx);
		}
	}
	if( act ) *act = 0;
	return 0;
}
int addServPort(PCStr(portspec),PCStr(servspec),Connection *Conn){
	IStr(proto,64);
	IStr(dsite,64);
	IStr(dports,64);
	IStr(ssite,64);
	IStr(sports,64);
	IStr(route,64);
	int type = 0;
	int sock = -1;
	int stdport;

	scan_protositeport(servspec,AVStr(proto),AVStr(dsite),AVStr(dports));
	stdport = serviceport(proto);
	type |= 0xFFFF0000 & (stdport << 16);
	type |= P_OPT;
	if( streq(proto,"ysh") || streq(proto,"console") ){
		type |= P_YSH;
	}
	if( strneq(portspec,"-P",2) ){
		if( strchr(portspec,':') ){
			Xsscanf(portspec+2,"%[^:]:%s",
				AVStr(ssite),AVStr(sports));
		}else{
			strcpy(sports,portspec+2);
		}
	}
	if( sports[0] == 0 ){
		sprintf(sports,"%d",stdport);
	}
	scanhostport(sports,ssite,type,sock,route);
	return 0;
}
int addServPorts(PCStr(ports),PCStr(serv),Connection *Conn){
	scan_commaListL(ports,0,scanListCall addServPort,serv,Conn);
	return 0;
}

/*
 * ENTR=proto://host:port/path
 * ENTR=proto://h1,h2:p1,p2-p3/path
 * ENTR=proto://host:port-_-natHost:natPort-_-clntHost:clntPort
 */
int scan_protositeport(PCStr(url),PVStr(proto),PVStr(userpasshost),PVStr(port));
void scan_ENTR(Connection *Conn,PCStr(entrance)){
	IStr(proto,64);
	IStr(site,64);
	IStr(ports,64);
	IStr(route,64);
	int type = 0;
	int sock = -1;
	int stdport;

	scan_protositeport(entrance,AVStr(proto),AVStr(site),AVStr(ports));
/*
fprintf(stderr,"------SERVER=%s\n",proto);
	scan_SERVER(Conn,proto);
*/
	stdport = serviceport(proto);
	type |= 0xFFFF0000 & (stdport << 16);
	if( ports[0] == 0 ){
		sprintf(ports,"%d",stdport);
	}
fprintf(stderr,"------PORTS=%s [%X]\n",ports,type);
	scanhostport(ports,site,type,sock,route);
}
const char *servicename(int port,const char **name);
int dump_ENTR(PCStr(fmt),PVStr(entrance)){
	int sx;
	refQStr(ep,entrance);
	const char *proto = "";
	const char *host;
	int iport;
	IStr(ports,256);
	int nports = 0;

	if( servPorts == 0 ){
		clearVStr(entrance);
		return 0;
	}
	for( sx = 0; sx < SVPortN; sx++ ){
		if( SvKeep(sx) )
			continue;
		if( SvSock(sx) < 0 && (SvType(sx) & P_OFF) ){
			continue;
		}
		nports++;
		if( SvType(sx) & P_ADMIN ){
			proto = "admin";
		}else
		if( SvType(sx) & P_YSH ){
			proto = "ysh";
		}else{
			if( iport = 0xFFFF & (SvType(sx) >> 16) ){
				servicename(iport,&proto);
			}
			if( *proto == 0 ) proto = iSERVER_PROTO;
		}
		/*
		if( SvHostStr(sx)[0] ){
			sprintf(ports,"-P%s:%d",SvHost(sx),SvPort(sx));
		}else{
			sprintf(ports,"-P%d",SvPort(sx));
		}
		sprintf(ep,"%s=\"%s:///:-:{%s}\"",P_SERVER,proto,ports);
		ep += strlen(ep);
		*/
		if( SvHostStr(sx)[0] ){
			sprintf(ports,"%s:%d",SvHost(sx),SvPort(sx));
		}else{
			sprintf(ports,"%d",SvPort(sx));
		}
		Rsprintf(ep," %-6s %s\n",proto,ports);
	}
	return nports;
}
