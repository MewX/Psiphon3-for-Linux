/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
//////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	thruwayd.c (bundled-sockets server)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
    Naming:
	- BSocks: bundled sockets
	- BillGates :-p
	- MTCP: Multiplexed Transport Control Protocol
	- ThruWay: ... as is ...
	- AlliGate: ALL-in-one application level Integrated Gateway ?
History:
	971113	created
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "vaddr.h"
#include "dglib.h"

#define TW_PORT		8715
#define TW_ENTR0	"ringer.etl.go.jp:8715"
#define TW_EXIT0	"localhost:9080"
#define TW_EXIT		0

#define BSOCKS_VER	"0.9"
/*
 *	ThruWay packet header
 */
#define M_CTLTYPE	0
#define M_CTLARG	1
#define M_SENDER	2	/* sender port */
#define M_RECEIVER	3	/* receiver port */
#define M_PACKID	4
#define M_PACKLENG	5
#define M_PACKSIZE	6
#define int32 int
#define HEADSIZE (M_PACKSIZE*sizeof(int32))

#include <errno.h>
#ifndef EINPROGRESS
#define EINPROGRESS	-1
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK	-1
#endif
#ifndef EALREADY
#define EALREADY	-1
#endif

/*
 *	BUNDLED-SOCKETS SERVER
 *	OMUNIBUS
 */
typedef struct {
	int	p_status;	/* current I/O status */
	int	p_statussave;	/* I/O status saved on ST_WAIT_RFLUSH */
	int	p_waitdst;	/* destination port (status is ST_WAIT_SEND) */
	int	p_waitwcc;	/* waiting to be flushed (ST_WAIT_RFLUSH) */
	int	p_bsize;	/* I/O buffer size */
	int	p_rwcc;		/* current I/O position */
	int	p_bleng;	/* buffered Output */
	int	p_flagment;	/* size of left flagment of current packet */
	defQStr(p_buff);	/* I/O buffer */
	int	p_iocount;	/* total I/O count */
	int	p_iototal;	/* total I/O bytes */
	int	p_pkcount;	/* total packet I/O count */
	int	p_pktotal;	/* total packet I/O bytes */
	int	p_remotetotal;	/* total bytes finished on remote peer */
	int	p_notifiedcc;	/* total bytes notified to remote peer */
	int	p_pendingto;
	int	p_pendingcc;
	int	p_waitingcc;	/* packet size at WAIT_SEND status BSOCKS */
} PORT;

typedef struct {
	int	p_portid;
  const	char   *p_sockname;	/* sockname of source (accepted) port */
  const	char   *p_peername;	/* peername of source (accepted) port */
	int	p_lport;	/* my I/O port (socket's file descriptor) */
	int	p_rport;	/* peer I/O port at remote router */
	int	p_rbuff;	/* buffer size of the peer I/O port */
	int	p_proto;	/* protocol with client */
	int	p_resfail;	/* count of failures of DNS trial */
	int	p_connecting;	/* connecting */
	int	p_EOF;		/* got local EOF */
	int	p_sentEOF;	/* local EOF is notified to the peer */
	int	p_closing;	/* closing (OR of reasons) */
	int	p_ctime;	/* creation time */
	int	p_waitingQ;	/* next waiting port */

	int	p_connectingR;	/* connecting at remote router */
	int	p_invoked;	/* remote peer port invoked */
	int	p_connected;	/* remote peer connected to destination */
	MStr(	p_dsthost,256);	/* ultimate destination host */
	int	p_dstport;	/* ultimate destination port */
	int	p_dstsock;	/* exit to peer port in this router */
	int	p_srcsock;	/* entrance from peer port in this router */

	int	p_accport;	/* doing ACCEPT from remote */
	int	p_accsock;	/* bound peer port after acceptance */
				/* first child vport in the accept queue */
	int	p_acclast;	/* last child vport in the accept queue */
	int	p_acceptQ;	/* next peer vport in the accept queue */

	MStr(	p_bhost,256);	/* router host */
	int	p_bport;	/* router port */

	PORT	io[2]; /**/
} IOPORT;

typedef struct {
	int	q_portx;
	int	q_ports;
} PORTS;

#define MAXPORTS 4096

typedef struct {
	FILE   *te_LOGFP;
	int	te_logisatty;
	int	te_prefetched;
	int	te_PACKID;
	int	te_dbglev;
	int	te_CONN_PREFECH;

	int	te_NUMPORTS;
	IOPORT **te_ports;
	int	te_ALIVEPORTS;
	int	te_Portid;
	int    *te_alives;
	int	te_alivex;
	int    *te_actives;  /* ports waiting I/O */
	int	te_activex;  /* the number of currently active ports */
	int	te_waitingQ; /* the top port in waiting queue */

	int	te_numAccept;
	int	te_numConnect;
	int	te_numSEND;
	int	te_numRECV;
	int	te_numSUSP;
	int	te_numPackSEND;
	int	te_numPackRECV;
	int	te_maxAlive;
	int	te_numPrefetchHIT;
	int	te_numPrefetchMISS;
	int	te_Ni;
	int	te_Nn;

  const char   *te_router;
  const char   *te_server;
	MStr(	te_server_host,128);
	int	te_server_port;
	MStr(	te_router_host,128);
	int	te_router_port;
	int	te_dbg_http;
	int	te_clockN;
	MStr(	te_svhost0,128);
	int	te_svport0;
	MStr(	te_Sctlbuf,64);
} ThruWayEnv;
static ThruWayEnv *thruWayEnv;
#define TWE		thruWayEnv[0]

#define LOGFP		TWE.te_LOGFP
#define logisatty	TWE.te_logisatty
#define prefetched	TWE.te_prefetched
#define PACKID		TWE.te_PACKID
#define dbglev		TWE.te_dbglev
#define CONN_PREFECH	TWE.te_CONN_PREFECH

#define NUMPORTS	TWE.te_NUMPORTS
#define ports		TWE.te_ports
#define ALIVEPORTS	TWE.te_ALIVEPORTS
#define Portid		TWE.te_Portid
#define alives		TWE.te_alives
#define alivex		TWE.te_alivex
#define actives		TWE.te_actives
#define activex		TWE.te_activex
#define waitingQ	TWE.te_waitingQ

#define numAccept	TWE.te_numAccept
#define numConnect	TWE.te_numConnect
#define numSEND		TWE.te_numSEND
#define numRECV		TWE.te_numRECV
#define numSUSP		TWE.te_numSUSP
#define numPackSEND	TWE.te_numPackSEND
#define numPackRECV	TWE.te_numPackRECV
#define maxAlive	TWE.te_maxAlive
#define numPrefetchHIT	TWE.te_numPrefetchHIT
#define numPrefetchMISS	TWE.te_numPrefetchMISS
#define Ni		TWE.te_Ni
#define Nn		TWE.te_Nn

#define router		TWE.te_router
#define server		TWE.te_server
#define server_host	TWE.te_server_host
/**/
#define server_port	TWE.te_server_port
#define router_host	TWE.te_router_host
/**/
#define router_port	TWE.te_router_port
#define dbg_http	TWE.te_dbg_http
#define clockN		TWE.te_clockN
#define Svhost0		TWE.te_svhost0
/**/
#define svport0		TWE.te_svport0
#define Sctlbuf		TWE.te_Sctlbuf
/**/

#define LOG (LOGFP?LOGFP:stderr)
#define LD dbglev<2?0:dbglog
#define LE dbglev<1?0:dbglog


int isSocksConnect(PCStr(pack),int leng,int *ver,PVStr(addr),int *port,const char **user);
int RIDENT_send(int sock,PCStr(sockname),PCStr(peername),PCStr(ident));

static void dumpQactive(FILE *fp);
static void dumpQwaiting(FILE *fp);
static void ackBSOCKS(IOPORT *pp,PCStr(ver));
static void enQactive(int sock);
static void deQactive(int sock);
static int deQwaiting(int delsock);
static int rewriteHTTPreq(IOPORT *PP,int IO);
static void bsocks_init();
static int relay(int src,int dst,int rwccoff);
static void bsock_server(int svsockn,int svsocks[]);
static void set_BUSBUF(int bsock);
static int connError(PCStr(where),int sock,PCStr(host),int port,int _errno);
static int try_identify(IOPORT *PP,int IO);
static int notify_connected(IOPORT *PP,int dsock);
static void putMSG(int dsock,PCStr(buff),int len);
static void shift_buff(IOPORT *dp);
static int getPackHead(int src,PCStr(msg),int rleng,int *rport,int *portid,int *packid,int *pleng,int *control,int *ctlarg);
static int putPackHead(char msg[],IOPORT *pp,int leng,int control,int ctlarg);
static int waitFlushed(IOPORT *pp,int wcc);
static void pollFlushed(IOPORT *pp);
static void notifyEOF(IOPORT *pp);
static void clock1(int sockx,int IO);
static void connectFromBSOCKS(int bsock,int rport,int rbuff,PCStr(cmd),int clen);
static void connectAtRemote(int bsock,int ssock);
static void notify_connectingR(int sock,int _errno);
static void notify_connectedR(int sock,int _errno);
static int try_identify(IOPORT *PP,int IO);
static void notifyFlushed(IOPORT *pp,int wcc);

void minit_thruway()
{
	if( thruWayEnv == 0 ){
		thruWayEnv = NewStruct(ThruWayEnv);
		dbglev = 1;
		CONN_PREFECH = 1;
	}
}

static int dbglog(FILE *log,PCStr(fmt),...)
{	CStr(stime,64);
	const char *sp;
	VARGS(14,fmt);

	getTimestamp(AVStr(stime));
	sp = strchr(stime,'-') + 1;
	fprintf(log,"%d %s ",clockN,sp);
	fprintf(log,fmt,VA14);
/*
	if( !logisatty )
		fflush(log);
*/
	return 0;
}

static void dumpstat(int out);
static void sigINT(int sig){
	LE(LOG,"GOT SIGINT/SIGTERM\n");
	dumpstat(fileno(LOG));
	exit(0);
}

extern int DNS_TIMEOUT;
extern int RSLV_TIMEOUT;
extern int RSLV_TIMEDOUT;

/*
 * THRUWAY_ENTR is like MASTER in DeleGate which points to destination server
 * THRUWAY_EXIT is like SERVER in DeleGate which points to mediator DeleGate
 */
int thruwayd_main(int ac,const char *av[])
{	ACStr(svhosts,64,64);
	int svports[64],svsocks[64];
	CStr(host,64);
	const char *arg;
	const char *env;
	int svportn,svsockn;
	int ai,port,sock;

	minit_thruway();

	DNS_TIMEOUT = 1;
	if( isatty(fileno(LOG)) ){
		fprintf(LOG,"Thruwayd [-P[host:]port]    \n");
		fprintf(LOG,"   [THRUWAY_ENTR=host:port] \n");
		fprintf(LOG,"   [THRUWAY_EXIT=host:port] \n");
		fprintf(LOG,"   [LOGFILE=path]           \n");
		logisatty = 1;
	}

	svportn = 0;
	svsockn = 0;

	if( env = getenv("THRUWAY_ENTR") )
		router = env;
	if( env = getenv("THRUWAY_EXIT") )
		server  = env;

	if( fromInetd() ){
		sock = 1;
		port = sockPort(sock);
		svsocks[svsockn++] = sock;
	}

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( arg[0] == '-' ){
			if( strcmp(&arg[1],"ringer") == 0 ){
				if( router == NULL ) router = TW_ENTR0;
				if( server == NULL ) server = TW_EXIT0;
			}else
			switch( arg[1] ){
			    case 'v':
				if( arg[2] == 'v' )
					dbglev = 2;
				else{
					dbglev = atoi(&arg[2]);
					if( dbglev == 0 )
						dbglev = 1;
				}
				break;
			    case 'P':
				host[0] = 0;
				port = atoi(arg+2);
				if( port == 0 )
					Xsscanf(arg+2,"%[^:]:%d",AVStr(host),&port);
				if( 0 < port ){
					Xstrcpy(EVStr(svhosts[svportn]),host);
					svports[svportn++] = port;
				}
				break;
			    default:
				LE(LOG,"unknown option: [%d] %s\n",ai,arg);
				break;
			}
		}else
		if( strncmp(arg,"LOGFILE=",8) == 0 ){
			FILE *fp;
			fp = fopen(arg+8,"a");
			if( fp == NULL ){
				fprintf(LOG,"ThruWay: cannot open: %s\n",
					arg+8);
				exit(1);
			}
			LOGFP = fp;
		}else
		if( strncmp(arg,"THRUPATH=",9) == 0 ){
		}else
		if( strncmp(arg,"THRUWAY_ENTR=",13) == 0 ){
			router = arg+13;
		}else
		if( strncmp(arg,"THRUWAY_EXIT=",13) == 0 ){
			server = arg+13;
		}else
		if( strncmp(arg,"RIDENT=",7) == 0 ){
			/*
			scan_RIDENT(arg+7);
			*/
			scan_RIDENT(NULL,arg+7);
			LE(LOG,"RIDENT=%s\n",arg+7);
		}else
		{
			LE(LOG,"unknown argument: [%d] %s\n",ai,arg);
		}
	}

	if( svsockn == 0 && svportn == 0 )
		svports[svportn++] = TW_PORT;

	for( ai = 0; ai < svportn; ai++ ){
		port = svports[ai];
		sock = server_open("bsockd",EVStr(svhosts[ai]),port,1);
		if( 0 <= sock ){
			svsocks[svsockn++] = sock;
LE(LOG,"THRUWAY_PORT = %s %d/%d\n",svhosts[ai],port,sock);

if( svhosts[ai][0] == 0 )
	gethostname(Svhost0,sizeof(Svhost0));
else	strcpy(Svhost0,svhosts[ai]);
svport0 = port;
		}
	}

	if( router ){
LE(LOG,"THRUWAY_ENTR = %s\n",router);
		Xsscanf(router,"%[^:]:%d",AVStr(router_host),&router_port);
		if( router_port == 0 ){
			LE(LOG,"Usage: THRUWAY_ENTR=host:port");
			exit(1);
		}
	}
	if( server ){
LE(LOG,"THRUWAY_EXIT = %s\n",server);
		Xsscanf(server,"%[^:]:%d",AVStr(server_host),&server_port);
		if( server_port == 0 ){
			LE(LOG,"Usage: THRUWAY_EXIT=host:port");
			exit(1);
		}
	}

#ifdef SIGPIPE
	signal(SIGPIPE,SIG_IGN);
#endif
#ifdef SIGTERM
	signal(SIGTERM,sigINT);
#endif
	signal(SIGINT,sigINT);
	bsocks_init();
	bsock_server(svsockn,svsocks);
	LE(LOG,"done.\n");
	dumpstat(2);
	return 0;
}

void service_bsocks(DGC*Conn)
{
	minit_thruway();
}

#define P_ERROR		-1
#define P_MORE		-2
#define P_UNDEF		0
#define P_BSOCKS	1
#define P_SOCKS4	2
#define P_HTTP		3
#define P_TBSOCKS	4

#define CTL_HELLO	0x01	/* opening */
#define CTL_CONNECTDO	0x02	/* make connect at remote router */
#define CTL_CONNECTING	0x04	/* < connecting at remote router */
#define CTL_CONNECTED	0x08	/* < connected at remote router */
#define CTL_CONNERR	0x10	/* < connection error occured at remote router*/
#define CTL_DATA	0x20	/* data */
#define CTL_SENT	0x40	/* < sent N bytes (total) */
#define CTL_EOF		0x80	/* < EOF occured */
#define CTL_ACCEPTDO	0x0400	/* accept at remote router */
#define CTL_ACCEPTED	0x0800	/* < accepted at remote router */

static const char *sctl(int ctl)
{	MrefQStr(cp,Sctlbuf); /**/

	McpyQStr(cp,Sctlbuf);
	setVStrEnd(cp,0);
	if( ctl & CTL_HELLO      ){ strcpy(cp,"Helo"), cp += strlen(cp); }
	if( ctl & CTL_CONNECTDO  ){ strcpy(cp,"Conn"), cp += strlen(cp); }
	if( ctl & CTL_CONNECTING ){ strcpy(cp,"Cing"); cp += strlen(cp); }
	if( ctl & CTL_CONNECTED  ){ strcpy(cp,"Coed"); cp += strlen(cp); }
	if( ctl & CTL_CONNERR    ){ strcpy(cp,"Cerr"); cp += strlen(cp); }
	if( ctl & CTL_ACCEPTDO   ){ strcpy(cp,"Acc");  cp += strlen(cp); }
	if( ctl & CTL_ACCEPTED   ){ strcpy(cp,"Aced"); cp += strlen(cp); }
	if( ctl & CTL_DATA       ){ strcpy(cp,"Data"); cp += strlen(cp); }
	if( ctl & CTL_SENT       ){ strcpy(cp,"Sent"); cp += strlen(cp); }
	if( ctl & CTL_EOF        ){ strcpy(cp,"Eof");  cp += strlen(cp); }
	return Sctlbuf;
}

/*
 *	reasons of closing
 */
/* destroy immediately */
#define CLOSE_INITERROR		0x01
#define CLOSE_LOCALEOF		0x02
#define CLOSE_CONNERROR		0x04

/* destroy after output drain */
#define CLOSE_LOCALPEER		0x08
#define CLOSE_BUSEOF		0x10
#define CLOSE_REMOTEPEER	0x20

/*
 *	STATUS OF I/O PORTS
 */
#define ST_INACTIVE	0	/* inactive */

/* input port */
#define ST_ACCEPT	0x001	/* accepting       ... poll(RECV)  */
#define ST_ACCEPT_WAIT	0x2000	/* waiting local port to accept    */
#define ST_INIT		0x002	/* initializing    ... poll(RECV)  */
#define ST_RESOLV	0x004	/* resolving ... watch(eof,dns,timeout) */
#define ST_RECV		0x008	/* receiving       ... poll(RECV)  */
#define ST_WAIT_SEND	0x010	/* waiting local output to be drained */
#define ST_WAIT_RFLUSH	0x020	/* waiting remote output to be drained */

/* output port */
#define ST_CONNECT	0x100	/* connecting      ... poll(SEND)  */
#define ST_RCONNECT	0x200	/* waiting remote connection */
#define ST_READY	0x400	/* waiting output */
#define ST_SEND		0x800	/* sending         ... poll(SEND)  */
#define ST_CONNPRE	0x1000	/* prefetched connection */

#define ST_POLLRECV	(ST_ACCEPT|ST_INIT|ST_RECV)
#define ST_POLLSEND	(ST_CONNECT|ST_SEND)
#define ST_WAITING	(ST_WAIT_SEND|ST_WAIT_RFLUSH)

static const char *ss(int stat)
{	switch( stat ){
	  case ST_ACCEPT:	return "ACC";
	  case ST_ACCEPT_WAIT:	return "WAC";
	  case ST_INIT:		return "INI";
	  case ST_RESOLV:	return "DNS";
	  case ST_RECV:		return "RCV";
	  case ST_WAIT_SEND:	return "WSN";
	  case ST_SEND:		return "SND";
	  case ST_CONNPRE:	return "CPF";
	  case ST_CONNECT:	return "CON";
	  case ST_RCONNECT:	return "RCO";
	  case ST_READY:	return "RDY";
	  case ST_WAIT_RFLUSH:	return "WRF";
	}
	return "INA";
}

static void bsocks_init()
{
	NUMPORTS = expand_fdset(MAXPORTS);
	ports = (IOPORT**)calloc(sizeof(IOPORT*),NUMPORTS);
	alives = (int*)calloc(sizeof(int),NUMPORTS);
	actives = (int*)calloc(sizeof(int),NUMPORTS);
}

#define W_IN		0
#define W_OUT		1

#define P_PROTO		PP->p_proto
#define P_SOCK		PP->p_lport

#define P_STATUS	PP->io[IO].p_status
#define P_RWCC		PP->io[IO].p_rwcc
#define P_BUFSIZE	PP->io[IO].p_bsize
#define P_BUFLEN	PP->io[IO].p_bleng
#define P_BUFF		PP->io[IO].p_buff
#define P_REMCC		((IO==W_IN?P_BUFSIZE:P_BUFLEN) - P_RWCC)
#define P_IOTOTAL	PP->io[IO].p_iototal
#define P_IOCOUNT	PP->io[IO].p_iocount
#define P_EOF		PP->p_EOF

#define P_DHOST		PP->p_dsthost
/**/
#define P_DPORT		PP->p_dstport
#define P_DSOCK		PP->p_dstsock
#define P_SSOCK		PP->p_srcsock
#define P_BHOST		PP->p_bhost
/**/
#define P_BPORT		PP->p_bport
#define P_RPORT		PP->p_rport

/* OUTSTANDING:
 * total read - left in read buffer + drained at remote output
 */
#define outstanding(pp)	\
	(pp->p_rport ? (pp->io[W_IN].p_iototal - \
		(pp->io[W_IN].p_rwcc + pp->io[W_IN].p_remotetotal)) : 0)

static void dumpstat(int out)
{	FILE *fp;
	int pi;
	IOPORT *pp;
	CStr(srcsock,128);

	fp = fdopen(dup(out),"w");
	fprintf(fp,"  MaxAlive=%d",maxAlive);
	fprintf(fp,"  Accepted=%d",numAccept);
	fprintf(fp,"  Connected=%d",numConnect);
	fprintf(fp,"  Prefetched=%dhit:%dmiss",numPrefetchHIT,numPrefetchMISS);
	fprintf(fp,"\n");
	fprintf(fp,"  Active=%d",activex); dumpQactive(fp);
	fprintf(fp,"\n");
	fprintf(fp,"  Waiting=",waitingQ); dumpQwaiting(fp);
	fprintf(fp,"\n");
	fprintf(fp,"  Raw-I/O: SEND=%d RECV=%d SUSP=%d\n",
		numSEND,numRECV,numSUSP);
	fprintf(fp,"  Pack-I/O: SEND=%d RECV=%d\n",
		numPackSEND,numPackRECV);

	for( pi = 0; pi < NUMPORTS; pi++ )
	if( pp = ports[pi] ){
		if( pp->p_proto == P_BSOCKS )
			strcpy(srcsock,"*");
		else	sprintf(srcsock,"%x",pp->p_srcsock);

		fprintf(fp,"%4x[%2x]%s %4x",
			pp->p_portid,pi,srcsock,
			pp->p_rport
		);
		fprintf(fp," I[%s %d %d(%d)/%d]",
			ss(pp->io[W_IN].p_status),
			pp->io[W_IN].p_rwcc,
			pp->io[W_IN].p_iototal,
			outstanding(pp),
			pp->io[W_IN].p_iocount
		);
		fprintf(fp," O[%s %d/%d %d(%d)/%d]",
			ss(pp->io[W_OUT].p_status),
			pp->io[W_OUT].p_rwcc,
			pp->io[W_OUT].p_bleng,
			pp->io[W_OUT].p_iototal,
			pp->io[W_OUT].p_notifiedcc,
			pp->io[W_OUT].p_iocount
		);
		if( pp->p_EOF ) fprintf(fp,"[EOF]");
		if( pp->p_closing ) fprintf(fp,"[closing:%x]",pp->p_closing);
		if( pp->io[W_IN].p_pendingcc ){
			fprintf(fp,">[%d]%d",
				pp->io[W_IN].p_pendingto,
				pp->io[W_IN].p_pendingcc);
		}
		if( pp->io[W_OUT].p_status == ST_CONNECT )
			fprintf(fp," (%s:%d)",pp->p_dsthost,pp->p_dstport);
		else{
			CStr(hostport,128);
			getpeerName(pi,AVStr(hostport),"%H:%P");
			fprintf(fp," %s",hostport);
		}
		if( pp->p_proto == P_BSOCKS && pp->p_bhost[0] ){
			fprintf(fp," <%s:%d>",pp->p_bhost,pp->p_bport);
		}
		fprintf(fp,"\n");
	}
	fclose(fp);
}

/*
 *	Output buffer to external agent must be larger than possible
 *	buffered input in socket and peer router...
 *	SERVER[Bsv]R1[B1] =>[Bsock]=> [B2]R2[Bcl]CLIENT
 */
#define BUFUNIT		(16*1024)
#define IBUFSIZE	(2*BUFUNIT-HEADSIZE)
#define OBUFSIZE	(4*BUFUNIT)
#define BSOCKBUFSIZE	(8*BUFUNIT)
#define BHEAD_MARGIN	1024

#define enPortID(ptp)	((ptp->p_lport<<8)|(ptp->p_portid&0xFF))
static int dePortID(int pti)
{	IOPORT *pp;
	int lport,portid;

	portid = pti & 0xFF;
	lport = pti >> 8;
	pp = ports[lport];
	if( pp == NULL ){
		LD(LOG,"[%x] ## DANGLING PORT SOCK (%x)\n",lport,pti);
		return -1;
	}
	if( (pp->p_portid & 0xFF) != portid ){
		LD(LOG,"[%x] ## OVERWRITEN PORT (%x)\n",lport,portid);
		return -1;
	}
	return lport;
}

static void new_port(PCStr(where),int src,int sock)
{	IOPORT *np;

	LD(LOG,"[%x] new_port(%s,%d)\n",src,where,sock);
	if( sock < 0 )
		exit(-1);

	/* ... should try to get from free list of IOPORT structure ... */
	np = (IOPORT*)calloc(1,sizeof(IOPORT));

	np->p_portid = ++Portid;
	np->p_lport = sock;
	np->p_ctime = time(NULL);
	setQStr(np->io[W_IN].p_buff,(char*)malloc(BHEAD_MARGIN+IBUFSIZE),BHEAD_MARGIN+IBUFSIZE);
	np->io[W_IN].p_bsize = BUFUNIT;
	setQStr(np->io[W_OUT].p_buff,(char*)malloc(BHEAD_MARGIN+OBUFSIZE),BHEAD_MARGIN+OBUFSIZE);
	np->io[W_OUT].p_bsize = BUFUNIT;
	ports[sock] = np;
	ALIVEPORTS++;
	if( maxAlive < ALIVEPORTS )
		maxAlive = ALIVEPORTS;
}
static void del_port(int sock)
{	int pi;
	IOPORT *dp,*pp;
	int deq;

	if( ports[sock] == NULL ){
		LE(LOG,"[%x] del_port... NULL\n",sock);
		return;
	}

	dp = ports[sock];
	if( dp->p_proto == P_BSOCKS && !dp->p_EOF ){
		/*LE(LOG,"[%x] postpone del_port BSOCKS\n",sock);*/
		dp->p_closing = 0;
		return;
	}

	deq = deQwaiting(sock);
	LE(LOG,"[%x] <%x>(%d) %ds %d/%di %d/%do\n",sock,
		dp->p_portid,ALIVEPORTS-3,time(0)-dp->p_ctime,
		dp->io[W_IN].p_iototal, dp->io[W_IN].p_iocount,
		dp->io[W_OUT].p_iototal,dp->io[W_OUT].p_iocount
		);

	close(sock);
	dp->p_lport = -1;

	for( pi = 0; pi < NUMPORTS; pi++ )
	if( pp = ports[pi] )
	if( pp->p_dstsock == sock || pp->p_srcsock == sock )
		pp->p_closing |= CLOSE_LOCALPEER;
	else
	if( dp->io[W_OUT].p_status == ST_ACCEPT_WAIT
	 && (pp->p_accsock == sock || pp->p_acclast == sock
	 ||  pp->p_acceptQ == sock) ){
LD(LOG,"#### [%x] MUST detach this vport from accept Q[%x].\n",
			sock,pi);
		if( pp->p_accsock == sock && pp->p_acclast == sock )
			pp->p_closing |= CLOSE_LOCALEOF;
	}

	deQactive(sock);

	/* ... to free list ... */
	free((char*)dp->io[W_IN].p_buff);
	free((char*)dp->io[W_OUT].p_buff);
	if( dp->p_sockname ) free((char*)dp->p_sockname);
	if( dp->p_peername ) free((char*)dp->p_peername);
	free(dp);
	ports[sock] = NULL;
	ALIVEPORTS--;
}
static int findLocalPort(int rport)
{	int portid;
	int pi;
	IOPORT *pp;

	for( pi = 0; pi < NUMPORTS; pi++ )
	if( pp = ports[pi] )
	if( pp->p_rport == rport ){
		LE(LOG,"[%d] is local port of %x\n",pi,rport);
		return enPortID(pp);
	}
	return 0;
}
/*
 * Find the vport of which protocol is BSOCKS and is connected to
 * the BSOCKS server at the host:port.
 */
static int findBSOCKS(PCStr(host),int port)
{	int pi;
	IOPORT *pp;

	for( pi = 0; pi < NUMPORTS; pi++ )
	if( pp = ports[pi] )
	if( pp->p_proto == P_BSOCKS )
{
LD(LOG,"[%x] findBSOCKS: %s:%d %s:%d\n",pi,host,port,pp->p_bhost,pp->p_bport);
	if( pp->p_bport == port )
	if( strcmp(host,pp->p_bhost) == 0 )
		return pi;
}
	return -1;
}
/*
 * Find the vport which is accepting at the host:port,
 * or create it if no such port exists.
 */
static int findASOCK(PCStr(spec),int ssock)
{	CStr(host,MaxHostNameLen);
	int port;
	int asock,listen;
	int pi;
	IOPORT *pp;
	int port1;

	host[0] = 0;
	port = 0;
	listen = 7;
	Xsscanf(spec,"%[^:]:%d:%d",AVStr(host),&port,&listen);
	if( strcmp(host,"*") == 0 )
		host[0] = 0;

	for( pi = 0; pi < NUMPORTS; pi++ )
	if( pp = ports[pi] ){
		if( pp->io[W_IN].p_status == ST_ACCEPT )
		if( pp->p_acclast ){
			port1 = sockPort(pp->p_lport);
			if( port1 == port ){

LD(LOG,"PARALLEL ACCEPT at [%d] %d,%d\n",
port,pp->p_acclast,ssock);
ports[pp->p_acclast]->p_acceptQ = ssock;
pp->p_acclast = ssock;
				return pi;
			}
		}
	}

	asock = Socket1("bsocks",-1,"inet","tcp","bsocks", AVStr(host),port,
		NULL,0, listen,NULL,1);
	if( asock < 0 )
		return -1;

LD(LOG,"[%x] NEW ACCEPT vport for [%x]\n",asock,ssock);

	new_port("ACCEPT",ssock,asock);
	ports[asock]->io[W_IN].p_status = ST_ACCEPT;
	ports[asock]->p_accsock = ssock;

ports[asock]->p_acclast = ssock;

	enQactive(asock);
	return asock;
}

static int prefetch(PCStr(where),int ssock,PCStr(host),int port)
{	int sock;
	IOPORT *pp;

	if( host == 0 || *host == 0 || port == 0 )
		return -1;

	sock = Socket1("bsocks",-1,"inet","tcp","bsocks", VStrNULL,0,
		host,port, 0,NULL,1);
	if( sock < 0 )
		return -1;
	if( connError(where,sock,host,port,errno) ){
		close(sock);
		return -1;
	}
	new_port(where,ssock,sock);
	pp = ports[sock];
	strcpy(pp->p_dsthost,host);
	pp->p_dstport = port;
	pp->io[W_OUT].p_status = ST_CONNPRE;
	return sock;
}

static int newsocket(PCStr(where),int ssock,PCStr(host),int port)
{	int sock;
	IOPORT *pp;

	if( router == NULL )
	for( sock = 0; sock < NUMPORTS; sock++ )
	if( pp = ports[sock] )
	if( pp->io[W_OUT].p_status == ST_CONNPRE )
	if( strcmp(host,pp->p_dsthost) == 0 )
	if( port == pp->p_dstport ){
		prefetched--;
		/* PollOut() ? */
		if( PollIn(sock,1) && Peek1(sock) <= 0 ){
			numPrefetchMISS++;
			LD(LOG,"[%x] TIMEOUT prefetched connection %s:%d\n",
				sock,host,port);
			del_port(sock);
		}else{
			numPrefetchHIT++;
			LD(LOG,"[%x] VALID prefetched connection %s:%d\n",
				sock,host,port);
			pp->p_ctime = time(NULL);
			return sock;
		}
	}
	return prefetch(where,ssock,host,port);
}

static void init_bhostport(PVStr(bhost),int *bportp)
{
	setVStrEnd(bhost,0);
	*bportp = 0;
	if( router ){
		strcpy(bhost,router_host);
		*bportp = router_port;
	}
}

static int identify_protocol(IOPORT *PP,int IO)
{	const char *elp;
	CStr(host,512);
	int port;
	const char *user;
	int leng;
	CStr(op,128);
	CStr(ver,128);
	int sver;
	CStr(bhost,512);
	int bport,rport;
	int proto = P_UNDEF;
	int rcode;
	CStr(msg,128);
	CStr(callback,128);

	callback[0] = 0;
	setVStrEnd(P_BUFF,P_RWCC);

	init_bhostport(AVStr(bhost),&bport);
	if( bhost[0] && bport ){
		strcpy(P_BHOST,bhost);
		P_BPORT = bport;
	}

	if( strncasecmp(P_BUFF,"STAT",4) == 0 ){
		dumpstat(P_SOCK);
		proto = P_ERROR;
	}else
	if( 8 <= P_RWCC && strncasecmp(P_BUFF,"ACCEPT ",7) == 0 ){
		CStr(sockhost,MaxHostNameLen);
		int asock;

		/* if not local port */
		if( bhost[0] && bport )
		if( elp = strchr(P_BUFF,'\n') ){
			elp++;
			leng = elp - P_BUFF;
			Bcopy(elp,P_BUFF,P_RWCC-leng);
			P_RWCC -= leng;

			if( Xsscanf(P_BUFF+7,"%[^:]:%d/%[^:]:%d/%d",AVStr(host),&port,AVStr(bhost),&bport,&rport) < 2 ){
				del_port(PP->p_lport);
				return -1;
			}
			P_PROTO = P_TBSOCKS;
			strcpy(P_DHOST,host);
			P_DPORT = 100000 + port;
			strcpy(P_BHOST,bhost);
			P_BPORT = bport;
LD(LOG,"[%x] P_TBSOCKS: Raccept %s:%d\n",PP->p_lport,host,port);
			return P_TBSOCKS;
		}

		P_RWCC = 0;
		asock = findASOCK(P_BUFF+7,PP->p_lport);
		if( asock < 0 )
			return -1;
		PP->io[W_OUT].p_status = ST_ACCEPT_WAIT;
/*
		gethostName(asock,sockhost,"%A:%P");
		PP->p_accsock = asock;
		sprintf(PP->io[W_OUT].p_buff,"BOUND %s\r\n",sockhost);
		PP->io[W_OUT].p_bleng = strlen(PP->io[W_OUT].p_buff);
		PP->io[W_OUT].p_status = ST_SEND;
*/
	}else
	if( 8 <= P_RWCC && strncasecmp(P_BUFF,"CONNECT ",8) == 0 ){
		if( elp = strchr(P_BUFF,'\n') ){
			elp++;
			leng = elp - P_BUFF;
			Bcopy(elp,P_BUFF,P_RWCC-leng);
			P_RWCC -= leng;

			if( Xsscanf(P_BUFF+8,"%[^:]:%d/%[^:]:%d/%d",AVStr(host),&port,AVStr(bhost),&bport,&rport) < 2 ){
				del_port(PP->p_lport);
				return -1;
			}
			P_PROTO = P_TBSOCKS;
			strcpy(P_DHOST,host);
			P_DPORT = port;
			if( bhost[0] && bport ){
				strcpy(P_BHOST,bhost);
				P_BPORT = bport;
			}
			proto = P_TBSOCKS;
LD(LOG,"[%x] P_TBSOCKS: connect %s:%d\n",PP->p_lport,host,port);
		}
	}else
	if( 8 <= P_RWCC && (leng = isSocksConnect(P_BUFF,P_RWCC,&sver,AVStr(host),&port,&user)) ){
		proto = P_SOCKS4;
		P_PROTO = P_SOCKS4;
		strcpy(P_DHOST,host);
		P_DPORT = port;
LD(LOG,"[%x] P_SOCKS%d: CONNECT %s:%d %s (%d/%d)\n",PP->p_lport,
sver,host,port,user,leng,P_RWCC);
		Bcopy(P_BUFF+leng,P_BUFF,P_RWCC-leng);
		P_RWCC -= leng;
	}else
	if( 8 <= P_RWCC && strncmp(P_BUFF,"BSOCKS/",7) == 0
	 && Xsscanf(P_BUFF,"BSOCKS/%s %s",AVStr(ver),AVStr(callback)) >= 1 ){
		proto = P_BSOCKS;
		P_PROTO = P_BSOCKS;
		strcpy(P_DHOST,"");
		P_DPORT = 0;
		ackBSOCKS(PP,ver);

LD(LOG,"####[%x] BSOCK CLEAR [%s:%d] AND SET [%s]\n",
PP->p_lport,P_BHOST,P_BPORT,callback);
Xsscanf(callback,"%[^:]:%d",AVStr(P_BHOST),&P_BPORT);

		if( elp = strchr(P_BUFF,'\n') ){
			elp++;
			leng = elp - P_BUFF;
			Bcopy(elp,P_BUFF,P_RWCC-leng);
			P_RWCC -= leng;
if( 0 < P_RWCC )
relay(P_SOCK,P_DSOCK,0); /* CONNECT... */

		}else	P_RWCC = 0;
		set_BUSBUF(PP->p_lport);
	}else
	if( server ){
		P_PROTO = P_TBSOCKS;
		strcpy(P_DHOST,server_host);
		P_DPORT = server_port;
		proto = P_PROTO;
	}else
	if( 8 <= P_RWCC && (proto = rewriteHTTPreq(PP,IO /*,host,&port*/ )) ){
	}else
	if( strncmp(P_BUFF,"DeleGate-HELLO",15) == 0 ){
	}else
	if(  8 < P_RWCC ){
		LE(LOG,"[%x] ERROR: protocol not identified\n",P_SOCK);
		proto = P_ERROR;
	}

	if( proto == P_MORE )
		proto = P_UNDEF;
	return proto;
}
static int rewriteHTTPreq(IOPORT *PP,int IO)
{	refQStr(up,P_BUFF); /**/
	const char *vp;
	const char *hp;
	const char *rp;
	CStr(hostport,512);
	char sc;
	const char *sp;
	refQStr(dp,P_BUFF); /**/
	CStr(host,512);
	int prefix;
	int port;
	const char *cka;
	int leng,remcc,rmcc,rmln;

	if( !HTTP_isMethod(P_BUFF) )
		return 0;

	if( (up = strchr(P_BUFF,' ')) == NULL ){
		LE(LOG,"[%x] BAD HTTP REQUEST\n",PP->p_lport);
		return P_ERROR;
	}
	up++;
	if( strncasecmp(up,"/-_-http://",11) == 0 ){
		prefix = 11;
	}else
	if( strncasecmp(up,"http://",7) == 0 ){
		prefix = 7;
	}else{
		LE(LOG,"[%x] BAD HTTP REQUEST\n",PP->p_lport);
		return P_ERROR;
	}
	if( vp = strpbrk(up," \t\r\n") )
		vp++;
	if( vp && strncmp(vp,"HTTP/",5) == 0 )
	if( strstr(P_BUFF,"\r\n\r\n") == NULL ){
		LD(LOG,"[%x] INCOMPLETE HTTP REQUEST\n",PP->p_lport);
		return P_MORE;
	}

	hp = up + prefix;
	rp = strpbrk(hp,"/ \t\r\n");
	Bcopy(hp,hostport,rp-hp);
	hostport[rp-hp] = 0;
	port = 80;
	Xsscanf(hostport,"%[^:]:%d",AVStr(host),&port);
	leng = rp - up;
	remcc = P_RWCC - (rp - P_BUFF);
	if( *rp != '/' )
		setVStrPtrInc(up,'/');
	Bcopy(rp,up,remcc);

	dp = up;
	rmln = 0;
	rmcc = 0;
	for( sp = up; sc = *sp++; ){
		if( rmln )
			rmcc++;
		else	setVStrPtrInc(dp,sc);
		if( sc != '\n' )
			continue;

		if( rmln ){
			rmln = 0;
		}else
		if( strncasecmp(sp,"Proxy-Connection:",17) == 0
		 || strncasecmp(sp,"Connection:",11) == 0 ){
			LD(LOG,"removed Connection: field\n");
			rmln = 1;
		}
	}

	P_RWCC = (up - P_BUFF) + remcc - rmcc;
	P_PROTO = P_HTTP;
	strcpy(P_DHOST,host);
	P_DPORT = port;
	setVStrEnd(P_BUFF,P_RWCC);

if( dbg_http )
fprintf(LOG,"HTTP[%s:%d]LENG=%d+%d\n%s\n",P_DHOST,P_DPORT,P_RWCC,rmcc,P_BUFF);

	return P_HTTP;
}

static int try_send(int src)
{	IOPORT *sp,*dp;
	int dst;

	sp = ports[src];
	dst = sp->io[W_IN].p_waitdst;
	if( dst == 0 ){
		LD(LOG,"[%x] SEND TO SOMETHING(%d)\n",src,sp->p_dstsock);
		return relay(src,sp->p_dstsock,0);
	}

	dp = ports[dst];
	if( dp == 0 ){
		int rwcc,rmcc;
		refQStr(buff,sp->io[W_IN].p_buff); /**/
		rwcc = sp->io[W_IN].p_rwcc;
		rmcc = sp->io[W_IN].p_waitingcc;
		buff = (char*)sp->io[W_IN].p_buff;
		sp->io[W_IN].p_waitdst = 0;

fprintf(LOG,"[%x]%s > %x #### SEND TO ZOMBI #### remove(%d/%d)\n",
src,sp->p_proto==P_BSOCKS?"*":" ",dst,rmcc,rwcc);
if( rmcc != rwcc ) sleep(5);

		if( sp->p_proto == P_BSOCKS ){
			relay(src,0,0);
		}else
		if( rmcc && sp->p_proto == P_BSOCKS ){
			Bcopy(buff+rmcc,buff,rwcc-rmcc);
			sp->io[W_IN].p_waitingcc = 0;
			sp->io[W_IN].p_rwcc -= rmcc;
			relay(src,0,0);
		}else{
			sp->io[W_IN].p_rwcc = 0;
			sp->io[W_IN].p_status = ST_RECV;
		}
		return 1;
	}

	if( dp->io[W_OUT].p_status == ST_READY || sp->p_proto == P_BSOCKS )
		return relay(src,dst,0);
	return 0;
}

static void enQactive(int sock)
{	int ai;

	for( ai = 0; ai < activex; ai++ )
		if( actives[ai] == sock )
			return;
	actives[activex++] = sock;
}
static void deQactive(int sock)
{	int ai,ao,ndel;

	ao = 0;
	ndel = 0;
	for( ai = 0; ai < activex; ai++ ){
		if( actives[ai] == sock )
			ndel++;
		else	actives[ao++] = actives[ai];
	}
	activex -= ndel;
}

static void enQwaiting(int sockx)
{	IOPORT *pp;
	int wq,nq;
	int nwait;

	if( waitingQ == sockx )
		return;

	if( waitingQ == 0 ){
		waitingQ = sockx;
		ports[sockx]->p_waitingQ = 0;
		nwait = 1;
	}else{
		nwait = 1;
		for( wq = waitingQ; 0 < (nq = ports[wq]->p_waitingQ); wq = nq ){
			if( nq == sockx )
				return;
			nwait++;
		}
		ports[wq]->p_waitingQ = sockx;
		ports[sockx]->p_waitingQ = 0;
		nwait++;
	}
	/*LD(LOG,"#### ENQ[%d] = %d\n",nwait,sockx);*/
}
static int inQwaiting(int sockq){
	int sockx;
	IOPORT *pp;

	for( sockx = waitingQ; 0 < sockx; sockx = pp->p_waitingQ ){
		if( sockx == sockq )
			return 1;
		pp = ports[sockx];
	}
	return 0;
}
static void scanQwaiting(){
	int sockx;
	IOPORT *pp,*wq;
	int ntrial;

	if( waitingQ == 0 )
		return;

	ntrial = 0;
	for( sockx = waitingQ; 0 < sockx; sockx = pp->p_waitingQ ){
		pp = ports[sockx];
		switch( pp->io[W_IN].p_status ){
		    case ST_WAIT_SEND:
			try_send(sockx);
			ntrial++;
			break;
		    case ST_WAIT_RFLUSH:
			pollFlushed(pp);
			ntrial++;
			break;
		}
	}

	wq = NULL;
	if( ntrial )
	for( sockx = waitingQ; 0 < sockx; sockx = pp->p_waitingQ ){
		pp = ports[sockx];
		if( (pp->io[W_IN].p_status & ST_WAITING) == 0 ){
			if( wq == NULL )
				waitingQ = pp->p_waitingQ;
			else	wq->p_waitingQ = pp->p_waitingQ;
		}else	wq = pp;
	}
}
static void dumpQactive(FILE *fp)
{	int pi;

	for( pi = 0; pi < activex; pi++ )
		fprintf(fp,"(%x)",actives[pi]);
}
static void dumpQwaiting(FILE *fp)
{	int sockx;

	for( sockx = waitingQ; 0 < sockx; sockx = ports[sockx]->p_waitingQ )
		fprintf(fp,"(%x)",sockx);
}
static int deQwaiting(int delsock)
{	int sockx;
	IOPORT *wq,*pp;

	wq = NULL;
	for( sockx = waitingQ; 0 < sockx; sockx = pp->p_waitingQ ){
		pp = ports[sockx];
		if( sockx == delsock ){
			if( wq == NULL )
				waitingQ = pp->p_waitingQ;
			else	wq->p_waitingQ = pp->p_waitingQ;
			return 1;
		}
		wq = pp;
	}
	return 0;
}

static void bsock_server(int svsockn,int svsocks[])
{	int svsock1;
	int fi,qfdv[MAXPORTS],rfdv[MAXPORTS];
	int pq,cactives[MAXPORTS],cactivex;
	int nready,timeout;
	int px,sockx;
	int wx;
	IOPORT *pp,*bp;
	int status;
	int nac,nai;

	timeout = 1*1000;
	new_port("INIT",-1,0); /* to internal */
	for( fi = 0; fi < svsockn; fi++ ){
		svsock1 = svsocks[fi];
		new_port("INIT",-1,svsock1); /* given entrance */
		ports[svsock1]->io[W_IN].p_status = ST_ACCEPT;
		enQactive(svsock1);
	}

	if( router == NULL && server != NULL )
	if( 0 <= prefetch("prefetch",-1,server_host,server_port) )
		prefetched++;

	for( clockN = 1;; clockN++ ){
		cactivex = 0;
		for( fi = 0; fi < activex; fi++ ){
			IOPORT *pp;

			sockx = actives[fi];
			pp = ports[sockx];
			pq = 0;
			status = pp->io[W_IN].p_status;
			if( pp->p_EOF && (status & ST_WAITING) )
				continue;
			if( status & ST_POLLRECV )
				pq |= PS_IN;
			status = pp->io[W_OUT].p_status;
			if( status & ST_POLLSEND )
				pq |= PS_OUT;
			if( pq ){
				cactives[cactivex] = sockx;
				qfdv[cactivex] = pq;
				cactivex++;
			}
		}
		nready = PollInsOuts(timeout,cactivex,cactives,qfdv,rfdv);

		if( nready < 0 ){
			LE(LOG,"POLL ERROR: %d / %d\n",cactivex,activex);
			dumpstat(fileno(LOG));
			break;
		}
		if( nready == 0 )
			fflush(LOG);

		for( px = 0; px < cactivex; px++ ){
			sockx = cactives[px];
			if( pp = ports[sockx] ){
				status = pp->io[W_OUT].p_status;

				if( rfdv[px] & PS_OUT )
				if( status & ST_POLLSEND )
					clock1(sockx,W_OUT);
			}
		}
		for( px = 0; px < cactivex; px++ ){
			sockx = cactives[px];
			if( pp = ports[sockx] ){
				status = pp->io[W_IN].p_status;

				if( rfdv[px] & PS_IN )
				if( status & ST_POLLRECV )
					clock1(sockx,W_IN);
			}
		}
		for( px = 0; px < cactivex; px++ ){
			sockx = cactives[px];
			if( pp = ports[sockx] ){
				if( rfdv[px] & PS_ERRORS ){
					LE(LOG,"[%x] POLL_ERROR (0x%x)\n",sockx,rfdv[px]);
					pp->p_EOF |= CLOSE_LOCALEOF;
/*
 * immediate deletion of the vport here can be harmful:
 *  connection reset cause (POLL_IN + POLL_HUP) on OSF/1
 *  deleting the port without informing of remote peer if exists,
 *  makes the remote port be dangling...
 * thus this whole loop for PS_ERRORS should be after the loop for POLL_IN
 */
if( pp->p_rport == 0 )
if( (pp->io[W_IN].p_status & ST_POLLRECV) == 0 )
					del_port(sockx);
				}
			}
		}
		for( px = 0; px < cactivex; px++ ){
			sockx = cactives[px];
			if( pp = ports[sockx] ){
				status = pp->io[W_OUT].p_status;
				if( status & ST_POLLSEND )
				if( (qfdv[px] & PS_OUT) == 0 ){
					LD(LOG,"[%x] output from this phase.\n",sockx);
					clock1(sockx,W_OUT);
				}
			}
		}

		scanQwaiting();

		nac = ALIVEPORTS;
		nai = 0;
		for( sockx = 0; sockx < NUMPORTS && nai < nac; sockx++ ){
			if( ports[sockx] == 0 )
				continue;
			nai++;

			if( pp = ports[sockx] )
			if( pp->io[W_IN].p_status == ST_RESOLV )
			if( nready == 0 )
				clock1(sockx,W_IN);

			if( pp = ports[sockx] )
			if( pp->io[W_IN].p_status == ST_RECV )
/*
			if( pp->p_connected )
*/
if( pp->p_connected || pp->p_invoked )
				if( 0 < pp->io[W_IN].p_rwcc ){
if( nready == 0 )
fprintf(LOG,"## ERROR: [%x] SOULD DO TIE BREAK %d\n",sockx,pp->io[W_IN].p_rwcc);
					relay(pp->p_lport,pp->p_dstsock,0);
				}

			if( pp = ports[sockx] )
			if( pp->io[W_IN].p_status & ST_WAITING )
			if( !inQwaiting(sockx) ){
fprintf(LOG,"## ERROR: [%x] not in Q %s\n",sockx,ss(pp->io[W_IN].p_status));
dumpstat(fileno(LOG));
exit(1);
			}

			if( pp = ports[sockx] )
			if( pp->io[W_OUT].p_status != ST_SEND )
			if( pp->p_closing )
				del_port(sockx);

			if( pp = ports[sockx] )
			if( pp->io[W_IN].p_status == ST_INIT )
			if( pp->io[W_IN].p_rwcc == 0 )
			if( server )
			if( 1 <= time(NULL) - pp->p_ctime ){
				try_identify(pp,W_IN);
			}

			if( pp = ports[sockx] )
			if( pp->io[W_OUT].p_status == ST_CONNECT )
			if( 10 <= time(NULL) - pp->p_ctime ){
				LE(LOG,"[%x] connection timeout (%s:%d)\n",
					sockx,pp->p_dsthost,pp->p_dstport);
				notifyEOF(pp);
				del_port(sockx);
			}
		}
		if( router == NULL && server != NULL )
		if( prefetched < 1 )
		if( 0 <= prefetch("prefetch",-1,server_host,server_port) )
			prefetched++;
	}
}

static int notify_connected(IOPORT *PP,int dsock)
{	int len,wcc;
	CStr(msg,256);

	if( P_PROTO == P_SOCKS4 ){
LD(LOG,"[%x] notify SOCKS4 connected: %d\n",PP->p_lport,dsock);
		msg[0] = 4;
		msg[1] = 90;
		msg[2] = 0; msg[3] = 0; msg[4] = 0; msg[5] = 0;
		msg[6] = 0; msg[7] = 0;
		len = 8;
	}else
	if( P_PROTO == P_BSOCKS ){
		return 0;
	}else
	if( P_PROTO == P_TBSOCKS ){
		return 0;
	}else{
		return 0;
	}

	putMSG(PP->p_lport,msg,len);
	return 0;
}

static int relay(int src,int dst,int rwccoff)
{	IOPORT *sp,*dp,*lp;
	int rleng; /* size of data left in the input buffer */
	int ihlen; /* size of header in the input buffer */
	int ohlen; /* size of header in the output buffer */
	const char *ibuff;
	int dsock;
	int pleng,oleng,cleng;
	int control,ctlarg;
	int rport,lport;
	int portid;
	int packid;
	int flagment,incomplete;

	sp = ports[src];
	if( sp == NULL )
		return 0;

	ibuff = sp->io[W_IN].p_buff;
	rleng = sp->io[W_IN].p_rwcc;
	cleng = rleng;
	pleng = -1;
	oleng = -1;
	ihlen = 0;
	ohlen = 0;
	dsock = dst;
	rport = 0;
	control = 0;
	ctlarg = 0;
	incomplete = 0;

	((char*)ibuff)[rleng] = 0;

	if( sp->p_proto == P_BSOCKS ){
		if( rleng == 0 && sp->p_EOF ){
			LE(LOG,"[%x] BSOCKS closed\n",src);
			sp->p_closing |= CLOSE_BUSEOF;
			return 0;
		}
		ihlen = getPackHead(src,ibuff,rleng,
			&rport,&portid,&packid,&pleng,&control,&ctlarg);

		if( ihlen == -1 ){
			if( !sp->p_EOF ){
				LD(LOG,"[%x] INCOMPLETE HEADER\n",src);
				return 0;
			}else{
				ihlen = 0;
				oleng = rleng;
				goto EXIT;
			}
		}
		ibuff += ihlen;
		cleng = rleng - ihlen;

		if( flagment = sp->io[W_IN].p_flagment )
			pleng = flagment;
		
		if( 0 <= pleng && cleng < pleng ){
			LD(LOG,"[%x] PK incomplete %x/%x (%s)\n",
				src,cleng,pleng,
				ss(sp->io[W_IN].p_status));
			if( control & CTL_DATA
 /* && the destination port does not have multiple sources like BSOCKS */ ){
				incomplete = HEADSIZE;
				sp->io[W_IN].p_flagment = pleng - cleng;
				pleng = cleng;
			}else{	
				sp->io[W_IN].p_status = ST_RECV;
				return 0;
			}
		}else{
			sp->io[W_IN].p_flagment = 0;
			numPackRECV++;
		}
		if( control & CTL_HELLO ){
			LE(LOG,"[%x] RECV HELO BSOCKS/%s\n",src,ibuff);
			oleng = pleng;
			goto EXIT;
		}
		if( control & CTL_CONNECTDO ){
LD(LOG,"####[%x] [%s:%d]\n",src,sp->p_bhost,sp->p_bport);
			connectFromBSOCKS(src,rport,ctlarg,ibuff,cleng);
			oleng = pleng;
			goto EXIT;
		}

		if( portid == 0 )
			portid = findLocalPort(rport);
		lport = dePortID(portid);

		if( lport < 0 ){
			/* notify the obsoletion to the peer ? */
			oleng = pleng;
			goto EXIT;
		}
		dsock = lport;
		lp = ports[lport];
		if( lp->p_rport == 0 ){
			lp->p_rport = rport;
LD(LOG, "[%x] PORT ASSOCIATED R=%x/L=%x\n",src,rport,portid);
		}
		if( control & CTL_CONNECTING ){
LD(LOG,"[%x] RECV CONNECTING R=%x/L=%x\n",src,rport,portid);
			if( OBUFSIZE < ctlarg )
				ctlarg = OBUFSIZE;
			lp->p_rbuff = ctlarg;
			lp->p_invoked = 1;
			lp->io[W_IN].p_status = ST_RECV;
			oleng = pleng; goto EXIT;
		}
		if( control & CTL_CONNECTED ){
LD(LOG,"[%x] RECV CONNECTED. R=%x/L=%x BUFFSIZE=0x%x\n",
sp->p_lport,rport,portid,ctlarg);
			if( OBUFSIZE < ctlarg )
				ctlarg = OBUFSIZE;
			lp->p_rbuff = ctlarg;
			lp->p_connected = 1;
			lp->io[W_IN].p_status = ST_RECV;
			oleng = pleng; goto EXIT;
		}
		if( control & CTL_ACCEPTED ){
LD(LOG,"[%x] RECV ACCEPTED. R=%x/L=%x BUFFSIZE=0x%x\n",
sp->p_lport,rport,portid,ctlarg);
		}
		if( control & CTL_SENT ){
LD(LOG,"[%x] RECV SENT #%d %d/%d(%d) -> R=%x/L=%x\n",
src,packid,lp->io[W_IN].p_remotetotal,lp->io[W_IN].p_iototal,
outstanding(lp),rport,portid);
			lp->io[W_IN].p_remotetotal = ctlarg;
			oleng = pleng; goto EXIT;
		}
		if( control & CTL_DATA ){
		}

		if( !incomplete )
		if( control & (CTL_CONNERR|CTL_EOF) ){
			lp->p_closing |= CLOSE_REMOTEPEER;
LD(LOG,"[%x] remote[%x] %s, status=IN[%s] OUT[%s,%d/%d]\n",
dsock,lp->p_rport,sctl(control),
ss(lp->io[W_IN].p_status),
ss(lp->io[W_OUT].p_status),
lp->io[W_OUT].p_rwcc,lp->io[W_OUT].p_bleng);
			if( pleng == 0 ){
				oleng = pleng; goto EXIT;
			}
		}
	}
	if( 0 <= pleng )
		oleng = pleng;
	else	oleng = cleng;

	dp = ports[dsock];
	if( dp == NULL ){
		LD(LOG,"[%x] IGNORE relay to bogus port #%x (%d)\n",
			src,dsock,oleng);
		goto EXIT;
	}
	if( waitFlushed(sp,oleng) ){
		/* wait until enough amount of output is flushed */
		return 0;
	}else
	if( dp->io[W_OUT].p_status != ST_READY ){
		int bleng = dp->io[W_OUT].p_bleng;
		int rwcc = dp->io[W_OUT].p_rwcc;
		int hsize;

		if( dp->p_proto == P_BSOCKS )
			hsize = HEADSIZE;
		else	hsize = 0;
		
if( oleng == 0 )
LE(LOG,"#### ERROR? [%x]->%x SEND 0 ? control=%s\n",
src,dsock,sctl(control));

		if( bleng+hsize+oleng < OBUFSIZE ){
			if( 0 < bleng )
			LD(LOG,"[%x] add output (%x+%x >> %x/%x)\n",
				dp->p_lport,hsize,oleng,rwcc,bleng);
		}else
		if( sp->p_proto == P_BSOCKS
		&& (bleng-rwcc+hsize+oleng) <= OBUFSIZE ){
			if( OBUFSIZE < bleng+hsize+oleng )
				shift_buff(dp);
		}else{
			sp->io[W_IN].p_waitdst = dsock;
			sp->io[W_IN].p_waitingcc = ihlen+oleng;
			sp->io[W_IN].p_status = ST_WAIT_SEND;
			enQwaiting(sp->p_lport);
			sp->io[W_IN].p_pendingcc = pleng;
			sp->io[W_IN].p_pendingto = dsock;
			return 0;
		}
	}
	sp->io[W_IN].p_pendingcc = 0;
	sp->io[W_IN].p_pendingto = 0;

	if( dp->p_proto == P_BSOCKS ){
		CStr(msg,256);
		ohlen = putPackHead(msg,sp,oleng,CTL_DATA,oleng);
		bcopy(msg,(char*)dp->io[W_OUT].p_buff+dp->io[W_OUT].p_bleng,ohlen);
		dp->io[W_OUT].p_bleng += ohlen;
		dp->io[W_OUT].p_pktotal += ohlen;
	}

	putMSG(dp->p_lport,ibuff,oleng);

EXIT:
	if( incomplete ){
		sp->io[W_IN].p_rwcc = incomplete;
		sp->io[W_IN].p_pktotal += oleng;
	}else{
		sp->io[W_IN].p_pkcount += 1;
		sp->io[W_IN].p_pktotal += ihlen+oleng;

/*
if(rleng-(ihlen+oleng))
LE(LOG,"[%x] relay bcopy(%d)\n",src,rleng-(ihlen+oleng));
*/

		bcopy(sp->io[W_IN].p_buff+(ihlen+oleng),
			(char*)sp->io[W_IN].p_buff,rleng-(ihlen+oleng));
		sp->io[W_IN].p_rwcc -= (ihlen+oleng);
	}
	sp->io[W_IN].p_status = ST_RECV;

	if( 3 < dbglev ){
		CStr(msg,0x1000);
		sprintf(msg,"[%d] PK_FORW %d+%d %d(%s)[%d]%d -> ",src,
			ohlen,oleng,src,
			ss(sp->io[W_IN].p_status),
			sp->io[W_IN].p_pkcount, ihlen+rleng);
		if( dp = ports[dsock] )
			Xsprintf(TVStr(msg),"(%d)%d(%s/%d)[%d]%d",dst,dsock,
			ss(dp->io[W_OUT].p_status),dp->io[W_OUT].p_bleng,
			dp->io[W_OUT].p_pkcount,ohlen+oleng);
		else	Xsprintf(TVStr(msg),"NULL(%d)",dst);
		LD(LOG,"%s\n",msg);
	}

	if( sp->io[W_IN].p_rwcc < 0 ){
		LD(LOG,"[%x] NEGATIVE RWCC %d\n",src,sp->io[W_IN].p_rwcc);
		exit(-1);
	}
	if( !incomplete && sp->io[W_IN].p_rwcc )
		relay(src,dst,0);
	return 1;
}
static void putMSG(int dsock,PCStr(buff),int len)
{	PORT *op;

	if( len == 0 )
		return;
	op = &ports[dsock]->io[W_OUT];
	bcopy(buff,(char*)op->p_buff+op->p_bleng,len);
	op->p_bleng += len;
	op->p_status = ST_SEND;
	op->p_pkcount += 1;
	op->p_pktotal += len;
}

static int putPackHead(char msg[],IOPORT *pp,int leng,int control,int ctlarg)
{	int hleng;
	int32 pack[8]; /**/
	int pi;

	if( pp->p_EOF ){
		control |= CTL_EOF;
		pp->p_sentEOF = 1;
	}

	PACKID++;
	numPackSEND++;

	pack[M_CTLTYPE]  = control;
	pack[M_CTLARG]   = ctlarg;
	pack[M_SENDER]   = enPortID(pp);
	pack[M_RECEIVER] = pp->p_rport;
	pack[M_PACKID]   = PACKID;
	pack[M_PACKLENG] = leng;
	for( pi = 0; pi < M_PACKSIZE; pi++ )
		pack[pi] = htonL(pack[pi]);
	hleng = HEADSIZE;
	bcopy(pack,msg,hleng);

LD(LOG,"[%x] PK_SEND %s/%x R=%x<L=%x ID=%d LENG=%x/%x\n",
pp->p_lport, sctl(control),ctlarg,
pp->p_rport,enPortID(pp), PACKID,leng,hleng+leng);

	return hleng;
}

static int getPackHead(int src,PCStr(msg),int rleng,int *rport,int *portid,int *packid,int *pleng,int *control,int *ctlarg)
{	int32 pack[8]; /**/
	int pi;

	if( rleng < HEADSIZE )
		return -1;

	bcopy(msg,pack,HEADSIZE);
	for( pi = 0; pi < M_PACKSIZE; pi++ )
		pack[pi] = ntohL(pack[pi]);
	*control = pack[M_CTLTYPE];
	*ctlarg  = pack[M_CTLARG];
	*rport   = pack[M_SENDER];
	*portid  = pack[M_RECEIVER];
	*packid  = pack[M_PACKID];
	*pleng   = pack[M_PACKLENG];

LD(LOG,"[%x] PK_RECV %s/%x R=%x>L=%x ID=%d LENG=%x\n",
src, sctl(*control),*ctlarg, *rport,*portid, *packid,*pleng);

	return HEADSIZE;
}

static void putCntrlMSG(IOPORT *bp,IOPORT *lp,int cntrl,int ctlarg)
{	CStr(msg,128);
	int len;

	if( bp == NULL ){
fprintf(LOG,"## ERROR: [%x] putCntrlMSG(NULL) BSOCKS closed ?\n",lp->p_lport);
		return;
	}
	len = putPackHead(msg,lp,0,cntrl,ctlarg);
	putMSG(bp->p_lport,msg,len);
}
static void genCntrlMSG(int bsock,int rport,int control,int ctlarg)
{	IOPORT lb;

	lb.p_lport = 0;
	lb.p_portid = 0;
	lb.p_rport = rport;
	putCntrlMSG(ports[bsock],&lb,control,ctlarg);
}
static void ackBSOCKS(IOPORT *pp,PCStr(ver))
{	CStr(msg,256);
	CStr(hello,128);
	int hlen,blen;
	CStr(srchost,256);

	getpeerName(pp->p_lport,AVStr(srchost),"%A:%P");
	LE(LOG,"[%x] ThruWay from %s\n",enPortID(pp),srchost);

LD(LOG,"[%x] RETN HELO BSOCKS/%s connected, peer/%s\n",
pp->p_lport,BSOCKS_VER,ver);
	sprintf(hello,"%s",BSOCKS_VER);
	blen = strlen(hello) + 1;
	hlen = putPackHead(msg,pp,blen,CTL_HELLO,OBUFSIZE);
	Xstrcpy(DVStr(msg,hlen),hello);
	putMSG(pp->p_lport,msg,hlen+blen);
	LD(LOG,"[%x] SENT HELO BSOCKS %s\n",pp->p_lport,msg);
}
static void shift_buff(IOPORT *dp)
{	int bleng,rwcc;

	if( 0 < (rwcc = dp->io[W_OUT].p_rwcc) ){
		refQStr(buff,dp->io[W_OUT].p_buff); /**/
		buff  = (char*)dp->io[W_OUT].p_buff;
		bleng = dp->io[W_OUT].p_bleng;
		Bcopy(buff+rwcc,buff,bleng-rwcc);
		dp->io[W_OUT].p_bleng -= rwcc;
		dp->io[W_OUT].p_rwcc = 0;
	}
}

static void set_connected(int ssock,int dsock)
{	IOPORT *pp;

	pp = ports[ssock];
	if( pp->p_srcsock == 0 ){
		/*LD(LOG,"[%x] first (default) connection\n",ssock);*/
		pp->p_srcsock = dsock;
		pp->p_dstsock = dsock;
		pp->io[W_IN].p_status  = ST_RECV;
		pp->io[W_OUT].p_status = ST_READY;
		notify_connected(pp,dsock);
	}else{
		/*LD(LOG,"[%x] second connection\n",ssock);*/
	}
/*
	if( ports[dsock]->p_proto == P_BSOCKS )
		pp->io[W_IN].p_status = ST_RCONNECT;
*/
}

static void set_BUSBUF(int bsock){
	PORT *ip = &ports[bsock]->io[W_IN];
	free((char*)ip->p_buff);
	setQStr(ip->p_buff,(char*)malloc(OBUFSIZE),OBUFSIZE);
	ip->p_bsize = OBUFSIZE;
}

#define NB_RETRY(errno)	\
	(errno==EINPROGRESS||errno==EWOULDBLOCK||errno==EALREADY||errno==EAGAIN)

static int connError(PCStr(where),int sock,PCStr(host),int port,int _errno)
{
	if( sock < 0 )
		return 1;
	if( NB_RETRY(_errno) )
		return 0;
	if( IsConnected(sock,NULL) )
		return 0;

	LE(LOG,"[%x] %s connect(%s:%d) ERRNO=%d\n",sock,where,host,port,_errno);
	return 1;
}
static int try_connect(int dsock)
{	int ssock;
	IOPORT *sp,*dp;
	IOPORT *PP;
	int errno_sav;
	int rcode;
	const char *host;
	int port;
	CStr(callback,128);

	dp = ports[dsock];

	if( *ports[dsock]->p_bhost && ports[dsock]->p_bport){
		int bsock;

		host = ports[dsock]->p_bhost;
		port = ports[dsock]->p_bport;
		bsock = findBSOCKS(host,port);
		if( 0 <= bsock ){
			connectAtRemote(bsock,ports[dsock]->p_srcsock);
			return 0;
		}
	}else{
		host = ports[dsock]->p_dsthost;
		port = ports[dsock]->p_dstport;
	}
	ssock = ports[dsock]->p_srcsock;
	PP = ports[ssock];
	enQactive(dsock);

	errno = 0;
	rcode = __connectServer(dsock,"Socket","BSOCK",host,port /*,1*/);
	errno_sav = errno;
	if( connError("try_connect",dsock,dp->p_dsthost,dp->p_dstport,errno) ){
		del_port(dsock);
		return -1;
	}
	LD(LOG,"[%x] connect(%d,%s:%d) = %d %d\n",
	dp->p_srcsock,dsock,dp->p_dsthost,dp->p_dstport,rcode,errno_sav);

	if( NB_RETRY(errno_sav) ){
		ports[dsock]->io[W_OUT].p_status = ST_CONNECT;
		notify_connectingR(dsock,errno_sav);
		return 0;
	}

	if( IsConnected(dsock,NULL) )
		rcode = 0;
	else{
		LE(LOG,"[%x] CONNECTION ERROR %s:%d\n",dsock,
			dp->p_dsthost,dp->p_dstport);
		rcode = -1;
	}

	if( rcode == 0 ){
		numConnect++;
		ports[dsock]->p_srcsock = ssock;
		ports[dsock]->p_dstsock = ssock;
		ports[dsock]->io[W_IN].p_status  = ST_RECV;
		ports[dsock]->io[W_OUT].p_status = ST_READY;
		/* if not multiplex protocol */

		if( *ports[dsock]->p_bhost && ports[dsock]->p_bport ){
			CStr(buff,1024);

			setsockbuf(dsock,BSOCKBUFSIZE,BSOCKBUFSIZE);
			set_nodelay(dsock,1);
			set_BUSBUF(dsock);
sprintf(callback,"%s:%d",Svhost0,svport0);
			sprintf(buff,"BSOCKS/%s %s\r\n",BSOCKS_VER,callback);
LE(LOG,"[%x] SEND HELO BSOCKS/%s connect\n",dsock,BSOCKS_VER);
			putMSG(dsock,buff,strlen(buff));
			ports[dsock]->p_proto = P_BSOCKS;
			set_connected(ssock,dsock);
			connectAtRemote(dsock,ssock);
		}else{
			setsockbuf(dsock,IBUFSIZE,OBUFSIZE);
			set_connected(ssock,dsock);
			notify_connectedR(dsock,errno_sav);
			if( ports[ssock]->io[W_IN].p_rwcc ){
				LD(LOG,"[%x] FLUSH INITIAL INPUT (%d)->[%d]\n",
					ssock,PP->io[W_IN].p_rwcc,dsock);
				relay(ssock,dsock,0);
			}
		}
	}else
	if( rcode < 0 ){
		if( ports[ssock]->p_proto == P_BSOCKS ){
			LE(LOG,"[%x] should close RPORT=%d\n",
				dsock,ports[dsock]->p_rport);
			ports[dsock]->p_closing |= CLOSE_CONNERROR;
			ports[dsock]->p_EOF |= CLOSE_CONNERROR;
			relay(dsock,ssock,0);
		}else{
			del_port(ssock);
			del_port(dsock);
		}
	}else{
		ports[dsock]->io[W_OUT].p_status = ST_CONNECT;
		notify_connectingR(dsock,errno_sav);
	}
	return 0;
}

/*
 *	request connection at remote router
 */
static void connectAtRemote(int bsock,int ssock)
{	IOPORT *pp;
	CStr(cmd,256);
	CStr(msg,OBUFSIZE*2);
	int hleng,cleng,bleng;

	pp = ports[ssock];
	sprintf(cmd,"%s:%d\r\n",pp->p_dsthost,pp->p_dstport);
	cleng = strlen(cmd);
	bleng = pp->io[W_IN].p_rwcc;

	hleng = putPackHead(msg,pp,cleng+bleng,CTL_CONNECTDO,OBUFSIZE);
	bcopy(cmd,msg+hleng,cleng);
	bcopy(pp->io[W_IN].p_buff,msg+hleng+cleng,bleng);
	msg[hleng+cleng+bleng] = 0;

	putMSG(bsock,msg,hleng+cleng+bleng);
	set_connected(ssock,bsock);
	pp->p_connectingR = 1;

pp->p_rbuff = 4096; /* default buffer size */

	if( bleng ){
		pp->io[W_IN].p_rwcc = 0;
/*
		pp->io[W_IN].p_status = ST_RCONNECT;
*/
LD(LOG,"[%x] PREFECHED REQUEST %x %x\n",pp->p_lport,bleng,
ports[bsock]->io[W_OUT].p_bleng);
	}else{
		if( 32 < time(NULL) - pp->p_ctime ){
LD(LOG,"[%x] ## EMPTY REQUEST BUFFER: TIMEOUT\n",pp->p_lport);
			pp->p_closing = CLOSE_INITERROR;
		}else
LD(LOG,"[%x] ## EMPTY REQUEST BUFFER\n",pp->p_lport);
	}
}
static void connectFromBSOCKS(int bsock,int rport,int rbuff,PCStr(cmd),int clen)
{	CStr(host,512);
	int port;
	CStr(bhost,512);
	int bport;
	int dsock;
	int errno_sav;
	IOPORT *pp,*bp;
	const char *ep;
	int mleng;

	if( OBUFSIZE < rbuff )
		rbuff = OBUFSIZE;

	init_bhostport(AVStr(bhost),&bport);
	Xsscanf(cmd,"%[^:]:%d/%[^:]:%d",AVStr(host),&port,AVStr(bhost),&bport);

	errno = 0;
	if( 100000 <= port ){
		CStr(spec,128);
		dsock = Socket1("bsocks",-1,"inet","tcp","bsocks", VStrNULL,0,
			NULL,0, 0,NULL,0);
		LD(LOG,"[%x] stab descriptor for remote ACCEPT\n",dsock);
		if( 0 <= dsock ){
			new_port("FromBSOCKS",bsock,dsock);
			pp = ports[dsock];
			strcpy(pp->p_dsthost,host);
			pp->p_accport = port;
		}
		sprintf(spec,"%s:%d:%d",host,port-100000,1);
		findASOCK(spec,dsock);
	}else
	dsock = newsocket("FromBSOCKS",bsock,host,port);
	errno_sav = errno;
	if( dsock < 0 ){
		genCntrlMSG(bsock,rport,CTL_CONNERR,0);
		return;
	}
	pp = ports[dsock];
	pp->p_rport = rport;
	pp->p_rbuff = rbuff;
	pp->p_srcsock = bsock;
	pp->p_dstsock = bsock;
	if( bhost[0] && bport ){
		strcpy(pp->p_bhost,bhost);
		pp->p_bport = bport;
	}
	enQactive(dsock);

	if( clen && (ep = strchr(cmd,'\n')) ){
		ep++;
		mleng = clen - (ep - cmd);
		if( 0 < mleng ){
			bcopy(ep,(char*)pp->io[W_OUT].p_buff+pp->io[W_OUT].p_bleng,
				mleng);
			pp->io[W_OUT].p_bleng += mleng;
		}
	}

	if( pp->p_accport ){
		pp->io[W_IN].p_status = 0;
		pp->io[W_OUT].p_status = ST_ACCEPT_WAIT;
	}else
	if( NB_RETRY(errno_sav) ){
		ports[dsock]->io[W_OUT].p_status = ST_CONNECT;
		notify_connectingR(dsock,errno_sav);
	}else{
		LD(LOG,"[%x] connected at the first trial.\n",dsock);
		if( 0 < pp->io[W_OUT].p_bleng )
			pp->io[W_OUT].p_status = ST_SEND;
		else	ports[dsock]->io[W_OUT].p_status = ST_READY;
		ports[dsock]->io[W_IN].p_status = ST_RECV;

		bp = ports[bsock];
		RIDENT_send(dsock,bp->p_sockname,bp->p_peername,NULL);
	}
}
/*
 *  CONNECTING message
 *	to the remote initiator can be ommitted and substituted by
 *	CONNECTED message if the connection establised immediately.
 */
static void notify_connectingR(int sock,int _errno)
{	IOPORT *pp,*bp;
/*
	pp = ports[sock];
	if( pp->p_rport && pp->p_connecting == 0 ){
LD(LOG,"[%x] SEND CONNECTING ->[%x]->[%x] errno=%d (%s:%d)\n",
sock,pp->p_dstsock,pp->p_rport,_errno,pp->p_dsthost,pp->p_dstport);
		bp = ports[pp->p_srcsock];
		putCntrlMSG(bp,pp,CTL_CONNECTING,OBUFSIZE);
		pp->p_connecting = 1;
	}
*/
}
static void notify_connectedR(int sock,int _errno)
{	IOPORT *pp,*bp;

	pp = ports[sock];
/*
	if( pp->p_rport ){
LD(LOG,"[%x] SEND CONNECTED -->[%x]->[%x] errno=%d (%s:%d)\n",
sock,pp->p_dstsock,pp->p_rport,_errno,pp->p_dsthost,pp->p_dstport);
		bp = ports[pp->p_srcsock];
		putCntrlMSG(bp,pp,CTL_CONNECTED,OBUFSIZE);
	}
*/
	if( pp->io[W_OUT].p_bleng ){
LD(LOG,"[%x] FLUSH INITIAL OUTPUT (%d)\n",sock,pp->io[W_OUT].p_bleng);
		pp->io[W_OUT].p_status = ST_SEND;
	}
}

static int try_identify(IOPORT *PP,int IO)
{	int proto;
	int sockx;

	sockx = P_SOCK;
	if( (proto = identify_protocol(PP,IO)) < 0 ){
		PP->p_closing = CLOSE_INITERROR;
		del_port(sockx);
		return -1;
	}
	if( P_PROTO == 0 ) /* not yet identified */
		return 0;

	if( proto == P_BSOCKS ){
		setsockbuf(sockx,BSOCKBUFSIZE,BSOCKBUFSIZE);
		set_nodelay(sockx,1);
		P_STATUS = ST_RECV;
	}else{
		setsockbuf(sockx,IBUFSIZE,OBUFSIZE);
		P_STATUS = ST_RESOLV;
	}
	return proto;
}
static void clock1(int sockx,int IO)
{	IOPORT *PP;
	int clsock;
	int ssock;
	int rcc,wcc;
	int errno_sav;
	const char *host;
	CStr(srchost,256);
	int port;
	CStr(sockname,256);
	CStr(peername,256);
	CStr(accepted,128);

	PP = ports[sockx];
	if( PP == NULL )
		return;

	switch( P_STATUS ){
	    case ST_ACCEPT:
		clsock = ACCEPT(sockx,1,-1,0);
		if( clsock < 0 && errno == EAGAIN ){
			LD(LOG,"[%d] ST_ACCEPT retry lator ????\n",sockx);
			return;
		}

		setNonblockingIO(clsock,1);
		numAccept++;

		getpairName(clsock,AVStr(sockname),AVStr(peername));
		sprintf(accepted,"ACCEPTED %s %s\r\n",peername,sockname);

		if( ssock = ports[sockx]->p_accsock ){
			IOPORT *sp = ports[ssock];
			if( sp == 0 ){
LD(LOG,"[%x] ST_ACCEPT (remote) = %d < srcsock=%d ****DANGLING\n",
sockx,clsock,ssock);
/* DEQ */
ports[sockx]->p_closing = CLOSE_LOCALEOF;
close(clsock);
				break;
			}
			if( sp->p_accport ){
				IOPORT *bp;
				CStr(msg,128);
				int len,alen;

LD(LOG,"[%x] ST_ACCEPT (remote) = %d < srcsock=%d\n",sockx,clsock,ssock);
				dup2(clsock,ssock);
				close(clsock);
				clsock = ssock;
				sp->io[W_OUT].p_status = ST_READY;
				sp->io[W_IN].p_status = ST_RECV;

/* DEQ */
ports[sockx]->p_accsock = sp->p_acceptQ;
LD(LOG,"[%x] [%x] NEXT ACCEPT = %d\n",sockx,clsock,sp->p_acceptQ);
if( ports[sockx]->p_accsock == 0 )
			ports[sockx]->p_closing |= CLOSE_LOCALEOF;

				alen = strlen(accepted);
				bp = ports[sp->p_srcsock];
			len = putPackHead(msg,sp,alen,CTL_ACCEPTED,OBUFSIZE);
				Xstrcpy(DVStr(msg,len),accepted);
				putMSG(bp->p_lport,msg,len+alen);
				break;
			}
		}

		new_port("ST_ACCEPT",sockx,clsock);
		PP = ports[clsock];
		P_STATUS = ST_INIT;
		enQactive(clsock);

		{
			CStr(sockname,256);
			CStr(peername,256);
			getpairName(clsock,AVStr(sockname),AVStr(peername));
			PP->p_sockname = stralloc(sockname);
			PP->p_peername = stralloc(peername);
		}

		if( 1 < dbglev ){
		getpeerName(clsock,AVStr(srchost),"%H:%P");
		LD(LOG,"<%x>(%d) acc %s\n",PP->p_portid,ALIVEPORTS,srchost);
		LD(LOG,"[%x] ST_ACCEPT = [%x] %s\n",sockx,clsock,srchost);
		}
		if( ssock = ports[sockx]->p_accsock ){
			IOPORT *sp = ports[ssock];

			LE(LOG,"[%x] ACCEPTED [%x]->[%x]\n",sockx,clsock,ssock);

/* DEQ */
ports[sockx]->p_accsock = sp->p_acceptQ;
LD(LOG,"[%x] [%x] NEXT ACCEPT = %d\n",sockx,clsock,sp->p_acceptQ);
if( ports[sockx]->p_accsock == 0 )
			ports[sockx]->p_closing = CLOSE_LOCALEOF;

			PP->p_srcsock = ssock;
			PP->p_dstsock = ssock;
			PP->io[W_IN].p_status = ST_RECV;
			PP->io[W_OUT].p_status = ST_READY;
			sp->p_srcsock = clsock;
			sp->p_dstsock = clsock;
			sp->io[W_IN].p_status = ST_RECV;
			sp->io[W_OUT].p_status = ST_SEND;
/*
			getpeerName(clsock,srchost,"%A:%P");
			sprintf(sp->io[W_OUT].p_buff,"ACCEPTED %s\r\n",srchost);
*/
			strcpy(sp->io[W_OUT].p_buff,accepted);
			sp->io[W_OUT].p_bleng = strlen(sp->io[W_OUT].p_buff);
		}
		break;

	    case ST_INIT:
		errno = 0;
		rcc = recv(sockx,(char*)P_BUFF+P_RWCC,P_REMCC,0);
		errno_sav = errno;
		LD(LOG,"[%x] ST_INIT = %d E=%d\n",sockx,rcc,errno_sav);

		if( rcc <= 0 ){
			if( errno_sav == EWOULDBLOCK )
				break;
			PP->p_EOF |= CLOSE_LOCALEOF;
			del_port(sockx);
			break;
		}
		if( 0 < rcc ){
			P_IOTOTAL += rcc;
			P_IOCOUNT += 1;
		}
		P_RWCC += rcc;
		try_identify(PP,IO);
		if( P_STATUS != ST_RESOLV )
			break;


	case ST_RESOLV:
		RSLV_TIMEOUT = 0;
		RSLV_TIMEDOUT = 0;
		if( strcmp(P_DHOST,"*") != 0 )
		if( gethostbyname(P_DHOST) == 0 ){
fprintf(LOG,"## ERROR: [%x] TIMEDOUT=%d %s\n",sockx,RSLV_TIMEDOUT,P_DHOST);
			if( !RSLV_TIMEDOUT || 5 < ++PP->p_resfail
			 || !IsConnected(sockx,NULL) ){
				del_port(sockx);
				break;
			}
			LD(LOG,"[%x] %d RESOLVING DHOST=%s...\n",sockx,
				PP->p_resfail,P_DHOST);
			P_STATUS = ST_RESOLV;
			break;
		}

		if( *P_BHOST && P_BPORT ){
			int bsock;
			bsock = findBSOCKS(P_BHOST,P_BPORT);
			if( 0 < bsock ){
				connectAtRemote(bsock,sockx);
				break;
			}
		}
		if( *P_BHOST && P_BPORT ){
			host = P_BHOST;
			port = P_BPORT;
		}else{
			host = P_DHOST;
			port = P_DPORT;
		}
		errno = 0;
		P_DSOCK = newsocket("ST_INIT",sockx,host,port);
		if( P_DSOCK < 0 ){
			LE(LOG,"[%x] connect error: %s:%d sock=%d errno=%d\n",
				P_DSOCK,host,port,P_DSOCK,errno);
			del_port(sockx);
			break;
		}

		ports[P_DSOCK]->io[W_OUT].p_status = ST_CONNECT;
		enQactive(P_DSOCK);

		ports[P_DSOCK]->p_srcsock = sockx;
		ports[P_DSOCK]->p_dstsock = sockx;
		strcpy(ports[P_DSOCK]->p_dsthost,P_DHOST);
		ports[P_DSOCK]->p_dstport = P_DPORT;
		strcpy(ports[P_DSOCK]->p_bhost,P_BHOST);
		ports[P_DSOCK]->p_bport = P_BPORT;
		ports[P_DSOCK]->p_rport = P_RPORT;
		P_RPORT = 0;
		/* should watch EOF before conection establied ... */

		P_STATUS = ST_RECV;
		break;

	    case ST_CONNECT:
		LD(LOG,"[%x] ST_CONNECT ready (%s:%d)\n",sockx,P_DHOST,P_DPORT);
		try_connect(sockx);
		if( P_STATUS != ST_CONNECT )
		if( RIDENT_SERVER ){
			IOPORT *sp;
			sp = ports[PP->p_srcsock];
			RIDENT_send(sockx,sp->p_sockname,sp->p_peername,NULL);
		}
		if( P_STATUS != ST_SEND )
			break;

	    case ST_SEND:
		numSEND++;

if( P_REMCC <= 0 )
LD(LOG,"[%x]%sST_SEND(%x+%x/%x)E=%d (%x/%x) SEND EMPTY?\n",
sockx,P_PROTO==P_BSOCKS?"*":" ",
P_RWCC,0,P_REMCC,0, P_IOTOTAL,P_IOCOUNT);

		if( 0 < P_REMCC ){
			errno = 0;
			wcc = send(sockx,P_BUFF+P_RWCC,P_REMCC,0);
			errno_sav = errno;

LD(LOG,"[%x]%sST_SEND(%x+%x/%x)E=%d (%x/%x)\n",
sockx,P_PROTO==P_BSOCKS?"*":" ",
P_RWCC,wcc,P_REMCC,errno_sav, P_IOTOTAL,P_IOCOUNT);

			if( wcc <= 0 ){
				if( errno_sav == EWOULDBLOCK )
					break;
LD(LOG,"[%x] #### SIGPIPE L=%x>R=%x\n",sockx,enPortID(PP),P_RPORT);
				ssock = P_SSOCK;
				if( P_RPORT ){
					notifyEOF(PP);
					PP->p_EOF |= CLOSE_LOCALEOF;
				}
				del_port(sockx);
				del_port(ssock);
				break;
			}else{
				P_IOTOTAL += wcc;
				P_IOCOUNT += 1;
			}
			P_RWCC += wcc;
			notifyFlushed(PP,wcc);
		}
		if( P_REMCC == 0 ){
			P_STATUS = ST_READY;
			P_BUFLEN = 0;
			P_RWCC = 0;

			if( ports[sockx]->p_closing )
				del_port(sockx);
		}
		break;

	    case ST_RECV:
		numRECV++;
		if( P_REMCC == 0 ){
			LD(LOG,"[%x] ST_RECV 0 (%x)\n",sockx,P_RWCC);
			sleep(1);
			relay(sockx,P_DSOCK,0);
			break;
		}

		errno = 0;
		rcc = recv(sockx,(char*)P_BUFF+P_RWCC,P_REMCC,0);
		errno_sav = errno;

LD(LOG,"[%x]%sST_RECV(%x+%x/%x)E=%d (%x/%x)\n",
sockx,P_PROTO == P_BSOCKS?"*":" ",
P_RWCC,rcc,P_REMCC,errno_sav, P_IOTOTAL,P_IOCOUNT);

		if( rcc <= 0 ){
			/* non-blocking read may return rcc=0,errno=0 ... */
			if( errno_sav != EWOULDBLOCK )
				P_EOF |= CLOSE_LOCALEOF;
			if( P_RWCC == 0 ){
				if( P_EOF ){
					notifyEOF(PP);
					del_port(P_SOCK);
				}
				break;
			}
			rcc = 0;
		}else{
			P_IOTOTAL += rcc;
			P_IOCOUNT += 1;

			if( rcc < P_REMCC )
			if( P_PROTO != P_BSOCKS )
			if( P_IOTOTAL < 4096 )
			if( PollIn(sockx,1) && Peek1(sockx) <= 0 ){
				LD(LOG,"[%x] EOF after 0x%x\n",sockx,rcc);
				P_EOF |= CLOSE_LOCALEOF;
			}
		}
		if( 0 < rcc ){
			P_RWCC += rcc;
			setVStrEnd(P_BUFF,P_RWCC);
		}

		relay(sockx,P_DSOCK,0);

		if( rcc <= 0
		 || PP->p_EOF && P_RWCC==0 && PP->io[W_OUT].p_bleng==0 ){
			IOPORT *dp;

			PP->p_closing |= CLOSE_LOCALEOF;
			if( (dp = ports[P_DSOCK]) && dp->p_proto != P_BSOCKS )
				dp->p_closing |= CLOSE_LOCALPEER;
			break;
		}
		break;	
	}
}

static int waitFlushed(IOPORT *pp,int wcc)
{	int status;

	if( pp->p_proto == P_BSOCKS )
		return 0;
	if( ports[pp->p_srcsock]->p_proto != P_BSOCKS )
		return 0;
	if( pp->io[W_IN].p_rwcc == 0 )
		return 0;

	status = pp->io[W_IN].p_status;
	if( status == ST_WAIT_RFLUSH )
		return 1;

	if( pp->p_rbuff < outstanding(pp)+wcc ){
LD(LOG,"[%x] SUSP %d BS=%x:%x\n",pp->p_lport,outstanding(pp),
OBUFSIZE,pp->p_rbuff);
		pp->io[W_IN].p_waitwcc = wcc;
		pp->io[W_IN].p_statussave = status;
		pp->io[W_IN].p_status = ST_WAIT_RFLUSH;
		enQwaiting(pp->p_lport);
		numSUSP++;
		return 1;
	}
	return 0;
}
static void pollFlushed(IOPORT *pp)
{	int status;
	int wcc;

	wcc = pp->io[W_IN].p_waitwcc;
	if( outstanding(pp)+wcc <= pp->p_rbuff ){
LD(LOG,"[%x] RESM %d L=%x/R=%x\n",
pp->p_lport,outstanding(pp),enPortID(pp),pp->p_rport);
		status = pp->io[W_IN].p_status = pp->io[W_IN].p_statussave;
		if( status == ST_RECV && pp->io[W_IN].p_rwcc ){
			/* duplicate enQwaiting may occur .. */
			relay(pp->p_lport,pp->p_dstsock,0);
		}
	}
}
static void notifyFlushed(IOPORT *pp,int wcc)
{	IOPORT *bp;
	PORT *op;
	int isize;

	if( pp->p_rport == 0 )
		return;

	bp = ports[pp->p_srcsock];
	if( bp == NULL )
		return;

	op = &pp->io[W_OUT];

	if( pp->p_EOF ){
		notifyEOF(pp);
		return;
	}
	isize = op->p_iototal - op->p_notifiedcc;

	/* Reduce flow control messae to 1/10 or less ... */
	/* the peer may be waiting for sending a large packet to write
	 * which size is full of buffer, thus when the buffer become
	 * empty, it must be informed anyway ???
	 */
	if( /*op->p_rwcc < op->p_bleng &&*/ isize < OBUFSIZE/4 ){
		Nn++;
		return;
	}else	Ni++;

	if( op->p_notifiedcc < op->p_iototal ){
		putCntrlMSG(bp,pp,CTL_SENT,op->p_iototal);

LD(LOG,"[%x] SEND SENT #%d %d/%d -> R=%x/L=%x (%d/%d/%s) INF=%d:IGN=%d\n",
pp->p_lport,PACKID,isize,op->p_iototal,
pp->p_rport,enPortID(pp),op->p_rwcc,op->p_bleng,ss(bp->io[W_OUT].p_status),
Ni,Nn);
		op->p_notifiedcc = op->p_iototal;
	}
}

/*
 * notify connection reset to the peer port at a remote router
 */
static void notifyEOF(IOPORT *pp)
{	IOPORT *bp;

LD(LOG,"[%x] notifyEOF R=%x B=[%s:%d] connectingR=%d\n",
pp->p_lport,pp->p_rport,pp->p_bhost,pp->p_bport,pp->p_connectingR);

	if( pp->p_rport == 0 )
	if( pp->p_connectingR == 0 )
		return;

	if( pp->p_sentEOF ){
fprintf(LOG,"[%x] ## don't send DUPLICATE EOF\n",pp->p_lport);
		return;
	}

	pp->p_sentEOF = 1;
	bp = ports[pp->p_srcsock];
	putCntrlMSG(bp,pp,CTL_EOF,0);
}
