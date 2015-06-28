const char *SIGN_spinach="{FILESIGN=spinach.c:20141022165616+0900:6d5712e8b172965e:Author@DeleGate.ORG:QAuaedIMjRwBwNOQV6i5Npwxzs5vGiO1LUZGAPvCx/z2/MaibLcm/aDgC8rvQcW099Jkdr9EknO0VzSUXBxHJ3eVBUQmhPQQydP4bqOafcJSwJaccO7R56eqsZ/8/qnDfJEhHyArArSsCPsxJtDo/36DRt1q461MBcYDDWLyasY=}";
/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2009 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	spinach.c
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
	A candidate of the kernel of DeleGate/10.X :)
	to replace SockMux, THRUWAY, VSAP, Coupler, relaysx(),
	Udpalrey, Tcprelay, Shio, ..., and HTTP, SOCKS, ...

History:
	090204	created
//////////////////////////////////////////////////////////////////////#*/

#include <ctype.h>
#include "vsocket.h"
#include "vsignal.h"
#include "delegate.h"
#include "fpoll.h"

/* should use va_list */
#ifdef daVARGS
#undef VARGS         
#define VARGS daVARGS
#define LINESIZE 4*1024       
#endif

#define TY_HTTP_REQ	1
#define TY_HTTP_RESP	2
#define TY_SOCKS_REQ	3
#define TY_SOCKS_RESP	4
#define ST_ZOMB		0x00000001
#define ST_IN_ACCEPT	0x00000002 /* for each entrance -Pport */
#define ST_IN_RESOLV	0x00000004
#define ST_IN_CONNECT	0x00000008
#define ST_IN_BIND	0x00000010
#define ST_IN_ACCTL	0x00000020
#define ST_IN_INPUT	0x00000040
#define ST_IN_OUTPUT	0x00000080

int eccLOGX_appReq = 0;
int eccLOGX_tcpCon = 0;
int eccLOGX_tcpAcc = 0;
int eccTOTAL_SERVED = 0;
int eccActivity = 0;

#ifndef SHUT_WR
#define SHUT_WR		SD_SEND /* 0 or 1 ? */
#define SHUT_RDWR	SD_BOTH /* 2 */
#endif
int ShutdownSocketRDWR(int fd){
	return shutdown(fd,SHUT_RDWR);
}
int shutdownWR(int fd){
	send(fd,"",0,0); // try pushing EoS ?
	return shutdown(fd,SHUT_WR);
}

/* '"DiGEST-OFF"' */
/* FrOM-HERE
##########################################################################
    CAUTION: re-distributing the copy of this file is not permitted.
##########################################################################
 */
/*
 * spike: simple protocol interpreter kernel ?
 * or pick...  * pickls ?
 * spice? spider? spilberg? spinach? spinat? spindle? spiral? spirit? spixe?
 */

#if 0 /*{*/
#define MAX_FD	128
typedef struct {
	char   *b_buf;
	int	b_size;
	int	b_from;
	int	b_peak;
} Buffer;
typedef struct {
	int	a_id;
	int	a_type;
	int	a_stat;
	FILE   *a_clfp;
	int	a_nclin; /* the number of input from clint */
	int	a_clsock;
	int	a_svsock;
	Buffer	a_ibuf;
	Buffer	a_obuf;
} Action;
typedef struct {
	int	f_mod;
	int	f_fc;
	int	f_ix[MAX_FD];
	FILE   *f_fp[MAX_FD];
	int	f_fd[MAX_FD];
	int	f_rd[MAX_FD];
} Fdv;
typedef struct {
	int	pi_aid;
	int	pi_nact;
	int	pi_lact; /* Last created active */
	Action	pi_actions[MAX_FD];
	Fdv	pi_fdv;
} PiContext;

static const char *pi_sstat(int st){
	switch( st ){
		case ST_IN_ACCEPT:  return "ACCEPT";
		case ST_IN_INPUT:   return "INPUT";
		case ST_IN_RESOLV:  return "RESOLV";
		case ST_IN_CONNECT: return "CONNECT";
		case ST_IN_BIND:    return "BIND";
	}
	return "?";
}

/*
 * BACKGROUND ACTIONS by thread for each
 */
static int pi_resolver(){
	return 0;
}
static int pi_connecter(){
	/* connect with PollOut() */
	return 0;
}
static int pi_binder(){
	/* bind with retry */
	return 0;
}
static int pi_acceptor(){
	/* accept with PollIn() */
	return 0;
}
static int pi_opener(){
	return 0;
}
static int pi_closer(){
	/* closing a socket (or file) */
	return 0;
}

void dumpacts(PiContext *Px){
	Action *ap1;
	int ai;

	fprintf(stderr,"---ACT(%d)\n",Px->pi_nact);
	for( ai = 0; ai < elnumof(Px->pi_actions); ai++ ){
		ap1 = &Px->pi_actions[ai];
		if( ap1->a_stat ){
			porting_dbg("ACT[%d] %X",ai,ap1->a_stat);
		}
	}
}
static int addact(PiContext *Px,int atype,int astat,FILE *clfp,int clsock){
	Action *ap1;
	Action *ap = 0;
	int ai;

	for( ai = 0; ai < elnumof(Px->pi_actions); ai++ ){
		ap1 = &Px->pi_actions[ai];
		if( ap1->a_id == 0 ){
			ap = ap1;
			break;
		}
		if( ap1->a_stat & ST_ZOMB ){
			ap = ap1;
			break;
		}
	}
	if( ap == 0 ){
		fprintf(stderr,"no more action (%d)\n",Px->pi_aid);
		return -1;
	}
	ap->a_id = ++Px->pi_aid;
	ap->a_type = atype;
	ap->a_stat = astat;
	ap->a_clfp = clfp;
	ap->a_clsock = clsock;
	Px->pi_nact++;
	return 0;
}
static int getfdv(PiContext *Px,Fdv *fdv){
	int ai;
	int ri = 0;
	Action *ap;

	for( ai = 0; ai < elnumof(Px->pi_actions); ai++ ){
		ap = &Px->pi_actions[ai];
		if( ap->a_stat == 0 ){
			continue;
		}
		if( ap->a_stat & ST_ZOMB ){
			continue;
		}
		fdv->f_ix[ri] = ai;
		fdv->f_fp[ri] = ap->a_clfp;
		fdv->f_fd[ri] = ap->a_clsock;
		ri++;
		if( Px->pi_nact <= ri ){
			break;
		}
	}
	fdv->f_fc = ri;
	fprintf(stderr,"---getfdv()=%d/%d\n",ri,Px->pi_nact);
	return ri;
}
static int delact(PiContext *Px,int ai,Fdv *fdv){
	Action *ap;

	fprintf(stderr,"---delact(%d)\n",ai);
	ap = &Px->pi_actions[ai];
	ap->a_stat = ST_ZOMB;
	fdv->f_mod++;
	return 0;
}
static int input1(PiContext *Px,Fdv *fdv,int ri){
	FILE *fp0;
	int ai0;
	IStr(buf,1024);
	int ch;
	Action *ap1;

	fp0 = fdv->f_fp[ri];
	ai0 = fdv->f_ix[ri];

	ap1 = &Px->pi_actions[ai0];
	if( ap1->a_nclin == 0 ){
		/* auto. detect the protocol */
	}

	if( ap1->a_type & TY_HTTP_REQ ){
		/* line by line mode, as HTTP */
		if( fgets(buf,sizeof(buf),fp0) == 0 ){
			delact(Px,ai0,fdv);
			fdv->f_mod++;
		}
		fprintf(stderr,"%d [%d][%d] %s",
			ap1->a_nclin,ri,fdv->f_fd[ri],buf);
		if( ap1->a_nclin == 0 ){
			/* decompose */
			/* cache */
			/* resolv */
			/* connect */
		}
		ap1->a_nclin += strlen(buf);
	}else{
		/* byte by byte mode, as SOCKS */
		ch = getc(fp0);
		fprintf(stderr,"[%d][%d] %X\n",ri,fdv->f_fd[ri],ch);
		if( ch == EOF ){
			/* remove the action */
			delact(Px,ai0,fdv);
			fdv->f_mod++;
		}
		ap1->a_nclin += 1;
	}
	return 0;
}

int spindle(PiContext *Px){
	int si;
	int nready;
	int ri;
	Fdv *fdv = &Px->pi_fdv;

	/* the port connected (via inetd or tty) */
	addact(Px,TY_HTTP_REQ,ST_IN_INPUT,stdin,0);

	/* add the port for accept (-Pxxx) */
	getfdv(Px,fdv);

	for( si = 0; ; si++ ){
		if( fdv->f_mod ){
			getfdv(Px,fdv);
		}
		if( fdv->f_fc <= 0 ){
			break;
		}
		nready = fPollIns(0,fdv->f_fc,fdv->f_fp,fdv->f_rd);
		if( nready <= 0 ){
			fprintf(stderr,"(%X)\n",nready);
			break;
		}
		for( ri = 0; ri < fdv->f_fc; ri++ ){
			if( fdv->f_rd[ri] <= 0 ){
				continue;
			}
			input1(Px,fdv,ri);
		}
	}
	dumpacts(Px);
	return 0;
}
int spinach_main(int ac,const char *av[]){
	PiContext Px;
	bzero(&Px,sizeof(PiContext));
	spindle(&Px);
	return 0;
}
#endif /*}*/
int spinach_main(int ac,const char *av[]){
	return 0;
}

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2009 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	ccsv.c
Author:		Yutaka Sato <y.sato@delegate.org>
Description:
History:
	090411	created
//////////////////////////////////////////////////////////////////////#*/
#include "proc.h"
/*
 * CCSV connection cache server
 * could be SOCKS compatible? (SOCKS with server-side connection cache)
 */
unsigned int trand1(unsigned int max);
Connection *SessionConn();
const char *ACTDIR();
int newSocket(PCStr(what),PCStr(opts));
int setosf_FL(const char *wh,const char *path,int fd,FILE *fp,const char *F,int L);
int server_open_localhost(PCStr(what),PVStr(path),int nlisten);
int setNonblockingSocket(int fd,int aon);
int VSA_getbyname(int cacheonly,PCStr(host),int port,VSAddr *vsa);
int HTTP_methodWithBody(PCStr(method));
int ClientCount(PCStr(host),PCStr(addr));

#define MAX_CONN 128

typedef struct {
	MStr(sv_acpath,256);
	int	sv_clock;
	int	sv_updateFdv;
	int	sv_id;
	int	sv_Acc;
	int	sv_Reu;
	int	sv_Err;
	int	sv_ErrId;
	int	sv_Max;
	int	sv_MaxBuf;
	int	sv_Rct;
	FileSize sv_Rcc;
	FileSize sv_Wcc;
	double	sv_Elps;
	MStr(sv_netif,256);
	int	sv_netifgot;
	int	sv_netifnum;
	int	sv_lSINGLEP;
	int	sv_lMULTIST;
	int	sv_lIMMREJECT;
	int	sv_lDONTROUTE_LOCAL;
} CCSV;
static CCSV Svcc;
#define SvccClock	Svcc.sv_clock
#define updateFdv	Svcc.sv_updateFdv
#define SvccId		Svcc.sv_id
#define SvccAcc		Svcc.sv_Acc
#define SvccReu		Svcc.sv_Reu
#define SvccErr		Svcc.sv_Err
#define SvccErrId	Svcc.sv_ErrId
#define SvccMax		Svcc.sv_Max
#define SvccMaxBuf	Svcc.sv_MaxBuf
#define SvccRcc		Svcc.sv_Rcc
#define SvccRct		Svcc.sv_Rct
#define SvccWcc		Svcc.sv_Wcc
#define Elps		Svcc.sv_Elps
#define SvccNetIF	Svcc.sv_netif
#define SvccNetIFgot	Svcc.sv_netifgot
#define SvccNetIFnum	Svcc.sv_netifnum
#define _lSINGLEP	Svcc.sv_lSINGLEP
#define _lMULTIST	Svcc.sv_lMULTIST
#define _lIMMREJECT	Svcc.sv_lIMMREJECT
#define _lDONTROUTE_LOCAL Svcc.sv_lDONTROUTE_LOCAL

static int ECC_bufSiz;
static int ECC_NumHttpReq;
static int ECC_NumHttpKa;
static int ECC_NumHttpKa1; /* switched to another server */
static int ECC_NumHttpKa2; /* disconnected by client */
static int ECC_NumHttpSw;
static int ECC_NumPipeSw;
static int ECC_NumReused;
static int ECC_LastActId;
static const char *ECC_LastAct = "-";
static int ECC_tmaz;
static double ECC_TimeForRes;
static int ECC_Res;

typedef struct {
	int	fd_fd;
	int	fd_handle;
	int	fd_mtu;
} FDesc;
typedef struct {
	int	ap_bufSiz;
	int	ap_bufRem;
	char   *ap_buf;
} AppBuf;
typedef struct {
	int	sa_buf[8];
} SAB;

#define KA_DO_11	0x0001	/* HTTP/1.1 */
#define KA_DO_Conn	0x0002	/* Connection: keep-alive */
#define KA_DO_PXConn	0x0004	/* Proxy-Connection: keep-alive */
#define KA_DO_KAlive	0x0008	/* Keep-Alive: */
#define KA_NO_10	0x0010	/* HTTP/1.0 */
#define KA_NO_Conn	0x0020	/* Connection: close */
#define KA_NO_PXConn	0x0040	/* Proxy-Connection: close */
#define KA_NO_Unk	0x0080
#define KA_DO_Inf	0x0100

typedef struct {
	double	cr_connSt;	/* the time of creation of the connection */
	double	cr_Timeout;
	double	cr_statSt;	/* current Status */
	double	cr_ckaSt;
	double  cr_irdySt;	/* the lasttime of input ready */
	double	cr_rdySt;	/* the lasttime of I/O ready not processed yet */
	double	cr_finSt;	/* finallization */
	double	cr_shutSt;	/* SHUT sent */
       FileSize cr_rcc[2];
       FileSize cr_wcc[2];

	int	cr_ix;
	int	cr_id;		/* unique id.: serial number */
	int	cr_para;
	int	cr_qflag;
	int	cr_rstat;
	int	cr_timeout;	/* conn. timeout, relay timeout, KA-timeout  */
	FDesc	cr_clSock;	/* client-side connection socket */
	FDesc	cr_svSock;	/* server-side connection socket */
	int	cr_svtid;	/* thread id. of the thread for the FTP/HTTP gateway */

	short	cr_err;
	int	cr_rct[2];
	int	cr_wct[2];

	int	cr_rcvd;
	int	cr_svcnt;
	int	cr_svka;
	int	cr_clcnt;
	int	cr_ccnum;
	SAB	cr_clsa;
	/*
	SAB	cr_clifsa;
	*/
	SAB	cr_rsvsa;	/* real destination server */
	SAB	cr_svsa;	/* next hop might be a proxy as SOCKS */
	SAB	cr_svifsa;
	int	cr_pcstat;
	int	cr_cstat;
    const char *cr_finStat;
	int	cr_endclock;
	short	cr_reused;
	short	cr_wrerr;
	AppBuf	cr_appBuf;

	char	cr_hqmeth;
	short	cr_hqstat;	/* HTTP request status */
	short	cr_hqst;
	short	cr_hqclka;
	short	cr_hqclKA;
	short	cr_hrsvka;
	short	cr_hrsvKA;

	short	cr_hqn;		/* HTTP requests (in keep-alive) */
	short	cr_hrn;		/* HTTP response */
	short	cr_hrendE;	/* HTTP ENDed without resp. body */
	short	cr_hrendC;	/* HTTP chunked reponse END */
	short	cr_hrendL;	/* HTTP Content-Length reponse END */
	char	cr_hrnobody;
	char	cr_hrenc;
	short	cr_delreqn;

	int	cr_hqclen;	/* Content-Length in HTTP req. */
	int	cr_hqrem;
	int	cr_hrlen;
	int	cr_hrrem;

	int	cr_sync;
} ConnReq;
#define cr_buf		cr_appBuf.ap_buf
#define cr_bufSiz	cr_appBuf.ap_bufSiz
#define cr_bufRem	cr_appBuf.ap_bufRem
#define cr_svsock	cr_svSock.fd_fd
#define cr_clsock	cr_clSock.fd_fd

#define CC_MTU		1500
#define CC_BUFSIZ	(2*CC_MTU)

#if 0
#define ST_ACCEPTING		0x00000000 /* polling accepting (master server or FTP-PASV)  */
#define ST_CONNECTING		0x00000000 /* polling output-to-server conecting (client or FTP-PORT) */
#define ST_ESTABLISED		0x00000000 /* established but idle */
#define ST_RELAYING		0x00000000 /* polling input-from-both-side */
#define ST_PENDING_SVO		0x00000000 /* polling output-to-server */
#define ST_PENDING_CLO		0x00000000 /* polling output-to-client */
#define ST_SERV_KA		0x00000000 /* waiting reuse (internal-accept) */
#define ST_WAITREQ		0x00000000 /* waiting request packet, after accept() */
#define ST_WAITTHREAD		0x00000000 /* waiting exit of a thread (by thread_join) */
#endif

/* cr_cstat */
#define CCSV_C_ACCEPT		0x00000001 /* AC accepting */
#define CCSV_C_WATCHEX		0x00000002 /* WB watching breaker */
#define CCSV_C_WAITREQ		0x00000004 /* WQ waiting request */
#define CCSV_C_WAITING_CLI	0x00000008 /* WC waiting request completion */
#define CCSV_C_CONN		0x00000010 /* CW connecting */
#define CCSV_C_RELAY		0x00000020 /* RB relaying bidirectionally */
#define CCSV_C_PENDING_CLO	0x00000040 /* WT waiting output to client */
#define CCSV_C_PENDING_SVO	0x00000080 /* WS waiting output to server */
#define CCSV_C_SVKA		0x00000100 /* KS keep-alive the server */
#define CCSV_C_WAITCON		0x00000200 /* WC dilayed conn. waiting reuse */
#define CCSV_C_WAITTHREAD	0x00000800 /* WT waiting thread done */
#define CCSV_C_WAITEVENT	0x00000400 /* WR notice of a resolution, timeout, thread */
#define CCSV_C_RESOLVING	0x00001000 /* WR resolving a host name */
#define CCSV_C_CLOSING		0x00002000 /* WC closing before destroy */
/*
#define CCSV_C_HTTPREQ
#define CCSV_C_HTTPREQ_HEAD
#define CCSV_C_HTTPREQ_BODY
*/

/* cr_qflag */
#define CCSV_Q_SVKA		0x00010000 /* reusable connection */
#define CCSV_Q_DESTROY		0x00020000
#define CCSV_Q_GETCLCNT		0x00040000

/* cr_rstat */
#define CCSV_R_NEW		0x00100000
#define CCSV_R_REU		0x00200000
#define CCSV_R_CON		0x00400000
#define CCSV_R_SENT		0x00800000
#define CCSV_R_ERR		0x01000000

typedef struct {
	int	pv_update;
	int	pv_nready;
	int	pv_fdc;
	int	pv_fdv[2*MAX_CONN];
	FDesc	pv_FDv[2*MAX_CONN];
	int	pv_rev[2*MAX_CONN];
	int	pv_qev[2*MAX_CONN];
	int	pv_cnv[2*MAX_CONN];
} PollVect;
#define fdc	Pv->pv_fdc
#define fdv	Pv->pv_fdv
#define FDv	Pv->pv_FDv
#define rev	Pv->pv_rev
#define qev	Pv->pv_qev
#define cnv	Pv->pv_cnv

#ifndef EINVAL
#define EINVAL -1
#endif

typedef struct {
	int	cx_crn;
       ConnReq *cx_crs;
      PollVect *cx_Pv;
} ConnCtx;

static const char *clientid(ConnReq *cr){
	VSAddr *vsa = (VSAddr*)&cr->cr_clsa;
	static IStr(sv_sid,128);
	static int sv_iid;
	sprintf(sv_sid,"%s:%d",VSA_ntoa(vsa),VSA_port(vsa));
	return sv_sid;
}
static const char *serverid(ConnReq *cr){
	VSAddr *vsa = (VSAddr*)&cr->cr_svsa;
	static IStr(cl_sid,128);
	static int cl_iid;
	sprintf(cl_sid,"%s:%d",VSA_ntoa(vsa),VSA_port(vsa));
	return cl_sid;
}
static char *stk_base;
static char *stk_lowest;
static int stk_tid;
static int stksize(FL_PAR){
	IStr(buf,1);
	if( buf < stk_lowest && getthreadid() == stk_tid ){
		stk_lowest = buf;
		sv1log("----stack size=%X <= %s:%d\n",(int)(stk_base-stk_lowest),FL_BAR);
	}
	return stk_base-stk_lowest;
}

int Ecc_tid;
static int nTime;

static int sysLog(PCStr(fmt),...){
	IStr(msg,1024);
	VARGS(16,fmt);

	stksize(FL_ARG);
	sprintf(msg,fmt,VA16);
	sv1log("%s\n",msg);
	return 0;
}

static double origTime(){ return Time(); }
#if defined(_MSC_VER)
#include <sys/timeb.h>
static double myTime(){
	struct timeb timeb;
	nTime++;
	if( isWindowsCE() ){
		static double tick0s;
		static int tick0m;
		if( tick0s == 0 ){
			tick0s = origTime();
			tick0m = GetTickCount();
		}
		return tick0s + (GetTickCount()-tick0m)/1000.0;
	}else{
		ftime(&timeb);
		return timeb.time + timeb.millitm / 1000.0;
	}
}
#else
static double myTime(){
	struct timeval tv;
	nTime++;
	gettimeofday(&tv,NULL);
        return tv.tv_sec + tv.tv_usec / 1000000.0;
}
#endif
#define Time()	myTime()

static int withoutSyslog = 0;
#define DEBUG	1?0:sysLog
#define DEBUGKA	1?0:sysLog
#define DEBUGEV	1?0:sysLog
#define DEBUGHT	1?0:sysLog
#define TRACE	withoutSyslog?0:sysLog
#define SERIOUS	0?0:sysLog
static int xsend(PCStr(wh),ConnReq *cr,FDesc sock,const void *b,int len);
static int xrecv(PCStr(wh),ConnReq *cr,FDesc sock,void *b,int siz);

static int withCloserThread = 0;
static int closeit(FL_PAR,ConnReq *cr,int fd,int imm);
#define xclose(cr,fd,imm)	(withCloserThread?closeit(FL_ARG,cr,fd,imm):close(fd))

static void endConn(ConnReq *cr,PCStr(fstat)){
	if( cr->cr_cstat == CCSV_C_RESOLVING ){
		TRACE("{%d} Aborted s%X (%s) [%d %d]",cr->cr_id,cr->cr_cstat,fstat,cr->cr_clsock,cr->cr_svsock);
	}
	cr->cr_finStat = fstat;
	cr->cr_cstat = 0;
}

int dupclosed_FL(FL_PAR,int fd);
static FDesc FD_NEW(PCStr(wh),ConnReq *cr,int fd){
	FDesc Fd;

	Fd.fd_fd = fd;
	Fd.fd_handle = SocketOf(fd);
	if( isWindows() ){
		if( 0 <= fd && Fd.fd_handle == 0 ){
			TRACE("----{%d} FATAL FD_NEW(%s) [%d/%d] err=%d",
				cr?cr->cr_id:0,wh,fd,Fd.fd_handle,errno);
			Fd.fd_fd = -900 - fd;
			dupclosed_FL(FL_ARG,fd);
		}
	}
	return Fd;
}
static FDesc FD_INVALID(int fd){
	FDesc Fd;

	Fd.fd_fd = fd;
	Fd.fd_handle = -1;
	return Fd;
}
static int FD_ISVALID(FDesc Fd){
	if( 0 <= Fd.fd_fd )
		return 1;
	else	return 0;
}
static CriticalSec handleCSC;
static int xnewSocket(ConnReq *cr,PCStr(what),PCStr(opts)){
	int sock;
		double Stc = 0;
		if( enterCSCX(handleCSC,1) != 0 ){
			Stc = Time();
			enterCSC(handleCSC);
		}
		sock = newSocket(what,opts);
		leaveCSC(handleCSC);
		if( Stc ){
			TRACE("---- {%d} Mutex newSocket(%s) [%d/%d] (%.3f)",cr->cr_id,what,
				sock,SocketOf(sock),Time()-Stc);
		}
	set_keepalive(sock,1);
	setNonblockingSocket(sock,1);
	if( isWindows() ){
		if( SocketOf(sock) <= 0 ){
			TRACE("##{%d} FATAL newSocket(%s) [%d/%d]",cr->cr_id,what,sock,SocketOf(sock));
			return sock;
		}
	}
	return sock;
}
static ConnReq *addConn(PollVect *Pv,int crn,ConnReq *crs,FDesc clSock);
static int dumpCon(PollVect *Pv,int na,int crn,ConnReq *crb,int verbose,int sweep,FILE *tc);
static int salvage(ConnCtx *cx,PollVect *Pv,int na,int crn,ConnReq *crb);

char *printnetif(PVStr(netif));
int DontRouteSocket(int sock,int on);
int BindSocket(int sock,VSAddr *sap,int port);
int isinSameSegment(VSAddr *vsa1,VSAddr *vsa2);
int getLocalIF(PCStr(iflist),VSAddr *dst,VSAddr *src){
	IStr(if1,128);
	VSAddr vif1;
	const char *ip = iflist;

	for( ip = iflist; *ip; ){
		ip = wordScan(ip,if1);	
		if( *if1 == 0 ){
			break;
		}
		VSA_atosa(&vif1,0,if1);
		if( isinSameSegment(&vif1,dst) ){
			IStr(ssrc,128);
			*src = vif1;
			strcpy(ssrc,VSA_ntoa(src));
			TRACE("NetIF: {%s} %s <= %s",iflist,VSA_ntoa(dst),ssrc);
			return 1;
		}
	}
	return 0;
}

#include "http.h" /* for HTTP_env */
int ShutdownSocket(int fd);
int waitFilterThreadX(Connection *Conn);
void setHTTPenv(Connection *Conn,HTTP_env *he);
int HTTP_decompRequest(Connection *Conn);
int dumpThreads(PCStr(wh));

static void sendSync(ConnCtx *cx,ConnReq *cr,int sid){
	cr->cr_sync = sid;
}
static void waitSync(ConnCtx *cx,ConnReq *cr,int sid){
	double St = Time();
	int ri;

	for( ri = 0; ri < 50; ri++ ){
		if( cr->cr_sync == sid ){
			break;
		}
		msleep(100);
	}
	if( 1 < ri ){
		sv1log("--FTP/HTTP wait(%d) %X %X (%.2f)\n",
			ri,cr->cr_sync,sid,Time()-St);
	}
}

FileSize httpftp(Connection *Conn,FILE *fc,FILE *tc,PCStr(ver),PCStr(method),int svsock,PCStr(auth),PCStr(uuser),PCStr(upass),PCStr(host),int port,int gtype,PCStr(path),int *stcodep);
static int ftpgw(ConnCtx *cx,ConnReq *cr,PCStr(ver),PCStr(method),PCStr(server),int sid){
	Connection ConnBuf,*Conn = &ConnBuf;
	FILE *fc;
	FILE *tc;
	int hcode = -1;
	FDesc clSock;
	IStr(host,MaxHostNameLen);
	IStr(path,1024);
	int port = 21;
	HTTP_env he;
	static int Nftpgw;
	static int Eftpgw;
	double Start = Time();
	double Elp;

	clSock = FD_NEW("ftpgw",cr,dup(cr->cr_clsock));
	if( 0 < Nftpgw-Eftpgw ){
		while( 0 < Nftpgw-Eftpgw ){
			Elp = Time()-Start;
			TRACE("##{%d} ftpgw*%d-%d waiting (%.2f)",cr->cr_id,Nftpgw,Eftpgw,Elp);
			if( 10 < Elp ){
	int wcc;
	IStr(msg,128);
	sprintf(msg,"HTTP/1.0 503 DeleGate/Ecc retry\r\nRetry-After: 10\r\n\r\n");
	wcc = xsend("RESP-Busy-Ftpgw",cr,clSock,msg,strlen(msg));
				msleep(100);
				ShutdownSocket(clSock.fd_fd);
				close(clSock.fd_fd);
				dumpThreads("ftpgw");
				return -1;
			}
			msleep(500);
		}
		Elp = Time()-Start;
		TRACE("##{%d} ftpgw*%d-%d waited (%.2f)",cr->cr_id,Nftpgw,Eftpgw,Elp);
	}
	++Nftpgw;
	TRACE("##{%d} ftpgw*%d-%d sock=[%d] #### th=%d/%d ####",cr->cr_id,
		Nftpgw,Eftpgw,clSock.fd_fd,actthreads(),numthreads());
	fc = fdopen(clSock.fd_fd,"r");
	tc = fdopen(clSock.fd_fd,"a");
/*
SigMaskInt mask,omask;
mask = sigmask(SIGPIPE);
thread_sigmask("SET",mask,&omask);
*/
//sigblock(sigmask(SIGPIPE));
	if( isWindowsCE() || 1 ){
		setNonblockingIO(clSock.fd_fd,0);
	}
//setbuffer(tc,NULL,0);
	bzero(Conn,sizeof(Connection));
	ConnInit(Conn);
	ClientSock = FromC = ToC = clSock.fd_fd;
	Xsscanf(server,"%[^:]:%d",AVStr(host),&port);
	Conn->from_myself = 1;
/* should cope with from_myself=0 not to Finish() */
	set_realserver(Conn,"ftp",host,port);
	bzero(&he,sizeof(he));
	he.r_resp.r_msg = UTalloc(SB_CONN,1024,1);
	he.r_i_buff = UTalloc(SB_CONN,URLSZ,1);
	he.r_o_buff = UTalloc(SB_CONN,OBUFSIZE,1);
	he.r_savConn = UTalloc(SB_CONN,sizeof(Connection),8);
	he.r_acclangs = UTalloc(SB_CONN,1024,1);
	he.r_ohost = UTalloc(SB_CONN,1024,1);
	setHTTPenv(Conn,&he);
	setFTOCL(NULL);
	QStrncpy(REQ,cr->cr_buf,cr->cr_bufRem+1);
	HTTP_decompRequest(Conn); /* to set RespWithBody */
	if( 1 ){
		refQStr(dp,OREQ);
		IStr(serv,MaxHostNameLen);
		strcpy(OREQ,REQ);
		if( dp = strchr(OREQ,' ') ){
			wordScan(dp,path);
			sprintf(serv,"%s://%s","ftp",server);
			Strins(DVStr(dp,1),serv);
		}
		//strcpy(OREQ_MSG,OREQ);
	}
	strcpy(CLNT_PROTO,"http");
//strcpy(iSERVER_PROTO,"http");

  {
	IStr(user,128);
	IStr(pass,128);
	IStr(auth,128);
	IStr(qauth,128);
	strcpy(user,"anonymous");
	strcpy(pass,"anonymous@delegate.-.-");
	strcpy(REQ_FIELDS,REQ);
	HTTP_authuserpass(Conn,AVStr(qauth),sizeof(qauth));
	if( strchr(qauth,':') ){
		Xsscanf(qauth,"%[^:]:%[^\r\n]",AVStr(user),AVStr(pass));
	}

	sendSync(cx,cr,sid);
	httpftp(Conn,fc,tc,ver,method,-1,auth,user,pass,host,port,0,path,&hcode);
  }

	fflush(tc);
	ShutdownSocket(cr->cr_clsock);
	waitFilterThreadX(Conn);

	fcloseFILE(tc);
	fclose(fc);
	Eftpgw++;
	return 0;
}
static int putSv(ConnCtx *cx,ConnReq *cr);
static int destroyAct(ConnReq *cr);
static int destroyActX(PCStr(wh),ConnReq *cr);
FILE *TMPFILE(PCStr(wh));
static int isHTTPorig(ConnCtx *cx,ConnReq *cr,PCStr(ver),PCStr(host),int port,PCStr(buf)){
	IStr(msg,512);
	IStr(met,128);
	IStr(url,256);
	const char *req;
	int wcc;

	if( host[0] != 0 ) // and if not SELF address in NetIFS
		return 0;

	req = wordScan(buf,met);
	wordScan(req,url);

	sprintf(msg,"HTTP/1.0 200 Not-Origin-Server\r\nContent-Length: 0\r\n\r\n");
	TRACE("##{%d}*%d SELF {%s}{%s}",cr->cr_id,cr->cr_hqn,met,url);

	if( *req == ' ' ){
		req++;
		if( strneq(req,"/-/builtin/icons/",17) ){
			int PutIcon(Connection *Conn,FILE *tc,int vno,PCStr(icon));
			Connection ConnBuf,*Conn = &ConnBuf;
			CStr(iname,128);
			CStr(iurl,128);
			FILE *tc;
			int rcc,wcc=-1;
			IStr(buf,CC_BUFSIZ);

			tc = TMPFILE("http-sp-resp");
			wordScanY(req+17,iname,"^ \t\r\n");
			sprintf(iurl,"builtin/icons/%s",iname);
			bzero(Conn,sizeof(Connection));
			PutIcon(Conn,tc,100,iurl);
			fseek(tc,0,0);
			rcc = fread(buf,1,sizeof(buf),tc);
			fclose(tc);
			if( 0 < rcc ){
				wcc = xsend("HTTP-ORIG",cr,cr->cr_clSock,buf,rcc);
			}
			TRACE("##{%d} internal {%s} %d => %d",cr->cr_id,iurl,rcc,wcc);
		}else
		if( strneq(req,"/-/ ",4) ){
			IStr(body,512);
sprintf(body,"<IMG SRC=%s> <A HREF=%s>DeleGate</A> for Windows Mobile/CE\r\n<HR>\r\n",
				"/-/builtin/icons/ysato/frog9L.gif",
				"http://wince.delegate.org"
			);
			if( cr->cr_hqclka == 0 ){
				if( strstr(req," HTTP/1.1") ){
					cr->cr_hqclka = cr->cr_id;
				}
			}
			if( cr->cr_hqclka ){
				DEBUG("##{%d} orig KA",cr->cr_id);
				sprintf(msg,"HTTP/1.1 200 Internal\r\nContent-Length: %d\r\n\r\n",istrlen(body));
				strcat(msg,body);
				wcc = xsend("HTTP-ORIG",cr,cr->cr_clSock,msg,strlen(msg));
				cr->cr_hqclka = 0;
				return 1;
			}else{
				sprintf(msg,"HTTP/1.0 200 Internal\r\nContent-Length: %d\r\n\r\n",istrlen(body));
				strcat(msg,body);
				wcc = xsend("HTTP-ORIG",cr,cr->cr_clSock,msg,strlen(msg));
				// HTTP/1.0 for client's req
				// HTTP/1.1 + Connection:close for client's req
			}
		}
	}
	destroyAct(cr);
	return 1;
}
static int putmsg(PCStr(wh),ConnReq *cr,FDesc clSock,int hcode,PCStr(msg)){
	IStr(times,128);
	IStr(head,1024);
	IStr(body,1024);
	IStr(resp,1024);
	int wcc;
	double Now = Time();

	sprintf(times,"%.2f %.2f %.2f",Now-cr->cr_connSt,Now-cr->cr_statSt,Now-cr->cr_irdySt);
	TRACE("{%d} s%X (%s) putmsg(%s)",cr->cr_id,cr->cr_cstat,times,msg);
	sprintf(body,"%s\r\n(%s)\r\n",msg,times);
	sprintf(head,"HTTP/1.0 %d DeleGate/Ecc %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n",
		hcode,msg,istrlen(body));
	sprintf(resp,"%s\r\n%s",head,body);
	wcc = xsend(wh,cr,clSock,resp,strlen(resp));
	return wcc;
}

int dialupOnConnect(int sock,SAP addr,int leng,int timeout,PVStr(cstat),int rcode);
static int findSv(ConnReq *crq,ConnReq *crs,int crn,ConnReq *ocr);
static int xPollIn(FDesc Fd,int timeout);
static int SyncID;

static int tryConnect(ConnCtx *cx,ConnReq *cr,PCStr(ver),PCStr(method),PCStr(proto),PCStr(server)){
	int svsock;
	int serrno;
	int nready;
	int alive;
	int rcode;
	VSAddr *sa = (VSAddr*)&cr->cr_svsa;
	int sz = VSA_size((VSAddr*)&cr->cr_svsa);
	ConnReq crq;
	ConnReq ocr;
	double St,Elp=0;

	if( _lSINGLEP && _lMULTIST )
	if( strcmp(proto,"ftp") == 0 ){
		int sid = ++SyncID;
		cr->cr_svtid = thread_fork(0x80000,0,"FTP/HTTP",
			(IFUNCP)ftpgw,cx,cr,ver,method,server,sid);
		cr->cr_cstat = CCSV_C_WAITTHREAD;
		waitSync(cx,cr,sid);
		return 0;
	}

	crq = *cr;
	crq.cr_qflag = CCSV_Q_SVKA;
	rcode = findSv(&crq,cx->cx_crs,cx->cx_crn,&ocr);
	if( rcode == 0 ){
		ECC_NumReused++;
		cr->cr_reused = ocr.cr_reused + 1;
		cr->cr_hrsvka = ocr.cr_hrsvka;
		if( cr->cr_hrsvka ){
			cr->cr_hrsvka |= KA_DO_Inf;
		}
		cr->cr_connSt = ocr.cr_connSt;
		svsock = ocr.cr_svsock;
		serrno = 0;
		nready = PollIn(svsock,1);
		alive = IsAlive(svsock);
		DEBUGKA("##{%d}*%d gotSv (%d){%d} [%d]rdy=%d %s (%d) Rdy=%d,%d",
			cr->cr_id,cr->cr_reused,
			ocr.cr_ix,ocr.cr_id,
			svsock,inputReady(svsock,0),
			serverid(&ocr),
			cr->cr_bufRem,nready,alive
		);
		if( nready != 0 || alive == 0 ){
			xclose(cr,svsock,1);
			rcode = -1;
		}
		/* it must be retried on EOS with empty resp. */
		/* or non-HTTP resp. (truncated resp) */
	}
	if( rcode != 0 ){
		svsock = xnewSocket(cr,"CCSV-tryCon","");
		setosf_FL("CCSV-tryCon","(serv-socket)",svsock,NULL,__FILE__,__LINE__);
		St = Time();

		if( _lDONTROUTE_LOCAL ){
			VSAddr locif;
			if( SvccNetIFgot == 0 || 10 < St-SvccNetIFgot ){
				IStr(netif,256);
				if( printnetif(AVStr(netif)) ){
					SvccNetIFgot = (int)St;
					if( strcmp(netif,SvccNetIF) != 0 ){
						TRACE("NetIF: {%s} <= {%s}",netif,SvccNetIF);
						strcpy(SvccNetIF,netif);
						if( strchr(netif,' ') ){
							SvccNetIFnum = 2;
						}else{
							SvccNetIFnum = 1;
						}
					}
				}
			}
			if( SvccNetIFgot && 1 < SvccNetIFnum ){
				if( getLocalIF(SvccNetIF,sa,&locif) ){
					BindSocket(svsock,&locif,0);
					DontRouteSocket(svsock,1);
				}
			}
		}

		errno = 0;
		rcode = connect(svsock,(SAP)sa,sz);
		serrno = errno;
		if( rcode == 0 ){
			set_keepalive(svsock,1);
		}
		Elp = Time()-St;

		if( rcode != 0 )
		if( serrno == EHOSTUNREACH || serrno == ENETUNREACH ){
			int ccode;
			IStr(stat,512);
			rcode = dialupOnConnect(svsock,(SAP)sa,sz,15,AVStr(stat),-1);
		}
	}

	if( rcode == 0 ){
		if( 0 < cr->cr_bufRem ){
			cr->cr_cstat = CCSV_C_PENDING_SVO;
			if( cr->cr_reused == 0 )
			TRACE("##{%d} imm. CONN to serv. %s (%d) %d-%d Q%d R%d (%.2f)",
				cr->cr_id,serverid(cr),
				cr->cr_bufRem,cr->cr_hqn,cr->cr_hrn,cr->cr_hqst,
				cr->cr_reused,Elp
			);
		}else{
			cr->cr_cstat = CCSV_C_RELAY; cr->cr_statSt = Time();
		}
		cr->cr_svSock = FD_NEW("tryConnect-1",cr,svsock);
		updateFdv = 1;
		DEBUG("-Ecc(%2d){%d} CONN %s imm. OK",cr->cr_ix,cr->cr_id,serverid(cr));
		if( cr->cr_reused ){
			DEBUGKA("{%d} s%X gotSv reusing <%s> [%d](%d)",cr->cr_id,cr->cr_cstat,serverid(cr),svsock,cr->cr_bufRem);
		}
		return 0;
	}else
	if( serrno == EINPROGRESS || serrno == EWOULDBLOCK ){
		cr->cr_cstat = CCSV_C_CONN; cr->cr_Timeout = Time()+10;
		cr->cr_svSock = FD_NEW("tryConnect-2",cr,svsock);
		updateFdv = 1;
		DEBUG("-Ecc(%2d){%d} CONN %s in progress",cr->cr_ix,cr->cr_id,serverid(cr));
		return 1;
	}else{
		int wcc;
	TRACE("##{%d} CON-E (imm.)=> %s connect([%d/%d]) failure, rcode=%d err=%d/%d rem=%d HTTP",
			cr->cr_id,serverid(cr),svsock,SocketOf(svsock),rcode,serrno,
			ETIMEDOUT,cr->cr_bufRem);
		wcc = putmsg("CONN-ERROR",cr,cr->cr_clSock,504,"Connection Failed");
		updateFdv = 1;
		xclose(cr,svsock,1);
		destroyActX("con-e-imm",cr);
	}
	DEBUG("-Ecc(%2d){%d} CONN %s siz=%d rcode=%d err=%d ##ERR##",
		cr->cr_ix,cr->cr_id,serverid(cr),sz,rcode,serrno);
	return -1;
}
static void checkBuf(ConnReq *cr,int siz,FL_PAR){
	if( cr->cr_bufSiz < siz ){
		TRACE("{%d} FATAL overflow %d/%d <= %s:%d",
			cr->cr_id,siz,cr->cr_bufSiz,FL_BAR);
		Finish(-1);
	}
}
static int putBuf(ConnCtx *cx,ConnReq *cr,const char *dat,int siz,FL_PAR){
	int ci;
	ConnReq *cr1 = 0;

	if( cr->cr_buf == 0 ){
		for( ci = 0; ci < cx->cx_crn; ci++ ){
			cr1 = &cx->cx_crs[ci];
			if( cr1->cr_buf != 0 && siz <= cr1->cr_bufSiz && cr1->cr_bufRem <= 0 )
			if( cr1->cr_cstat == 0
			 || cr1->cr_cstat == CCSV_C_SVKA
			){
				DEBUG("###Ecc [%d]{%d}%d found free [%d]{%d}%d",
					cr->cr_ix,cr->cr_id,siz,
					cr1->cr_ix,cr1->cr_id,cr1->cr_bufSiz);
				cr->cr_buf = cr1->cr_buf;
				cr->cr_bufSiz = cr1->cr_bufSiz;
				cr->cr_bufRem = 0;
				cr1->cr_buf = 0;
				cr1->cr_bufSiz = 0;
				cr1->cr_bufRem = 0;
				goto EXIT;
			}
		}
		if( 0 < ECC_bufSiz ){
			cr->cr_bufSiz = ECC_bufSiz;
		}else
		cr->cr_bufSiz = CC_BUFSIZ;
		ECC_tmaz += cr->cr_bufSiz;
		TRACE("###Ecc [%d]{%d} putBuf malloc(%d/%d)",
			cr->cr_ix,cr->cr_id,cr->cr_bufSiz/1024,ECC_tmaz/1024);
		cr->cr_buf = (char*)malloc(cr->cr_bufSiz);
	}
EXIT:
	cr->cr_bufRem = siz;
	checkBuf(cr,siz,FL_BAR);
	Xbcopy(dat,ZVStr(cr->cr_buf,cr->cr_bufSiz),siz);
	return 0;
}

#define HSQ_METHOD	1
#define HSQ_PROTO	2
#define HSQ_SERVER	3
#define HSQ_URLPATH	4
#define HSQ_VERSION	5
#define HSQ_FIELDS	6
#define HSQ_EOH		7
#define HSQ_BODY	8

static int parseConnection(ConnReq *cr,int proxy,PCStr(val),int ka){
	IStr(cka,128);

	wordScan(val,cka);
	if( strncasecmp(cka,"close",5) == 0 ){
		if( proxy )
			ka |= KA_NO_PXConn;
		else	ka |= KA_NO_Conn;
		if( cr ){
			cr->cr_hrsvka = 0;
		}
	}else
	if( strncasecmp(cka,"keep-alive",9) == 0 ){
		if( proxy )
			ka |= KA_DO_PXConn;
		else	ka |= KA_DO_Conn;
		if( cr ){
			if( proxy )
				cr->cr_hrsvka |= 2;
			else	cr->cr_hrsvka |= 4;
		}
	}else{
		ka |= KA_NO_Unk;
	}
	return ka;
}
static int parseHTTPresp(ConnCtx *cx,ConnReq *cr,PVStr(buf),int rcc){
	refQStr(bp,buf);
	IStr(line,1024);
	refQStr(lp,line);
	char ch;
	IStr(resp,CC_BUFSIZ);
	char *rp = resp;
	int rx;
	int atTop = 1;
	int cleng = 0;
	int got_cleng = 0;
	IStr(cenc,128);
	IStr(ctype,128);
	int hcode = 0;
	IStr(hver,128);
	IStr(tenc,128);
	int eoH = 0;

	if( buf[0] != 'H'
	 || buf[1] != 'T'
	 || buf[2] != 'T'
	 || buf[3] != 'P'
	 || buf[4] != '/'
	){
		if( cr->cr_hqmeth == 'C' ){ // if CONNECT don't put TRACE
		}else{
			TRACE("##{%d} %d-%d RESP #### CONT #### %d / %d / %d (%d)",
				cr->cr_id,cr->cr_hqn,cr->cr_hrn,
				rcc,cr->cr_hrrem,cr->cr_hrlen,cr->cr_delreqn
			);
			/* if the first resp from a reused server to the client
			 * in keep-alive, it must be remaining response to
			 * another request, and must be abandoned.
			 */
		}
		return rcc;
	}
	if( cr->cr_hrenc || cr->cr_hrlen ){
		/* 9.9.8 initialize */
		DEBUG("{%d} #### clear R encode(%d) len=%d Q%d-R%d ####",
			cr->cr_id,cr->cr_hrenc,cr->cr_hrlen,
			cr->cr_hqn,cr->cr_hrn
		);
		cr->cr_hrenc = 0;
		cr->cr_hrlen = 0;
	}

	Xsscanf(buf,"%s %d",AVStr(hver),&hcode);
	DEBUG("####{%d} Q%d-R%d %s %d",cr->cr_id,cr->cr_hqn,cr->cr_hrn,hver,hcode);
	if( hcode == 100 ){
		TRACE("####{%d} %s %d CONT",cr->cr_id,hver,hcode);
	}
	cr->cr_hrn++;
	if( strcmp(hver,"HTTP/1.1") == 0 ){
		cr->cr_hrsvka = 1;
		cr->cr_hrsvKA = KA_DO_11;
	}else{
		cr->cr_hrsvka = 0;
		cr->cr_hrsvKA = KA_NO_10;
	}

	for( rx = 0; rx < rcc && rx < sizeof(resp)-1; rx++ ){
		ch = buf[rx];
		if( ch == '\n' ){
			if( buf[rx+1] == '\n' ){
				rx += 2;
				eoH = 1;
			}
			if( buf[rx+1] == '\r' && buf[rx+2] == '\n' ){
				*rp++ = buf[rx++];
				*rp++ = buf[rx++];
				*rp++ = buf[rx++];
				eoH = 1;
			}
			if( eoH ){
				break;
			}
			atTop = 1;
			*rp++ = ch;
			continue;
		}
		if( atTop ){
			if( ch == 'T' && buf[rx+1] == 'r' ){
			    if( strneq(buf+rx,"Transfer-Encoding:",18) ){
				lineScan(buf+rx+18,tenc);
				if( strcasestr(tenc,"chunked") ){
					cr->cr_hrenc = 1;
				}else{
				}
			    }
			}
			if( ch == 'K' && buf[rx+1] == 'e' && buf[rx+2] == 'e' ){
			    if( strneq(buf+rx,"Keep-Alive:",11) ){
				cr->cr_hrsvka |= 8;
			    }
			}
			if( ch == 'P' && buf[rx+1] == 'r' && buf[rx+2] == 'o' ){
			    if( strneq(buf+rx,"Proxy-Connection:",17) ){
				cr->cr_hrsvKA = parseConnection(cr,1,buf+rx+17,cr->cr_hrsvKA);
				// should erase the field
			    }
			}
			if( ch == 'C' && buf[rx+1] == 'o' && buf[rx+2] == 'n' ){
			    if( strneq(buf+rx,"Connection:",11) ){
				cr->cr_hrsvKA = parseConnection(cr,0,buf+rx+11,cr->cr_hrsvKA);
				// should erase the field
			    }else
			    if( strneq(buf+rx,"Content-Type:",13) ){
				lineScan(buf+rx+13,ctype);
			    }else
			    if( strncaseeq(buf+rx,"Content-Length:",15) ){
				cleng = atoi(buf+rx+15);
				cr->cr_hrlen = cr->cr_hrrem = cleng;
				got_cleng = 1;
				if( hcode == 304 ){
					ch = '-';
					((char*)buf)[rx] = '-'; /* disable the field */
					TRACE("##HT disabled 304 Content-Length:%d <= %s",cleng,serverid(cr));
				}
			    }else
			    if( strneq(buf+rx,"Content-Encoding:",17) ){
				lineScan(buf+rx+17,cenc);
			    }
			}
		}
		atTop = 0;
		*rp++ = ch;
	}
	*rp = 0;

	/*
	if( hcode == 304 || cr->cr_hrnobody ){
	*/
	if( hcode == 304 || hcode == 204 || cr->cr_hrnobody ){
		cr->cr_hrrem = 0;
		cr->cr_hrendE++;
	}else
	if( 0 < got_cleng && cleng <= 0 && cr->cr_hrenc == 0 ){
		TRACE("{%d} #### ContLeng:0 got=%d #### hcode=%d enc=%X rcc=%d rx=%d",
			cr->cr_id,got_cleng,hcode,cr->cr_hrenc,rcc,rx);
		cr->cr_hrrem = 0;
		cr->cr_hrendE++;
	}else{
		cr->cr_hrrem -= (rcc - rx);
		if( cr->cr_hrenc == 0 ){
			if( cr->cr_hrrem == 0 ){
				cr->cr_hrendL++;
			}
		}
	}
	if( tenc[0] ){
		DEBUGHT("##{%d} RESP %d-%d D%d %s %d %s,%s,%s,%d(%d)",
			cr->cr_id,cr->cr_hqn,cr->cr_hrn,cr->cr_delreqn,
			hver,hcode,
			ctype,cenc,tenc,cleng,cr->cr_hrrem
		);
	}
	return rcc;
}
static int isHTTPreq(PCStr(req)){
	if( req[0]=='G' && req[1]=='E' && req[2]=='T' && req[3]==' ' ){
		return 1;
	}
	if( req[0]=='H' && req[1]=='E' && req[2]=='A' && req[3]=='D' && req[4]==' ' ){
		return 2;
	}
	if( req[0]=='P' && req[1]=='O' && req[2]=='S' && req[3]=='T' && req[4]==' ' ){
		return 3;
	}
	if( req[0]=='C' && req[1]=='O' && req[2]=='N' && req[3]=='N' && req[4]=='E' ){
		return 4;
	}
	if( req[0]=='Y' && req[1]=='1' && req[2]=='1' && req[3]==' ' ){
		return 5;
	}
	return 0;
}
static int parseHTTPreq(ConnReq *cr,PVStr(req),int rcc,PVStr(method),PVStr(proto),PVStr(server),PVStr(ver),int rew,int *wlen){
	const char *qp = req;
	const char *xp = req + rcc;
	char *rp = (char*)req;
	refQStr(vrp,req);
	refQStr(mp,method);
	refQStr(pp,proto);
	refQStr(sp,server);
	refQStr(vp,ver);
	int ch;
	int isCONN = 0;
	int eoh = 0;
	int cka = 0;
	const char *upathtop = 0;
	const char *upathend = 0;

	cr->cr_hqclen = -1;
	cr->cr_hqmeth = req[0];

	if( req[0] == 'H' && req[1] == 'E' && req[2] == 'A' && req[3] == 'D' ){
		cr->cr_hrnobody = 1;
	}
	else
	if( cr->cr_hrnobody ){
		TRACE("{%d} #### clear Q nobody(%d) ####",cr->cr_id,cr->cr_hrnobody);
		cr->cr_hrnobody = 0;
	}

HQ_METHOD:
	cr->cr_hqst = HSQ_METHOD;
	for( qp = req; ch = *qp; qp++ ){
		if( ch == ' ' || ch == '\r' || ch == '\n' )
			break;
		setVStrPtrInc(mp,ch);
	}
	setVStrPtrInc(mp,0);
	if( ch != ' ' ){
		return -1;
	}

	if( isCONN = strcmp(method,"CONNECT")==0 ){
		qp++;
		rp = (char*)req;
		goto HQ_SERVER;
	}
	rp = (char*)++qp;

HQ_PROTOCOL:
	ch = *qp;
	if( ch == '/' || ch == '*' ){
		if( rew == 0 ){
			return 0;
		}
		setVStrPtrInc(pp,0);
		setVStrPtrInc(sp,0);
		goto HQ_URLPATH;
	}
	cr->cr_hqst = HSQ_PROTO;
	for(; ch = *qp; qp++ ){
		if( ch == ':' || ch == '\r' || ch == '\n' )
			break;
		setVStrPtrInc(pp,ch);
	}
	setVStrPtrInc(pp,0);
	if( ch != ':' || qp[1] != '/' || qp[2] != '/' ){
		return -2;
	}
	qp += 3;

HQ_SERVER:
	cr->cr_hqst = HSQ_SERVER;
	for(; ch = *qp; qp++ ){
		if( ch == ' ' || ch == '/' || ch == '?' || ch == '\r' || ch == '\n' )
			break;
		setVStrPtrInc(sp,ch);
	}
	setVStrPtrInc(sp,0);
	if( ch == '\r' || ch == '\n' ){
		return 3;
	}
	if( rew == 0 ){
		return 0;
	}
	if( isCONN ){
		rp = (char*)req;
		goto HQ_VERSION;
	}

HQ_URLPATH:
	upathtop = rp;
	cr->cr_hqst = HSQ_URLPATH;
	if( ch == ' ' ){
		/* http://server without a url-path */
		*rp++ = '/';
		*rp++ = ' ';
	}else{
		for(; ch = *qp; qp++ ){
			*rp++ = ch;
			if( ch == ' ' || ch == '\r' || ch == '\n' )
				break;
		}
	}
	upathend = rp-1;

HQ_VERSION:
	cr->cr_hqst = HSQ_VERSION;
	if( ch == ' ' && *qp ){
		for( qp++; ch = *qp; qp++ ){
			*rp++ = ch;
			if( ch == '\r' || ch == '\n' )
				break;
			setVStrPtrInc(vp,ch);
		}
		setVStrPtrInc(vp,0);
		/* cka = 1; if 1.1 */
		if( strcasecmp(ver,"HTTP/1.1") == 0 ){
			cr->cr_hqclka = cr->cr_id;
			cr->cr_hqclKA = KA_DO_11;
		}else{
			cr->cr_hqclka = 0;
			cr->cr_hqclKA = KA_NO_10;
		}
	}

HQ_FIELDS:
	cr->cr_hqst = HSQ_FIELDS;
	if( *qp ){
		int pch = ch;
		int atTop = 1;
		IStr(host,MaxHostNameLen);
		int didPutHost = 0;

		for( qp++; ch = *qp; qp++ ){
			*rp++ = ch;
			if( atTop ){
				if( ch == 'H' && qp[1] == 'o' && strneq(qp,"Host:",5) ){
					/*
					wordScan(qp+5,host);
					empty-field CRLF next-filed ... wordScan() gets nextfield
					*/
					lineScan(qp+5,host);
					if( server[0] == 0 ){
						// origin server. leave the
						// vhost in the Host: header
					}else
					if( strcmp(server,host)==0 ){
						//DEBUG("##Host: %s (thru)",host);
						didPutHost = 1;
					}else
					if( cr->cr_hqmeth == 'C' ){
						/* CONNECT, don't rewrite not forwarded head */
					}else{
						TRACE("##{%d} Host: %s <= %s (replace) %s %s",
							cr->cr_id,server,host,proto,method);

						// skip the field
						rp--;
						for(; *qp && *qp != '\n'; qp++ );
						ch = *qp;
						if( ch == 0 ){
							break;
						}else{
							pch = '\n';
							continue;
						}
					}
				}else
				if( ch == 'P' && qp[1] == 'r' && strneq(qp,"Proxy-Connection:",17) ){
					cr->cr_hqclKA |= parseConnection(0,1,qp+17,cr->cr_hqclKA);
					// should erase the connection
					rp--; qp += 5; // rewriting the field name to "Connection:"
				}else
				if( ch == 'C' && qp[1] == 'o' ){
				    if( strneq(qp,"Content-Length:",15) ){
					cr->cr_hqclen = atoi(qp+15);
				    }else
				    if( strneq(qp,"Connection:",11) ){
					cr->cr_hqclKA |= parseConnection(0,0,qp+11,cr->cr_hqclKA);
					// should erase the field
				    }
				}
			}
			if( ch == '\n' && pch == '\n' ){
				cr->cr_hqst = HSQ_EOH;
				qp++;
				eoh = 1;
				break;
			}
			if( ch == '\n' && (qp[1] == '\r' && qp[2] == '\n' || qp[1] == '\n') ){
				if( server[0] == 0 ){
					// origin server.
				}else
				if( didPutHost == 0 ){
					IStr(host,MaxHostNameLen);
					//DEBUG("##Host: %s <= (none)",server,host);
					sprintf(host,"Host: %s\r\n",server);
					vrp = rp;
					Strins(AVStr(vrp),host);
					rp += strlen(host);
					qp += strlen(host);
				}
			}
			if( ch != '\r' )
				pch = ch;
			if( ch == '\n' ){
				atTop = 1;
			}else{
				atTop = 0;
			}
		}
	}
	if( isCONN ){
		rp = (char*)req;
		goto HQ_BODY;
	}

HQ_BODY:
	if( *qp && xp <= qp ){
		TRACE("{%d] #### NOT BODY [%X] %X %X ####",cr->cr_id,*qp,xp,qp);
	}else
	if( *qp ){
		int blen = strlen(qp);
		int hln,rem,len;

		cr->cr_hqst = HSQ_BODY;
		DEBUG("##HT BODYof[%s]? eoh(%d) len(%d) %c:%d",
			method,eoh,cr->cr_hqclen,*qp,blen);
//*rp = 0;
//fprintf(stderr,"--------\n%s",req);
		hln = qp - req;
		blen = rcc - hln; /* body length */
		if( blen < cr->cr_hqclen ){
			/* set CCSV_C_HQBODY */
			len = rem = rcc - hln;
			cr->cr_hqrem = cr->cr_hqclen - len;
		}else{
			/*
			len = rem = 0;
			*/
			len = rem = rcc - hln;
			cr->cr_hqrem = 0;
		}
		for(; ch = *qp; qp++ ){
			if( xp <= qp ){
				/* 9.9.8 not to get dust */
				break;
			}
			*rp++ = ch;
			rem--;
		}
		TRACE("--{%d}--POST-1 rcc=%d hln=%d cln=%d txl=%d len=%d rem=%d (%d) %d",
			cr->cr_id,rcc,hln,cr->cr_hqclen,blen,len,rem,xp-qp,cr->cr_hqrem);
		if( qp < xp ){
			while( qp < xp ){
				*rp++ = *qp++;
				rem--;
			}
		TRACE("--{%d}--POST-2 rcc=%d hln=%d cln=%d txl=%d len=%d rem=%d (%d) %d",
			cr->cr_id,rcc,hln,cr->cr_hqclen,blen,len,rem,xp-qp,cr->cr_hqrem);
		}
	}
	*rp = 0;
*wlen = rp - req;

	eccTOTAL_SERVED += 1;
	LOGX_appReq++;
	ECC_NumHttpReq++;
	cr->cr_hqstat++;
	cr->cr_hqn++;
	if( 0 ){	
		TRACE("######HTSP REQ (%2d){%d} %d-%d %s",cr->cr_ix,cr->cr_id,
			cr->cr_hqn,cr->cr_hrn,req);
	}
	if( 0 ){
		char upb[16],*up = upb;
		const char *qp;
		up = &upb[sizeof(upb)-1];
		*up = 0;
		if( upathtop != 0 && upathend != 0 ){
			for( qp = upathend; upathtop < qp; qp-- ){
				if( up == upb )
					break;
				*--up = *qp;
			}
		}
		TRACE("#REQ#%d.%-2d [%d]{%d} %s %s://%s %s %s",
			ECC_NumHttpReq,cr->cr_hqstat,
			cr->cr_ix,cr->cr_id,method,proto,server,up,ver);
	}
	return 4;
}
int CachedHosts(int *siz);
int SortCachedHosts();
int ExpireCachedHosts(int mexp,int iexp);
static int maintainCachedHosts(){
	int siz,fil;

	SortCachedHosts();
	fil = CachedHosts(&siz);
	if( siz - fil < 10 ){
		ExpireCachedHosts(3*60*60,3*60);
	}
	return 0;
}
static int resclient(ConnReq *cr,PCStr(host),int port,VSAddr *vsa);
int VSA_getbynameNocache(FL_PAR,ConnReq *cr,int cacheonly,PCStr(host),int port,VSAddr *vsa){
	int found;

	/*
	 * find in the host/addr in the table of local connections
	 */

	if( host[0] == 0 ){
		found = 0;
		VSA_atosa(vsa,port,host);
	}else
	if( VSA_strisaddr(host) ){
		/* only ip-address is necessary */
		found = 1;
		VSA_atosa(vsa,port,host);
	}else{
		double St,Elp;

		St = Time();
		{
		int conly;
		conly = RES_CACHEONLY(0);
		found = VSA_getbyname(cacheonly,host,port,vsa);
		RES_CACHEONLY(conly);
		}
		Elp = Time()-St;
		ECC_TimeForRes += Elp;
		ECC_Res++;
		if( found == 0 || 0.1 <= Elp ){
			TRACE("{%d} gethostbyname=%d %s:%d (%.2fs) <= co=%d (Fil=%d) %s:%d",
				(cr?cr->cr_id:0),found,host,port,Elp,cacheonly,CachedHosts(0),FL_BAR);
		}
	}
	return found;
}
static int newHTTPproxy(ConnCtx *cx,PollVect *Pv,ConnReq *crs,int crn,ConnReq *cr,FDesc clSock,PVStr(req),int rcc);
static int isHTTPtomyself(PCStr(req)){
	const char *qp;
	int ch;
	if( req[0] == 'C' && strncasecmp(req,"CONNECT",7) == 0 ){
		return 1;
	}
	for( qp = req; ch = *qp; qp++ ){
		if( ch == ' ' ){
			ch = *++qp;
			if( ch == '/' ){
				return 2;
			}
			break;
		}
	}
	return 0;
}
static int mssgWithEOH(PCStr(req)){
	const char *qp;
	int ch;
	int pch = 0;
	for( qp = req; ch = *qp; qp++ ){
		if( ch == '\n' && pch == '\n' )
			return 1;
		if( ch != '\r' )
			pch = ch;
	}
	return 0;
}

static int withResThread = 1;
#define RES_NOTYET -2
static int gotoWaitResolv(ConnCtx *cx,ConnReq *cr,PVStr(req),int rcc,VSAddr *svsa,int *foundp){
	IStr(mt,64);
	IStr(pr,64);
	IStr(sv,256);
	IStr(vr,64);
	IStr(host,256);
	int port = 80;
	int qlen;
	int wlen = 0;

	/*
	parseHTTPreq(cr,ZVStr(req,strlen(req)+1),rcc,AVStr(mt),AVStr(pr),AVStr(sv),AVStr(vr),0,&wlen);
	qlen = strlen(req);
	*/
	parseHTTPreq(cr,BVStr(req),rcc,AVStr(mt),AVStr(pr),AVStr(sv),AVStr(vr),0,&wlen);
	qlen = rcc;
	if( 0 < wlen && wlen != qlen ){
		TRACE("{%d}--BIN-1 %d / %d",cr->cr_id,qlen,wlen);
		qlen = wlen;
	}

	Xsscanf(sv,"%[^:]:%d",AVStr(host),&port);
	bzero(svsa,sizeof(VSAddr));
	if( withResThread == 0 ){
		*foundp = VSA_getbynameNocache(FL_ARG,cr,0,host,port,svsa);
		return 0;
	}else
	if( cr->cr_cstat == CCSV_C_RESOLVING ){
		*foundp = VSA_getbynameNocache(FL_ARG,cr,1,host,port,svsa);
		return 0;
	}else{
		*foundp = resclient(cr,host,port,svsa);
		if( *foundp == RES_NOTYET ){
			//putBuf(cx,cr,req,strlen(req));
			putBuf(cx,cr,req,qlen,FL_ARG);
			cr->cr_cstat = CCSV_C_RESOLVING;
			updateFdv++;
			return 1;
		}
	}
	return 0;
}
static int gotoWaitHTTPreq(ConnCtx *cx,ConnReq *cr,PCStr(req)){
	if( isHTTPtomyself(req) ){
		if(  !mssgWithEOH(req) ){
			TRACE("##{%d} incomp. REQ[%c]",cr->cr_id,req[0]);
			putBuf(cx,cr,req,strlen(req),FL_ARG);
			cr->cr_cstat = CCSV_C_WAITING_CLI;
			updateFdv++;
			return 1;
		}
	}
	/* if without LF (in the request line) ... */
	return 0;
}
static int newHTTPproxy2(ConnCtx *cx,PollVect *Pv,ConnReq *crs,int crn,ConnReq *cr){
	int rcc,siz,off,len;
	IStr(req,CC_BUFSIZ+1);

	if( cr->cr_buf ){
		off = cr->cr_bufRem;
		siz = CC_BUFSIZ;
		rcc = xrecv("HTTP Req2",cr,cr->cr_clSock,cr->cr_buf+off,siz-off-1);
		if( 0 < rcc ){
			cr->cr_bufRem += rcc;
			checkBuf(cr,cr->cr_bufRem,FL_ARG);
			cr->cr_buf[cr->cr_bufRem] = 0;
			if( mssgWithEOH(cr->cr_buf) ){
				len = cr->cr_bufRem;
				cr->cr_bufRem = 0;
				bcopy(cr->cr_buf,req,len);
				setVStrEnd(req,len);
				newHTTPproxy(cx,Pv,crs,crn,cr,cr->cr_clSock,AVStr(req),len);
				TRACE("##{%d} incomp. REQ[%c] DONE rcc=%d %d/%d/%d s%X",
					cr->cr_id,req[0],rcc,cr->cr_bufRem,strlen(req),len,
					cr->cr_cstat);
				return 1;
			}
			return 2;
		}
	}
	endConn(cr,"newHTTP2");
	updateFdv++;
	return 0;
}
static int parseHTTPreq2(ConnCtx *cx,ConnReq *cr,PVStr(buf),int rcc){
	IStr(method,64);
	IStr(proto,64);
	IStr(server,256);
	IStr(ver,64);
	int rcc2;
	int fround;
	VSAddr svsa;
	IStr(host,MaxHostNameLen);
	int found;
	int port = 80;
	int cont = 0;
	int wlen = 0;

	if( cr->cr_hqmeth == 'C' ){ /* CONNECT, don't parse after connection establised  */
		return rcc;
	}
	if( cr->cr_hqst == HSQ_FIELDS ){
		DEBUG("##{%d} HT req rem (%d)",cr->cr_id,rcc);
		cr->cr_hqst = HSQ_EOH;
		return rcc;
	}
	if( !isHTTPreq(buf) ){
		const unsigned char *ub = (const unsigned char*)buf;
		DEBUG("####{%d} HT not req [%d] %d [%X %X %X %X] HQST=%d",
			cr->cr_id,cr->cr_svsock,
			rcc,ub[0],ub[1],ub[2],ub[3],
			cr->cr_hqst
		);
		return rcc;
	}

	if( gotoWaitResolv(cx,cr,BVStr(buf),rcc,&svsa,&found) ){
		TRACE("{%d} reu WaitingResolv [%d %d]",cr->cr_id,cr->cr_clsock,cr->cr_svsock);
		return 0;
	}
	if( gotoWaitHTTPreq(cx,cr,buf) ){
		return 0;
	}
	parseHTTPreq(cr,BVStr(buf),rcc,AVStr(method),AVStr(proto),AVStr(server),AVStr(ver),1,&wlen);
	rcc2 = strlen(buf);
	if( 0 < wlen && wlen != rcc2 ){
		TRACE("{%d}--BIN-2 %d / %d",cr->cr_id,rcc2,wlen);
		rcc2 = wlen;
	}
	Xsscanf(server,"%[^:]:%d",AVStr(host),&port);
	DEBUG("##HT %s:%d %s:%d fn=%d eq=%d",
		host,port,VSA_ntoa(&svsa),VSA_port(&svsa),
		found,VSA_comp((VSAddr*)&cr->cr_svsa,&svsa)==0
	);

	if( cr->cr_delreqn ){
		SERIOUS("#####{%d} SWSV %s:%d Q%d-R%d D%d EXIT",cr->cr_id,host,port,
			cr->cr_hqn,cr->cr_hrn,cr->cr_delreqn);
		ECC_NumPipeSw++;
		endConn(cr,"del-Q");
		return 0;
	}
	if( cr->cr_hrn+1 < cr->cr_hqn ){
		SERIOUS("#####{%d} SWSV %s:%d Q%d-R%d D%d",cr->cr_id,host,port,
			cr->cr_hqn,cr->cr_hrn,cr->cr_delreqn);
		ECC_NumPipeSw++;
		cr->cr_delreqn++;
		return 0;
	}
	if( host[0] == 0 ){
		if( isHTTPorig(cx,cr,ver,host,port,buf) ){
			return 0;
		}
	}
	if( found ){
		cont = VSA_comp((VSAddr*)&cr->cr_svsa,&svsa) == 0;
		if( cont ){
			ECC_NumHttpKa++;
		}else{
			ECC_NumHttpSw++;
			DEBUGHT("##{%d} SWSV %d-%d D%d %s:%d",cr->cr_id,
				cr->cr_hqn,cr->cr_hrn,cr->cr_delreqn,host,port);
		/* if with pending resp. and switching to another server,
		 * by a pipelined req., abandon the req. not to break the pending resp.
 		 */
			if( 0 <= cr->cr_hrlen && cr->cr_hrrem <= 0 ){
			}else
			if( 0 < IsConnected(cr->cr_svsock,0) ){
				if( cr->cr_hrlen <= 0 || 0 < cr->cr_hrlen && 0 < cr->cr_hrrem ){
					TRACE("## ## ##svsw{%d} A rem=%d/%d PENDING",
						cr->cr_id,cr->cr_hrrem,cr->cr_hrlen);
					/* pipeline req during pending resonse */
					cr->cr_delreqn++;
					return 0;
				}
			}
			/* copy the old server connection in KA status */
			putSv(cx,cr);

			/* switch to the new server and continue */
			/* client side to SVCC_C_CONN status */
			cr->cr_cstat = CCSV_C_CONN; cr->cr_Timeout = Time()+10;
			cr->cr_svsa = *(SAB*)&svsa;
cr->cr_rsvsa = cr->cr_svsa;
			putBuf(cx,cr,buf,strlen(buf),FL_ARG);
			tryConnect(cx,cr,ver,method,proto,server);
			cont = 1;
			DEBUG("##svsw{%d} B [%d] rcc=%d",cr->cr_id,cr->cr_svsock,rcc2);
			return 0;
		}
	}
	DEBUG("-Ecc(%2d){%d} ##HT req %d len(%d) => %d (%s %s:%d) %s => %s:%d",
		cr->cr_ix,cr->cr_id,cr->cr_hqstat,rcc,rcc2,
		cont?"REU":"RST",host,port,
		serverid(cr),VSA_ntoa(&svsa),VSA_port(&svsa)
	);
	if( cont == 0 ){
		if( !found ){
			int wcc;
			TRACE("##{%d} SVSW Q%d-R%d Unknown %s",cr->cr_id,cr->cr_hqn,cr->cr_hrn,server);
			wcc = putmsg("RESP-Unknown-Host",cr,cr->cr_clSock,502,"Unknown Host");
		}
		rcc2 = -1;
	}
	return rcc2;
}
static int newHTTPproxy(ConnCtx *cx,PollVect *Pv,ConnReq *crs,int crn,ConnReq *cr,FDesc clSock,PVStr(req),int rcc){
	IStr(method,64);
	IStr(ver,64);
	IStr(proto,64);
	IStr(server,MaxHostNameLen);
	IStr(host,MaxHostNameLen);
	int port = 80;
	VSAddr svsa;
	int found;
	int qlen;
	int wcc;
	int wlen = 0;

	if( isHTTPreq(req) ){
		if( gotoWaitResolv(cx,cr,BVStr(req),rcc,&svsa,&found) ){
			TRACE("{%d} new WaitingResolv [%d %d]",cr->cr_id,cr->cr_clsock,cr->cr_svsock);
			return 0;
		}
		if( gotoWaitHTTPreq(cx,cr,req) ){
			return 0;
		}
		parseHTTPreq(cr,AVStr(req),rcc,AVStr(method),AVStr(proto),AVStr(server),AVStr(ver),1,&wlen);
		qlen = strlen(req);
		if( 0 < wlen && wlen != qlen ){
			TRACE("{%d}--BIN-3 %d / %d clen=%d",cr->cr_id,qlen,wlen,cr->cr_hqclen);
			qlen = wlen;
		}
		Xsscanf(server,"%[^:]:%d",AVStr(host),&port);
		if( host[0] == 0 ){
			if( isHTTPorig(cx,cr,ver,host,port,req) ){
				return 0;
			}
		}
		if( found == 0 ){
			wcc = putmsg("RESP-Unknown-Host",cr,clSock,502,"Unknown Host");
			TRACE("##{%d} Q%d-R%d Unknown Host %s",cr->cr_id,
				cr->cr_hqn,cr->cr_hrn,server);
			destroyAct(cr);
			return -1;
		}
		DEBUG("-Ecc{%d} HTTP<%d>(%s)[%s]%s://[%s](%d) len=%d",
			cr->cr_id,cr->cr_hqst,ver,method,proto,server,found,qlen);
		/*
		 * should wait if in HSQ_FIELDS
		 */
		cr->cr_svsa = *(SAB*)&svsa;
cr->cr_rsvsa = cr->cr_svsa;
		cr->cr_clSock = clSock;
		if( qlen ){
			putBuf(cx,cr,req,qlen,FL_ARG);
		}
		tryConnect(cx,cr,ver,method,proto,server);
		/*
		cr->cr_cstat = CCSV_C_RESOLV | CCSV_C_CONN | CCSV_C_HTTPREQ;
		*/
	}
	return 0;
}

static void shutdownAct(ConnReq *cr){
	int shut;

	if( cr->cr_hqmeth == 'C' ){
		/* trial to suppress CLOSE_WAIT at client-side */
		shut = SHUT_RDWR;
	}else{
		/* without RD not to cause EPIPE at remote ? */
		shut = SHUT_WR;
	}
	if( 0 <= cr->cr_clsock ){
		send(cr->cr_clsock,"",0,0);
		shutdown(cr->cr_clsock,shut);
	}
	if( 0 <= cr->cr_svsock ){
		send(cr->cr_svsock,"",0,0);
		shutdown(cr->cr_svsock,shut);
	}
}
static int destroyActX(PCStr(wh),ConnReq *cr){
	if( 0 <= cr->cr_svsock || 0 <= cr->cr_clsock ){
		if( cr->cr_hqmeth == 'C' ){
			TRACE("{%d} s%X destroying CONNECT [%d %d]",
				cr->cr_id,cr->cr_cstat,cr->cr_clsock,cr->cr_svsock);
		}
		shutdownAct(cr);
		cr->cr_finSt = Time();
		cr->cr_pcstat = cr->cr_cstat;
		cr->cr_cstat = CCSV_C_CLOSING;
		updateFdv++;
		return 0;
	}
	if( 0 <= cr->cr_svsock ){
		xclose(cr,cr->cr_svsock,0);
		cr->cr_svSock = FD_INVALID(-1);
	}
	if( 0 <= cr->cr_clsock ){
		xclose(cr,cr->cr_clsock,0);
		cr->cr_clSock = FD_INVALID(-1);
	}
	cr->cr_endclock = SvccClock;
	endConn(cr,wh);
	updateFdv++;
	if( cr->cr_svtid ){
		int terr;
		double St = Time();
		terr = thread_wait(cr->cr_svtid,1000);
		TRACE("##{%d} ThreadWait=%d %X (%.2f)",cr->cr_id,terr,cr->cr_svtid,Time()-St);
	}
	return 0;
}
static int destroyAct(ConnReq *cr){
	return destroyActX("destr",cr);
}
/* close() must be in non-blocking, by shutdown() ? */
static int delCon(PCStr(what),ConnReq *crs,int crn,ConnReq *dcr);
static int putSv(ConnCtx *cx,ConnReq *cr);
static int putSv(ConnCtx *cx,ConnReq *cr);
static int isAllZero(const void *ptr,int siz){
	const char *pp = (const char*)ptr;
	int pi;
	for( pi = 0; pi < siz; pi++ ){
		if( pp[pi] != 0 )
			return 0;
	}
	return 1;
}

static int newConn(PollVect *Pv,ConnReq *crs,int crn,FDesc acSock);
static int setConn(PCStr(what),ConnReq *cr,ConnReq *ncr);
static int getCount(ConnReq *crs,int crn,ConnReq *qcr);
static int getReq(ConnCtx *cx,PollVect *Pv,ConnReq *crs,int crn,ConnReq *cr,FDesc clSock){
	int svsock;
	SAB sa;
	VSAddr *vsa = (VSAddr*)&sa;
	int asiz;
	int rcode;
	int rcc,wcc;
	IStr(st,128);
	int timeout = 5*1000;
	IStr(sockname,128);
	int ci;
	ConnReq ncr;
	ConnReq ocr;
	double St,Elp;
	int serrno;
	IStr(buf,CC_BUFSIZ);

	St = Time();
	rcc = xrecv("RECV Req",cr,clSock,buf,CC_BUFSIZ-256);
	if( rcc <= 0 ){
		SERIOUS("{%d} s%X getReq rcc=%d/E%d Q%d-R%d (%.3f)",cr->cr_id,cr->cr_cstat,rcc,errno,cr->cr_hqn,cr->cr_hrn,Time()-cr->cr_statSt);
		destroyAct(cr);
		return -1;
	}
	setVStrEnd(buf,rcc);

	if( 8 <= rcc ){
		const char *req = buf;
		if( isupper(req[0]) && isupper(req[1]) && isupper(req[2]) ){
			int rcc2 = 0;
			int rem;
			int withEOH;

			withEOH = mssgWithEOH(buf);
			if( rcc < CC_BUFSIZ-256 )
			//if( 0 < inputReady(clSock.fd_fd,0) || (!withEOH && 0 < PollIn(clSock,10)) ){
			if( !withEOH && 0 < xPollIn(clSock,10) ){
				rem = CC_BUFSIZ-256-rcc; /* 256 -- space for Host: insertion */
				rcc2 = xrecv("RECV HTTP Req2",cr,clSock,buf+rcc,rem);
				TRACE("##{%d} long REQ=%d+%d(%d) /%d",cr->cr_id,rcc,rcc2,withEOH,rem);
				if( rcc2 < 0 ){
					rcc2 = 0;
				}
			} 
			newHTTPproxy(cx,Pv,crs,crn,cr,clSock,AVStr(buf),rcc+rcc2);
			return 0;
		}
	}

	if( sizeof(ncr) != rcc ){
		TRACE("## FATAL bad size REQ %d/%d",rcc,sizeof(ncr));
	}
	bcopy(buf,&ncr,sizeof(ncr));

	if( rcc < sizeof(ncr) ){
		if( rcc != 0 )
		DEBUG("-Ecc(%2d){%d} BadReq %d/%d [%d][%d] ####",
			cr->cr_ix,cr->cr_id,
			rcc,sizeof(ncr),clSock.fd_fd,cr->cr_clsock);
		delCon("emptyReq",crs,crn,cr);
		return 0;
	}
	if( ncr.cr_qflag & CCSV_Q_DESTROY ){
		DEBUG("-Ecc(%2d){%d} destroy (%d){%d} [%d][%d] ####",
			cr->cr_ix,cr->cr_id,ncr.cr_ix,ncr.cr_id,
			clSock.fd_fd,cr->cr_clsock);
		delCon("Destroy-Dst",crs,crn,&ncr);
		wcc = xsend("Resp-Done-Destroy",cr,clSock,&ncr,sizeof(ncr));
		delCon("Destroy-Src",crs,crn,cr);
		return 0;
	}
	if( ncr.cr_qflag & CCSV_Q_GETCLCNT ){
		getCount(crs,crn,&ncr);
		ncr.cr_ix = cr->cr_ix;
		ncr.cr_id = cr->cr_id;
		ncr.cr_rcvd = SvccRct;
		/*
		DEBUG("-Ecc(%2d){%d} CLCNT D[%d][%d] ### (%d)",
			cr->cr_ix,cr->cr_id,
			clsock,cr->cr_clsock,ncr.cr_clcnt);
		*/
		wcc = xsend("Resp-Info-ClientCnt",cr,clSock,&ncr,sizeof(ncr));
		updateFdv = 1; /* to get connect for the resp. */
		return 0;
	}

	if( isAllZero(&ncr.cr_clsa,sizeof(ncr.cr_clsa)) ){
		TRACE("##{%d} newConn(0.0.0.0:0) <= %s",cr->cr_id,clientid(cr));
	}
	cr->cr_clsa = ncr.cr_clsa;
	serrno = errno;
	asiz = VSA_size((VSAddr*)&sa);
	ncr.cr_clSock = clSock;
	sa = ncr.cr_svsa;
	bzero(&ocr,sizeof(ocr));
	rcode = findSv(&ncr,crs,crn,&ocr);
	if( rcode == 0 ){
		svsock = ocr.cr_svsock;
		ncr.cr_ix = cr->cr_ix;
		ncr.cr_id = ocr.cr_id;
		ncr.cr_svSock = FD_NEW("getReq-1",cr,svsock);
		ncr.cr_cstat = CCSV_C_RELAY; ncr.cr_statSt = Time();
		ncr.cr_reused = ocr.cr_reused + 1;
		ncr.cr_connSt = ocr.cr_connSt;
		ncr.cr_rstat = CCSV_R_REU;
		ncr.cr_ckaSt = 0;
		setConn("REU-1",cr,&ncr);
		SvccReu++;
	}else{
		svsock = xnewSocket(cr,"CCSV-getReq","");
		setosf_FL("CCSV-getReq","(serv-socket)",svsock,NULL,__FILE__,__LINE__);
		/* should set the size of socket buffer ? */

		ncr.cr_ix = cr->cr_ix;
		ncr.cr_id = cr->cr_id;
		ncr.cr_para = ocr.cr_para;
		ncr.cr_svSock = FD_NEW("getReq-2",cr,svsock);
		ncr.cr_cstat = CCSV_C_CONN; cr->cr_Timeout = Time()+10;

		ncr.cr_connSt = Time();
		errno = 0;
		rcode = connect(svsock,(SAP)&sa,asiz);
		serrno = errno;
		if( rcode == 0 ){
			set_keepalive(svsock,1);
			ncr.cr_rstat = CCSV_R_NEW;
			ncr.cr_cstat = CCSV_C_RELAY; ncr.cr_statSt = Time();
			setConn("CON-1",cr,&ncr);
		}else
		if( serrno == EINPROGRESS || serrno == EWOULDBLOCK ){
			ncr.cr_rstat = CCSV_R_CON;
			setConn("CON-2",cr,&ncr);
		}else{
	TRACE("##{%d} CON-E (imm.)[%d]=> %s:%d connect() failure, rcode=%d err=%d ##ERR##",
				ncr.cr_id,svsock,VSA_ntoa(vsa),VSA_port(vsa),rcode,errno);
			updateFdv = 1;
			xclose(cr,svsock,1);
			svsock = -1;
			ncr.cr_svSock = FD_INVALID(-8);
			ncr.cr_rstat = CCSV_R_ERR;
			cr->cr_cstat = CCSV_C_WAITREQ; cr->cr_statSt = Time();
		}
	}
	if( rcode == 0 ){
		ncr.cr_svSock = FD_NEW("getReq-3",cr,svsock);
	}
	if( ncr.cr_rstat != CCSV_R_CON /* or in progressive mode */ ){
		wcc = xsend("Resp-ImmStartClient",cr,clSock,&ncr,sizeof(ncr));
		ncr.cr_rstat |= CCSV_R_SENT;
	}
	if( rcode == 0 ){
		updateFdv = 1;
	}

	Elp = Time()-St;
	Elps += Elp;
	if( 0.1 < Elp ){
		SERIOUS("-Ecc(%2d){%d} slow conn. %.3f/%.3f %s:%d",
			ncr.cr_ix,ncr.cr_id,Elp,Elps,
			VSA_ntoa((VSAddr*)&sa),VSA_port((VSAddr*)&sa));
	}
	return -1;
}
#ifndef WSAEINVAL
#define WSAEINVAL -EINVAL
#endif
static int gotConn(ConnReq *cr1,int svsock){
	int rcode;
	int serrno;
	int wcc;
	SAP sap = (SAP)&cr1->cr_svsa;
	int xerr = 0;
	int xlen = sizeof(xerr);
	double St,Elp;

	errno = 0;
	rcode = connect(svsock,sap,VSA_size((VSAddr*)sap));
	serrno = errno;
	if( rcode == 0 ){
		set_keepalive(svsock,1);
		if( 0.1 < Time()-cr1->cr_connSt ){
			TRACE("{%d} CON-slow (%.3f) [%d] => %s",cr1->cr_id,Time()-cr1->cr_connSt,svsock,serverid(cr1));
		}
	}

	if( rcode < 0 && serrno == WSAEINVAL ){
		int iscon = IsConnected(svsock,0);
		DEBUG("-Ecc(%2d){%d} CON-3T e=%d [%d/%d %X %d] con=%d ##ERR##",
			cr1->cr_ix,cr1->cr_id,
			serrno,svsock,sockPort(svsock),
			sap,VSA_size((VSAddr*)sap),iscon);

 cr1->cr_err++;
 TRACE("-Ecc(%2d){%d} CON-3T e=%d [%d/%d %X %d] con=%d ##ERR(%d)##",
 cr1->cr_ix,cr1->cr_id,
 serrno,svsock,sockPort(svsock),
 sap,VSA_size((VSAddr*)sap),iscon,cr1->cr_err);
		if( 10 <= cr1->cr_err ){
		}else
		if( iscon ){
			/* WinSock transient status ? */
			return 0;
			// should be rcode = 0; ??
		}
	}
	if( rcode < 0 && serrno == EINVAL ){
		int iscon = IsConnected(svsock,0);
		DEBUG("-Ecc(%2d){%d} CON-3T e=%d [%d/%d %X %d] con=%d ##ERR##",
			cr1->cr_ix,cr1->cr_id,
			serrno,svsock,sockPort(svsock),
			sap,VSA_size((VSAddr*)sap),iscon);
		if( iscon ){
			TRACE("####{%d} CONNECTED errno=EINVAL",cr1->cr_id);
			rcode = 0;
		}
	}

	if( rcode == 0
	 || rcode < 0 && serrno == EISCONN
	){
		if( cr1->cr_hqmeth == 'C' ){ /* CONNECT, return HTTP/1.0 200 */
			const char *resp = "HTTP/1.0 200 DeleGate/Ecc OK\r\n\r\n";
		wcc = xsend("Resp-CONNECT-OK",cr1,cr1->cr_clSock,resp,strlen(resp));
			DEBUG("##{%d} CONNECT OK rem=%d",cr1->cr_id,cr1->cr_bufRem);
			if( cr1->cr_bufRem == 0 ){
				cr1->cr_cstat = CCSV_C_RELAY; cr1->cr_statSt = Time();
				updateFdv++;
				eccLOGX_tcpCon++;
				return 0;
			}
		}
	}
	if( cr1->cr_bufRem )
	if( rcode == 0
	 || rcode < 0 && serrno == EISCONN
	){
		cr1->cr_cstat = CCSV_C_PENDING_SVO;
		updateFdv++;
		DEBUG("-Ecc(%2d){%d} CON-3 [%d] (%.3f) %s:%d ##FORW(%d)##",
			cr1->cr_ix,cr1->cr_id,
			svsock,Time()-cr1->cr_connSt,
			VSA_ntoa((VSAddr*)sap),VSA_port((VSAddr*)sap),
			cr1->cr_bufRem
		);
		eccLOGX_tcpCon++;
		return 0;
	}

	if( rcode == 0
	 || rcode < 0 && serrno == EISCONN
	){
		cr1->cr_cstat = CCSV_C_RELAY; cr1->cr_statSt = Time();
		updateFdv++;
/*log*/if(0)
		DEBUG("-Ecc(%2d){%d} CON-3 [%d] r%d e%d (%.3f) %s:%d",
			cr1->cr_ix,cr1->cr_id,
			svsock,rcode,serrno,Time()-cr1->cr_connSt,
			VSA_ntoa((VSAddr*)sap),VSA_port((VSAddr*)sap)
		);

		cr1->cr_rstat = CCSV_R_NEW;
		if( (cr1->cr_rstat & CCSV_R_SENT) == 0 ){
			St = Time();
		wcc = xsend("Resp-CONN-DELAYED",cr1,cr1->cr_clSock,cr1,sizeof(ConnReq));
			cr1->cr_rstat |= CCSV_R_SENT;
			if( 0.1 < (Elp=Time()-St) ){
				SERIOUS("-Ecc(%2d){%d} CON-3 slow resp. (%.3f)",
					cr1->cr_ix,cr1->cr_id,Elp);
			}
		}
		eccLOGX_tcpCon++;
		return 0;
	}

	getsockopt(svsock,SOL_SOCKET,SO_ERROR,&xerr,&xlen);
	SvccErr++;
	SvccErrId = cr1->cr_id;
	TRACE("##{%d} s%X CON-E (%.3f)=> %s connect() failure, rcode=%d err=%d/%d %s",cr1->cr_id,cr1->cr_cstat,
		Time()-cr1->cr_connSt,serverid(cr1),
		rcode,serrno,xerr,
		xerr==ETIMEDOUT?"TIMEOUT":"##ERR##");

	cr1->cr_rstat = 0; /* ERR */
	if( cr1->cr_hqstat ){
		const char *emsg = (xerr == ETIMEDOUT)?"Connection Timeout":"Connection Error";;
		wcc = putmsg("CONN-HTTP-TIMEOUT",cr1,cr1->cr_clSock,504,emsg);
	}else{
		wcc = xsend("CONN-ERROR",cr1,cr1->cr_clSock,cr1,sizeof(ConnReq));
	}
	updateFdv = 1;
	xclose(cr1,cr1->cr_svsock,1);
	xclose(cr1,cr1->cr_clsock,0);
	cr1->cr_svSock = FD_INVALID(-3);
	cr1->cr_clSock = FD_INVALID(-3);
	cr1->cr_endclock = SvccClock;
	endConn(cr1,"connF");
	return -1;
}

#if defined(_MSC_VER)
static void setSendError(PCStr(wh),ConnReq *cr,FDesc oSock,int len,int wcc){
	int xerr;

	xerr = WSAGetLastError();
	TRACE("##{%d} %s send [%d/%d] %d/%d err=%d/%d",cr->cr_id,wh,
		oSock.fd_fd,oSock.fd_handle,wcc,len,errno,xerr);
	if( xerr == WSAEWOULDBLOCK ){
		errno = EAGAIN;
	}else
	if( xerr == WSAECONNRESET || xerr == WSAECONNABORTED ){
		errno = EPIPE;
	}
}
#else
static void setSendError(PCStr(wh),ConnReq *cr,FDesc oSock,int len,int wcc){
}
#endif

static int xaccept(ConnReq *cr,FDesc acSock,VSAddr *vsa,int *len){
	int clsock;

	if( acSock.fd_fd < 0 ){
		TRACE("##{%d} s%X FATAL xaccept([%d/%d])",cr->cr_id,cr->cr_cstat,acSock.fd_fd,acSock.fd_handle);
		return -1;
	}
	if( isWindows() ){
		double Stc = 0;
		if( enterCSCX(handleCSC,1) != 0 ){
			Stc = Time();
			enterCSC(handleCSC);
		}
		clsock = _ACCEPT(acSock.fd_fd,(SAP)vsa,len);
		leaveCSC(handleCSC);
		if( clsock < 0 ){
			TRACE("---- FATAL xaccept(%d/%d)=%d",acSock.fd_fd,acSock.fd_handle,clsock);
		}
		if( Stc ){
			TRACE("---- {%d} Mutex xaccept [%d/%d] (%.3f)",cr->cr_id,
				clsock,SocketOf(clsock),Time()-Stc);
		}
	}else
	{
		clsock = accept(acSock.fd_fd,(SAP)vsa,len);
	}
	return clsock;
}
#undef send
static int xsend(PCStr(wh),ConnReq *cr,FDesc oSock,const void *b,int len){
	int wcc;

	stksize(FL_ARG);
	if( oSock.fd_fd < 0 || len < 0 ){
		TRACE("##{%d} s%X FATAL (%s) xsend([%d/%d],%d)",cr->cr_id,cr->cr_cstat,wh,oSock.fd_fd,oSock.fd_handle,len);
		return -1;
	}
	if( CC_BUFSIZ < len ){
		TRACE("##{%d} s%X FATAL (%s) xsend([%d/%d],%d)",cr->cr_id,cr->cr_cstat,wh,oSock.fd_fd,oSock.fd_handle,len);
	}
	if( isWindows() ){
		/* truncated images in AppleStore with iPod */
		if(0)if( isWindowsCE() ){ /* wireless */
			if( CC_MTU < len ){ /* should be the MTU of the connection */
				len = CC_MTU;
			}
		}
		wcc = send(oSock.fd_handle,(const char*)b,len,0);
		if( wcc < len && isWindows() ){
			setSendError(wh,cr,oSock,len,wcc);
			// tune automatically.
		}
	}else{
		wcc = send(oSock.fd_fd,(const char*)b,len,0);
	}
	return wcc;
}
#undef recv
static int xrecv(PCStr(wh),ConnReq *cr,FDesc iSock,void *b,int siz){
	int rcc;

	stksize(FL_ARG);
	if( iSock.fd_fd < 0 || siz < 0 ){
		TRACE("##{%d} s%X FATAL (%s) xrecv([%d/%d],%d)",cr->cr_id,cr->cr_cstat,wh,iSock.fd_fd,iSock.fd_handle,siz);
		return -1;
	}
	if( CC_BUFSIZ < siz ){
		TRACE("##{%d} s%X FATAL (%s) xrecv([%d/%d],%d)",cr->cr_id,cr->cr_cstat,wh,iSock.fd_fd,iSock.fd_handle,siz);
	}
	if( isWindows() ){
		rcc = recv(iSock.fd_handle,(char*)b,siz,0);
	}else{
		rcc = recv(iSock.fd_fd,(char*)b,siz,0);
	}
	return rcc;
}
static int xwrite(FDesc oSock,const void *buf,int len){
	int wcc;
	unsigned long uwcc;

#ifdef _MSC_VER
	if( WriteFile((HANDLE)oSock.fd_handle,buf,len,&uwcc,NULL) ) wcc = uwcc; else wcc = -2;
	if( wcc < 0 ){
		TRACE("-- xwrite([%d/%d])=%d err=%d",oSock.fd_fd,oSock.fd_handle,uwcc,GetLastError());
	}
#else
	wcc = write(oSock.fd_fd,buf,len);
#endif
	return wcc;
}
static int xread(FDesc iSock,void *buf,int siz){
	int rcc;
	unsigned long urcc;

#ifdef _MSC_VER
        if( ReadFile((HANDLE)iSock.fd_handle,buf,siz,&urcc,NULL) ) rcc = urcc; else rcc = -2;
	if( rcc < 0 ){
		TRACE("-- xread([%d/%d])=%d err=%d",iSock.fd_fd,iSock.fd_handle,urcc,GetLastError());
		msleep(200);
	}
#else
	rcc = read(iSock.fd_fd,buf,siz);
#endif
	return rcc;
}
#ifdef _MSC_VER
static int _PollInsOuts(int timeout,int nfds,FDesc _fdv[],int ev[],int _rev[]);
#endif
static int xPollIn(FDesc Fd,int timeout){
	int _ev[1],_rev[1],nready;
	_ev[0] = PS_IN|PS_PRI;
#ifdef _MSC_VER
	nready = _PollInsOuts(timeout,1,&Fd,_ev,_rev);
#else
	nready = PollInsOuts(timeout,1,&Fd.fd_fd,_ev,_rev);
#endif
	return nready;
}

static int relay1(ConnCtx *cx,PollVect *Pv,ConnReq *cr,int wrdy,FDesc rSock,int qev1,int rev1){
	IStr(buf,CC_BUFSIZ);
	int rcc = 0;
	int wcc = 0;
	FDesc iSock,oSock;
	FDesc clSock = cr->cr_clSock;
	FDesc svSock = cr->cr_svSock;
	int fromclnt;
	double St0;
	double St,Elp;
	double ElpR = 0;
	int serrnoR = 0;
	int serrnoS = 0;
	int fromBuf = 0;

	if( cr->cr_cstat == CCSV_C_SVKA ){
		rcc = xrecv("SVKA-EOS",cr,cr->cr_svSock,buf,8);
		DEBUGKA("{%d}*%d SVKA closed (%.3f) %d %X <= %s",
			cr->cr_id,cr->cr_reused,Time()-cr->cr_ckaSt,rcc,buf[0],serverid(cr));
		destroyAct(cr);
		return 0;
	}
	if( clSock.fd_fd < 0 && svSock.fd_fd < 0 ){
		DEBUG("-Ecc(%2d){%d}*%d FIN-X [%d %d] %X {%d} ##ERR##",
			cr->cr_ix,cr->cr_id,cr->cr_reused,
			clSock.fd_fd,svSock.fd_fd,cr->cr_cstat,SvccClock);
		endConn(cr,"Fin-X");
		cr->cr_endclock = SvccClock;
		return -1;
	}

	St0 = Time();
	if( wrdy ){
		oSock = rSock;
		if( clSock.fd_fd == oSock.fd_fd )
			iSock = svSock;
		else	iSock = clSock;
	}else{
		iSock = rSock;
		if( clSock.fd_fd == iSock.fd_fd )
			oSock = svSock;
		else	oSock = clSock;
	}
	fromclnt = (iSock.fd_fd == clSock.fd_fd);
	errno = 0;

	if( 0 < cr->cr_bufRem ){
		bcopy(cr->cr_buf,buf,cr->cr_bufRem);
		rcc = cr->cr_bufRem;
		cr->cr_bufRem = 0;
		fromBuf = 1;
		serrnoR = 0;
		goto CC_SEND;
	}

	/* should be a multple of MTU */
	St = Time();
	errno = 0;
	rcc = xrecv("RECV relay",cr,iSock,buf,sizeof(buf));
	serrnoR = errno;
	ElpR = Time() - St;

if(0)
if( !fromclnt && rcc == 0 && serrnoR == 0 ){
 if( 0 <= cr->cr_clsock && 0 <= cr->cr_svsock ){
  DEBUG("-Ecc(%2d){%d}*%d err=%d [%d %d] PEND[%d]%d[%X]",
  cr->cr_ix,cr->cr_id,cr->cr_reused,serrnoR,
  cr->cr_clsock,cr->cr_svsock,iSock.fd_fd,IsConnected(rSock.fd_fd,0),rev1);
  return 0;
 }
}

	if( rcc <= 0 && serrnoR == EAGAIN ){
		DEBUG("-Ecc(%2d) ## EAGAIN %d/%d fromc=%d",
			cr->cr_ix,rcc,sizeof(buf),fromclnt);
		return 0;
	}else
	if( 0 < rcc ){
		cr->cr_rct[0] += 1;
		SvccRcc += rcc;
		SvccRct += 1;
	}else{
		ConnReq *cr1;
		if( iSock.fd_fd < 0 ){
			TRACE("##{%d} s%X [%d %d] rcc=%d err=%d ##FATAL##",
				cr->cr_id,cr->cr_cstat,
				cr->cr_clsock,cr->cr_svsock,rcc,serrnoR);
		}else
		if( cr1 = addConn(cx->cx_Pv,cx->cx_crn,cx->cx_crs,iSock) ){
TRACE("--{%d} <= {%d} CLOSING [%d][%d %d]%s",cr1->cr_id,cr->cr_id,iSock.fd_fd,
cr->cr_clsock,cr->cr_svsock,fromclnt?"EoS-CL":"EoS-SV");

		shutdownWR(iSock.fd_fd);
		cr1->cr_finSt = Time();
		cr1->cr_pcstat = cr->cr_cstat;
		cr1->cr_cstat = CCSV_C_CLOSING;
		updateFdv++;

			if( iSock.fd_fd == cr->cr_clsock )
				cr->cr_clSock = FD_INVALID(-100 - cr->cr_clsock);
			else	cr->cr_svSock = FD_INVALID(-100 - cr->cr_svsock);
		}else{
			xclose(cr,iSock.fd_fd,0);
			if( iSock.fd_fd == cr->cr_clsock )
				cr->cr_clSock = FD_INVALID(-100 - cr->cr_clsock);
			else	cr->cr_svSock = FD_INVALID(-100 - cr->cr_svsock);
		}
		updateFdv++;

		if( cr->cr_clsock < 0 && cr->cr_svsock < 0 ){
/*log*/if(0)
			DEBUG("-Ecc(%2d){%d}*%d FIN-R s%X [%d %s %d] %d err=%d (%.2f)",
				cr->cr_ix,cr->cr_id,cr->cr_reused,cr->cr_cstat,
				clSock.fd_fd,fromclnt?">>":"<<",svSock.fd_fd,rcc,errno,
				Time()-cr->cr_connSt);
			cr->cr_endclock = SvccClock;
			endConn(cr,"Fin-R");
			return 1;
		}
		if( fromclnt ){
			if( cr->cr_qflag & CCSV_Q_SVKA ){
				/*log*/if(0)
				DEBUG("-Ecc(%2d){%d}*%d SVKA1 [%d %d] %s:%d",
					cr->cr_ix,cr->cr_id,cr->cr_reused,
					clSock.fd_fd,svSock.fd_fd,
					VSA_ntoa((VSAddr*)&cr->cr_svsa),
					VSA_port((VSAddr*)&cr->cr_svsa)
				);
				cr->cr_ckaSt = Time();
				cr->cr_cstat = CCSV_C_SVKA;
				ECC_NumHttpKa1++;
				return 1;
			}
			if( rcc == 0 && serrnoR == 0
			 && 0 < cr->cr_hqn && cr->cr_hqn == cr->cr_hrn
			 && cr->cr_hrsvka /* in keep-alive */
			 && inputReady(cr->cr_svsock,0) == 0 /* no pending resp. */
			){
				/* reset from client with a left server in keep-alive */
				DEBUGKA("##{%d}*%d s%X SVKA=%d Q%d-R%d/%d (%d+%d+%d) %s",
					cr->cr_id,cr->cr_reused,cr->cr_cstat,cr->cr_hrsvka,
					cr->cr_hqn,cr->cr_hrn,
					cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,
					cr->cr_hrendE,cr->cr_hrendL,cr->cr_hrendC,
					serverid(cr)
				);
				if( cr->cr_hrn == (cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC) ){
					cr->cr_ckaSt = Time();
					cr->cr_cstat = CCSV_C_SVKA;
					updateFdv++;
					ECC_NumHttpKa2++;
					return 1;
				}
			}
			DEBUG("-Ecc(%2d) DONT SVKA [%d %d] %s:%d",
				cr->cr_ix,clSock.fd_fd,svSock.fd_fd,
				VSA_ntoa((VSAddr*)&cr->cr_svsa),
				VSA_port((VSAddr*)&cr->cr_svsa)
			);
		}else{
			/* if this is the first response (response header) to a client
			 * not in keep-live, to server reused in keep-alive, then should
			 * retry the connection and resending the request.
			 */
			if( cr->cr_hqstat && cr->cr_hrn < cr->cr_hqn ){
				if( cr->cr_hqn <= 1 && cr->cr_reused ){
					const char *req = "";
					if( cr->cr_buf && cr->cr_bufRem ){
						char *dp;
						req = cr->cr_buf;
						cr->cr_buf[128] = 0;
						if( dp = strchr(cr->cr_buf,'\n') )
							*dp = 0;
					}
		TRACE("#### #### {%d}*%d s%X %d-%d (%d) RETRY-inKA %.2f %s (%d)%s",
					cr->cr_id,cr->cr_reused,cr->cr_cstat,cr->cr_hqn,cr->cr_hrn,
					cr->cr_hrsvka,Time()-cr->cr_connSt,serverid(cr),
					cr->cr_bufRem,req
					);
	if(0)
					if( cr->cr_hqn == cr->cr_hrn+1 ){
	sprintf(buf,"HTTP/1.1 503 DeleGate/Ecc retry\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n");
	wcc = xsend("retry-HCKA",cr,cr->cr_clSock,buf,strlen(buf));
						updateFdv++;
						xclose(cr,cr->cr_svSock.fd_fd,1);
						cr->cr_svSock = FD_INVALID(-1);
						cr->cr_cstat = CCSV_C_WAITREQ; cr->cr_statSt = Time();
						cr->cr_hrn++;
						TRACE("-- --{%d} RETRY-inKA CLKA %s",cr->cr_id,
							serverid(cr));
						return 4;
					}
	sprintf(buf,"HTTP/1.0 503 DeleGate/Ecc retry\r\nRetry-After: 1\r\n\r\n");
	wcc = xsend("retry-HCKA",cr,cr->cr_clSock,buf,strlen(buf));
					destroyAct(cr);
					return 4;
				}else{
					DEBUG("##{%d}*%d %d-%d (%d) EMPTY-resp %.2f %s",
					cr->cr_id,cr->cr_reused,cr->cr_hqn,cr->cr_hrn,
					cr->cr_hrsvka,Time()-cr->cr_connSt,serverid(cr));
				}
			}
			if( cr->cr_cstat == CCSV_C_RELAY
			 && cr->cr_hqn == cr->cr_hrn
			 && cr->cr_hrn == cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC
			 && cr->cr_hrsvka
			 && 0 <= cr->cr_clsock
			){
				// should remove Connection:close
				// should set correct Content-Length or do resp. in chunked
				TRACE("{%d} s%X CLKA [%d %d] Q%d-R%d-E%d-K%d",cr->cr_id,cr->cr_cstat,
					cr->cr_clsock,cr->cr_svsock,
					cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,
					cr->cr_hrsvka
				);
				cr->cr_cstat = CCSV_C_WAITREQ; cr->cr_statSt = Time();
				return 0;
			}
		}
		/* must relay the reset to the client */ //return 1;
	}

	/* should close isock immediatery after its EOF and keep flushing osock ... */

	if( oSock.fd_fd < 0 ){
		/* should close the input after too much err. */
		cr->cr_wrerr++;
		if( !fromclnt && cr->cr_wrerr < 8 ){
			/* flush server response to try keeping it alive */
			return 2;
		}
		updateFdv++;
		xclose(cr,iSock.fd_fd,0);
		if( iSock.fd_fd == cr->cr_clsock )
			cr->cr_clSock = FD_INVALID(-200 - cr->cr_clsock);
		else	cr->cr_svSock = FD_INVALID(-200 - cr->cr_svsock);
		if( cr->cr_clsock < 0 && cr->cr_svsock < 0 ){
			DEBUG("-Ecc(%2d) FIN-O E%d [%d %s %d]%d DST RESET",
				cr->cr_ix,cr->cr_wrerr,
				cr->cr_clsock,fromclnt?">":"<",cr->cr_svsock,
				rcc);
			cr->cr_endclock = SvccClock;
			endConn(cr,"Fin-O");
		}else{
			DEBUG("-Ecc(%2d) FIN-O {%d} [%d %d]%d DST RESET ?? ##ERR##",
				cr->cr_ix,cr->cr_wrerr,iSock.fd_fd,oSock.fd_fd,rcc);
		}
		return 3;
	}

CC_SEND:
	if( 0 < rcc && 0 < cr->cr_hqstat ){
		int rcc2;
		if( fromclnt ){
			if( 1 < cr->cr_hqstat++ ){
			  if( fromBuf ){
				/* prefetched and parsed already */
				rcc2 = rcc;
			  }else{
				rcc2 = parseHTTPreq2(cx,cr,AVStr(buf),rcc);

	/* if it is not a resp. head, then the connection must be abandoned */

				if( rcc2 == 0
				 && (cr->cr_cstat == CCSV_C_CONN || cr->cr_cstat == CCSV_C_PENDING_SVO) ){
					/* server switch in keep-alive */
					return 4;
				}
				if( rcc2 == 0 ){
					return 4; /* just ignore pipelined request to another server */
				}
				if( rcc2 < 0 ){
					/* don't destroy but fallback to C_CONN */
					if( 0 <= oSock.fd_fd ){
	IStr(resp,128);
	sprintf(resp,"HTTP/1.0 500 DeleGate/Ecc\r\n\r\n");
	wcc = xsend("EOS-HTTP",cr,cr->cr_clSock,resp,strlen(resp));
					}
					destroyAct(cr);
					return 4;
				} 
				rcc = rcc2;
			   }
			}
		}else{
			if( cr->cr_hrn < cr->cr_hqn ){
if( fromBuf ){
  TRACE("----{%d} WARN-A retrying fromSV Q%d-R%d-E%d-K%d",cr->cr_id,
  cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,cr->cr_hrsvka);
  rcc2 = rcc;
}else{
				rcc2 = parseHTTPresp(cx,cr,AVStr(buf),rcc);
}
			}else{
				if( rcc == cr->cr_hrrem ){
if( fromBuf ){
  TRACE("----{%d} WARN-B retrying fromSV Q%d-R%d-E%d-K%d",cr->cr_id,
  cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,cr->cr_hrsvka);
}else{
					cr->cr_hrendL++;
}
				}
if( fromBuf ){
  TRACE("----{%d} WARN-C retrying fromSV Q%d-R%d-E%d-K%d rcc=%d/%d",cr->cr_id,
  cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,cr->cr_hrsvka,rcc,cr->cr_hrrem);
}else{
				cr->cr_hrrem -= rcc;
}
				if( 0 < cr->cr_hrlen && cr->cr_hrrem <= 0 ){
					if( cr->cr_hrenc == 0 )
		DEBUGHT("##{%d} RESP %d-%d D%d rcc=%d rem=%d/%d",
		cr->cr_id,cr->cr_hqn,cr->cr_hrn,cr->cr_delreqn,
		rcc,cr->cr_hrrem,cr->cr_hrlen);
					// if pipeline, cstat = 0;
				}
			}
			if( cr->cr_hrenc && 7 <= rcc ){
				const unsigned char *ub = (const unsigned char*)buf;
				if( ub[rcc-7] == '\r' && ub[rcc-6] == '\n'
				 && ub[rcc-5] == '0'
				 && ub[rcc-4] == '\r' && ub[rcc-3] == '\n'
				 && ub[rcc-2] == '\r' && ub[rcc-1] == '\n'
				){
		DEBUGHT("##{%d} RESP %d-%d rcc=%d rem=%d/%d [%X %X %X %X %X %X %X]",
		cr->cr_id,cr->cr_hrn,cr->cr_hqn,
		rcc,cr->cr_hrrem,cr->cr_hrlen,
		ub[rcc-7],ub[rcc-6],ub[rcc-5],
		ub[rcc-4],ub[rcc-3],ub[rcc-2],ub[rcc-1]);
if( fromBuf ){
  TRACE("----{%d} WARN-D retrying fromSV Q%d-R%d-E%d-K%d",cr->cr_id,
  cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,cr->cr_hrsvka);
}else{
					cr->cr_hrendC++;
}
				}
			}
		}
	}

	St = Time();
	errno = 0;
/* must care the caes of rcc==0 */
	if( rcc < 0 ){
		if( cr->cr_hqmeth != 'C' ) /* Read error from serv. in non CONNECT */
		TRACE("####{%d} s%X rcc=%d err=%d fromcl=%d [%d]",
			cr->cr_id,cr->cr_cstat,rcc,serrnoR,fromclnt,iSock.fd_fd);
		wcc = -1;
		errno = EINVAL;
	}else{
		wcc = xsend(fromclnt?"relay-tosv":"relay-tocl",cr,oSock,buf,rcc);
	}
	serrnoS = errno;
	Elp = Time()-St;

//TRACE("##{%d}s%X %d <= %d e%d/%d",cr->cr_id,cr->cr_cstat,osock,isock,wcc,rcc,serrnoS,serrnoR);

	if( 0.05 < ElpR+Elp ){
		SERIOUS("-Ecc(%2d){%d} ##slow relay %s i%.3f o%.3f [%d]%d/%d",
			cr->cr_ix,cr->cr_id,fromclnt?"toSV":"toCL",
			ElpR,Elp,iSock.fd_fd,wcc,rcc);
	}
	if( 0 < wcc ){
		SvccWcc += wcc;
	}
	if( serrnoS == EPIPE ){
		DEBUG("-Ecc(%2d) %d/%d EPIPE ##ERR##",cr->cr_ix,wcc,rcc);
		/* C_FLUAH_SVI or C_FLUSH_CLI */
		if( !fromclnt ){
			updateFdv++;
			xclose(cr,iSock.fd_fd,1);
			xclose(cr,oSock.fd_fd,0);
			cr->cr_svSock = FD_INVALID(-1);
			cr->cr_clSock = FD_INVALID(-1);
			cr->cr_endclock = SvccClock;
			endConn(cr,"EPIPE");
			return 4;
		}
	}
	if( rcc == 0 ){
		IStr(msg,64);
		sprintf(msg,"{%d} s%X FB=%d (%.3f) Q%d-R%d-E%d-K%d/%X/%X",cr->cr_id,cr->cr_cstat,fromBuf,Time()-St0,
			cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,
			cr->cr_hrsvka,cr->cr_hrsvKA,cr->cr_hqclKA
		);
		TRACE("##%s DBGFD [%d]wcc=%d/E%d (%.3f) [%d]rcc=%d/E%d (%.3f) <= %s %s",
			msg,
			oSock.fd_fd,wcc,serrnoS,Elp,
			iSock.fd_fd,rcc,serrnoR,ElpR,
			fromclnt?"fromCL":"fromSV",
			fromclnt?clientid(cr):serverid(cr)
		);
	}
	if( wcc <= 0 && serrnoS == EAGAIN && rcc <= 0 ){
		// should do ShutdownSocket() ?
		TRACE("##{%d} s%X DBGFD clearERR [%d]wcc=%d/E%d [%d]rcc=%d/E%d",
			cr->cr_id,cr->cr_cstat,
			oSock.fd_fd,wcc,serrnoS,iSock.fd_fd,rcc,serrnoR);
		serrnoS = 0;
	}
	if( wcc <= 0 && serrnoS == EAGAIN ){
		/*
		DEBUG("-Ecc(%2d) %d/%d W EAGAIN [%d %s %d] ##ERR##",
			cr->cr_ix,wcc,rcc,
			cr->cr_clsock,fromclnt?">>":"<<",cr->cr_svsock
		);
		*/
		goto WAGAIN;
	}else
	if( wcc <= 0 ){
		updateFdv++;
		if( oSock.fd_fd == cr->cr_svsock && cr->cr_clsock < 0 ){
			TRACE("--{%d} s%X CLOSING on EoS fromCL [%d %d]",cr->cr_id,cr->cr_cstat,cr->cr_clsock,cr->cr_svsock);
			destroyAct(cr);
			return 5;
		}
		if( oSock.fd_fd == cr->cr_clsock ){
			if( cr->cr_cstat == CCSV_C_RELAY
			 || cr->cr_cstat == CCSV_C_WAITREQ
			){
				// should put "503 RETRY" ?
			TRACE("--{%d} s%X CLOSING on EoS fromSV [%d %d] Q%d-R%d-E%d-K%d",cr->cr_id,
			cr->cr_cstat,cr->cr_clsock,cr->cr_svsock,
			cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,cr->cr_hrsvka);

				DEBUG("{%d} s%X shutdown-CL [%d %d] %d/%d",cr->cr_id,cr->cr_cstat,
					cr->cr_clsock,cr->cr_svsock,wcc,rcc);
				destroyAct(cr);
				return 5;
			}
		}
		xclose(cr,oSock.fd_fd,0);
		if( oSock.fd_fd == cr->cr_clsock )
			cr->cr_clSock = FD_INVALID(-300 - cr->cr_clsock);
		else	cr->cr_svSock = FD_INVALID(-300 - cr->cr_svsock);

		if( 0 <= cr->cr_clsock && cr->cr_cstat == CCSV_C_PENDING_SVO ){
DEBUG("---- ---- {%d}*%d H%d Q%d-R%d",cr->cr_id,cr->cr_reused,
cr->cr_hqstat,cr->cr_hqn,cr->cr_hrn);
			if( cr->cr_reused && cr->cr_hqstat
			 && cr->cr_hqn <= 1 && cr->cr_hrn < cr->cr_hqn
			){
				// RETRY for server in keep-alive with client in the first request
TRACE("---- ---- {%d}*%d H%d Q%d-R%d (503 RETRY)",cr->cr_id,cr->cr_reused,
cr->cr_hqstat,cr->cr_hqn,cr->cr_hrn);
	sprintf(buf,"HTTP/1.0 503 DeleGate/Ecc retry\r\nRetry-After: 1\r\n\r\n");
	xsend("retry-HCKA",cr,cr->cr_clSock,buf,strlen(buf));
				destroyAct(cr);
				return 4;
			}

			updateFdv++;
			xclose(cr,cr->cr_clsock,0);
			cr->cr_clSock = FD_INVALID(-300 - cr->cr_clsock);
			TRACE("####Ecc(%2d){%d} EOS of SV with PENDING_SVO fromcl=%d err=%d",
				cr->cr_ix,cr->cr_id,fromclnt,serrnoS);
		}
		if( cr->cr_clsock < 0 && cr->cr_svsock < 0 ){
/*log*/if(0)
			DEBUG("-Ecc(%2d){%d}*%d FIN-W s%X [%d %s %d] %d/%d err=%d (%.2f)",
				cr->cr_ix,cr->cr_id,cr->cr_reused,cr->cr_cstat,
				clSock.fd_fd,fromclnt?">>":"<<",svSock.fd_fd,wcc,rcc,serrnoS,
				Time()-cr->cr_connSt);
			cr->cr_endclock = SvccClock;
			if( serrnoS && cr->cr_hqmeth != 'C' ) /* Send error, not in CONNECT */
			TRACE("####{%d}FIN-W s%X [%d] rcc=%d wcc=%d err=%d/%d fromcl=%d fromBuf=%d",
				cr->cr_id,cr->cr_cstat,oSock.fd_fd,rcc,wcc,serrnoS,serrnoR,fromclnt,
				fromBuf);
			endConn(cr,"Fin-W");
		}
		if( !fromclnt && 0 <= cr->cr_svsock ){
		DEBUG("-Ecc(%2d) SVKA2 [%d %d] %d/%d e%d (not yet) ##WARN##",
				cr->cr_ix,clSock.fd_fd,svSock.fd_fd,wcc,rcc,serrnoS);
		}
		return 4;
	}else
	if( wcc == rcc ){
		if( fromBuf ){
			if( cr->cr_cstat == CCSV_C_PENDING_CLO ){
				DEBUG("-Ecc(%2d){%d} flush StoC %d/%d ##WARN##",
					cr->cr_ix,cr->cr_id,wcc,rcc);
				cr->cr_cstat = CCSV_C_RELAY; cr->cr_statSt = Time();
				updateFdv = 1;
			}
			if( cr->cr_cstat == CCSV_C_PENDING_SVO ){
				DEBUG("-Ecc(%2d){%d} flush CtoS %d/%d ##WARN##",
					cr->cr_ix,cr->cr_id,wcc,rcc);
				cr->cr_cstat = CCSV_C_RELAY; cr->cr_statSt = Time();
				updateFdv = 1;
			}
		}
	}else
	if( wcc < rcc ){
WAGAIN:
		if( 1 ){
			int rwcc; /* real wcc */
	TRACE("{%d} s%X %d/%d err=%d FB=%d %lld/%lld [%d %s %d] %d-%d-%d ##WARN##",
				cr->cr_id,cr->cr_cstat,
				wcc,rcc,serrnoS,
				fromBuf,SvccWcc,SvccRcc,
				cr->cr_clsock,fromclnt?">>":"<<",cr->cr_svsock,
				cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC
			);
			if( cr->cr_buf == 0 ){
				if( ECC_bufSiz ){
					cr->cr_bufSiz = ECC_bufSiz;
				}else
				cr->cr_bufSiz = CC_BUFSIZ;
				cr->cr_buf = (char*)malloc(cr->cr_bufSiz);
			}
			if( 0 < wcc )
				rwcc = wcc;
			else	rwcc = 0;
			cr->cr_bufRem = rcc-rwcc;
			checkBuf(cr,rcc-rwcc,FL_ARG);
			if( cr->cr_bufRem <= 0 ){
				TRACE("##{%d} s%X FATAL DBGFD bufRem=%d %d %d [%d <= %d]",
					cr->cr_id,cr->cr_cstat,
					cr->cr_bufRem,rcc,wcc,
					oSock.fd_fd,iSock.fd_fd
				);
			}
			bcopy(buf+rwcc,cr->cr_buf,cr->cr_bufRem);
			if( fromclnt ){
				cr->cr_cstat = CCSV_C_PENDING_SVO;
			}else
			cr->cr_cstat = CCSV_C_PENDING_CLO;
			updateFdv = 1;
		}else{
			DEBUG("-Ecc(%2d) %d/%d ##WARN##",
				cr->cr_ix,wcc,rcc);
		}
	}
	return 0;
}
static int makeFdv(PollVect *Pv,int crn,ConnReq *crb){
	int ci;
	ConnReq *cq1;

	fdc = 0;
	for( ci = 0; ci < crn; ci++ ){
		cq1 = &crb[ci];
		if( cq1->cr_cstat ){
			if( cq1->cr_cstat == CCSV_C_PENDING_CLO ){
				if( 0 <= cq1->cr_clsock ){
					cnv[fdc] = ci;
					qev[fdc] = PS_OUT;
					FDv[fdc] = cq1->cr_clSock;
					fdv[fdc++] = cq1->cr_clsock;
				}
			}else
			if( cq1->cr_cstat == CCSV_C_PENDING_SVO ){
				if( 0 <= cq1->cr_svsock ){
					cnv[fdc] = ci;
					qev[fdc] = PS_OUT;
					FDv[fdc] = cq1->cr_svSock;
					fdv[fdc++] = cq1->cr_svsock;
				}
			}else
			if( cq1->cr_cstat == CCSV_C_WAITTHREAD ){
				if( 0 <= cq1->cr_clsock ){
					cnv[fdc] = ci;
					if( isWindowsCE() ){ /* FTP/HTTP/1.0 non WinCE without pipeline */
						/* reset can be detected with PRI */
						qev[fdc] = PS_PRI;
					}else{
						qev[fdc] = PS_PRI | PS_IN;
					}
					FDv[fdc] = cq1->cr_clSock;
					fdv[fdc++] = cq1->cr_clsock;
				}
			}else
			if( cq1->cr_cstat == CCSV_C_RESOLVING ){
				/* 9.9.8 inactivate during resolv. */
				if( 0 <= cq1->cr_clsock ){
					if( isWindowsCE() ){ /* detecting reset only */
						cnv[fdc] = ci;
						qev[fdc] = PS_PRI;
						FDv[fdc] = cq1->cr_clSock;
						fdv[fdc++] = cq1->cr_clsock;
					}
				}
			}else
			if( cq1->cr_cstat == CCSV_C_CONN ){
				cnv[fdc] = ci;
				qev[fdc] = PS_OUT | PS_PRI;
				FDv[fdc] = cq1->cr_svSock;
				fdv[fdc++] = cq1->cr_svsock;
			}else{
				if( 0 <= cq1->cr_clsock ){
					cnv[fdc] = ci;
					qev[fdc] = PS_IN | PS_PRI;
					FDv[fdc] = cq1->cr_clSock;
					fdv[fdc++] = cq1->cr_clsock;
				}
				if( 0 <= cq1->cr_svsock ){
					cnv[fdc] = ci;
					qev[fdc] = PS_IN | PS_PRI;
					FDv[fdc] = cq1->cr_svSock;
					fdv[fdc++] = cq1->cr_svsock;
				}
			}
		}
	}
	updateFdv = 0;
	return fdc;
}

#if defined(_MSC_VER)
//#undef select
static int _PollInsOuts(int timeout,int nfds,FDesc _fdv[],int ev[],int _rev[])
{	fd_set rfds,wfds,xfds;
	int fi,fd,fh,ev1,ev2;
	int ofd;
	int width;
	struct timeval tv;
	struct timeval *tvp;
	int nready;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&xfds);

	width = 0;
	for( fi = 0; fi < nfds; fi++ ){
		fd = _fdv[fi].fd_fd;
		if( fd < 0 ){
			continue;
		}
		fh = _fdv[fi].fd_handle;
		if( width <= fh )
			width = fh+1;
		ev1 = ev[fi];
		if( ev1 & PS_IN  ) FD_SET(fh,&rfds);
		if( ev1 & PS_OUT ) FD_SET(fh,&wfds);
		if( ev1 & PS_PRI ) FD_SET(fh,&xfds);
	}
	if( timeout < 0 ){ /* spec. of timeout of poll() */
		tvp = NULL;
	}else{
		tvp = &tv;
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}
	nready = select(SELECT_WIDTH(width),&rfds,&wfds,&xfds,tvp);
	for( fi = 0; fi < nfds; fi++ ){
		fd = _fdv[fi].fd_fd;
		ofd = fd;
		if( fd < 0 ){
			_rev[fi] = 0;
			continue;
		}
		fh = _fdv[fi].fd_handle;
		ev2 = 0;
		if( FD_ISSET(fh,&rfds) ) ev2 |= PS_IN;
		if( FD_ISSET(fh,&wfds) ) ev2 |= PS_OUT;
		if( FD_ISSET(fh,&xfds) ) ev2 |= PS_PRI;
		_rev[fi] = ev2;
	}
	return nready;
}
#define PollInsOuts(t,n,_fdv,ev,_rev) _PollInsOuts(t,n,FDv,ev,rev)
#endif

static void conntimeout(ConnReq *cr){
	int wcc;
	if( cr->cr_Timeout == 0){
		return;
	}
	if( Time() < cr->cr_Timeout ){
		return;
	}
	TRACE("##{%d} s%X CON-E (%.2f)=> %s connect() timeout",cr->cr_id,cr->cr_cstat,
		Time()-cr->cr_connSt,serverid(cr));
	if( cr->cr_hqstat ){
		wcc = putmsg("CONN-HTTP-TIMEOUT",cr,cr->cr_clSock,504,"Connection Timeout");
	}else{
	}
	destroyAct(cr);
}
static int abort1(ConnReq *cr,int rev1,double Now,PCStr(wh)){
	int ncx = 0;
	if( rev1 == 0 && cr->cr_cstat == CCSV_C_WAITREQ ){
		if( 0 < cr->cr_statSt && 15 < Now-cr->cr_statSt
		 && 15 < Now-cr->cr_irdySt /* repetitive getCount staying in WAITREQ */
		){
			TRACE("{%d} CLNT req timeout %s (%.2f %.2f)[%d]",cr->cr_id,wh,
				Now-cr->cr_statSt,Now-cr->cr_irdySt,cr->cr_clsock);
			destroyAct(cr);
			ncx++;
		}
	}
	if( rev1 == 0 && cr->cr_cstat == CCSV_C_CONN ){
		if( cr->cr_Timeout <= Now ){
			conntimeout(cr);
			ncx++;
		}
	}
	if( rev1 == 0 && cr->cr_cstat == CCSV_C_RELAY ){
		int timeout = 0;
		if( 0 < cr->cr_hqn ){
			if( cr->cr_hrn < cr->cr_hqn ){
				timeout = 30; // first response timeout in KA
			}else
			if( cr->cr_hrn == cr->cr_hqn
			 && cr->cr_hrn == cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC
			){
				timeout = 15; // idling keep-alive
			}
		}else{
		}
		if( 0 < timeout && timeout < Now-cr->cr_irdySt ){
			TRACE("{%d} RELAY timeout (%.2f %.2f) %d-%d-%d-%d/%X/%X => %s",
				cr->cr_id,Now-cr->cr_irdySt,Now-cr->cr_statSt,
				cr->cr_hqn,cr->cr_hrn,cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,
				cr->cr_hrsvka,cr->cr_hrsvKA,cr->cr_hqclKA,serverid(cr));
			if( Now-cr->cr_statSt < timeout ){
				TRACE("{%d} RELAY timeout (%.2f %.2f) NO",
				cr->cr_id,Now-cr->cr_irdySt,Now-cr->cr_statSt);
			}else{
				if( 0 < cr->cr_hqn ){
				//putmsg("RELAY-timeout",cr,cr->cr_clSock,504,"KA Timeout");
				}
				destroyAct(cr);
				ncx++;
			}
		}
	}
	if( rev1 == 0 && cr->cr_cstat == CCSV_C_SVKA ){
		if( 0 < cr->cr_ckaSt && 15 < Now-cr->cr_ckaSt ){
			DEBUGKA("{%d} SVKA fin timeout %s (%.2f)[%d]",cr->cr_id,wh,Now-cr->cr_ckaSt,cr->cr_svsock);
			destroyAct(cr);
			ncx++;
		}
	}
	if( rev1 == 0 && cr->cr_cstat == CCSV_C_CLOSING ){
		if( 0 < cr->cr_finSt && 15 < Now-cr->cr_finSt ){
			TRACE("--{%d} s%X fin timeout CLOSING (%.2f)[%d %d]",cr->cr_id,cr->cr_pcstat,Now-cr->cr_finSt,cr->cr_clsock,cr->cr_svsock);
			if( 0 <= cr->cr_clsock ){
int sock,lport,rport;
sock = cr->cr_clsock;
lport = sockPort(sock);
rport = peerPort(sock);
TRACE("--{%d} CLOSING [%d]con=%d,alv=%d ####ports{%d <= %d}",cr->cr_id,
sock,IsConnected(sock,0),IsAlive(sock),lport,rport);

				xclose(cr,cr->cr_clsock,1);
				cr->cr_clSock = FD_INVALID(-800 - cr->cr_clsock);
			}
			if( 0 <= cr->cr_svsock ){
				xclose(cr,cr->cr_svsock,1);
				cr->cr_svSock = FD_INVALID(-800 - cr->cr_svsock);
			}
			destroyAct(cr);
			ncx++;
		}else
		if( 0 < cr->cr_finSt && 5 < Now-cr->cr_finSt && 5 < Now-cr->cr_shutSt ){
			cr->cr_shutSt = Now;
			TRACE("--{%d} s%X fin timeout CLOSING (%.2f)[%d %d] shut",cr->cr_id,cr->cr_pcstat,Now-cr->cr_finSt,cr->cr_clsock,cr->cr_svsock);
			/* previous FIN might be lost over WiFi ... */
			shutdownAct(cr);
			ncx++;
		}
	}
	return ncx;
}
static int sweeptimeout(ConnReq *crs,int crn){
	int ci;
	ConnReq *cr;
	double Now = Time();
	int ncx = 0;

	for( ci = 0; ci < crn; ci++ ){
		cr = &crs[ci];
		if( cr->cr_cstat ){
		ncx += abort1(cr,0,Now,"swept");
		}
	}
	return ncx;
}

static int gotevent(ConnCtx *cx,PollVect *Pv,ConnReq *cre,ConnReq *crs,int crn);
static void initAcc(ConnReq *crs,int crn,int acsock,int exsock,int clsock);
static void stkbase(void *buf,int siz){
	char *btm = ((char*)buf) + siz;
	if( stk_base < btm ){
		stk_base = btm;
	}
}
static ConnCtx *CX1;
static void relays(Connection *Conn,int acsock,int exsock,int clsock){
	ConnReq crbuf[MAX_CONN],*crs = crbuf;
	PollVect Pvbuf[1],*Pv = Pvbuf;
	ConnCtx cxbuf[1],*cx = cxbuf;
	int na;
	int crn = elnumof(crbuf);
	ConnReq *cr1;
	int nready;
	int ri;
	int doexit = 0;
	int serrno;
	double St,PSt;
	int ocstat;
	int rev1;
	int verblap = lSINGLEP();
	int nretry = 0;

	Ecc_tid = getthreadid();
	setthreadgid(0,getthreadid());
	stk_tid = getthreadid();
	stkbase(crbuf,sizeof(crbuf));
	stkbase(cxbuf,sizeof(ConnCtx));
	stkbase(Pvbuf,sizeof(PollVect));
	stk_lowest = stk_base; 
	TRACE("----relays CRQ=%d MTU=%d",sizeof(ConnReq),CC_MTU);

	CX1 = cx;
	cx->cx_crs = crs;
	cx->cx_crn = crn;
	cx->cx_Pv = Pv;
	_lSINGLEP = lSINGLEP();
	_lMULTIST = lMULTIST();
	_lIMMREJECT = lIMMREJECT();
	_lDONTROUTE_LOCAL = lDONTROUTE_LOCAL();

	ProcTitle(Conn,"Connection-Cache");
{
SigMaskInt mask,omask;
mask = sigmask(SIGPIPE);
thread_sigmask("SET",mask,&omask);
}
	signal(SIGPIPE,SIG_IGN);
	bzero(crbuf,sizeof(crbuf));
	initAcc(crs,crn,acsock,exsock,clsock);

	PSt = Time();
	for( na = 0; !doexit; na++ ){
		SvccClock++;
		if( verblap && (na % 500) == 0
		 || (na % 1000) == 0
		){
			dumpCon(Pv,na,crn,crs,1,0,NULL);
		}
		if( updateFdv ){
			fdc = makeFdv(Pv,crn,crs);
		}
		errno = 0;
		nready = PollInsOuts(3*1000,fdc,fdv,qev,rev);
		serrno = errno;

		if( 0 ) /* debug */
		if( 0 < nready ){
			int i;
			msleep(100);
			for(i=0;i<fdc;i++)
			DEBUG("-Ecc nready=%d (%d) [%d]%X",nready,fdc,i,rev[i]);
		}

		if( nready == 0 ){
			/* ... should sweep timeouted CONN and RELAY */
			dumpCon(Pv,na,crn,crs,1,1,NULL);
			if( sweeptimeout(crs,crn) ){
				continue;
			}
			nready = PollInsOuts(7*1000,fdc,fdv,qev,rev);
			if( nready == 0 ){
				sweeptimeout(crs,crn);
				maintainCachedHosts();
				continue;
			}
		}
		if( nready < 0 ){
			/* can be caused SIGPIPE to FTP/HTTP thread */
			updateFdv++;
			TRACE("-Ecc #%d nready=%d/%d errno=%d ##ERRx%d## #### ####",
				SvccClock,nready,fdc,serrno,nretry);
			dumpCon(Pv,na,crn,crs,1,1,NULL);
			salvage(cx,Pv,na,crn,crs);
			if( ++nretry < 100 ){
				msleep(100);
				continue;
			}
			TRACE("-Ecc ######## Finish on too many select() errors");
			Finish(-1);
			break;
		}
		nretry = 0;

		eccActivity++;
		St = Time();
		for( ri = 0; ri < fdc; ri++ ){
			if( rev[ri] ){
				cr1 = &crs[cnv[ri]];
				if( cr1->cr_rdySt == 0 ){
					cr1->cr_rdySt = St;
				}
			}
		}
		for( ri = 0; ri < fdc; ri++ ){
			if( updateFdv ){
				break;
			}
			cr1 = &crs[cnv[ri]];
			rev1 = 0;
			if( ocstat = cr1->cr_cstat ){
				rev1 = rev[ri];
				PSt = Time();
				if( rev1 & (PS_IN|PS_PRI) ){
					cr1->cr_irdySt = PSt;
				}
				if( abort1(cr1,rev[ri],PSt,"-") ){
					goto NEXT;
				}
			}
			if( rev[ri] && cr1->cr_cstat == CCSV_C_CLOSING ){
				IStr(buf,CC_BUFSIZ);
				int rcc,serrno,rdy1,rdy2;
				IStr(ht,128);
				refQStr(hp,ht);
				double St1,Now;

				updateFdv++;
				if( isWindowsCE() && (rev[ri] & PS_PRI) ){
					shutdown(fdv[ri],SHUT_RDWR);
					DEBUG("--{%d} s%X done CLOSING (%.3f) [%d][%d %d] RESET rev=%d",
						cr1->cr_id,cr1->cr_pcstat,PSt-cr1->cr_finSt,
						fdv[ri],cr1->cr_clsock,cr1->cr_svsock,rev[ri]);
					goto FIN_CLOSED;
				}
				St1 = Time();
				rdy1 = xPollIn(FDv[ri],1);
				if( 0 < rdy1 ){
					rcc = xrecv("CLOSING",cr1,FDv[ri],buf,sizeof(buf));
					serrno = errno;
					rdy2 = xPollIn(FDv[ri],1);
				}else{
					rcc = -2;
					serrno = errno;
					rdy2 = -2;
				}
				shutdown(fdv[ri],SHUT_RDWR);
				if( rcc == 0 && serrno == 0 && rdy1 == 1 && rdy2 == 1 ){
					/* normal end */
				}else{
					sprintf(hp,"rcc=%d/E%d Q%d-R%d-E%d-K%d/%X/%X",rcc,serrno,
						cr1->cr_hqn,cr1->cr_hrn,cr1->cr_hrendE+cr1->cr_hrendL+cr1->cr_hrendC,
						cr1->cr_hrsvka,cr1->cr_hrsvKA,cr1->cr_hqclKA);
					hp += strlen(hp);
					setVStrPtrInc(hp,'{');
					if( 0 < rcc ){
						int bi,ch;
						for( bi = 0; bi < rcc && bi < 8; bi++ ){
							ch = buf[bi];
							if( isalnum(ch) ){
								setVStrPtrInc(hp,ch);
							}
						}
					}
					setVStrPtrInc(hp,'}');
					Now = Time();

	TRACE("--{%d} s%X done CLOSING (%.3f %.3f) [%d][%d %d] rev=%d,rdy1=%d,rdy2=%d,con=%d %s",
					cr1->cr_id,cr1->cr_pcstat,Now-cr1->cr_finSt,Now-St1,
					fdv[ri],cr1->cr_clsock,cr1->cr_svsock,
					rev[ri],rdy1,rdy2,IsConnected(fdv[ri],0),ht);
				}
				if( rdy1 != 0 && rdy2 == 0 ){
					break;
				}

			FIN_CLOSED:
				xclose(cr1,fdv[ri],1);
				if( cr1->cr_clsock == fdv[ri] ){
					cr1->cr_clSock = FD_INVALID(-700 - cr1->cr_clsock);
				}else{
					cr1->cr_svSock = FD_INVALID(-700 - cr1->cr_svsock);
				}
				if( cr1->cr_clsock < 0 && cr1->cr_svsock < 0 ){
					destroyAct(cr1);
				}
				break;
			}
			if( cr1->cr_cstat == 0 ){
				DEBUG("-Ecc(%2d) hit zomb [%d][%d %d] {%d}{%d} ##ERR##",
					cr1->cr_ix,fdv[ri],cr1->cr_clsock,cr1->cr_svsock,
					cr1->cr_endclock,SvccClock
				);
ECC_LastAct = "Z";
ECC_LastActId = cr1->cr_id;
				goto NEXT;
			}
if( rev[ri] ){
ECC_LastAct = "g";
ECC_LastActId = cr1->cr_id;
}
			if( rev[ri] && cr1->cr_cstat == CCSV_C_WATCHEX ){
				DEBUG("-Ecc(%2d){%d} detected EXSOCK [%d] %X",
					cr1->cr_ix,cr1->cr_id,cr1->cr_svsock,cr1->cr_cstat);
				doexit = 1;
				Finish(0);
				break;
			}
			if( cr1->cr_cstat == CCSV_C_ACCEPT ){
				if( rev[ri] & PS_IN ){
					newConn(Pv,crs,crn,FDv[ri]);
ECC_LastAct = "N";
ECC_LastActId = cr1->cr_id;
					break; /* to cope with the rush of accept() */
				}else
				if( rev[ri] ){
					DEBUG("####{%d} Acc %X",cr1->cr_id,rev[ri]);
ECC_LastAct = "A";
ECC_LastActId = cr1->cr_id;
				}else{
ECC_LastAct = "a";
ECC_LastActId = cr1->cr_id;
				}
				goto NEXT;
			}
			if( cr1->cr_cstat == CCSV_C_WAITEVENT ){
				if( rev[ri] & PS_IN ){
ECC_LastAct = "e";
ECC_LastActId = cr1->cr_id;
					if( gotevent(cx,Pv,cr1,crs,crn) == 0 ){
					}
				}
				goto NEXT;
			}
			if( rev[ri] && cr1->cr_cstat == CCSV_C_WAITREQ ){
				if( rev[ri] & PS_IN ){
					getReq(cx,Pv,crs,crn,cr1,FDv[ri]);
ECC_LastAct = "Q";
ECC_LastActId = cr1->cr_id;
				}else{
					DEBUG("####{%d} Req %X",cr1->cr_id,rev[ri]);
ECC_LastAct = "q";
ECC_LastActId = cr1->cr_id;
				}
				goto NEXT;
			}
			if( rev[ri] && cr1->cr_cstat == CCSV_C_WAITING_CLI ){
				newHTTPproxy2(cx,Pv,crs,crn,cr1);
				goto NEXT;
			}
			if( rev[ri] && cr1->cr_cstat == CCSV_C_WAITTHREAD ){
				int alive = IsAlive(cr1->cr_clsock);
				int thalv = threadIsAlive(cr1->cr_svtid);
ECC_LastAct = "t";
ECC_LastActId = cr1->cr_id;
				TRACE("##{%d}[%d] s%X r%X clalv=%d THREAD %X thalv=%d %d/%d",
					cr1->cr_id,fdv[ri],cr1->cr_cstat,
					rev[ri],alive,cr1->cr_svtid,thalv,
					actthreads(),numthreads()
				);
				if( !alive || (rev[ri] & PS_PRI) || thalv <= 0 ){
					destroyAct(cr1);
				}
				goto NEXT;
			}
			if( rev[ri] & PS_HUP ){ /* Vine4 or poll() */
				DEBUG("-Ecc(%2d){%d} got HUP s%X [%d] re=%X ##WARN##",
					cr1->cr_ix,cr1->cr_id,cr1->cr_svsock,cr1->cr_cstat,rev[ri]);
				if( cr1->cr_cstat == CCSV_C_CONN ){
					gotConn(cr1,fdv[ri]);
ECC_LastAct = "P";
ECC_LastActId = cr1->cr_id;
					goto NEXT;
				}else{
ECC_LastAct = "H";
ECC_LastActId = cr1->cr_id;
				}
			}
			if( rev[ri] & PS_PRI ){ /* Win32 or select() */
				if( cr1->cr_cstat == CCSV_C_CONN ){
					DEBUG("-Ecc(%2d){%d} CONN PRI [%d] re=%X ##WARN##",
						cr1->cr_ix,cr1->cr_id,cr1->cr_svsock,rev[ri]);
					gotConn(cr1,fdv[ri]);
ECC_LastAct = "S";
ECC_LastActId = cr1->cr_id;
					goto NEXT;;
				}
ECC_LastAct = "s";
ECC_LastActId = cr1->cr_id;
DEBUG("---- ----{%d} #%d s%X PRI rev=%X alv=%d [%d][%d %d]",
cr1->cr_id,SvccClock,
cr1->cr_cstat,rev1,IsAlive(fdv[ri]),fdv[ri],cr1->cr_clsock,cr1->cr_svsock);
				DEBUG("-Ecc(%2d){%d} CCSV-PRI [%d]",
					cr1->cr_ix,cr1->cr_id,fdv[ri]);
			}
			if( rev[ri] & PS_OUT ){
				if( cr1->cr_cstat == CCSV_C_CONN ){
					if( gotConn(cr1,fdv[ri]) == 0 ){
ECC_LastAct = "C";
ECC_LastActId = cr1->cr_id;
/* 9.9.5 this can cause loop */
						goto NEXT;;
					}else{
/* might be on connection timeout */
ECC_LastAct = "c";
ECC_LastActId = cr1->cr_id;
					}
				}else{
					relay1(cx,Pv,cr1,1,FDv[ri],qev[ri],rev[ri]);
ECC_LastAct = "R";
ECC_LastActId = cr1->cr_id;
				}
			}
			if( rev[ri] & PS_IN ){
				relay1(cx,Pv,cr1,0,FDv[ri],qev[ri],rev[ri]);
ECC_LastAct = "I";
ECC_LastActId = cr1->cr_id;
			}
			if( rev[ri] == 0 && cr1->cr_cstat == CCSV_C_CONN ){
				if( cr1->cr_Timeout < St ){
					conntimeout(cr1);
				}
			}

		NEXT: /* detecting slow relay */
			if( ocstat && rev1 ){
				St = Time();
				if( 0.05 < St-PSt
				 || 0 < cr1->cr_rdySt && 2.0 < St-cr1->cr_rdySt){
	SERIOUS("-Ecc{%d}%s #%d %X s%X=>%X slow Relay (e%.3f w%.3f) %d/%d %s",
					cr1->cr_id,ECC_LastAct,SvccClock,
					rev1,ocstat,cr1->cr_cstat,
					St-PSt,
					cr1->cr_rdySt?(St - cr1->cr_rdySt):0.0,
					nready,fdc,
					serverid(cr1)
					);
				}
				cr1->cr_rdySt = 0;
				PSt = St;
			}
		}
	}
}
static int putSv(ConnCtx *cx,ConnReq *cr){
	ConnReq *cr1;
	FDesc svSock;

	svSock = cr->cr_svSock;
	cr->cr_svSock = FD_INVALID(-600);
	if( cr->cr_hrsvka == 0 ){
		DEBUG("##{%d} NO putSv ##1 rdy=%d %s",cr->cr_id,inputReady(svSock.fd_fd,0),serverid(cr));
	}else
	if( inputReady(svSock.fd_fd,0) ){
		DEBUG("##{%d} NO putSv ##2 rdy=%d %s",cr->cr_id,inputReady(svSock.fd_fd,0),serverid(cr));
	}else
	if( cr1 = addConn(cx->cx_Pv,cx->cx_crn,cx->cx_crs,FD_INVALID(-1)) ){
		cr1->cr_cstat = CCSV_C_SVKA;
		cr1->cr_ckaSt = Time();
		cr1->cr_svSock = svSock;
		cr1->cr_clSock = FD_INVALID(-600);
		cr1->cr_svsa = cr->cr_svsa;
		cr1->cr_rsvsa = cr->cr_rsvsa;
		cr1->cr_hrsvka = cr->cr_hrsvka;
		cr1->cr_reused = cr->cr_reused;
		cr->cr_reused = 0;
		DEBUG("##{%d}*%d putSv (%d){%d} %s",
			cr->cr_id,cr->cr_reused,
			cr1->cr_ix,cr1->cr_id,serverid(cr1));
		return 1;
	}
	updateFdv++;
	xclose(cr,svSock.fd_fd,1);
	return 0;
}
static int findSv(ConnReq *crq,ConnReq *crs,int crn,ConnReq *ocr){
	int ci;
	ConnReq *cr1;
	int siz = VSA_size((VSAddr*)&crq->cr_svsa);
	int para;

	if( (crq->cr_qflag & CCSV_Q_SVKA) == 0 ){
		/*
		VSAddr *vsa = (VSAddr*)&crq->cr_svsa;
		DEBUG("-Ecc DONT REUSE %s:%d ##ERR##",VSA_ntoa(vsa),VSA_port(vsa));
		*/
		return -1;
	}
	for( ci = 1; ci < crn; ci++ ){
		cr1 = &crs[ci];
		if( cr1->cr_cstat != CCSV_C_SVKA ){
			continue;
		}
		if( VSA_comp((VSAddr*)&crq->cr_svsa,(VSAddr*)&cr1->cr_svsa) != 0 ){
			continue;
		}
		if( VSA_comp((VSAddr*)&crq->cr_rsvsa,(VSAddr*)&cr1->cr_rsvsa) != 0 ){
			continue;
		}
		para = ++ocr->cr_para;
		if( 0 <= cr1->cr_svsock ) /* C_SVKA */
		if( cr1->cr_clsock < 0 ){
			*ocr = *cr1;
			cr1->cr_para = para;
			cr1->cr_endclock = SvccClock;
			endConn(cr1,"findS");
			cr1->cr_reused = 0;
			cr1->cr_svSock = FD_INVALID(-400 - cr1->cr_svsock);
			updateFdv = 1;
			return 0;
		}
	}
	/*
	 * should wait short time when there is same dst. servers ...
	 */
	return -1;
}
static int setConn(PCStr(what),ConnReq *cr,ConnReq *ncr){
	int ci;
	int leng;
	int rcode;
	IStr(reu,128);

	leng = sizeof(ncr->cr_svifsa);
	rcode = getsockname(ncr->cr_svsock,(SAP)&ncr->cr_svifsa,&leng);
	if( rcode != 0 ){
		DEBUG("-Ecc IFSA %d %d/%d ##ERR##",
			rcode,leng,sizeof(ncr->cr_svifsa));
	}
	*cr = *ncr;
	ncr->cr_ix = cr->cr_ix;
	if( ncr->cr_id ){
		cr->cr_id = ncr->cr_id;
		if( cr->cr_connSt == 0 )
		DEBUG("-Ecc(%2d){%d}*%d REUSING ##ERR##",
			ncr->cr_ix,ncr->cr_id,ncr->cr_reused);
	}else{
		cr->cr_id = ++SvccId;
		ncr->cr_id = cr->cr_id;
	}
	if( cr->cr_connSt ){
		sprintf(reu,"(%.2f)",Time()-cr->cr_connSt);
	}
/*log*/if(0)
	DEBUG("-Ecc(%2d){%d}*%d %s [%d %d] %s",
		cr->cr_ix,cr->cr_id,cr->cr_reused,what,
		cr->cr_clsock,cr->cr_svsock,reu);
	updateFdv = 1;
	return 0;
}
static ConnReq *addConn(PollVect *Pv,int crn,ConnReq *crs,FDesc clSock){
	int ci;
	ConnReq *cr;
	IStr(reu,128);
	AppBuf apb;

	for( ci = 0; ci < crn; ci++ ){
		cr = &crs[ci];
		if( cr->cr_cstat == 0 ){
				apb = cr->cr_appBuf;
			bzero(cr,sizeof(ConnReq));
				cr->cr_appBuf = apb;
				cr->cr_appBuf.ap_bufRem = 0;
			cr->cr_ix = ci;
			cr->cr_id = ++SvccId;
			cr->cr_clSock = clSock;
			cr->cr_svSock = FD_INVALID(-1);
			cr->cr_connSt = Time();
			updateFdv = 1;
			return cr;
		}
	}
	return 0;
}

static struct {
	MStr(r_clnt,64);
	int r_len;
	int r_rej;
} TBR;
static int toberejectedX(int clsock,PCStr(clhost),int clport);
static int toberejected(int clsock,PCStr(clhost),int clport){
	int rej;
	if( TBR.r_clnt[0] ){
		if( strncmp(clhost,TBR.r_clnt,TBR.r_len) == 0 ){
			return TBR.r_rej;
		}
	}
	rej = toberejectedX(clsock,clhost,clport);
	strcpy(TBR.r_clnt,clhost);
	TBR.r_len = strlen(clhost);
	TBR.r_rej = rej;
	return rej;
}
static int newConn(PollVect *Pv,ConnReq *crs,int crn,FDesc acSock){
	IStr(sockname,MaxHostNameLen);
	IStr(claddr,128);
	int clport = 0;
	int clsock;
	FDesc clSock;
	double St;
	int serrno;
	ConnReq *cr;
	VSAddr clsa;
	int wcc;
	VSAddr sab;
	int addrlen = sizeof(VSAddr);

	St = Time();
	clsock = xaccept(&crs[0],acSock,(VSAddr*)&sab,&addrlen);
	serrno = errno;
	clSock = FD_NEW("newConn",0,clsock);
	setosf_FL("CCSV-Accept","(clnt-socket)",clSock.fd_fd,NULL,__FILE__,__LINE__);
	eccLOGX_tcpAcc++;

	if( clSock.fd_fd < 0 ){
		TRACE("---- accept [%d][%d] err=%d ##ERR##",
			clSock.fd_fd,acSock.fd_fd,serrno);
		msleep(100);
		return -1;
	}

	VSA_xtoap(&sab,AVStr(sockname),sizeof(sockname));
	Xsscanf(sockname,"%[^:]:%d",AVStr(claddr),&clport);
	VSA_atosa(&clsa,clport,claddr);

	if( _lIMMREJECT ){
		if( toberejected(clSock.fd_fd,claddr,clport) ){
			IStr(resp,512);
			sprintf(resp,"HTTP/1.0 403 DeleGate/Ecc Forbidden\r\n\r\n");
			wcc = xsend("Resp-Reject-NewConn",0,clSock,resp,strlen(resp));
			close(clSock.fd_fd);
			return -1;
		}
	}

	setNonblockingSocket(clSock.fd_fd,1);
	SvccAcc++;
	cr = addConn(Pv,crn,crs,clSock);
	if( cr ){
		/*
		int getsockVSAddr(int sock,VSAddr *vsa);
		getsockVSAddr(clsock,(VSAddr*)&cr->cr_clifsa);
		*/
		cr->cr_clsa = *(SAB*)&clsa;
		cr->cr_cstat = CCSV_C_WAITREQ; cr->cr_statSt = Time();
		/*
		DEBUG("-Ecc(%2d){%d} new [%d]",cr->cr_ix,cr->cr_id,cr->cr_clsock);
		*/
	}else{
		TRACE("{%d} new [%d] ##ERR##",cr->cr_id,clSock.fd_fd);
		close(clSock.fd_fd);
	}
	return 0;
}
static int delCon(PCStr(what),ConnReq *crs,int crn,ConnReq *dcr){
	int ci;
	ConnReq *cr;
	int found = 0;

	if( dcr->cr_id == 0 ){
		DEBUG("-Ecc {%d} DONT DESTROY",dcr->cr_id);
		return -1;
	}
	for( ci = 0; ci < crn; ci++ ){
		cr = &crs[ci];
		if( cr->cr_cstat && cr->cr_id == dcr->cr_id ){
			DEBUG("-Ecc(%2d){%d} DESTROY %s [%d %d]",ci,cr->cr_id,
				what,cr->cr_clsock,cr->cr_svsock);
			if( 0 <= cr->cr_svsock ){
				xclose(cr,cr->cr_svsock,0);
				cr->cr_svSock = FD_INVALID(-500 - cr->cr_svsock);
			}
			if( 0 <= cr->cr_clsock ){
				xclose(cr,cr->cr_clsock,0);
				cr->cr_clSock = FD_INVALID(-500 - cr->cr_clsock);
			}
			endConn(cr,"DelCo");
			updateFdv = 1;
			found++;
			break;
		}
	}
	if( found == 0 ){
		DEBUG("-Ecc {%d} NOT DESTROYED",dcr->cr_id);
	}
	return 0;
}
void dumpns(PCStr(wh));
static int testfd(ConnReq *cr,FDesc *Sock){
	if( Sock->fd_fd < 0 )
		return 0;
	if( 0 <= PollIn(Sock->fd_fd,1) )
		return 1;
	TRACE("####{%d} s%X Abort SALVAGED BAD SOCK [%d/%d/%d]",cr->cr_id,cr->cr_cstat,Sock->fd_fd,Sock->fd_handle,SocketOf(Sock->fd_fd));
	close(Sock->fd_fd);
	Sock->fd_fd = -1;
	Sock->fd_handle = -1;
	return -1;
}
static int salvage(ConnCtx *cx,PollVect *Pv,int na,int crn,ConnReq *crb){
	int ci;
	ConnReq *cr;
	for( ci = 0; ci < crn; ci++ ){
		cr = &crb[ci];
		if( cr->cr_cstat == 0 )
			continue;
		if( testfd(cr,&cr->cr_clSock) < 0 || testfd(cr,&cr->cr_svSock) < 0 ){
			TRACE("####{%d} s%X Abort SALVAGED BAD SOCK",cr->cr_id,cr->cr_cstat);
			destroyAct(cr);
		}
	}
	return 0;
}
static int dumpCon(PollVect *Pv,int na,int crn,ConnReq *crb,int verbose,int sweep,FILE *tc){
	int ci;
	int nact;
	ConnReq *cr;
	VSAddr *sa;
	double Now;
	const char *sst = "";
	const char *cst = "";
	IStr(msg,256);
	int nbuf = 0;
	int nactbuf = 0;

	nact = 0;
	for( ci = 0; ci < crn; ci++ ){
		cr = &crb[ci];
		if( cr->cr_cstat ){
			nact++;
		}
		if( cr->cr_buf ){
			nbuf++;
			if( cr->cr_cstat && 0 < cr->cr_bufRem ){
				nactbuf++;
			}
		}
	}
	if( SvccMax < nact ){
		SvccMax = nact;
	}
	if( SvccMaxBuf < nactbuf ){
		SvccMaxBuf = nactbuf;
	}

	sprintf(msg,"-Ecc clk#%d A%d C%d,%d H%d,%d,%d,%d tot=%d reu=%d",na,
		eccLOGX_tcpAcc,eccLOGX_tcpCon,ECC_NumReused,
		ECC_NumHttpReq,ECC_NumHttpKa,ECC_NumHttpSw,ECC_NumPipeSw,
		SvccAcc,SvccReu
	);
	if( _lSINGLEP )
		TRACE("%s",msg);
	else	porting_dbg("%s",msg);

	sprintf(msg,"-Ecc err=%d{%d} LA=%s{%d} res=%.2fs/%d act=%d/%d buf=%d/%d/%d rcc=%lld/%d stk=%X",
		SvccErr,SvccErrId,
		ECC_LastAct,ECC_LastActId,
		ECC_TimeForRes,ECC_Res,
		nact,SvccMax,nactbuf,SvccMaxBuf,nbuf,
		SvccRcc,SvccRct,stksize(FL_ARG)
	);
	if( _lSINGLEP )
		TRACE("%s",msg);
	else	porting_dbg("%s",msg);
	if( tc ){
		fprintf(tc,"%s\n",msg);
	}

	Now = Time();
	for( ci = 0; ci < crn; ci++ ){
		cr = &crb[ci];
		if( cr->cr_cstat ){
			sa = (VSAddr*)&cr->cr_svsa;
			sst = "-";
			if( sweep && (cr->cr_cstat & CCSV_C_SVKA)
			 && (0 < cr->cr_ckaSt) && (5 < Now-cr->cr_ckaSt)
			){
				if( IsAlive(cr->cr_svSock.fd_fd) )
					sst = "A";
				else	sst = "X";
			}
			cst = "-";
			if( cr->cr_cstat == CCSV_C_WAITTHREAD ){
				if( inputReady(cr->cr_clsock,0) ){
					sst = "i";
				}else
				if( IsAlive(cr->cr_clsock) )
					sst = "a";
				else
				if( IsConnected(cr->cr_clsock,0) )
					sst = "c";
				else	sst = "x";
			}
			sprintf(msg,"-Ecc(%2d){%d}*%d s%X [%d %d]%s%s %s (%.1f %.1f) ",
				cr->cr_ix,cr->cr_id,cr->cr_reused,
				cr->cr_cstat,cr->cr_clsock,cr->cr_svsock,cst,sst,
				serverid(cr),
				Now-cr->cr_connSt,0<cr->cr_ckaSt?Now-cr->cr_ckaSt:0.0
			);
			Xsprintf(TVStr(msg),"%d %d,%d-%d-%d K%d B%d %s",
				cr->cr_rct[0],
				cr->cr_hqst,cr->cr_hqn,cr->cr_hrn,
				cr->cr_hrendE+cr->cr_hrendL+cr->cr_hrendC,
				cr->cr_hrsvka,
				cr->cr_bufRem,
				cr->cr_delreqn?"D":"-"
			);
			if( _lSINGLEP )
				TRACE("%s",msg);
			else	porting_dbg("%s",msg);
			if( tc ){
				fprintf(tc,"%s\n",msg);
			}
		}
	}
	if( verbose ){
		dumpns("-Ecc");
	}
	return 0;
}

typedef struct {
	int	ci_timeout;
	int	ci_id;
	int	ci_cstat;
	short	ci_hrsvka;
	short	ci_srcline;
	short	ci_ix;
	short	ci_event;
	FDesc	ci_Fd;
	ConnReq *ci_cr;
} ConnId;

static int closeQ[2];
static FDesc CloseQ[2];
static int close_tid;

/* internal pseudo inputs to cause state transitions */
static FDesc ResQ[2];
static int resQ[2];
static int resQlen;
static int res_tid;
typedef struct {
	ConnId	rq_ci;
	MStr(	rq_name,256-sizeof(ConnId));
} ResReq;

static int gotevent(ConnCtx *cx,PollVect *Pv,ConnReq *cre,ConnReq *crs,int crn){
	int rcc;
	ConnId ci;
	ConnReq *cr1;
	int len;
	IStr(buf,CC_BUFSIZ+1);

	rcc = xrecv("gotevent",cre,ResQ[0],&ci,sizeof(ci));
	if( rcc != sizeof(ci) ){
		TRACE("{%d}I event#%X -- Aborted BAD-SIZE (%d)",ci.ci_id,ci.ci_event,rcc);
		return -1;
	}
	if( ci.ci_ix < 0 || crn <= ci.ci_ix ){
		TRACE("{%d}I event#%X -- Aborted BAD-IX (%d)",ci.ci_id,ci.ci_event,ci.ci_ix);
		return -2;
	}
	cr1 = &crs[ci.ci_ix];
	if( cr1->cr_ix != ci.ci_ix || cr1->cr_id != ci.ci_id ){
		TRACE("{%d}I event#%X -- Aborted BAD-ID (%d){%d}",ci.ci_id,ci.ci_event,ci.ci_ix,cr1->cr_id);
		return -3;
	}
	if( cr1->cr_cstat == 0
	 || cr1->cr_cstat != CCSV_C_RESOLVING
	){
		TRACE("{%d}I event#%X -- Aborted BAD-STAT (s%X)",ci.ci_id,ci.ci_event,cr1->cr_cstat);
		return -4;
	}

	DEBUGEV("{%d}A event#%X s%X (%d) Q%d-R%d [%d %d]",
		cr1->cr_id,ci.ci_event,cr1->cr_cstat,cr1->cr_bufRem,
		cr1->cr_hqn,cr1->cr_hrn,cr1->cr_clsock,cr1->cr_svsock);
	if( 0 < cr1->cr_hqn && 0 <= cr1->cr_svsock ){
		putSv(cx,cr1);
	}
	len = cr1->cr_bufRem;
	cr1->cr_bufRem = 0;
	Xbcopy(cr1->cr_buf,AVStr(buf),len);
	setVStrEnd(buf,len); /* for large header of which end will be detected by '\0' in parseHTTPreq() */
	newHTTPproxy(cx,Pv,crs,crn,cr1,cr1->cr_clSock,AVStr(buf),len);
	DEBUGEV("{%d}B event#%X s%X (%d) [%d %d]",
		cr1->cr_id,ci.ci_event,cr1->cr_cstat,cr1->cr_bufRem,
		cr1->cr_clsock,cr1->cr_svsock
	);

	// TRACE("{%d} #### Resolved",cr1->cr_id);
	updateFdv++; /* 9.9.8 activate after resolv. */

	if( cr1->cr_cstat == CCSV_C_RESOLVING ){
		destroyActX("con-e-res",cr1);
		return -5;
	}
	return 0;
}
static int Resolver(){
	int ri,rcc,found;
	ResReq rq;
	VSAddr vsab;
	double St,Elp;
	double Total = 0;
	int wcc;
	ConnReq cr0;

	setthreadgid(0,Ecc_tid);
	bzero(&cr0,sizeof(cr0));
	for( ri = 1; ; ri++ ){
		rcc = xrecv("Resolver",&cr0,ResQ[1],&rq,sizeof(rq));
		resQlen--;
		St = Time();
		found = VSA_getbynameNocache(FL_ARG,NULL,0,rq.rq_name,0,&vsab);
		Elp = Time()-St;
		Total += Elp;
		TRACE("EccRes/%d+%d %d %d (%.3f %.1f %.1f/%d) [%d]{%d} %s",ri,resQlen,rcc,found,
			Elp,Total,ECC_TimeForRes,ECC_Res,
			rq.rq_ci.ci_ix,rq.rq_ci.ci_id,
			rq.rq_name
		);
		rq.rq_ci.ci_event = 1;
		wcc = xsend("Resolver",&cr0,ResQ[1],&rq.rq_ci,sizeof(rq.rq_ci));
	}
	return 0;
}
static int resclient(ConnReq *cr,PCStr(host),int port,VSAddr *vsa){
	int found;
	int wcc;
	ResReq rq;

	if( host[0] == 0 ){
		found = 0;
		VSA_atosa(vsa,port,host);
	}else
	if( VSA_strisaddr(host) ){
		found = 1;
		VSA_atosa(vsa,port,host);
	}else
	if( VSA_getbynameNocache(FL_ARG,cr,1,host,port,vsa) ){
		found = 2;
	}else{
		if( res_tid == 0 ){
			res_tid = thread_fork(0x80000,0,"EccRES",(IFUNCP)Resolver);
		}
		rq.rq_ci.ci_ix = cr->cr_ix;
		rq.rq_ci.ci_id = cr->cr_id;
		strcpy(rq.rq_name,host);
		resQlen++;
		wcc = xsend("resclient",cr,ResQ[0],&rq,sizeof(rq));
		found = RES_NOTYET;
	}
	return found;
}

static int Closer();
static void initAcc(ConnReq *crs,int crn,int acsock,int exsock,int clsock){
	int si = 0;
	double Now = Time();

	setupCSC("handleCSC",handleCSC,sizeof(handleCSC));

	updateFdv = 1;
	crs[si].cr_ix = si;
	crs[si].cr_id = SvccId++;
	crs[si].cr_cstat = CCSV_C_ACCEPT;
	crs[si].cr_clSock = FD_NEW("acSock",0,acsock);
	crs[si].cr_svSock = FD_INVALID(-4);
	crs[si].cr_connSt = Now;
	si++;

	if( 0 <= exsock ){
		crs[si].cr_ix = si;
		crs[si].cr_id = SvccId++;
		crs[si].cr_cstat = CCSV_C_WATCHEX;
		crs[si].cr_clSock = FD_INVALID(-5);
		crs[si].cr_svSock = FD_NEW("exSock",0,exsock);
		crs[si].cr_connSt = Now;
		si++;
	}
	if( withResThread ){ /* Resolver thread */
		Socketpair(resQ);
		ResQ[0] = FD_NEW("resQ0",0,resQ[0]); 
		ResQ[1] = FD_NEW("resQ1",0,resQ[1]); 
		setNonblockingSocket(resQ[0],1);

		crs[si].cr_ix = si;
		crs[si].cr_id = SvccId++;
		crs[si].cr_cstat = CCSV_C_WAITEVENT;
		crs[si].cr_clSock = ResQ[0];
		crs[si].cr_svSock = FD_INVALID(-7);
		crs[si].cr_connSt = Now;
		si++;
	}
	if( withCloserThread ){
		Socketpair(closeQ);
		CloseQ[0] = FD_NEW("closeQ0",0,closeQ[0]);
		CloseQ[1] = FD_NEW("closeQ1",0,closeQ[1]);
		close_tid = thread_fork(0x80000,0,"EccClose",(IFUNCP)Closer);
	}
	if( 0 <= clsock ){
		crs[si].cr_ix = si;
		crs[si].cr_id = SvccId++;
		crs[si].cr_cstat = CCSV_C_WAITREQ; crs[si].cr_statSt = Time();
		crs[si].cr_clSock = FD_NEW("clSock",0,clsock);
		crs[si].cr_svSock = FD_INVALID(-6);
		crs[si].cr_connSt = Now;
		si++;
	}

	TRACE("## initAcc(ac=%d ex=%d cl=%d)",acsock,exsock,clsock);
}

static int getCount(ConnReq *crs,int crn,ConnReq *qcr){
	int ci;
	int ca = 0;
	int cn = 0;
	int svn = 0;
	int svka = 0;
	ConnReq *cr;
	int csiz = VSA_size((VSAddr*)&qcr->cr_clsa);
	int vsiz = VSA_size((VSAddr*)&qcr->cr_svsa);

	for( ci = 0; ci < crn; ci++ ){
		cr = &crs[ci];
		if( cr->cr_cstat == 0 ){
			continue;
		}
		ca++;
		if( cr->cr_cstat == CCSV_C_SVKA ){
			if( bcmp(&qcr->cr_svsa,&cr->cr_svsa,vsiz) == 0 ){
				svka++;
			}
		}
		if( cr->cr_cstat == CCSV_C_RELAY ){
			if( bcmp(&qcr->cr_clsa,&cr->cr_clsa,csiz) == 0 ){
				cn++;
			}
			if( bcmp(&qcr->cr_svsa,&cr->cr_svsa,vsiz) == 0 ){
				svn++;
			}
		}
	}
	qcr->cr_ccnum = ca;
	qcr->cr_clcnt = cn;
	qcr->cr_svcnt = svn;
	qcr->cr_svka = svka;
	return cn;
}

static int relaysF(Connection *Conn,int exsock,int svsock,int ac,const char *av[],PCStr(arg)){
	DEBUG("-Ecc relays svsock=[%d]%d [%d] [%s]",svsock,sockPort(svsock),
		svsock,arg);
	relays(Conn,svsock,exsock,-1);
	return 0;
}
int startCCSV(Connection *Conn){
	IStr(path,256);
	int acsock;
	int sync[2];
	int pid;
	IStr(portenv,256);

	if( !EccEnabled() )
		return -2;
	sprintf(path,"%s/ccsvsock/%d",ACTDIR(),SERVER_PORT());

	/* use the open_localhost just to share a CCSV */
	acsock = server_open_localhost("CCSV-start",AVStr(path),32);
	DEBUG("-Ecc PORT=%d [%s]",sockPort(acsock),path);

	sprintf(portenv,"CCSV_PORT=%s",path);
	putenv(stralloc(portenv));

	ECC_svSock = acsock;
	strcpy(Svcc.sv_acpath,path);
	Socketpair(sync);
	if( lSINGLEP() ){
		Ecc_tid = thread_fork(0x80000,0,"Ecc",(IFUNCP)relays,Conn,acsock,sync[0],-1);
	}else
	if( INHERENT_fork() ){
		if( pid = Fork("CCSV-server") ){
			close(sync[0]);
			return pid;
		}else{
			close(sync[1]);
			relays(Conn,acsock,sync[0],-1);
		}
	}else{
		DEBUG("-Ecc acsock=[%d]%d [%d %d] [%s]",acsock,sockPort(acsock),
			sync[0],sync[1],portenv);
		setCloseOnExecSocket(sync[1]);
		execFunc(Conn,sync[0],acsock,(iFUNCP)relaysF,portenv);
		close(sync[0]);
	}
	return 0;
}
int dupclosed_FL(FL_PAR,int fd);
static void dumpsizes();
int service_ecc(Connection *Conn,int sock,int port){
	dumpsizes();
	if( Port_Proto ){
		int clsock,acsock,acsock1;
		TRACE("##Ecc [%d]%d",Conn->clif._acceptSock,Conn->clif._acceptPort);
		if( Ecc_tid == 0 ){
			Ecc_tid = -1;
			clsock = dup(ClientSock);
			dupclosed_FL(FL_ARG,ClientSock); /* to avoid shutdown for alive socket */
			acsock = dup(Conn->clif._acceptSock);
			acsock1 = server_open("Ecc",VStrNULL,0,1);
			TRACE("##Ecc-A PORT=%d/%d",ServSockX(),sockPort(ServSockX()));
			dup2(acsock1,Conn->clif._acceptSock);
			TRACE("##Ecc-B PORT=%d/%d",ServSockX(),sockPort(ServSockX()));
			close(acsock1);
			Ecc_tid = thread_fork(0x80000,0,"Ecc",(IFUNCP)relays,Conn,acsock,-1,clsock);
		}else
		if( Ecc_tid == -1 ){
			int wi;
			for( wi = 0; wi < 10; wi++ ){
				TRACE("##Ecc-C PORT=%d/%d waiting... tid=%X",
					ServSockX(),sockPort(ServSockX()),Ecc_tid);
				if( Ecc_tid != -1 ){
					TRACE("##Ecc-Cx xC PORT=%d/%d tid=%X",
						ServSockX(),sockPort(ServSockX()),Ecc_tid);
					break;
				}
				msleep(100);
			}
		}
		return 0;
	}
	relays(Conn,sock,-1,-1);
	return 0;
}

/*
 * CCSV CLIENT
 */
static int connectCCSV(){
	const char *env;
	int svsock;

	if( Svcc.sv_acpath[0] == 0 ){
		if( env = getenv("CCSV_PORT") ){
			strcpy(Svcc.sv_acpath,env);
		}else{
			return -2;
		}
	}
	/* use the open_localhost just to share a CCSV */
	svsock = client_open_localhost("CCSV-connect",Svcc.sv_acpath,1);
	if( svsock < 0 ){
		DEBUG("-Ecc clnt %X NG1 %d [CCSV_PORT=%s] ##ERR##",
			ECC_svCtl,ECC_svCnt,Svcc.sv_acpath);
		return -2;
	}
	return svsock;
}
int connectViaCCSV(int sock,SAP svaddr,int leng,int timeout,PVStr(cstat)){
	FDesc svSock;
	ConnReq cr;
	int wcc,rcc;
	Connection *Conn = 0;
	const char *proto = "";
	const char *host = "";
	int port = 0;
	double Start,Now;
	int isHTTP = 0;
	VSAddr rsvaddr;

	if( strcmp(VSA_ntoa((VSAddr*)svaddr),"127.0.0.1")==0 ){
		return -2; /* -2 to indicate retry */
	}
	if( _lMULTIST )
		Conn = SessionConn();
	if( Conn == 0 )
		Conn = MainConn();
	if( Conn ){
		if( streq(DST_PROTO,"ftp") || streq(DST_PROTO,"ftp-data") ){
			return -2;
		}
		Conn->ccsv.ci_connSt = 0;
		Conn->ccsv.ci_reused = 0;
		Conn->ccsv.ci_svaddr = *(VSAddr*)svaddr;
		if( streq(DST_PROTO,"http") ){
			isHTTP = 1;
		}
	}

	/* if RTT is small */
	/* if private 192.* or local sv/dg/cl on the same  class-B */
	/* then return -2 */

	Start = Time();
	ECC_svCnt++;
	svSock = FD_NEW("cvc",0,connectCCSV());
	if( svSock.fd_fd < 0 ){
		return -2;
	}

	bzero(&cr,sizeof(cr));
	if( Conn ){
		cr.cr_clsa = *(SAB*)&Client_VAddr->a_vsa;
		if( isAllZero(&cr.cr_clsa,sizeof(cr.cr_clsa)) ){
			//VSA_atosa(&cr.cr_clsa,CLNT_PORT,CLNT_ADDR);  ... should get from a_int[]
			int getpeerVSAddr(int sock,VSAddr *vsa);
			getpeerVSAddr(ClientSock,(VSAddr*)&cr.cr_clsa);
			TRACE("## connVia() <= [%d] %s %X",ClientSock,clientid(&cr),Client_VAddr->I3);
		}
		VSA_getbynameNocache(FL_ARG,NULL,0,DST_HOST,DST_PORT,&rsvaddr);
		cr.cr_rsvsa = *(SAB*)&rsvaddr;
	}
	cr.cr_svsa = *(SAB*)svaddr;
	cr.cr_timeout = timeout;
	if( VSA_port((VSAddr*)svaddr) == 80
	 || isHTTP /* via proxy */
	){
		if( streq(RequestMethod,"POST")
		 || HTTP_methodWithBody(RequestMethod)
		 || 0 < RequestLength /* req. body. leng */
		){
			/* retrial on error for req.body is incomplete */
			DEBUG("-Ecc no-SVKA Method[%s]%d",
				RequestMethod,RequestLength);
		}else{
			cr.cr_qflag |= CCSV_Q_SVKA;
		}
	}
	wcc = xsend("Ecc-Req-Conn",&cr,svSock,&cr,sizeof(cr));
	if( PollIn(svSock.fd_fd,timeout) <= 0 ){
		/* should be PollIns() for ClientSock */
		DEBUG("-Ecc clnt timeout %d => %s:%d ##ERR##",timeout,
			VSA_ntoa((VSAddr*)svaddr),VSA_port((VSAddr*)svaddr));
		close(svSock.fd_fd);
		return -2;
	}else{
		rcc = xrecv("RECV ViaSvcc",&cr,svSock,&cr,sizeof(cr));
	}

	if( cr.cr_rstat == 0 ){
		close(svSock.fd_fd);
		return -2;
	}

	dup2(svSock.fd_fd,sock);
	close(svSock.fd_fd);

	/* set TeleportPort */
	if( Conn ){
		Conn->ccsv.ci_connSt = cr.cr_connSt;
		Conn->ccsv.ci_ix = cr.cr_ix;
		Conn->ccsv.ci_id = cr.cr_id;
		bcopy(&cr.cr_svifsa,&Conn->ccsv.ci_ifaddr,sizeof(VSAddr));
		proto = DST_PROTO;
		host = DST_HOST;
		port = DST_PORT;
	}
	Now = Time();
	if( 1 ){
		IStr(cstat,128);
		sprintf(cstat,"(%X %d %d/%d %X)",ECC_svCtl,ECC_svCnt,
			wcc,rcc,cr.cr_rstat);

		daemonlog("E","-Ecc(%2d){%d}*%d CCSVc (%.1f %.3f) [%d]%s:%d %s://%s %s\n",
			cr.cr_ix,cr.cr_id,cr.cr_reused,
			Now-cr.cr_connSt,Now-Start,
			sock,VSA_ntoa((VSAddr*)svaddr),VSA_port((VSAddr*)svaddr),
			proto,host,cstat
		);
	}
	if( Conn )
	if( cr.cr_rstat & CCSV_R_REU ){
		/* set "reusing" to retry on error */
		Conn->ccsv.ci_reused = cr.cr_reused;
		DEBUG("-Ecc(%2d){%d}*%d reu(%.1f) %s://%s:%d",
			cr.cr_ix,cr.cr_id,cr.cr_reused,Time()-cr.cr_connSt,
			DST_PROTO,DST_HOST,DST_PORT);
		/*
		 * should restore
		 * toProxy, toMaster, MediatorVersion, ServViaSocks
		 * ...
		 */
	}
	return 0;
}
int destroyCCSV(PCStr(what),Connection *Conn,int svsock){
	int ccid;
	int alive;
	int ok = -1;

	if( Conn->ccsv.ci_id == 0 ){
		return 0;
	}
	alive = IsAlive(svsock);
	DEBUG("-Ecc(%2d){%d}*%d destroy(%s) [%d]%d (%.2f) ##WARN##",
		Conn->ccsv.ci_ix,Conn->ccsv.ci_id,
		Conn->ccsv.ci_reused,
		what,svsock,alive,
		Time()-Conn->ccsv.ci_connSt
	);
	if( 1 /*alive*/ ){
		FDesc csvSock;
		csvSock = FD_NEW("dcv",0,client_open_localhost("CCSV-destroy",Svcc.sv_acpath,1));
		if( csvSock.fd_fd < 0 ){
			ok = -1;
		}else{
			ConnReq cr;
			int wcc,rcc;

			bzero(&cr,sizeof(cr));
			cr.cr_ix = Conn->ccsv.ci_ix;
			cr.cr_id = Conn->ccsv.ci_id;
			cr.cr_qflag = CCSV_Q_DESTROY;
			wcc = xsend("Ecc-Req-Destroy",&cr,csvSock,&cr,sizeof(cr));
			if( PollIn(csvSock.fd_fd,3*1000) <= 0 ){
			  DEBUG("-Ecc(%2d){%d} destroy NO-RESP. ##ERR##",
				Conn->ccsv.ci_ix,Conn->ccsv.ci_id);
				ok = -2;
			}else{
		rcc = xrecv("RECV destroy",&cr,csvSock,&cr,sizeof(cr));
				if( rcc == sizeof(cr) )
					ok = 1;
				else	ok = -10000-rcc;
			}
			close(csvSock.fd_fd);
		}
	}
	Conn->ccsv.ci_id = 0;
	return ok;
}

/* wait until no active conn. to the server.
 * detecting the disconnection from the client
 */
static int getDstCount(Connection *Conn,FDesc svSock,ConnReq *cr){
	IStr(addr,128);
	const char *host;
	int count = 0;
	int wcc,rcc;
	int serrno;

	bzero(cr,sizeof(ConnReq));

	Client_Addr(addr);
	host = Client_Host;
	count = ClientCount(host,addr);

	cr->cr_qflag = CCSV_Q_GETCLCNT;
	cr->cr_clsa = *(SAB*)&Client_VAddr->a_vsa;
	cr->cr_svsa = *(SAB*)&Conn->ccsv.ci_svaddr;
	cr->cr_ccnum = -1;
	cr->cr_svcnt = -1;
	cr->cr_svka = -1;
	cr->cr_clcnt = -1;
	cr->cr_rcvd = -1;

	wcc = xsend("Ecc-Req-DstCount",cr,svSock,cr,sizeof(ConnReq));
	serrno = errno;
	if( wcc < (int)sizeof(ConnReq) ){
		TRACE("--Ecc FATAL getDst [%d] wcc=%d/%d err=%d",
			svSock.fd_fd,wcc,sizeof(ConnReq),serrno);
		return -1;
	}
	if( PollIn(svSock.fd_fd,3*1000) <= 0 ){
		DEBUG("-Ecc ##BadCount## timeout ##ERR##");
		rcc = -99;
	}else{
		rcc = xrecv("RECV DstCount",cr,svSock,cr,sizeof(ConnReq));
		serrno = errno;
	}
	if( rcc <= 0 ){
		TRACE("--Ecc FATAL getDst [%d] rcc=%d/%d err=%d",
			svSock.fd_fd,rcc,sizeof(ConnReq),serrno);
		return -1;
	}
	if( rcc == sizeof(ConnReq) && 0 <= cr->cr_ccnum ){
		count = cr->cr_clcnt;
	}else{
		DEBUG("##BadCount %d/%d %d/%d %d ##ERR##",rcc,wcc,
			cr->cr_clcnt,cr->cr_ccnum,cr->cr_rcvd);
	}
	return count;
}
/* waiting over-loaded server (503 response) */
int waitCCSV(Connection *Conn,int msec){
	int ri;
	int count0;
	int count = 0;
	double St = Time();
	IStr(addr,128);
	const char *host;
	FDesc svSock;
	int off = trand1(500);
	ConnReq qcr;

	Client_Addr(addr);
	host = Client_Host;
	svSock = FD_NEW("wcv",0,connectCCSV());
	count0 = ClientCount(host,addr);

	for( ri = 0; ri < 60; ri++ ){
		count = getDstCount(Conn,svSock,&qcr);
		if( 15 < ri )
		TRACE("##Ecc(%2d){%d} waiting s=%d k=%d c=%d / %d / %d (%d)(%.1f)",
			qcr.cr_ix,qcr.cr_id,qcr.cr_svcnt,qcr.cr_svka,
			count,qcr.cr_ccnum,qcr.cr_rcvd,ri,Time()-St);
		if( count < 0 ){
			break;
		}
		if( 0 < qcr.cr_svka ){
			TRACE("##Ecc waiting(%d) SVKA=%d (%.2f)",ri,qcr.cr_svka,Time()-St);
			break;
		}
		if( qcr.cr_svcnt <= 1 ){
			break;
		}
		/*
		if( count < 3 ){
			break;
		}
		*/
		if( IsAlive(ClientSock) == 0 ){
			break;
		}
		msleep(1000+off);
	}
	close(svSock.fd_fd);

	DEBUG("## waitCCSV cl=[%d/%d] (%d / %d) <- %d <- %d (%.2f)(%d)",
		ClientSock,IsAlive(ClientSock),
		count,qcr.cr_ccnum,count0,Conn->cl_count,
		Time()-St,ri);
	return 0;
}

#include "vaddr.h"
int tobeREJECTED(Connection*Conn);
static int toberejectedX(int clsock,PCStr(clhost),int clport){
	static Connection *Conn;
	int conly;
	int rej;

	stksize(FL_ARG);
	if( Conn == 0 ){
		Conn = (Connection*)malloc(sizeof(Connection));
	} 
	conly = RES_CACHEONLY(1);
	Conn->no_dstcheck_proto = 80;
	ClientSock = clsock;
	VA_gethostNAME(clsock,&Conn->cl_sockHOST); /* -Pclif */
	VA_setClientAddr(Conn,clhost,clport,0);
	rej = tobeREJECTED(Conn);
	conly = RES_CACHEONLY(conly);

	if( rej ){
		TRACE("##Ecc ToBeRejected [%s:%d] {%s}",clhost,clport,Conn->reject_reason);
	}
	return rej;
}

int spinach(Connection *Conn,FILE *fc,FILE *tc){
	IStr(req,256);
	IStr(com,256);
	IStr(arg,256);

	for(;;){
		fprintf(tc,"Spinach> "); fflush(tc);
		truncVStr(req);
		truncVStr(com);
		truncVStr(arg);
		if( fgets(req,sizeof(req),fc) == 0 ){
			break;
		}
		Xsscanf(req,"%s %[^\r\n]",AVStr(com),AVStr(arg));
		if( strncaseeq(com,"QUIT",3) ){
			fprintf(tc,"-- Bye.\r\n");
			break;
		}
		if( strncaseeq(com,"CLOSER",3) ){
			int owct = withCloserThread;
			withCloserThread = atoi(arg);
			fprintf(tc,"-- CLOSER %d <= %d\r\n",withCloserThread,owct);
			continue;
		}
		if( strncaseeq(com,"NOLOG",3) ){
			int owsl = withoutSyslog;
			withoutSyslog = atoi(arg);
			fprintf(tc,"-- NOLOG %d <= %d\r\n",withoutSyslog,owsl);
			continue;
		}
		if( strncaseeq(com,"TIME",3) ){
			double St;
			int ti,tn;
			tn = atoi(arg);
			if( tn <= 0 ) tn = 100*1000;
			if( 1000*1000 < tn ) tn = 1000*1000;

#ifdef _MSC_VER
			if( isWindowsCE() ){
			double mine = myTime();
			double orig = origTime();
			fprintf(tc,"-- Time() = mine=%.3f orig=%.3f diff=%.03f\r\n",mine,orig,mine-orig);
			fflush(tc);

			St = Time();
			int tk0 = GetTickCount();
			for( ti = 0; ti < tn; ti++ ) GetTickCount();
			fprintf(tc,"-- GetTickCount() = %.3f / %d (%d)\r\n",Time()-St,ti,GetTickCount()-tk0);

			St = Time();
			struct timeb timeb;
			for( ti = 0; ti < tn; ti++ ) ftime(&timeb);
			fprintf(tc,"-- ftime() = %.3f / %d\r\n",Time()-St,ti);

			St = Time();
			SYSTEMTIME gst;
			for( ti = 0; ti < tn; ti++ ) GetSystemTime(&gst);
			fprintf(tc,"-- GetSystemStime() = %.3f / %d\r\n",Time()-St,ti);
			}
#endif

			St = Time();
			for( ti = 0; ti < tn; ti++ ) Time();
			fprintf(tc,"-- Time() = %.3f / %d\r\n",Time()-St,ti);
			St = Time();
			for( ti = 0; ti < tn; ti++ ) origTime();
			fprintf(tc,"-- origTime() = %.3f / %d\r\n",Time()-St,ti);
			continue;
		}
		if( CX1 ){
			fprintf(tc,"-- Time() x %d\r\n",nTime);
			dumpCon(CX1->cx_Pv,0,CX1->cx_crn,CX1->cx_crs,1,1,tc);
			dumpsizes();
		}
	}
	return 0;
}
static void dumpsizes(){
	TRACE("----serverid=%llX",p2llu(serverid));
	TRACE("----clientid=%llX",p2llu(clientid));
	TRACE("----servcice_ecc=%llX",p2llu(service_ecc));
	TRACE("----TextSize=%lld",p2llu(service_ecc)-p2llu(serverid));
}

static ConnId idQ[32];
static int idQput;
static int idQget;
static CriticalSec idQCSC;
static int idQenQ(ConnId *id){
	int wi;
	for( wi = 0; ; wi++ ){
		if( idQput - idQget < elnumof(idQ) )
			break;
		msleep(10);
	}
	idQ[idQput % elnumof(idQ)] = *id;
	if( 0 < wi )
	TRACE("----(%d - %d) %d %d {%d} idQ put",idQget,idQput,idQput-idQget,wi,id->ci_id);
	idQput++;
	return sizeof(ConnId);
}
static int idQdeQ(ConnId *id){
	int wi;
	for( wi = 0; ; wi++ ){
		if( idQget < idQput )
			break;
		msleep(1000);
	}
	*id = idQ[idQget % elnumof(idQ)];
	if( 10 < wi )
	TRACE("----(%d - %d) %d %d {%d} idQ get",idQget,idQput,idQput-idQget,wi,id->ci_id);
	idQget++;
	return sizeof(ConnId);
}

static int closeQlen;
static int close_imm;
static int Closer(){
	int ri,rcc,rcode;
	double St,Elp;
	double Stc;
	double Total = 0;
	ConnId ci;
	int fd;
	int ready;
	ConnReq *cr;
	const char *peer = "";
	int timeout;
	IStr(hostb,128);
	IStr(peerb,128);
	ConnReq cr0;
	FDesc Fd;
	int sock;

	setthreadgid(0,Ecc_tid);
	bzero(&cr0,sizeof(cr0));
	for( ri = 0; ; ri++ ){
		St = Time();
		ci.ci_event = 0;
		if( 0 ){
			rcc = xrecv("Closer",&cr0,CloseQ[0],&ci,sizeof(ci));
		}else{
			rcc = idQdeQ(&ci);
		}
		closeQlen--;
		fd = ci.ci_event;
		sock = SocketOf(fd);
		cr = ci.ci_cr;
		if( rcc != sizeof(ci) || fd < 0 ){
			TRACE("{%d} Closer rcc=%d [%d] err=%d",ci.ci_id,rcc,fd,errno);
			continue;
		}
		if( 0 < ci.ci_timeout && ci.ci_timeout < 10*1000 )
			timeout = ci.ci_timeout;
		else	timeout = 100;
		peer = "";

		//if( IsConnected(fd,0) ){
			getpairName(fd,AVStr(hostb),AVStr(peerb));
			Xsprintf(TVStr(hostb),"<=%s",peerb);
			peer = hostb;
		//}
		St = Time();
		/* should do it in blocking-IO ? */
		// setNonblockingSocket(fd,0);
		/* should do LINGER ? */
		// set_linger(fd,0);

		if( 0 < ci.ci_timeout ){
			ready = PollIn(fd,timeout);
			shutdown(fd,SHUT_RDWR);
			if( ready == 0 ){
				ready = PollIn(fd,timeout);
			}
		}else{
			ready = 0;
			shutdown(fd,SHUT_RDWR);
		}

		Stc = 0;
		if( enterCSCX(handleCSC,1) != 0 ){
			Stc = Time();
			enterCSC(handleCSC);
		}
		rcode = close(fd);
		leaveCSC(handleCSC);
		if( Stc ){
			TRACE("---- {%d} Mutex Closer [%d/%d] (%.3f)",ci.ci_id,
				fd,sock,Time()-Stc);
		}
		Elp = Time() - St;
		Total += Elp;

		if( 0.1 < Elp || ready == 0 )
		TRACE("--{%d} Closer %d+%d+%d (e%.3f t%.1f) [%d] rdy=%d cls=%d #%d s%X tou=%d K%d %s",
			ci.ci_id,close_imm,ri,closeQlen,Elp,Total,fd,ready,rcode,
			ci.ci_srcline,ci.ci_cstat,ci.ci_timeout,ci.ci_hrsvka,peer);
	}
	return 0;
}
static int closeit(FL_PAR,ConnReq *cr,int fd,int imm){
	ConnId ci;
	int ready = 0;
	int rcode;
	int wcc;
	double St0,St1,St2,Now,Elp;
static double Total;
	int rcc;
	int sock;
	IStr(buf,32);

	if( close_tid == 0 ){
		return -1;
	}
	St0 = Time();
	sock = SocketOf(fd);
	shutdown(fd,SHUT_WR);
	St1 = Time();

goto CLOSE_ENQ;

	if( 0 < closeQlen
	  || cr->cr_cstat == CCSV_C_CLOSING && 5 < (St1 - cr->cr_finSt)
	  || cr->cr_cstat == CCSV_C_RELAY && imm == 0 /* if not closed by the client-side */
	){
		/* don't be blocked in mutex for close() */
		goto CLOSE_ENQ;
	}
	ready = PollIn(fd,1);
	if( ready < 0 || 0 < ready && !IsAlive(fd) ){
		St2 = Time();
		if( ready < 0 ){
			TRACE("{%d} Closeit-FG [%d/%d] <= %s:%d (%.3f %.3f) Rdy=%d",
				cr->cr_id,fd,sock,FL_BAR,St1-St0,St2-St1,ready);
		}
		if( 0 < ready ){
			/* should flush input ? */
			//rcc = read(fd,buf,1);
			shutdown(fd,SHUT_RDWR);
			/* should do closesocket() on Win ? */
		}
		rcode = close(fd);
		Now = Time();
		Elp = Now - St0;
		Total += Elp;
		close_imm++;
		if( ready < 0 || 0.02 < Elp ){
			IStr(elps,64);
			sprintf(elps,"(t%.1f e%.3f / %.3f %.3f %.3f)",Total,Elp,
				St1-St0,St2-St1,Now-St2);
			TRACE("{%d} s%X %s Closeit-FG [%d/%d] %s Rdy=%d cls=%d %s:%d",
				cr->cr_id,cr->cr_cstat,imm?"i":"-",
				fd,sock,elps,ready,rcode,FL_BAR);
		}
		return rcode;
	}

CLOSE_ENQ:
	ci.ci_srcline = FL_L;
	ci.ci_cr = cr;
	ci.ci_ix = cr->cr_ix;
	ci.ci_id = cr->cr_id;
	ci.ci_cstat = cr->cr_cstat;
	ci.ci_hrsvka = cr->cr_hrsvka;
	if( cr->cr_cstat == CCSV_C_SVKA
	){
		// no need to wait
		ci.ci_timeout = 1;
	}else
	if( cr->cr_cstat == CCSV_C_CLOSING
	){
		// already waited enough
		ci.ci_timeout = 1;
	}else
	if( cr->cr_cstat == CCSV_C_WAITREQ
	){
		// should wait drain of response
		ci.ci_timeout = 1000;
	}else
	if( imm ){
		ci.ci_timeout = 100;
	}else
	if( fd == cr->cr_clsock ){
		if( 0 < cr->cr_hqn && cr->cr_hrn < cr->cr_hqn ){
			// no response from the HTTP server
			// maybe generating 503 response is necessary
			ci.ci_timeout = 100;
		}else{
			/* the timeout must be short on EOS from the client */
			ci.ci_timeout = 1500;
		}
	}else{
		ci.ci_timeout = 200;
	}
	ci.ci_event = fd;

	/* WinCE: should set the owner gid of the fd */
	DEBUG("--{%d} closeit [%d] <= %s:%d",cr->cr_id,fd,FL_BAR);
	closeQlen++;
	St2 = Time();

	if( 0 ){
		wcc = xsend("Closeit",cr,CloseQ[1],&ci,sizeof(ci));
	}else{
		wcc = idQenQ(&ci);
	}
	Now = Time();
	if( 0.1 < Now-St0 ){
		TRACE("{%d} Closeit-BG [%d/%d] <= %s:%d (%.3f %.3f %.3f) Rdy=%d",
			cr->cr_id,fd,sock,FL_BAR,St1-St0,St2-St1,Now-St2,ready);
	}
	return 0;
}

