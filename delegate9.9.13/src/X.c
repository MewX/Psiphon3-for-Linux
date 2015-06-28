/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2010 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	X.c (X proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950308	created
	091212	added "Y11" protocol (9.9.7)
	091229	named "yyMUX" or "y2MUX" protocol
TODO:
	- X cache (fonts, etc.)
	- message compression (for each connection)
	- accepting connection at remote Y11 proxy
	- symmetric connection (connection coupler, reflector)
	- authentication (Basic encrypted by Credhy, Digest/HTTP)
	- partial encryption (ex. key stroke)
	- automatic networking of Y11 servers
	- mirroring window (multicasting)
	- restricting available functionality at remote host
	- restriction based on types of X requests
	- logging X protocol
	- virtual hosting by the Host: field
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include "vsocket.h" /* RecvFrom() */
#include "ystring.h"
#include "vsignal.h"
#include "delegate.h"
#include "filter.h" /* XF_FSV */
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "auth.h"
#include "credhy.h"
#include "mysgTTy.h"
#include "service.h"
#include "http.h"

#if 0 /*{ became unnecessary with FL_fcloseFILE for Unix */
#if defined(fcloseFILE) /*{*/

/* WinCE */
static int YfcloseFILE(FL_PAR,FILE *fp){
	int rcode;
	fflush(fp);
	rcode = XXfcloseFILE(FL_BAR,fp);
	return rcode;
}
#undef fcloseFILE
#define fcloseFILE(fp) YfcloseFILE(FL_ARG,fp)

#else /*}{*/
static CriticalSec FILECSC;
static int YfcloseFILE(FL_PAR,FILE *fp){
	int rcode;

	fflush(fp);
	enterCSC(FILECSC);
	rcode = XXfcloseFILE(FL_BAR,fp);
	leaveCSC(FILECSC);
	return rcode;
}
#define fcloseFILE(fp) YfcloseFILE(FL_ARG,fp)
static int Yfclose(FL_PAR,FILE *fp){
	int rcode;

	fflush(fp);
	enterCSC(FILECSC);
	rcode = Xfclose(FL_BAR,fp);
	leaveCSC(FILECSC);
	return rcode;
}
#undef fclose
#define fclose(fp)     Yfclose(FL_ARG,fp)

static FILE *Yfdopen(FL_PAR,int fd,PCStr(mode)){
	FILE *fp;

	setupCSC("Yfdopen",FILECSC,sizeof(FILECSC));
	enterCSC(FILECSC);
	fp = Xfdopen(FL_BAR,fd,mode);
	leaveCSC(FILECSC);
	return fp;
}
#undef fdopen
#define fdopen(fp,mode) Yfdopen(FL_ARG,fp,mode)
#endif /*}*/
#endif /*}*/

#if defined(FMT_CHECK)
#define lfprintf(wh,fp,fmt,...) (fp==0?0:(fprintf(fp,fmt,##__VA_ARGS__),fputs("\r\n",fp)))
#else
#define lfprintf FMT_lfprintf
#endif

static jmp_buf tel_env;
static void sigPIPE(int sig){
	signal(SIGPIPE,SIG_IGN);
	longjmp(tel_env,SIGPIPE);
}
static void sigTERM(int sig){
	signal(SIGTERM,SIG_IGN);
	longjmp(tel_env,SIGTERM);
}

#define Getc(fc)	fputc(fgetc(fc),ts)

static int LEND;

static int GetInt2(FILE *fc,FILE *ts)
{	int iv;

	iv = Getc(fc);
	if( LEND )
		iv = (Getc(fc) << 8) | iv;
	else	iv = (iv << 8) | Getc(fc);
	return iv;
}
static int GetInt4(FILE *fc,FILE *ts)
{	int iv;

	iv = GetInt2(fc,ts);
	if( LEND )
		iv = (GetInt2(fc,ts) << 16) | iv;
	else	iv = (iv << 16) | GetInt2(fc,ts);
	return iv;
}

static int XCS(Connection *Conn,int fcbsize,int peer,int omask)
{	CStr(buf,0x4000);
	int gotsig;
	int rcc;
	int count,total;
	FILE *fc,*ts;
	int ch,op;
int b_order;
int n,l,r;
int code[4];
int ver,rev,nan,nad;

	total = count = 0;
	if( fcbsize == 0 )
		fcbsize = 1;
	if( sizeof(buf) < fcbsize )
		fcbsize = sizeof(buf);

	if( (gotsig = setjmp(tel_env)) == 0 ){

fc = fdopen(FromC,"r");
ts = fdopen(ToS,"w");

		sigsetmask(omask);

		b_order = Getc(fc);
		DBGMSG("BYTEORDER: %x:%c\n",b_order,b_order);
		if( b_order == 'l' || b_order == 'L' ){
			Verbose("#### LITTLE ENDIEN ####\n");
			LEND = 1;
		}else	LEND = 0;
		Getc(fc); /* padding */

		ver = GetInt2(fc,ts);
		rev = GetInt2(fc,ts);
		DBGMSG("VERSION: %d.%d\n",ver,rev);
		nan = GetInt2(fc,ts);
		nad = GetInt2(fc,ts);
		GetInt2(fc,ts); /* padding */

		for(;;){
			if( ready_cc(fc) == 0 )
				fflush(ts);
			op = getc(fc);
			if( op == EOF ){
				sv1log("EOF from the client\n");
				break;
			}
			buf[0] = op;
			if( putc(op,ts) == EOF ){
				sv1log("EOF from the server\n");
				break;
			}
			n = Getc(fc);
			l = GetInt2(fc,ts);

if( op == 45 ){
	int fid,leng,i;
	CStr(name,128);

	fid = GetInt4(fc,ts);
	leng = GetInt2(fc,ts);
	GetInt2(fc,ts);

	if( sizeof(name) <= leng+1 ){
		syslog_ERROR("OpenFont so long name: %d\n",leng);
	}
	for( i = 0; i < leng; i++ ){
		if( elnumof(name)-1 <= i ){
			Getc(fc);
			continue;
		}
		setVStrElem(name,i,Getc(fc)); /**/
	}
	setVStrEnd(name,i);
	Verbose("OpenFont: %s\n",name);
	for(; i % 4 != 0; i++ )
		Getc(fc);
}else
if( op == 46 ){
	int fid;
	fid = GetInt4(fc,ts);
	Verbose("CloseFont: %d\n",fid);
}else
if( op == 74 || op == 76 || op == 77 ){
	int d,g,x,y,p,i,och;
	d = GetInt4(fc,ts);
	g = GetInt4(fc,ts);
	x = GetInt2(fc,ts);
	y = GetInt2(fc,ts);

	if( op == 77 ){
		for( i = 0; i < n; i++ ){
			/*
			och = getc(fc)<<8 | getc(fc);
			*/
			och = getc(fc) << 8;
			och = och | getc(fc);
DBGMSG("OP ImageTEXT16[%3d / %3d/%3d]: outch=%4x x=%4d, y=%4d\n",i,n,l,och,x,y);
			putc(och >> 8,ts);
			putc(och&0xFF,ts);
		}
		if( (i % 2) != 0 )
			GetInt2(fc,ts);
	}else
	if( op == 76 ){
DBGMSG("OP ImageTEXT8[%3d/%3d]: x=%4d, y=%4d\n",n,l,x,y);
		for( i = 0; i < n; i++ ){
			int nch;
			och = getc(fc);
DBGMSG("OP ImageTEXT8[%3d / %3d/%3d]: outch=%4x x=%4d, y=%4d\n",i,n,l,och,x,y);
			if( (och & 0x80) && i+1 <= n ){
				nch = getc(fc);
				if( nch & 0x80 ){
					putc('+',ts);
					putc('-',ts);
				}else{
					putc(och,ts);
					putc(nch,ts);
				}
				i++;
			}else	putc(och,ts);
		}
		for(; i % 4 != 0; i++ )
			Getc(fc);
	}else
	if( op == 74 ){
		int len,delta,j,r;
DBGMSG("OP PolyTEXT8[%3d/%3d]: x=%4d, y=%4d\n",n,l,x,y);
		r = (l-4)*4;
		for( i = 0; 1 < r; i++ ){
			len = getc(fc); r--;
DBGMSG("OP PolyTEXT8[%3d / %3d/%3d]: len=%3d x=%4d, y=%4d\n",i,n,l,len,x,y);
			if( len == 255 ){
				int fid;
				putc(len,ts);
				fid = GetInt4(fc,ts);
				r -= 4;
DBGMSG("OP PolyTEXT8:Font=[%8x]:",fid);
			}else{
				putc(len,ts);
				delta = getc(fc); r--;
				putc(delta,ts);

				for( j = 0; j < len; j++ ){
					och = getc(fc); r--;
DBGMSG("PolyTEXT8[%3d]: %2x %c\n",j,och,och);
					putc(och,ts);
				}
			}
		}
		for(; 0 < r; r-- )
			Getc(fc);
	}
}else{
DBGMSG("OP %4d / %4d / %4d\n",op,n,l);
	for( r = (l-1)*4; 0 < r; r-- )
		ch = Getc(fc);
}
			count += 1;
			total += 1;
		}
	}
	signal(SIGPIPE,SIG_IGN);
	signal(SIGTERM,SIG_IGN);
	sv1log("CS-RELAY[%d>%d]: %dBytes %dI/O buf=%d\n",
		FromC,ToS,total,count,fcbsize);

	return total;
}
static int XSC(Connection *Conn,int fsbsize,int peer,int omask)
{	CStr(buf,0x4000);
	int gotsig;
	int rcc,wcc;
	int count,total;

	total = count = 0;
	if( fsbsize == 0 )
		fsbsize = 1;
	if( sizeof(buf) < fsbsize )
		fsbsize = sizeof(buf);

	if( setjmp(tel_env) == 0 ){
		sigsetmask(omask);
		while( 0 < (rcc = read(FromS,buf,QVSSize(buf,fsbsize))) ){
			count += 1;
			total += rcc;
			if( (wcc = write(ToC,buf,rcc)) <= 0 )
				break;
		}
		if( rcc <= 0 ) sv1log("SC-EOF\n");
	}
	signal(SIGPIPE,SIG_IGN);
	signal(SIGTERM,SIG_IGN);
	sv1log("SC-RELAY[%d<%d]: %dBytes %dI/O buf=%d\n",
		ToC,FromS,total,count,fsbsize);

	Kill(peer,SIGTERM);
	return total;
}
static int bidirectional_relay(Connection *Conn,int fcbsize,int fsbsize)
{	register int ppid,cpid;
	int omask;
	int total;

	Verbose("buffer: CS=%d SC=%d\n",fcbsize,fsbsize);

	ppid = getpid();
	omask = sigblock(sigmask(SIGPIPE)|sigmask(SIGTERM));
	signal(SIGPIPE,sigPIPE);
	signal(SIGTERM,sigTERM);

	if( (cpid = Fork("bidirectional_relay")) == 0 ){
		total = XSC(Conn,fsbsize,ppid,omask);
		Finish(0);
	}else{
		total = XCS(Conn,fcbsize,cpid,omask);
Kill(cpid,SIGTERM);
		wait(0);
		sigsetmask(omask);
	}
	return total;
}

void proxyX(Connection *Conn)
{	const char *rhost;
	int rdisp;

	/*
	 *	should support MOUNT="%d X://host:port/" ?
	 */
	rhost = "ysato";
	rdisp = 0;
	set_realserver(Conn,"X",rhost,6000+rdisp);

	sv1log("#### PROXY X to %s:%d [%s://%s:%d]\n",rhost,rdisp,
		DFLT_PROTO,DFLT_HOST,DFLT_PORT);

	if( 0 <= connect_to_serv(Conn,FromC,ToC,0) ){
		bidirectional_relay(Conn,0x1000,0x1000);
	}
}
static int relayXlocal(Connection *Conn);
int service_X(Connection *Conn)
{	int total;

	if( streq(iSERVER_HOST,"-.-") || streq(iSERVER_HOST,"x.-") ){
		relayXlocal(Conn);
		return 0;
	}
	if( isMYSELF(DFLT_HOST) ){
		proxyX(Conn);
		return -1;
	}
	if( ToS < 0 ){
		sv1log("No connection\n");
		return -1;
	}
	total = bidirectional_relay(Conn,0x1000,0x1000);
	return total;
}

int fpollinsX(int timeout,int fpc,FILE *fpv[],int rdv[]);

static int yy_gotSIG;
static int yy_nsigPIPE;

static int drain1(int timeout,int ifd,int ofd,PVStr(buf),int bsz){
	int rcc,wcc;
	int total = 0;

	for(;;){
		if( PollIn(ifd,timeout) <= 0 ){
			break;
		}
		rcc = read(ifd,(char*)buf,bsz);
		if( rcc <= 0 ){
			break;
		}
		total += rcc;
		wcc = write(ofd,buf,rcc);
		if( wcc <= rcc ){
			break;
		}
	}
	if( total ){
		sv1log("---- drain[%d][%d] %d\n",ifd,ofd,total);
	}
	return total;
}
int shutdownWR(int fd);
static int relay1(int in,int out){
	IStr(buf,8*1024);
	int rcc,wcc;

	for(;;){
		rcc = read(in,buf,sizeof(buf));
		if( rcc <= 0 ){
			break;
		}
		wcc = write(out,buf,rcc);
		if( wcc < rcc ){
			break;
		}
	}
	shutdownWR(out);
	return 0;
}
int relay2C(CCXP ccx2CL,CCXP ccx2SV,int fromcl,int tocl,int fromsv,int tosv){
	int fv[2],tv[2],rv[2],cv[2];
	int fi;
	int rdy;
	int rcc,wcc;
	IStr(buf,16*1024);
	int serrno;
	int nint = 0;
	int tid = 0;
	int sp[2];
	CCXP ccx[2];

	if( isWindows() && !file_ISSOCK(fromcl) ){
		Socketpair(sp);
		tid = thread_fork(0,0,"relay1",(IFUNCP)relay1,fromcl,sp[1]);
		fromcl = sp[0];
	}

	fv[0] = fromcl; tv[0] = tosv; cv[0] = 0;
	ccx[0] = (ccx2SV != 0 && CCXactive(ccx2SV)) ? ccx2SV : 0;
	fv[1] = fromsv; tv[1] = tocl; cv[1] = 0;
	ccx[1] = (ccx2CL != 0 && CCXactive(ccx2CL)) ? ccx2CL : 0;

	for(;;){
		if( (rdy = PollIns(0,2,fv,rv)) <= 0 ){
			serrno = errno;
			nint++;
 sv1log("--relay2 poll()=%d errno=%d SIG=%d PIPE=%d nint=%d\n",
				rdy,errno,yy_gotSIG,yy_nsigPIPE,nint);
			if( serrno == EINTR && nint < 4 ){
				continue;
			}
			break;
		}
		for( fi = 0; fi < 2; fi++ ){
			if( rv[fi] ){
				rcc = read(fv[fi],buf,sizeof(buf));
				serrno = errno;
				if( rcc <= 0 ){
 sv1log("--relay2 rcc=%d/%d errno=%d rdy=%d(%d %d) alv(%d %d)\n",
	rcc,isizeof(buf),errno,rdy,rv[0],rv[1],IsAlive(fv[0]),IsAlive(fv[1]));
					goto EXIT;
				}
				if( ccx[fi] ){
					IStr(xuf,sizeof(buf)*4+1024);
					int xcc;

					xcc = CCXexec(ccx[fi],buf,rcc,
						AVStr(xuf),sizeof(xuf));
					wcc = write(tv[fi],xuf,xcc);
				}else{
					wcc = write(tv[fi],buf,rcc);
				}
				serrno = errno;
				if( wcc < rcc ){
 sv1log("--relay2 wcc=%d/%d errno=%d\n",wcc,rcc,errno);
					goto EXIT;
				}
				cv[fi] += rcc;
			}
		}
	}
EXIT:
	cv[0] += drain1(10,fv[0],tv[0],AVStr(buf),sizeof(buf));
	cv[1] += drain1(10,fv[1],tv[1],AVStr(buf),sizeof(buf));
	if( tid ){
		int terr;
		close(sp[0]);
		close(sp[1]);
		terr = thread_wait(tid,100);
		sv1log("--relay2C [%d][%d] [%X]err=%d th=%d/%d\n",
			sp[0],sp[1],PRTID(tid),terr,actthreads(),numthreads());
	}
 sv1log("--relay2 done [%d -> %d]%u [%d -> %d]%u e%d\n",
	fromcl,tosv,cv[0],fromsv,tocl,cv[1],serrno);
	return 0;
}
int relay2(int fromcl,int tocl,int fromsv,int tosv){
	return relay2C(NULL,NULL,fromcl,tocl,fromsv,tosv);
}

/*
 * SERVER=X://localhost
 * SERVER=X://X0.=2EX11-unix.tmp.af-local
 * HOSTS="{myserver,localhost,X0.=2EX11-unix.tmp.af-local}"
 */
static int connectXlocal(PCStr(wh),int besilent);
static int relayXlocal(Connection *Conn){
	int xsock;

	xsock = connectXlocal("relayXlocal",0);
	if( 0 <= xsock ){
		relay2(FromC,ToC,xsock,xsock);
		close(xsock);
	}
	return 0;
}

/*---- Y11 / yyMUX -------------------------------------- Dec. 2009 ----*/

/* Yxx/y.z: External protocol identifiers */
#define myYYVER   "YYMUX/0.13"
#define myYY11VER "YY11/0.11"
#define myYYSHVER "YYSH/0.4"
static const char *ZCredhy = "Z-Credhy/0.1";

/* YXXXXXX: External method names */
#define YY_Y11	"Y11"	    /* relaying X only by y11://server/xcommand */
#define YY_CON	"YYCONNECT" /* the method to initiate a YY connection */
#define YY_ACC	"YYACCEPT"  /* the method to initiate a YY accept */
#define YY_CQ	"YYHELLO"   /* the method to request YY coupling */
#define YY_SH	"YYSH"      /* the method to request YY-shell */

/*
 * 1)   yMUX multiplexing protocol
 * 2)  yyMUX negotiation protocol over HTTP
 * 3) yyyMUX resumption protocol
 *
 *   YY-Request:
 *         Y11       y11://server/xterm HTTP/1.1
 *         YYCONNECT telnet://server:23 HTTP/1.1
 *         YYACCEPT  ftp-data://server:* HTTP/1.1
 *
 *   YY-Response:
 *         HTTP/1.1 100 Continue
 *         HTTP/1.1 101 Upgraded (YYMUX, SSL)
 *         HTTP/1.1 200 OK
 *         HTTP/1.1 401 Auth. required
 *         HTTP/1.1 403 Forbidden
 *         HTTP/1.1 410 Gone (cannot resume)
 *         HTTP/1.1 504 Gateway Timeout
 *
 *   YY-Headers:
 *     COMMON TO Y11 and YYCONNECT request/response
 *       Version matching
 *         Y-Version: Y11R6 // mandatory
 *       Initiationg and resumption
 *         Y-Connection: initial; key=12345678; hold=86400; port=0
 *         Y-Connection: resume;  key=12345678; hold=86400; port=54321
 *       Salvaging
 *         Y-Connection: salvage; key=12345678; hold=0; port=54321
 *         Y-Connection: finish;  key=12345678; hold=0; port=54321
 *         Y-Connection: exiting; key=12345678; hold=0; port=54321
 *         Y-Connection: cleared; key=12345678; hold=0; port=54321
 *       Accepting
 *         Y-Accepting: host=xx.xx.xx.xx; port=54321
 *
 *     Y11 request SPECIFIC
 *         X-Arg: -bg
 *         X-Arg: red
 *         X-Env: name=value
 */

static struct {
	MStr(io_stat,128);
} ioStat;
#define IoStat ioStat.io_stat

static int yy_timeSIG;
static int yy_tidPIPE;
static int yy_showStats;

static void sigINT(int sig){
	int now = time(0);

	yy_showStats++;
	if( sig == SIGTERM ){
		yy_gotSIG += 2;
	}else{
		if( 30 < now - yy_timeSIG ){
			yy_gotSIG = 1;
		}else{
			yy_gotSIG++;
		}
	}
	yy_timeSIG = now;
}
static void SigPIPE(int sig){
	yy_nsigPIPE++;
	yy_tidPIPE = getthreadid();
	if( 100 < yy_nsigPIPE ){
		sv1log("####Y11 FATAL SIGPIPE*%d\n",yy_nsigPIPE);
		Finish(-1);
	}
}

int ShutdownSocket(int fd);
int ShutdownSocketRDWR(int fd);
unsigned int trand1(unsigned int max);
/*
 * file descriptor or handle
 */
typedef unsigned int UInt;
typedef unsigned short UShort;

enum _BufFlags {
	BUF_IS   = 0x0001,
	BUF_FREE = 0x0002,
	BUF_BUSY = 0x0004,
} BufFlags;
typedef struct _BufDesc {
    const char *buf_what;
	int	buf_stat;
	int	buf_slot;
	int	buf_size;
	int	buf_nreu;
	int	buf_disp; /* starting point of data in buf_data */
	int	buf_tail; /* end of data in buf_data */
	char   *buf_data;
} BufDesc;
static CriticalSec bufsCSC;
static BufDesc *bufsV;
static int bufsN;
static void BUF_init(){
	if( bufsV == 0 ){
		setupCSC("yyBUF",bufsCSC,sizeof(bufsCSC));
		bufsN = 256;
		bufsV = (BufDesc*)calloc(bufsN,sizeof(BufDesc));
	}
}
static BufDesc *BUF_get(PCStr(what),int size){
	int bi;
	int ei = -1;
	BufDesc *buf = 0;
	int isgot = 0;
	int ostat = 0;

	BUF_init();
	enterCSC(bufsCSC);
	for( bi = 0; bi < bufsN; bi++ ){ 
		buf = &bufsV[bi];
		ostat = buf->buf_stat;
		if( buf->buf_stat == (BUF_IS|BUF_FREE) ){
			if( buf->buf_size == size ){
				buf->buf_stat = BUF_IS|BUF_BUSY;
				buf->buf_slot = bi;
				isgot = 1;
				buf->buf_nreu++;
sv1log("--BUF-R [%d] %X %X/%d stat=%X:%X reu=%d %s\n",
bi,buf,buf->buf_data,size,ostat,buf->buf_stat,buf->buf_nreu,what);
				break;
			}
		}
		if( ei < 0 ){
			if( buf->buf_stat == 0 ){
				ei = bi;
			}
		}
	}
	if( isgot == 0 ){
		if( 0 <= ei ){
			buf = &bufsV[ei];
			buf->buf_stat = BUF_IS|BUF_BUSY;
			buf->buf_size = size;
			buf->buf_slot = ei;
			buf->buf_data = (char*)malloc(size);
sv1log("--BUF-N [%d] %X %X/%d %s\n",ei,buf,buf->buf_data,size,what);
		}else{
			sv1log("----FATAL BUF table full\n");
		}
	}
	leaveCSC(bufsCSC);
	if( buf ){
		buf->buf_disp = 0;
		buf->buf_tail = 0;
	}
	return buf;
}
static void putb(BufDesc *buf){
	buf->buf_stat = BUF_IS|BUF_FREE;
}
static int BUF_free(PCStr(what),void *data,int size){
	int bi;
	BufDesc *buf;
	int freed = 0;

	BUF_init();
	enterCSC(bufsCSC);
	for( bi = 0; bi < bufsN; bi++ ){ 
		buf = &bufsV[bi];
		if( buf->buf_data == data ){
	sv1log("----BUF put [%2d]*%d %X (%X / %X) %s\n",
		bi,buf->buf_nreu,p2i(buf->buf_data),buf->buf_size,size,what);
			buf->buf_stat = BUF_IS|BUF_FREE;
			freed = 1;
			break;
		}
	}
	if( freed == 0 ){
		sv1log("----FATAL BUF free not found: %X (%X) %s\n",
			p2i(data),size,what);
	}
	leaveCSC(bufsCSC);
	return freed;
}

enum _FdFlags {
	FD_DONTCLOSE = 0x0001,
	FD_CHOWN     = 0x0002,
	FD_IGNOWNER  = 0x0004,
} FdFlags;
typedef struct _FileDesc {
	UShort	fd_fd;
	UShort	fd_stat;
	int	fd_flags;	/* FdFlags */
	int	fd_tid;
    const char *fd_what;
	int	fd_mxId;
} FileDesc;

static CriticalSec filesCSC;
static FileDesc *filesV;
static int filesN;
static void FD_init(){
	if( filesV == 0 ){
		setupCSC("yyFD",filesCSC,sizeof(filesCSC));
		filesN = 256;
		filesV = (FileDesc*)calloc(filesN,sizeof(FileDesc));
	}
}
static FileDesc *findFd(int fd,int create){
	FileDesc *Fd;
	FileDesc *rFd = 0;
	int fi;

	FD_init();
	for( fi = 0; fi < filesN; fi++ ){
		Fd = &filesV[fi];
		if( Fd->fd_what == 0 ){
			if( create ){
				rFd = Fd;
				break;
			}
		}else{
			if( Fd->fd_fd == fd ){
				rFd = Fd;
				break;
			}
		}
	}
	return rFd;
}
int YYgetpairName(Connection *Conn,int fd,PVStr(host),PVStr(peer)){
	FileDesc *Fd;
	if( Conn && ConnType == 'y' ){
		if( fd == ToS ){
			fd = ServerSockX;
		}else
		if( Fd = findFd(fd,0) ){
			/* FTP-data connection ... (PASV,PORT)
			 * it was conveyed in sendCONN()'s payload
			 */
			if( Fd->fd_stat ){
				sv1log("--yy FD[%d](%X %X %X) %s\n",
					fd,Fd->fd_stat,Fd->fd_flags,
					PRTID(Fd->fd_tid),Fd->fd_what);
			}
		}
	}
	getpairName(fd,BVStr(host),BVStr(peer));
	return 0;
}
static void FD_dump(PCStr(wh)){
	FileDesc *Fd;
	int fi;
	int filled = 0;
	int act = 0;

	for( fi = 0; fi < filesN; fi++ ){
		Fd = &filesV[fi];
		if( Fd->fd_stat ){
			act++;
		}
		if( Fd->fd_what ){
			sv1log("FD (%3d) %s[%2d]%X [%X]%s\n",
				fi,wh,
				Fd->fd_fd,Fd->fd_stat,
				PRTID(Fd->fd_tid),Fd->fd_what);
			filled++;
		}
	}
	sv1log("FD %s %d/%d/%d\n",wh,act,filled,filesN);
}
int FD_newX(int mxId,int fd,PCStr(what),int flags){
	FileDesc *Fd;
	int rcode = -1;

	FD_init();
	enterCSC(filesCSC);
	Fd = findFd(fd,0);
	if( flags & FD_CHOWN ){
		if( Fd ){
			Fd->fd_tid = getthreadid();
			Fd->fd_flags = flags & ~FD_CHOWN;
			rcode = 0;
		}else{
			sv1log("--FD FATAL CHOWN %s NG[%d]\n",what,fd);
		}
		goto EXIT;
	}
	if( Fd ){
		if( Fd->fd_stat != 0 ){
			sv1log("--FD FATAL-DUP [%d]%X ##DUP?NEW? %X [%X]%s <= [%X]%s\n",
				fd,Fd->fd_stat,p2i(Fd),
				PRTID(Fd->fd_tid),Fd->fd_what,
				TID,what);
			FD_dump("FATAL-DUP");
			Fd = 0;
		}
	}else{
		Fd = findFd(fd,1);
		if( Fd == 0 ){
			FD_dump("FATAL-FULL");
		}
	}
	if( Fd ){
		Fd->fd_mxId = mxId;
		Fd->fd_fd = fd;
		Fd->fd_stat = 1;
		Fd->fd_flags = flags;
		Fd->fd_tid = getthreadid();
		Fd->fd_what = what;
		sv1log("--Y%d FD %X [%d] NEW %s\n",mxId,p2i(Fd),fd,what);
		rcode = 0;
	}
EXIT:
	leaveCSC(filesCSC);
	return rcode;
}
static Connection *getConnPtr(int mxId);
static Connection *Conn0;

/* 
 * avoid SEGV by accessing to or applying CTX_closed to a dangling Conn
 * pointing to a garbage on stack or heap
 */
static int isMyConn(FileDesc *Fd,Connection *Conn,int fd,PCStr(where),FL_PAR){
	sv1log("--Y%d FD close[%d] Fd=%X Conn=(%X %X %X) %s <= %s %s:%d\n",
		Fd->fd_mxId,Fd->fd_fd,Fd,
		getConnPtr(Fd->fd_mxId),Conn,Conn0,
		Fd->fd_what,where,FL_BAR);

	if( getConnPtr(Fd->fd_mxId) != Conn ){
		return 0;
	}
	if( Conn == Conn0 ){
		return 0;
	}
	sv1log("--Y%d FD close[%d]%s <= %s:%d (%s)\n",
		Fd->fd_mxId,Fd->fd_fd,Fd->fd_what,FL_BAR,where);
	return 1;
}

int FD_closeY(FL_PAR,Connection *Conn,int fd,PCStr(where),int force){
	FileDesc *Fd;
	int rcode = -2;
	int tid;

	FD_init();
	enterCSC(filesCSC);
	if( Fd = findFd(fd,0) ){
		tid = getthreadid();
		if( Fd->fd_tid != tid && (Fd->fd_flags & FD_IGNOWNER) == 0 ){
			sv1log("--FD [%d] FATAL not mine [%X]%s [%X]%s <=%s:%d ---- ----\n",
				fd,PRTID(Fd->fd_tid),Fd->fd_what,
				PRTID(tid),where,FL_BAR);
			rcode = -99;
		}else
		if( Fd->fd_stat == 0 ){
			sv1log("--FD [%d] not active (%s) <= %s #######\n",
				fd,Fd->fd_what,where);
			rcode = 0;
		}else
		if( (Fd->fd_flags & FD_DONTCLOSE) && force == 0 ){
			sv1log("--FD [%d]%X DONTCLOSE (%s) <= %s #######\n",
				fd,Fd->fd_stat,Fd->fd_what,where);
			if( (Fd->fd_stat & 0x8) == 0 ){
				Fd->fd_stat |= 0x8;
				dupclosed(fd);
			}
			rcode = -98;
		}else{
		    if( isMyConn(Fd,Conn,fd,where,FL_BAR) ){
			sv1log("--Y%d FD close[%d]%s Cl[%d %d]Sv[%d %d] <= %s:%d\n",
				Fd->fd_mxId,Fd->fd_fd,Fd->fd_what,
				FromC,ToC,ServerSock,ToS,FL_BAR);
			CTX_closedX(FL_BAR,where,Conn,Fd->fd_fd,-1,1);
		    }
			Fd->fd_stat = 0;
			close(Fd->fd_fd);
			rcode = 0;
		}
	}else{
		sv1log("--FD [%d] ### CLS??? NON %s\n",fd,where);
		rcode = -1;
	}
	leaveCSC(filesCSC);
	return rcode;
}
int FD_showall(PCStr(where)){
	int fi;
	FileDesc *Fd;

	FD_init();
	for( fi = 0; fi < filesN; fi++ ){
		Fd = &filesV[fi];
		if( Fd->fd_what ){
			sv1log("--FD %s %X %X [%d]%d %s\n",where,
				p2i(Fd),PRTID(Fd->fd_tid),
				Fd->fd_fd,Fd->fd_stat,Fd->fd_what);
		}
	}
	return 0;
}

int bgexecX(PCStr(mode),PCStr(path),char *av[],char *ev[],int *ph);
int bgwait(int pid,int ph,double timeout);

#ifdef _MSC_VER
#if isWindowsCE()
static char **environ = {0};
#endif
#else
#define _cwait(stat,ph,act) 0
extern char **environ;
#endif

static const char *yy_origDISP;
static int yy_origDISP_isset;
const char *origDISPLAY(){
	if( yy_origDISP_isset == 0 ){
		yy_origDISP_isset = 1;
		yy_origDISP = getenv("DISPLAY");
	}
	return yy_origDISP;
}
static int connectXlocal(PCStr(wh),int besilent){
	int xport = 6000;
	const char *xhost;
	int xsock = -2;

	if( xhost = origDISPLAY() ){
		sv1log("--X DISPLAY=%s\n",xhost);
		if( isFullpath(xhost) ){
			xsock = client_open_un("X11",xhost,10);
			sv1log("--X DISPLAY=%s [%d]\n",xhost,xsock);
		}else
		if( strneq(xhost,"127.0.0.1:",10) ){
			IStr(host,128);
			int port = 6000;
			int ndisp = -1;

			/* maybe chained yysh */
			Xsscanf(xhost,"%[^:]:%d",AVStr(host),&ndisp);
			if( 0 <= ndisp ){
				sv1log("--yy DISPLAY=%s\n",xhost);
				port = 6000+ndisp;
				xsock = client_open("X11","X11",host,port);
			}
		}
	}
	if( xsock < 0 )
	if( isWindows() ){
		xsock = -1;
	}else{
		xhost = "X0.=2EX11-unix.tmp.af-local";
		xsock = connectServer("-connectXlocal","y11",xhost,xport);
	}
	if( xsock < 0 ){
		xhost = "127.0.0.1";
		xsock = connectServer("-connectXlocal","y11",xhost,xport);
	}
	if( xsock < 0 && !besilent ){
		fprintf(stderr,"####Y11 (%s) cannot open lcoal X server\r\n",wh);
	}
	return xsock;
}
static int createXunix(PVStr(xchost),PVStr(dispenv)){
	int xcsock = -99;
	int dx;
	IStr(base,256);
	IStr(path,256);

	strcpy(base,"/tmp/.X11-unix");
	if( fileIsdir(base) )
	for( dx = 10; dx < 20; dx++ ){
		sprintf(path,"%s/X%d",base,dx);
		if( File_is(path)
		 && File_uid(path) == getuid()
		 && 30 < time(0)-File_mtime(path)
		){
			if( unlink(path) != 0 ){
				continue;
			}
		}
		xcsock = server_open("Y11display",AVStr(path),0,1);
		if( 0 <= xcsock ){
			sprintf(dispenv,"DISPLAY=:%d",dx);
			sv1log("----%s\n",dispenv);
			return xcsock;
		}else{
			sv1log("----%s e%d\n",path,errno);
		}
	}

	sv1log("----FAILED getting X DISPLAY %s\n",path);
	return -1;
}
static int createXdisp(PVStr(xchost),int *yportp,PVStr(dispenv)){
	int dx;
	int xcsock;
	int yport;

	if( yportp == 0 ){
		xcsock = createXunix(BVStr(xchost),BVStr(dispenv));
		return xcsock;
	}
	yport = *yportp;
	//strcpy(xchost,"127.0.0.1");
	for( dx = 0; dx < 10; dx++ ){
		xcsock = server_open("Y11display",BVStr(xchost),yport,1);
		if( 0 <= xcsock ){
			break;
		}
		fprintf(stderr,"----[%d] %s:%d\n",xcsock,xchost,yport);
		yport++;
	}
	*yportp = yport;
	sprintf(dispenv,"DISPLAY=%s:%d.0",xchost,yport-6000);
	return xcsock;
}
static int recvs(FILE *fp,char *buf,int len){
	int rcc = 0;
	int rc1;
	while( rcc < len ){
		rc1 = fread(buf+rcc,1,len-rcc,fp);
		if( rc1 <= 0 ){
			break;
		}
		rcc += rc1;
	}
	return rcc;
}
static int flushBuffered(FILE *fs,int sock){
	int ncc;
	int ch;
	FILE *tc;

	tc = fdopen(sock,"w");
	for( ncc = 0; 0 < ready_cc(fs); ncc++ ){
		ch = getc(fs);
		if( ch == EOF ){
			break;
		}
		putc(ch,tc);
	}
	fcloseFILE(tc);
	if( ncc ){
		sv1log("--Y11 flushed %d\n",ncc);
	}
	return ncc;
}

#define LINESIZE 0x4000
#ifdef daVARGS
#undef VARGS
#define VARGS daVARGS
#endif

static void FMT_lfprintf(PCStr(wh),FILE *fp,PCStr(fmt),...){
	IStr(msg,1024);
	VARGS(16,fmt);

	sprintf(msg,fmt,VA16);
	if( fp ){
		fprintf(fp,"%s\r\n",msg);
	}
	if( yy_gotSIG || yy_nsigPIPE )
		sv1log("--YY S%d P%d %s: %s\n",yy_gotSIG,yy_nsigPIPE,wh,msg);
	else	sv1log("--YY %s: %s\n",wh,msg);
}

/*
 * Y11 -- X client invitation protocol over the YMUX protocol
 */

int resetPATHs();
int TimeoutWait(double To);
#define TimeoutY11 ((UInt)(TIMEOUT_Y11*1000))

double TIMEOUT_Y11 = 30;
static int yy_doMUX = 1;
static const char *AllowedXcom = "X11,firefox";

static const char *pushenv(int san,const char *sav[],PVStr(sab),PCStr(env)){
	IStr(name,128);
	const char *nv,*oe,*ne;

	nv = wordScanY(env,name,"^=");
	if( *nv == '=' ){
		nv++;
	}
	if( oe = getenv(name) ){
		if( streq(oe,nv) ){
			return oe;
		}else{
		}
	}
	ne = stralloc(env);
	putenv(ne);
	sv1log("----pushenv(%s) %X\n",env,p2i(ne));
	return ne;
}

#if isWindows()
#define _PATHSEP() ";"
#else
#define _PATHSEP() ":"
#endif
static int uniqp(PCStr(path1),PCStr(delim),PVStr(xpath)){
	if( !isinListX(xpath,path1,delim) ){
		if( *xpath ){
			strcat(xpath,delim);
		}
		strcat(xpath,path1);
	}
	return 0;
}
static int uniqPATH1(PVStr(path),PCStr(delim)){
	IStr(xpath,8*1024);
	scan_List(path,*delim,STR_OVWR,scanListCall uniqp,delim,AVStr(xpath));
	strcpy(path,xpath);
	return 0;
}
static int uniqPATH(PVStr(path)){
	if( isWindows() ){
		uniqPATH1(BVStr(path),_PATHSEP());
	}else{
		uniqPATH1(BVStr(path),_PATHSEP());
	}
	return 0;
}

static const char *yy_xpath[] = {
	"/usr/X11R7/bin",
	"/usr/X11R7/lib",
	"/usr/X11R6/bin",
	"/usr/X11R6/lib",
	"/usr/bin/X11",
	"C:\\cygwin\\bin",
	"C:\\cygwin\\usr\\bin",
	"C:\\cygwin\\usr\\X11R6\\bin",
	"C:\\cygwin\\usr\\X11R6\\lib",
	0
};
static void addX11PATH(int san,const char *sav[],PVStr(sab)){
	IStr(penv,8*1024);
	IStr(uenv,8*1024);
	int pi;
	refQStr(pp,penv);
	const char *ep;
	const char *xp;
	const char *dp = isWindows() ? ";":":";
	const char *name = "PATH";
	int nadd = 0;

	ep = getenv(name);
	if( ep == 0 ){
		name = "Path";
		ep = getenv(name);
	}
	sprintf(penv,"%s=",name);
	pp = penv + strlen(penv);
	if( ep ){
		sprintf(pp,"%s",ep);
		pp += strlen(pp);
	}
	for( pi = 0; xp = yy_xpath[pi]; pi++ ){
		if( !isinListX(penv,xp,_PATHSEP()) ){
			if( fileIsdir(xp) ){
				sprintf(pp,"%s%s",dp,xp);
				pp += strlen(pp);
				nadd++;
			}
		}
	}
	if( nadd ){
		Verbose("----%s\n",penv);
		pushenv(san,sav,BVStr(sab),penv);
	}else{
		strcpy(uenv,penv);
		uniqPATH(AVStr(uenv));
		if( !streq(uenv,penv) ){
			pushenv(san,sav,BVStr(sab),uenv);
		}
	}
	resetPATHs(); /* clear conf.c:initPATH() */

	/* might need utf-8 or Shift_JIS conversion */
	sprintf(penv,"YYEXEC=%s",EXEC_PATH);
	strsubst(AVStr(penv),"\\","/");
	pushenv(san,sav,BVStr(sab),penv);
	sprintf(penv,"YYSH=%s -Fyysh",EXEC_PATH);
	strsubst(AVStr(penv),"\\","/");
	pushenv(san,sav,BVStr(sab),penv);
	sprintf(penv,"YYROOT=%s",DELEGATE_DGROOT);
	strsubst(AVStr(penv),"\\","/");
	pushenv(san,sav,BVStr(sab),penv);

	/* to be used as "eval $YYALSS" */
	sprintf(penv,"YYALIASES=alias yysh \"$YYEXEC\" -Fyysh; alias yy11 \"$YYEXEC\" -Fyy11");
	pushenv(san,sav,BVStr(sab),penv);
}

/*
 * YY entity and the context negotiation over HTTP
 */
enum _EntType {
	ET_CLNT = 0x01,	/* working as a client */
	ET_SERV = 0x02,	/* server */
	ET_PROX = 0x04,	/* proxy */
	ET_REFL = 0x08,	/* reflector */
	ET_NOX  = 0x10  /* non-implicit X server */
} EntType;

#define RSMSIZE	(1024*1024)

/* internal status flags of YYMUX connection status */
enum _connectionStatus {
	CST_INITIAL = 0x01, /* "Y-Connection: initial" initial connection */
	CST_RESUME  = 0x02, /* "Y-Connection: resume"  resumption */
	CST_SALVAGE = 0x04, /* "Y-Connection: salvage" salvaging */
	CST_FINISH  = 0x08, /* "Y-Connection: finish"  req. to finish */
	CST_EXITING = 0x10, /* "Y-Connection: exiting" req. to finish */
	CST_CLEARED = 0x20, /* "Y-Connection: cleared" ok resp. to SALVAGE */
} connectionStatus;

/* salvage: External YYMUX connection status names */
#define CS_INITIAL "initial"
#define CS_RESUME  "resume"
#define CS_SALVAGE "salvage"
#define CS_FINISH  "finish"
#define CS_EXITING "exiting"
#define CS_CLEARED "cleared"

typedef struct _Rsm {
	int	rsm_state;/* connectionStatus {initial,resume,salvage,clean} */
	int	rsm_port; /* the port for resume */
	int	rsm_hold; /* (sec.) max waiting for resumption with the peer */
	int	rsm_holdSet:1;
	int	rsm_yyguid; /* server's YYGUID */
	int	rsm_key;  /* keyword for the resume port */
	int	rsm_count;/* total count of resumption (optional) */
} Rsm;

typedef struct _UserEnv {
	MStr(	ue_yyuid,128);
	MStr(	ue_home,128);
	MStr(	ue_path,1024);
	MStr(	ue_ld_path,128);
	MStr(	ue_shell,128);
	MStr(	ue_prompt,128);
	MStr(	ue_histfile,128);
} UserEnv;

#define YH_DSTPORT	"Y-Port-Dst"
#define YH_SRCPORT	"Y-Port-Src"
#define YH_ACCPORT	"Y-Port-Acc"
typedef struct _SockInfo {
	MStr(	pp_dsthost,32);
	int	pp_dstport;
	MStr(	pp_srchost,32);
	int	pp_srcport;
	MStr(	pp_acchost,32);
	int	pp_accport;
	int	pp_accsock;
} SockInfo;

typedef struct _Port1 {
	MStr(	p1_proto,32);
	MStr(	p1_host,128);
	int	p1_port;
	int	p1_sock;
	int	p1_flags;
} Port1;
enum _P1Flags {
	P1_UDP      = 0x01,
	P1_TCP      = 0x02,
	P1_SSL      = 0x04,
} P1Flags;
enum _PmFlags {
	PM_FORWARD  = 0x01,
	PM_BACKWARD = 0x02,
	PM_ACTIVE   = 0x04,
} PmFlags;
typedef struct _PortMap1 {
	int	pm_flags;
	Port1	pm_local;
	Port1	pm_remote;
} PortMap1;
typedef struct _PortMaps {
	PortMap1 pm_maps[8];
} PortMaps;

typedef struct _ZStat {
	int	zs_litotal; /* local input (sent to remote) */
	int	zs_zototal; /* compressed out sent to remote */
	int	zs_zitotal; /* compressed input received from remote */
	int	zs_lototal; /* local output (uncompressed) */
} ZStat;

typedef union _MuxStat {
   unsigned int	ms_status;
   struct {
   unsigned int	ms_SWEEP:1,  /* to be swept by finishServYY() */
		ms_DHKRECV:1,/* Credhy-Key has been recv. & set */
		ms_DHKSENT:1,/* Credhy-Key has been sent */
		ms_ISMAIN:1, /* main YYMUX */
		ms_ACTIVATED:1, /* activated to be MUXrealy */
		ms_SELFEND:1,/* cleanup by self */
		ms_ZOMBI:1,  /* zombi */
		ms_ENDING:1, /* ending */
		ms_FREEING:1,/* freeing */
		ms_dummy:1;
   } bits;
} MuxStat;
#define MxStats		Mc->mc_status
#define MxStatALL	MxStats.ms_status
#define MxStatSWEEP	MxStats.bits.ms_SWEEP
#define MxStatDHKSENT	MxStats.bits.ms_DHKSENT
#define MxStatDHKRECV	MxStats.bits.ms_DHKRECV
#define MxStatACTIVATED	MxStats.bits.ms_ACTIVATED
#define MxStatISMAIN	MxStats.bits.ms_ISMAIN
#define MxStatSELFEND	MxStats.bits.ms_SELFEND
#define MxStatZOMBI	MxStats.bits.ms_ZOMBI
#define MxStatENDING	MxStats.bits.ms_ENDING
#define MxStatFREEING	MxStats.bits.ms_FREEING

typedef struct _RSACtx RSACtx;
RSACtx *_RSA_new();
int _RSA_avail(RSACtx *Rc);
int _RSA_newkey(RSACtx *Rc);
int _RSA_chpass(RSACtx *Rc);
int _RSA_free(RSACtx *Rc);
int _RSA_encrypt(RSACtx *Rc,PCStr(data),int dlen,PVStr(edata),int esiz,int hex);
int _RSA_decrypt(RSACtx *Rc,PCStr(edata),int elen,PVStr(data),int dsiz,int hex);

typedef struct _MuxCtx {
	int	mc_id;      /* identifier of MuxCtx instantiation */
	int	mc_ygid;    /* groupd ID */
	int	mc_ytgid;   /* owner thread */
struct _MuxCtx *mc_parent;  /* the Mux wrapping this Mux */
	int	mc_yyguid;  /* globally uniq ID of this server */
  struct _Cony *mc_Cv;
	int	mc_Cn;
	double	mc_start;   /* the time of the start of the session */
	double	mc_muxstart;/* the time of YYMUX start */
	double	mc_muxdone; /* the time of YYMUX finish */
	int	mc_tidyyx;  /* yyMux thread */
	int	mc_tidpwt;  /* ProcWait thread */
	int	mc_etype;   /* (EntType ET_XXXX) */
	int	mc_flags;   /* MxFlags */
	MuxStat	mc_status;  /* MxStats */
	int	mc_sadend;  /* sadness */
	int	mc_nbsb;    /* SO_SNDBUF size for non-blocking yysend() */
	int	mc_listen;  /* listen() */

	int	mc_pid;     /* owner process of the primary connection */
	int	mc_phandle; /* the handle of mc_pid on Windows */
	int	mc_palive;  /* the primary process alive */
	double	mc_pdone;   /* the time of process termination */
	int	mc_cantwait;/* LinuxThreads cannot wait in a child thread */

	int	mc_psins;   /* stdin from remote to local X command */
	int	mc_psout;   /* stdout from the process (pipe/socket input) */
	int	mc_pserr;   /* stderr from the process (pipe/socket input) */
	int	mc_console; /* socket to/from tty (client-side stdio) */
	int	mc_ttystat[32]; /* "stty raw/-raw" for yysh */
	MStr(	mc_forkpty,128);
	MStr(	mc_sttyraw,128);

	int	mc_xsid;    /* connection-ID initiated in this entity */
	int	mc_debug;
	int	mc_coupler;
	int	mc_Shutting;/* in shutdown procedure */
	double	mc_shutStart;
	int	mc_SHUTsent;
    const char *mc_doupdate;/* update Fdv[] */
	int	mc_doupTerse;
	int	mc_holdonNX;/* alive even without active connections */
	int	mc_ClntHOLDONNX;/* HOLDONNX from client (forwarded) */
	int	mc_timeoutNX; /* timeout of NX by HOLDONNX */

	PortMaps mc_portmap;
	PortMap1 mc_pmap_dns;
	PortMap1 mc_pmap_ftp;
	PortMap1 mc_pmap_pop;
	PortMap1 mc_pmap_smtp;
	PortMap1 mc_pmap_rsync;
	PortMap1 mc_pmap_vnc;
	PortMap1 mc_pmap_http;
	PortMap1 mc_pmap_socks;

	MStr(	mc_clntAddr,64);
	MStr(	mc_clifAddr,64);
	int	mc_withAuth;   /* with AUTHORIZER as a server */
	int	mc_authFlags;  /* auth. type (AUTHORIZATION) */
	int	mc_authOK;     /* auth. OK */
	int	mc_autherr;    /* auth. error */
	MStr(	mc_autho,512); /* Authorization */
	MStr(	mc_myauth,128);
	Credhy	mc_Credhy[2]; /* Credhy Encryption */
	MStr(	mc_CredhyKey,256); /* Credhy Encryption */
	int	mc_CredhyKeyLen;
	int	mc_CredhyKeyCRCs; /* key sent to peer */
	int	mc_CredhyKeyCRCr; /* key recv. from peer */
struct _RSACtx *mc_rsa;
	ZStat	mc_Z1;
	struct {
		int sent;
		int recv;
	} mc_IO;

	UserEnv mc_ue;
	MStr(	mc_strbuf,2*1024);
	const char *mc_strtail;
	const char *mc_env[32];/* pushed environment */

    Connection *mc_Conn;/* DeleGate Connection environment */
	int	mc_SSLerr;
	int	mc_SSLok;
	MStr(	mc_serv,MaxHostNameLen);
	int	mc_servport;/* the port for 1st connection */
	MStr(	mc_servstat,128);
	int	mc_servcode;
	MStr(	mc_upgrade,128); /* Upgrade: response */
	MStr(	mc_servyver,32);
	MStr(	mc_clntyver,32);
    const char *mc_forbidden;
	MStr(	mc_dstproto,32);
	MStr(	mc_dsthost,MaxHostNameLen);
	int	mc_dstport;
	MStr(	mc_dsturl,MaxHostNameLen);
	MStr(	mc_servdisp,128);

	MStr(	mc_yyproto,32); /* YYMUX server to be resumed */
	MStr(	mc_yyhost,MaxHostNameLen); /* YYMUX server to be resumed */
	int	mc_yyport;  /* YYMUX server to be resumed */

	int	mc_pingitvl;/* starting after idle seconds */
	int	mc_rsmstart;/* starting after idle seconds */
	int	mc_maxPending; /* max. pending to MUX */

	Rsm	mc_Rsmv[8]; /* Rsmv[0] for initial,resume */
	int	mc_rsmsock; /* socket to accept persistent connections */
	int	mc_resuming;/* in resuming (from RSMG and ended with RSMD) */
	double	mc_lastin;  /* time of last YMUX input */
	double	mc_lastout; /* time of last YMUX output */
	int	mc_inRESUME;

	UInt	mc_iseq;    /* input sequence number of the next packet */
	UInt	mc_oseq;    /* output sequence number of the next packet */
	Int64	mc_ilen;    /* total octets received via the YMUX */
	Int64	mc_olen;    /* total octets sent via the YMUX */

	Int64	mc_xmit0;   /* total data transmit to YMUX */
	Int64	mc_xmit;    /* total local input to YMUX */
	Int64	mc_xack;    /* total acknowledged by RCPT */

	int	mc_yacc;    /* YACC */
       SockInfo mc_remote;  /* connection info. at remote side */
       SockInfo mc_local;   /* connection info. at local side */

	Z1Ctx  *mc_Z1dfl;   /* compressor for data to YYMUX */
	Z1Ctx	mc_ZCdfl;   /* the context for Z1dfl */
	Z1Ctx  *mc_Z1ifl;   /* uncompressor for datq from YYMUX */
	Z1Ctx	mc_ZCifl;   /* the context for Z1ifl */

	int	mc_ysock;   /* socket descriptor of outgoing YMUX */
	int	mc_yport;   /* port of the ysock */
	UInt	mc_opk;     /* total messages sent via the YMUX (mc_oseq) */
	Int64	mc_top;     /* == mc_olen */
	MStr(	mc_sent,RSMSIZE); /* total outstanding, used for RSM  */
} MuxCtx;

/* Cony_ID: External id. num. of a YYMUX end point (ver. YYMUX) */
enum _Cony_ID {
	CID_ACC  =  0,	/* #0 for accept port (optional) */
	CID_MUX  =  1,	/* #1 for yyMUX channel */
	CID_PRI  =  2,	/* #2 primary (initial) connection */
	CID_PWT  =  3,	/* #3 process watcher */
	CID_RSM  =  4,	/* #4 port for resumption */
	CID_TMR  =  5,	/* #5 timer */
	CID_SIN  =  6,	/* #6 stdin to local X command */
	CID_SOUT =  7,	/* #7 stdout from local X, or out to Y stdout */
	CID_SERR =  8,	/* #8 stderr from local X, or out to Y stderr */
	CID_CONS =  9,	/* #9 YY client side console */
	CID_YACC = 10,	/* #10 accepting connection for YYY request */
	CID_FTDA = 11,	/* #11 accept FTP data connection */
	CID_FTP  = 12,	/* #12 private ad-hoc FTP server at the peer end */
	CID_HTTP = 13,	/* #13 private ad-hoc HTTP server at the peer end */
	CID_VNC  = 14,	/* #14 VNC */
	CID_SOCKS= 15,	/* #15 SOCKS */
	CID_DNS  = 16,	/* #16 DNS */
	CID_POP  = 17,	/* #17 POP */
	CID_SMTP = 18,	/* #18 SMTP */
	CID_RSYNC= 19,	/* #19 RSYNC */
	CID_SV1  = 32,	/* #32 conn. initiated by the server side */
	CID_CL1  = 33,	/* #33 conn. initiated by the client side */
} Cony_ID;

#define MxYYGUID	Mc->mc_yyguid
#define MxParent	Mc->mc_parent
#define MxParentId	(MxParent?MxParent->mc_id:0)
#define MxId		Mc->mc_id
#define MxCv		Mc->mc_Cv
#define MxCn		Mc->mc_Cn

#define MxStart		Mc->mc_start
#define MxMuxStart	Mc->mc_muxstart
#define MxMuxDone	Mc->mc_muxdone
#define MxTidyyx	Mc->mc_tidyyx
#define MxTidpwt	Mc->mc_tidpwt
#define MxEtype		Mc->mc_etype

#define MxPid		Mc->mc_pid
#define MxPhandle	Mc->mc_phandle
#define MxPalive	Mc->mc_palive
#define MxPdone		Mc->mc_pdone
#define MxCantwait	Mc->mc_cantwait

#define MxPsins		Mc->mc_psins
#define MxPserr		Mc->mc_pserr
#define MxPsout		Mc->mc_psout
#define MxConsole	Mc->mc_console
#define MxTtystat	Mc->mc_ttystat
#define MxSttyRaw	Mc->mc_sttyraw
#define MxForkPty	Mc->mc_forkpty

#define MxXsid		Mc->mc_xsid
#define MxDebug		Mc->mc_debug
#define MxCoupler	Mc->mc_coupler
#define MxShutStart	Mc->mc_shutStart
#define MxShutting	Mc->mc_Shutting
#define MxSHUTsent	Mc->mc_SHUTsent
#define MxDoupdate	Mc->mc_doupdate
#define MxDoupTerse	Mc->mc_doupTerse
#define MxHoldonNX	Mc->mc_holdonNX
#define MxClntHOLDONNX	Mc->mc_ClntHOLDONNX
#define MxTimeoutNX	Mc->mc_timeoutNX

#define MxPmapDns	Mc->mc_pmap_dns
#define MxDnsServ	MxPmapDns.pm_remote.p1_host
#define MxDnsRport	MxPmapDns.pm_remote.p1_port
#define MxDnsSock	MxPmapDns.pm_local.p1_sock
#define MxDnsPort	MxPmapDns.pm_local.p1_port
#define MxPmapFtp	Mc->mc_pmap_ftp
#define MxFtpServ	MxPmapFtp.pm_remote.p1_host
#define MxFtpRport	MxPmapFtp.pm_remote.p1_port
#define MxFtpSock	MxPmapFtp.pm_local.p1_sock
#define MxFtpPort	MxPmapFtp.pm_local.p1_port
#define MxPmapPop	Mc->mc_pmap_pop
#define MxPopServ	MxPmapPop.pm_remote.p1_host
#define MxPopRport	MxPmapPop.pm_remote.p1_port
#define MxPopSock	MxPmapPop.pm_local.p1_sock
#define MxPopPort	MxPmapPop.pm_local.p1_port
#define MxPmapSmtp	Mc->mc_pmap_smtp
#define MxSmtpServ	MxPmapSmtp.pm_remote.p1_host
#define MxSmtpRport	MxPmapSmtp.pm_remote.p1_port
#define MxSmtpSock	MxPmapSmtp.pm_local.p1_sock
#define MxSmtpPort	MxPmapSmtp.pm_local.p1_port

#define MxPmapRsync	Mc->mc_pmap_rsync
#define MxRsyncServ	MxPmapRsync.pm_remote.p1_host
#define MxRsyncRport	MxPmapRsync.pm_remote.p1_port
#define MxRsyncSock	MxPmapRsync.pm_local.p1_sock
#define MxRsyncPort	MxPmapRsync.pm_local.p1_port

#define MxPmapHttp	Mc->mc_pmap_http
#define MxHttpServ	MxPmapHttp.pm_remote.p1_host
#define MxHttpRport	MxPmapHttp.pm_remote.p1_port
#define MxHttpSock	MxPmapHttp.pm_local.p1_sock
#define MxHttpPort	MxPmapHttp.pm_local.p1_port
#define MxPmapVnc	Mc->mc_pmap_vnc
#define MxVncServ	MxPmapVnc.pm_remote.p1_host
#define MxVncRport	MxPmapVnc.pm_remote.p1_port
#define MxVncSock	MxPmapVnc.pm_local.p1_sock
#define MxVncPort	MxPmapVnc.pm_local.p1_port
#define MxPmapSocks	Mc->mc_pmap_socks
#define MxSocksServ	MxPmapSocks.pm_remote.p1_host
#define MxSocksRport	MxPmapSocks.pm_remote.p1_port
#define MxSocksSock	MxPmapSocks.pm_local.p1_sock
#define MxSocksPort	MxPmapSocks.pm_local.p1_port

#define MxClntAddr	Mc->mc_clntAddr
#define MxClifAddr	Mc->mc_clifAddr
#define MxWithAuth	Mc->mc_withAuth
#define MxAuthFlags	Mc->mc_authFlags
#define MxAuthOK	Mc->mc_authOK
#define MxAuthErr	Mc->mc_autherr
#define MxAutho		Mc->mc_autho
#define MxMyAuth	Mc->mc_myauth
#define MxCredhy	Mc->mc_Credhy
#define MxCredhyKey	Mc->mc_CredhyKey
#define MxCredhyKeyLen	Mc->mc_CredhyKeyLen
#define MxCredhyKeyCRCs	Mc->mc_CredhyKeyCRCs
#define MxCredhyKeyCRCr	Mc->mc_CredhyKeyCRCr
#define MxRSA		Mc->mc_rsa
#define MxZ1		Mc->mc_Z1
#define MxIO		Mc->mc_IO

#define MxYYUID		Mc->mc_ue.ue_yyuid
#define MxUserHOME	Mc->mc_ue.ue_home
#define MxUserPATH	Mc->mc_ue.ue_path
#define MxUserLD_PATH	Mc->mc_ue.ue_ld_path
#define MxUserSHELL	Mc->mc_ue.ue_shell
#define MxUserPROMPT	Mc->mc_ue.ue_prompt
#define MxUserHISTFILE	Mc->mc_ue.ue_histfile
#define MxEnv		Mc->mc_env
#define MxStrbuf	Mc->mc_strbuf
#define MxStrtail	Mc->mc_strtail

#define MxConn		Mc->mc_Conn
#define MxSSLerr	Mc->mc_SSLerr
#define MxSSLok		Mc->mc_SSLok
#define MxDstProto	Mc->mc_dstproto
#define MxDstHost	Mc->mc_dsthost
#define MxDstPort	Mc->mc_dstport
#define MxDstUrl	Mc->mc_dsturl
#define MxServDISPLAY	Mc->mc_servdisp

#define MxServ		Mc->mc_serv
#define MxServport	Mc->mc_servport
#define MxServstat	Mc->mc_servstat
#define MxServcode	Mc->mc_servcode
#define MxServyver	Mc->mc_servyver
#define MxUpgrade	Mc->mc_upgrade
#define MxClntyver	Mc->mc_clntyver
#define MxForbidden	Mc->mc_forbidden

#define MxPingitvl	Mc->mc_pingitvl
#define MxRsmstart	Mc->mc_rsmstart
#define MxMaxPending	Mc->mc_maxPending

#define MxYYproto	Mc->mc_yyproto
#define MxYYhost	Mc->mc_yyhost
#define MxYYport	Mc->mc_yyport
#define MxRsmv		Mc->mc_Rsmv
#define MxRsmstate	Mc->mc_Rsmv[0].rsm_state
#define MxRsmport	Mc->mc_Rsmv[0].rsm_port
#define MxRsmhold	Mc->mc_Rsmv[0].rsm_hold
#define MxRsmholdSet	Mc->mc_Rsmv[0].rsm_holdSet
#define MxRsmYYGUID	Mc->mc_Rsmv[0].rsm_yyguid
#define MxRsmkey	Mc->mc_Rsmv[0].rsm_key
#define MxRsmcnt	Mc->mc_Rsmv[0].rsm_count

#define MxRsmsock	Mc->mc_rsmsock
#define MxResuming	Mc->mc_resuming
#define MxLastMuxIn	Mc->mc_lastin
#define MxLastMuxOut	Mc->mc_lastout
#define MxInRESUME	Mc->mc_inRESUME

#define MxIseq		Mc->mc_iseq
#define MxIlen		((UInt)Mc->mc_ilen)
#define MxIlen64	Mc->mc_ilen
#define MxOseq		Mc->mc_oseq
#define MxOlen64	Mc->mc_olen
#define MxOlen		((UInt)Mc->mc_olen)

#define MxXmit0		Mc->mc_xmit0
#define MxXmit		Mc->mc_xmit
#define MxXack		Mc->mc_xack

#define MxYAccSock	Mc->mc_yacc
#define MxRSrcHost	Mc->mc_remote.pp_srchost
#define MxRSrcPort	Mc->mc_remote.pp_srcport
#define MxRAccHost	Mc->mc_remote.pp_acchost
#define MxRAccPort	Mc->mc_remote.pp_accport
#define MxRAccSock	Mc->mc_remote.pp_accsock
#define MxLAccSock	Mc->mc_local.pp_accsock

#define MxZ1dfl		Mc->mc_Z1dfl
#define MxZCdfl		Mc->mc_ZCdfl
#define MxZ1ifl		Mc->mc_Z1ifl
#define MxZCifl		Mc->mc_ZCifl

#define MxYsock		Mc->mc_ysock
#define MxYport		Mc->mc_yport
#define MxOpk		Mc->mc_opk
#define MxTop		((UInt)Mc->mc_top)
#define MxTop64		Mc->mc_top
#define MxSent		Mc->mc_sent

enum _AuthFlag {
	MA_BASIC     = 0x00000001, /* Basic */
	MA_BASICr    = 0x00000002, /* asked Basic */
	MA_CBASIC    = 0x00000010, /* Credhy-Basic */
	MA_CBASICr   = 0x00000020, /* asked Credhy-Basic */
	MA_YYKEY     = 0x00000100, /* Verfy peer's YYKEY */
	MA_YYKEYr    = 0x00000200, /* asked to send YYKEY to be verifyed */
} AuthFlag;
/* internal flags to represent YYMUX status */
enum _MuxFlag {
	MX_TERSE     = 0x00000001, /* terse logging */
	MX_VERBOSE   = 0x00000002, /* verbose logging */
	MX_INTERACT  = 0x00000004, /* info to the console with human */
	MX_ISILENT   = 0x00000008, /* silent interact */
	MX_IDEBUG    = 0x00000010, /* verbose interact */
	MX_DUMP      = 0x00000020, /* packet dump */
	MX_VV_TOMUX  = 0x00000040, /* trace uploading to YYMUX */
	MX_LOG_YYSH  = 0x00000080, /* disp. and key logger */

	MX_SHUTIMM   = 0x00000100, /* immediately SHUT when non-X-active */
	MX_HOLDONNX  = 0x00000200, /* hold on no active X connections */ 
	MX_FLOWCTL   = 0x00000400, /* do flowcontrol by RCPT */
	MX_PERSIST   = 0x00000800, /* persistent connection */
	MX_YYACTIVE  = 0x00001000, /* YYMUX is active */
	MX_MUXACC    = 0x00002000, /* -Phost:port/proto/yymux */
	MX_MUXCON    = 0x00004000, /* SERVER=proto://hosrt:port.yymux */
	MX_STLS      = 0x00008000, /* Upgrade to SSL by STARTTLS nego. */

	MX_X11_LOCAL = 0x00010000, /* create X DISPLAY in AF_INET 127.0.0.1 */
	MX_X11_INET  = 0x00020000, /* create X DISPLAY in AF_INET 0.0.0.0 */
	MX_X11_UNIX  = 0x00040000, /* create X DISPLAY in AF_UNIX */
	MX_CREDHY_SV = 0x00080000, /* Z-Credhy: Upgrade the connection */
	MX_CREDHY_CL = 0x00100000, /* Z-Credhy: Credhy to data from client */
	MX_DEFLATE1  = 0x00200000, /* Z-Credhy: deflate requested by client */
	MX_DEFLATE2  = 0x00400000, /* Z-Credhy: the peer accepts deflate/Zlib */
	MX_WITH_YYM  = 0x00800000, /* on the top of YYMUX */

	MX_WITH_PMAP = 0x01000000, /* port mapping by tcprelay/udprelay */
	MX_WITH_DNS  = 0x02000000, /* with DNS forwarding */
	MX_WITH_VNC  = 0x04000000, /* with VNC forwarding */
	MX_WITH_SOCKS= 0x08000000, /* SOCKS server at the server side */
	MX_WITH_HTTP = 0x10000000, /* HTTP server to the client's CWD */
	MX_WITH_FTP  = 0x20000000, /* FTP server to the client's CWD */
	MX_WITH_POP  = 0x40000000, /* POP server at the serve side */
	MX_WITH_SMTP = 0x40000000, /* MAIL server at the serve side */
	MX_WITH_Y11  = 0x80000000, /* with X DISPLAY (over YYMUX) */
} MuxFlag;
	//MX_SIGN    = 0x00080000, /* Z-Credhy: with sign */
	//MX_ORIGIN_R= 0x00000080, /* got response from an origin server */
	//MX_MUX1    = 0x00001000, /* on a single connection */
	//MX_REVERSE = 0x02000000, /* accept reverse YYSH from server side */
	//#define MxFlagsORIGIN_R	(MxFlags & MX_ORIGIN_R)

#define MX_CREDHY	(MX_CREDHY_SV|MX_CREDHY_CL)
#define MX_DEFLATE	(MX_DEFLATE1|MX_DEFLATE2)

#define MxFlags		Mc->mc_flags
#define MxFlagsFLOWCTL	(MxFlags & MX_FLOWCTL)
#define MxFlagsPERSIST	(MxFlags & MX_PERSIST)
#define MxFlagsTERSE	(MxFlags & MX_TERSE)
#define MxFlagsVERBOSE	(MxFlags & MX_VERBOSE)
#define MxFlagsDUMP	(MxFlags & MX_DUMP)
#define MxFlagsSHUTIMM	(MxFlags & MX_SHUTIMM)
#define MxFlagsINTERACT	(MxFlags & MX_INTERACT)
#define MxFlagsVV_TOMUX	(MxFlags & MX_VV_TOMUX)
#define MxFlagsIDEBUG	(MxFlags & MX_IDEBUG)
#define MxFlagsISILENT	(MxFlags & MX_ISILENT)
#define MxFlagsLOG_YYSH	(MxFlags & MX_LOG_YYSH)

#define MxFlagsMUXACC	(MxFlags & MX_MUXACC)
#define MxFlagsMUXCON	(MxFlags & MX_MUXCON)
#define MxFlagsWITH_DNS	(MxFlags & MX_WITH_DNS)
#define MxFlagsWITH_VNC	(MxFlags & MX_WITH_VNC)
#define MxFlagsWITH_Y11	(MxFlags & MX_WITH_Y11)
#define MxFlagsWITH_YYM	(MxFlags & MX_WITH_YYM)
#define MxFlagsWITH_FTP	(MxFlags & MX_WITH_FTP)
#define MxFlagsWITH_POP	(MxFlags & MX_WITH_POP)
#define MxFlagsWITH_SMT	(MxFlags & MX_WITH_SMTP)
#define MxFlagsWITH_HTT	(MxFlags & MX_WITH_HTTP)
#define MxFlagsWITH_SOC	(MxFlags & MX_WITH_SOCKS)
#define MxFlagsWITH_PMA	(MxFlags & MX_WITH_PMAP)

#define MxFlagsYYACTIVE	(MxFlags & MX_YYACTIVE)
#define MxFlagsSTLS	(MxFlags & MX_STLS)
#define MxFlagsDEFLATE1	(MxFlags & MX_DEFLATE1)
#define MxFlagsDEFLATE2	(MxFlags & MX_DEFLATE2)
#define MxFlagsDEFLATE	(MxFlags & MX_DEFLATE)
#define MxFlagsCREDHY	(MxFlags & MX_CREDHY)
#define MxFlagsX11UNIX	(MxFlags & MX_X11_UNIX)
#define MxFlagsX11INET	(MxFlags & MX_X11_INET)
#define MxFlagsX11LOCAL	(MxFlags & MX_X11_LOCAL)
#define MxFlagsHOLDONNX (MxFlags & MX_HOLDONNX)
#define MxSadEnd	Mc->mc_sadend
#define MxNBSendBuf	Mc->mc_nbsb
#define MxSOListen	Mc->mc_listen

#define FD_new(fd,what,flags) FD_newX(MxId,fd,what,flags)

static char *stimes(int longfmt){
	static IStr(stm,32);
	int sec,usec;
	const char *fmt;

	sec = Gettimeofday(&usec);
	if( longfmt ){
		fmt = "%Y/%m/%d-%H:%M:%S%.2s";
	}else{
		fmt = "%H:%M:%S%.2s";
	}
	StrftimeLocal(AVStr(stm),sizeof(stm),"%H:%M:%S%.2s",sec,usec);
	return stm;
}
#define zprintf !MxFlagsVERBOSE?0:yprintf
static int yprintf(MuxCtx *Mc,PCStr(fmt),...){
	IStr(msg,1024);
	refQStr(mp,msg);
	VARGS(16,fmt);

	Rsprintf(mp,"--");
	if( Mc ){
		Rsprintf(mp,"Y%d",MxId);
		if( MxParent ){
			Rsprintf(mp,"/%d",MxParent->mc_id);
		}
	}
	Rsprintf(mp," %s ",stimes(0));
	Rsprintf(mp,fmt,VA16);
	if( Mc && MxFlagsINTERACT ){
		fprintf(stderr,"%s\r\n",msg);
	}
	sv1log("%s\n",msg);
	return 0;
}
static void YYlogComm(MuxCtx *Mc,PCStr(pfx),PCStr(wh),PCStr(resp)){
	IStr(sresp,512);

	if( strncaseeq(resp,"Y-Credhy-Key:",13)
	 || strncaseeq(resp,"Authorization: YYKEY ",21)
	){
		strcpy(sresp,resp);
		Xstrcpy(DVStr(sresp,60),"...");
		resp = sresp;
	}
	sv1log("--%s %s\n",wh,resp);
	if( MxFlagsINTERACT && MxFlagsVERBOSE || MxFlagsIDEBUG ){
		fprintf(stderr,"%05.2f %d %s %s\r\n",
			Time()-MxStart,MxId,pfx,resp);
	}
}
static void YYlfprintfX(MuxCtx *Mc,PCStr(wh),PCStr(com),FILE *fp,PCStr(fmt),...){
	IStr(msg,1024);
	VARGS(16,fmt);

	sprintf(msg,fmt,VA16);
	YYlogComm(Mc,com,wh,msg);
	if( fp ){
		fprintf(fp,"%s\r\n",msg);
	}
}
static void YYlfprintf(MuxCtx *Mc,PCStr(wh),FILE *fp,PCStr(fmt),...){
	VARGS(16,fmt);
	YYlfprintfX(Mc,wh,"-c--",fp,fmt,VA16);
}

static const char *MxStralloc(MuxCtx *Mc,PCStr(str)){
	refQStr(ap,MxStrbuf);
	const char *sp;

	if( MxStrtail == 0 ){
		MxStrtail = MxStrbuf;
	}
	sp = ap = MxStrtail;
	strcpy(ap,str);
	ap += strlen(ap);
	setVStrPtrInc(ap,0);
	MxStrtail = ap;
	return sp;
}

int withZlib();
/* ZCFlags: External flags in the ZC packet (ver. Z-Credhy) */
enum _ZCFlags {
	ZC_DEFLATE = 0x01, /* in Zlib deflate */
	ZC_CREDHY  = 0x02, /* in Credhy encryption */
	ZC_SIGNED  = 0x04, /* signed with a secret key */
	ZC_CTL     = 0x08, /* control message */
	ZC_INIT    = 0xE8, /* niitialize stream */
	ZC_EOS     = 0xF8, /* end of stream */
	ZC_CTLXX   = 0xF8, /* niitialize stream */
} ZCFlags;
#define isZC_INIT(f)  ((f & ZC_CTLXX) == (ZC_INIT & ZC_CTLXX))
#define isZC_EOS(f)   ((f & ZC_CTLXX) == (ZC_EOS  & ZC_CTLXX))
static int isZC_CTL(int f){
	if( f & ZC_CTL ){
		return 1;
	}
	return 0;
}

/* External -- ZCredhy packet format (ver. YYMUX) */
static void ZCsend(FILE *ofp,int oflags,int ocrc,int leng){
	putc(leng >> 8,ofp);
	putc(leng,ofp);
	putc(ocrc,ofp);
	putc(oflags,ofp);
}
static void ZCrecv(FILE *ifp,int *iflags,int *rcrc,int *leng){
	*leng = getc(ifp) << 8;
	*leng |= getc(ifp);
	*rcrc = getc(ifp);
	*iflags = getc(ifp);
}
static int isZCpack(PCStr(bp),int size){
	const unsigned char *up = (const unsigned char*)bp;
	int leng;

	if( 4 <= size ){
		leng = (up[0] << 8) | up[1];
		if( 0 < leng ){
			if( size == leng + 4 ){
				return 0x100 | up[3];
			}
		}
	}
	return 0;
}
enum _HttpHeadPosition {
	HS_BODY   = 0,
	HS_HTOP   = 1,
	HS_FTOP   = 2,
	HS_INHEAD = 4,
} HttpHeadPosition;
static const char *HTTPHEAD = "HTTP/";
/* to skip YYMUX or YYSH header to calc. body checksum */
static int inHTTPhead(int hpos,PCStr(buf),int len){
	const char *bx = buf+len;
	const char *bp;
	int ohp = hpos;

	for( bp = buf; bp < bx; bp++ ){
		if( hpos == HS_HTOP ){
			if( bp[0] != 'H' || bp[1] != 'T' || bp[2] != 'T' ){
				hpos = HS_BODY;
				break;
			}
		}
		if( hpos == HS_FTOP ){
			if( bp[0] == '\r' && bp[1] == '\n' ){
				hpos = HS_HTOP;
				bp += 1;
				continue;
			}
			if( bp[0] == '\n' ){
				hpos = HS_HTOP;
				continue;
			}
		}
		if( bp[0] == '\r' ){
			continue;
		}else
		if( bp[0] == '\n' ){
			hpos = HS_FTOP;
		}else{
			hpos = HS_INHEAD;
		}
	}
/*
 sv1log("----inHH %d->%d %d [%X %X]\n",ohp,hpos,len,buf[0],buf[1]);
*/
	return hpos;
}
#define ZC_MAXPBSIZE (16*1024)
static int freads(PVStr(buf),int len,FILE *fp){
	double St = Time();
	int rcc = 0;
	int rc1;
	int ri;
	int rdy = -9;
	int serrno1 = 0;
	int serrno2 = 0;

	if( len == 0 ){
		return 0;
	}
	for( ri = 0; ri < 100; ri++ ){
		if( feof(fp) ){
			break;
		}
		errno = 0;
		rdy = fPollIn(fp,30);
		if( rdy == 0 ){
			msleep(10);
			continue;
		}
		rc1 = fread((char*)buf+rcc,1,len-rcc,fp);
		if( 0 < rc1 ){
			rcc += rc1;
		}
		if( rcc == len ){
			break;
		}
		if( 0 < rc1 ){
			serrno1 = errno;
		}else{
			serrno2 = errno;
		}
/*
 fprintf(stderr,"----PARTIAL fread(%2d)%6d/%6d/%6d rdy=%d eof=%d e=%d (%.3f)\n",
	ri,rc1,len-rcc,len,rdy,feof(fp),errno,Time()-St);
*/
	}
	if( 0 < ri ){
 sv1log("----freads([%d],%d)=%d *%d rdy=%d eof=%d e=%d,%d (%.3f)\n",
	fileno(fp),len,rcc,ri,rdy,feof(fp),serrno1,serrno2,Time()-St);
	}
	return rcc;
}
static int ZCwaitEOS(FILE *ifp){
	double St = Time();
	int frdy,rdy;
	int iflg,rcrc,icc;

	frdy = ready_cc(ifp);
	rdy = fPollIn(ifp,10*1000);
	if( frdy || rdy ){
		ZCrecv(ifp,&iflg,&rcrc,&icc);
 sv1log("----ZC wait EOS=%d,%d (%.2f)%X %d %02X\n",frdy,rdy,Time()-St,iflg,icc,rcrc);
		/* should skip until iflg==ZC_EOS */
		return 1;
	}else{
 sv1log("----ZC wait EOS=%d,%d (%.2f) TIMEOUT\n",frdy,rdy,Time()-St);
		return 0;
	}
}
static void relayZCredhy(MuxCtx *Mc,int id,int ox,int ix,int od){
	FILE *fiv[2],*fov[2],*ifp,*ofp;
	int rdv[2],nready,ri,icc,rcc,wcc;
	int osq = 0;
	int rcrc = 0;
	int ocrc = 0;
	int icrc = 0;
	IStr(ibuf,ZC_MAXPBSIZE);
	IStr(zbuf,ZC_MAXPBSIZE);
	char *obuf = 0;
	int olen = 0;
	unsigned const char *up = (unsigned const char*)ibuf;
	int och = -9;
	int oflags = 0;
	int oflg = 0;
	int iflg = 0;
	int zlen = -9;
	Credhy *iCr = &MxCredhy[0];
	Credhy *oCr = &MxCredhy[1];
	Z1Ctx *Z1dfl = 0;
	Z1Ctx *Z1ifl = 0;
	Z1Ctx ZCdfl;
	Z1Ctx ZCifl;
	int vvlog = MxFlagsVERBOSE;
	int litotal = 0;
	int zototal = 0;
	int zitotal = 0;
	int lototal = 0;
	int ignhead = 1;
	int pi = 0;
	int hpos = HS_HTOP;
	int putINIT = 0;
	int peerEOS = 0;
	double St = Time();
	int frdy,rdy;
	int serrno;

	fiv[0] = fdopen(id,"r"); fov[0] = fdopen(ox,"w");
	fiv[1] = fdopen(ix,"r"); fov[1] = fdopen(od,"w");

	MxCredhy[1] = MxCredhy[0];
	if( MxFlagsCREDHY ){
		oflags |= ZC_CREDHY;
	}
	if( MxFlagsDEFLATE ){
		if( MxFlagsDEFLATE1 && MxFlagsDEFLATE2 ){
			bzero(&ZCdfl,sizeof(Z1Ctx));
			ZCdfl.z1_debug = vvlog;
			Z1dfl = deflateZ1new(&ZCdfl);
		}
		bzero(&ZCifl,sizeof(Z1Ctx));
		ZCifl.z1_debug = vvlog;
		Z1ifl = inflateZ1new(&ZCifl);
	}
	/*
	if( MxFlagsCREDHY )
	*/
	{
		ifp = fiv[1];
		ofp = fov[0];
		sprintf(ibuf,"%08X%08X",trand1(0xFFFFFFFF),trand1(0xFFFFFFFF));
		rcc = strlen(ibuf) + 1;
		ocrc = strCRC32add(ocrc,ibuf,rcc);
		oflg = (oflags & ~ZC_DEFLATE)|ZC_CTL|ZC_INIT;
		ZCsend(ofp,oflg,ocrc,rcc);
		CredhyEncrypt(oCr,rcc,ibuf,ibuf);
		wcc = fwrite(ibuf,1,rcc,ofp);
		if( vvlog ){
			sv1log("----ZC put INIT %08X\n",ocrc);
		}
		fflush(ofp);
		rdy = fPollIn(ifp,10*1000);
		if( 0.03 < Time()-St ){
 sv1log("----ZC slow INIT %08X rdy=%d (%.3f)\n",ocrc,rdy,Time()-St);
		}
		ocrc = 0;
	}

	nready = fpollinsX(0,2,fiv,rdv);
 sv1log("----ZC Start ready=%d (%d %d)\n",nready,rdv[0],rdv[1]);
	for( pi = 0; ; pi++ ){
		if( ready_cc(fiv[0]) <= 0 ){
			fflush(fov[0]);
		}
		if( ready_cc(fiv[1]) <= 0 ){
			fflush(fov[1]);
		}
		errno = 0;
		nready = fpollinsX(0,2,fiv,rdv);
		serrno = errno;
		if( nready <= 0 && serrno == EBADF ){
 sv1log("----ZC ready=%d [%d %d][%d %d][%d %d] e%d FATAL EBADF ####\n",
	nready,fileno(fiv[0]),fileno(fiv[1]),rdv[0],rdv[1],
	file_ISSOCK(fileno(fiv[0])),file_ISSOCK(fileno(fiv[1])),serrno);
			break;
		}
		if( nready < 0 ){
			break;
		}
		for( ri = 0; ri < 2; ri++ ){
			if( rdv[ri] == 0 ){
				continue;
			}
			putINIT = 0;
			ifp = fiv[ri];
			ofp = fov[ri];
			if( ri == 0 ){ /* direct raw input */
				rcc = read(fileno(ifp),ibuf,sizeof(ibuf));
				if( rcc <= 0 ){
 sv1log("----ZC send EOS {%08X} len=%d rcc=%d e%d\n",ocrc,litotal,rcc,errno);
					sprintf(ibuf,"%08X",ocrc);
					obuf = ibuf;
					olen = strlen(ibuf)+1;
					oflg = ZC_EOS;
					if( 0 ){
						oflg |= ZC_SIGNED;
						/* should be signed */
					}
					ZCsend(ofp,oflg,ocrc,olen);
					fwrite(obuf,1,olen,ofp);
					fflush(ofp);
					goto EXIT;
				}
				litotal += rcc;
				ocrc = strCRC32add(ocrc,ibuf,rcc);
				obuf = ibuf;
				olen = rcc;
				oflg = oflags & ~ZC_DEFLATE;

				if( ignhead )
				if( hpos )
				if( hpos = inHTTPhead(hpos,ibuf,rcc) ){
 sv1log("----ZC IGN HTTP HEAD %X %d\n",ocrc,litotal);
					putINIT = 1;
				}
				if( Z1dfl ){
				    if( 16 <= rcc ){
					zlen = deflateZ1(Z1dfl,ibuf,rcc,
						AVStr(zbuf),sizeof(zbuf));
 if( vvlog )
 yprintf(Mc,"----ZC enZ %d/%d %08X %u",zlen,rcc,ocrc,litotal);
					if( 0 < zlen && zlen <= olen ){
					}else{
 sv1log("----ZC enZ %d/%d larger than orig. ####WARN\n",zlen,rcc);
					}
					if( 0 < zlen ){
						obuf = zbuf;
						olen = zlen;
						oflg = oflg | ZC_DEFLATE;
					}
				    }
				}
				zototal += olen;
				ZCsend(ofp,oflg,ocrc,olen);
				if( oflags & ZC_CREDHY ){
					och = up[0];
					CredhyEncrypt(oCr,olen,obuf,obuf);
				}
 if( vvlog )
 sv1log("----ZC enc[%02X]->[%02X]%d\n",och,up[0],rcc);

			}else{ /* tagged input (ZC packet) */
				ZCrecv(ifp,&iflg,&rcrc,&icc);
				if( icc == 0 && isZC_CTL(iflg) ){
				}else
				if( icc <= 0 || sizeof(ibuf) < icc ){
 sv1log("----ZC detect EOS {%08X}\n",icrc);
					goto EXIT;
				}
				rcc = freads(AVStr(ibuf),icc,ifp);
				if( rcc < icc ){
					goto EXIT;
				}
				if( isZC_EOS(iflg) ){
					peerEOS = 1;
 sv1log("----ZC recv EOS {%08X}{%s} len=%d\n",icrc,ibuf,lototal);
					if( iflg & ZC_SIGNED ){
						/* should verify the sign */
					}
					/* should send EOS from this side */
					goto EXIT;
				}
				zitotal += rcc;
				och = up[0];
				if( iflg & ZC_CREDHY ){
					CredhyDecrypt(iCr,rcc,ibuf,ibuf);
				}
				obuf = ibuf;
				olen = rcc;
				if( iflg & ZC_DEFLATE ){
					if( Z1ifl == 0 ){
 sv1log("----ZC got DEFLATEd packet withoout annoounce ####FATAL\n");
						goto EXIT;
					}
					zlen = inflateZ1(Z1ifl,ibuf,rcc,
						AVStr(zbuf),sizeof(zbuf));
					obuf = zbuf;
					olen = zlen;
				}
				lototal += olen;
				icrc = strCRC32add(icrc,obuf,olen);
				if( iflg & ZC_DEFLATE ){
 if( vvlog )
 yprintf(Mc,"----ZC unZ %d/%d %08X %u",zlen,rcc,icrc,lototal);
				}
 if( vvlog )
 sv1log("----ZC dec[%02X]->[%02X]%d CRC{%02X %08X}%s\n",och,up[0],rcc,
	rcrc,icrc,(iflg&ZC_CTL)?"IGN":"");
				if( iflg & ZC_CTL ){
					if( vvlog ){
 sv1log("----ZC got CTL %02X\n",icrc);
					}
				}
				if( isZC_INIT(iflg) ){
 sv1log("----ZC got INIT %08X len=%d\n",icrc,lototal);
					icrc = 0;
					lototal = 0;
				}
				if( iflg & ZC_CTL ){
					continue;
				}
			}
			if( olen <= 0 ){
				goto EXIT;
			}
			wcc = fwrite(obuf,1,olen,ofp);
			if( wcc <= 0 ){
				goto EXIT;
			}
			if( ready_cc(ifp) <= 0 ){
				fflush(ofp);
			}
			if( ferror(ofp) ){
				goto EXIT;
			}
			if( putINIT ){
				fflush(ofp);
				ZCsend(ofp,ZC_INIT,ocrc,0);
				fflush(ofp);
				ocrc = 0;
				litotal = 0;
			}
		}
	}
EXIT:
	if( !ferror(fov[0]) ) fflush(fov[0]);
	if( !ferror(fov[1]) ) fflush(fov[1]);
	shutdownWR(od);
	if( peerEOS == 0 ){ // poll peer's soft EOS
		ZCwaitEOS(fiv[1]);
	}
	/* SSLway shutdown should be after the detection of peer's EOS */
	shutdownWR(ox);
	if( Z1dfl ){
		deflateZ1end(Z1dfl);
	}
	if( Z1ifl ){
		inflateZ1end(Z1ifl);
	}
 sv1log("----ZC End---- recv(%u / %uz) sent(%uz / %u) o%X i%X Y%d\n",
		lototal,zitotal,zototal,litotal,ocrc,icrc,MxId);
	MxZ1.zs_litotal += litotal;
	MxZ1.zs_zototal += zototal;
	MxZ1.zs_zitotal += zitotal;
	MxZ1.zs_lototal += lototal;
}
extern int FilterID;
int pushPFilter(Connection *Conn,PCStr(proto),PFilter *aPf);
int popPFilter(Connection *Conn,int timeout,int which);
static int insertZCredhy(MuxCtx *Mc,int peer,int ftype){
	Connection *Conn = MxConn;
	int tid;
	int io[2];
	PFilter Pf;

	Socketpair(io);
	tid = thread_fork(0,0,ZCredhy,(IFUNCP)relayZCredhy,
		Mc,io[0],peer,peer,io[0]);

	bzero(&Pf,sizeof(PFilter));
	Pf.f_fid = ++FilterID;
	Pf.f_ftype = ftype;
	Pf.f_tid = tid;
	Pf.f_owner = getthreadid();
	pushPFilter(Conn,ZCredhy,&Pf);
	return io[1];
}

/*
 * forward  -yf[:port[/[host][/proto]][:port[/host][/proto]]
 * backward -yb[:port[/[host][/proto]][:port[/host][/proto]]
 */
static const char *scanPort1(Port1 *P1,PCStr(port)){
	const char *pf;
	IStr(buff,256);

	pf = wordScanY(port,buff,"^/:");
	P1->p1_port = atoi(buff);
	if( isinListX(buff,"udp",".") ){
		P1->p1_flags |= P1_UDP;
	}
	if( isinListX(buff,"tcp",".") ){
		P1->p1_flags |= P1_TCP;
	}
	if( isinListX(buff,"ssl",".") ){
		P1->p1_flags |= P1_SSL;
	}
	if( *pf == '/' ){
		pf = wordScanY(pf+1,buff,"^/:");
		if( buff[0] ){
			strcpy(P1->p1_host,buff);
		}
		if( *pf == '/' ){
			pf = wordScanY(pf+1,buff,"^/:");
			if( buff[0] ){
				strcpy(P1->p1_proto,buff);
			}
		}
	}
	return pf;
}
static void setDfltMap1(Port1 *Pd,Port1 *Ps){
	if( Pd->p1_port == 0 ){
		if( Pd->p1_proto[0] == 0 ){
			strcpy(Pd->p1_proto,Ps->p1_proto);
		}
		if( Pd->p1_proto[0] ){
			Pd->p1_port = serviceport(Ps->p1_proto);
		}else{
			Pd->p1_port = Ps->p1_port;
		}
	}
}
static int scanPortMap1(MuxCtx *Mc,int flags,PCStr(fwd),PortMap1 *Pm,PCStr(proto),PCStr(rhost),int rport,int lport){
	const char *fw;

	Pm->pm_flags = flags;

	strcpy(Pm->pm_remote.p1_proto,proto);
	strcpy(Pm->pm_remote.p1_host,rhost);
	       Pm->pm_remote.p1_port = rport;

	strcpy(Pm->pm_local.p1_proto,proto);
	strcpy(Pm->pm_local.p1_host,"127.0.0.1");
	       Pm->pm_local.p1_port = lport;

	for( fw = fwd; *fw; fw++ ){
		if( *fw == ':' || *fw == '/' ){
			fw = scanPort1(&Pm->pm_local,fw+1);
			if( *fw == ':' ){
				fw = scanPort1(&Pm->pm_remote,fw+1);
			}
			break;
		}
	}
	setDfltMap1(&Pm->pm_remote,&Pm->pm_local);
	setDfltMap1(&Pm->pm_local,&Pm->pm_remote);

	if( Pm->pm_remote.p1_port == 0 && Pm->pm_local.p1_port == 0 ){
		return 0;
	}
	if( Pm->pm_local.p1_proto[0] == 0 ){
		strcpy(Pm->pm_local.p1_proto,"tcprelay");
	}
	if( Pm->pm_remote.p1_proto[0] == 0 ){
		strcpy(Pm->pm_remote.p1_proto,"tcprelay");
	}
	sv1log("---- PortMap %d/%s/%s %s %d/%s/%s\n",
	Pm->pm_local.p1_port,Pm->pm_local.p1_host,Pm->pm_local.p1_proto,
	Pm->pm_flags ? "->":"<-",
	Pm->pm_remote.p1_port,Pm->pm_remote.p1_host,Pm->pm_remote.p1_proto
	);
	return 1;
}
static PortMap1 *addPortMap1(MuxCtx *Mc,int flags,PCStr(map),PCStr(proto),PCStr(rhost),int rport,int lport){
	PortMap1 *Pm;
	int pi;

	for( pi = 0; pi < elnumof(Mc->mc_portmap.pm_maps); pi++ ){
		Pm = &Mc->mc_portmap.pm_maps[pi];
		if( Pm->pm_local.p1_port == 0 ){
			if( scanPortMap1(Mc,flags,map,Pm,proto,rhost,rport,lport) ){
				return Pm;
			}
		}
	}
	return 0;
}
static void dumpPortMaps(MuxCtx *Mc){
	PortMap1 *Pm;
	int pi;
	IStr(lopts,128);
	IStr(ropts,128);

	for( pi = 0; pi < elnumof(Mc->mc_portmap.pm_maps); pi++ ){
		Pm = &Mc->mc_portmap.pm_maps[pi];
		if( Pm->pm_local.p1_port ){
			if( Pm->pm_local.p1_flags ){
				strcpy(lopts,".udp");
			}
			if( Pm->pm_remote.p1_flags ){
				strcpy(ropts,".udp");
			}
 yprintf(Mc,"PortMap %d%s/%s/%s %s %d%s/%s/%s [%d]",
	Pm->pm_local.p1_port,lopts,Pm->pm_local.p1_host,Pm->pm_local.p1_proto,
	(Pm->pm_flags & PM_FORWARD) ? "->":"<-",
	Pm->pm_remote.p1_port,ropts,Pm->pm_remote.p1_host,Pm->pm_remote.p1_proto,
	Pm->pm_local.p1_sock
 );
		}
	}
}

static int scan_keyopts(MuxCtx *Mc,PCStr(arg));
int scan_yopts(MuxCtx *Mc,Connection *Conn,int flags,PCStr(a1)){
	if( a1[0] == '-' && a1[1] == 'y' )
	switch( a1[2] ){
	  case 'I':
		flags ^= MX_SHUTIMM;
		break;
	  case 'C':
		switch( a1[3] ){
		  case 'f':
			flags |= MX_FLOWCTL;
			break;
		  case 'c':
			MxCoupler = 'c';
			break;
		  case 's':
			MxCoupler = 's';
			break;
		}
		break;
	  case 'k':
	  case 'K':
		scan_keyopts(Mc,a1);
		break;
	  case 'l':
		flags ^= MX_LOG_YYSH;
		break;
	  case 's':
		flags ^= MX_STLS;
		break;
	  case 'j':
		flags ^= MX_IDEBUG;
		break;
	  case 'i':
		switch( a1[3] ){
			case 0:
				flags ^= MX_INTERACT;
				break;
			case 'i':
				flags ^= MX_IDEBUG;
				break;
			case 's':
				flags ^= MX_ISILENT;
				break;
		}
		break;
	  case 'o':
		switch( a1[3] ){
		    case 'a':
		      switch( a1[4] ){
			case 'l': MxSOListen = atoi(a1+5);
			    break;
		      }
		      break;
		    case 'o':
		      switch( a1[4] ){
			case 'z':
			    {
				int size;
				size = kmxatoi(a1+5);
				fprintf(stderr,"\rNB send size=%d (%s)\r\n",size,a1+5);
				if( 0 <= size && size < 1024*1024 ){
					MxNBSendBuf = size;
				}
			    }
			    break;
		      }
		      break;
		}
		break;
	  case 'p':
		switch( a1[3] ){
		  case 'h':
			flags |= MX_PERSIST;
			MxRsmhold = (UInt)Scan_period(a1+4,'m',(double)MxRsmhold);
			MxRsmholdSet = 1;
			break;
		  case 'i':
			MxPingitvl = (UInt)Scan_period(a1+4,'s',(double)MxPingitvl);
			break;
		  case 's':
			MxRsmstart = (UInt)Scan_period(a1+4,'s',(double)MxRsmstart);
			break;
		}
		break;
	  case 'H':
		flags |= MX_HOLDONNX;
		break;
	  case 'd':
		flags |= MX_DUMP;
		break;
	  case 'q':
		flags |= MX_ISILENT;
		break;
	  case 't':
		flags |= MX_TERSE;
		break;
	  case 'V':
		flags |= MX_VERBOSE;
		break;
	  case 'r':
		//flags |= MX_REVERSE;
		break;
	  case 'f':
		switch( a1[3] ){
		  default:
			if( addPortMap1(Mc,PM_FORWARD,a1+3,"","127.0.0.1",0,0) ){
				flags |= MX_WITH_PMAP;
			}
			break;
		  case 0:
			flags |= MX_WITH_HTTP;
			flags |= MX_WITH_DNS;
			flags |= MX_WITH_FTP;
			flags |= MX_WITH_POP;
			flags |= MX_WITH_SMTP;
			flags |= MX_WITH_SOCKS;
			flags |= MX_WITH_VNC;
			break;
		  case 'd':
			flags |= MX_WITH_YYM | MX_WITH_DNS;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapDns,"dns","-.-",53,10053);
			break;
		  case 'f':
			flags |= MX_WITH_YYM | MX_WITH_FTP;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapFtp,"ftp","-.-",21,10021);
			break;
		  case 'h':
			flags |= MX_WITH_YYM | MX_WITH_HTTP;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapHttp,"http","-.-",80,10080);
			break;
		  case 'm':
			flags |= MX_WITH_YYM | MX_WITH_SMTP;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapSmtp,"smtp","-.-",25,10025);
			break;
		  case 'p':
			flags |= MX_WITH_YYM | MX_WITH_POP;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapPop,"pop","-.-",110,10110);
			break;
		  case 's':
			flags |= MX_WITH_YYM | MX_WITH_SOCKS;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapSocks,"socks","-.-",1080,11080);
			break;
		  case 'v':
			flags |= MX_WITH_YYM | MX_WITH_VNC;
	scanPortMap1(Mc,PM_FORWARD,a1+4,&MxPmapVnc,"vnc","127.0.0.1",5900,15900);
			break;
		}
		break;
	  case 'b':
		switch( a1[3] ){
		  default:
			if( addPortMap1(Mc,PM_BACKWARD,a1+3,"","127.0.0.1",0,0) ){
				flags |= MX_WITH_PMAP;
			}
			break;
		  case 0:
			flags |= MX_WITH_Y11;
		  case 'x':
	scanPortMap1(Mc,PM_BACKWARD,a1+3,&MxPmapVnc,"X","127.0.0.1",6010,6000);
			break;
		}
		break;
	  case 'x':
		flags |= MX_WITH_Y11;
		switch( a1[3] ){
			default:
				break;
			case 'u':
				flags |= MX_X11_UNIX;
				break;
			case 'i':
				flags |= MX_X11_INET;
				/* -yxixx.xx.xx.xx */
				break;
			case 'l':
				flags |= MX_X11_LOCAL;
				break;
		}
		break;
	  case 'y':
		if( isdigit(a1[3]) ){
			MxRsmhold = (UInt)Scan_period(a1+3,'m',(double)MxRsmhold);
			MxRsmholdSet = 1;
		}
		switch( a1[3] ){
			case 0:
				flags |= MX_WITH_YYM;
				break;
			case 'a':
				if( a1[4]=='c' ){
					flags |= MX_MUXACC;
				}
				break;
			case 'c': /* yyc */
				if( a1[4]=='o' ){
					flags |= MX_MUXCON;
				}
				break;
			case 'f':
				flags |= MX_WITH_FTP;
				break;
			case 'h':
				flags |= MX_WITH_HTTP;
				break;
			case 't':
				MxRsmhold = (UInt)Scan_period(a1+4,'m',(double)MxRsmhold);
				MxRsmholdSet = 1;
				break;
			case 'm':
				//flags |= MX_MUX1;
				break;
			case 'x':
				flags |= MX_WITH_Y11;
				break;
		}
		break;
	  case 'z':
		switch( a1[3] ){
			default:
				if( withZlib() ){
					flags ^= MX_DEFLATE1;
				}
				break;
		}
		break;
	  case 'c':
		switch( a1[3] ){
			default:
				flags ^= MX_CREDHY_SV;
				flags ^= MX_CREDHY_CL;
				break;
		}
		break;
	}
	return flags;
}

int dumpThreads(PCStr(wh));
int dumpTids();
void dumpFds(FILE *outf);
static MuxCtx *yy_gMc;
static MuxCtx *yy_Mcv[32];
static int yy_id;
static int yy_gid;
static int endYY1(MuxCtx *Mc){
	int mi;
	int terr;
	double St;

	St = Time();
	if( MxTidyyx != 0 ){
		terr = thread_wait(MxTidyyx,1);
		sv1log("--endYY1 Y%d wait tid=%X,err=%d (%.3f) th=%d/%d\n",
			MxId,PRTID(MxTidyyx),terr,Time()-St,actthreads(),numthreads());
		if( terr == 0 ){
			MxTidyyx = 0;
		}
	}
	if( MxTidyyx != 0 )
		return -1;
	for( mi = 1; mi < elnumof(yy_Mcv); mi++ ){
		if( yy_Mcv[mi] == Mc ){
			yy_Mcv[mi] = 0;
			sv1log("--endYY1 Y%d (%d) %X th=%d/%d\n",
				MxId,mi,p2i(Mc),
				actthreads(),numthreads()
			);
			BUF_free("YYMUXa",Mc,sizeof(MuxCtx));
			return 0;
		}
	}
	return -2;
}
static int owningYY(Connection *Conn){
	int mi;
	MuxCtx *Mc;
	int independ = 0;
	int owned = 0;
	int active = 0;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( (Mc = yy_Mcv[mi]) == 0 ){
			continue;
		}
		active++;
		if( MxConn == Conn ){
			if( MxStatSELFEND ){
				independ++;
			}else{
				owned++;
			}
		}
	}
	if( 0 < active ){
sv1log("---fin---SELFEND act=%d own=%d ind=%d yy=%d YYSHD=%X YYSHD_YYM=%X\n",
active,owned,independ,
STX_yy,GatewayFlags&GW_IS_YYSHD,GatewayFlags&GW_IS_YYSHD_YYM);
	}
	return owned;
}
static int actCony(MuxCtx *Mc,int free);
static int waitendYY(Connection *Conn,PCStr(wh),int timeout){
	int ri;
	int start;
	int endt;
	int mi;
	MuxCtx *Mc;
	int nact;
	int ncon;
	int mxId = 0;
	int shut = 0;
	int stat = 0;
	int zomb = 0;

	start = time(0);
	endt = start + timeout;
	for( ri = 0; time(0) < endt; ri++ ){
		nact = 0;
		ncon = 0;
		zomb = 0;
		mxId = 0;
		for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
			if( Mc = yy_Mcv[mi] ){
				if( MxConn == Conn ){
					nact++;
					zomb += MxStatZOMBI ? 1 : 0;
if( mxId != 0 ){
sv1log("----waitendY%d act=%d %2d [%s:%d] (%d / %d)\n",
mxId,nact,ncon,DST_HOST,DST_PORT,time(0)-start,timeout);
}
					mxId = MxId;
					shut = MxShutting;
					stat = MxStatALL;
					ncon += actCony(Mc,0);
				}
			}
		}
sv1log("----waitendY%d act=%d zomb=%d con=%2d [%s:%d] (%d / %d) stat=%X shut=%X\n",
mxId,nact,zomb,ncon,DST_HOST,DST_PORT,time(0)-start,timeout,stat,shut);
		if( nact == 0 || nact == zomb ){
			break;
		}
		msleep(3*1000);
	}
	return 0;
}
/* no owner (application proxy) will wait and clean this YYMUX */
static int setselfendYY(Connection *Conn,PCStr(wh),int timeout){
	int mi;
	MuxCtx *Mc;
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
			if( MxConn == Conn ){
sv1log("----1 MX=%X SELFEND=%d Y%d %d %s\n",Mc,MxStatSELFEND,MxId,STX_yy,wh);
				MxStatSELFEND = 1;
sv1log("----2 MX=%X SELFEND=%d Y%d %d %s\n",Mc,MxStatSELFEND,MxId,STX_yy,wh);
			}
		}
	}
	return 0;
}
static int isAliveY(int mxId){
	int mi;
	MuxCtx *Mc;
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
			if( MxId == mxId ){
				return 1;
			}
		}
	}
	return 0;
}
static int cleanZombiYY(){
	int mi;
	MuxCtx *Mc;
	int nc = 0;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
			if( MxStatSELFEND && MxStatZOMBI ){
sv1log("####endYY [%d]Y%d clean zombiYY, self-clean\n",mi,MxId);
				endYY1(Mc);
				nc++;
			}
		}
	}
	return nc;
}
static int activeYY(){
	MuxCtx *Mc;
	int mi;
	int nact = 0;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc && MxFlagsYYACTIVE ){
			nact++;
		}
	}
	return nact;
}

static void endYY(Connection *Conn,MuxCtx *Mc){
	int mi;
	int terr;
	double St;
	int mxId = MxId;
	int ytid = MxTidyyx;

	if( mxId == MxId ){
		if( MxStatFREEING ){
			sv1log("##FATAL BUF in freeing: Y%d Y%d\n",mxId,MxId);
			return;
		}
		MxStatFREEING = 1;
	}

dumpThreads("--endYY--");
	St = Time();
	if( MxTidyyx != 0 ){
		if( streq(DST_PROTO,"ftp-data") ){
			terr = thread_wait(MxTidyyx,10);
			if( terr != 0 ){
				sv1log("--[%s] wait err=%d th=%d/%d\n",DST_PROTO,terr,
					actthreads(),numthreads());
				return;
			}
		}
		terr = thread_wait(MxTidyyx,3*1000);
		sv1log("--endYY Y%d wait tid=%X,err=%d (%.3f) th=%d/%d\n",
			MxId,PRTID(MxTidyyx),terr,Time()-St,
			actthreads(),numthreads());
		if( MxId != mxId ){
			sv1log("##FATAL BUF reused-a: Y%d => Y%d %X\n",mxId,MxId,p2i(Mc));
			return;
		}
		if( terr == 0 ){
			MxTidyyx = 0;
		}
		if( terr ){
			/* might leave dangling YYMUX server at remote */
		}
	}
	if( MxId != mxId ){
		sv1log("##FATAL BUF reused-b: Y%d => Y%d %X\n",mxId,MxId,p2i(Mc));
		return;
	}

	/*
	if( 0 <= MxYsock && IsAlive(MxYsock) ){
		close(MxYsock);
	}
	*/

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( yy_Mcv[mi] == Mc ){
			if( MxId != mxId ){
				sv1log("##FATAL BUF reused-c: Y%d => Y%d %X\n",mxId,MxId,p2i(Mc));
				return;
			}
			yy_Mcv[mi] = 0;
			MxId = -MxId;
			if( Mc == yy_gMc ){
				yy_gMc = 0;
				sv1log("##endYY Y%d Global YY?\n",mxId);
			}
			STX_yy = 0;
			sv1log("--endYY Y%d (%d) %X th=%d/%d actYY=%d/%d\n",
				mxId,mi,p2i(Mc),
				actthreads(),numthreads(),activeYY(),yy_id
			);
			BUF_free("YYMUXb",Mc,sizeof(MuxCtx));
			return;
		}
	}
	/* duplicated closed */
	sv1log("---- #### --endYY Y%d (?) %X\n",MxId,p2i(Mc));

	if( MxId != mxId ){
		sv1log("##FATAL BUF reused-d: Y%d => Y%d %X\n",mxId,MxId,p2i(Mc));
	}else{
		sv1log("##FATAL BUF reused-e: Y%d => Y%d %X\n",mxId,MxId,p2i(Mc));
		MxId = -MxId;
		BUF_free("YYMUXc",Mc,sizeof(MuxCtx));
	}
}
static void sendSHUT1st(MuxCtx *Mc);
static int YY_endYYs(PCStr(wh),Connection *Conn,int ygid,int ytgid){
	MuxCtx *Mc;
	int mi;
	int nc = 0;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc == 0 ){
			continue;
		}
		if( MxStatISMAIN ){
			continue;
		}
		if( Mc->mc_ygid && Mc->mc_ygid == ygid
		 || Mc->mc_ytgid && Mc->mc_ytgid == ytgid
		){
sv1log("---YY_endYYs %s [%d]Y%d (%d %d)(%X %X) shut=%X main=%X stats=%X Mc=%X\n",
wh,mi,MxId,Mc->mc_ygid,ygid,Mc->mc_ytgid,ytgid,
MxShutting,MxStatISMAIN,MxStatALL,Mc);
			sendSHUT1st(Mc);
			endYY(Conn,Mc);
		}
	}
	return nc;
}
static Connection *getConnPtr(int mxId){
	MuxCtx *Mc;
	int mi;
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
			return MxConn;
		}
	}
	return 0;
}
static int cleanConnPtr(FL_PAR,Connection *Conn){
	int nc = 0;
	MuxCtx *Mc;
	int mi;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
			if( MxConn == Conn ){
				if( Conn0 == 0 ){
					Conn0 = (Connection*)malloc(sizeof(Connection));
				}
				bzero(Conn0,sizeof(Connection));
				ConnInit(Conn0);
				MxConn = Conn0;
putfLog("#### clearConnPtr Y%d %X => %X ##### <= %s:%d",MxId,Conn,Conn0,FL_BAR);
			}
		}
	}
	return nc;
}
void CTX_endYY(Connection *Conn){
	MuxCtx *Mc;
	int mi;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc == 0 ){
			continue;
		}
		if( MxFlagsVERBOSE ){
			sv1log("--CTX_endYY%d %d (%d) %X %X\n",
				MxId,STX_yy,mi,p2i(MxConn),p2i(Conn));
		}
		if( MxId == STX_yy ){
			if( MxMuxDone == 0 ){
				/* the YYMUX is not closed yet */
 sv1log("####CTX_endYY%d-%d yet alive %.1f %.1f %.1f ACT%d\n",
 MxId,STX_yy,MxStart,MxMuxStart,MxMuxDone,MxStatACTIVATED);
				if( MxStatACTIVATED || MxMuxStart ){
				/* the YYMUX was started (alive),
				 * thus don't overwrite it.
				 * A Connection can have multiple
				 * YYMUX, typically one for server
				 * and one for client.
				 * "STX_yy" is NG from this view pt.
				 */
					continue;
				}
			}
			endYY(Conn,Mc);
			return;
		}
	}
	sv1log("####CTX_endYY%d Conn=%X (?)\n",STX_yy,p2i(Conn));
}
static MuxCtx *findYY(Connection *Conn,PCStr(proto),PCStr(host),int port){
	MuxCtx *Mc;
	int mi;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc && MxFlagsYYACTIVE ){
			if( hostcmp(MxDstHost,host) == 0 ){
				return Mc;
			}
		}
	}
	return 0;
}
static int findYYxRsmport(int port,int key){
	int mi;
	MuxCtx *Mc;
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
			if( MxRsmport == port ){
				return MxId;
			}
		}
	}
	return 0;
}
static MuxCtx *lastYY(Connection *Conn){
	MuxCtx *Mc;
	MuxCtx *lMc = 0;
	int mi;

	for( mi = 1; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc == 0 ){
			continue;
		}
		if( MxConn == Conn && MxFlagsYYACTIVE ){
			if( lMc == 0 ){
				lMc = Mc;
			}else
			if( lMc->mc_id < Mc->mc_id ){
				lMc = Mc;
			}
		}
	}
	return lMc;
}
static void sendSHUT(MuxCtx *Mc);
static void sendSHUT1st(MuxCtx *Mc);
int CTX_setSweep(Connection *Conn){
	MuxCtx *Mc;
	int mi;

	for( mi = 1; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc == 0 ){
			continue;
		}
		if( MxConn == Conn ){
			MxStatSWEEP = 1;
		}
	}
	return 0;
}
int CTX_sweepYY(Connection *Conn){
	MuxCtx *Mc;
	int mi;
	int nend = 0;

	for( mi = 1; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc == 0 ){
			continue;
		}
		if( MxFlagsVERBOSE ){
			sv1log("--CTX_sweepYY (%d) yy#%d %d %X %X\n",
				mi,MxId,STX_yy,p2i(MxConn),p2i(Conn));
		}
		if( MxConn == Conn ){
			sendSHUT1st(Mc);
			endYY(Conn,Mc);
			nend++;
		}
	}
	return nend;
}
int finishThreadYY(int tgid){
	MuxCtx *Mc;
	int mi;
	int nend = 0;
	int terr = -9;

	for( mi = elnumof(yy_Mcv)-1; 0 <= mi; mi-- ){
		Mc = yy_Mcv[mi];
		if( Mc == 0 ){
			continue;
		}
		if( !MxFlagsYYACTIVE ){
			continue;
		}
		if( tgid == 0 || tgid == Mc->mc_ytgid ){
			if( 0 < MxClntHOLDONNX ){
				MxClntHOLDONNX = 0;
			}
			sendSHUT1st(Mc);
			if( MxTidyyx != 0 ){
				terr = thread_wait(MxTidyyx,300);
				/* MxTidyyx should be cleared */
				/* or add an option to retain the thread-id */
			}
			endYY1(Mc);
			nend++;
		}
	}
	return nend;
}
static CriticalSec YYCSC;
static int addYY(FL_PAR,int ri,Connection *Conn,MuxCtx *Mc){
	int mi;
	int csc = 0;
	double St = Time();

	if( 1 < STX_yy ){
		int yy = STX_yy;
		sv1log("--yy before addYY free yy#%d ---- BEGIN\n",STX_yy);
		CTX_endYY(Conn);
		sv1log("--yy before addYY free yy#%d/%d ---- END\n",STX_yy,yy);
	}
	cleanZombiYY();

	setupCSC("addYY",YYCSC,sizeof(YYCSC));
	if( enterCSCX(YYCSC,1) != 0 ){
		sv1log("--FATAL addYY CSC start\n");
		enterCSC(YYCSC);
		sv1log("--FATAL addYY CSC end (%.3f)\n",Time()-St);
		csc = 1;
	}
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( yy_Mcv[mi] == 0 ){
			yy_Mcv[mi] = Mc;
			STX_yy = ++yy_id;
			MxId = STX_yy;
			sv1log("--newYY (%d) yy#%d %X\n",mi,MxId,p2i(Mc));
			leaveCSC(YYCSC);
			if( csc ){
				sv1log("--FATAL addYY%d CSC done (%.3f)\n",yy_id,Time()-St);
			}
			return mi;
		}
	}
	leaveCSC(YYCSC);

	sv1log("####%d FATAL addYY full (%d) -- yy#%d %X <= %s:%d\n",
		ri,elnumof(yy_Mcv),MxId,p2i(Mc),FL_BAR);
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] ){
	sv1log("####%d FATAL addYY [%d] %X Y%d E%X [%d] [%X]%d shut=%X %s://%s:%d\n",
				ri,mi,Mc,MxId,MxEtype,MxYsock,
				PRTID(MxTidyyx),threadIsAlive(MxTidyyx),
				MxShutting,
				MxDstProto,MxDstHost,MxDstPort
			);
		}
	}
	return -1;
}
static int endYYs(Connection *Conn,FL_PAR){
	int mi;
	MuxCtx *Mc;
	int ne = 0;

	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( (Mc = yy_Mcv[mi]) == 0 ){
			continue;
		}
		if( MxTidyyx
		 && threadIsAlive(MxTidyyx) == 0
		 && MxShutting
		){
			sv1log("####[%d] Y%d FATAL endsYY <= %s:%d\n",mi,MxId,FL_BAR);
			if( endYY1(Mc) == 0 ){
				ne++;
			}
		}
	}
	return ne;
}
static MuxCtx *newYYY(FL_PAR,Connection *Conn,int etype){
	BufDesc *Bc;
	MuxCtx *Mc;
	MuxCtx *pMc;
	int ri;

	Bc = BUF_get("YYMUX",sizeof(MuxCtx));
	Mc = (MuxCtx*)Bc->buf_data;
	bzero(Mc,sizeof(MuxCtx));
	if( yy_gMc != 0 ){
		*Mc = *yy_gMc;
	}
	MxConn = Conn;
	pMc = lastYY(Conn);
	MxEtype = etype;
	MxYsock = -1;
	MxRsmsock = -1;
	MxPsins = -1;
	MxPsout = -1;
	MxPserr = -1;
	MxConsole = -1;
	MxLAccSock = -1;
	MxYAccSock = -1;
	MxFtpSock = -1;
	MxHttpSock = -1;
	MxVncSock = -1;
	MxDnsSock = -1;
	MxPopSock = -1;
	MxSmtpSock = -1;
	MxSocksSock = -1;
	MxRsyncSock = -1;
	for( ri = 0; ri < 30; ri++ ){
		if( 0 <= addYY(FL_BAR,ri,Conn,Mc) ){
			break;
		}
		if( endYYs(Conn,FL_BAR) == 0 ){
			msleep(1000);
		}
	}
	MxParent = pMc;
	sv1log("--newYY Y%d/%d %X Et=%X Co=%X <= %s:%d\n",MxId,
		pMc?pMc->mc_id:0,p2i(Mc),etype,p2i(Conn),FL_BAR);
	return Mc;
}
#define newYY(Conn,etype) newYYY(FL_ARG,Conn,etype)

static int YYGUID(){
	IStr(key,128);
	IStr(port,32);
	IStr(uniq,128);
	int id;

	NonceKey(AVStr(key));
	printPrimaryPort(AVStr(port));
	sprintf(uniq,"%d.%s.%s",getuid(),port,key);
	id = strCRC32(uniq,strlen(uniq));
	return id;
}
static MuxCtx *initgMc(Connection *Conn){
	MuxCtx *Mc;
	if( yy_gMc == 0 ){
		yy_gMc = Mc = newYY(Conn,0);
		MxYYGUID = YYGUID();
		MxFlags |= MX_PERSIST;
		MxRsmhold = 10*60;
		MxPingitvl = 10;
		MxRsmstart = 30;
	}
	return yy_gMc;
}
static MuxCtx *getLastMc(Connection *Conn){
	MuxCtx *Mc;
	MuxCtx *lastMc = initgMc(Conn);
	int mi;

	for( mi = 1; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc )
		if( MxConn == Conn ){
			lastMc = Mc;
			/* should check STX_yy */
		}
	}
	return lastMc;
}
static MuxCtx *getThreadMc(){
	MuxCtx *Mc;
	int mi;

	for( mi = 1; mi < elnumof(yy_Mcv); mi++ ){
		Mc = yy_Mcv[mi];
		if( Mc )
		if( Mc->mc_ytgid )
{
 fprintf(stderr,"---AA---lMc[%d]Y%d TID[%X %X g=%X]\n",mi,MxId,
 TID,Mc->mc_ytgid,getthreadgid(0));
		if( Mc->mc_ytgid == getthreadgid(0) ){
 fprintf(stderr,"---BB---lMc[%d]Y%d TID[%X %X g=%X]\n",mi,MxId,
 TID,Mc->mc_ytgid,getthreadgid(0));
			return Mc;
		}
}
	}
	return 0;
}

int scan_yyopts(Connection *Conn,PCStr(arg)){
	MuxCtx *Mc = initgMc(Conn);
	MxFlags = scan_yopts(Mc,Conn,MxFlags,arg);
	return MxFlags;
}
void scan_YYCONF(Connection *Conn,PCStr(conf)){
	MuxCtx *Mc = initgMc(Conn);
	IStr(nam,128);
	IStr(val,1024);

	fieldScan(conf,nam,val);
	if( streq(nam,"YYUID") ){
		sprintf(MxYYUID,"%s=%s",nam,val);
	}else
	if( streq(nam,"CHROOT") ){
	}else
	if( streq(nam,"OWNER") ){
	}else
	if( streq(nam,"HOME") ){
		sprintf(MxUserHOME,"HOME=%s",val);
	}else
	if( streq(nam,"PATH") ){
		sprintf(MxUserPATH,"PATH=%s",val);
	}else
	if( streq(nam,"LD_LIBRARY_PATH") ){
		sprintf(MxUserLD_PATH,"%s=%s",nam,val);
	}else
	if( streq(nam,"SHELL") ){
		sprintf(MxUserSHELL,"SHELL=%s",val);
	}else
	if( streq(nam,"PROMPT") ){
		sprintf(MxUserPROMPT,"PS1=%s",val);
	}else
	if( streq(nam,"HISTFILE") ){
		sprintf(MxUserHISTFILE,"%s=%s",nam,val);
	}else
	if( streq(nam,"STLS") ){
		MxFlags |= MX_STLS;
	}else
	if( streq(nam,"persistent") ){
		MxFlags |= MX_PERSIST;
		MxRsmhold = (UInt)Scan_period(val,'m',(double)0);
	}else
	if( streq(nam,"sttyraw") ){
		strcpy(MxSttyRaw,val);
	}else
	if( streq(nam,"forkpty") ){
		strcpy(MxForkPty,val);
	}else
	if( streq(nam,"accept") ){
		IStr(host,128);
		int port = 0;
		strcpy(host,"0.0.0.0");
		MxYAccSock = server_open("yyacc",AVStr(host),port,64);
		sv1log("----YaccSock[%d]\n",MxYAccSock);
	}else
	{
	}
}

static const char *yy_YYMUX_MAP = "YYMUX";
static int yy_withYYMUX;
void scan_YYMUX(Connection *Conn,PCStr(conf)){
	MuxCtx *Mc = initgMc(Conn);
	IStr(host,MaxHostNameLen);
	IStr(sport,128);
	int port = serviceport("yymux");
	IStr(cmap,MaxHostNameLen);
	IStr(xcmap,MaxHostNameLen);

	yy_withYYMUX++;
	Xsscanf(conf,"%[^:]:%[^:]:%[^\n]",AVStr(host),AVStr(sport),AVStr(cmap));
	port = atoi(sport);
	if( cmap[0] == 0 ){
		strcpy(cmap,"*:*:*");
	}
	sprintf(xcmap,"{%s:%s}:%s",host,sport,cmap);
	scan_CMAP2(Conn,yy_YYMUX_MAP,xcmap);
	sv1log("--yyMUX=%s\n",xcmap);
}
static int find_YYMUX(Connection *Conn,void *cty,PVStr(host),int *port){
	IStr(yymux,MaxHostNameLen);
	IStr(sport,128);
	MuxCtx *Mc = (MuxCtx*)cty;
	int cf;

	if( 0 <= find_CMAP(Conn,yy_YYMUX_MAP,AVStr(yymux)) ){
		*port = serviceport("yymux");
		Xsscanf(yymux,"%[^:]:%s",AVStr(host),AVStr(sport));
		sscanf(sport,"%d",port);
		if( *port == DST_PORT && hostcmp(host,DST_HOST) == 0 ){
			MuxCtx *Mc = (MuxCtx*)cty;
			if( Mc == 0 || Mc && !MxInRESUME ){
				/* don't try connect it via it self */
 yprintf(Mc,"#### YYMUX SELF %s:%d <= {%s}%X",DST_HOST,DST_PORT,yymux,p2i(Mc));
				return 0;
			}
 zprintf(Mc,"#### YYMUX RSM %s:%d <= {%s}",DST_HOST,DST_PORT,yymux);
		}
		sv1log("--FOUND YYMUX=%s <= %s://%s:%d\n",yymux,
			DST_PROTO,DST_HOST,DST_PORT);
		if( isinListX(sport,"ssl","/")
		 || isinListX(sport,"ssl",".")
		){
			cf = ConnectFlags;
			cf = scanConnectFlags("YYMUX",sport,cf);
			ConnectFlags = cf;
 yprintf(Mc,"#### YYMUX over SSL {%s}",yymux);
		}
		return 1;
	}
	return 0;
}
static int find_YYMUXX(Connection *Conn,void *cty,PCStr(dproto),PCStr(dhost),int dport,PVStr(host),int *port){
	Port sv;
	int sock;

//sv1log("###find----A[%s %s %d][%s %s %d]\n",DST_PROTO,DST_HOST,DST_PORT,dproto,dhost,dport);
	sv = Conn->sv;
	strcpy(REAL_PROTO,dproto);
	strcpy(REAL_HOST,dhost);
	REAL_PORT = dport;
//sv1log("###find----B[%s %s %d][%s %s %d]\n",DST_PROTO,DST_HOST,DST_PORT,dproto,dhost,dport);
	sock = find_YYMUX(Conn,cty,BVStr(host),port);
	Conn->sv = sv;
//sv1log("###find----C[%s %s %d][%s %s %d]\n",DST_PROTO,DST_HOST,DST_PORT,dproto,dhost,dport);
	return sock;
}

static int netTail(int itvl,PCStr(file),FILE *inf,FILE *out,FILE *cin){
	double Start = Time();
	FILE *fpv[2];
	int fdv[2];
	IStr(cmd,128);
	int rdy;
	IStr(buf,8*1024);
	int rcc,wcc;
	int ino0,ino,nino;

	ino0 = ino = file_ino(fileno(inf));
	for(;;){
		rdy = fPollIn(cin,itvl);
		if( rdy < 0 ){
			break;
		}
		if( 0 < rdy ){
			if( fgets(cmd,sizeof(cmd),cin) == 0 ){
				break;
			}
			/* change the parameters (itvl) */
		}
		rcc = fread(buf,1,sizeof(buf),inf);
		if( 0 < rcc ){
			wcc = fwrite(buf,1,rcc,out);
			if( wcc < rcc ){
				break;
			}
			if( fflush(out) == EOF ){
				break;
			}
		}else{
			nino = File_ino(file);
			if( ino != nino ){
				/* reopen or exit */
				ino = nino;
			}
			clearerr(inf);
		}
	}
	sv1log("----netTail DONE (%.2f)\n",Time()-Start);
	return 0;
}
int yycommand_main(int ac,const char *av[]){
	int ai;
	const char *a1;
	const char *com = 0;
	const char *opt = 0;
	const char *file = 0;
	IStr(lsfmt,128);
	int opt_p = 0;
	int opt_f = 0;
	FILE *fp;
	IStr(buf,4*1024);

	strcpy(lsfmt,"%T %8S %D %N");
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		/*
		fprintf(stderr,"--[%d]%s\n",ai,a1);
		*/
		if( *a1 == '-' ){
			switch( a1[1] ){
				case 'p':
					opt_p = 1;
					break;
				case 'H': /* data is prfixed with a HTTP header */
					break;
				case 'f':
					opt_f = atoi(a1+2);
					if( opt_f == 0 ){
						opt_f = 1000;
					}else
					if( opt_f < 100 ){
						opt_f = 100;
					}else
					if( 10*1000 < opt_f ){
						opt_f = 10*1000;
					}
					break;
				defalut:
					opt = a1;
					break;
			}
		}else{
			if( com == 0 )
				com = a1;
			else
			if( file == 0 )
				file = a1;
		}
	}
	if( com == 0 || file == 0 ){
		fprintf(stderr,"--Usage: [-options] command file\r\n");
		return -1;
	}
	if( strpbrk(file,"/\\:") ){
		fprintf(stderr,"--ForbiddenFileName: %s\r\n",file);
		return -2;
	}
	if( streq(com,".lst") ){
		if( File_is(file) ){
			putenv("LSTFMT=%y%m%d-%H%M%S");
			ls_unix(stdout,opt?opt:"",AVStr(lsfmt),file,NULL);
		}else{
			fprintf(stderr,"--Not found: %s\r\n",file);
		}
	}else
	if( streq(com,".get") ){
		if( fp = fopen(file,"r") ){
			copyfile1(fp,stdout);
			fflush(stdout);
			if( opt_f ){
				/* get -f : streaming as tail -f */
				netTail(opt_f,file,fp,stdout,stdin);
			}
			fclose(fp);
		}else{
			fprintf(stderr,"--Cannot open: %s\r\n",file);
		}
	}else
	if( streq(com,".put") ){
		if( File_is(file) ){
			/* rename to file~ */
		}
		if( fp = fopen(file,"w") ){
			copyfile1(stdin,fp);
			fclose(fp);
		}else{
			fprintf(stderr,"--Cannot open: %s\r\n",file);
		}
	}else
	if( streq(com,".add") ){
		if( fp = fopen(file,"a") ){
			copyfile1(stdin,fp);
			fclose(fp);
		}else{
			fprintf(stderr,"--Cannot open: %s\r\n",file);
		}
	}else
	if( streq(com,".del") ){
	}else
	{
		fprintf(stderr,"--unknown yycommand [%s]\r\n",com);
	}
	fflush(stdout);
	return 0;
}
int spawnv_self1(int aac,const char *aav[]);
static int isyycom(PCStr(path)){
	if( streq(path,".lst")
	 || streq(path,".get")
	 || streq(path,".put")
	 || streq(path,".add")
	 || streq(path,".del")
	 || streq(path,".socksd")
	 || streq(path,".yymuxd")
	 || streq(path,".httpd")
	 || streq(path,".ftpd")
	){
		return 1;
	}
	return 0;
}
static int bgexecyy(PCStr(path),char *av[],char *ev[],int *ph){
	int rcode;
	if( isyycom(path) ){
		const char *nav[512];
		int nac = 0;
		int pid;
		int ac;

		nav[nac++] = "-Fyycommand";
		for( ac = 0; av[ac]; ac++ ){
			nav[nac++] = av[ac];
		}
		nav[nac] = 0;
		if( isWindows() ){
			pid = *ph = spawnv_self1(nac,nav);
		}else{
			if( (pid = fork()) == 0 ){
				yycommand_main(nac,nav);
				_exit(0);
			}
		}
		*ph = pid;
		return pid;
	}
	rcode = bgexecX("e",path,av,ev,ph);
	return rcode;
}
int yybgexec(MuxCtx *Mc,PCStr(path),char *av[],char *ev[],int *ph){
	int pins[2],pout[2],perr[2];
	int sins,sout,serr;
	int rcode;

	if( MxFlagsVERBOSE ){
		int ai;
		sv1log("--YY bgexec(%s)\n",path);
		for( ai = 0; av[ai]; ai++ ){
			sv1log("--YY arg[%d] %s\n",ai,av[ai]);
		}
	}
	if( 1 ){
		if( isWindows() ){
		}else{
			Socketpair(pins); sins = dup(0); dup2(pins[0],0);
			Socketpair(pout); sout = dup(1); dup2(pout[1],1);
			Socketpair(perr); serr = dup(2); dup2(perr[1],2);
		}
	}
	rcode = bgexecyy(path,av,ev,ph);
	if( 1 ){
		if( isWindows() ){
		}else{
			dup2(sins,0); close(sins); close(pins[0]);
			dup2(sout,1); close(sout); close(pout[1]);
			dup2(serr,2); close(serr); close(perr[1]);

			MxPsins = pins[1]; FD_new(MxPsins,"Stdins",0);
//setsockbuf(MxPsins,0,128*1024);
 			MxPsout = pout[0]; FD_new(MxPsout,"Stdout",0);
//setsockbuf(MxPsout,128*1024,0);
			MxPserr = perr[0]; FD_new(MxPserr,"Stderr",0);
		}
	}
	return rcode;
}

/*
salvaging the YY server-side dangling processes
- client-side down without shutdown of YYChannel
- the peer process at the server-side waits untill the timeout
- keep a activeList on the client-side
  + each connction is represented as "yymux-ddddd-ddddd-uuuuu"
    in the list (yymux-pid-port-key)
  + client sends the list with "Y-Connection: salvage; key=uuuuu"
  + server forward it as       "Y-Connection; finish; key=uuuuu"
  + if succeeded, it returns   "Y-Connection; cleared;"
  + when received "cleared" then remove it from the salvage-list
 */
static void activeList(PVStr(path)){
	sprintf(path,"${ADMDIR}/yymux");
	Substfile(path);
}
static const char *YYPFX = "yymux.";
static void salvageFile(MuxCtx *Mc,PVStr(path),int port,int key){
	activeList(AVStr(path));
	strcat(path,"/");
	Xsprintf(TVStr(path),"%s%05u.%010u",YYPFX,port,key);
}
static int scanSlvg(PCStr(file),int *port,int *key){
	int nc;
	nc = sscanf(file,"yymux.%u.%u",port,key);
	return nc;
}
#define salvageClnt(Mc,cstat,port,key) salvageClnt_FL(FL_ARG,Mc,cstat,port,key) 
static void salvageClnt_FL(FL_PAR,MuxCtx *Mc,int cstat,int port,int key){
	FILE *fp;
	IStr(date,128);
	IStr(path,256);
	int rcode = -99;

	salvageFile(Mc,TVStr(path),port,key);
	if( MxFlagsVERBOSE ){
		sv1log("##SLVG %s:%d shut=%X stat=%X:%X %u.%u is=%d\n",FL_BAR,
			MxShutting,MxRsmstate,cstat,port,key,File_is(path));
	}
	if( port == 0 ){
		return;
	}
	switch( cstat ){
	    case CST_INITIAL: /* save for salvage */
	    case CST_RESUME:
		if( fp = dirfopen("SLVG",AVStr(path),"a") ){
			StrftimeLocal(AVStr(date),sizeof(date),"%y-%m-%d-%H-%M-%S",
				time(0),0);
			fprintf(fp,"%u %6d %s %05u %010u %s\r\n",itime(0),getpid(),
				date,port,key,MxDstHost);
			fclose(fp);
			chmod(path,0600);
		}
		if( MxFlagsVERBOSE ){
			sv1log("##SLVG %X %s created=%X\n",cstat,path,p2i(fp));
		}
		break;
	    case CST_CLEARED: /* remove salvaged */
	      if( File_is(path) ){
		if( fp = dirfopen("SLVG",AVStr(path),"a") ){
			/* "a" means this file writable by this user ? */
			/* but it might be created by the dirfopen() */
			fclose(fp);
			rcode = unlink(path);
		}
		if( MxFlagsVERBOSE ){
			sv1log("##SLVG %X %s unlinked=%X\n",cstat,path,rcode);
		}
	      }
	}
}
static int aliveMux(int pid,int port,int key){
	if( procIsAlive(pid) ){
	    if( pid == getpid() ){
		if( findYYxRsmport(port,key) ){
			return 2;
		}else{
			sv1log("==== not aliveMux2 port=%d key=%u\n",port,key);
			return 0;
		}
	    }
	    return 1;
	}else{
	    sv1log("==== not aliveMux1 port=%d key=%u\n",port,key);
	    return 0;
	}
}
static scanDirFunc putslvg(PCStr(file),MuxCtx *Mc,PCStr(dir),FILE *ts,int *rem){
	int key = 0,port = 0;
	int start = -1;
	int pid = -1;
	IStr(path,256);
	FILE *fp;
	int ne = -1;

	if( *rem <= 0 ){
		return -1;
	}
	if( strneq(file,YYPFX,strlen(YYPFX)) ){
		scanSlvg(file,&port,&key);
		sprintf(path,"%s/%s",dir,file);
		ne = -1;
		start = -1;
		pid = -1;
		if( fp = fopen(path,"r") ){
			ne = fscanf(fp,"%u %u",&start,&pid);
			fclose(fp);
		}
		if( ne <= 0 ){
			sv1log("--bad file %s\n",file);
			unlink(path);
		}else
		if( pid <= 0 ){
			sv1log("--bad pid %d, %s\n",pid,file);
		}else
		/*
		if( procIsAlive(pid) ){
		*/
		if( aliveMux(pid,port,key) ){
			sv1log("--alive process %d, %s\n",pid,file);
		}else{
 lfprintf("Salvage",ts,"Y-Connection: %s; yyid=%08X; hold=0; key=%010u; port=%u",
	CS_SALVAGE,MxYYGUID,key,port);
			*rem -= 1;
		}
	}
	return 0;
}
static void putSalvageList(PCStr(wh),MuxCtx *Mc,FILE *ts){
	IStr(path,256);
	int rem = 7;

	activeList(AVStr(path));
	Scandir(path,scanDirCall putslvg,Mc,path,ts,&rem);
}
static void clearYConnection(PCStr(wh),MuxCtx *Mc){
	int ci;
	for( ci = 1; ci < elnumof(MxRsmv); ci++ ){
		if( MxRsmv[ci].rsm_state ){
			MxRsmv[ci].rsm_state = 0;
		}
	}
}
static void putYConnection(PCStr(wh),int gen,MuxCtx *Mc,FILE *ts){
	const char *state = "Initial";
	int ci;

	switch( MxRsmstate ){
		default:
		case CST_INITIAL: state = CS_INITIAL; break;
		case CST_RESUME:  state = CS_RESUME;  break;
		case CST_SALVAGE: state = CS_SALVAGE; break;
		case CST_FINISH:  state = CS_FINISH;  break;
		case CST_EXITING: state = CS_EXITING;  break;
		case CST_CLEARED: state = CS_CLEARED; break;
	}
 lfprintf(wh,ts,"Y-Connection: %s; yyid=%08X; hold=%d; key=%010u; port=%d; count=%d",
	state,MxRsmYYGUID,MxRsmhold,MxRsmkey,MxRsmport,MxRsmcnt);
	if( gen ){
		putSalvageList(wh,Mc,ts);
	}
	for( ci = 1; ci < elnumof(MxRsmv); ci++ ){
		if( MxRsmv[ci].rsm_state == CST_CLEARED ){
 lfprintf(wh,ts,"Y-Connection: %s; yyid=%08X; hold=0; key=%010u; port=%d",
	CS_CLEARED,MxRsmv[ci].rsm_yyguid,MxRsmv[ci].rsm_key,MxRsmv[ci].rsm_port);
		}
		if( MxRsmv[ci].rsm_state == CST_EXITING ){
 lfprintf(wh,ts,"Y-Connection: %s; yyid=%08X; hold=0; key=%010u; port=%d",
	CS_EXITING,MxRsmv[ci].rsm_yyguid,MxRsmv[ci].rsm_key,MxRsmv[ci].rsm_port);
		}
	}
}
int setREUSEADDR(int on);
static int openRsmPort(PCStr(wh),MuxCtx *Mc,int port){
	int sock;
	int reuse;
	IStr(host,64);

	strcpy(host,"127.0.0.1");
	reuse = setREUSEADDR(0);
	sock = server_open(wh,AVStr(host),port,1);
	setREUSEADDR(reuse);
	return sock;
}
static int salvageServ(MuxCtx *Mc,int cstat,int hold,int key,int port){
	int sock;
	FILE *ts;
	FILE *fs;

	sock = openRsmPort("test-yyRsmPort",Mc,port);
	if( 0 <= sock ){ /* not used */
		close(sock);
		cstat = CST_CLEARED;
	}else{
		sock = client_open("yymux","yyRsmport","127.0.0.1",port);
		if( sock < 0 ){
			sv1log("#### FATAL cannot open Rsmport[%d]\n",sock);
		}else{
			/* send SHUT and set CLEARED if succeeed */
			ts = fdopen(sock,"w");
			fs = fdopen(sock,"r");
			lfprintf("Salvage",ts,"%s x HTTP/1.0",YY_CON);
 lfprintf("Salvage",ts,"Y-Connection: %s; yyid=%08X; hold=0; key=%010u; port=%d",
	CS_FINISH,MxYYGUID,key,port);
			lfprintf("Salvage",ts,"",YY_CON);
			fflush(ts);

			/* get resp */
			/* CST_CLEARED if succeed (but may take a time) */
			/* CST_CLEARED if bad-key returned (reused port) */

			cstat = CST_EXITING;
			fcloseFILE(ts);
			fcloseFILE(fs);
			close(sock);
		}
	}
	return cstat;
}
static int scanYConnection(PCStr(wh),int isclient,MuxCtx *Mc,PCStr(opt),int filter){
	IStr(state,32);
	int hold = 0,key = 0,port = 0,count = 0,cstat = 0,yyid = 0;
	int ci;
	int co = 0;

	if( !strncaseeq(opt,"Y-Connection:",13) ){
		return 0;
	}
Xsscanf(opt,"Y-Connection: %[^;]; yyid=%X; hold=%d; key=%u; port=%d; count=%d",
AVStr(state),&yyid,&hold,&key,&port,&count);

	cstat = CST_INITIAL;
	if( strcaseeq(state,CS_INITIAL) ) cstat = CST_INITIAL; else
	if( strcaseeq(state,CS_RESUME ) ) cstat = CST_RESUME; else
	if( strcaseeq(state,CS_SALVAGE) ) cstat = CST_SALVAGE; else
	if( strcaseeq(state,CS_FINISH ) ) cstat = CST_FINISH; else
	if( strcaseeq(state,CS_EXITING) ) cstat = CST_EXITING; else
	if( strcaseeq(state,CS_CLEARED) ) cstat = CST_CLEARED;
	if( isclient ){
		salvageClnt(Mc,cstat,port,key);
	}
	if( filter && (filter & cstat) == 0 ){
 svlog("Y-Connection %s[%s] state=%X, hold=%d, yyid=%X,key=%u,port=%d *%d\n",
 wh,"IGNORED",cstat,hold,yyid,key,port,count);
		return 0;
	}
	if( cstat == CST_INITIAL || cstat == CST_RESUME || cstat == CST_FINISH ){
		co = 0;
	}else{
		if( isclient ){
		}else{
			if( cstat == CST_SALVAGE ){
				cstat = salvageServ(Mc,cstat,hold,key,port);
			}
		}
		for( ci = 0;  ci < elnumof(MxRsmv); ci++ ){
			if( MxRsmv[ci].rsm_state == 0 ){
				co = ci;
				break;
			}
		}
	}
 svlog("Y-Connection %s[%d] state=%X, hold=%d, yyid=%X,key=%u,port=%d *%d\n",
 wh,co,cstat,hold,yyid,key,port,count);
	MxRsmv[co].rsm_state = cstat;
	MxRsmv[co].rsm_hold = hold;
	MxRsmv[co].rsm_yyguid = yyid;
	MxRsmv[co].rsm_key = key;
	MxRsmv[co].rsm_port = port;
	MxRsmv[co].rsm_count = count;
	return 1;
}

static int DHKG = 2;
int hextoStr(PCStr(hex),PVStr(bin),int siz);
static void YYinitCredhy(MuxCtx *Mc){
	MxCredhyKeyLen = 0;
	CredhyInit(MxCredhy,DHKG);
}
void strCRC64(int crc[2],PCStr(str),int len);
static int generateCredhyKey(MuxCtx *Mc,FILE *fp,PCStr(wh),int force){
	IStr(tmp,512);

	MxStatDHKSENT = 1;
	if( MxCredhyKeyLen == 0 ){
		CredhyInit(MxCredhy,DHKG);
		MxCredhy[0].k_flags |= CR_AKFIRST | CR_CRC32;
		MxCredhyKeyLen = CredhyGenerateKey(MxCredhy,AVStr(MxCredhyKey),
			sizeof(MxCredhyKey));
	}
	if( fp ){
		strtoHex(MxCredhyKey,MxCredhyKeyLen,AVStr(tmp),sizeof(tmp));
		YYlfprintf(Mc,wh,fp,"Y-Credhy-Key: %s",tmp);
		MxCredhyKeyCRCs = strCRC32(tmp,strlen(tmp));
	}
	return 0;
}
static int agreedCredhyKey(MuxCtx *Mc,PCStr(wh),PCStr(key)){
	IStr(bkey,256);
	int len;
	int err;

	MxStatDHKRECV = 1;
	len = hextoStr(key,AVStr(bkey),sizeof(bkey));
	MxCredhyKeyCRCr = strCRC32(key,strlen(key));
	err = CredhyAgreedKey(MxCredhy,bkey);
	if( err == 0 ){
		Verbose("--yy Credhy Agreed: len=%d crc=%X\n",
			MxCredhy[0].k_leng,MxCredhy[0].k_crc8);
		return 0;
	}else{
		sv1log("--yy FATAL Credhy Not Agreed: e%d\n",err);
		return 0;
	}
}
int isinSSL(int fd);
static int scanYYresponse(PCStr(wh),MuxCtx *Mc,FILE *fs,int contcont){
	IStr(resp,512);
	refQStr(rp,resp);
	IStr(name,256);
	IStr(body,512);
	int hi;
	int hcode = -1;
	double St = Time();

	clearVStr(MxServstat);
	MxServcode = 0;
	if( PollIn(fileno(fs),1000) ){
//yprintf(Mc,"#### YY response ready: alv=%d",IsAlive(fileno(fs)));
		if( isinSSL(fileno(fs)) ){
		}
	}
	for( hi = 0; ; hi++ ){
		if( fPollIn(fs,0) <= 0 ){
			sv1log("--yy scanYY (%.2f) SIG=%d eof=%d e%d\n",
				Time()-St,yy_gotSIG,feof(fs),errno);
			if( feof(fs) ){
				break;
			}
			if( 1 < yy_gotSIG ){
				break;
			}
			if( 10 < Time()-St ){
				break;
			}
			continue;
		}
		if( fgets(resp,sizeof(resp),fs) == NULL ){
			if( hi == 0 ){
				Connection *Conn = MxConn;
 yprintf(Mc,"#### server [%s:%d] disconnected without response",
					MxServ,MxServport);
				return -1;
			}
			break;
		}
		fieldScan(resp,name,body);
		if( rp = strpbrk(resp,"\r\n") ){
			clearVStr(rp);
		}
		YYlogComm(Mc,"s---","R",resp);
		if( *resp == 0 || *resp == '\r' || *resp == '\n' ){
			if( MxServcode == 100 && contcont ){
				sv1log("----Cont on 100: %s\n",MxServstat);
				clearVStr(MxServstat);
				MxServcode = 0;
				continue;
			}
			break;
		}
		if( MxServstat[0] == 0 ){
			strcpy(MxServstat,resp);
			sscanf(MxServstat,"HTTP/%*s %d",&hcode);
			MxServcode = hcode;
		}
		if( strncaseeq(resp,"Y-Version:",10) ){
			lineScan(resp+10,MxServyver);
		}
		if( streq(name,"Y-Credhy-Key") ){
			generateCredhyKey(Mc,0,"yyResp",0);
			agreedCredhyKey(Mc,"Req",body);
		}
		if( strcaseeq(name,"Y-Server") ){
			if( strstr(body,"origin=") ){
				//MxFlags |= MX_ORIGIN_R;
			}
		}
		if( strcaseeq(name,"X-DISPLAY-2") ){
			strcpy(MxServDISPLAY,body);
		}
		if( strncaseeq(resp,"Y-Connection:",13) ){
			scanYConnection("R",1,Mc,resp,0);
		}
		if( strcaseeq(name,YH_ACCPORT) ){
			Xsscanf(body,"%[^:]:%d",AVStr(MxRAccHost),&MxRAccPort);
		}
		if( strcaseeq(name,YH_SRCPORT) ){
			Xsscanf(body,"%[^:]:%d",AVStr(MxRSrcHost),&MxRSrcPort);
		}
	}
	sscanf(MxServstat,"HTTP/%*s %d",&hcode);
	if( hcode < 0 || 300 <= hcode ){
 yprintf(Mc,"#### YY bad resp. code: %s",MxServstat);
		return -3;
	}
	if( !strcaseeq(MxServyver,myYYVER) ){
 yprintf(Mc,"#### YY server response: %s",MxServstat);
 yprintf(Mc,"#### YY version mismatch: %s %s",MxServyver,myYYVER);
		return -2;
	}
	return 0;
}

static const char CredhyBasic[] = "Credhy-Basic";
static int genEBasic(Credhy *Cre,PCStr(aup),PVStr(ebasic)){
	IStr(eaup,256);
	int len,xlen;

	len = strlen(aup);
	xlen = CredhyAencrypt(Cre,aup,AVStr(eaup),sizeof(eaup));
	sprintf(ebasic,"%s %s",CredhyBasic,eaup);
	return 1;
}
static int EBasic2Basic(Credhy *Cre,PVStr(fval)){
	IStr(tenc,256);
	IStr(eaup,128);
	IStr(aup,128);
	IStr(b64,128);
	int len;
	int crc;
	int icrc = 0;

	if( !strneq(fval,CredhyBasic,strlen(CredhyBasic)) ){
		return 0;
	}
	if( Cre->k_leng <= 0 ){
		return -1;
	}
	Xsscanf(fval,"%*s %s %X",AVStr(tenc),&icrc);
	len = CredhyAdecrypt(Cre,tenc,AVStr(aup),sizeof(aup));
	sv1log("-- %s %s len=%d\n",CredhyBasic,tenc,len);
	if( len < 0 ){
		return -2;
	}
	str_to64(aup,strlen(aup),AVStr(b64),sizeof(b64),1);
	sprintf(fval,"Basic %s",b64);
	return 1;
}
int HTTP_getAuthorizationX(Connection *Conn,int proxy,AuthInfo *ident,int decomp,PCStr(aauth));
static int sendYYKEY(MuxCtx *Mc,FILE *ts){
	RSACtx *rsa;
	IStr(key,512);
	IStr(ekey,512);
	IStr(xekey,1024);
	int elen;

	if( (MxAuthFlags & MA_YYKEYr) == 0 ){
		return 0;
	}
	rsa = _RSA_new();
	if( _RSA_avail(rsa) == 0 ){
 fprintf(stderr,"----send: NO local RSA KEY\n");
		return -1;
	}
	sprintf(key,"%08X.MyKey",MxCredhyKeyCRCr);
	elen = _RSA_encrypt(rsa,key,strlen(key),AVStr(ekey),sizeof(ekey),0);
	strtoHex(ekey,elen,AVStr(xekey),sizeof(xekey));
	YYlfprintf(Mc,"YYKEY",ts,"Authorization: YYKEY %s",xekey);
	return 1;
}
static int scanYYKEY(MuxCtx *Mc,PCStr(xekey)){
	RSACtx *rsa;
	IStr(ekey,512);
	IStr(key,512);
	int elen;
	int dlen;

	rsa = _RSA_new();
	if( _RSA_avail(rsa) == 0 ){
 fprintf(stderr,"----recv: NO local RSA\n");
		return -1;
	}
	elen = hextoStr(xekey,AVStr(ekey),sizeof(ekey));
	dlen = _RSA_decrypt(rsa,ekey,elen,AVStr(key),sizeof(key),0);
	if( dlen <= 0 ){
 fprintf(stderr,"----recv: cannot decrypt KEY by RSA\n");
		return -2;
	}

 yprintf(Mc,"---- auth. YYKEY %s %X",key,MxCredhyKeyCRCs);

	MxAuthOK = 1;
	return 1;
}
static int scanAuthorization(MuxCtx *Mc,PCStr(req)){
	Connection *Conn = MxConn;
	IStr(fnam,32);
	IStr(fval,1024);
	IStr(atype,32);
	IStr(avalue,1024);

	fieldScan(req,fnam,fval);
	Xsscanf(fval,"%s %s",AVStr(atype),AVStr(avalue));
	if( strcaseeq(atype,"YYKEY") ){
		scanYYKEY(Mc,avalue);
		return 1;
	}

	strcpy(MxAutho,req);
	if( MxWithAuth ){
		EBasic2Basic(MxCredhy,AVStr(fval));
		HTTP_getAuthorizationX(Conn,1,&ClientAuth,4,fval);
		if( 0 <= doAuth(Conn,&ClientAuth) ){
			MxAuthOK = 1;
			return 1;
		}
	}
	return 0;
}
static int sendAuthenticate(MuxCtx *Mc,PCStr(wh),FILE *tp){
	if( MxAuthFlags & MA_YYKEY ){
		YYlfprintf(Mc,wh,tp,"Authenticate: YYKEY nonce=%08X",
			trand1(0xFFFFFFFF));
	}
	return 0;
}
static int scanAuthenticate(MuxCtx *Mc,PCStr(auth)){
	IStr(atype,128);

	wordScan(auth,atype);
	if( strcaseeq(atype,"YYKEY") ){
		MxAuthFlags |= MA_YYKEYr;
	}
	return 0;
}

/* receive arguments and evironments */
char *fgetsByLine(PVStr(line),int lsiz,FILE *in,int timeout,int *rccp,int *isbinp);
static int scanYYrequest(MuxCtx *Mc,int maxac,const char *av[],int ac,FILE *fc){
	Connection *Conn = MxConn;
	IStr(req,512);
	refQStr(rp,req);
	IStr(nam,128);
	IStr(val,512);
	const char *a1;
	IStr(auth,512);
	int hi;
	int rcc;
	int bin;

	MxWithAuth = CTX_withAuth(Conn);
	for( hi = 0; ; hi++ ){
		/*
		if( fgets(req,sizeof(req),fc) == NULL ){
		*/
		if( fgetsByLine(AVStr(req),sizeof(req),fc,10*1000,&rcc,&bin) == NULL ){
			break;
		}
		if( *req == '\r' || *req == '\n' ){
			break;
		}
		if( rp = strpbrk(req,"\r\n") ){
			clearVStr(rp);
		}
		sv1log("--YY Q %s\n",req);
		fieldScan(req,nam,val);
		if( strncaseeq(req,"Y-Version:",10) ){
			lineScan(req+10,MxClntyver);
		}
		if( strncaseeq(req,"Y-Connection:",13) ){
			if( scanYConnection("Q",0,Mc,req,0) ){
				MxFlags |= MX_PERSIST;
			}
		}
		if( strncaseeq(req,"Y-Max-Pending:",14) ){
			MxMaxPending = atoi(req+14);
		}
		if( strcaseeq(nam,"Y-HOLDONNX") ){
			MxClntHOLDONNX = atoi(val);
		}
		if( strneq(req,"X-Arg:",6) ){
			if( ac < maxac ){
				a1 = req + 6;
				if( *a1 == ' ' ) a1++;
				av[ac++] = MxStralloc(Mc,a1);
				if( streq(a1,"-display") ){
					MxForbidden = "WithDisplay";
				}
			}
		}
		if( strneq(req,"X-Env:",6) ){
		}
		if( streq(nam,"Y-Credhy-Key") ){
			agreedCredhyKey(Mc,"Resp",val);
		}
		if( strncaseeq(req,"Authorization:",14) ){
			scanAuthorization(Mc,req);
		}
	}
	av[ac] = 0;
	if( MxWithAuth && MxAuthOK == 0 ){
		MxAuthErr = 1;
	}
	return ac;
}

int enCreysX(PCStr(opts),PCStr(pass),PCStr(str),int slen,PVStr(estr),int esiz);
int deCreys(PCStr(opts),PCStr(pass),PCStr(estr),PVStr(dstr),int esiz);
int getCRYPTkey(Connection *Conn,int clnt,PVStr(ckey),int ksiz);

static void clearMyAuth(MuxCtx *Mc){
	bzero(MxMyAuth,sizeof(MxMyAuth));
}
static int setMyAuth(MuxCtx *Mc,PCStr(user),PCStr(pass)){
	IStr(aub,256);

	sprintf(aub,"%s:%s",user,pass);
	enCreysX("b","",aub,strlen(aub)+1,AVStr(MxMyAuth),sizeof(MxMyAuth));
	return 0;
}
static int getMyAuth(MuxCtx *Mc,PVStr(aub),int asiz){
	IStr(nonce,128);

	if( MxMyAuth[0] ){
		deCreys("b","",MxMyAuth,BVStr(aub),asiz);
		return 1;
	}
	return 0;
}
static int genAutho(MuxCtx *Mc){
	Connection *Conn = MxConn;
	IStr(aup,256);
	IStr(b64,1024);
	refQStr(bp,b64);
	const char *host = DST_HOST;
	int port = DST_PORT;

	sv1log("**YY Auth. for %s://%s:%d\n",DST_PROTO,DST_HOST,DST_PORT);
	if( getMyAuth(Mc,AVStr(aup),sizeof(aup))
	 || get_MYAUTH(Conn,AVStr(aup),DST_PROTO,host,port)
	 || get_MYAUTH(Conn,AVStr(aup),"yymux",host,port)
	 || get_MYAUTH(Conn,AVStr(aup),"yy",host,port)
	){
		if( MxCredhy[0].k_leng ){
			genEBasic(MxCredhy,aup,AVStr(b64));
			sprintf(MxAutho,"Authorization: %s",b64);
			return 2;
		}
		str_to64(aup,strlen(aup),AVStr(b64),sizeof(b64),1);
		if( bp = strpbrk(b64,"\r\n") )
			clearVStr(bp);
		sprintf(MxAutho,"Authorization: Basic %s",b64);
		return 1;
	}else{
		return 0;
	}
}
static void putAutho(PCStr(wh),MuxCtx *Mc,FILE *ts){
	if( MxAutho[0] ){
		YYlfprintf(Mc,wh,ts,"%s",MxAutho);
	}
}
static void sendYYUID(PCStr(wh),MuxCtx *Mc,FILE *ts){
	IStr(yyuid,128);
	int sec,usec;

	if( MxYYUID[0] ){
		strcpy(yyuid,MxYYUID);
	}else{
		/* generate yyuid and store */
		sec = Gettimeofday(&usec);
		StrftimeGMT(AVStr(yyuid),sizeof(yyuid),"%y%m%d-%H%M%S",
			sec,usec);
		Xsprintf(TVStr(yyuid),"-%06d",trand1(999999));
	}
	YYlfprintf(Mc,wh,ts,"Y-YYUID: %s",yyuid);
}

/*
 * YMUX -- a minimum multiplexer
 */
/* YMUX message size: header and body */
#define PHSIZE 8	/* header size (fixed), see enPack() */
#define PBSIZE 16*1024	/* max. body size */

#define MUX_OFF 0
#define MUX_ON 1

#define MAXSES	64	/* max. parallel connections */

/* internal status for the inner connection over YYMUX */
enum _ConyFlag {
	CF_PAUSING     = 0x0001, /* suppress polling */
	CF_LAZY        = 0x0002, /* lazy activation */
	CF_GETABORT    = 0x0004, /* to be discarded on ABORT */
	CF_DISCARDING  = 0x0008, /* discardeding */
	CF_NODEFLATE   = 0x0010, /* don't apply deflate/ZLib */
	CF_NONBLKSEND  = 0x0020, /* do non-block send() */
	CF_WAITOUT     = 0x0040, /* waiting output become ready */
	CF_SUSPEND     = 0x0080, /* waiting remote output (RCPT) */
	CF_SENTRSET    = 0x0100, /* sent RSET to remote */
	CF_GOTRSET     = 0x0200, /* got RSET from remote */
	CF_UDPACC      = 0x1000, /* UDP client side */
	CF_UDP_CL      = 0x2000, /* UDP to a client */
	CF_UDP_SV      = 0x4000, /* UDP to a server */
} ConyFlag;

typedef struct _Cony {
	int	c_type; /* connection type (ConyType CY_XXX) */
	int	c_etype;/* type of the peer on the connection */
	int	c_cflag;/* suppressing polling, etc. */
	int	c_fd;	/* socket for either input(CY_IN) or output */
	FILE   *c_fp;	/* for stream input with interpretation */
	BufDesc *c_fpbuf;
	BufDesc *c_outbuf;
	int	c_xsid;	/* connection ID */
	int	c_tid;
	int	c_ipk;	/* total input packet */
	Int64	c_icc;	/* total input octets */
	Int64	c_occ;	/* total output to local X */
	Int64	c_rcptsent; /* ack. sent as RCPT */
	int	c_recv; /* received from remote X (not yet reported) */
	int	c_totalreadN; /* totatlread64  */
	Int64	c_totalread64; /* total data received from local X */
	Int64	c_totalsent64; /* total data sent to remote X */
	int	c_pendlog; /* logging pending status (for debug) */
	double	c_pauseTill;
	MStr(	c_src_addr,64); /* client port of PY_CONN (info.) */
	int	c_src_portnum;
	MStr(	c_dst_port,64); /* destination of PY_CONN */
} Cony;

/* internal type of the inner connection over YYMUX */
enum _ConyType {
	CY_NULL   = 0x0000, /* fresh slot not yet used */
	CY_IN     = 0x0001, /* is an input socket to be polled */
	CY_YMUX   = 0x0002, /* is a YMUX socket */
	CY_ZOMB   = 0x0008, /* terminated connection */

	CY_ACC    = 0x0011, /* accepting new local connection */
	CY_YMUXIN = 0x0023, /* YMUX input */
	CY_YMUXOUT= 0x0042, /* YMUX output */
	CY_PWT    = 0x0081, /* process watcher */
	CY_RSMACC = 0x0101, /* accepting port for resumption */
	CY_YACC   = 0x0201, /* accepting port for sending YY req. over YYMUX */

	CY_XIN    = 0x0401, /* X input */
	CY_XOUT   = 0x0800, /* X output */
	CY_UDP_SV = 0x0C01, /* UDP server side */
	CY_STDIN  = 0x1000, /* stdin to X command */
	CY_STDOUT = 0x2001, /* stdout from X command */
	CY_STDERR = 0x4001, /* stderr from X command */
	CY_CONS   = 0x8001, /* console at the YY client side */
} ConyType;

/* MsgType: External types of the YYMUX packet (ver. YYMUX) */
enum _MsgType {
	PY_DATA =   1,	/* X protocol data (with body) */
	PY_CONN =   2,	/* request for new connection to the X server */
	PY_RSET	=   3,	/* request for disconnection of a X connection */
	PY_INFO =   4,	/* something informational (with body) */
	PY_BIND =   5,	/* request for bind() a port */
	PY_ACC  =   6,	/* request for accept() at a port */

	PY_RCPT =  11,	/* large size of RCPT (flow control) */
	PY_SHUT =  12,	/* request for starting shutdown of YMUX */
	PY_RCON =  13,	/* request for reconnection of the YMUX session */

	PY_RSMG =  21,	/* RSM in resuming, X inputs must be suspended */
	PY_RSMQ =  22,	/* RSM resume req. asking resending from the point */
	PY_RSMD =  23,	/* RSM report resume complete */

	PY_REQ  =  31,	/* request */
	PY_RESP =  32,	/* response */

	PY_NOP  = 126,	/* no operation */
	PY_EOS  = 127,	/* end of stream from YMUX */
	PY_RSNT = 128,	/* the message is resent */
} MsgType;

enum _yyREQ {
	RQ_ECHO =   1,	/* echo */
} yyREQ;

/* MsgFlag: External flags in the YYMUX packet (ver. YYMUX) */
enum _MsgFlag {
	MF_NOBODY  = 0x01, /* no body (length field is not the msg. length) */
	MF_OOB     = 0x02, /* OOB */
	MF_DEFLATE = 0x04, /* compressed with Zlib "deflate" */
	MF_ZCREDHY = 0x08, /* with the Z-Credhy header */
} MsgFlag;

typedef struct {
	int	m_type; /* message type (MsgType PY_XXX) */
	int	m_flag; /* misc. flag (MF_XXX) */
	int	m_xsid; /* connection-ID (0 - 255) */
	int	m_snum; /* sequence num. of messages (mod 256)(infomational) */
	int	m_rsnt; /* in resending (informational) */
	UShort	m_leng; /* the length of the body (0 - 65535) */
	UShort	m_rcpt; /* the amount of received (drained) data */
} MuxMssg;

/* The least significant bit of a connection-ID (xsid) indicates
 * the side of the connection {0:client,1:server} the entity is.
 * In the synmetrical connection, it may be assigned by the proxy.
 */

/* External -- YYMUX packet format (ver.YYMUX) */
static int enPack(MuxMssg *mx,char *pack){
	unsigned char *up = (unsigned char*)pack;
	up[0] = mx->m_type;
	up[1] = mx->m_flag;
	up[2] = mx->m_xsid;
	up[3] = mx->m_snum;
	up[4] = mx->m_leng >> 8;
	up[5] = mx->m_leng;
	up[6] = mx->m_rcpt >> 8;
	up[7] = mx->m_rcpt;
	return 0;
}
static int dePack(MuxMssg *mx,char *pack){
	unsigned char *up = (unsigned char*)pack;
	mx->m_rsnt =  up[0] & 0x80;
	mx->m_type =  up[0] & 0x7F;
	mx->m_flag =  up[1];
	mx->m_xsid =  up[2];
	mx->m_snum =  up[3];
	mx->m_leng = (up[4] << 8) | up[5];
	mx->m_rcpt = (up[6] << 8) | up[7];
	return 0;
}
static int bodyLeng(MuxMssg *mx){
	if( mx->m_flag & MF_NOBODY ){
		return 0;
	}
	return mx->m_leng;
}
static int putInt64(char *bp,Int64 i64){
	int bi;
	for( bi = 0; bi < 8; bi++ ){
		bp[bi] = i64 >> (8*(7-bi));
	} 
	return 0;
}
static Int64 getInt64(const char *bp){
	const unsigned char *up = (const unsigned char*)bp;
	Int64 i64 = 0;
	int bi;
	for( bi = 0; bi < 8; bi++ ){
		i64 = (i64 << 8) | up[bi];
	} 
	return i64;
}

static int dePackBody(MuxCtx *Mc,MuxMssg *mx,char *pack,int rcc,FILE *fp){
	unsigned char *up = (unsigned char*)pack;
	int m_leng;

	dePack(mx,pack);
	m_leng = bodyLeng(mx);
	if( MxFlagsDUMP || m_leng < 0 || PBSIZE < m_leng ){
 sv1log("-yd [%d] y%-2d %-4d %3d#%d r%d\n",
	fileno(fp),mx->m_type,m_leng,mx->m_snum,mx->m_xsid,mx->m_rcpt);
	}
	if( m_leng < 0 || PBSIZE < m_leng ){
 sv1log("####YMUX FATAL: wrong size packet (%d)\n",m_leng);
 fprintf(stderr,"####YMUX FATAL: wrong size packet (%d)\n",m_leng);
		Finish(-1);
	}
	if( m_leng != rcc-PHSIZE ){
		int slen = rcc - PHSIZE;
		if( slen < m_leng ){
			int rem,icc;
			rem = m_leng - slen;
			icc = recvs(fp,pack+rcc,rem);
			if( 0 < MxDebug ){
 sv1log("--Y%d --dePack[%d]alv=%d,eof=%d icc=%d/%d y%d %d#%d\n",
	MxId,fileno(fp),IsAlive(fileno(fp)),feof(fp),
	icc,m_leng,mx->m_type,mx->m_snum,mx->m_xsid);
			}
			if( icc != rem ){
 sv1log("----YMUX read %d < %d %d %d#%d eof=%d #########\n",
	icc,rem,mx->m_leng,mx->m_xsid,mx->m_snum,feof(fp));
				if( feof(fp) ){
					return -1;
				}
			}
		}else{
 sv1log("----YMUX read %d > %d\n",rcc-PHSIZE,m_leng);
		}
	}
	return m_leng;
}
static int recvPack1(MuxCtx *Mc,Cony *Ci,char *bp,MuxMssg *mx,int *ilen){
	int rcc,rcc2;
	FILE *fp = Ci->c_fp;
	int eof = feof(fp);

	rcc = fread(bp,1,PHSIZE,fp);
	if( rcc <= 0 ){
		sv1log("##Y%d/%d EOS [%d]alv=%d rcc=%d,eof=%d/%d,errno=%d\n",
			MxId,MxParentId,
			fileno(fp),IsAlive(fileno(fp)),rcc,eof,feof(fp),errno);
		return -1;
	}
	if( rcc < PHSIZE ){
		sv1log("----YMUX rcc=%d/%d\n",rcc,PHSIZE);
		rcc2 = fread(bp+rcc,1,PHSIZE-rcc,fp);
		sv1log("----YMUX rcc=%d+%d/%d\n",rcc,rcc2,PHSIZE);
		if( rcc2 != PHSIZE-rcc ){
			return -2;
		}
		rcc += rcc2;
	}
	*ilen = dePackBody(Mc,mx,bp,rcc,fp);
	if( 0 ){
		int pi;
		fprintf(stderr,"---- recvPack[%d]: rcc=%d ilen=%d %d#%d\n",
			fileno(fp),rcc,*ilen,mx->m_snum,mx->m_xsid);
		for( pi = 0; pi < rcc; pi++ ){
			fprintf(stderr,"[%d] %X\n",pi,0xFF&bp[pi]);
		}
	}
	return rcc;
}

/*
 * RSM Resumption subprotocol {RSMQ,RSMD}
 * RSM begin {
 */
static void scanRSMQ(MuxCtx *Mc,MuxMssg *mx,const char *bp);
static void sendRSMQ(MuxCtx *Mc);
static void sendRSMD(MuxCtx *Mc);
#define McGetc(up,off,siz)  up[off++ % siz]

/* save sending data */
/* backup the sending data
 * also used for non-blocking partial send?
 */
static void saveForResume(MuxCtx *Mc,MuxMssg *mx,PCStr(msg),int leng){
	int oi;
	int ci;

	if( MxFlagsPERSIST )
	if( mx->m_type != PY_RSMQ && mx->m_type != PY_RSMD ){
		MxOpk++;
		oi = MxTop % sizeof(MxSent);
		for( ci = 0; ci < leng; ci++ ){
			if( sizeof(MxSent) <= oi ){
				oi = 0;
			}
			MxSent[oi++] = msg[ci];
		}
		MxTop64 += leng;
		MxOlen64 += leng;
	}
}
static int resend(MuxMssg *mx,MuxCtx *Mc,Int64 from64,FILE *fp){
	int siz = sizeof(MxSent);
	Int64 tail64 = MxOlen64;
	Int64 off64 = from64;
	Int64 base64;
	unsigned char ub[PHSIZE];
	const unsigned char *up = (const unsigned char*)MxSent;
	int np;
	int fi;
	int wcc;
	int occ = 0;
	int m_leng = -9;

	/*
	 * should detect overflow of the buffer by RSMSIZE<(MxTop-from)
	 * also the consistency of m_snum must be checked
	 */

	sv1log("--Y%d RSNT #### resend %u bytes #### (%d)[%u - %u / %u]\n",
		MxId,(int)(MxTop-from64),MxOseq,(int)from64,MxOlen,MxTop);

	for( np = 0; np < 1024; np++ ){
		if( tail64 <= off64 ){
			break;
		}
		base64 = off64;
		for( fi = 0; fi < PHSIZE; fi++ ){
			ub[fi] = McGetc(up,off64,siz);
		}
		dePack(mx,(char*)ub);
		if( mx->m_type != PY_RSMQ ){
			errno = 0;
			ub[0] |= 0x80;
			wcc = fwrite(ub,1,8,fp);
			occ += 8;
			m_leng = bodyLeng(mx);
			for( fi = 0; fi < m_leng; fi++ ){
				putc(McGetc(up,off64,siz),fp);
				occ++;
			}
		}
		sv1log("--RSNT(%d) out=%d rem=%u (y%d %d %d#%d) PIPE=%d err=%d\n",
			np,occ,(int)(tail64-base64),
			mx->m_type,m_leng,mx->m_snum,mx->m_xsid,
			yy_nsigPIPE,errno
		);
	}
	fflush(fp);
	return 0;
}
static void respRSMD(MuxCtx *Mc,Int64 roff){
	MuxMssg mx1;
	FILE *fp;

	fp = fdopen(MxYsock,"w");
	if( fp == 0 ){
		sv1log("####RSMD FATAL cannot fdopen[%d] e%d\n",MxYsock,errno);
		sleep(1);
	}else{
		resend(&mx1,Mc,roff,fp);
		fflush(fp);
		fcloseFILE(fp);
		sendRSMD(Mc);
	}
}
static void saveYYserver(MuxCtx *Mc,PCStr(proto),PCStr(host),int port){
	strcpy(MxYYproto,proto);
	strcpy(MxYYhost,host);
	MxYYport = port;
}
static int toSubMux(MuxCtx *Mc){
	if( MxParent )
	if( MxParent->mc_flags & MX_YYACTIVE )
	if( (MxParent->mc_Shutting) == 0 ){
		return 1;
	}
	return 0;
}
int connect_to_serverY(Connection *Conn,void *cty,PCStr(proto),PCStr(host),int port,int fromC,int toC,int relay_input);
static Connection *ckConn(FL_PAR,MuxCtx *Mc,Connection *Conn){
	if( MxConn != Conn ){
		sv1log("----Y%d SE=%d FATAL Conn=%X => %X (%X) <= %s:%d\n",
			MxId,MxStatSELFEND,Conn,MxConn,Conn0,FL_BAR);
	}
	return MxConn;
}
static int connects(MuxCtx *Mc,PCStr(host),double Start,int *sleep1,int slpx,int islocal){
	Connection *Conn = MxConn;
	int sflags;
	int ri;
	int sock = -9;
	int nready;
	int slp1 = *sleep1;
	int start = time(0);
	int elps;
	int serrno = 0;
	double St;
	double Elp = 0;
	int connY = (ConnType == 'y');
	Port sv;
	int ttystat[32];
	IStr(dstproto,64);
	IStr(dsthost,MaxHostNameLen);
	int dstport;

Conn = ckConn(FL_ARG,Mc,Conn);
	sflags = ConnectFlags;
	ConnectFlags |= COF_TERSE;
	if( ConnType ){
		sv1log("--Y%d/%d #%d reconnect ConnType=%c %s://%s:%d <= %s:%d\n",
			MxId,MxParent?MxParent->mc_id:0,STX_yy,
			ConnType,DST_PROTO,DST_HOST,DST_PORT,MxYYhost,MxYYport);
	}
	strcpy(dstproto,DST_PROTO);
	strcpy(dsthost,DST_HOST);
	dstport = DST_PORT;

	if( islocal ){
	}else{
		sv = Conn->sv;
		/* REAL_PROTO might have been set to "starttls" */

 zprintf(Mc,"---- RSM connects SF=%X cur-real[%s:%s:%d] DST[%s:%s:%d] MUX[%s:%s:%d]",
 ServerFlags,
 REAL_PROTO,REAL_HOST,REAL_PORT,
 MxDstProto,MxDstHost,MxDstPort,
 MxYYproto,MxYYhost,MxYYport
 );
		// was necessary to enable connection to self with find_YYMUX()
		//		if( MxDstProto[0] ){
		//		}else{
		set_realserver(Conn,MxYYproto,MxYYhost,MxYYport);
		//		}
	}

	ttystat[0] = ttystat[1] = 0;
	if( MxTtystat[0] ){ /* yysh */
		getTTyStat(0,ttystat,sizeof(ttystat));
		setTTyStat(0,MxTtystat,sizeof(MxTtystat));
	}else
	if( MxParent && MxParent->mc_ttystat[0] ){
		getTTyStat(0,ttystat,sizeof(ttystat));
		setTTyStat(0,MxParent->mc_ttystat,sizeof(MxTtystat));
	}

	for( ri = 0; ri < 10000; ri++ ){
Conn = ckConn(FL_ARG,Mc,Conn);
		if( MxFlagsINTERACT ){
			fprintf(stderr,"---- trying ... (%.3f)\r\n",
				Time()-Start);
		}
		elps = time(0) - start;
		sv1log("--Y%d RSM connects i%d/%d (%d/%d) (%.2f) e%d\n",
			MxId,slp1,slpx,elps,MxRsmhold,Elp,serrno);
		if( MxRsmhold < elps ){
			sv1log("RSM Timeout (%ds) i%d\n",elps,slpx);
			break;
		}
		St = Time();

		if( MxFlagsVERBOSE )
		sv1log("--yy connects %d {%c}[%s:%s:%d][%s:%s:%d]\n",
			islocal,ConnType?ConnType:' ',
			DFLT_PROTO,DFLT_HOST,DFLT_PORT,
			REAL_PROTO,REAL_HOST,REAL_PORT
		);

/* to insert STLS=fsv:appProto */
/* ServerFlags should be cleared ? */
/* REALPROT must be MxDstProto to insert STLS=fsv:appProto */

if( 0 )
if( MxDstPort == REAL_PORT )
if( hostcmp(MxDstHost,REAL_HOST) == 0 )
if( strcmp(MxDstProto,REAL_PROTO) != 0 )
{
	/* where is this RELA_PROTO set? */
	strcpy(REAL_PROTO,MxDstProto);
}

		if( islocal ){
			/* will be forbidden by connect_to_serv() */
			sock = OpenServer("yy","yy",DST_HOST,DST_PORT);
		}else{
			/* "yymux" is not in REMITTABLE in general */
			MxConn->from_myself = 1;
			sock = connect_to_serverY(Conn,Mc,DST_PROTO,DST_HOST,
				DST_PORT,-1,-1,0);
			/*
			sock = connect_to_serv(MxConn,-1,-1,0);
			*/
			MxConn->from_myself = 0;
		}

		serrno = errno;
		Elp = Time() - St;

		if( MxShutting ){
 yprintf(Mc,"---- connect[%d] IN SHUT",sock);
			break;
		}
		if( MxParent && MxParent->mc_Shutting ){
 yprintf(Mc,"---- connect[%d] PARENT IN SHUT",sock);
			break;
		}
		if( 0 <= sock ){
			nready = PollIn(sock,100);
			if( nready == 0 ){
				break;
			}
			if( IsAlive(sock) ){
				break;
			}
			/* RSMx: the first connection will be closed imm. */
			sv1log("Y%d ##RSM## immediate reset, shut=%X,sig=%d <= %s:%d\n",
				MxId,MxShutting,yy_gotSIG,host,MxServport);
			if( 1 < yy_gotSIG ){
				break;
			}
		}
		msleep(slp1);
		if( slp1 < slpx ){
			slp1 += 200;
		}
		if( 1 < yy_gotSIG ){
			break;
		}
		close(sock);
	}
	*sleep1 = slp1;
	sv1log("--Y%d RSM CLNT[%d] *%d\n",MxId,sock,ri);
Conn = ckConn(FL_ARG,Mc,Conn);
	ConnectFlags = sflags;
	if( islocal ){
	}else{
		Conn->sv = sv;
	}
	if( ttystat[0] || ttystat[1] ){ /* yysh */
		setTTyStat(0,ttystat,sizeof(ttystat));
	}
	return sock;
}
static int serverFin(MuxCtx *Mc){
	Connection *Conn = MxConn;

	if( 0 <= ServerSockX )
	if( !IsAlive(ServerSockX) ){
		sv1log("--serverFin[%d] con. NotAlive [%s:%d]\n",
			ServerSockX,DST_HOST,DST_PORT);
		return 1;
	}
	return 0;
}

int _PollIns(int timeout,int nfd,int *fdv,int *rdv);
static int accepts(MuxCtx *Mc){
	Connection *Conn = MxConn;
	int sock = -2;
	int ri;
	int rem;
	int start = time(0);
	int nint = 0;
	int rdy;
	int rj;
	int serrno;
	IStr(host,64);
	IStr(peer,64);

	getpairName(ServerSockX,AVStr(host),AVStr(peer));
	sv1log("--Y%d RSM SV[%d]A%d [%d][%d][%d][%d]{%s}{%s} %s:%d e%d\n",
		MxId,ServerSockX,IsAlive(ServerSockX),
		ServerSock,ToS,ToSX,ToSF,host,peer,DST_HOST,DST_PORT,errno);

	for( ri = 0; ri < 20; ri++ ){
		rem = MxRsmhold - (time(0)-start);
		if( rem <= 0 ){
			break;
		}
		for( rj = 0; ; rj++ ){
			int tout,fdn,fdv[2],rdv[2];

			rem = MxRsmhold - (time(0)-start);
			if( rem <= 0 ){
				goto EXIT;
			}
			fdv[0] = MxRsmsock;
			fdv[1] = ServerSockX;
			rdv[0] = rdv[1] = 0;
			if( 0 <= ServerSockX && PollIn(ServerSockX,1) == 0 ){
				fdn = 2;
				tout = 0;
			}else{
				fdn = 1;
				tout = 10*1000;
			}
			errno = 0;
			rdy = _PollIns(tout,fdn,fdv,rdv);
			serrno = errno;
			sv1log("--Y%d RSM:%d ACC poll %d [%d %d/%d] rdy=%d/%d(%d %d) e%d\n",
				MxId,rj,tout,
				fdv[0],ServerSockX,IsAlive(ServerSockX),
				rdy,fdn,rdv[0],rdv[1],
				serrno);
			if( serverFin(Mc) ){
				if( MxFlagsHOLDONNX ){
					sv1log("##Y%d IGN serverFin[%d]\n",
						MxId,ServerSockX);
				}else{
				goto EXIT;
				}
			}
			if( rdy ){
				if( rdv[0] ){
					break;
				}else{
				}
			}
		}
		if( rdy <= 0 ){
			if( yy_gotSIG ){
				break;
			}
			/* SIGPIPE to another thread ? */
		}else{
			sock = ACCEPT(MxRsmsock,0,-1,1);
			if( 0 <= sock ){
				break;
			}
		}
		if( errno == EINTR ){
			nint++;
			sv1log("--Y%d RSM SERV[%d] e%d i%d SIGPIPE=%d/%X\n",
				MxId,sock,errno,nint,yy_nsigPIPE,
				PRTID(yy_tidPIPE));
			if( 1 < nint ){
				break;
			}
			msleep(500);
		}else{
			break;
		}
	}
EXIT:
	sv1log("--Y%d RSM SERV[%d] *%d i%d SIG=%d err=%d\n",
		MxId,sock,ri,nint,yy_gotSIG,errno);
	return sock;
}
static int accYYMUX(MuxCtx *Mc,FILE *fc,FILE *tc){
	IStr(req,256);
	refQStr(rp,req);
	int rsmkey;
	int ri;
	int rcode = 0;

	rsmkey = MxRsmkey;
	MxRsmkey = 0;
	for( ri = 0; ; ri++ ){
		if( fgets(req,sizeof(req),fc) == 0 ){
			break;
		}
		if( rp = strpbrk(req,"\r\n") )
			truncVStr(rp);
		sv1log("RSM-Req: %s\n",req);
		if( *req == 0 )
			break;
		if( strncaseeq(req,"Y-Connection:",13) ){
			scanYConnection("R",0,Mc,req,CST_RESUME|CST_FINISH);
		}
	}
	/* read and check the KEY MxRsmkey */
	sv1log("--RSM-Key %u %u p%d #%d\n",rsmkey,MxRsmkey,MxRsmport,MxRsmcnt);
	if( rsmkey != MxRsmkey ){
		sv1log("##RSM-Key## bad key: %u %u\n",rsmkey,MxRsmkey);
		lfprintf("RSM-Sent",tc,"HTTP/1.0 500 bad resumption key");
		lfprintf("RSM-Sent",tc,"");
		MxRsmkey = rsmkey;
		rcode = -1;
	}else{
		if( MxRsmstate == CST_FINISH ){
			sv1log("---------SHOULD FINISH IMM. --------\n");
		}
		lfprintf("RSM-Sent",tc,"HTTP/1.1 200 server resume OK ");
		lfprintf("RSM-Sent",tc,"");
		rcode = 0;
	}
	fflush(tc);
	return rcode;
}
static void yyRsmacc(MuxCtx *Mc,int asock){
	int sock;
	Connection *Conn = MxConn;

	sock = ACCEPT(asock,0,-1,1);
	sv1log("##RSM## forced resume [%d][%d]\n",asock,sock);
	/* RSMx: this sock should be used for resume(ET_SERV) */
	/* input messages buffered in CY_YMUXIN must be flushed */
	if( 0 <= sock ){
		close(sock);
	}else{
		sv1log("--FATAL yyRsmacc[%d] failed, e%d\n",asock,errno);
		msleep(250);
	}

	ShutdownSocket(MxYsock);
	/*
	dupclosed(MxYsock); // YY client side does not sense it in the first connection
	*/
	if( ClientFlags & PF_SSL_ON ){
		/* SHOULD CLEAR SSLway */
	}
}
static int conYYMUX(MuxCtx *Mc,FILE *fs,FILE *ts,int *hstat,PVStr(statline)){
	IStr(res,512);
	refQStr(rp,res);
	IStr(nam,128);
	IStr(val,1024);
	int ri;
	int rdy;
	int ch;
	double St = Time();
	int rcode;
	int haveAuth = 1;

	rdy = fPollIn(fs,3*1000);
	if( rdy != 0 ){
		ch = getc(fs);
		if( ch == EOF ){
			lfprintf("RSM-Req",0,"EOS before request [%d]",fileno(fs));
			if( MxFlagsINTERACT ){
 yprintf(Mc,"---- got EOS before request [%d](%.3f) S%d ####",
 fileno(fs),Time()-St,MxSSLerr);
				sleep(3);
			}
			return -1;
		}
		ungetc(ch,fs);
	}
	if( haveAuth ){
		YYinitCredhy(Mc);
		generateCredhyKey(Mc,0,"RSMQ",1);
	}
	if( rdy ){
		rcode = scanYYresponse("RSMQ",Mc,fs,0);
	}
	YYlfprintf(Mc,"RSM-Req",ts,"%s %s HTTP/1.1",YY_CON,MxDstUrl);
	YYlfprintf(Mc,"RSM-Req",ts,"Y-Version: %s",myYYVER);
	if( haveAuth ){
		generateCredhyKey(Mc,ts,"RSM",1);
		if( genAutho(Mc) ){
			putAutho("RSMQ",Mc,ts);
		}
	}
	clearYConnection("RSM-Req",Mc);
	MxRsmstate = CST_RESUME;
	putYConnection("RSM-Req",1,Mc,ts); /* with port=dddd */
	YYlfprintf(Mc,"RSM-Req",ts,"");
	fflush(ts);

	clearVStr(statline);
	for( ri = 0; ; ri++ ){
		rdy = fPollIn(fs,1000);
		if( rdy <= 0 ){
			lfprintf("RSM-Resp",0,"rdy=%d e%d (%.2f) Y%d",
				rdy,errno,Time()-St,MxId);
			if( 1 < yy_gotSIG ){
				break;
			}
			if( 30 < Time()-St ){
				sv1log("##Y%d RSM-Resp timeout\n",MxId);
				return -1;
			}
			msleep(1000);
			continue;
		}
		if( fgets(res,sizeof(res),fs) == 0 ){
			lfprintf("RSM-Resp",0,"EOS eof=%d[%d] pid=%d SIG=%d",
				feof(fs),fileno(fs),MxPid,yy_gotSIG);
			if( 1 < yy_gotSIG ){
				MxSadEnd = 3;
				break;
			}
			if( statline[0] == 0 ){
				MxSadEnd = 4;
				return -1;
			}
			MxSadEnd = 5;
			break;
		}
		if( statline[0] == 0 ){
			strcpy(statline,res);
			sscanf(statline,"%*s %d",hstat);
			if( *hstat == 410 ){
				Connection *Conn = MxConn;
 yprintf(Mc,"---- cleared RESUMING on 401: %X %X",ConnectFlags,MxInRESUME);
				ConnectFlags &= ~COF_RESUMING;
				MxInRESUME = 0;
			}
		}
		if( rp = strpbrk(res,"\r\n") )
			truncVStr(rp);
		YYlfprintfX(Mc,"RSM-Resp","s---",0,"%s",res);
		fieldScan(res,nam,val);
		if( *res == 0 ){
			if( *hstat == 100 ){
				sv1log("----Cont on 100: %s",statline);
				clearVStr(statline);
				continue;
			}
			break;
		}
	}
	return 0;
}

int needSTLS_SVi(Connection *Conn,int server,PCStr(proto));
int insertTLS_SVi(Connection *Conn,int client,int server,PCStr(proto));
PFilter *lastPFilter(Connection *Conn,int tid,int which);

int YYMUX_STARTTLS_withSV(MuxCtx *Mc,Connection *Conn,PCStr(proto),int sock,PCStr(what)){
	int fsv;
	int rcode = 0;
	int need;
	int mxid = 0;
	PFilter *Pf;

	if( Mc ){
		mxid = MxId;
	}
	need = needSTLS_SVi(Conn,sock,proto);
	if( need == 0 ){
		uncheckSTLS_SV(Conn);
		if( streq(proto,"yy") ){ /* alias of yymux */
			proto = "yymux";
			need = needSTLS_SVi(Conn,sock,proto);
		}
	}
	if( need ){
		if( ServerFlags & PF_STLS_OPT ){
			/* appliy TLS to the payload */
		}else{
			if( 0 < PollIn(sock,30) ){
				IStr(buf,8);
				int rcc;
				rcc = RecvPeek(sock,(char*)buf,sizeof(buf));
 yprintf(Mc,"#### YY resp. before SSL=%d rcc=%d[%X]",isinSSL(sock),rcc,buf[0]);
			}
			fsv = insertTLS_SVi(Conn,ClientSock,sock,proto);
			if( Pf = lastPFilter(Conn,getthreadid(),XF_FSV) ){
				if( Pf->f_error ){
 yprintf(Mc,"--Y%d STLS_SV[%d] MxSSLerr=%d Mc=%X FID=%d e%d [%04X]",
 	mxid,fsv,Pf->f_error,Mc,Pf->f_fid,Pf->f_error,PRTID(Pf->f_tid));
				}
     sv1log("--Y%d STLS_SV[%d] MxSSLerr=%d Mc=%X FID=%d e%d [%04X]",
 	mxid,fsv,Pf->f_error,p2i(Mc),Pf->f_fid,Pf->f_error,PRTID(Pf->f_tid));
				if( Mc ){
					MxSSLerr = Pf->f_error;
					if( MxSSLerr ){
						MxSSLok = 0;
					}else{
						MxSSLok = 1;
					}
				}
			}
			if( 0 <= fsv ){
				sv1log("--Y%d [%d] YYMUX STLS=fsv (%s)\n",
					mxid,sock,what);
				dup2(fsv,sock);
				close(fsv);
				pushSTLS_FSV(Conn,proto);
				rcode = 1;
			}
		}
	}
	uncheckSTLS_SV(Conn);
	return rcode;
}
static int clearSSLway(Connection *Conn,int filter,MuxCtx *Mc,PCStr(wh)){
	int ntx;
	int flags = 0;
	int timeout = 100;

	if( MxFlagsVERBOSE ){
		dumpFds(curLogFp());
	}
	if( filter & XF_FCL ){
		flags |= ClientFlags;
	}
	if( filter & XF_FSV ){
		flags |= ServerFlags;
	}
	if( (flags & (PF_STLS_ON|PF_SSL_ON)) == 0 ){
		/* clearn up pushed thread */
		timeout = 1;
		ntx = waitFilterThread(Conn,timeout,filter);
		if( MxFlagsINTERACT ){
			/* maybe the inner Mux in a nested ones */
			if( MxFlagsVERBOSE ){
				dumpFds(stderr);
			}
		}
		return 0;
	}

	ntx = waitFilterThread(Conn,timeout,filter);
	sv1log("--Y%d %s %X SSLway threads th=%d/%d N%d ToS[%d][%d][%d][%d]\n",
		MxId,wh,flags,actthreads(),numthreads(),ntx,
		ServerSock,ToS,ToSX,ToSF);
	if( 0 < actthreads() ){
		dumpThreads(wh);
	}
	if( filter & XF_FSV ){
		if( 0 <= ToSX){
			sv1log("--closeToSX[%d]%d SF=%X for SSLway?\n",
				ToSX,IsAlive(ToSX),ServerFlags);
			close(ToSX);
			ToSX = -1;
		}
		if( 0 <= ToSF){
			close(ToSF);
			ToSF = -1;
		}
	}
	if( MxFlagsVERBOSE ){
		dumpFds(curLogFp());
	}
	clearSTLSX(Conn,filter);
	return 1;
}
static int resume(MuxCtx *Mc,Cony *Ci){
	Connection *Conn = MxConn;
	MuxCtx *pMc;
	IStr(statline,256);
	int asock,sock;
	IStr(host,MaxHostNameLen);
	FILE *ifp = Ci->c_fp;
	int ifd = fileno(Ci->c_fp);
	int sleep1 = 100;
	int hstat = -1;
	double St = Time();
	IStr(date,64);

Conn = ckConn(FL_ARG,Mc,Conn);
	if( GatewayFlags & GW_COMMAND ){ /* for LOGFILE */
		extern int CHILD_SERNO;
		extern int CHILD_SERNO_MULTI;
		if( MxParent ){
			CHILD_SERNO_MULTI++;
		}else{
			CHILD_SERNO++;
		}
	}
	sv1log("--Y%d/%d resume shut=%X ET%X PS%d %X:%d.%u[%d] o%d i%d p%d [%d]\n",
		MxId,MxParent?MxParent->mc_id:0,
		MxShutting,MxEtype,MxFlagsPERSIST,
		MxRsmYYGUID,MxRsmport,MxRsmkey,MxRsmsock,
		MxOseq,MxIseq,yy_nsigPIPE,fileno(Ci->c_fp));

	if( pMc = MxParent ){
		MuxCtx *Mc = pMc;
		/* if innter Muxes are in resume, they should be frozen ...*/

		if( MxInRESUME || MxResuming || (ConnectFlags & COF_RESUMING) ){
			int wi;
			for( wi = 0; wi < 60; wi++ ){
				if( MxInRESUME == 0 && MxResuming == 0
				 && (ConnectFlags & COF_RESUMING) == 0
				){
					break;
				}
 yprintf(Mc,"---- waiting another ongoing resume ...(%d){%X %X %X}",
 wi,MxInRESUME,MxResuming,ConnectFlags&COF_RESUMING);
				sleep(1);
			}
		}
	}
Conn = ckConn(FL_ARG,Mc,Conn);
	if( MxShutting ){
		return -1;
	}
	if( MxParent && MxParent->mc_Shutting ){
		sv1log("--Y%d/%d outer shut=%d\n",MxId,MxParent->mc_id,
			MxParent->mc_Shutting);
		return -1;
	}
	if( MxFlagsPERSIST == 0 ){
		return -1;
	}
	if( MxRsmport <= 0 ){
		sv1log("--yy No RSM-Port:%d Sock:[%d]\n",MxRsmport,MxRsmsock);
		return -1;
	}
	if( MxFlagsINTERACT ){
		IStr(inner,128);
		if( MxParent ){
			sprintf(inner,"[%s:%d]~",
				MxParent->mc_yyhost,MxParent->mc_yyport);
		}
		fprintf(stderr,"\r\n");
		fprintf(stderr,"----  @\"@  lost connection ??? %s[%s:%d] Y%d\r\n",inner,MxServ,MxServport,MxId);
		fprintf(stderr,"---- ( o ) {trying to resume...} %s\r\n",stimes(0));
		/* should popup window on Windows */
	}

Conn = ckConn(FL_ARG,Mc,Conn);
	MxInRESUME = 1;
	ConnectFlags |= COF_RESUMING;

	yy_nsigPIPE = 0;
	if( MxEtype & ET_SERV ){
		sv1log("RSM-Serv accepting at [%d]%d/%d ... (%d) th=%d/%d\n",
			MxRsmsock,sockPort(MxRsmsock),MxRsmport,MxRsmhold,
			actthreads(),numthreads());
	TRY_ACC:
		clearSSLway(Conn,XF_FCL,Mc,"----RsmAcc");
		sock = accepts(Mc);
Conn = ckConn(FL_ARG,Mc,Conn);
		if( 0 <= sock ){
			dup2(sock,ifd);
			close(sock);
			clearerr(ifp);
			sv1log("#### RSM-Serv accepted #### dup2(%d,%d) %d alv=%d\n",
				sock,ifd,sockPort(ifd),IsAlive(ifd));
		}
		sv1log("--Y%d RSM ACCEPT SERV[%d][%d]\n",MxId,MxRsmsock,sock);
		if( 1 ) /* via RSM proxy */
		if( 0 <= sock ){
			FILE *fc;
			FILE *tc;
			fc = ifp;
			tc = fdopen(ifd,"w");
			if( tc == 0 ){
				Finish(-1);
			}
			if( accYYMUX(Mc,fc,tc) != 0 ){
				fcloseFILE(tc);
				dupclosed(ifd);
				goto TRY_ACC;
			}
			fcloseFILE(tc);
		}
	}else{
		const char *dstproto;
		if( toSubMux(Mc) ){
			dstproto = MxDstProto;
		}else{
			dstproto = "yymux";
		}
		sv1log("--Y%d RSM-Clnt conn... %s:%d via %s://%s:%d.%d+K%X\n",
			MxId,MxServ,MxServport,
			MxYYproto,MxYYhost,MxYYport,
			MxRsmport,MxRsmkey);
		strcpy(host,MxServ);

	TRY_CONN:
		clearSSLway(Conn,XF_FSV,Mc,"----RsmConn");
		sock = connects(Mc,host,St,&sleep1,10*1000,0);
Conn = ckConn(FL_ARG,Mc,Conn);

		if( MxParent && MxParent->mc_Shutting ){
 yprintf(Mc,"---- connects(%s)[%d] PARENT IN SHUT",dstproto,sock);
			if( 0 <= sock ){
				close(sock);
				sock = -1;
			}
		}
		if( 0 <= sock ){
			double St = Time();

			if( PollIn(sock,10) && !IsAlive(sock) ){
 /* might be a empty connection in the backlog which will not be accept() */
 /* too long wait will cause timeout in STLS=fcl detection on the server */
 zprintf(Mc,"---- connects(%s)[%d] %X alv=%d (%.3f) ---- RETRY-A ####",
 dstproto,sock,ServerFlags,IsAlive(ifd),Time()-St);
				close(sock);
				goto TRY_CONN;
			}
			dup2(sock,ifd);
			close(sock);
			clearerr(ifp);
			sv1log("--Y%d #### RSM-Clnt connected #### dup2(%d,%d) %d alv=%d\n",
				MxId,sock,ifd,sockPort(ifd),IsAlive(ifd));
			YYMUX_STARTTLS_withSV(Mc,Conn,dstproto,ifd,"RSM-Clnt");
			if( MxSSLerr ){
 zprintf(Mc,"---- connects(%s)[%d] %X alv=%d (%.3f) ---- RETRY-S e%d ####",
 dstproto,sock,ServerFlags,IsAlive(ifd),Time()-St,MxSSLerr);
				goto TRY_CONN;
			}
			if( PollIn(ifd,10) && !IsAlive(ifd) ){
 zprintf(Mc,"---- connects(%s)[%d] %X alv=%d (%.3f) ---- RETRY-B ####",
 dstproto,ifd,ServerFlags,IsAlive(ifd),Time()-St);
				goto TRY_CONN;
			}
			if( MxFlagsVERBOSE ){
 zprintf(Mc,"---- connects(%s)[%d] %X alv=%d (%.3f)",
 dstproto,sock,ServerFlags,IsAlive(ifd),Time()-St);
			}
		}else{
			MxSadEnd = 6;
			if( MxFlagsINTERACT ){
				fprintf(stderr,"---- She's been broken... orz...\r\n");
			}
		}
		if( 1 ) /* via RSM proxy */
		if( 0 <= sock ){
			FILE *fs;
			FILE *ts;
			fs = ifp;
			ts = fdopen(ifd,"w");

			hstat = 999;
			if( conYYMUX(Mc,fs,ts,&hstat,AVStr(statline)) != 0 ){
				fcloseFILE(ts);
				sleep1 += 100;
				/* watch SIG or TimeoutWait() */
				msleep(sleep1);
				goto TRY_CONN;
			}
			if( hstat == 503 || hstat == 504 ){
				/* 504 from a local Y11 proxy should be ignored */
				/* 504 not from the host of target yymux should be ignored */
				if( 1 ){
					fcloseFILE(ts);
					sleep1 += 100;
					msleep(sleep1);
					goto TRY_CONN;
				}
			}
			fcloseFILE(ts);
			if( hstat < 100 || 300 <= hstat ){
				sv1log("RSM-Clnt the peer seems gone: %s",statline);
				MxSadEnd = 1;
				if( MxFlagsINTERACT ){
					fprintf(stderr,"---- She's gone... orz...\r\n");
				}
				return -1;
			}
			if( 1 < yy_gotSIG ){
				sv1log("## RSM gotSIG=%d\n",yy_gotSIG);
				Finish(0);
			}
		}
		/* send the KEY */
	}

Conn = ckConn(FL_ARG,Mc,Conn);
	MxInRESUME = 0;
	ConnectFlags &= ~COF_RESUMING; /* not to disable ConnectViaYYMUX()
					* (for PASV) after the resumption
					*/
	if( sock < 0 ){
		MxSadEnd = 2;
		return -1;
	}
	if( MxFlagsINTERACT ){
		fprintf(stderr,"\r\n");
		fprintf(stderr,"----  @ @ %s (%.3f sec.)\r\n",stimes(0),Time()-St);
		fprintf(stderr,"----\\( v )/ {reconnected!! #%d Y%d} %s\r\n",
			MxRsmcnt,MxId,
			(MxSSLok||(ServerFlags&PF_SSL_ON))?"((with SSL))":"");
	}
	sv1log("--Y%d RSM send RSMQ to peer, local ready cc=%d\n",
		MxId,ready_cc(ifp));
	MxDebug = 10;
	sendRSMQ(Mc);
	return 0;
}
/*
 * } end RSM
 */

static int recvPack(MuxCtx *Mc,Cony *Ci,char *bp,MuxMssg *mx,int *ilen){
	int rcc;
	FILE *fp = Ci->c_fp;
	static MuxMssg pmx;

	if( 0 < MxDebug ){
		MxDebug--;
	}
	mx->m_type = PY_EOS;
	rcc = recvPack1(Mc,Ci,bp,mx,ilen);
	/* should skip duplicated packet ? */

	if( rcc <= 0 || feof(fp) || mx->m_type == PY_EOS ){
		/* reconnect or accept */
		/* resend data that have been sent, with extended sequence number? */
		/* restart */
	}else{
		MxLastMuxIn = Time();
	}
	if( MxEtype & ET_PROX ){
		if( rcc <= 0 ){
			sv1log("##recvPack proxy: rcc=%d\n",rcc);
			/* resuming by proxy might be useful when it sits remote
			 * from the both sides
			 */
		}
		return rcc;
	}
	if( rcc <= 0 || feof(fp) ){
	}else{
		if( mx->m_type == PY_RSMQ ){
			MxDebug = 10;
			sv1log("--Y%d RSM received RSMQ etype=%X\n",MxId,MxEtype);
			scanRSMQ(Mc,mx,bp);
			mx->m_type = PY_NOP;
			return 0;
		}
		if( mx->m_rsnt /*|| 0 < ndbg*/ ){
			sv1log("--YMUX %u {%4d}(%3d) RSNT=%X y%d %d %d#%d\n",
				MxIlen,MxIseq,
				mx->m_snum,mx->m_rsnt,mx->m_type,
				mx->m_leng,mx->m_snum,mx->m_xsid);
		}
		if( (0xFF & mx->m_snum) != (0xFF & MxIseq) ){
			if( mx->m_rsnt )
			if( mx->m_type != PY_EOS ){
				sv1log("--YMUX %u IGN RSNT y%d {%d %d}(%d) rcc=%d ET=%X\n",
					MxIlen,mx->m_type,
					MxIseq,0xFF&MxIseq,mx->m_snum,
					rcc,MxEtype);
				mx->m_type = PY_NOP;
				return 0;
			}
		}
		if( (0xFF & mx->m_snum) == (0xFF & MxIseq) ){
			if( mx->m_type == PY_RSMQ
			 || mx->m_type == PY_RSMD
			){
				sv1log("--Y%d DONT COUNT RSM y%d {%u/%d}\n",
					MxId,mx->m_type,MxIlen,MxIseq);
			}else{
				MxIseq++;
				MxIlen64 += rcc + *ilen;
			}
			return rcc;
		}
	sv1log("--YMUX %u FATAL MUX IN[%d] y%d {%d %d}(%d#%d R%X %d) rcc=%d ET=%X [%s][R%d]\n",
			MxIlen,fileno(fp),
			mx->m_type,MxIseq,0xFF&MxIseq,mx->m_snum,mx->m_xsid,
			mx->m_rsnt,mx->m_leng,rcc,MxEtype,
			MxDstHost,MxRsmport);
	}
	if( rcc <= 0 || feof(fp) || mx->m_type == PY_EOS ){
		if( MxShutting ){
			sv1log("--Y%d SHUT in shutting, rcc=%d eof=%d y#%d\n",
				MxId,rcc,feof(fp),mx->m_type);
		}else
		if( MxClntHOLDONNX ){
			sv1log("--Y%d recv=%d peer Shut in HOLDONNX (%d %d) %s:%d\n",
				MxId,rcc,MxClntHOLDONNX,time(0)-MxTimeoutNX,
				MxYYhost,MxYYport);
		}else
		if( resume(Mc,Ci) == 0 ){
			MxLastMuxIn = Time();
			mx->m_type = PY_RSMG;
			return 0;
		}else{
			mx->m_type = PY_SHUT;
			return -1;
		}
	}
	mx->m_type = PY_SHUT;
	return -1;
}
static int sendToMux(MuxCtx *Mc,MuxMssg *mx,PCStr(msg),int leng){
	int wcc;

	saveForResume(Mc,mx,msg,leng);
	errno = 0;
	wcc = write(MxYsock,msg,leng);
	if( MxFlagsVV_TOMUX ){
		sv1log("---ToMUX y%d %d %d#%d\n",
			mx->m_type,mx->m_leng,0xFF&mx->m_snum,mx->m_xsid);
	}
	if( 0 < MxDebug || mx->m_type == PY_SHUT ){
		sv1log("--Y%d/%d sendToMux [%d]alv=%d %d/%d y%d %d#%d [R%d] e%d\n",
			MxId,MxParentId,MxYsock,IsAlive(MxYsock),
			wcc,leng,mx->m_type,0xFF&mx->m_snum,mx->m_xsid,
			MxRsmport,errno);
		if( 0 < MxDebug ) MxDebug--;
	}
	if( wcc == leng ){
		MxLastMuxOut = Time();
	}
	if( wcc < leng ){
		Connection *Conn = MxConn;

if( MxShutting == 0 && (MxParent == 0 || MxParent->mc_Shutting == 0) ){
 yprintf(Mc,"---- failed sendToMux [%X] %d/%d RSM=(%X %X %X) shut=%X",
 TID,wcc,leng,MxResuming,MxInRESUME,ConnectFlags&COF_RESUMING,MxShutting);
}

		sv1log("##Y%d/%d sendToMux[%d] #%d %d/%d errno=%d\n",
			MxId,MxParent?MxParent->mc_id:0,
			MxYsock,mx->m_xsid,wcc,leng,errno);
	}
	if( 0 < wcc ){
		if( CID_PRI <= mx->m_xsid ){
			MxXmit0 += mx->m_leng;
		}else{
		}
		Verbose(">>MUX [%d] %d / %d\n",MxYsock,wcc,leng);
	}else{
		/* reconnect or accept */
		/* resend output record */
		/* restart */
	}
	if( wcc < leng ){
		return -1;
	}else{
		return 0;
	}
}

enum _yyShutCode {
	YS_XEOF =	0x0001, /* EOF form local X */
	YS_NOPROC =	0x0002, /* no active processes */
	YS_GOTSIG =	0x0004, /* got SIGINT */
	YS_REMOTE =	0x0010, /* shutting notify from remote */
	YS_NOACTS =	0x0020, /* no active connections */
	YS_PWEXIT =	0x0040, /* exit of primary processs detected by wait()*/
	YS_SOUTEOF =	0x0100, /* EOF from local X command to stdout */
	YS_SERREOF =	0x0200, /* EOF from local X command to stderr */
} yyShutCode;
static void yyShutting(MuxCtx *Mc,int code,PCStr(wh)){
	MxShutting |= code;
	if( MxShutStart == 0 ){
		MxShutStart = Time();
	}
}
static int withLazy(MuxCtx *Mc,Cony *Cv,int Cn,int *timeout){
	int ci;
	Cony *C1;
	double Idle = Time()-MxLastMuxIn;
	double Silent = Time()-MxLastMuxOut;
	double Lazy = Time()-MxMuxStart;

	for( ci = 0; ci < Cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_cflag & CF_PAUSING )
		if( C1->c_cflag & CF_LAZY )
		if( 2.0 < Lazy || (0.2 < Idle && 0.2 < Silent) )
		{
	sv1log("--withLazy (%.2f %.2f %.2f) shut=%X\n",Lazy,Idle,Silent,MxShutting);
			C1->c_cflag &= ~(CF_PAUSING|CF_LAZY);
			return 1;
		}else{
	if( MxFlagsVERBOSE )
	sv1log("--withLazy (%.2f %.2f %.2f) shut=%X\n",Lazy,Idle,Silent,MxShutting);
			*timeout = 100;
			break;
		}
	}
	return 0;
}
static void showStat1(PCStr(wh),MuxCtx *Mc,int ci,int fc,Cony *C1){
	if( C1->c_type == 0 ){
		return;
	}
	sv1log("--%s (%2d) #%d s%04X %s (%d)[%2d]%s %d/%-6u %6u/%d\n",
		wh,ci,C1->c_xsid,C1->c_type,
		C1->c_etype==ET_SERV?"S":"-",fc,C1->c_fd,
		(C1->c_type&CY_IN)?"*":" ",
		(int)(C1->c_totalread64-C1->c_totalsent64),
		(int)(C1->c_totalread64),
		(int)C1->c_icc,C1->c_ipk
	);
}
static void showStats(MuxCtx *Mc){
	int ci;
	Cony *C1;

	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];
		showStat1("stat",Mc,ci,0,C1);
	}
}
static int updateFdv(PCStr(wh),MuxCtx *Mc,Cony *Cv,int cn,int fdv[],int qev[],int civ[],int *nxcp){
	int ci;
	Cony *C1;
	int fc = 0;
	int nx = 0;
	int nxc = 0;
	int na = 0;
	double Now = Time();
	int pending;
	int npause = 0;
	int nsusp = 0;

	sv1log("--Y%d update (%s)\n",MxId,wh);
	for( ci = 0; ci < cn; ci++ ){
		C1 = &Cv[ci];
		if( MxFlagsVERBOSE )
			showStat1("upd",Mc,ci,fc,C1);
		if( C1->c_cflag & CF_PAUSING ){
			npause++;
			continue;
		}
		if( C1->c_cflag & CF_SUSPEND ){
			nsusp++;
			continue;
		}
		if( 0 <= Cv[ci].c_fd ){
			if( C1->c_type == CY_XIN ){
				nx++;
				if( C1->c_etype == ET_CLNT ){
					nxc++;
				}
			}
			if( C1->c_type == CY_ACC ){
				na++;
			}
		}
		/*
		if( C1->c_pauseTill ){
			pending = C1->c_totalread64 - C1->c_totalsent64;
			sv1log("--#%d pausing with pending (%d/%d)\n",
				C1->c_xsid,pending,(int)(MxXmit-MxXack));
			if( Now < C1->c_pauseTill ){
				continue;
			}
			C1->c_pauseTill = 0;
		}
		*/
		if( C1->c_type == CY_XIN ){
			if( MxResuming ){
				sv1log("--Y%d IGN (%2d) X in resume\n",
					MxId,ci);
				continue;
			}
		}
		if( C1->c_type & CY_IN ){
			if( 0 <= Cv[ci].c_fd ){
				civ[fc] = ci;
				fdv[fc] = Cv[ci].c_fd;
				qev[fc] = PS_IN | PS_PRI;
				fc++;
			}
		}
	}
	*nxcp = nxc;
	MxTimeoutNX = 0;
	if( 0 < nx || 0 < na ){
	}else
	if( MxHoldonNX || MxFlagsHOLDONNX ){
	}else
	if( 0 < nsusp ){
		sv1log("##Y%d no-active connections (shut=%X) susp=%d pause=%d\n",
			MxId,MxShutting,nsusp,npause);
	}else
	if( 0 < MxClntHOLDONNX ){
		MxTimeoutNX = time(0) + MxClntHOLDONNX;
sv1log("--Y%d ------NO-ACTIVE CONNECTIONS, HOLDONNX=%d (port=%d key=%u)\n",MxId,MxClntHOLDONNX,MxRsmport,MxRsmkey);
	}else{
		if( MxShutting == 0 && MxFlagsSHUTIMM ){
			sendSHUT(Mc);
		}
		yyShutting(Mc,YS_NOACTS,"");
		sv1log("##Y%d shutting start on no-active connections (shut=%X)\n",
			MxId,MxShutting);
		/* relaying firefox need to allow non-actives for a while */
	}
	if( !MxDoupTerse ){
		IStr(rusg,256);
		MxDoupTerse = 0;
		strfRusage(AVStr(rusg),"%A",3,NULL);
		sv1log("RUSG: %s\n",rusg);
		dumpThreads(wh);
		dumpTids();
	}
	return fc;
}
static int clearConiesFd(Cony *Cv,int cn,int fd);
#define FD_close(fd,wh)  FD_closeX(FL_ARG,Mc,0,0,fd,wh,0)
static int FD_closeX(FL_PAR,MuxCtx *Mc,Cony *Cv,int cn,int fd,PCStr(wh),int force){
	int rcode;
	int ncls = 0;

	rcode = FD_closeY(FL_BAR,MxConn,fd,wh,force);
	if( rcode == 0 ){
		if( Cv ){
			ncls = clearConiesFd(Cv,cn,fd);
		}
	}
	return rcode;
}
static void shutdownAll(PCStr(wh),MuxCtx *Mc,Cony *Cv,int cn,int shut){
	Connection *Conn = MxConn;
	int ci;
	Cony *C1;
	int fc = 0;
	int fd;
	IStr(desc,128);

	for( ci = 0; ci < cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_type ){
	sprintf(desc,"--Y%d %s (%2d) #%d s%04X %s (%d)[%2d]%s %d/%-6u %6u/%d",
			MxId,wh,ci,C1->c_xsid,C1->c_type,
			C1->c_etype==ET_SERV?"S":"-",
			fc,C1->c_fd,
			(C1->c_type&CY_IN)?"*":" ",
			(int)(C1->c_totalread64-C1->c_totalsent64),
			(int)(C1->c_totalread64),
			(int)C1->c_icc,C1->c_ipk
			);
			if( MxFlagsVERBOSE ){
				sv1log("%s\n",desc);
			}
		}
		if( shut )
		if( 0 <= C1->c_fd ){
			fd = C1->c_fd;
			ShutdownSocket(fd);
/*
if( streq(wh,"relayShutdownAll") ){
}else
*/
			FD_closeX(FL_ARG,Mc,Cv,cn,fd,wh,0);
		}
	}
}
static int getXpend(Cony *Cv,int Cn,Cony *Ci,int log);
static int MaxPending(MuxCtx *Mc,int max){
	if( 0 < MxMaxPending && MxMaxPending < max ){
		return MxMaxPending;
	}else{
		return max;
	}
}
static int yySuspend(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci){
	int pend;
	int nx;
	int maxPending;

	/* also should see total pending for RSMSIZE */
	nx = 2; /* active input activity */
	if( pend = getXpend(Cv,Cn,Ci,0) ){
		/* if this is from the X server side, sending to the X client
		 * should be suspended to avoid to be blocked.
		 */
		maxPending = MaxPending(Mc,RSMSIZE/nx);
		if( maxPending < pend ){
			Ci->c_pendlog = 1;
			if( Ci->c_pauseTill ){
				if( Ci->c_pauseTill < Time() ){
					Ci->c_pauseTill = 0;
				}else{
				}
			}else{
 sv1log("--Y%d %3d#%d susp. with pending data (%d/%d / %d) %llu\n",
	MxId,0xFF&MxOseq,Ci->c_xsid,
	pend,(int)(MxXmit-MxXack),maxPending,Ci->c_icc);
 sv1log("####SUSP #%d pend=%d\n",Ci->c_xsid,pend);
				MxDoupdate = "FlowCtrlSusp";
				MxDoupTerse = 1;
				Ci->c_cflag |= CF_SUSPEND;
				Ci->c_pauseTill = Time()+0.1;
			}
			return 1;
		}
	}
	return 0;
}

static int x_tids[32]; /* should belong to each YYMUX? */
static int addTid(MuxCtx *Mc,int tid){
	int tx;

 sv1log("--tid Y%d addTid=%X\n",MxId,PRTID(tid));
	for( tx = 0; tx < elnumof(x_tids); tx++ ){
		if( x_tids[tx] == 0 ){
			x_tids[tx] = tid;
			break;
		}
	}
 sv1log("--tid Y%d addTid[%d] wait[%X] th=%d/%d\n",MxId,tx,PRTID(tid),actthreads(),numthreads());
	return 0;
}
static int delTid(MuxCtx *Mc){
	int tx;
	int tid;
	int terr;

	for( tx = 0; tx < elnumof(x_tids); tx++ ){
		if( (tid = x_tids[tx]) != 0 ){
			terr = thread_wait(tid,1);
 sv1log("--tid Y%d delTid[%d] wait[%X] err=%d th=%d/%d\n",MxId,tx,PRTID(tid),terr,actthreads(),numthreads());
			if( terr == 0 ){
				x_tids[tx] = 0;
			}
		}
	}
	return 0;
}
static void closeFd(FL_PAR,PCStr(wh),MuxCtx *Mc,Cony *Cv,int cn,Cony *Cx,int fd){
	int ci;
	Cony *C1;
	int tid = 0;
	int dont_close = 0;
	int xsid = 0;
	int type = 0;
	int icc = 0;
	int occ = 0;

	for( ci = 0; ci < cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_fd == fd ){
			if( C1->c_xsid == CID_DNS ){
				dont_close = 1;
				continue;
			}
			if( C1->c_cflag & CF_UDP_SV ){
 sv1log("----UDP close [%d] CF=%X #%d #%d ----\n",fd,
 C1->c_cflag,C1->c_xsid,Cx->c_xsid);
				MxDoupTerse = 1;
			}
			xsid = C1->c_xsid;
			type = C1->c_type;
			icc = C1->c_icc;
			occ = C1->c_occ;

			C1->c_type |= CY_ZOMB;
			C1->c_fd = -1;
			if( tid == 0 && C1->c_tid ){
				tid = C1->c_tid;
				C1->c_tid = 0;
			}
		}
	}
	if( dont_close ){
		return;
	}
//yprintf(Mc,"--Cony SHUT[%d] #%d y%X cc=%d/%d [%s]<= %s:%d",fd,xsid,type,occ,icc,wh,FL_BAR);
	if( (type & CY_XOUT) == CY_XOUT || (type & CY_XIN) == CY_XIN ){
		double St = Time();
		int rdy;
		shutdownWR(fd);
		rdy = PollIn(fd,100);
//yprintf(Mc,"--Cony SHUT[%d] #%d y%X rdy=%d (%.3f) cc=%d/%d",fd,xsid,type,rdy,Time()-St,occ,icc);
	}
	ShutdownSocket(fd);
	FD_closeX(FL_BAR,Mc,Cv,cn,fd,wh,0);
	if( tid ){
		double St = Time();
		int terr;
		terr = thread_wait(tid,100);
 sv1log("--tid Y%d closeFd wait[%X] err=%d (%.3f) th=%d/%d\r\n", MxId,
 PRTID(tid),terr,Time()-St,actthreads(),numthreads());
		sv1log("--Y%d wait[%X] err=%d (%.3f) th=%d/%d\n", MxId,
			PRTID(tid),terr,Time()-St,actthreads(),numthreads());
		if( terr != 0 ){
			addTid(Mc,tid);
		}
	}
}
static char yy_ev0[32] = {
	0x02,0x0A,0xFF,0xFF,
	0xBE,0xB6,0x07,0xA9,
	0x57,0x00,0x00,0x00,
	0x15,0x00,0x40,0x00,
	0x00,0x00,0x00,0x00,
	0x4F,0x01,0x09,0x01,
	0x4F,0x01,0xDD,0x00,
	0x04,0x00,0x01,0x70
};
static void closeXclients(Cony *Cv,int cn,int waitms){
	int ci;
	Cony *C1;
	int ready1,ready2;
	int wcc;

	if( isWindows() ){
		/* a trial to close xterm normally to terminate bash/CYGWIN */
		for( ci = cn-1; 0 <= ci; ci-- ){
			C1 = &Cv[ci];
			if( C1->c_type != CY_XOUT || C1->c_fd < 0 ){
				continue;
			}
			ready1 = PollIn(C1->c_fd,10);
			wcc = write(C1->c_fd,yy_ev0,32);
			ready2 = PollIn(C1->c_fd,waitms);
			sv1log("--YMUX close #%d [%d] ready=%d,%d\n",C1->c_xsid,
				C1->c_fd,ready1,ready2);
		}
	}
}

static void setCony(Cony *C1,int ctype,int etype,int fd,int xsid){
	C1->c_type = ctype;
	C1->c_cflag = 0;
	C1->c_etype = etype;
	C1->c_xsid = xsid;
	C1->c_fd = fd;
	C1->c_fp = 0;
	C1->c_fpbuf = 0;
	C1->c_outbuf = 0;
	C1->c_icc = 0;
	C1->c_occ = 0;
	C1->c_rcptsent = 0;
	C1->c_ipk = 0;
	C1->c_recv = 0;
	C1->c_totalread64 = 0;
	C1->c_totalsent64 = 0;
	C1->c_pendlog = 0;
	C1->c_pauseTill = 0;
	clearVStr(C1->c_dst_port);
}
static void clearCony(Cony *C1){
	bzero(C1,sizeof(Cony));
	C1->c_type = CY_NULL;
	C1->c_cflag = 0;
	C1->c_etype = 0;
	C1->c_xsid = 0;
	C1->c_fd = -1;
	C1->c_fp = 0;
	C1->c_fpbuf = 0;
	C1->c_outbuf = 0;
	C1->c_icc = 0;
	C1->c_occ = 0;
	C1->c_rcptsent = 0;
	C1->c_ipk = 0;
	C1->c_recv = 0;
	C1->c_totalread64 = 0;
	C1->c_totalsent64 = 0;
	C1->c_pendlog = 0;
	C1->c_pauseTill = 0;
	clearVStr(C1->c_dst_port);
}

static int ConyFlags(MuxCtx *Mc,int xsid,int set,int clr){
	int ci;
	Cony *C1 = 0;
	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];
		if( C1->c_xsid == xsid ){
			C1->c_cflag |= set;
			C1->c_cflag &= ~clr;
			return C1->c_cflag;
		}
	}
	return 0;
}
static int actCony(MuxCtx *Mc,int byfree){
	int nconn = 0;
	int nfree = 0;
	int ci;
	int mxId = MxId;
	int cn = MxCn;
	Cony *cv = MxCv;
	Cony *C1 = 0;

	for( ci = 0; ci < cn; ci++ ){
		if( !isAliveY(mxId) ){
sv1log("####FATAL addCony(%X,%d) not alive Y%d\n",p2i(Mc),byfree,mxId);
			break;
		}
		if( mxId != MxId ){
sv1log("####FATAL addCony(%X,%d) dangling Y%d Y%d\n",p2i(Mc),byfree,mxId,MxId);
			break;
		}
		C1 = &cv[ci];
		if( C1->c_type == CY_NULL || (C1->c_type & CY_ZOMB) ){
			nfree++;
		}else{
			nconn++;
		}
	}
	if( byfree )
		return nfree;
	else	return nconn;
}
static int YYMUXnotfull(MuxCtx *cMc,MuxCtx *Mc,int nvia){
	int nfree = 0;
	int ri;
	int mxId = MxId;
	int cmxId = cMc->mc_id;

	if( MxStatENDING ){
sv1log("--isViaYY%d ENDING-C FATAL\n",mxId);
		return 0;
	}
	if( MxMuxStart == 0 ){
sv1log("--isVia Y%d notfull (%d) ---- NOT READY A---- << Y%d\n",MxId,MxCn,cmxId);
		for( ri = 0; ri < 50; ri++ ){
			msleep(100);
			if( MxMuxStart != 0 ){
				break;
			}
			if( !isAliveY(mxId) ){
sv1log("--isVia Y%d notfull (%d) ---- gone A FATAL\n",mxId);
				return 0;
			}
		}
		if( MxMuxStart == 0 ){
sv1log("--isVia Y%d notfull (%d) ---- NOT READY B----\n",MxId,MxCn);
			return 0;
		}
sv1log("--isVia Y%d notfull (%d) ---- became READY (%d)\n",MxId,MxCn,ri);
	}
	if( !isAliveY(mxId) ){
sv1log("--isVia Y%d notfull ---- gone B FATAL\n",mxId);
		return 0;
	}
	if( MxStatENDING ){
sv1log("--isViaYY%d ENDING-D FATAL\n",mxId);
		return 0;
	}
	nfree = actCony(Mc,1);
	if( 1 < nvia && MxCn-MxCn/nvia < nfree ){
sv1log("--isVia Y%d notfull (%d/%d) ---- OK /%d << Y%d\n",MxId,nfree,MxCn,nvia,cmxId);
		return 1;
	}else
	if( MxCn * 0.2 < nfree ){
sv1log("--isVia Y%d notfull (%d/%d) ---- OK /%d << Y%d\n",MxId,nfree,MxCn,nvia,cmxId);
		return 1;
	}else{
sv1log("--isVia Y%d notfull (%d/%d) ---- FULL /%d << Y%d\n",MxId,nfree,MxCn,nvia,cmxId);
		return 0;
	}
}
static Cony *addCony(Cony *Cv,int cn,int xsid,int ctype,int etype,int fd){
	int ci;
	Cony *C1 = 0;
	for( ci = 0; ci < cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_type == CY_NULL || (C1->c_type & CY_ZOMB) ){
			setCony(C1,ctype,etype,fd,xsid);
			if( ctype == CY_YMUXIN ){
				setsockbuf(fd,128*1024,0);
				C1->c_fp = fdopen(fd,"r");
				if( C1->c_fp == NULL ){
					sv1log("####addCony FATAL cannot fopen[%d] e%d\n",
						fd,errno);
				}else{
					C1->c_fpbuf = BUF_get("Fbuf",128*1024);
					setbuffer(C1->c_fp,C1->c_fpbuf->buf_data,C1->c_fpbuf->buf_size);
				}
			}
			if( ctype == CY_YMUXOUT ){
				setsockbuf(fd,0,128*1024);
			}
			break;
		}
	}
	if( ci == cn ){
		if( C1 == NULL ){
			sv1log("##YY FATAL addCony: table full cn=%d <= [%d]#%d s%04X\n",
				cn,fd,xsid,ctype);
		}else
		sv1log("##YY FATAL addCony: table full [%d]#%d s%04X <= [%d]#%d s%04X\n",
			C1->c_fd,C1->c_xsid,C1->c_type,fd,xsid,ctype
		);
	}
	return C1;
}
static int openAppAcc(MuxCtx *Mc,PCStr(wh),PortMap1 *Pm,int pbase,int *rsock,int *rport);
static int nextXsid(MuxCtx *Mc,Cony *Cv,int Cn);
static int activatePortMaps(MuxCtx *Mc){
	PortMap1 *Pm;
	int pi;
	int sock;
	int port;
	int xsid;
	Cony *C1;
	IStr(opts,128);

	for( pi = 0; pi < elnumof(Mc->mc_portmap.pm_maps); pi++ ){
		Pm = &Mc->mc_portmap.pm_maps[pi];
		if( Pm->pm_local.p1_port ){
			openAppAcc(Mc,"PortMap",Pm,Pm->pm_local.p1_port,&sock,&port);
			Pm->pm_local.p1_sock = sock;
			if( 0 <= sock && 0 < port ){
				xsid = MxXsid;
				nextXsid(Mc,MxCv,MxCn);
				FD_new(sock,"PortMap",0);
				C1 = addCony(MxCv,MxCn,xsid,CY_ACC,ET_CLNT,sock);
				if( Pm->pm_remote.p1_flags & P1_UDP ){
					strcpy(opts,".udp");
				}
				if( Pm->pm_local.p1_flags & P1_UDP ){
					C1->c_cflag |= CF_UDPACC;
				}
				sprintf(C1->c_dst_port,"%s://%s:%d%s",
					Pm->pm_remote.p1_proto,
					Pm->pm_remote.p1_host,
					Pm->pm_remote.p1_port,
					opts
				);
 yprintf(Mc,"Activated[%d] %d(%d) => %s",sock,port,Pm->pm_local.p1_port,
	C1->c_dst_port);
				Pm->pm_local.p1_port = port;
			}else{
			}
		}
	}
	return 0;
}
static int fcloseConies(Cony *Cv,int cn){
	Cony *C1;
	int ci;
	int nc = 0;
	FILE *fp;
	const char *buf;
	BufDesc *fpbuf;

	for( ci = 0; ci < cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_fp ){
			/*
			fcloseFILE(C1->c_fp);
			*/
			fp = C1->c_fp;
			C1->c_fp = 0;
			fcloseFILE(fp);
			if( C1->c_fpbuf ){
				/*
				putb(C1->c_fpbuf);
				*/
				fpbuf = C1->c_fpbuf;
				C1->c_fpbuf = 0;
				putb(fpbuf);
			}
			nc++;
		}
	}
	return nc;
}
static int clearConiesFd(Cony *Cv,int cn,int fd){
	Cony *C1;
	int clsn = 0;
	int ci;

	for( ci = 0; ci < cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_fd == fd ){
			clsn++;
			C1->c_fd = -1;
		}
	}
	return clsn;
}

static int getXpend(Cony *Cv,int Cn,Cony *Ci,int log){
	int ci;
	Cony *C1;
	int pending = 0;

	for( ci = 0; ci < Cn; ci++ ){
		C1 = &Cv[ci];	
		pending = C1->c_totalread64 - C1->c_totalsent64;
		if( pending && log ){
/*
 sv1log("----#%d Xpend=%d (%d / %d)\n",C1->c_xsid,pending,
 (int)C1->c_totalsent64,(int)C1->c_totalread64);
*/
		}
		if( Ci == 0 ){
		}else
		if( C1->c_xsid == Ci->c_xsid ){
			break;
		}
	}
	return pending;
}
static void gotXsent(MuxCtx *Mc,MuxMssg *mx,Int64 rcpt64){
	int ci;
	Cony *C1;
	int pending;

	if( rcpt64 == 0 ){
		return;
	}
	if( CID_PRI <= mx->m_xsid ){
		MxXack += rcpt64;
	}
	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];	
		if( C1->c_type == CY_XIN )
		if( C1->c_xsid == mx->m_xsid ){
			C1->c_totalsent64 += rcpt64;
			pending = C1->c_totalread64 - C1->c_totalsent64;
			if( C1->c_cflag & CF_SUSPEND ){
				C1->c_cflag &= ~CF_SUSPEND;
				MxDoupdate = "FlowCtrlCont";
 sv1log("####CONT #%d pend=%d (%d)\n",C1->c_xsid,pending,(int)rcpt64);
			}
/*
if( 0x10000 < pending )
 sv1log("--Y%d#%d sent %d (%d / %d) pend = %d\r\n",
 MxId,mx->m_xsid,(int)rcpt64,(int)C1->c_totalsent64,(int)C1->c_totalread64,pending);
*/

			if( pending || C1->c_pendlog ){
				Verbose("---#%d read=%llu sent=%llu(%llu) pend=%d\n",
					C1->c_xsid,
					C1->c_totalread64,
					C1->c_totalsent64,
					rcpt64,
					pending);
				C1->c_pendlog = 0;
			}
			break;
		}
	}
}
static int getXrcpt(MuxCtx *Mc,Cony *Cv,int Cn,int xsid,int max){
	int ci;
	Cony *C1;
	Cony *Ci = 0;
	int nrecv = 0;
	int rcc;
	for( ci = 0; ci < Cn; ci++ ){
		C1 = &Cv[ci];	
		if( C1->c_xsid == xsid )
		if( 0 < (rcc = C1->c_recv) ){
			Ci = C1;
			if( max < nrecv + C1->c_recv ){
				rcc = max - nrecv;
				Verbose("--RCPT %3d#%d too large %d / %d\n",
					0xFF&MxOseq,C1->c_xsid,rcc,C1->c_recv);
				Ci->c_rcptsent += rcc;
				nrecv += rcc;
				C1->c_recv -= rcc;
				break;
			}else{
				Ci->c_rcptsent += rcc;
				nrecv += rcc;
				C1->c_recv -= rcc;
				break; /* don't mix RCPT of multi-conn. */
			}
		}
	}
	if( Ci != 0 && 0 < nrecv ){
		if( 64*1024 < nrecv || MxFlagsVERBOSE || 0 < MxDebug ){
			sv1log("--#%d send RCPT (%d) %llu %llu /%d\n",
				Ci->c_xsid,nrecv,Ci->c_rcptsent,Ci->c_icc,Ci->c_ipk);
		}
	}
	return nrecv;
}
static Cony *findXout(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci,MuxMssg *mx){
	Cony *Co = 0;
	Cony *Cz = 0;
	int ci;
	Cony *C1;
	int cstat;
	int cstat2;
	int xsid;

	if( Ci->c_type == CY_YMUXIN ){
		cstat = CY_XOUT;
		cstat2 = CY_UDP_SV;
		xsid = mx->m_xsid;
	}else{
		cstat = CY_YMUXOUT;
		cstat2 = -1;
		xsid = CID_MUX;
	}
	for( ci = 0; ci < Cn; ci++ ){
		C1 = &Cv[ci];	
		if( C1->c_type == cstat
		 || C1->c_type == cstat2
		){
			if( C1->c_xsid == xsid ){
				Co = C1;
				break;
			}
			if( (0xFF & C1->c_xsid) == (0xFF & xsid) ){
				Co = C1;
				break;
			}
		}
		if( (C1->c_type & ~CY_ZOMB) == cstat
		 || (C1->c_type & ~CY_ZOMB) == cstat2
		){
			if( (0xFF & C1->c_xsid) == (0xFF & xsid) ){
				Cz = C1;
				break;
			}
		}
	}
	if( Co == 0 && Cz != 0 ){
		sv1log("--YMUX to zombi [%d] %X %X #%d len=%d\n",
			Cz->c_fd,cstat,Cz->c_type,xsid,bodyLeng(mx));
	}else
	if( Co == 0 ){
		sv1log("--YMUX not found out %X,#%d len=%d\n",
			cstat,xsid,bodyLeng(mx));
		for( ci = 0; ci < Cn; ci++ ){
			C1 = &Cv[ci];	
			if( C1->c_type ){
				sv1log("--YMUX find [%2d] %04X #%d\n",ci,
					C1->c_type,C1->c_xsid);
			}
		}
	}else
	if( Co->c_cflag & CF_DISCARDING ){
		sv1log("--YMUX discarding out [%d] %X %X #%d len=%d\n",
			Co->c_fd,cstat,Co->c_type,xsid,bodyLeng(mx));
		Co = 0;
	}
	return Co;
}
static Cony *findXin(MuxCtx *Mc,int xsid){
	Cony *Ci = 0;
	int ci;
	Cony *C1;

	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];	
		if( C1->c_type == CY_XIN
		 || C1->c_type == CY_UDP_SV
		){
			if( (0xFF & C1->c_xsid) == (0xFF & xsid) ){
				Ci = C1;
				break;
			}
		}
	}
	return Ci;
}

static void sendSHUT(MuxCtx *Mc){
	MuxMssg mx;
	IStr(buf,PHSIZE+PBSIZE);
	int wcc;

	mx.m_rsnt = 0;
	mx.m_type = PY_SHUT;
	mx.m_flag = MF_NOBODY;
	mx.m_leng = 0;
	mx.m_rcpt = 0;
	mx.m_snum = MxOseq++;
	mx.m_xsid = 0;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE);
	if( !IsAlive(MxYsock) ){
		sv1log("##Y%d/%d SHUT MIGHT UNSENT (shut=%X sent=%d)\n",
			MxId,MxParentId,MxShutting,MxSHUTsent);
	}
	MxSHUTsent++;
}
static void sendSHUT1st(MuxCtx *Mc){
	if( MxSHUTsent == 0 ){
		sendSHUT(Mc);
	}
}

/*
 * RCPT should notify the total number of received data ?
 */
static void scanRCPT(MuxCtx *Mc,MuxMssg *mx,const char *bp){
	Int64 rcpt64;
	Cony *Ci;
	Int64 olen64;
	int oseq;

	if( Ci = findXin(Mc,mx->m_xsid) ){
		olen64 = Ci->c_totalread64;
		oseq = Ci->c_totalreadN;
	}else{
		olen64 = 0;
		oseq = 0;
	}
	rcpt64 = getInt64(bp+PHSIZE);
	if( 0x10000 <= rcpt64 ){
	sv1log("--Y%d %3d#%d recv RCPT (%llu) %llu /%d\n",MxId,
		mx->m_snum,mx->m_xsid,rcpt64,olen64,oseq);
	}
	if( mx->m_xsid == CID_MUX ){
		/* CID_MUX(#1) to check MxXack? */
	}else{
		gotXsent(Mc,mx,rcpt64);
	}
}
static void sendRCPT1(MuxCtx *Mc,int xsid,int rcpt){
	IStr(buf,PHSIZE+8);
	char *bp = ((char*)buf)+PHSIZE;
	MuxMssg mx;

	putInt64(bp,rcpt);
	mx.m_rsnt = 0;
	mx.m_type = PY_RCPT;
	mx.m_flag = 0;
	mx.m_xsid = xsid;
	mx.m_snum = MxOseq++;
	mx.m_leng = 8;
	mx.m_rcpt = rcpt;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE+mx.m_leng);
}
static void sendRCPT(Cony *Cv,int Cn,Cony *Co,MuxCtx *Mc){
	int xsid = Co->c_xsid;
	int rcpt;

	rcpt = getXrcpt(Mc,Cv,Cn,xsid,0x7FFFFFFF);
	sendRCPT1(Mc,xsid,rcpt);
}
static void scanRSMQ(MuxCtx *Mc,MuxMssg *mx,const char *bp){
	Int64 roff64;

	roff64 = getInt64(bp+PHSIZE);
	sv1log("--Y%d RSM got request from peer:%llu Sent:%llu\n",
		MxId,roff64,MxOlen64);
	respRSMD(Mc,roff64);
}
static void sendRSMQ(MuxCtx *Mc){
	MuxMssg mx;
	IStr(buf,PHSIZE+8);
	char *bp = ((char*)buf)+PHSIZE;
	int wcc;

	putInt64(bp,MxIlen64);
	mx.m_rsnt = 1; /* not to be counted by the receiver */
	mx.m_type = PY_RSMQ;
	mx.m_flag = 0;
	mx.m_xsid = 0;
	mx.m_snum = MxOseq;
	mx.m_leng = 8;
	mx.m_rcpt = 0;
	enPack(&mx,buf);
	sv1log("--Y%d RSM sent request RSMQ %llu (%llu)\n",
		MxId,MxIlen64,MxOlen64);
	sendToMux(Mc,&mx,buf,PHSIZE+mx.m_leng);
}
static void sendRSMD(MuxCtx *Mc){
	MuxMssg mx;
	IStr(buf,PHSIZE);
	int wcc;

	mx.m_rsnt = 1; /* not to be counted by the receiver */
	mx.m_type = PY_RSMD;
	mx.m_flag = MF_NOBODY;
	mx.m_leng = 0;
	mx.m_rcpt = 0;
	mx.m_snum = MxOseq;
	mx.m_xsid = 0;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE);
}
static void scanINFO(MuxCtx *Mc,MuxMssg *mx,PCStr(msg)){
	if( *msg == 'C' ){
		int wcc = -2;
		if( 0 <= MxPsins ){
			if( MxFlagsVERBOSE )
			sv1log("--YY from remote console: %d =>[%d] ...\n",
				mx->m_leng,MxPsins);
			wcc = write(MxPsins,msg+1,mx->m_leng-1);
		}
		if( MxFlagsVERBOSE )
		sv1log("--YY from remote console: %d =>[%d] wcc=%d\n",
			mx->m_leng,MxPsins,wcc);
		return;
	}
	if( *msg == 'O' ){
		fwrite(msg+1,1,mx->m_leng-1,stdout);
		return;
	}
	if( *msg == 'E' ){
		fprintf(stderr,"%s",msg+1);
		return;
	}
	sv1log("--Y%d info #%d %d {%s}\n",MxId,mx->m_xsid,mx->m_leng,msg);
	if( *msg == 'e' ){
		fprintf(stderr,"#YMUX %s\n",msg+1);
	}
}
static void sendINFO(MuxCtx *Mc,PCStr(msg),int leng){
	MuxMssg mx;
	IStr(buf,PHSIZE+PBSIZE);
	int wcc;

	if( leng < 0 ){
		Xstrcpy(DVStr(buf,PHSIZE),msg);
		leng = strlen(buf+PHSIZE) + 1;
	}else
	if( PBSIZE < leng ){
		sv1log("----FATAL: TOO LARGE INFO (%d/%d)\n",leng,PBSIZE);
		leng = PBSIZE;
	}else{
		bcopy(msg,buf+PHSIZE,leng);
	}
	mx.m_rsnt = 0;
	mx.m_type = PY_INFO;
	mx.m_flag = 0;
	mx.m_rcpt = 0;
	mx.m_snum = MxOseq++;
	mx.m_leng = leng;
	mx.m_xsid = 0;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE+mx.m_leng);
}
static void sendREQ(MuxCtx *Mc,PCStr(msg)){
	MuxMssg mx;
	IStr(buf,PHSIZE+PBSIZE);
	IStr(xmsg,128);

	sprintf(xmsg,"%f %s",Time(),msg);
	Xstrcpy(DVStr(buf,PHSIZE),xmsg);
	mx.m_rsnt = 0;
	mx.m_type = PY_REQ;
	mx.m_flag = 0;
	mx.m_rcpt = 0;
	mx.m_snum = MxOseq++;
	mx.m_leng = strlen(buf+PHSIZE)+1;
	mx.m_xsid = 0;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE+mx.m_leng);
}
static void scanREQ(MuxCtx *Mc,MuxMssg *qmx,PCStr(msg)){
	MuxMssg mx;
	IStr(buf,PHSIZE+PBSIZE);
	int wcc;

	if( strcasestr(msg,"HOLDONNX=on") ){
		int ofg = MxFlags;
		MxFlags |= MX_HOLDONNX;
		sv1log("##Y%d PY_REQ %X (%X) %s\n",MxId,MxFlags,ofg,msg);
	}
	if( strcasestr(msg,"HOLDONNX=off") ){
		MxFlags &= ~MX_HOLDONNX;
	}
	sv1log("--Y%d got REQ %d#%d %d {%s}\n",
		MxId,qmx->m_snum,qmx->m_xsid,qmx->m_leng,msg);
	Xstrcpy(DVStr(buf,PHSIZE),msg);
	mx.m_rsnt = 0;
	mx.m_type = PY_RESP;
	mx.m_flag = 0;
	mx.m_rcpt = 0;
	mx.m_snum = MxOseq++;
	mx.m_leng = strlen(buf+PHSIZE)+1;
	mx.m_xsid = 0;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE+mx.m_leng);
}
static void scanRESP(MuxCtx *Mc,MuxMssg *rmx,PCStr(msg)){
	double Snt = 0;
	sscanf(msg,"%lf",&Snt);
	sv1log("--Y%d got RESP %d#%d %d {%s} (%f)\n",MxId,rmx->m_snum,rmx->m_xsid,
		rmx->m_leng,msg,Time()-Snt);
}
static int sendCONN(MuxCtx *Mc,int xsid,PCStr(dstport)){
	MuxMssg mx;
	IStr(buf,PHSIZE+PBSIZE);
	int wcc;

	mx.m_rsnt = 0;
	mx.m_type = PY_CONN;
	mx.m_flag = MF_NOBODY;
	mx.m_leng = 0;
	mx.m_rcpt = 0;
	mx.m_snum = MxOseq++;
	mx.m_xsid = xsid;
	if( dstport[0] ){
		Xstrcpy(DVStr(buf,PHSIZE),dstport);
		mx.m_leng = strlen(buf+PHSIZE)+1;
		mx.m_flag = 0;
	}
	enPack(&mx,buf);
	return sendToMux(Mc,&mx,buf,PHSIZE+mx.m_leng);
}
static void sendRSET(Cony *Cv,int Cn,int xsid,MuxCtx *Mc){
	MuxMssg mx;
	IStr(buf,PHSIZE+PBSIZE);
	int wcc;

	mx.m_rsnt = 0;
	mx.m_type = PY_RSET;
	mx.m_flag = MF_NOBODY;
	mx.m_leng = 0;
	mx.m_rcpt = getXrcpt(Mc,Cv,Cn,xsid,0xFFFF);
	mx.m_snum = MxOseq++;
	mx.m_xsid = xsid;
	enPack(&mx,buf);
	sendToMux(Mc,&mx,buf,PHSIZE);
}
static int deflatePack(MuxCtx *Mc,MuxMssg *mx,char *bp){
	int ilen = bodyLeng(mx);
	IStr(zb,PBSIZE);
	int flag;
	int zlen;
	int tsz;

	if( MxFlagsDEFLATE2 == 0 ){
		return 0;
	}
	if( MxZ1dfl == 0 ){
		return 0;
	}
	if( ConyFlags(Mc,mx->m_xsid,0,0) & CF_NODEFLATE ){
		return 0;
	}else
	/* peep the syntax of bp[0-3] */
	if( flag = isZCpack(bp,ilen) ){
		sv1log("----detected ZC, set NODEFLATE #%d\n",mx->m_xsid);
		ConyFlags(Mc,mx->m_xsid,CF_NODEFLATE,0);
		if( flag & ZC_DEFLATE ){
			/* compressed already */
			return 0;
		}else{
			return 0;
		}
	}else{
		if( ilen < 16 ){
			return 0;
		}
	}
	if( 1 ){
		mx->m_flag |= MF_ZCREDHY;
		tsz = 4;
	}else{
		tsz = 0;
	}
	zlen = deflateZ1(MxZ1dfl,bp,ilen,AVStr(zb),sizeof(zb)-tsz);
	if( MxFlagsVERBOSE ){
 yprintf(Mc,"----dfl %d#%d %d / %d",mx->m_snum,mx->m_xsid,zlen,ilen);
	}
	if( mx->m_flag & MF_ZCREDHY ){
		/* reserved */
		bp[0] = 0x00;
		bp[1] = 0x00;
		bp[2] = 0x00;
		bp[3] = 0x00;
	}
	bcopy(zb,bp+tsz,zlen);
	mx->m_leng = tsz+zlen;
	mx->m_flag |= MF_DEFLATE;
	MxZ1.zs_litotal += ilen;
	MxZ1.zs_zototal += zlen;
	return 1;
}
static int inflateBody(MuxCtx *Mc,MuxMssg *mx,char *bp,int ilen){
	int zlen;
	IStr(zb,PBSIZE);
	int tsz;

	if( mx->m_flag & MF_DEFLATE ){
		if( MxZ1ifl == 0 ){
 yprintf(Mc,"----ifl %d#%d %d NO Z1Ctx",mx->m_snum,mx->m_xsid,mx->m_leng);
			return 0;
		}
		if( mx->m_flag & MF_ZCREDHY ){
			tsz = 4;
		}else{
			tsz = 0;
		}
		zlen = inflateZ1(MxZ1ifl,bp+tsz,ilen-tsz,AVStr(zb),sizeof(zb));
		if( MxFlagsVERBOSE ){
 yprintf(Mc,"----ifl %d#%d %d => %d",mx->m_snum,mx->m_xsid,ilen,zlen);
		}
		bcopy(zb,bp,zlen);
		MxZ1.zs_zitotal += ilen;
		MxZ1.zs_lototal += zlen;
		return zlen;
	}
	return ilen;
}
static void dumpXmsg(MuxCtx *Mc,Cony *Ci,PCStr(bp),int ilen);
int setNonblockingSocket(int fd,int aon);
int PollInOut(int fd,int timeout){
	int fdv[2],qev[2],rev[2];
	int rdy;

	fdv[0] = fd; qev[0] = PS_IN;
	fdv[1] = fd; qev[1] = PS_OUT;
	rdy = PollInsOuts(timeout,2,fdv,qev,rev);
	return rdy;
}
static int ysends(MuxCtx *Mc,Cony *Co,PCStr(buf),int len){
	int fd = Co->c_fd;
	int xsid = Co->c_xsid;
	int wcc0 = 0;
	int wcc = 0;
	int wc1;
	int ri = 0;
	int serrno;
	BufDesc *Bp = Co->c_outbuf;

	if( MxNBSendBuf ){
		/* avoiding frozen JollysFastVNC with zrle/zlib enabled */
		/* by -yooz32k */
		int oiz,ooz;
		getsockbuf(fd,&oiz,&ooz);
		setsockbuf(fd,16*1024,MxNBSendBuf*1024);
	}
	sprintf(IoStat,"ysend Y%d #%d %llu +%d (%d)(%d)",
		MxId,xsid,Co->c_icc,len,
		Co->c_recv,(Bp!=0)?Bp->buf_tail:0);

	if( Bp && Bp->buf_tail ){
		char *buff = Bp->buf_data;
		int blen = Bp->buf_tail;
		double St = Time();
		int rem;

		setNonblockingSocket(fd,1);
		errno = 0;
		wcc = send(fd,buff,blen,0);
		serrno = errno;
		setNonblockingSocket(fd,0);
		if( wcc < blen ){
			if( wcc < 0 ){
				wcc = 0;
				rem = blen;
			}else{
				rem = blen-wcc;
				bcopy(buff+wcc,buff,blen-wcc);
			}
			if( Bp->buf_size < (blen-wcc)+len ){
 sv1log("----ysend OVF buff %d/%d\n",(blen-wcc)+len,Bp->buf_size);
				return -1;
			}
			bcopy(buf,buff+(blen-wcc),len);
			Bp->buf_tail = (blen-wcc)+len;
 sv1log("----ysend %d/%d+%d buff=%d e%d rdy=%X\n",
	wcc,blen,len,Bp->buf_tail,serrno,PollInOut(fd,TIMEOUT_IMM));
			return wcc;
		}else{
			wcc0 = blen;
			Bp->buf_tail = 0;
 sv1log("----ysend drained %d/%d buff=%d\n",wcc,blen,Bp->buf_tail);
		}
	}
	for( wcc = 0; wcc < len && ri < 10; ri++ ){
		setNonblockingSocket(fd,1);
		errno = 0;
		wc1 = send(fd,buf+wcc,len-wcc,0);
		serrno = errno;
		setNonblockingSocket(fd,0);
		if( wc1 < len || 32*1024 < len || 64*1024 < Co->c_recv ){
 sv1log("----ysend sent to local Y%d #%d %llu x%d %5d/%5d (%d) e%d\n",
	MxId,xsid,Co->c_icc,ri,wc1,len-wcc,Co->c_recv,serrno);
		}
		if( wc1 <= 0 ){
			if( serrno == EAGAIN || serrno == EWOULDBLOCK ){
				int iordy;
				double St = Time();
				iordy = PollInOut(fd,100);
 sv1log("----ysend retry #%d input-ready(%X)(%.3f)\n",xsid,iordy,Time()-St);
				if( iordy & 1 ){
				}else
				if( iordy & 2 ){
 sv1log("----ysend retry #%d (%.3f)\n",xsid,Time()-St);
					continue;
				}
 sv1log("----ysend retry #%d (%.3f) LATER %d/%d rdy=%d,%d\n",xsid,Time()-St,
	len-wcc,len,PollOut(fd,1),PollIn(fd,1));
				Co->c_cflag |= CF_WAITOUT;
				Bp = BUF_get("SEND",256*1024);
				Bp->buf_tail = len-wcc;
				bcopy(buf+wcc,Bp->buf_data,len-wcc);
				Co->c_outbuf = Bp;
			}else{
				/* SIGPIPE or so */
 sv1log("----ysend %d+%d/%d e%d to be discared ####\n",wc1,wcc,len,serrno);
				/* tobe sent as RCPT */
				wcc = len;
			}
			break;
		}else{
			wcc += wc1;
		}
	}
	Xsprintf(TVStr(IoStat)," DONE %d x%d",wcc,ri);
	return wcc0 + wcc;
}
static int flushOutBuf(MuxCtx *Mc){
	Cony *C1;
	int ci;
	int fn = 0;
	int wcc;
	BufDesc *Bp;

	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];
		if( Bp = C1->c_outbuf ){
			if( 0 < Bp->buf_tail ){
				wcc = ysends(Mc,C1,"",0);
				if( 0 < wcc ){
					C1->c_recv += wcc;
					sendRCPT(MxCv,MxCn,C1,Mc);
				}
			}
		}
	}
	return fn;
}
static int flushRCPT(MuxCtx *Mc,int force){
	Cony *C1;
	int ci;
	int fn = 0;
	int wcc;

	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];
		if( force && 0 < C1->c_recv || 16*1024 < C1->c_recv ){
			Verbose("--Y%d #%d flushRCPT %lld %d\n",MxId,
				C1->c_xsid,C1->c_icc,C1->c_recv);
			sendRCPT(MxCv,MxCn,C1,Mc);
		}
	}
	return fn;
}
static int discardPack(MuxCtx *Mc,MuxMssg *mx,PCStr(bp),int ilen){
	int olen;

	olen = inflateBody(Mc,mx,(char*)bp,ilen);
	sendRCPT1(Mc,mx->m_xsid,olen);
	return 0;
}
static int recvDATA(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Co,MuxMssg *mx,PCStr(bp),int olen,int OOB){
	int wcc;
	int aolen = olen;

	olen = inflateBody(Mc,mx,(char*)bp,olen);
	dumpXmsg(Mc,Co,bp,olen);
	if( OOB ){
		sv1log("----OOB DATA recv #%d len=%d [%X]\n",Co->c_xsid,olen,0xFF&bp[0]);
		wcc = sendOOB(Co->c_fd,bp,olen);
	}else{
		if( Co->c_cflag & CF_NONBLKSEND ){
			wcc = ysends(Mc,Co,bp,olen);
		}else
		if( Co->c_cflag & CF_UDP_CL ){
			wcc = SendTo(Co->c_fd,bp,olen,Co->c_src_addr,
				Co->c_src_portnum);

 sv1log("----UDP recv [%d] #%d %d wcc=%d e%d =>[%s:%d] CF=%X\n",Co->c_fd,
 mx->m_xsid,olen,wcc,errno,Co->c_src_addr,Co->c_src_portnum,Co->c_cflag);

		}else{
			wcc = send(Co->c_fd,bp,olen,0);
		}
	}
	if( wcc < 0 ){
	}else{
		Co->c_recv += wcc;
		Co->c_occ += wcc;
	}
	if( 0 <= MxYsock ){
		if( MaxPending(Mc,128*1024) < Co->c_recv ){
			sendRCPT(Cv,Cn,Co,Mc);
		}
	}
	Verbose("->M [%d] %d / %d\n",Co->c_fd,wcc,olen);
	return 0;
}
static void sendDATA(MuxCtx *Mc,Cony *Cv,int Cn,int xsid,Cony *Co,char *bp,int ilen,int olen,int OOB){
	MuxMssg mx;

	mx.m_rsnt = 0;
	mx.m_type = PY_DATA;
	mx.m_flag = 0;
	if( OOB ){
		sv1log("----OOB DATA sent #%d len=%d [%X]\n",xsid,olen,0xFF&bp[0]);
		mx.m_flag |= MF_OOB;
	}
	mx.m_rcpt = getXrcpt(Mc,Cv,Cn,xsid,0xFFFF);
	mx.m_snum = MxOseq++;
	mx.m_leng = ilen;
	mx.m_xsid = xsid;
	olen += PHSIZE;
	bp -= PHSIZE;

	deflatePack(Mc,&mx,bp+PHSIZE);
	enPack(&mx,bp);
	if( Co != 0 && MxYsock != Co->c_fd ){
		syslog_ERROR("####DATA-FD?#### Mc[%d] Co[%d]\n",MxYsock,Co->c_fd);
	}
	sendToMux(Mc,&mx,bp,PHSIZE+mx.m_leng);
}
static void dumpXmsg(MuxCtx *Mc,Cony *Ci,PCStr(bp),int ilen){
	unsigned char *up = (unsigned char *)bp;
	int pi;

	if( MxFlagsDUMP == 0 ){
		return;
	}
	sv1log("--X [%d] rcc=%-4d %u\n",Ci->c_fd,ilen,(int)Ci->c_totalread64);
	fprintf(stderr,"[%2d]%X (%4d) ",Ci->c_fd,Ci->c_type,ilen);
	for( pi = 0; pi < ilen && pi < 32; pi++ ){
		fprintf(stderr,"%02X ",up[pi]);
	}
	fprintf(stderr,"\r\n");
}

static int yyCONSOLE(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci,int fd){
	IStr(mbuf,PHSIZE+PBSIZE+1);
	char *bp = mbuf + PHSIZE;
	int rcc;
	int pending;

	rcc = read(fd,bp,PBSIZE);
	if( 0 < rcc ){
		if( MxFlagsVERBOSE ){
			pending = Ci->c_totalread64 - Ci->c_totalsent64;
			sv1log("--YY from local console: rcc=%d, pend=%d\n",
				rcc,pending);
		}
		sendDATA(Mc,Cv,Cn,CID_SIN,0,bp,rcc,rcc,0);
	}
	return 0;
}
static void scanDATA(MuxCtx *Mc,MuxMssg *mx,PCStr(bp)){
	int wcc;

	switch( mx->m_xsid ){
		case CID_SERR:
			fwrite(bp,1,mx->m_leng,stderr);
			fflush(stderr);
			break;
		case CID_SOUT:
			fwrite(bp,1,mx->m_leng,stdout);
			fflush(stdout);
			break;
		case CID_SIN:
			wcc = write(MxPsins,bp,mx->m_leng);
			break;
		default:
			fprintf(stderr,"--DATA #%d leng=%d\n",mx->m_xsid,mx->m_leng);
			break;
	}
}
static int yySTDERR(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci,int fd,PCStr(wh),int shut,int xsid){
	IStr(mbuf,PHSIZE+PBSIZE+1);
	char *bp = mbuf + PHSIZE;
	int rcc;
	int rcc2;

	rcc = read(fd,bp,PBSIZE);
	if( 0 < rcc && rcc < PBSIZE ){
		if( shut == YS_SERREOF && 0 < PollIn(fd,10) ){
			/* to suppress small packets for unbuffered stderr  */
			msleep(10);
			rcc2 = read(fd,bp+rcc,PBSIZE-rcc);
			sv1log("--Stderr rcc=%d rcc2=%d\n",rcc,rcc2);
			if( 0 < rcc2 ){
				rcc += rcc2;
			}
		}
	}
	if( MxFlagsVERBOSE ){
		sv1log("--YY %s rcc=%d\n",wh,rcc);
	}
	if( 0 < rcc ){
		bp[rcc] = 0;
		sendDATA(Mc,Cv,Cn,xsid,0,bp,rcc,rcc,0);
	}else{
		Ci->c_cflag |= CF_PAUSING;
		MxDoupdate = wh;
		yyShutting(Mc,shut,wh);
	}
	return rcc;
}
static int drainStderr(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci,int fd,PCStr(wh),int shut,int xsid){
	double St = Time();
	int rcc;

	while( 0 < PollIn(fd,100) ){
		rcc = yySTDERR(Mc,Cv,Cn,Ci,fd,wh,shut,xsid);
		if( rcc <= 0 ){
			break;
		}
		if( 10 < Time()-St ){
			break;
		}
	}
	return 0;
}

/* this search can be replaced by a simple bit map */
static int nextXsid1(MuxCtx *Mc,Cony *Cv,int Cn){
	int found = 0;
	int ci;
	int xsid;
	Cony *C1;

	MxXsid += 2;
	xsid = MxXsid & 0xFF;
	if( xsid < CID_SV1 ){
		/* reserved */
		return 1;
	}
	for( ci = 0; ci < Cn; ci++ ){
		C1 = &Cv[ci];
		if( C1->c_type != CY_NULL && (C1->c_type & CY_ZOMB) == 0 ){
			if( (C1->c_xsid & 0xFF) == xsid ){
				found = 1;
				break;
			}
		}
	}
	return found;
}
static int nextXsid(MuxCtx *Mc,Cony *Cv,int Cn){
	int si;
	int got = 0;

	for( si = 0; si < Cn+CID_SV1/2; si++ ){
		if( nextXsid1(Mc,Cv,Cn) == 0 ){
			got = 1;
			break;
		}
	}
	Verbose("--nextXsid got=%d #%d #%d (%d)\n",got,MxXsid,0xFF&MxXsid,si);
	return got;
}

static int putDstsrc(MuxCtx *Mc,PVStr(dstsrc),PCStr(dst),PCStr(src),int xsid){
	if( dst[0] == 0 ){
		strcpy(dstsrc,"");
		return 0;
	}
	/* it shuld be YYCONNECT as
	 * YYCONNECT ftp-data://host:port HTTP/1.1
	 * Y-Client-Port: host:port
	 * Y-Clif-Port: host:port
	 *
	 * and receive the response to the connection
	 */
	sprintf(dstsrc,"YCNCT %s %s",dst,src); /* proto://host:port */
	/* and the identity of the source port */

	sv1log("--Y%d CONN#%d to [%s]\n",MxId,xsid,dstsrc);
	return 1;
}

typedef struct _AppServer {
	MStr(	as_proto,32);
	MStr(	as_serv,128);
	MStr(	as_host,128);
	int	as_port;
	int	as_clsock;
	MStr(	as_clnt,128);
	MStr(	as_clif,128);
	int	as_tid;
} AppServer;
typedef int (*ServFuncp)(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt));

int service_socks(Connection *Conn);
int service_pop(Connection *Conn);
int service_smtp(Connection *Conn);
void  init_mtab();
void set_BASEURL(Connection *Conn,PCStr(url));
int service_http(Connection *Conn);
int service_ftp(Connection *Conn);
int INET_Socketpair(int sv[]);
int clearthreadsig(int tid,int silent);
int setthreadgid(int tid,int tgid);

static int SocksServer1(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt)){
	scan_SERVER(Conn,"socks://-.-");
	service_socks(Conn);
	close(clsock);
	return 0;
}
void dns_initX();
int dns_search(PVStr(reply),PCStr(query),int qcc,PCStr(froma),int fromp);
static int DnsServer1(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt)){
	int rcc,occ,wcc;
	IStr(ib,2048);
	IStr(ob,2048);

	dns_initX();
	rcc = read(clsock,ib,sizeof(ib));
	occ = dns_search(AVStr(ob),ib,rcc,"",0);
	wcc = write(clsock,ob,occ);
	putfLog("--DnsProxy [%d] rcc=%d occ=%d wcc=%d",clsock,rcc,occ,wcc);
	close(clsock);
	return 0;
}
static int PopServer1(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt)){
	scan_SERVER(Conn,"pop://-.-");
	service_pop(Conn);
	close(clsock);
	return 0;
}
static int SmtpServer1(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt)){
	scan_SERVER(Conn,"smtp://-.-");
	service_smtp(Conn);
	close(clsock);
	return 0;
}
static int HttpServer1(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt)){
	IStr(myurl,256);
	double Start = Time();
	double St;
	int rdy;

/*
{
SigMaskInt mask,omask;
mask = sigmask(SIGPIPE);
thread_sigmask("SET",mask,&omask);
}
*/
	HTCFI_opts |= HTCFI_THRU_304;
	GatewayFlags |= GW_FROM_MYSELF;
	GatewayFlags |= GW_NO_HTTP_CKA;
	GatewayFlags |= GW_IS_YYSHD;
	scan_SERVER(Conn,"http://-.-");
	//sprintf(myurl,"http://%s",clif);
	//set_BASEURL(Conn,myurl);
	strcpy(CLNT_PROTO,"http");
	if( 1 ){
		/* to suppress relaying by vhost */
		scan_MOUNT(Conn,"/-/* = default");
		scan_MOUNT(Conn,"/-/screen/* gendata:/-/ysh/screen/* default");
		scan_MOUNT(Conn,"/* file:./* default");
		init_mtab();
	}
	rdy = PollIn(clsock,5*1000);
	if( rdy <= 0 ){
		sv1log("##[%d] HttpServer1 rdy=%d (%.3f)\n",clsock,rdy,Time()-Start);
	}else{
		sv1log("--[%d] HttpServer1 rdy=%d (%.3f)\n",clsock,rdy,Time()-Start);
		service_http(Conn);
	}
	shutdownWR(clsock);
	St = Time();
	rdy = PollIn(clsock,1000);
	close(clsock);
	clearthreadsig(getthreadid(),1); /* to suppress "clear signal(0)" log */

	if( GatewayFlags & GW_IS_YYSHD_YYM ){
		sv1log("---- HTTP/yyshd ... Conn=%X %X %X rdy=%d (%.3f)\n",
			p2i(Conn),GatewayFlags,GW_IS_YYSHD_YYM,rdy,Time()-St);
		//setselfendYY(Conn,"endHttpServer1");
		waitendYY(Conn,"HttpServer1",600);
	}
	return 0;
}
static int FtpServerN;
static int FtpServer1(Connection *Conn,int clsock,PCStr(serv),PCStr(clif),PCStr(clnt)){
	IStr(cwd,256);
	IStr(mount,256);
	IStr(user,128);
	IStr(pass,128);

	scan_SERVER(Conn,"ftp://-.-");
	if( 1 ){
		getcwd(cwd,sizeof(cwd));
		/*
		sprintf(mount,"/* file:%s default",cwd);
		*/
		strcpy(user,"user");
		strcpy(pass,"pass");
		/* echo this to the remote client */
		/*
		sprintf(mount,"/* file:/* default,rw,noanon,AUTHORIZER=-list{%s:%s}",user,pass);
		*/
		scan_MOUNT(Conn,"/* file:./* default,rw");
		scan_MOUNT(Conn,mount);
		init_mtab();
	}
	GatewayFlags |= GW_SERV_THREAD;
	FtpServerN++;
	sv1log("--FTP *%d BEGIN [%d] th=%d/%d\n",FtpServerN,clsock,
		actthreads(),numthreads());
	service_ftp(Conn);
	sv1log("--FTP *%d END [%d] th=%d/%d\n",FtpServerN,clsock,
		actthreads(),numthreads());
	FtpServerN--;
	shutdownWR(clsock); /* might be duplicated somewere ... */
	close(clsock);
	CTX_closedX(FL_ARG,"--FTP--",Conn,clsock,-1,1);
	return 0;
}
static int svthread(IFUNCP func,AppServer *Apps,int gid){
	int code;
	Connection ConnBuf,*Conn = &ConnBuf;

sv1log("----svthread A %X [%d %s %s %s]\n",
func,Apps->as_clsock,Apps->as_serv,Apps->as_clif,Apps->as_clnt);

	setthreadgid(0,gid);
	bzero(Conn,sizeof(Connection));
	ConnInit(Conn);
	ClientSock = ClientSockX = FromC = ToC = Apps->as_clsock;
	Conn->from_myself = 1;

	code = (*func)(Conn,Apps->as_clsock,Apps->as_serv,Apps->as_clif,Apps->as_clnt);

sv1log("----svthread X %X [%d %s %s %s]\n",
func,Apps->as_clsock,Apps->as_serv,Apps->as_clif,Apps->as_clnt);

	cleanConnPtr(FL_ARG,Conn); /* avoid dangling ptr. to ConnBuf */
	// should wait the YYMUX, refering this Conn, finish
	// or place ConnBuf in heap by getBuf()
	free(Apps);
	return code;
}
static int serverthread(PCStr(what),ServFuncp func,AppServer *Apps){
	int gid = getthreadgid(0);
	int tid;
	AppServer *apps;

	apps = (AppServer*)malloc(sizeof(AppServer));
	*apps = *Apps;
	tid = thread_fork(0x100000,0,what,(IFUNCP)svthread,func,apps,gid);
	return tid;
}

void setNumProcThread(PCStr(spec));
static int isViaYYMUXX(Connection *Conn,MuxCtx *cMc,int fd,PCStr(proto),PCStr(host),int port,MuxCtx **rMc);
static int ConnectOverYYMUXX(FL_PAR,MuxCtx *Mc,Connection *Conn,PCStr(proto),PCStr(host),int port);
static int ConnectViaYYMUXXX(Connection *Conn,void *cty,MuxCtx **rrMc,int relay_input,PCStr(yyhost),int yyport);
static int getDstsrc(MuxCtx *Mc,MuxMssg *mx,PCStr(dstsrc),int *cflag,int *tid){
	Connection *Conn = MxConn;
	VSAddr vsa;
	double St = Time();
	IStr(proto,64);
	IStr(addr,128);
	int port = 0;
	int xsock;
	int xrdy;
	int serrno;
	int sflags;
	int sp[2];
	IStr(serv,256);
	IStr(clif,256);
	IStr(clnt,256);
	IStr(ports,256);
	int isUdp = 0;
	AppServer As;
	MuxCtx *rMc = 0;
	ServFuncp svfunc;
	const char *svwhat;
	Port sv;

	Xsscanf(dstsrc,"YCNCT %s %s %s",AVStr(serv),AVStr(clif),AVStr(clnt));
	Xsscanf(serv,"%[^:]://%[^:]:%[^ ]",AVStr(proto),AVStr(addr),AVStr(ports));
	port = atoi(ports);
	if( isinListX(ports,"udp",".") ){
		isUdp = 1;
	}

	bzero(&As,sizeof(As));
	strcpy(As.as_serv,serv);
	strcpy(As.as_clif,clif);
	strcpy(As.as_clnt,clnt);

	if( addr[0] == 0 || isMYSELF(addr) ){
		INET_Socketpair(sp);
		As.as_clsock = sp[0];

		if( lSINGLEP() == 0 && lMULTIST() == 0 ){
extern int RELAY_threads_timeout;
RELAY_threads_timeout = 20;
/* for CONNECT relay under heavy load */
/* might be due to scheduling multiplexed connections */
			setNumProcThread("1+1");
		}
		if( streq(proto,"dns") ){
			strcpy(As.as_proto,"dns");
			svwhat = "DnsServer";
			svfunc = DnsServer1;
		}else
		if( streq(proto,"pop") ){
			strcpy(As.as_proto,"pop");
			svwhat = "PopServer";
			svfunc = PopServer1;
		}else
		if( streq(proto,"smtp") ){
			strcpy(As.as_proto,"smtp");
			svwhat = "SmtpServer";
			svfunc = SmtpServer1;
		}else
		if( streq(proto,"ftp") ){
			strcpy(As.as_proto,"ftp");
			svwhat = "FtpServer";
			svfunc = FtpServer1;
		}else
		if( streq(proto,"http") ){
			strcpy(As.as_proto,"http");
			svwhat = "HttpServer";
			svfunc = HttpServer1;
		}else
		if( streq(proto,"socks") ){
			strcpy(As.as_proto,"socks");
			svwhat = "SocksServer";
			svfunc = SocksServer1;
		}else{
			sv1log("----YCNCT Unknown [%s][%s]\n",proto,addr);
			close(sp[0]);
			close(sp[1]);
			return -1;
		}
		*tid = serverthread(svwhat,svfunc,&As);
		xsock = sp[1];

		/* must wait the thread receive serv,clif,clnt */
		xrdy = PollIn(xsock,10);
		serrno = errno;

		sv1log("--Y%d CONN#%d self [%s][%d](%.3f) e%d (%s %s) [%X]rdy=%d\n",MxId,
			mx->m_xsid,serv,xsock,Time()-St,errno,clif,clnt,
			PRTID(*tid),xrdy);

		if( xrdy < 0 ){
			/* close(xsock); */
			sv1log("####YCNCT FATAL Socketpair() [%d]%d [%d]%d,%d\n",
				sp[0],file_issock(sp[0]),
				sp[1],file_issock(sp[1]),file_ISSOCK(sp[1]));
			return -1;
		}
		return xsock;
	}
	*cflag = 0;
	if( port == 0 ){
		port = serviceport(proto);
	}
	if( streq(proto,"ftp-data") ){
		*cflag = CF_GETABORT;
	}
	if( streq(addr,"0.0.0.0") || *addr == 0 ){
		VSA_getpeername(&vsa,ClientSockX);
		strcpy(MxClntAddr,VSA_ntoa(&vsa));
		strcpy(addr,MxClntAddr);
	}

	sv = Conn->sv;
	set_realserver(Conn,proto,addr,port);
	if( isViaYYMUXX(Conn,Mc,ServerSockX,proto,addr,port,&rMc) ){
		if( rMc ){
			xsock = ConnectOverYYMUXX(FL_ARG,rMc,Conn,proto,addr,port);
			/* this should be realized just in YYMUXrelay() */
sv1log("--Y%d >> Y%d [%d] YCNCT-A %s://%s:%d (%s://%s:%d)\n",MxId,rMc->mc_id,xsock,proto,addr,port,DST_PROTO,DST_HOST,DST_PORT);
			if( 0 <= xsock ){
				return xsock;
			}
			/* the outer YYMUX (rMc) might have been closed */
			endYY(Conn,rMc);
		}
	}
	if( 1 ){
		IStr(yyhost,MaxHostNameLen);
		int yyport;
		if( find_YYMUXX(Conn,Mc,proto,addr,port,AVStr(yyhost),&yyport) ){
			rMc = 0;
			xsock = ConnectViaYYMUXXX(Conn,NULL,&rMc,0,yyhost,yyport);
sv1log("--Y%d >> Y%d [%d] YCNCT-B %s://%s:%d (%s://%s:%d)\n",MxId,rMc?rMc->mc_id:0,xsock,proto,addr,port,DST_PROTO,DST_HOST,DST_PORT);
			if( 0 <= xsock ){
				return xsock;
			}
		}
	}
	Conn->sv = sv;

	/*
	 * should use connect_to_serv() instead of client_open()
	 * and connection should be done in the background
	 */
	if( strneq(proto,"y",1) ){ /* if conn. for resume */
		sflags = ConnectFlags;
		ConnectFlags |= COF_TERSE;
		xsock = client_open("-yymux",proto,addr,port);
		ConnectFlags = sflags;
	}else
	if( isUdp ){
		xsock = UDP_client_open("yymux",proto,addr,port);
		*cflag |= CF_UDP_SV;
	}else{
		xsock = client_open("yymux",proto,addr,port);
	}
	sv1log("--Y%d CONN#%d to [%s][%d](%.3f) e%d\n",MxId,mx->m_xsid,
		dstsrc,xsock,Time()-St,errno);
	/* return response */

sv1log("--Y%d >> Y%d [%d] YCNCT-C %s://%s:%d (%s://%s:%d)\n",MxId,rMc?rMc->mc_id:0,xsock,proto,addr,port,DST_PROTO,DST_HOST,DST_PORT);
	return xsock;
}

static Cony *findUDP(MuxCtx *Mc,Cony *Ci,PCStr(shost),int sport){
	Cony *C1;
	Cony *Cx = 0;
	int xsid = 0;
	int cn = 0;
	int ci;

	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];
		if( (C1->c_cflag & CF_UDP_CL) == 0
		 || strcmp(Ci->c_dst_port,C1->c_dst_port) != 0
		){
			continue;
		}
		cn++;
		if( xsid == 0 || C1->c_xsid < xsid ){
			Cx = C1;
			xsid = C1->c_xsid;
		}
		if( sport == C1->c_src_portnum ){
			if( streq(shost,C1->c_src_addr) ){
 sv1log("----UDP find %s <= %s:%d %s:%d ----FOUND\n",
 C1->c_dst_port,shost,sport,C1->c_src_addr,C1->c_src_portnum);
				return C1;
			}
		}
	}
	if( 8 < cn && Cx != 0 ){
		sendRSET(MxCv,MxCn,xsid,Mc);
		Cx->c_type |= CY_ZOMB;
		Cx->c_fd = -1;
 sv1log("----UDP find %s act=%d #%d <= %s:%d ----RESET\n",
 Cx->c_dst_port,cn,xsid,Cx->c_src_addr,Cx->c_src_portnum);
	}
	return 0;
}
static int sendUDP(MuxCtx *Mc,Cony *Ci,int asock){
	int rcc;
	IStr(clhost,256);
	int clport;
	int xsid;
	Cony *C1;
	IStr(src,256);
	IStr(dstsrc,512);
	IStr(mbuf,PHSIZE+PBSIZE);
	char *bp = mbuf + PHSIZE;

	rcc = RecvFrom(asock,bp,PBSIZE,AVStr(clhost),&clport);
	if( C1 = findUDP(Mc,Ci,clhost,clport) ){
		sendDATA(Mc,MxCv,MxCn,C1->c_xsid,0,bp,rcc,rcc,0);
		return 1;
	}

	xsid = MxXsid;
	nextXsid(Mc,MxCv,MxCn);
	C1 = addCony(MxCv,MxCn,xsid,CY_XOUT,ET_CLNT,asock);
	C1->c_cflag |= CF_UDP_CL;
	C1->c_src_portnum = clport;
	strcpy(C1->c_src_addr,clhost);
	strcpy(C1->c_dst_port,Ci->c_dst_port);

	sprintf(src,"127.0.0.1:%d %s:%d",sockPort(asock),clhost,clport);
	putDstsrc(Mc,AVStr(dstsrc),Ci->c_dst_port,src,xsid);
	sendCONN(Mc,xsid,dstsrc);
	sendDATA(Mc,MxCv,MxCn,xsid,0,bp,rcc,rcc,0);
 sv1log("----UDP forw #%d rcc=%d e%d =>[%s:%d] CF=%X\n",
 xsid,rcc,errno,clhost,clport,C1->c_cflag);
	return 2;
}
static void recvUDPnew(MuxCtx *Mc,MuxMssg *mx,int cflag,int tid,int xsock){
	Cony *C1;

 sv1log("----UDP new #%d CF=%X (#%d %X) [%d]\n",
 mx->m_xsid,cflag,mx->m_xsid,cflag,xsock);

	C1 = addCony(MxCv,MxCn,mx->m_xsid,CY_UDP_SV,ET_SERV,xsock);
	C1->c_cflag |= cflag;
	C1->c_tid = tid;
	sendINFO(Mc,"iNewUdp",-1);
}

static int FtpClient(MuxCtx *Mc,int clsock);
static int yyAccept(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci,int asock){
	int xsock;
	Cony *C1;
	IStr(peer,256);
	IStr(clif,256);
	IStr(src,256);
	IStr(dstsrc,512);
	int xsid;

	if( Ci->c_cflag & CF_UDPACC ){
		sendUDP(Mc,Ci,asock);
		return 0;
	}
	MxDoupdate = "yyAccept";
	xsock = ACCEPT(asock,0,-1,10);
	if( xsock < 0 ){
		sv1log("##Y%d #%d accept failure: errno=%d [%d] TY=%X CF=%X\n",
			MxId,Ci->c_xsid,errno,Ci->c_fd,Ci->c_type,Ci->c_cflag);
		//if( errno == EINVAL || errno == ENOTSOCK )
		if( 1 )
		{
			Ci->c_cflag |= CF_PAUSING;
		}
		return -1;
	}
	/* check if it is "RELIABLE" or in "PERMIT" */

	xsid = MxXsid;
	nextXsid(Mc,Cv,Cn);
	if( Ci->c_xsid == CID_FTP ){
		sv1log("#### accepted private FTP #%d\n",xsid);
		xsock = FtpClient(Mc,xsock);
	}
	if( CID_FTDA == Ci->c_xsid ){
		FD_new(xsock,"ftpDataAcc",0);
	}else{
		FD_new(xsock,"yyAccept",0);
	}

	C1 = addCony(Cv,Cn,xsid,CY_XIN,ET_CLNT,xsock);
//yprintf(Mc,"--Cony iACC[%d] #%d y%X",xsock,xsid,C1->c_type);
	C1 = addCony(Cv,Cn,xsid,CY_XOUT,ET_CLNT,xsock);
//yprintf(Mc,"--Cony oACC[%d] #%d y%X",xsock,xsid,C1->c_type);
	if( Ci->c_cflag & CF_NONBLKSEND ){
		C1->c_cflag |= CF_NONBLKSEND;
		expsockbuf(MxVncSock,0,256*1024);
	}
	sv1log("## --yMUX ACCEPT(#%d) [%d]\n",xsid,xsock);
	getpairName(xsock,AVStr(clif),AVStr(peer));
	sprintf(src,"%s %s",clif,peer);
	putDstsrc(Mc,AVStr(dstsrc),Ci->c_dst_port,src,xsid);
	sendCONN(Mc,xsid,dstsrc);

	if( CID_FTDA == Ci->c_xsid ){
		closeFd(FL_ARG,"--ftpData--",Mc,MxCv,MxCn,Ci,Ci->c_fd);
		/*
		showStats(Mc);
		*/
	}
	return 0;
}
static int yyConnect(MuxCtx *Mc,Cony *Cv,int Cn,Cony *Ci,MuxMssg *mx,PCStr(bp),int servside){
	int xsock;
	Cony *C1;
	int cflag = 0;
	int tid = 0;

	MxDoupdate = "yyConnect";
	if( mx->m_xsid == CID_FTP ){
		/* to be connectPrivateFTP() */
		if( 0 < mx->m_leng ){
			xsock = getDstsrc(Mc,mx,bp,&cflag,&tid);
		}else{
			xsock = getDstsrc(Mc,mx,"YCNCT ftp://127.0.0.1:21",&cflag,&tid);
		}
		sv1log("#### connect to the private FTP server [%d]\n",xsock);
	}else
	if( mx->m_leng ){
		xsock = getDstsrc(Mc,mx,bp,&cflag,&tid);
	}else{
		xsock = connectXlocal("yyConnect",1);
	}
	if( xsock < 0 ){
		sv1log("##YMUX connect failure: RSET #%d errno=%d\n",
			mx->m_xsid,errno);
		sendRSET(Cv,Cn,mx->m_xsid,Mc);
		return -1;
	}
	if(  servside && (mx->m_xsid & 1) == 0 /* CID_CL1 + 2*N */
	 || !servside && (mx->m_xsid & 1) != 0 /* CID_SV1 + 2*N */
	){
		sv1log("#YMUX ID invalid side: %d #%d\n",servside,mx->m_xsid);
	}
	FD_new(xsock,"yyConnect",0);
	if( cflag & CF_UDP_SV ){
		recvUDPnew(Mc,mx,cflag,tid,xsock);
		return 0;
	}

	C1 = addCony(Cv,Cn,mx->m_xsid,CY_XIN,ET_SERV,xsock);
	C1 = addCony(Cv,Cn,mx->m_xsid,CY_XOUT,ET_SERV,xsock);
	C1->c_cflag |= cflag;
	C1->c_tid = tid;
 sv1log("--tid Y%d yyConnect c_tid=%X \r\n",MxId,tid);
	sv1log("--Y%d YCNCT #%d [%d]\n",MxId,mx->m_xsid,xsock);
	sendINFO(Mc,"iNewConnection",-1);
	return 0;
}
static int abortCony(MuxCtx *Mc,int src,int dst){
	int ci;
	Cony *C1 = 0;
	FileDesc *Fd;
	int closed = 0;

	if( Mc == 0 ){
		return 0;
	}
	for( ci = 0; ci < MxCn; ci++ ){
		C1 = &MxCv[ci];
		if( C1->c_type != CY_NULL && (C1->c_type & CY_ZOMB) == 0 ){
			Fd = findFd(C1->c_fd,0);
			/* should find the peer of Socketpair for src and dst */
			if( C1->c_cflag & CF_GETABORT )
			if( C1->c_type == CY_XIN || C1->c_type == CY_XOUT ){
	sv1log("--yy ABORT[%d %d] Cony-%d %X [%d] #%d (%d) %s\n",
					src,dst,ci,C1->c_cflag,
					C1->c_fd,C1->c_xsid,
					closed,Fd?Fd->fd_what:"");
				C1->c_cflag |= CF_DISCARDING;
				if( closed == 0 ){
					sendRSET(MxCv,MxCn,C1->c_xsid,Mc);
					ShutdownSocket(C1->c_fd);
					MxDoupdate = "destroy";
				}
				closed++;
			}
		}
	}
	return closed;
}
int abortYY(PCStr(wh),Connection *Conn,int src,int dst){
	MuxCtx *Mc;

	Mc = findYY(Conn,DST_PROTO,DST_HOST,DST_PORT);
	if( Mc ){
		abortCony(Mc,src,dst);
	}
	return 0;
}

/*
 * process watcher
 */
typedef struct {
	int wt_xpid;
} ProcWait;
static int procWaitThread(MuxCtx *Mc,int pwtsock){
	ProcWait wt;
	int wcc;
	int xstatus;
	int rdy;
	int ph = 0;
	int xpid;

	for(;;){
		if( isWindows() ){
			sv1log("#### wait start... %d/h%d\n",
				MxPid,MxPhandle);
			ph = _cwait(&xstatus,MxPhandle,0);
			if( ph == MxPhandle )
				wt.wt_xpid = MxPid;
			else	wt.wt_xpid = -1;
			sv1log("#### wait done ... %d %d/h%d = %d alv=%d\n",
				MxPid,MxPid,MxPhandle,wt.wt_xpid,
				procIsAlive(MxPid));
		}else{
			errno = 0;
			wt.wt_xpid = xpid = wait(0);
			if( xpid < 0 && getpid() != uGetpid() && errno == ECHILD ){
				/* LinuxThreads */
				sv1log("#### cannot wait %d %d/%d [%d %d] e%d\n",
					xpid,MxPid,procIsAlive(MxPid),
					getpid(),uGetpid(),errno);
				MxCantwait = 1;
				return -1;
			}
			sv1log("#### wait()=%d e%d\n",wt.wt_xpid,errno);
		}
		if( wt.wt_xpid < 0 ){
			double St = Time();
			rdy = PollIn(pwtsock,10*1000);
			sv1log("#### wait %d/%d ... (%.2f) rdy=%d,errno=%d\n",
				MxPid,procIsAlive(MxPid),Time()-St,rdy,errno);
			if( rdy != 0 ){
				break;
			}
		}else{
			wcc = write(pwtsock,&wt,sizeof(wt));
			sv1log("----YY pid=%d wait()=%d, wcc=%d [%d]\n",
				MxPid,wt.wt_xpid,wcc,pwtsock);
			if( wt.wt_xpid == MxPid ){
				break;
			}
		}
	}
	return 0;
}

static int startResume(MuxCtx *Mc){
	Connection *Conn = MxConn;

	if( MxRsmhold == 0 ){
		return 0;
	}
	if( MxShutting ){
		return 0;
	}
	if( MxInRESUME ){
		if( MxPingitvl < Time()-MxLastMuxOut ){
 zprintf(Mc,"#### ignored ECHO: in resume (%X)",MxInRESUME);
		}
		if( MxRsmstart < Time()-MxLastMuxIn ){
 zprintf(Mc,"#### ignored RSM: in resume (%X)",MxInRESUME);
		}
		return 0;
	}
	if( MxParent && (MxParent->mc_resuming||MxParent->mc_inRESUME) ){
		int pid = MxParent->mc_id;
		int rsm = MxParent->mc_inRESUME;
		if( MxPingitvl < Time()-MxLastMuxOut ){
 zprintf(Mc,"#### ignored ECHO: outer in resume (%X)",rsm);
		}
		if( MxRsmstart < Time()-MxLastMuxIn ){
 zprintf(Mc,"#### ignored RSM: outer in resume (%X)",rsm);
		}
		return 0;
	}
	if( MxPingitvl < Time()-MxLastMuxOut ){
		sv1log("--Y%d RSM sent ECHO (o%.2f i%.2f)\n",
			MxId,Time()-MxLastMuxOut,Time()-MxLastMuxIn);
		sendREQ(Mc,"ECHO");
getXpend(MxCv,MxCn,0,1);
	}

	if( MxRsmstart <= 0 ){
		return 0;
	}
	if( MxRsmstart < Time()-MxLastMuxIn ){
		sv1log("--RSM-- reconnect on idle -- (i%.2f o%.2f %.2f) ----\n",
			Time()-MxLastMuxIn,Time()-MxLastMuxOut,
			MxLastMuxIn-MxLastMuxOut);

		/* new connection might fail and original connectin might become
		 * active again, so the original must not be closed
		 * - dup2(MxYsock,MxYsockorig);
		 * - select(CY_RSMCON)
		 */
		dupclosed(MxYsock);
		return 1;
	}
	return 0;
}
static int waitY(MuxCtx *Mc){
	int xpid;
	int serrno;

	errno = 0;
	xpid = NoHangWait();
	serrno = errno;
	sv1log("##STDERR-EOF xpid=%d pid=%d/%d [%d %d] e%d\n",
		xpid,MxPid,procIsAlive(MxPid),
		getpid(),uGetpid(),serrno
	);
	return xpid;
}
int waitYYMUXready(MuxCtx *Mc,double timeout){
	double St = Time();
	int wi;

	for( wi = 0; wi < 50; wi++ ){
		if( MxMuxStart != 0 ){
			break;
		}
		if( timeout != 0 && timeout < Time()-St ){
			break;
		}
		msleep(20);
	}
	return MxStart != 0;
}

int readyOOB(int sock);
int yyMUXrelay(MuxCtx *Mc,int acc,int fromcl,int tocl,int xcl,int fromsv,int tosv,int xsv,int servside){
	Cony Cv[MAXSES];
	int Cn = elnumof(Cv);
	Cony *Ci;
	Cony *Co;
	Cony *C1;
	int ci;
	int civ[MAXSES],fdv[MAXSES],qev[MAXSES],rev[MAXSES];
	int fi;
	int fdc = -9;
	int numxcl;
	int nready;
	int fready;
	int serrno = -9;
	int rcc,wcc;
	int ilen,olen;
	MuxMssg mx;
	IStr(buf,PBSIZE+PHSIZE*2);
	char *bp;
	int iSiz = PBSIZE;
	int xpid;
	int pi;
	int li;
	void (*osig)(int);
	const char *whexit = "";
	int pwt[2] = {-1,-1};
	int tid = 0;
	Cony *CiPsout = 0;
	Cony *CiPserr = 0;
	int localOOB;
	int remoteOOB;
	int mxId;
	Connection *mxConn = MxConn;

	MxFlags |= MX_YYACTIVE;
	MxCv = Cv;
	MxCn = Cn;
	mxId = MxId;

	osig = Vsignal(SIGINT,sigINT);
	osig = Vsignal(SIGTERM,sigINT);
	Vsignal(SIGPIPE,SigPIPE);
	if( lMULTIST() ){
		/* thread_sigmask(); for SIGPIPE */
	}

	if( MxFlagsDEFLATE ){
		/* not for each connection */
		if( MxFlagsVERBOSE ){
			MxZCdfl.z1_debug = 1;
			MxZCifl.z1_debug = 1;
		}
		if( MxFlagsDEFLATE1 && MxFlagsDEFLATE2 ){
			MxZ1dfl = deflateZ1new(&MxZCdfl);
		}
		MxZ1ifl = inflateZ1new(&MxZCifl);
	}

	for( ci = 0; ci < Cn; ci++ ){
		clearCony(&Cv[ci]);
	}
	if( servside ){
		MxXsid = CID_SV1;
	}else{
		MxXsid = CID_CL1;
	}
	if( 0 <= acc ){
		addCony(Cv,Cn,CID_ACC,CY_ACC,ET_CLNT,acc);
	}
	if( MxPalive ){
		Socketpair(pwt);
		FD_new(pwt[0],"procWait0",0);
		FD_new(pwt[1],"procWait1",0);
		tid = thread_fork(0x40000,0,"ProcWait",(IFUNCP)procWaitThread,Mc,pwt[1]);
		MxTidpwt = tid;
		addCony(Cv,Cn,CID_PWT,CY_PWT,ET_CLNT,pwt[0]);
	}
	if( 0 <= MxRsmsock ){
		addCony(Cv,Cn,CID_RSM,CY_RSMACC,ET_CLNT,MxRsmsock);
	}
	if( xcl ){
		MxYsock = tocl;
		MxYport = sockPort(MxYsock);
		addCony(Cv,Cn,CID_MUX,CY_YMUXIN,ET_CLNT,fromcl);
		addCony(Cv,Cn,CID_MUX,CY_YMUXOUT,ET_CLNT,tocl);
	}else{
		addCony(Cv,Cn,CID_PRI,CY_XIN,ET_SERV,fromcl);
		addCony(Cv,Cn,CID_PRI,CY_XOUT,ET_SERV,tocl);
	}
	if( xsv ){
		MxYsock = tosv;
		MxYport = sockPort(MxYsock);
		addCony(Cv,Cn,CID_MUX,CY_YMUXIN,ET_SERV,fromsv);
		addCony(Cv,Cn,CID_MUX,CY_YMUXOUT,ET_SERV,tosv);
	}else{
		addCony(Cv,Cn,CID_PRI,CY_XIN,ET_CLNT,fromsv);
		addCony(Cv,Cn,CID_PRI,CY_XOUT,ET_CLNT,tosv);
	}
	if( 0 <= MxPsout ){
		CiPsout =
		addCony(Cv,Cn,CID_SOUT,CY_STDOUT,ET_CLNT,MxPsout);
	}
	if( 0 <= MxPserr ){
		CiPserr =
		addCony(Cv,Cn,CID_SERR,CY_STDERR,ET_CLNT,MxPserr);
	}
	if( 0 <= MxConsole ){ /* to be relayed to remote MxPsins */
		C1 = addCony(Cv,Cn,CID_CONS,CY_CONS,ET_CLNT,MxConsole);
		C1->c_cflag |= CF_PAUSING|CF_LAZY;
	}
	if( 0 <= MxYAccSock ){
		addCony(Cv,Cn,CID_YACC,CY_YACC,ET_SERV,MxYAccSock);
	}
	if( 0 <= MxDnsSock ){
		const char *tcpudp;
		FD_new(MxDnsSock,"DNS",0);
		C1 = addCony(Cv,Cn,CID_DNS,CY_ACC,ET_CLNT,MxDnsSock);
		C1->c_cflag |= CF_UDPACC;
		if( MxPmapDns.pm_remote.p1_flags & P1_TCP ){
			tcpudp = ".tcp";
		}else{
			tcpudp = ".udp";
		}
		if( MxDnsServ[0] ){
			sprintf(C1->c_dst_port,"dns://%s:%d%s",MxDnsServ,MxDnsRport,tcpudp);
		}else{
			sprintf(C1->c_dst_port,"dns://-.-:53%s",tcpudp);
		}
	}
	if( 0 <= MxRsyncSock ){
		FD_new(MxRsyncSock,"RsyncAccept",0);
		C1 = addCony(Cv,Cn,CID_RSYNC,CY_ACC,ET_CLNT,MxRsyncSock);
		if( MxRsyncServ[0] ){
			sprintf(C1->c_dst_port,"rsync://%s:%d",MxRsyncServ,MxRsyncRport);
		}else{
			sprintf(C1->c_dst_port,"rsync://-.-");
		}
	}
	if( 0 <= MxSmtpSock ){
		FD_new(MxSmtpSock,"SmtpAccept",0);
		C1 = addCony(Cv,Cn,CID_SMTP,CY_ACC,ET_CLNT,MxSmtpSock);
		if( MxSmtpServ[0] ){
			sprintf(C1->c_dst_port,"smtp://%s:%d",MxSmtpServ,MxSmtpRport);
		}else{
			sprintf(C1->c_dst_port,"smtp://-.-");
		}
	}
	if( 0 <= MxPopSock ){
		FD_new(MxPopSock,"PopAccept",0);
		C1 = addCony(Cv,Cn,CID_POP,CY_ACC,ET_CLNT,MxPopSock);
		if( MxPopServ[0] ){
			sprintf(C1->c_dst_port,"pop://%s:%d",MxPopServ,MxPopRport);
		}else{
			sprintf(C1->c_dst_port,"pop://-.-");
		}
	}
	if( 0 <= MxFtpSock ){
		FD_new(MxFtpSock,"FtpAccept",0);
		C1 = addCony(Cv,Cn,CID_FTP,CY_ACC,ET_CLNT,MxFtpSock);
		if( MxFtpServ[0] ){
			sprintf(C1->c_dst_port,"ftp://%s:%d",MxFtpServ,MxFtpRport);
		}else{
			sprintf(C1->c_dst_port,"ftp://-.-");
		}
	}
	if( 0 <= MxHttpSock ){
		FD_new(MxHttpSock,"HttpAccept",0);
		C1 = addCony(Cv,Cn,CID_HTTP,CY_ACC,ET_CLNT,MxHttpSock);
		if( MxHttpServ[0] ){
			sprintf(C1->c_dst_port,"http://%s:%d",MxHttpServ,MxHttpRport);
		}else{
			sprintf(C1->c_dst_port,"http://-.-");
		}
	}
	if( 0 <= MxSocksSock ){
		FD_new(MxSocksSock,"SocksAccept",0);
		C1 = addCony(Cv,Cn,CID_SOCKS,CY_ACC,ET_CLNT,MxSocksSock);
		if( MxSocksServ[0] ){
			sprintf(C1->c_dst_port,"socks://%s:%d",MxSocksServ,MxSocksRport);
		}else{
			sprintf(C1->c_dst_port,"socks://-.-");
		}
	}
	if( 0 <= MxVncSock ){
		FD_new(MxVncSock,"VNC",0);
		C1 = addCony(Cv,Cn,CID_VNC,CY_ACC,ET_CLNT,MxVncSock);
		C1->c_cflag |= CF_NONBLKSEND;
		if( MxVncServ[0] ){
			sprintf(C1->c_dst_port,"vnc://%s:%d",MxVncServ,MxVncRport);
		}else{
			sprintf(C1->c_dst_port,"vnc://127.0.0.1:5900");
		}
	}
	activatePortMaps(Mc);

	MxMuxStart = Time();
	if( MxStart == 0 ){
		MxStart = MxMuxStart;
	}
	MxLastMuxIn = Time();
	MxLastMuxOut = Time();
	MxDoupdate = "Init";

	for( li = 0;; li++ ){
		if( mxConn != MxConn ){
			sv1log("----FATAL Y%d Conn=%X : Y%d Conn=%X %X\n",
				MxId,p2i(MxConn),mxId,p2i(mxConn),p2i(Conn0));
			MxConn = mxConn;
		}
		if( MxId != mxId || MxCv != Cv ){
			sv1log("----FATAL Y%d Cv=%X : Y%d Cv=%X alive=%d\n",
				MxId,p2i(MxCv),mxId,p2i(Cv),isAlive(mxId));
		}
		if( yy_showStats ){
			yy_showStats = 0;
			showStats(Mc);
		}
		if( MxDoupdate ){
			fdc = updateFdv(MxDoupdate,Mc,Cv,Cn,fdv,qev,civ,&numxcl);
			MxDoupdate = 0;
		}
		if( MxTimeoutNX ){
			if( MxTimeoutNX < time(0) ){
				sv1log("--Y%d timeoutNX %u %u\n",MxId,time(0),MxTimeoutNX);
				MxTimeoutNX = 0;
				yyShutting(Mc,YS_NOACTS,"timeoutNX");
				sendSHUT(Mc);
			}
		}
		if( MxPalive && MxCantwait && (MxShutting & (YS_SERREOF|YS_SOUTEOF)) ){
			if( waitY(Mc) == MxPid ){
				MxPalive = 0;
				sendSHUT(Mc);
				goto NEXT;
			}
		}
		nready = 0;
		for( fi = 0; fi < fdc; fi++ ){
			rev[fi] = 0;
			Ci = &Cv[civ[fi]];
			if( Ci->c_fp ){
				if( 0 < ready_cc(Ci->c_fp) ){
					rev[fi] = PS_IN;
					nready++;
				}
			}
		}
		fready = nready;
		if( fready == 0 ){
			flushRCPT(Mc,0);
		}
		if( nready == 0 && MxShutting ){
			nready = PollInsOuts(100,fdc,fdv,qev,rev);
			serrno = errno;
			sv1log("##Y%d shutting X:%X rdy=%d pid=%d/%d (%.2f)\n",
				MxId,MxShutting,nready,MxPid,0<MxPid?procIsAlive(MxPid):0,
				Time()-MxShutStart);
			if( nready <= 0 ){
				if( 2 < Time()-MxShutStart ){
					whexit = "ShutTimeout";
					fdc = updateFdv(whexit,Mc,Cv,Cn,fdv,qev,civ,&numxcl);
					goto EXIT;
				}
				if( MxPalive ){
					if( !procIsAlive(MxPid) ){
						sv1log("--YY not alive pid=%d\n",MxPid);
						MxPalive = 0;
						MxPdone = Time();
						goto NEXT;
					}else{
						sv1log("#YMUX Kill(%d/%d)\n",MxPid,MxPhandle);
						if( isWindows() ){
							Kill(MxPhandle,SIGTERM);
						}else{
							Kill(MxPid,SIGTERM);
						}
						goto NEXT;
					}
				}
			}
		}
		if( servside ){
		}else{
			startResume(Mc);
		}
		if( nready == 0 ){
			nready = PollInsOuts(1000,fdc,fdv,qev,rev);
			if( nready == 0 ){
delTid(Mc);
				flushOutBuf(Mc);
				flushRCPT(Mc,1);
				LOG_flushall(); /* for HTTP/yysh */
			}
			if( MxShutting ){
				serrno = errno;
				sv1log("##Y%d shutting Y:%X rdy=%d pid=%d\n",
					MxId,MxShutting,nready,MxPid,procIsAlive(MxPid));
			}else{
				int timeout = 10*1000;
				if( withLazy(Mc,Cv,Cn,&timeout) ){
					MxDoupdate = "LazyStart";
					goto NEXT;
				}
				nready = PollInsOuts(timeout,fdc,fdv,qev,rev);
				serrno = errno;
			}
		}
		if( nready == 0 ){
			Verbose("--YMUX idle-B (fdc=%d)... (%.2f)\n",fdc,Time()-MxLastMuxIn);
			continue;
		}
		if( nready <= 0 ){
			if( nready<0 && yy_gotSIG && MxShutting==0 ){
				if( 1 < yy_gotSIG ){
					yyShutting(Mc,YS_GOTSIG,"");
					sendSHUT(Mc);
				}
				sv1log("##B rdy=%d SIG*%d %X\n",nready,yy_gotSIG,MxShutting);
				goto NEXT;
			}
			whexit = "NoReady";
			sv1log("##Y%d rdy=%d/%d err=%d SIGPIPE=%d/%X/%X SIG=%d shut=%X NX=%u\n",
				MxId,nready,fdc,serrno,yy_nsigPIPE,PRTID(yy_tidPIPE),TID,
				yy_gotSIG,MxShutting,MxTimeoutNX);
			if( nready < 0 && serrno == EINTR ){
				/* should be nready <= 0 ? */
				continue;
			}
			/* might be already closed socket ? */
			if( fdc == 1 && MxTimeoutNX ){
			}else{
			FD_dump("FATAL-POLL");
			showStats(Mc);
			}
			goto EXIT;
		}
		if( 0 < fready ){
			int xrev[MAXSES];
			int xready,xxready;
			int xi;
			xready = PollInsOuts(TIMEOUT_IMM,fdc,fdv,qev,xrev);
			if( 0 < xready ){
				xxready = 0;
				for( xi = 0; xi < xready; xi++ ){
					if( rev[xi] == 0 && xrev[xi] != 0 ){
						rev[xi] = xrev[xi];
						xxready++;
					}
				}
				if( xxready ){
					sv1log("++++ fready=%d/%d/%d + %d\n",
						fready,nready,fdc,xxready);
				}
			}
		}
		for( fi = 0; fi < fdc; fi++ ){
			/*
			if( rev[fi] & PS_ERR ){
				sv1log("####FATAL rev[%d]=%d\n",fi,rev[fi]);
				whexit = "PollError";
				goto EXIT;
			}
			*/
			if( rev[fi] == 0 ){
				continue;
			}
			Ci = &Cv[civ[fi]];

			localOOB = 0;
			if( rev[fi] & PS_PRI ){
				int calive = IsAlive(fdv[fi]);
				int isOOB = readyOOB(fdv[fi]);
 sv1log("--(%d)[%d]#%d poll got PRI rev=%X alv=%d OOB=%d e%d\n",
	fi,fdv[fi],Ci->c_xsid,rev[fi],calive,isOOB,serrno);
				if( isOOB ){
					localOOB = 1;
				}else{
					/* should suppress further PRI... */
					/* maybe shutdownWR() on another end */
					/*
					Ci->c_cflag |= CF_PAUSING;
					MxDoupdate = "PRI,NON-OOB";
					continue;
					*/
				}
			}
			remoteOOB = 0;

			if( Ci->c_type == CY_CONS ){
				yyCONSOLE(Mc,Cv,Cn,Ci,fdv[fi]);
				goto NEXT;
			}
			if( Ci->c_type == CY_STDOUT){
				yySTDERR(Mc,Cv,Cn,Ci,fdv[fi],"Stdout",YS_SOUTEOF,CID_SOUT);
				goto NEXT;
			}
			if( Ci->c_type == CY_STDERR ){
				yySTDERR(Mc,Cv,Cn,Ci,fdv[fi],"Stderr",YS_SERREOF,CID_SERR);
				goto NEXT;
			}
			if( Ci->c_type == CY_ACC ){
				yyAccept(Mc,Cv,Cn,Ci,fdv[fi]);
				goto NEXT;
			}
			if( Ci->c_type == CY_RSMACC ){
				yyRsmacc(Mc,fdv[fi]);
				goto NEXT;
			}
			if( Ci->c_type == CY_PWT ){
				int rcc;
				ProcWait wt;
				rcc = read(fdv[fi],&wt,sizeof(wt));
				sv1log("----YY pid=%d/%d done=%d rcc=%d\n",
					MxPid,procIsAlive(MxPid),wt.wt_xpid,rcc);
				if( MxPid == wt.wt_xpid ){
					MxPdone = Time();
					MxPalive = 0;
					if( 0 <= MxPsout ){
				drainStderr(Mc,Cv,Cn,CiPsout,MxPsout,"Stdout",YS_SOUTEOF,CID_SOUT);
					}
					if( 0 <= MxPserr ){
				drainStderr(Mc,Cv,Cn,CiPserr,MxPserr,"Stderr",YS_SERREOF,CID_SERR);
					}
					yyShutting(Mc,YS_PWEXIT,"");
					sendSHUT(Mc);
				}
				goto NEXT;
			}
			bp = (char*)buf+PHSIZE;
			if( yy_doMUX && Ci->c_type & CY_YMUX ){
				rcc = recvPack(Mc,Ci,bp,&mx,&ilen);
				if( rcc < 0 ){
 sv1log("##Y%d/%d yMUX-EOS [%d] rcc=%d pid=%d/%d\n",
	MxId,MxParentId,fdv[fi],rcc,MxPid,procIsAlive(MxPid));
					whexit = "yMUX-EOS";
					goto EXIT;
				}

				if( ilen < 0 ){
					sv1log("## --#%d bad leng=%d rcc=%d<MUX\n",
						mx.m_xsid,ilen,rcc);
				}
				if( mx.m_flag & MF_OOB ){
					remoteOOB = 1;
				}
				if( mx.m_type == PY_NOP ){
					sv1log("--Y%d NOP ---\n",MxId);
					goto NEXT;
				}
				if( mx.m_type == PY_RSMG ){
					sv1log("--Y%d RESUMING ---\n",MxId);
					MxDoupdate = "Resuming";
					MxResuming = 1;
					goto NEXT;
				}
				if( mx.m_type == PY_RSMD ){
					Connection *Conn = MxConn;
					MxRsmcnt++;
			sv1log("--Y%d RESUMED(%d) th=%d/%d SF=%X CF=%X\n",
						MxId,MxRsmcnt,
						actthreads(),numthreads(),
						ServerFlags,ClientFlags
					);
					MxDoupdate = "Resumed";
					MxResuming = 0;
					goto NEXT;
				}
				if( mx.m_type == PY_SHUT ){
					Verbose("--YMUX SHUT\n");
					yyShutting(Mc,YS_REMOTE,"");
					sv1log("##Y%d shutting C:%X pid=%d/%d\n",
						MxId,MxShutting,MxPid,procIsAlive(MxPid));
					if( MxPalive == 0 ){
						whexit = "RemoteShut";
						fdc = updateFdv(whexit,Mc,Cv,Cn,fdv,qev,civ,&numxcl);
	sv1log("--Y%d done on remote SHUT: shut=%X p%d/%d X%d\n",
		MxId,MxShutting,MxPid,procIsAlive(MxPid),numxcl);
						/* if no local X client ... */
						goto EXIT;
					}
					/* start local SHUT */
					sv1log("#### SHUT to local X ####\n");
					closeXclients(Cv,Cn,100);
					continue;
				}
				if( mx.m_type == PY_RCPT ){
					scanRCPT(Mc,&mx,bp);
					continue;
				}

				olen = ilen;
				bp += PHSIZE;
				gotXsent(Mc,&mx,mx.m_rcpt);

				if( mx.m_type == PY_REQ ){
					scanREQ(Mc,&mx,bp);
					continue;
				}
				if( mx.m_type == PY_RESP ){
					scanRESP(Mc,&mx,bp);
					continue;
				}
				if( mx.m_type == PY_INFO ){
					scanINFO(Mc,&mx,bp);
					continue;
				}
				if( mx.m_type == PY_DATA ){
					switch( mx.m_xsid ){
						case CID_SIN:
						case CID_SOUT:
						case CID_SERR:
							scanDATA(Mc,&mx,bp);
							goto NEXT;
					}
				}
				if( mx.m_type == PY_CONN ){
					yyConnect(Mc,Cv,Cn,Ci,&mx,bp,servside);
					goto NEXT;
				}
				if( mx.m_type == PY_RSET ){
					Co = findXout(Mc,Cv,Cn,Ci,&mx);
					if( Co == 0 ){
					sv1log("--Y%d got RSET #%d ?\n",
						MxId,mx.m_xsid);
						goto NEXT;
					}
					Co->c_cflag |= CF_GOTRSET;
					sv1log("--Y%d got RSET #%d [%d]\n",
						MxId,mx.m_xsid,Co->c_fd);
					/* should send closing packet of X11 ? */
			closeFd(FL_ARG,"--remoteRESET--",Mc,Cv,Cn,Co,Co->c_fd);
					MxDoupdate = "RemoteXend";
					goto NEXT;
				}
			}else{
				if( MxFlagsFLOWCTL || MxFlagsPERSIST ){
					if( yySuspend(Mc,Cv,Cn,Ci) ){
						goto NEXT;
					}
				}
				/*
				rcc = read(fdv[fi],bp,iSiz-(bp-buf));
				*/
				if( MxZ1dfl ){
					/* might be deflated larger than orig. */
					rcc = recv(fdv[fi],bp,iSiz*3/4,0);
				}else{
					rcc = recv(fdv[fi],bp,iSiz-(bp-buf),0);
				}
				serrno = errno;

				if( Ci->c_cflag & CF_UDP_SV ){
 sv1log("----UDP read [%d] #%d rcc=%d e%d CF=%X\n",
 fdv[fi],Ci->c_xsid,rcc,errno,Ci->c_cflag);
				}
				if( localOOB ){
					sv1log("----OOB DATA read #%d rcc=%d [%X]\n",
						Ci->c_xsid,rcc,0xFF&bp[0]);
				}
				ilen = olen = rcc;
				if( ilen < 0 ){
					sv1log("--#%d EOS [%d] leng=%d from X e%d #### ####\n",
						Ci->c_xsid,fdv[fi],ilen,serrno);
				}
				if( 0 < rcc ){
					Ci->c_totalread64 += rcc;
					Ci->c_totalreadN++;
					MxXmit += rcc;
					dumpXmsg(Mc,Ci,bp,ilen);
				}
			} 
			if( rcc <= 0 ){
				if( Ci->c_type == CY_XIN ){
					sv1log("--Y%d local Xend #%d [%d]\n",
						MxId,Ci->c_xsid,fdv[fi]);
					sendRCPT(Cv,Cn,Ci,Mc);
					sendRSET(Cv,Cn,Ci->c_xsid,Mc);
				}
			closeFd(FL_ARG,"--localRESET--",Mc,Cv,Cn,Ci,fdv[fi]);
				MxDoupdate = "LocalXend";

				if( MxPalive && procIsAlive(MxPid) ){
					if( 0 ){
						yyShutting(Mc,YS_XEOF,"");
						sv1log("##Y%d shutting A:%X\n",
							MxId,MxShutting);
						sendSHUT(Mc);
					}
					/* the process initiated this sesson */
					goto NEXT;
				}else{
					if( 0 ){
						whexit = "ReadError";
						goto EXIT;
					}
					goto NEXT;
				}
			}
			Ci->c_icc += ilen;
			Ci->c_ipk++;

			Co = findXout(Mc,Cv,Cn,Ci,&mx);
			if( Co == 0 ){
				/* if with PY_DATA and MF_DEFLATE */
				/* to keep ZCredhy consistent */
				discardPack(Mc,&mx,bp,ilen);
				continue;
			}
			Co->c_icc += olen;
			Co->c_ipk++;
			if( ilen < 0 || PBSIZE < ilen  ){
				sv1log("--#%d FATAL bad length: %d rcc=%d\n",
					Ci->c_xsid,ilen,rcc);
			}else
			if( yy_doMUX && Co->c_type & CY_YMUX ){
				sendDATA(Mc,Cv,Cn,Ci->c_xsid,Co,bp,ilen,olen,localOOB);
			}else{
				recvDATA(Mc,Cv,Cn,Co,&mx,bp,olen,remoteOOB);
			}
		}
	NEXT:;
	}
EXIT:
delTid(Mc);
	MxStatENDING = 1;
	sv1log("--Y%d/%d relay DONE (%u/%u %u/%u %u/%u %u/%u) %s\n",
		MxId,MxParentId,
		(int)Cv[1].c_icc,Cv[1].c_ipk,
		(int)Cv[2].c_icc,Cv[2].c_ipk,
		(int)Cv[3].c_icc,Cv[3].c_ipk,
		(int)Cv[4].c_icc,Cv[4].c_ipk,
		whexit
	);
	if( yy_nsigPIPE ){
		sv1log("--Y%d SIGPIPE=%d err=%d tid=%X/%X %s\n",
			MxId,yy_nsigPIPE,serrno,PRTID(yy_tidPIPE),TID,whexit);
	}
	if( MxParent && MxParent->mc_Shutting ){
	}else
	if( 1 ){ /* if the YMUXOUT is alive */
		sendSHUT(Mc);
		sendINFO(Mc,"iFinish",-1);
	}
	fcloseConies(Cv,Cn);
	closeXclients(Cv,Cn,1000);
	shutdownAll("relayShutdownAll",Mc,Cv,Cn,1);
	if( tid ){
		int terr;
		wcc = write(pwt[0],"",1);
		terr = thread_wait(tid,3*1000);
		sv1log("##YY thread done: %d tid=%X th=%d/%d\n",terr,PRTID(tid),actthreads(),numthreads());
		FD_closeX(FL_ARG,Mc,Cv,Cn,pwt[1],"yyrelayDone",1);
		FD_closeX(FL_ARG,Mc,Cv,Cn,pwt[0],"yyrelayDone",1);
	}
	if( MxZ1dfl ){
		deflateZ1end(MxZ1dfl);
	}
	if( MxZ1ifl ){
		inflateZ1end(MxZ1ifl);
	}
	MxMuxDone = Time();
	return 0;
}

int relay2X(int fromcl,int tocl,int fromsv,int tosv,int ignsig){
	int fv[2],tv[2],rv[2],cv[2];
	int fi;
	int rcc,wcc;
	IStr(buf,16*1024);
	int nready;
	int nint = 0;
	int aftint = 0;

	if( ignsig ){
		Vsignal(SIGINT,sigINT);
		Vsignal(SIGTERM,sigINT);
	}
	fv[0] = fromcl; tv[0] = tosv; cv[0] = 0;
	fv[1] = fromsv; tv[1] = tocl; cv[1] = 0;
	for(;;){
		nready = PollIns(0,2,fv,rv);
		if( nready <= 0 ){
			if( errno == EINTR ){
				nint++;
				sv1log("##relay2X got INTR: %d\n",nint);
				continue;
			}
			break;
		}
		for( fi = 0; fi < 2; fi++ ){
			if( rv[fi] ){
				rcc = read(fv[fi],buf,sizeof(buf));
				if( rcc <= 0 ){
					sv1log("--relay2X rcc=%d/%d errno=%d\n",
						rcc,isizeof(buf),errno);
					goto EXIT;
				}
				wcc = write(tv[fi],buf,rcc);
				if( wcc < rcc ){
					sv1log("--relay2X wcc=%d/%d errno=%d\n",
						wcc,rcc,errno);
					goto EXIT;
				}
				if( nint ){
					aftint += wcc;
				}
				cv[fi] += rcc;
			}
		}
	}
EXIT:
	sv1log("--relay2X done (%u %u) i%d SIG=%d e%d\n",cv[0],cv[1],
		nint,yy_gotSIG,errno);
	return 0;
}

/*
 * an interpretive Y11 relay
 */
static int yy_YYrelay(MuxCtx *Mc,Connection *Conn,int fromcl,int tocl,int fromsv,int tosv);
static int YYrelay(Connection *Conn,int fromcl,int tocl,int fromsv,int tosv){
	MuxCtx *Mc;
	int rcode;

	Mc = newYY(Conn,ET_PROX);
	MxYsock = tosv;
	rcode = yy_YYrelay(Mc,Conn,fromcl,tocl,fromsv,tosv);
	endYY(Conn,Mc);
	return rcode;
}
static int yy_YYrelay(MuxCtx *Mc,Connection *Conn,int fromcl,int tocl,int fromsv,int tosv){
	FILE *fpv[2];
	int tv[2],rv[2],cv[2];
	int fi;
	int rcc,wcc;
	IStr(buf,PBSIZE+PHSIZE*2);
	char *bp;
	Cony Cv[2];
	MuxMssg mx;
	int ilen;
	int nready;
	int nint = 0;
	int aftint = 0;

	Vsignal(SIGINT,sigINT);
	Vsignal(SIGTERM,sigINT);

	bzero(Cv,sizeof(Cv));
	clearCony(&Cv[0]);
	clearCony(&Cv[1]);
	addCony(Cv,2,0,CY_YMUXIN,ET_CLNT,fromcl);
	addCony(Cv,2,0,CY_YMUXIN,ET_SERV,fromsv);
	fpv[0] = Cv[0].c_fp; tv[0] = tosv; cv[0] = 0;
	fpv[1] = Cv[1].c_fp; tv[1] = tocl; cv[1] = 0;

	for(;;){
		errno = 0;
		if( nint ){
			nready = fPollIns(3*1000,2,fpv,rv);
		}else{
			nready = fPollIns(0,2,fpv,rv);
		}
		if( nready <= 0 ){
			if( errno == EINTR ){
				nint++;
				sv1log("##YYrelay got INTR: %d\n",nint);
				if( 1 < nint ){
					break;
				}
				continue;
			}
			sv1log("#YYrelay poll error rdy=%d [%d %d] e%d i%d\n",
				nready,rv[0],rv[1],errno,nint);
			break;
		}
		for( fi = 0; fi < 2; fi++ ){
			if( rv[fi] ){
				bp = (char*)buf+PHSIZE;
				ilen = 0;
				rcc = recvPack(Mc,&Cv[fi],bp,&mx,&ilen);
				if( rcc <= 0 ){
					sv1log("#YYrelay rcc=%d,%d err=%d\n",rcc,ilen,errno);
					goto EXIT;
				}
				if( ilen < 0 ){
					sv1log("#YYrelay broken data: %d\n",ilen);
					goto EXIT;
				}
				wcc = write(tv[fi],bp,PHSIZE+ilen);
				if( wcc < rcc ){
					sv1log("#YYrelay wcc=%d/%d\n",wcc,rcc);
					goto EXIT;
				}
				if( nint ){
					aftint += rcc;
				}
				cv[fi] += rcc;
			}
		}
	}
EXIT:
	fcloseConies(Cv,2);
	sv1log("--YYrelay done (%u %u) i%d SIG=%d e%d +%d\n",cv[0],cv[1],
		nint,yy_gotSIG,errno,aftint);
	return 0;
}
typedef int appRelay(struct _appProxy *Ap,FILE *in,FILE *out,PVStr(line));
typedef struct _appProxy {
	MuxCtx	 *ap_Mc;
	appRelay *ap_tosv;
	appRelay *ap_tocl;
} appProxy;
static int relayLineByLine(MuxCtx *Mc,appProxy *Ap,int svsock,int clsock){
	int fpc,rdv[4],nready;
	FILE *fsv,*tsv,*fcl,*tcl,*ifv[4];
	int serrno;
	IStr(qbuf,1024);
	IStr(rbuf,1024);

	fsv = fdopen(svsock,"r");
	tsv = fdopen(svsock,"w");
	fcl = fdopen(clsock,"r");
	tcl = fdopen(clsock,"w");

	fpc = 0;
	ifv[fpc++] = fcl;
	ifv[fpc++] = fsv;

	for(;;){
		nready = fPollIns(0,fpc,ifv,rdv);
		serrno = errno;
		if( nready <= 0 ){
			if( serrno == EINTR ){
				continue;
			}
			break;
		}
		if( rdv[0] ){
			if( fgets(qbuf,sizeof(qbuf),fcl) == 0 ){
				break;
			}
			if( MxFlagsVERBOSE ){
				sv1log("--CL %s",qbuf);
			}
			if( Ap->ap_tosv ){
				(*Ap->ap_tosv)(Ap,fcl,tsv,AVStr(qbuf));
			}
			fputs(qbuf,tsv);
			fflush(tsv);
		}
		if( rdv[1] ){
			if( fgets(rbuf,sizeof(rbuf),fsv) == 0 ){
				break;
			}
			if( MxFlagsVERBOSE ){
				sv1log("--SV %s",rbuf);
			}
			if( Ap->ap_tocl ){
				(*Ap->ap_tocl)(Ap,fsv,tcl,AVStr(rbuf));
			}
			fputs(rbuf,tcl);
			if( ready_cc(fsv) <= 0 ){
				fflush(tcl);
			}
		}
	}

	fcloseFILE(fsv);
	fclose(tsv);
	fcloseFILE(fcl);
	fclose(tcl);
	return 0;
}
static int FtpTocl(appProxy *Ap,FILE *fsv,FILE *tcl,PVStr(line)){
	if( atoi(line) == 227 ){
		sv1log("----FTP SV2CL %s",line);
	}
	return 0;
}
static int FtpTosv(appProxy *Ap,FILE *fcl,FILE *tsv,PVStr(line)){
	MuxCtx *Mc = Ap->ap_Mc;
	Connection *Conn  = Ap->ap_Mc->mc_Conn;
	IStr(com,128);
	IStr(arg,128);
	const char *dp;
	IStr(host,128);
	IStr(peer,128);

	dp = wordScan(line,com);
	lineScan(dp,arg);
	if( strcaseeq(com,"PORT") || strcaseeq(com,"EPRT") ){
		IStr(addr,128);
		int port;
		int asock;
		Cony *C1;

		getpairName(ServerSockX,AVStr(host),AVStr(peer));
		sv1log("----FTP [%d][%s][%s] CL2SV %s",fileno(tsv),
			host,peer,line);
		/* save the port in the arg (on the client) */
		/* create a port on the host IF */
		/* rewrite the address to it and forward */
		/* send PY_CONN to the saved port on acception */
		port = 0;
		Xsscanf(host,"%[^:]:%d",AVStr(addr),&port);
		asock = server_open("yyftp",AVStr(addr),0,1);
		if( 0 <= asock ){
			VSAddr cldata;
			VSAddr myaddr;
			IStr(nasock,64);

			FD_new(asock,"ftpPORT",FD_IGNOWNER);
			C1 = addCony(MxCv,MxCn,CID_FTDA,CY_ACC,ET_CLNT,asock);

			VSA_getsockname(&myaddr,asock);
			VSA_prftp(&myaddr,AVStr(nasock));
			sprintf(line,"PORT %s\r\n",nasock);
			VSA_atosa(&cldata,0,"0.0.0.0"); /* client address for EPRT |||p| */
			VSA_ftptosa(&cldata,arg);
			sprintf(C1->c_dst_port,"ftp-data://%s:%d",
				VSA_ntoa(&cldata),VSA_port(&cldata));
			sv1log("----FTP %s <= %s",C1->c_dst_port,line);
			MxDoupdate = "FtpPORT";
			MxDoupTerse = 1;
		}
	}
	return 0;
}
static int relayFTP(MuxCtx *Mc,int svsock,int clsock){
	appProxy Ap;

	bzero(&Ap,sizeof(Ap));
	Ap.ap_Mc = Mc;
	Ap.ap_tocl = FtpTocl;
	Ap.ap_tosv = FtpTosv;
	relayLineByLine(Mc,&Ap,svsock,clsock);
	return 0;
}
static int relayLn(appProxy *Ap,FILE *fcl,FILE *tsv,PVStr(line)){
	const char *dp;
	IStr(com,128);
	IStr(arg,128);

	dp = wordScan(line,com);
	lineScan(dp,arg);
	sv1log("--Ln--[%s][%s]\n",com,arg);
	return 0;
}
static int relay2sv(appProxy *Ap,FILE *fcl,FILE *tsv,PVStr(line)){
	const char *dp;
	IStr(com,1024);
	IStr(arg,1024);
	int asock;

	dp = wordScan(line,com);
	lineScan(dp,arg);
	return 0;
}
const char *searchPortSpec(PCStr(resp));
static int relay2cl(appProxy *Ap,FILE *fsv,FILE *tcl,PVStr(line)){
	MuxCtx *Mc = Ap->ap_Mc;
	Connection *Conn  = Ap->ap_Mc->mc_Conn;
	const char *dp;
	IStr(com,1024);
	IStr(arg,1024);
	int code;

	dp = wordScan(line,com);
	lineScan(dp,arg);
	code = atoi(line);

	if( code == 227 || code == 229 ){
		Cony *C1;
		VSAddr cldata;
		VSAddr myaddr;
		int asock;
		IStr(addr,128);
		IStr(dport,64);

		sv1log("--ToCL--[%s][%s]\n",com,arg);
		strcpy(addr,"0.0.0.0");
		asock = server_open("yyftp",AVStr(addr),0,1);
		if( 0 <= asock ){
			FD_new(asock,"ftpPASV",FD_IGNOWNER);
			C1 = addCony(MxCv,MxCn,CID_FTDA,CY_ACC,ET_CLNT,asock);
			VSA_atosa(&cldata,0,"127.0.0.1");
			if( dp = searchPortSpec(line) )
				VSA_ftptosa(&cldata,dp);
			else	VSA_ftptosa(&cldata,arg);
			sprintf(C1->c_dst_port,"ftp-data://%s:%d",
				VSA_ntoa(&cldata),VSA_port(&cldata));
			if( code == 229 ){
				sprintf(line,"229 Entering Extended Passive Mode (|||%d|)\r\n",
					sockPort(asock));
			}else{
				VSA_atosa(&myaddr,0,"127.0.0.1");
				VSA_getsockname(&myaddr,ClientSockX);
				VSA_setport(&myaddr,sockPort(asock));
				VSA_prftp(&myaddr,AVStr(dport));
				sprintf(line,"227 Entering Extended Passive Mode (%s)\r\n",
					dport);
			}
			MxDoupdate = "FtpPASV";
			MxDoupTerse = 1;
		}
	}
	return 0;
}
static int FtpClient1(MuxCtx *Mc,int clsock,int svsock){
	appProxy Ap;

	bzero(&Ap,sizeof(Ap));
	Ap.ap_Mc = Mc;
	Ap.ap_tocl = relay2cl;
	Ap.ap_tosv = relay2sv;
	relayLineByLine(Mc,&Ap,svsock,clsock);
	return 0;
}
static int FtpClient(MuxCtx *Mc,int clsock){
	int sp[2];
	int tid;

	Socketpair(sp);
	tid = thread_fork(0,0,"FtpClient",(IFUNCP)FtpClient1,Mc,clsock,sp[1]);
	return sp[0];
}
static void setupLAccPort(MuxCtx *Mc,FILE *tc,int ysock,PCStr(proto),PCStr(yhost),int yport){
	/* biding a port for PORT */
	IStr(sockname,MaxHostNameLen);
	IStr(peername,MaxHostNameLen);
	IStr(host,MaxHostNameLen);
	int asock;
	int port;

	if( strcaseeq(proto,"ftp") ){
		Connection *Conn = MxConn;
		int pp[2]; /* client--[0]pp[1]--relayFTP--(ysock)--server */
		int fsock;
		int tid;

		Socketpair(pp);
		fsock = dup(ysock);
		if( ysock == ServerSockX ){
			ServerSockX = fsock;
		}
		dup2(pp[0],ysock);
		close(pp[0]);
		tid = thread_fork(0,0,"FTP",(IFUNCP)relayFTP,Mc,fsock,pp[1]);
	}

	if(0)
	if( streq(proto,"ftp") ){
		getpairName(ysock,AVStr(sockname),AVStr(peername));
		Xsscanf(sockname,"%[^:]",AVStr(host));
		asock = server_open("yy-FTP-data-PORT",AVStr(host),0,1);
		port = sockPort(asock);
		MxLAccSock = asock;
		sv1log("--FTP[%s](%s)(%d) %s <= %s [%d]\n",proto,yhost,yport,
			peername,sockname,asock);
		FD_new(asock,"LAccSock",1);
		lfprintf("FTP",tc,"%s: %s",YH_DSTPORT,peername);
		lfprintf("FTP",tc,"%s: %s",YH_SRCPORT,sockname);
		lfprintf("FTP",tc,"%s: %s:%d",YH_ACCPORT,host,port);
	}
}
static int flushinbuf(FILE *ifp,int out);
static int yyMUXproxy(MuxCtx *Mc,Connection *Conn,FILE *fc,FILE *tc,PCStr(ymethod),PCStr(ycom),int ac,const char *av[]){
	IStr(proto,128);
	IStr(serv,MaxHostNameLen);
	IStr(xcom,1024);
	IStr(resp,1024);
	IStr(yhost,MaxHostNameLen);
	int yport = 0;
	int ysock;
	int serrno;
	int ai;
	FILE *ts = 0;
	FILE *fs = 0;
	int ri;
	IStr(hver,16);
	IStr(hreason,128);
	int hcode = 0;
	int badSv = 0;
	int localRSM = 0;
	int isRSM = 0;
	double St = Time();

	sv1log("--YY proxy (%s %s)\n",ymethod,ycom);
	if( !strncaseeq(ycom,"y11://",6)
	 && !streq(ymethod,YY_CON)
	){
		sv1log("##YY proxy forbidden: %s %s\n",ymethod,ycom);
		return -1;
	}
	Xsscanf(ycom,"%[^:]://%[^/]/%s",AVStr(proto),AVStr(serv),AVStr(xcom));
	Xsscanf(serv,"%[^:]:%d",AVStr(yhost),&yport);
	if( yport == 0 ){
		yport = serviceport(proto);
		if( yport == 0 ){
			yport = 6010;
		}
	}
	if( streq(ymethod,YY_CON) && MxRsmstate == 0 ){
		/* simple YY router */
		set_realserver(Conn,proto,yhost,yport);
		ysock = connect_to_serv(Conn,fileno(fc),fileno(tc),0);
		if( 0 <= ysock ){
			flushinbuf(fc,ysock);
			relay2X(fileno(fc),fileno(tc),ysock,ysock,1);
		}else{
			lfprintf(ymethod,tc,"HTTP/1.0 500 Cannot connect");
			lfprintf(ymethod,tc,"");
		}
		return 0;
	}

	if( streq(ymethod,YY_CON) && MxRsmstate != CST_INITIAL ){
		isRSM = 1;
		sv1log("--Y%d RSM %s %s [%s:%d] PORT=%d KEY=%u\n",
			MxId,ymethod,ycom,yhost,yport,MxRsmport,MxRsmkey);
		if( do_RELAY(Conn,RELAY_Y11) ){
			sv1log("##RSM THRU PROXY (SERVER=y11 RELAY=y11) %d k%u\n",
				MxRsmport,MxRsmkey);
			/* don't try to connect to RSMPORT */
		}else
		if( (MxEtype & ET_NOX) && strcaseeq(proto,"y11") ){
			/* cascaded y11 proxy */
			sv1log("##RSM THRU PROXY (SERVER=yymux %s %s) %d k%u\n",
				ymethod,ycom,MxRsmport,MxRsmkey);
		}else
		if( MxRsmYYGUID && MxYYGUID && MxRsmYYGUID != MxYYGUID ){
 yprintf(Mc,"#### ERROR: NOT A LOCAL RSM: %X %X ####",MxRsmYYGUID,MxYYGUID);
		}else
		if( MxRsmport && MxRsmkey ){
			strcpy(yhost,"127.0.0.1");
			yport = MxRsmport;
			Conn->no_dstcheck = 1; /* maybe SERVER=http (not SERVER=y11) */
			localRSM = 1;
			sv1log("--RSM state=%X localRSM\n",MxRsmstate);
		}else{
			sv1log("##YY proxy forbidden: BAD RSM %s %s, port=%d, key=%u\n",
				ymethod,ycom,MxRsmport,MxRsmkey);
			return -1;
		}
	}

	sv1log("##yyMUX PROXY [%s %s:%d] DST[%s:%s:%d] etype=%X\n",
		ymethod,yhost,yport,DST_PROTO,DST_HOST,DST_PORT,MxEtype);
	if( yhost[0] == 0 ){
		sv1log("##YY proxy empty yhost ####\n");
		return -1;
	}

	if( streq(DST_PROTO,"yymux") ){
		if( isRSM ){
			Conn->no_dstcheck_proto = serviceport("yymux");
		}
		Conn->no_dstcheck_proto = serviceport("y11");
	}
	if( proto[0] && serv[0] ){
		set_realserver(Conn,proto,yhost,yport);
		if( MxEtype & ET_NOX ){
			/* if without explicit REMITTABLE */
			Conn->no_dstcheck_proto = serviceport(proto);
		}
	}else{
		set_realserver(Conn,"y11",yhost,yport);
	}
	if( localRSM ){
		int sleep1 = 100;
		int rsmhold = MxRsmhold;
		sv1log("--RSM-- ---- reconnecting to %s %d/%d ... (%d)\n",
			yhost,yport,MxRsmport,MxRsmhold);
		MxRsmhold = 3;
		ysock = connects(Mc,yhost,St,&sleep1,3*1000,1);
		MxRsmhold = rsmhold; /* to be used for accepts() in the server */
	}else{
		ysock = connect_to_serv(Conn,FromC,ToC,0);
	}
	serrno = errno;

	sv1log("--YY proxy[%d][%d][%d]: %s:%d %s e%d\n",ysock,
		ToS,FromS,yhost,yport,xcom,serrno);
	if( ysock < 0 ){
		/* the port is gone, if ymethod == YY_RSM */
		if( isRSM ){
			sv1log("--RSM-- connect error, local=%d\n",localRSM);
		}
		if( localRSM ){
			lfprintf(ymethod,tc,"HTTP/1.0 410 Gone");
		}else
		if( (serrno == ECONNREFUSED) || (ConnError & CO_REFUSED) ){
			lfprintf(ymethod,tc,"HTTP/1.0 503 No Server There");
		}else
		{
			lfprintf(ymethod,tc,"HTTP/1.0 504 Cannot Connect");
		}
		lfprintf(ymethod,tc,"");
		fflush(tc);
		return -2;
	}
	FD_new(ysock,"proxFromS",FD_DONTCLOSE);
	fs = fdopen(ysock,"r");
	if( fs == NULL ){
		sv1log("--yymux FATAL: cannot fdopen ysock-r[%d] e%d\n",
			ysock,errno);
		goto EXIT;
	}
setbuffer(fs,0,0); /* yymux-proxy */
	ts = fdopen(ysock,"w");
	if( ts == NULL ){
		sv1log("--yymux FATAL: cannot fdopen ysock-w[%d] e%d\n",
			ysock,errno);
		goto EXIT;
	}

	/*
	if( (MxEtype & ET_NOX) && !streq(proto,"y11") ){
	*/
	if( (MxEtype & ET_NOX) && (!streq(proto,"y11") || streq(ymethod,YY_CON) ) ){
		if( isRSM ){
			lfprintf("RSM-relay",ts,"%s %s HTTP/1.1",ymethod,xcom);
			lfprintf("RSM-relay",ts,"Y-Version: %s",myYYVER);
			putAutho("pxForw",Mc,ts);
			putYConnection("pxForw",0,Mc,ts);
			lfprintf("RSM-relay",ts,"");
			fflush(ts);
			relay2X(fileno(fc),fileno(tc),ysock,ysock,0);
		}else{
			lfprintf("pxResp",tc,"HTTP/1.1 200 yyMux proxy OK");
			lfprintf("pxResp",tc,"Y-Version: %s",myYYVER);
			setupLAccPort(Mc,tc,ysock,proto,yhost,yport);
			if( MxFlagsPERSIST ){
				MxRsmkey ^= trand1(0xFFFFFFFF);
				putYConnection("pxResp",0,Mc,tc);
			}
			lfprintf("pxResp",tc,"");
			fflush(tc);
			MxPalive = 0;
			MxPid = -1;
			//yyMUXrelay(Mc,-1,FromC,ToC,MUX_ON,ysock,ysock,MUX_OFF,1);
			yyMUXrelay(Mc,-1,fileno(fc),fileno(tc),MUX_ON,ysock,ysock,MUX_OFF,1);
			if( 0 <= MxLAccSock ){
				FD_close(MxLAccSock,"LAccSock");
			}
		}
	}else{
		if( *xcom == 0 ){
			strcpy(xcom,"xterm");
		}
		if( fPollIn(fs,20) ){
			int ch;
			ch = getc(fs);
			ungetc(ch,fs);
			fgetsBuffered(AVStr(resp),sizeof(resp),fs);
			sv1log("#Y11 BadServer: %s",resp);
			lfprintf("Forbidden",tc,"HTTP/1.0 403 Bad X Server");
			lfprintf("Forbidden",tc,"");
			goto EXIT;
		}
		lfprintf("pyForw",ts,"%s %s HTTP/1.1",ymethod,xcom);
		lfprintf("pyForw",ts,"Y-Version: %s",myYYVER);
		putAutho("pyForw",Mc,ts);
		putYConnection("pyForw",0,Mc,ts);
		for( ai = 1; ai < ac; ai++ ){
			lfprintf("pyForw",ts,"X-Arg: %s",av[ai]);
		}
		lfprintf("pyForw",ts,"");
		fflush(ts);
		for( ri = 0; ri < 100; ri++ ){
			if( fPollIn(fs,10*1000) <= 0 ){
				sv1log("--Y11 serv. timeout #### ####\n");
				goto EXIT;
			}
			if( fgets(resp,sizeof(resp),fs) == 0 ){
				sv1log("--Y11 serv. premature EOS\n");
				goto EXIT;
			}
			sv1log("--YY proxy resp: %s",resp);
			if( ri == 0 ){
				Xsscanf(resp,"%s %d %[^\r\n]",AVStr(hver),
					&hcode,AVStr(hreason));
				if( !strneq(hver,"HTTP/1",6) ){
			sv1log("--YY proxy: Bad server: %s",resp);
			lfprintf("Yproxy",tc,"HTTP/1.0 500 Bad Server");
					fprintf(tc,"\r\n");
					badSv = 1;
				}
			}else{
			}
			if( !badSv ){
				fputs(resp,tc);
			}
			if( *resp == '\r' || *resp == '\n' ){
				break;
			}
		}
		fflush(tc);
		if( badSv ){
		}else{
			if( PollIn(ysock,1) ){
				sv1log("--YY input active: alv=%d readycc=%d\n",
					IsAlive(ysock),ready_cc(fs));
			}
			if( 1 ){
				YYrelay(Conn,FromC,ToC,ysock,ysock);
			}else{
				relay2X(FromC,ToC,ysock,ysock,1);
			}
		}
	}
EXIT:
	if( ts != NULL ){
		fcloseFILE(ts);
	}
	if( fs != NULL ){
		fcloseFILE(fs);
	}
	FD_closeX(FL_ARG,Mc,0,0,ysock,"yyProxy",1);
	CTX_closedX(FL_ARG,"---FATAL---yyProxy---",Conn,ysock,-1,1);
	return 0;
}
static int yyCoupler(MuxCtx *Mc,Connection *Conn,FILE *fc,FILE *tc,PCStr(ycom),int ac,const char *av[]){
	int socksv;
	IStr(host,MaxHostNameLen);
	int ysock = -1;
	int fdv[2],rdv[2],rdy;
	int side;

	strcpy(host,"127.0.0.1");
	socksv = server_open("YYCQ",AVStr(host),16010,1);

	fdv[0] = fileno(fc);
	if( 0 <= socksv ){
		fdv[1] = socksv;
		rdy = PollIns(60*1000,2,fdv,rdv);
		if( 0 < rdy && rdv[1] ){
			ysock = ACCEPT(socksv,0,-1,1);
		}
		close(socksv);
		sv1log("--YYCQ (%s) ACCEPTED[%d] >>> [%d]\n",host,socksv,ysock);
		side = 1;
	}else{
		/* PollInsOut */
		ysock = client_open("YYCQ","yymux",host,16010);
		/*
		ysock = OpenServer("YYCQ","yymux",host,16010,yy_PORT);
		*/
		sv1log("--YYCQ (%s) CONNECTED >>> [%d]\n",host,ysock);
		side = 0;
	}
	if( 0 <= ysock ){
		fprintf(tc,"HTTP/1.1 200 OK\r\n");
		fprintf(tc,"Y-Side: %d\r\n",side);
		fprintf(tc,"\r\n");
		fflush(tc);
		relay2(fileno(fc),fileno(tc),ysock,ysock);
	}else{
	}
	return 0;
}
static int forbiddenXcom(PCStr(xcom),int ac,const char *av[]){
	IStr(fpath,256);
	int xp;

	if( streq(xcom,"=")
	 || streq(xcom,"-")
	 || streq(xcom,".put")
	 || streq(xcom,".get")
	 || streq(xcom,".tar")
	 || streq(xcom,".ysh")
	){
		return 0;
	}
	xp = fullpathCOM(xcom,"r",AVStr(fpath));
	sv1log("--Y11 %d{%s}{%s}\n",xp,xcom,fpath);
	if( xp == 0 ){
		/* should scan PATHEXT */
		IStr(xxcom,128);
		sprintf(xxcom,"%s.exe",xcom);
        	if( xp = fullpathCOM(xxcom,"r",AVStr(fpath)) ){
			sv1log("--Y11 %d{%s}{%s}\n",xp,xcom,fpath);
		}
	}
	if( xp == 0 ){
		return 1;
	}
	if( strcasestr(fpath,"X11") == 0 ){
		if( *xcom == 'x' || *xcom == 'X' ){
		}else
		if( strtailchr(xcom) == 'x' ){
			/* firefox :p) */
		}else{
			return 2;
		}
	}
	return 0;
}

static const char *YYpushenv(MuxCtx *Mc,PCStr(env)){
	const char *ne;
	ne = pushenv(elnumof(MxEnv),MxEnv,QVStr(MxStrtail,MxStrbuf),env);
	return ne;
}
void getHOME(int uid,PVStr(home));
static void setupYYenv(MuxCtx *Mc){
	int rcode;
	IStr(path,256);

	if( MxUserHOME[0] && strneq(MxUserHOME,"HOME=",5) ){
		rcode = chdir(MxUserHOME+5);
		putenv(MxUserHOME);
	}else{
		getHOME(getuid(),AVStr(path));
		if( *path && !streq(path,"/") ){
			rcode = chdir(path);
			if( rcode == 0 ){
				sprintf(MxUserHOME,"HOME=%s",path);
				putenv(MxUserHOME);
			}
		}
	}
	if( MxUserPATH[0] ){
		putenv(MxUserPATH);
	}
	if( MxUserLD_PATH[0] ){
		putenv(MxUserLD_PATH);
	}
}
/*
 * SERVER=y11
 * SERVER=yymux -- YMUX on client-side, raw relay on server-side
 * SERVER=yymux://server -- YMUX/server-side, raw/client-side
 * YYMUX=yyserv:yyport
 */
int yy_service_Y11a(MuxCtx *Mc,Connection *Conn,int svsock,int svport,int etype);
int service_Y11a(Connection *Conn,int svsock,int svport,int etype){
	MuxCtx *Mc;
	int rcode;
	IStr(rusg,256);

	initgMc(Conn);
	Mc = newYY(Conn,etype);
	rcode = yy_service_Y11a(Mc,Conn,svsock,svport,etype);
	endYY(Conn,Mc);

	/*
	strfRusage(AVStr(rusg),"%A",3,NULL);
	sv1log("RUSG: %s threads=%d/%d\n",rusg,actthreads(),numthreads());
	*/
	if( 0 <= ClientSock
	 && 0 <= FromC
	 && 0 <= ToC
	 && 0 <= ServerSock
	 && 0 <= FromS
	 && 0 <= ToS
	){
		sv1log("--yy Cl[%d %d %d] Sv[%d %d %d]\n",
			ClientSock,FromC,ToC,ServerSock,FromS,ToS);
	}
	return rcode;
}
static int setupRSMport(MuxCtx *Mc,PCStr(xcom)){
	int closeRSM = 0;

	if( MxRsmstate == CST_RESUME
	 || MxRsmstate == CST_SALVAGE
	){
		sv1log("##RSM-PORT DONT RENEW in RSM %d p%d k%u\n",
			MxRsmstate,MxRsmport,MxRsmkey);
	}else
	if( (MxEtype & ET_NOX) && strneq(xcom,"y11://",6) ){
		sv1log("##RSM-PORT DONT CREATE, Y11 proxy\n");
	}else
	if( MxRsmport ){
		/* don't make new RSM port in RSM request */
		sv1log("##RSM-PORT DONT RENEW (%d)\n",MxRsmport);
	}else{
		MxRsmsock = openRsmPort("new-yyRsmPort",Mc,0);
		MxRsmport = sockPort(MxRsmsock);
		MxRsmYYGUID = MxYYGUID;
		FD_new(MxRsmsock,"rsmAccept",FD_DONTCLOSE);
		closeRSM = 1;
		sv1log("##RSM-PORT NEW (%d) %d %010u [%d]\n",
			MxRsmport,MxRsmhold,MxRsmkey,MxRsmsock);
		/* don't yet assign MxRsmkey to indicate non-RSM */
	}
	return closeRSM;
}

static int createYdispX(MuxCtx *Mc,PVStr(xchost),int *yportp,PVStr(dispenv)){
	int xsock;

	strcpy(xchost,"127.0.0.1");
	if( MxFlagsX11UNIX ){
		yportp = 0;
	}else
	if( MxFlagsX11LOCAL ){
	}else
	if( MxFlagsX11INET ){
		strcpy(xchost,"0.0.0.0");
	}
	xsock = createXdisp(BVStr(xchost),yportp,BVStr(dispenv));
	return xsock;
}
#define createYdisp(host,port,env) createYdispX(Mc,host,port,env)

int tobeREJECTED(Connection *Conn);
int service_yysh2(Connection *Conn,int svsock,int svport,MuxCtx *Mc,FILE *fc,FILE *tc,PCStr(req));
int yy_service_Y11a(MuxCtx *Mc,Connection *Conn,int svsock,int svport,int etype){
	FILE *tc = 0;
	FILE *fc = 0;
	IStr(xchost,MaxHostNameLen);
	int xcsock = -99;
	IStr(req,256);
	refQStr(rp,req);
	IStr(env,256);
	const char *disp;
	int nready;
	int xtsock;
	int total;
	const char *origDISP = origDISPLAY();
	IStr(xproto,64);
	IStr(xhost,MaxHostNameLen);
	int xport = 0;
	IStr(xcom,128);
	IStr(lcom,128);
	int xpid = -99;
	const char *av[64];
	int ac = 0;
	const char *a1;
	int ph;
	const char *ep;
	IStr(ymethod,64);
	int asProxy = 0;
	int withoutX = 0;
	int closeRSM = 0;
	int wcc;

setthreadgid(getthreadid(),getthreadid());
MxStatISMAIN = 1;
Mc->mc_ytgid = getthreadgid(0);

	sv1log("--yy (%s) [%d/%d][%s:%d] start\r\n",
		iSERVER_PROTO,svsock,svport,iSERVER_HOST,iSERVER_PORT);

	if( tobeREJECTED(Conn) ){
		sprintf(req,"HTTP/1.0 403 forbidden\r\n\r\n");
		wcc = write(ToC,req,strlen(req));
		return -1;
	}
	if( ImMaster && 0 <= ToS ){
		sv1log("##YYMUX via MASTER [%d %d][%d %d]\n",
			FromC,ToC,FromS,ToS);
		relay2(FromC,ToC,FromS,ToS);
		return 0;
	}
	/*
	if( PollIn(FromC,1) == 0 ){
	*/
	if( 1 ){
		tc = fdopen(ToC,"w");
		lfprintf("YYMUX",tc,"HTTP/1.1 100 yyMux");
		if( 1 ){
			generateCredhyKey(Mc,tc,"YYMUX",1);
		}
		lfprintf("YYMUX",tc,"Y-Version: %s",myYYVER);
		lfprintf("YYMUX",tc,"");
		fcloseFILE(tc);
		tc = 0;
	}
	if( PollIn(FromC,TimeoutY11) == 0 ){
		return -1;
	}

	FD_new(FromC,"servFromC",FD_DONTCLOSE);
	fc = fdopen(FromC,"r");
	if( fc == NULL ){
		sv1log("--FATAL cannot fdopen FromC[%d] e%d\n",FromC,errno);
		goto EXIT;
	}
	if( fgets(req,sizeof(req),fc) == NULL ){
		sv1log("--FATAL EOS[%d] on request. e%d\n",FromC,errno);
		goto EXIT;
	}
	tc = fdopen(ToC,"w");
	if( tc == NULL ){
		sv1log("--FATAL cannot fdopen ToC[%d] e%d\n",ToC,errno);
		goto EXIT;
	}
	Xsscanf(req,"%s %s %*s",AVStr(ymethod),AVStr(xcom));
	sv1log("----Y11 [%s][%s] REQ=%s",ymethod,xcom,req);
	withoutX = (MxEtype & ET_NOX) && !streq(ymethod,YY_Y11);

	if( strchr(xcom,':') ){
		Xsscanf(xcom,"%[^:]://%[^:]:%d",AVStr(xproto),AVStr(xhost),&xport);
	}
	if( streq(xproto,"yysh") && (xhost[0] == 0 || streq(xhost,"-")) ){
		int rcode;
		sv1log("--YYMUX to yysh server [%s][%s] [%s][%s]\n",
			ymethod,xcom,xproto,xhost);
		/* if yysh://-.- is not in REJECT */
		rcode = service_yysh2(Conn,svsock,svport,Mc,fc,tc,req);
		goto EXIT;
	}
	if( streq(ymethod,YY_CQ) ){
		/* coupling rquest */
		if( !do_RELAY(Conn,RELAY_Y11) ){
			MxForbidden = "AsCoupler";
		}
	}else
	if( streq(ymethod,YY_CON) ){
		/* YYCONNECT http://server */
		asProxy = 2;
	}else
	if( strncaseeq(xcom,"y11://",6) ){
		asProxy = 1;
		if( streq(iSERVER_PROTO,"yymux")
		 || streq(iSERVER_PROTO,"yy")
		){
			/* born proxy */
		}else
		if( !do_RELAY(Conn,RELAY_Y11) ){
			MxForbidden = "AsProxy";
			/* SERVER=y11 without proxying */
		}
	}else
	if( strneq(xcom,"yy:",3) ){
	}else
	if( strpbrk(xcom,"/\\:;<>(){}[]`'") ){
		MxForbidden = "BadChars";
	}

	av[ac++] = xcom;
	scanYYrequest(Mc,elnumof(av),av,ac,fc);
	if( MxAuthErr ){
		lfprintf("Resp",tc,"HTTP/1.0 401 auth. error");
		lfprintf("Resp",tc,"Y-Version: %s",myYYVER);
		lfprintf("Resp",tc,"");
		fflush(tc);
		goto EXIT;
	}

	if( strneq(xcom,"yy:",3) ){
	}else
	if( strncaseeq(xcom,"y11://",6) ){
		asProxy = 1;
	}else
	if( streq(ymethod,YY_CON) ){
		/* YYCONNECT http://server */
		/* should do usual service_permitted() here */
		asProxy = 2;
	}else{
		addX11PATH(elnumof(MxEnv),MxEnv,AVStr(MxStrbuf));
		if( forbiddenXcom(xcom,ac,av) ){
			MxForbidden = "BadCommand";
		}
	}
	if( MxForbidden ){
		sv1log("--Y11 Forbidden: etype=%X method=%s xcom=%s %s\n",
			MxEtype,ymethod,xcom,MxForbidden);
		lfprintf("SentResp",tc,"HTTP/1.0 403 forbidden");
		lfprintf("SentResp",tc,"");
		goto EXIT;
	}
	if( !streq(MxClntyver,myYYVER) ){
		fprintf(tc,"HTTP/1.0 500 bad version\r\n");
		fprintf(tc,"\r\n");
		goto EXIT;
	}
	if( MxFlagsPERSIST ){
		if( (MxEtype & ET_NOX) || !asProxy ){
			closeRSM = setupRSMport(Mc,xcom);
		}
	}
	MxStatACTIVATED = 1;
	if( (MxRsmstate & CST_INITIAL) == 0 && (MxRsmstate & CST_RESUME) ){
		yyMUXproxy(Mc,Conn,fc,tc,ymethod,xcom,ac,av);
		goto EXIT;
	}else
	if( strneq(xcom,"yy:",3) ){
		withoutX = 2;
	}else
	if( strncaseeq(xcom,"y11://",6)
	 || streq(ymethod,YY_CON)
	){
		yyMUXproxy(Mc,Conn,fc,tc,ymethod,xcom,ac,av);
		goto EXIT;
	}
	if( streq(ymethod,YY_CQ) ){
		yyCoupler(Mc,Conn,fc,tc,xcom,ac,av);
		goto EXIT;
	}

	if( withoutX ){
		xcsock = -1;
	}else{
		int yport = 6001;
		xcsock = createYdisp(AVStr(xchost),&yport,AVStr(env));
		FD_new(xcsock,"servYdisp",0);
		if( xcsock < 0 ){
			sv1log("----Y11 could not bind\n");
			fprintf(tc,"HTTP/1.0 500 could not bind\r\n");
			fprintf(tc,"\r\n");
			goto EXIT;
		}
	}

	lfprintf("svResp",tc,"HTTP/1.1 200 OK");
	lfprintf("svResp",tc,"Y-Version: %s",myYYVER);
	lfprintf("svResp",tc,"Y-Server: origin=y11");
	if( MxFlagsPERSIST ){
		MxRsmkey ^= trand1(0xFFFFFFFF);
		putYConnection("svResp",0,Mc,tc);
	}
	if( withoutX ){
	}else{
		ep = getenv("DISPLAY");
		lfprintf("svResp",tc,"X-DISPLAY-1: %s",ep?ep:"");
		YYpushenv(Mc,env);
		disp = getenv("DISPLAY");
		sv1log("--Y11 DISPLAY=%s\n",disp?disp:"");
		ep = getenv("DISPLAY");
		lfprintf("svResp",tc,"X-DISPLAY-2: %s",ep?ep:"");
	}
	lfprintf("svResp",tc,"");
	fflush(tc);

	if( strneq(xcom,"yy:",3) ){
		MxHoldonNX = 1;
		ovstrcpy(xcom,xcom+3);
		MxPid = yybgexec(Mc,xcom,(char**)av,(char**)environ,&ph);
		MxPhandle = ph;
		MxPalive = 2;
		yyMUXrelay(Mc,xcsock,FromC,ToC,MUX_ON,-1,-1,MUX_OFF,1);
		goto EXIT;
	}
	if( withoutX ){
		MxPalive = 0;
		MxPid = -3;
		yyMUXrelay(Mc,xcsock,FromC,ToC,MUX_ON,-1,-1,MUX_OFF,1);
	}else
	if( streq(xcom,"=") || streq(xcom,"-") ){
		MxPalive = 0;
		MxPid = -2;
		xtsock = -1;
		yyMUXrelay(Mc,xcsock,FromC,ToC,MUX_ON,xtsock,xtsock,MUX_OFF,1);
	}else{
		MxPid = yybgexec(Mc,xcom,(char**)av,(char**)environ,&ph);
		MxPhandle = ph;
		MxPalive = 1;
	}
	if( MxPalive ){
		double St = Time();
		sv1log("----Y11 pid=%d\n",MxPid);
		for(;;){
			nready = PollIn(xcsock,100);
			if( nready != 0 ){
				break;
			}
			if( !procIsAlive(MxPid) ){
				sv1log("----Y11 pid=%d dead\n",MxPid);
				break;
			}
			if( !isWindows() ){
				xpid = NoHangWait();
				if( 0 < xpid ){
					sv1log("----Y11 pid=%d dead %d\n",MxPid,xpid);
					if( xpid == MxPid ){
						break;
					}
				}
			}
			if( TIMEOUT_Y11 < Time()-St ){
				break;
			}
		}
		sv1log("----Y11 pid=%d nready=%d\n",MxPid,nready);
		if( 0 < nready ){
			xtsock = ACCEPT(xcsock,0,-1,(int)(TIMEOUT_Y11));
			FD_new(xtsock,"servXclnt",0);
			sv1log("----Y11 pid=%d nready=%d xtsock=%d\n",MxPid,nready,xtsock);
			yyMUXrelay(Mc,xcsock,FromC,ToC,MUX_ON,xtsock,xtsock,MUX_OFF,1);
			FD_close(xtsock,"servXclnt");
		}else{
			MxYsock = ToC;
			sendINFO(Mc,"eXcommandError",-1);
			sendSHUT(Mc);
			sv1log("##Y11 X command Error\n");
			if( 0 <= MxPsout ){ FD_close(MxPsout,"Stdout"); }
			if( 0 <= MxPserr ){ FD_close(MxPserr,"Stderr"); }
		}
		FD_close(xcsock,"Ydisp");
		if( MxPalive ){
			if( isWindows() ){
				xpid = bgwait(MxPid,ph,5);
			}else{
				xpid = TimeoutWait(5);
			}
		}else{
		}
	}else{
		FD_close(xcsock,"Ydisp");
	}
EXIT:
	if( closeRSM ){
		FD_closeX(FL_ARG,Mc,0,0,MxRsmsock,"rsmAccept",1);
	}
	if( tc ){
		fcloseFILE(tc);
	}
	if( fc ){
		fcloseFILE(fc);
	}
	FD_closeX(FL_ARG,Mc,0,0,FromC,"servFromC",1);
	CTX_closedX(FL_ARG,"---FATAL---servFromC---",Conn,FromC,-1,1);
	if( 0 <= ServerSock ){
	CTX_closedX(FL_ARG,"---FATAL---ServerSock---",Conn,ServerSock,-1,1);
	}
	sv1log("--Y11 [%s:%d] done [%d]\n",DST_HOST,DST_PORT,xpid);
	if( 0 <= MxPsins ){
		FD_close(MxPsins,"clntStdin");
	}
	if( MxFlagsVERBOSE ){
		FD_showall("yyserv");
	}
	YY_endYYs("end-Y11a",Conn,0,getthreadgid(0));
	return 0;
}
static void relayYMS(MuxCtx *Mc,int clsock,int yyx0,int yyx1,int xcsock,PCStr(xcom)){
	sv1log("--YY relayYMS cl[%d] sv[%d] {%s}\n",clsock,yyx0,xcom);
	if( 0 <= MxRsmsock ){
		FD_new(MxRsmsock,"rsmAccept",FD_CHOWN);
	}
	FD_new(xcsock,"servYdisp",0);
	FD_new(clsock,"ViaYY-CL",0);
	FD_new(yyx0,"ViaYY-SV",0);
	if( MxFlagsVERBOSE ){
		MxDebug = 10;
	}
	MxPid = -3;
	MxPalive = 0;
	yyMUXrelay(Mc,xcsock,clsock,clsock,MUX_ON,yyx0,yyx0,MUX_OFF,1);
	sv1log("--YY relayYMS end, alv=%d\n",IsAlive(yyx0));
}
static int createRserv(PCStr(name),int port,PVStr(env)){
	IStr(host,MaxHostNameLen);
	int sock;

	strcpy(host,"127.0.0.1");
	sock = server_open(name,AVStr(host),port,1);
	sprintf(env,"%s=%s:%d",name,host,port);
	return sock;
}
int insertMuxSV(MuxCtx *Mc,Connection *Conn,int clsock,FILE *fc,FILE *tc,int dodup){
	int yyx[2];
	int tid;
	IStr(xchost,64);
	int xcsock = -99;
	int osock,nsock;
	IStr(req,256);
	IStr(ymethod,64);
	IStr(xcom,128);
	IStr(hver,128);
	const char *av[64];
	int ac = 0;
	const char *origDISP = origDISPLAY();
	int rcc = -1;
	int bcc = -1;

	const char *disp;
	IStr(dispenv,256);
	const char *ep;

	IStr(servenv,256);
	int svsock = -1;

	lfprintf("muxSV",tc,"HTTP/1.1 100 yymux");
	lfprintf("muxSV",tc,"Y-Version: %s",myYYVER);
	lfprintf("muxSV",tc,"");
	fflush(tc);

	if( fgetsByLine(AVStr(req),sizeof(req),fc,10*1000,&rcc,&bcc) == NULL ){
		return -1;
	}
	if( strtailchr(req) != '\n' ){
		sv1log("--insMux SV bad req len=%d bin=%d [%s]\n",
			rcc,bcc,req);
		return -1;
	}
	Xsscanf(req,"%s %s %s",AVStr(ymethod),AVStr(xcom),AVStr(hver));
	av[ac++] = xcom;
	scanYYrequest(Mc,elnumof(av),av,ac,fc);
	if( MxRsmstate == CST_RESUME ){
		sv1log("--RSM in insMux START [%s]\n",req);
		yyMUXproxy(Mc,Conn,fc,tc,ymethod,xcom,ac,av);
		sv1log("--RSM in insMux END\n");
		return -1;
	}

	if( MxFlagsWITH_HTT ){
		/* YYHTTP=127.0.0.1:6080 */
		int port = 6080;
		svsock = createRserv("YYHTTP",port,AVStr(servenv));
		if( 0 <= svsock ){
			MxHttpSock = svsock;
			YYpushenv(Mc,servenv);
		}
	}
	if( MxFlagsWITH_FTP ){
		/* YYFTP=127.0.0.1:6021 */
		int port = 6021;
		svsock = createRserv("YYFTP",port,AVStr(servenv));
		if( 0 <= svsock ){
			MxFtpSock = svsock;
			YYpushenv(Mc,servenv);
		}
	}
	if( MxFlagsWITH_Y11 ){
		int yport = 6001;
		xcsock = createYdisp(AVStr(xchost),&yport,AVStr(dispenv));
		if( xcsock < 0 ){
			sv1log("----Y11 could not bind\n");
			fprintf(tc,"HTTP/1.0 500 could not bind\r\n");
			fprintf(tc,"\r\n");
			return -1;
		}
	}

	lfprintf("svResp",tc,"HTTP/1.1 200 OK");
	lfprintf("svResp",tc,"Y-Version: %s",myYYVER);
	lfprintf("svResp",tc,"Y-Server: origin=y11");
	if( MxFlagsPERSIST ){
		MxRsmkey ^= trand1(0xFFFFFFFF);
		setupRSMport(Mc,xcom); /* to be closed in the child */
		putYConnection("svResp",0,Mc,tc);
	}
	if( MxFlagsWITH_Y11 ){
		ep = getenv("DISPLAY");
		lfprintf("svResp",tc,"X-DISPLAY-1: %s",ep?ep:"");
		YYpushenv(Mc,dispenv);
		disp = getenv("DISPLAY");
		sv1log("--Y11 DISPLAY=%s\n",disp?disp:"");
		ep = getenv("DISPLAY");
		lfprintf("svResp",tc,"X-DISPLAY-2: %s",ep?ep:"");
	}
	lfprintf("svResp",tc,"");
	fflush(tc);
	if( 0 < ready_cc(fc) ){
		sv1log("----FATAL buffered data in fc\n");
	}

	Socketpair(yyx);
	if( dodup ){
		osock = dup(clsock);
		nsock = clsock;
		dup2(yyx[1],clsock);
		close(yyx[1]);
	}else{
		osock = clsock;
		nsock = yyx[1];
	}
	tid = thread_fork(0x80000,0,"insMuxSV",(IFUNCP)relayYMS,Mc,osock,yyx[0],yyx[1],xcsock,xcom);
	setthreadgid(tid,getthreadgid(0));
	MxTidyyx = tid;
	return nsock;
}

/*
 * -Fy11 host[:port] [-options] [remote-command args] [: local-command args]
 * proxying: -Fy11 proxy[:port]//host[:port] ...
 */
static void putHelp(int ac,const char *av[]){
printf(": ////////////////////////////// 2010/01/24 Y.Sato @ @ AIST.Gov.Japan\r\n");
printf(":  X proxy on the top of the Y11 protocol         ( - ) {%s} \r\n",myYY11VER);
printf(":  Usage:                                        _<   >_\r\n");
printf(":    server                                             \r\n");
printf(":      serv%% delegated -P6010 SERVER=y11               \r\n");
printf(":    proxy\r\n");
printf(":      prox%% delegated -P6010 SERVER=y11 RELAY=y11\r\n");
printf(":    client\r\n");
printf(":      clnt%% delegated -Fy11 serv [remote-command] [: local-command]\r\n");
printf(":    client via proxy\r\n");
printf(":      clnt%% delegated -Fy11 prox//serv [remote-command] [: local-command]\r\n");
printf(":  Note:\r\n");
printf(":    remote-command is executed at serv and displayed on the X server at clnt\r\n");
printf(":    local-command is executed at clnt and displayed on the X server at serv\r\n");
printf(":    generic proxy as SOCKS or SSLTUNNEL can be used to reach a Y11 server\r\n");
printf(":    add -fv option before the -Fy11 option to peep the activity of Y11\r\n");
printf(":  Example:\r\n");
printf(":    clnt%% delegated -Fy11 serv xterm\r\n");
printf(":    clnt%% delegated -Fy11 serv : /usr/X11R6/bin/xeyes\r\n");
printf(":    clnt%% delegated -Fy11 serv xterm -bg red : xlogo -fg blue\r\n");
printf(": ///////////////////////////////////////////////////////////////////\r\n");
}

#define Rav RLav[0]
#define Rac RLac[0]
#define Lav RLav[1]
#define Lac RLac[1]

static void file2sock(FILE *in,int sock){
	int ch;
	IStr(buf,PBSIZE);
	int rcc;

	for(;;){
		ch = getc(in);
		if( ch == EOF ){
			break;
		}
		setVStrElem(buf,0,ch);
		rcc = 1 + fgetBuffered(DVStr(buf,1),sizeof(buf)-1,in);
		if( write(sock,buf,rcc) <= 0 ){
			break;
		}
	}
}
static void sock2file(FILE *out,int sock){
	IStr(buf,PBSIZE);
	int rcc;
	for(;;){
		rcc = read(sock,buf,sizeof(buf));
		if( rcc <= 0 ){
			break;
		}
		fwrite(buf,1,rcc,out);
		fflush(out);
	}
}
static int openAppAcc(MuxCtx *Mc,PCStr(wh),PortMap1 *Pm,int pbase,int *rsock,int *rport){
	IStr(host,128);
	int port;
	int sock;
	int vx;
	int listen = 15;

	if( 0 < MxSOListen )
		listen = MxSOListen;

	if( Pm->pm_local.p1_host[0] ){
		strcpy(host,Pm->pm_local.p1_host);
	}else{
		strcpy(host,"127.0.0.1");
	}
	port = pbase;
	for( vx = 0; vx < 10; vx++ ){
		if( Pm->pm_local.p1_flags & P1_UDP ){
			sock = server_open(wh,AVStr(host),port+vx,-1);
		}else{
			/*
			sock = server_open(wh,AVStr(host),port+vx,1);
			*/
			sock = server_open(wh,AVStr(host),port+vx,listen);
			/* the LISTEN value should be large for HTTP */
		}
		if( 0 <= sock ){
			*rport = port+vx;
			*rsock = sock;
			return 1;
		}
		if( MxFlagsISILENT == 0 )
		fprintf(stderr,"==== %s [%d]%d e%d (FAILED TO BIND)\r\n",wh,
			sock,port,errno);
	}
	return -1;
}
static void relayYMC(MuxCtx *Mc,int xcsock,int svsock,int yyx0,int yyx1,int tgid){
	Connection *Conn = MxConn;

	setthreadgid(0,tgid);
	sv1log("--YMUX-%d relayYMC sv[%d] cl[%d]\n",MxId,svsock,yyx0);
	FD_new(svsock,"ViaYY-SV",0);
	FD_new(yyx0,"ViaYY-CL",0);

	if( MxFlagsVERBOSE ){
		MxDebug = 10;
	}
	MxPid = -1;
	MxPalive = 0;

	if( MxFlagsWITH_VNC ){
		if( MxVncPort == 0 ) MxVncPort = 15900;
		openAppAcc(Mc,"VNC",&MxPmapVnc,MxVncPort,&MxVncSock,&MxVncPort);
	}
	if( MxFlagsWITH_DNS ){
		if( MxDnsPort == 0 ) MxDnsPort = 10053;
		if( (MxPmapDns.pm_local.p1_flags & P1_TCP) == 0 ){
			MxPmapDns.pm_local.p1_flags |= P1_UDP;
		}
		openAppAcc(Mc,"DNS",&MxPmapDns,MxDnsPort,&MxDnsSock,&MxDnsPort);
	}
	if( MxFlagsWITH_FTP ){
		if( MxFtpPort == 0 ) MxFtpPort = 10021;
		openAppAcc(Mc,"FTP",&MxPmapFtp,MxFtpPort,&MxFtpSock,&MxFtpPort);
	}
	if( MxFlagsWITH_POP ){
		if( MxPopPort == 0 ) MxPopPort = 10110;
		openAppAcc(Mc,"POP",&MxPmapPop,MxPopPort,&MxPopSock,&MxPopPort);
	}
	if( MxFlagsWITH_SMT ){
		if( MxSmtpPort == 0 ) MxSmtpPort = 10025;
		openAppAcc(Mc,"SMTP",&MxPmapSmtp,MxSmtpPort,&MxSmtpSock,&MxSmtpPort);
	}
	if( MxFlagsWITH_HTT ){
		if( MxHttpPort == 0 ) MxHttpPort = 10080;
		openAppAcc(Mc,"HTTP",&MxPmapHttp,MxHttpPort,&MxHttpSock,&MxHttpPort);
	}
	if( MxFlagsWITH_SOC ){
		if( MxSocksPort == 0 ) MxSocksPort = 11080;
		openAppAcc(Mc,"SOCKS",&MxPmapSocks,MxSocksPort,&MxSocksSock,&MxSocksPort);
	}
	yyMUXrelay(Mc,xcsock,svsock,svsock,MUX_ON,yyx0,yyx0,MUX_OFF,0);
	/* yyMUXrelay() should exit on the reset of ClientSock */

	if( MxYsock == svsock && MxYport == sockPort(svsock) ){
		FD_closeX(FL_ARG,Mc,MxCv,MxCn,svsock,"relayYMC-END",1);
		sv1log("----Y%d FATAL end [%d][%d] P%d/%d\n",MxId,svsock,
			MxYsock,sockPort(svsock),MxYport);
	}

	clearthreadsig(getthreadid(),1); /* to suppress log */
	sv1log("--Y%d/%d relayYMC end, alv=%d (shut=%d sent=%d port=%d key=%u)\n",
		MxId,MxParentId,
		IsAlive(yyx0),MxShutting,MxSHUTsent,MxRsmport,MxRsmkey);
	if( MxShutting & YS_REMOTE ){
		/* if YYMUX finished normally with remote SHUT */
		salvageClnt(Mc,CST_CLEARED,MxRsmport,MxRsmkey);
	}
	MxStatZOMBI = 1;
}
int insertMuxCL(MuxCtx *Mc,Connection *Conn,int xcsock,int svsock,FILE *ts,FILE *fs,int dodup,int doauth){
	int rcode;
	int yyx[2];
	int tid;
	int close_ts = 0;
	int osock;
	int nsock;

	if( ts == 0  ){
		close_ts = 1;
		ts = fdopen(svsock,"w");
		if( ts == NULL ){
			sv1log("##Y%d FATAL insertMuxCL failure[%d] e%d\n",MxId,svsock,errno);
			return -1;
		}
		fs = fdopen(svsock,"r");
setbuffer(fs,0,0); /* yymux-client */
	}
	if( MxFlagsIDEBUG ){
		IStr(host,64);
		IStr(peer,64);
		IStr(msg,128);
		getpairName(svsock,AVStr(host),AVStr(peer));
		sprintf(msg,"YYMUX [%s:%d] <= [%s]",MxServ,MxServport,peer);
		YYlogComm(Mc,"====","YYMUX",msg);
	}
	rcode = scanYYresponse("insMuxCL",Mc,fs,0);
	if( rcode < 0 ){
		if( close_ts ){
			fcloseFILE(ts);
			fcloseFILE(fs);
		}
		return -3;
	}

	sprintf(MxDstUrl,"%s://%s:%d/-",DST_PROTO,DST_HOST,DST_PORT);
	strcpy(MxDstProto,DST_PROTO);
	strcpy(MxDstHost,DST_HOST);
	MxDstPort = DST_PORT;

	YYlfprintf(Mc,"insMuxCL",ts,"%s %s HTTP/1.1",YY_CON,MxDstUrl);
	YYlfprintf(Mc,"insMuxCL",ts,"Y-Version: %s",myYYVER);
	if( doauth ){
		generateCredhyKey(Mc,ts,"insMuxCL",0);
		if( genAutho(Mc) ){
			putAutho("insMuxCL",Mc,ts);
		}
	}
	if( streq(DST_PROTO,"yysh") ){
		MxMaxPending = 128*1024;
		lfprintf("insMuxCL",ts,"Y-Max-Pending: %d",MxMaxPending);
	}
	putYConnection("insMuxCL",1,Mc,ts);
	if( MxClntHOLDONNX ){
		YYlfprintf(Mc,"insMuxCL",ts,"Y-HOLDONNX: %d",MxClntHOLDONNX);
	}
	YYlfprintf(Mc,"insMuxCL",ts,"");
	fflush(ts);

	rcode = scanYYresponse("insMuxCL",Mc,fs,1);
	if( close_ts ){
		fcloseFILE(ts); ts = 0;
		fcloseFILE(fs); fs = 0;
	}
	if( rcode != 0 ){
		return -2;
	}
	Socketpair(yyx);
	if( dodup ){
		osock = dup(svsock);
		nsock = svsock;
		dup2(yyx[1],svsock);
		close(yyx[1]);
	}else{
		osock = svsock;
		nsock = yyx[1];
	}
	tid = thread_fork(0x80000,0,"insMuxCL",(IFUNCP)relayYMC,Mc,xcsock,osock,yyx[0],yyx[1],getthreadgid(0));
	MxTidyyx = tid;
	return nsock;
}

Connection *SessionConn();
extern int BREAK_STICKY;
int isSockOfServ(Connection *Conn,int fd);
void finishClntYY(FL_PAR,Connection *Conn){
	int rdy;
	double St = Time();

	if( (ClientFlags & PF_WITH_YYMUX) == 0 ){
		return;
	}
	shutdownWR(ToC);
	rdy = PollIn(FromS,1000);
	sv1log("--finishClntYY Y%d %X [%d][%d](%.3f) <= %s:%d\n",
		STX_yy,ClientFlags&PF_WITH_YYMUX,
		ClientSockX,ToC,
		Time()-St,FL_BAR);
	CTX_endYY(Conn);
}
int CTX_withYY_SV(Connection *Conn);
int YYfinishSV(FL_PAR,Connection *Conn){
	double St;

	if( ConnType != 'y' && !CTX_withYY_SV(Conn) ){
		return 0;
	}
	sv1log("----YYfinishSV-A %s:%d (%s:%d) [%d]%d Y%d[%c]%d\n",
		FL_BAR,DST_HOST,DST_PORT,
		ServerSockX,IsAlive(ServerSockX),
		STX_yy,ConnType?ConnType:' ',CTX_withYY_SV(Conn));
	St = Time();
	finishServYY(FL_BAR,Conn);
	sv1log("----YYfinishSV-B %s:%d (%s:%d)(%.3f) [%d]%d Y%d[%c]%d\n",
		FL_BAR,DST_HOST,DST_PORT,Time()-St,
		ServerSockX,IsAlive(ServerSockX),
		STX_yy,ConnType?ConnType:' ',CTX_withYY_SV(Conn));
	return 1;
}
void finishServYY(FL_PAR,Connection *Conn){
	double St = Time();
	int issvsock = -1;
	int rdy;

	if( Conn == 0 ){
		Conn = SessionConn();
	}
	if( Conn == 0 ){
		Conn = MainConn();
	}
	if( owningYY(Conn) == 0 ){
		return;
	}
	if( STX_yy == 0 ){
		return;
	}
	if( ToS < 0 || FromS < 0 ){
		return;
	}

	if( GatewayFlags & GW_IS_YYSHD ){
		/* keep YYMUX alive to be reused by YCNCTs */
		/* this can be called multiple times for each server
		 * disconnection during a single client session with
		 * a connection in keep-alive.
		 */
		sv1log("----SELFEND Y%d YYSHD=%X YYSHD_YYM=%X\n",STX_yy,
		GatewayFlags & GW_IS_YYSHD,GatewayFlags & GW_IS_YYSHD_YYM);
		//setselfendYY(Conn,"finishServYY");
		return;
	}

	/*
	if( ConnType != 'y' )
		return;
	*/
	if( ServerSock < 0 || (issvsock = isSockOfServ(Conn,ServerSock)) ){
		/* HTTP keep alive ? */
		sv1log("--finYY Y%d sv[%d]%d [%d][%d]%s <= %s:%d\n",
			STX_yy,ServerSock,issvsock,
			ToS,FromS,DST_PROTO,FL_BAR);
		return;
	}
	sv1log("##finYY Y%d %s:%d SIG=%d sv[%d]%d [%d][%d] [%d][%d] {%c}A%d e%d\n",
		STX_yy,FL_BAR,yy_gotSIG,
		ServerSock,issvsock,FromS,ToS,ToSX,ToSF,
		ConnType?ConnType:' ',IsAlive(ServerSock),errno);
	if( !IsAlive(ToS) ){
		msleep(100);
	}
	shutdownWR(ToS);
	rdy = PollIn(FromS,1000);
	sv1log("##finYY Y%d [%d][%d] {%c}A%d rdy=%d (%.2f)\n",
		STX_yy,ToS,ServerSock,
		ConnType?ConnType:' ',IsAlive(ServerSock),
		rdy,Time()-St);

	if( yy_gotSIG ){
		BREAK_STICKY = 1;
	}
	CTX_endYY(Conn);
	CTX_sweepYY(Conn);
}
int pollYY(Connection *Conn,PCStr(wh),FILE *fc){
	if( ConnType == 'y' ){
		int rdy;
		rdy = fPollIn(fc,0);
		if( rdy <= 0 && errno == EINTR ){
			/* 9.9.7 POP via YY, SIGTERM ignored */
			sv1log("##YY %s e=%d rdy=%d\n",wh,errno,rdy);
			finishServYY(FL_ARG,Conn);
			return 1;
		}
	}
	return 0;
}
int connectViaSocks(DGC*Conn,PCStr(dsthost),int dstport,PVStr(rhost),int *rport);
extern int CON_TIMEOUT;
int OpenServerVia(Connection *Conn,PCStr(what),PCStr(proto),PCStr(yhost),int yport){
	int sock = -1;
	IStr(rhost,MaxHostNameLen);
	int rport = 0;
	int viasocks = 0;
	int cto = CON_TIMEOUT;

	if( viasocks = GetViaSocks(Conn,yhost,yport) ){
		sv1log("--yymux %s:%d to %s:%d via SOCKS...\n\n",yhost,yport,
			DST_HOST,DST_PORT);
		sock = connectViaSocks(Conn,yhost,yport,AVStr(rhost),&rport);
		sv1log("--yymux connected via SOCKS[%d] %s:%d\n",sock,
			rhost,rport);
		if( 0 <= sock ){
			return sock;
		}
		cto = CON_TIMEOUT;
		CON_TIMEOUT = 1;
	}
	sock = OpenServer(what,proto,yhost,yport);
	if( viasocks ){
		CON_TIMEOUT = cto;
		sv1log("--yymux direct[%d] after SOCKS failure\n",sock);
	}
	return sock;
}
static int isViaYYMUXX(Connection *Conn,MuxCtx *cMc,int fd,PCStr(proto),PCStr(host),int port,MuxCtx **rMc){
	MuxCtx *Mc;
	int mi;
	IStr(yhost,MaxHostNameLen);
	int yport;
	int viaYY = 0;
	int nviaYY = 0;

	if( yy_withYYMUX == 0 && yy_gMc == 0 ){
		/* 9.9.8 suppress YYMUX setup/logging for ftp-data */
		return 0;
	}
	if( cMc == 0 ){
		cMc = initgMc(Conn);
	}
	if( viaYY = find_YYMUXX(Conn,cMc,proto,host,port,AVStr(yhost),&yport) ){
		for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
			if( Mc = yy_Mcv[mi] )
			if( MxYYport == yport )
			if( hostcmp(MxYYhost,yhost) == 0 )
			if( MxStatENDING ){
				Verbose("--isViaYY%d ENDING-A FATAL\n",MxId);
			}else
			{
				nviaYY++;
			}
		}
		sv1log("--isViaYY %s:%d %s:%s:%d YY/%d\n",yhost,yport,proto,host,port,nviaYY);
	}else{
		sv1log("--Not isViaYY %s:%s:%d\n",proto,host,port);
	}
	for( mi = 0; mi < elnumof(yy_Mcv); mi++ ){
		if( Mc = yy_Mcv[mi] )
		if( MxYYport == yport )
		if( hostcmp(MxYYhost,yhost) == 0 )
		if( MxStatENDING ){
			sv1log("--isViaYY%d ENDING-B FATAL\n",MxId);
			endYY(Conn,Mc);
		}else
		if( YYMUXnotfull(cMc,Mc,nviaYY) )
		/*
		if( MxDstPort )
		if( hostcmp(host,MxDstHost) == 0 )
		*/
		{

 sv1log("--isViaYYMUX Y%d >> Y%d (%s:%d)(%s:%d)(%s:%d) St=%.3f %.3f\n",
	cMc->mc_id,MxId,MxDstHost,MxDstPort,host,port,yhost,yport,MxMuxStart,MxMuxDone);
 sv1log("--isViaYYMUX Y%d >> Y%d [%d] SV[%d][%c] shut=%X Z%d RSM=%X/%X\n",
	cMc->mc_id,MxId,fd,ServerSockX,ConnType?ConnType:' ',
	MxShutting,MxStatZOMBI,MxResuming,MxInRESUME);

			if( MxMuxStart == 0 ){
				continue;
			}
			if( MxShutting ){
				endYY(Conn,Mc);
				continue;
			}
			if( MxStatZOMBI ){
				endYY(Conn,Mc);
				continue;
			}
			if( MxResuming || MxInRESUME ){
				continue;
			}
			*rMc = Mc;
strcpy(MxDstProto,proto);
strcpy(MxDstHost,host);
MxDstPort = port;
			return 1;
		}
	}

	if( ConnType == 'y' && fd == ServerSockX ){
		sv1log("##isViaYYMUX [%d] SV[%d][%c]\n",
			fd,ServerSockX,ConnType?ConnType:' ');
		*rMc = 0;
		return 1;
	}
	return 0;
}
int isViaYYMUX(Connection *Conn,int fd,PCStr(proto),PCStr(host),int port){
	MuxCtx *rMc;
	return isViaYYMUXX(Conn,0,fd,proto,host,port,&rMc);
}
int ConnectViaYYMUXX(Connection *Conn,void *cty,int relay_input,PCStr(yyhost),int yyport);
int ConnectViaYYMUX(Connection *Conn,void *cty,int relay_input){
	IStr(yyhost,MaxHostNameLen);
	int yyport;
	int sock;

	if( find_YYMUX(Conn,cty,AVStr(yyhost),&yyport) == 0 ){
		return -1;
	}
	sock = ConnectViaYYMUXX(Conn,cty,relay_input,yyhost,yyport);
	return sock;
}
static int ConnectOverYYMUXX(FL_PAR,MuxCtx *Mc,Connection *Conn,PCStr(proto),PCStr(host),int port){
	int skp[2];
	IStr(dst,512);
	IStr(src,512);
	IStr(dstsrc,512);
	Cony *C1,*C2;
	int xsid;
	double St = Time();
	int mxId = 0;

	if( Mc == 0 ){
		sv1log("--COY FATAL Mc=NULL %s://%s:%d <= %s:%d\n",proto,host,port,FL_BAR);
		return -1;
	}
	mxId = MxId;
	if( MxShutting ){
		/* MxParent must be cleared when the outer exits */
		sv1log("--Y%d ConOverYY shut=%d [%c][%s:%s:%d] <= %s:%d\n",MxId,
			MxShutting,ConnType?ConnType:' ',
			proto,host,port,FL_BAR);
		return -1;
	}
	if( MxCn <= 0 ){
		sv1log("----Y%d/%X FATAL xsid=%d cv=%X cn=%d shut=%X Z=%d\n",
			MxId,Mc,MxXsid,p2i(MxCv),MxCn,MxShutting,MxStatZOMBI);
		return -1;
	}
	if( MxResuming || MxInRESUME ){
		int wi;
		for( wi = 0; wi < 60; wi++ ){
 yprintf(Mc,"---- waiting ongoing resume in outer YYMUX ... (%d %.2f) Y%d (%d)",
 wi,Time()-St,mxId,isAliveY(mxId));
			if( !isAliveY(mxId) ){
				break;
			}
 yprintf(Mc,"---- waiting ongoing resume in outer YYMUX ... (%d %.2f) %X",
 wi,Time()-St,MxInRESUME);
			if( MxId != mxId ){
sv1log("--Y%d <- Y%d COY YYMUX recycled (%X:%d <- %X:%d) ####FATAL\n",
MxId,mxId,MxDstHost,MxDstPort,host,port);
sv1log("--Y%d <- Y%d COY YYMUX recycled (%s:%d <- %s:%d) ####FATAL\n",
MxId,mxId,MxDstHost,MxDstPort,host,port);
				return -1;
			}
			if( MxResuming == 0 && MxInRESUME == 0 ){
				break;
			}
			sleep(1);
		}
	}
	if( isAliveY(mxId) == 0 ){
sv1log("####Y%d FATAL Mc=%X gone A\n",mxId,Mc);
		return -1;
	}

	Socketpair(skp);

if( isAliveY(mxId) == 0 ){
sv1log("####Y%d FATAL Mc=%X gone B\n",mxId,Mc);
	close(skp[0]);
	close(skp[1]);
	return -1;
}
	xsid = MxXsid;
	nextXsid(Mc,MxCv,MxCn);
	C1 = addCony(MxCv,MxCn,xsid,CY_XIN,ET_CLNT,skp[0]);
	if( C1 == NULL ){
		sv1log("----Y%d/%X FATAL xsid=%d/%d cv=%X cn=%d skp[%d] shut=%X Z=%d\n",
			MxId,Mc,xsid,MxXsid,p2i(MxCv),MxCn,skp[0],MxShutting,MxStatZOMBI);
		close(skp[0]);
		close(skp[1]);
		return -1;
	}
	FD_new(skp[0],"ConnOverYY-YY",FD_IGNOWNER);
	C2 = addCony(MxCv,MxCn,xsid,CY_XOUT,ET_CLNT,skp[0]);
	if( streq(DST_PROTO,"ftp-data") ){
		C1->c_cflag |= CF_GETABORT;
		C2->c_cflag |= CF_GETABORT;
	}
	sv1log("--Y%d COY #%d %X %s sub[%d %d] (%s)\n",MxId,
		C1->c_xsid,C1->c_cflag,proto,
		skp[0],skp[1],src);
	sprintf(dst,"%s://%s:%d",proto,host,port);
	putDstsrc(Mc,AVStr(dstsrc),dst,src,xsid);
	if( sendCONN(Mc,xsid,dstsrc) < 0 ){
		if( isAliveY(mxId) == 0 ){
 yprintf(Mc,"---- [%X] RSM COY ---- FATAL #### Y%d Mc=%X gone C",TID,mxId,Mc);
		}else{
 yprintf(Mc,"---- [%X] RSM COY ---- FATAL #### Y%d %s:%d",TID,mxId,MxDstHost,MxDstPort);
		}
		close(skp[1]);
		return -1;
	}
	MxDoupdate = "ConnOverYY";
	return skp[1];
}
static int ConnectOverYYMUX(FL_PAR,MuxCtx *Mc,Connection *Conn){
	int sock;
	sock = ConnectOverYYMUXX(FL_BAR,Mc,Conn,DST_PROTO,DST_HOST,DST_PORT);
	return sock;
}
static int ConnectViaYYMUXXX(Connection *Conn,void *cty,MuxCtx **rrMc,int relay_input,PCStr(yyhost),int yyport);
int ConnectViaYYMUXX(Connection *Conn,void *cty,int relay_input,PCStr(yyhost),int yyport){
	return ConnectViaYYMUXXX(Conn,cty,NULL,relay_input,yyhost,yyport);
}
static int ConnectViaYYMUXXX(Connection *Conn,void *cty,MuxCtx **rrMc,int relay_input,PCStr(yyhost),int yyport){
	int yysock;
	int svsock;
	MuxCtx *Mc = 0;
	int mxid = 0;
	int mxpid = 0;
	int inRESUME = 0;
	int ygid = -1;
	MuxCtx *lMc = 0;

	if( GatewayFlags & GW_IS_YYSHD ){
	    if( cty == 0 && ConnType != 'y' ){
		MuxCtx *rMc = 0;
		if( isViaYYMUXX(Conn,0,-1,DST_PROTO,DST_HOST,DST_PORT,&rMc) ){
			yysock = ConnectOverYYMUX(FL_ARG,rMc,Conn);
			if( 0 <= yysock ){
				initConnected(Conn,yysock,relay_input);
				svlog("--YYSHD over Y%d [%d]\n",rMc->mc_id,yysock);
				if( rrMc ){ *rrMc = rMc; }
{
MuxCtx *Mc = rMc;
sv1log("----COY Y%d yy=%d ---XXXX MX=%X SELFEND=%d\n",MxId,STX_yy,Mc,MxStatSELFEND);
}
				return yysock;
			}
		}
	    }
	}
	if( cty ){
		MuxCtx *Mc = (MuxCtx*)cty;

		mxid = MxId;
		inRESUME = MxInRESUME;
		/*
		MuxCtx *Mcc;
		Mcc = findYY(Conn,DST_PROTO,DST_HOST,DST_PORT);
		*/
		if( MxParent ){ /* && SUBYYMUX && Mcc==MxParent */
			mxpid = MxParent->mc_id;
			svsock = ConnectOverYYMUX(FL_ARG,MxParent,Conn);
 zprintf(Mc,"--- COY [%d] via (%s:%d) >>> %s://%s:%d\n",
 svsock,yyhost,yyport,DST_PROTO,DST_HOST,DST_PORT);
			if( 0 <= svsock ){
				if( rrMc ){ *rrMc = Mc; }
				return svsock;
			}
 yprintf(Mc,"---- connect COY ERROR [%d] ####",svsock);
			return -1;
		}
	}
	if( ConnType == 'y' ){
		/* may happen on server switch in FTP,POP,... */
		/* or it can be ftp-data conection */
		if( streq(DST_PROTO,"ftp-data") ){
			/* if the destination is the same with the current
			 * control connection in YYMUX to the server (PASV)
			 * or YYMUX to the client (PORT)
			 */
			Mc = findYY(Conn,DST_PROTO,DST_HOST,DST_PORT);
			if( Mc ){
				sv1log("----yyFTP %s://%s:%d ==>> $%X %s://%s:%d\n",
					DST_PROTO,DST_HOST,DST_PORT,MxId,
					MxDstProto,MxDstHost,MxDstPort
				);
				svsock = ConnectOverYYMUX(FL_ARG,Mc,Conn);
				if( rrMc ){ *rrMc = Mc; }
				return svsock;
			}
		}
		sv1log("#### cleared ConnType=y, yy#%d cf=%X [%s]\n",
			STX_yy,ConnectFlags,DST_PROTO);
		if( streq(DST_PROTO,"ftp-data") ){
			CTX_setSweep(Conn);
		}
		clearSTLSX(Conn,XF_FSV);
		ConnType = 0;
	}

	sv1log("--Y%d/%d %X yyMUX conn-A .... via (%s:%d) >>> %s://%s:%d cof=%X\n",
		mxid,mxpid,p2i(cty),yyhost,yyport,
		DST_PROTO,DST_HOST,DST_PORT,ConnectFlags);
	svsock = OpenServerVia(Conn,"YYMUX","yymux",yyhost,yyport);
	sv1log("--Y%d/%d %X yyMUX conn-B [%d] via (%s:%d) >>> %s://%s:%d cof=%X\n",
		mxid,mxpid,p2i(cty),svsock,yyhost,yyport,
		DST_PROTO,DST_HOST,DST_PORT,ConnectFlags);

	if( svsock < 0 ){
		return svsock;
	}
	if( cty && inRESUME ){
		/* this must not happen ? */
		sv1log("--Y%d/%d %X FATAL ConnectViaYY in RSM [%c] COF=%X\n",
			mxid,mxpid,p2i(cty),ConnType?ConnType:' ',
			ConnectFlags&COF_RESUMING);
		if( rrMc ){ *rrMc = 0; }
		return svsock;
	}

	YYMUX_STARTTLS_withSV(Mc,Conn,"yymux",svsock,"ViaYYMUX");

	if( cty ){
		lMc = (MuxCtx*)cty;
	}else{
		lMc = getThreadMc();
	}
	if( lMc ){
		ygid = lMc->mc_ygid;
	}

	Mc = newYY(Conn,ET_CLNT);
sv1log("---Ba----Mc=%X Y%d newY%d ygid=%d GID=%X\n",lMc,lMc?lMc->mc_id:-1,MxId,ygid,getthreadgid(0));
	MxFlags ^= MX_SHUTIMM;
	MxRsmkey ^= trand1(0xFFFFFFFF);
	strcpy(MxServ,DST_HOST);
	MxServport = DST_PORT;
	saveYYserver(Mc,"yymux",yyhost,yyport);

	if( lMc != 0 && 0 < lMc->mc_ClntHOLDONNX ){
		MxClntHOLDONNX = lMc->mc_ClntHOLDONNX;
	}
	if( MxClntHOLDONNX == 0 && (GatewayFlags & GW_IS_YYSHD) ){
		MxClntHOLDONNX = 30;
	}
	if( GatewayFlags & GW_IS_YYSHD ){
		GatewayFlags |= GW_IS_YYSHD_YYM;
		/* the YYMUX will be left alive by finishServYY on the
		 * exit of owner app. (HttpServer), and it need to be
		 * freed by self on its exit.
		 */
sv1log("----1---CVY %d ---XXXX MX=%X SELFEND=%d yy=%d\n",MxId,Mc,MxStatSELFEND,STX_yy);
		MxStatSELFEND = 1;
sv1log("----2---CVY %d ---XXXX MX=%X SELFEND=%d\n",MxId,Mc,MxStatSELFEND);
sv1log("XXXX-XXXX XXXX XXXX HTTP/YYSH YY%d ConnVia MX=%X\n",MxId,MxFlags);
//STX_yy = 0; /* to be independent of the Conn */
	}

	yysock = insertMuxCL(Mc,Conn,-1,svsock,NULL,NULL,0,1);

	Mc->mc_ygid = ygid;
	Mc->mc_ytgid = getthreadgid(0);
sv1log("---Bb----Y%d ygid=%d GID=%X\n",MxId,ygid,getthreadgid(0));
	if( MxFlagsVERBOSE ){
		dumpFds(curLogFp());
	}
	if( yysock < 0 ){
		sv1log("--Y%d FATAL ConnVia failure: [%d][%d %d %d] GF=%X %s://%s:%d\n",
			MxId,svsock,ToS,FromS,ServerSock,GatewayFlags,
			MxDstProto,MxDstHost,MxDstPort);
		close(svsock);
		if( GatewayFlags & GW_IS_YYSHD ){
			/* finishServYY() will return without endYY() */
			endYY(Conn,Mc);
		}
		finishServYY(FL_ARG,Conn);
		return -2;
	}
	sv1log("--Y%d %X ConnVia: RELAY START [%d][%d]\n",MxId,Mc,svsock,yysock);

	if( streq(DST_PROTO,"ftp-data") ){
		/* ConnType is not set for "ftp-data" by connect_ftp_data()
		 * Both ConnType='y' + ServerSockX are required by ServSock()
		 * ServerSockX must be kept the control-conn. to the FTP serv.
		 */
		if( 0 <= yysock ){
			ConnType = 'y';
		}
	}else{
		initConnected(Conn,yysock,relay_input); /* ToS,FromS,ServerSock,ServerSockX */
		/* socket to YYMUX server owned by sub-thread (relayYMC) */
		/* to be closed as ViaYY-SV at the exit of it, */
		/* not to be read/written/closed by th main-thread, but */
		/* necessary to get real socknaem/peername */
		/* as ToSX/ServSock() in FTP, but ToSX has a side effect */
		/* to be auto. closed thus is NG for RSM */
		ServerSockX = svsock;
	}
	if( rrMc ){ *rrMc = Mc; }
	return yysock;
}

int Y11_main1(int ac,const char *av[],Connection *Conn,int etype);
int Y11_main(int ac,const char *av[],Connection *Conn){
	return Y11_main1(ac,av,Conn,ET_CLNT);
}
int yymux_main(int ac,const char *av[],Connection *Conn){
	return Y11_main1(ac,av,Conn,ET_CLNT|ET_NOX);
}

int yy_Y11_main1(MuxCtx *Mc,int ac,const char *av[],Connection *Conn,int etype);
int Y11_main1(int ac,const char *av[],Connection *Conn,int etype){
	int rcode;
	MuxCtx *Mc;

	initgMc(Conn);
	Mc = newYY(Conn,etype);
	if( MxRsmholdSet == 0 ){
		MxRsmhold = 12*60*60;
	}
	MxStart = Time();
	rcode = yy_Y11_main1(Mc,ac,av,Conn,etype);
	endYY(Conn,Mc);
	return rcode;
}
const char *scan_arg1(Connection *Conn,PCStr(ext_base),PCStr(arg));
static int isDGARGS(Connection *Conn,const char *av[],int ai){
	const char *a1;
	a1 = av[ai];

	if( strneq(a1,"FSV=",4)
	 || strneq(a1,"STLS=",5)
	 || strneq(a1,"SOCKS=",6)
	 || strneq(a1,"YYMUX=",6)
	 || strneq(a1,"MYAUTH=",7)
	 || strneq(a1,"MASTER=",7)
	 || strneq(a1,"DGROOT=",7)
	 || strneq(a1,"YYCONF=",7)
	 || strneq(a1,"CONNECT=",8)
	 || strneq(a1,"CHARCODE=",9)
	 || strneq(a1,"SSLTUNNEL=",10)
	){
		return 1;
	}
	return 0;
}
int yy_Y11_main1(MuxCtx *Mc,int ac,const char *av[],Connection *Conn,int etype){
	int xsock = -99;
	int ysock = -99;
	int myopts = 1;
	FILE *ts,*fs;
	IStr(resp,256);
	refQStr(rp,resp);
	const char *RLav[2][64];
	int RLac[2] = {0,0};
	int localcom = 0;
	int ai;
	int console[2];

	const char *a1;
	const char *dp;
	int mc_xsport = 6000; IStr(mc_xshost,MaxHostNameLen); /* local X server */
	int mc_ysport = 6010; IStr(mc_yshost,MaxHostNameLen); /* remote Y server */
	IStr(ysserv,MaxHostNameLen);
	IStr(ysreq,MaxHostNameLen);

	int mc_lcsock;
	IStr(lcenv,128);
	IStr(lcpath,256);
	int ph = 0;

	IStr(statline,256);
	refQStr(sp,statline);

	sv1log("----Y11 ac=%d START\n",ac);
	if( ac <= 1 ){
		putHelp(ac,av);
		return 0;
	}
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( isDGARGS(MxConn,av,ai) ){
			continue;
		}
		if( myopts ){
		  if( *a1 == '-' ){
			switch( a1[1] ){
		    	    case 'X':
				Xsscanf(a1+2,"%[^:]:%d",AVStr(mc_xshost),&mc_xsport);
				break;
			    case 'y':
				MxFlags = scan_yopts(Mc,Conn,MxFlags,a1);
				break;
			}
		  }else{
			myopts = 0;
		  }
		}
		if( myopts == 0 ){
			if( mc_yshost[0] == 0 ){
				Xsscanf(a1,"%[^:]:%d",AVStr(mc_yshost),&mc_ysport);
				if( dp = strstr(a1,"//") ){
					strcpy(ysserv,dp+2);
				}
			}else
			if( strneq(a1,":",1) ){
				if( Rac == 0 ){
					Rav[Rac++] = "=";
				}
				localcom = 1;
			}else{
				if( RLac[localcom] < elnumof(Rav) ){
					int ac = RLac[localcom];
					RLav[localcom][ac] = MxStralloc(Mc,a1);
					RLac[localcom] += 1;
				}
			}
		}
	}
	if( mc_yshost[0] == 0 ){
		strcpy(mc_yshost,"127.0.0.1");
	}

	if( Rac == 0 && Lac == 0 ){
		Rav[Rac++] = MxStralloc(Mc,"xterm");
	}
	if( MxEtype & ET_NOX ){
		Socketpair(console);
		thread_fork(0,0,"ConsoleIn",(IFUNCP)file2sock,stdin,console[1]);
		thread_fork(0,0,"ConsoleOut",(IFUNCP)sock2file,stdout,console[1]);
		xsock = console[0];
	}else
	if( Rac == 0 ){
		/* no remote X command to use the local X server */
		xsock = -1;
	}else{
		/*
		 * file2sock() should be postponed till the XOpenDisplay()
		 * is done, otherwise it might cause blocking at the stdin
		 * to remote X client.
		 */
		Socketpair(console);
		thread_fork(0,0,"ConsoleIn",(IFUNCP)file2sock,stdin,console[1]);
		thread_fork(0,0,"ConsoleOut",(IFUNCP)sock2file,stdout,console[1]);
		MxConsole = console[0];
		FD_new(MxConsole,"ClientConsole",0); /* should be via a pty ? */
		/* console[1] should be closed at end too */

		if( mc_xshost[0] ){
			xsock = connectServer("y11","y11",mc_xshost,mc_xsport);
		}else{
			xsock = connectXlocal("Fy11",0);
		}
		sv1log("----Y11 [%d] %s:%d\n",xsock,mc_xshost,mc_xsport);
		if( xsock < 0 ){
			if( localcom == 0 ){
				return -1;
			}
		}
		if( 0 <= xsock ){
			FD_new(xsock,"clntXserv",0);
		}
	}

	if( MxEtype & ET_NOX ){
		mc_lcsock = -1;
	}else{
		IStr(mc_lchost,128); /* entry point for local X clients */
		int mc_lcport = 6000;
		mc_lcport = 6000;
		mc_lcsock = createYdisp(AVStr(mc_lchost),&mc_lcport,AVStr(lcenv));
		if( 0 <= mc_lcsock ){
			FD_new(mc_lcsock,"clntYdisp",0);
		}
		YYpushenv(Mc,lcenv);
		if( lFG() ){
			fprintf(stderr,"%s\n",lcenv);
		}
	}

	set_realserver(Conn,"y11",mc_yshost,mc_ysport);
	Conn->from_myself = 1;
	ysock = connect_to_serv(Conn,FromC,ToC,0);
	sv1log("--[%d] %s:%d\n",ysock,DST_HOST,DST_PORT);
	if( ysock < 0 ){
		goto EXIT;
	}
	saveYYserver(Mc,DST_PROTO,DST_HOST,DST_PORT);
	FD_new(ysock,"clntFromY",0);
	YYMUX_STARTTLS_withSV(Mc,Conn,"y11",ysock,"-Fy11");

	strcpy(MxServ,DST_HOST);
	MxServport = DST_PORT;

	fs = fdopen(ysock,"r");
setbuffer(fs,0,0); /* yy11-client */
	ts = fdopen(ysock,"w");

	strcpy(MxDstProto,"y11");
	if( ysserv[0] ){
		MxDstPort = 6010;
		Xsscanf(ysserv,"%[^:]:%d",AVStr(MxDstHost),&MxDstPort);
	}else{
		strcpy(MxDstHost,mc_yshost);
		MxDstPort = mc_ysport;
	}
	MxRsmkey ^= trand1(0xFFFFFFFF);

	if( MxCoupler ){
		strcpy(MxDstUrl,"x");
		lfprintf("Sent",ts,"%s x HTTP/1.1",YY_CQ);
		lfprintf("Sent",ts,"Y-Version: %s",myYYVER);
		lfprintf("Sent",ts,"");
		fflush(ts);
		fgets(statline,sizeof(statline),fs);
		sv1log("--YCQ %s",statline);
		while( 1 ){
			if( fgets(resp,sizeof(resp),fs) == NULL ){
				break;
			}
			sv1log("--YCQ %s",resp);
			if( *resp == '\r' || *resp == '\n' ){
				break;
			}
		}
		if( MxCoupler == 's' ){
			FromC = ToC = ysock;
			sv1log("####start servcie: %d %d (rdy=%d)\n",
				FromC,ToC,PollIn(FromC,1000));
			service_Y11a(Conn,-1,0,ET_SERV|ET_REFL);
			return 0;
		}
		MxEtype = ET_CLNT|ET_REFL;
	}

	if( ysserv[0] ){
		sprintf(ysreq,"y11://%s/%s",ysserv,Rav[0]);
	}else{
		sprintf(ysreq,"%s",Rav[0]);
	}
	strcpy(MxDstUrl,ysreq);
	if( etype & ET_NOX ){
		lfprintf("QSent",ts,"%s %s HTTP/1.1",YY_CON,ysreq);
	}else{
		lfprintf("QSent",ts,"%s %s HTTP/1.1",YY_Y11,ysreq);
	}
	if( genAutho(Mc) ){
		putAutho("QSent",Mc,ts);
	}
	lfprintf("QSent",ts,"Y-Version: %s",myYYVER);
	if( MxFlagsPERSIST ){
		putYConnection("QSent",1,Mc,ts);
	}
	for( ai = 1; ai < Rac; ai++ ){
		lfprintf("QSent",ts,"X-Arg: %s",Rav[ai]);
	}
	lfprintf("QSent",ts,"");
	fflush(ts);

	if( scanYYresponse("yyClient",Mc,fs,1) != 0 ){
		goto EXIT;
	}
	if( PollIn(ysock,1) ){
		sv1log("----Y11 fast initiation\n");
	}

	if( 0 < Lac && !streq(Lav[0],"-") ){
		addX11PATH(elnumof(MxEnv),MxEnv,AVStr(MxStrbuf));
		Lav[Lac] = 0;
		MxPid = yybgexec(Mc,Lav[0],(char**)Lav,(char**)environ,&ph);
		MxPhandle = ph;
		MxPalive = 1;
	}else{
		MxPid = -1;
		MxPalive = 0;
	}
	MxYsock = -1;
	yyMUXrelay(Mc,mc_lcsock,ysock,ysock,MUX_ON,xsock,xsock,MUX_OFF,0);
	salvageClnt(Mc,CST_CLEARED,MxRsmport,MxRsmkey);

EXIT:
	sv1log("----Y11 xsock[%d] DONE\n",xsock);
	return 0;
}

/*---------------------------------------------------------------- YYSH ----*/
/*	2010/01/11 created
 *
 *  yysh [NAME=VALUE]* [-opts] [user[:pass]@]host[:[port][.ssl]][/wdir] [-opts] [command]
 *
 */

typedef struct _yyshCtx {
	int	ys_flag;	/* YF */
	double	ys_Tmout;
	int	ys_KAIntvl;	/* new-140626b ping interval for keep-alive */
	MStr(	ys_request,128);
	MStr(	ys_yuid,128);	/* YY-globally unique user-id */
	MStr(	ys_user,128);	/* user at the server-side */
	MStr(	ys_pass,128);
	MStr(	ys_dest,MaxHostNameLen);
	MStr(	ys_host,MaxHostNameLen);
	int	ys_port;	/* 6023 by default */
	MStr(	ys_opts,256);	/* with SSL */
	FILE   *ys_logfp;	/* logfile with MxFlagsLOG_YYSH */

	MStr(	ys_shell,256);	/* /bin/sh or so */
    const char *ys_shav[64];
	MStr(	ys_shab,1024);
    const char *ys_shev[64];
	MStr(	ys_sheb,1024);
	MStr(	ys_SHELL,128);
	MStr(	ys_YYUID,128);
	MStr(	ys_YYGUID,64);

	MStr(	ys_wdir,256);	/* working dir. at the start */
	MStr(	ys_prol,256);	/* preamble, could be auto. login  */
	MStr(	ys_cmdb,1024);	/* command (not login with tty) */
	MStr(	ys_root,256);	/* chroot() */
	MStr(	ys_envs,1024);	/* environ[] at remote */
	MStr(	ys_alias,1024); /* alias at remote */
	MStr(	ys_prompt,128);	/* prompt format at remote */
	int	ys_ccx2cl[16];
	int	ys_ccx2sv[16];
	int	ys_cols;
	int	ys_rows;
	double	ys_Start;
	MStr(	ys_Lfile,128);
	int	ys_Lfmod;
	int	ys_ac;
    const char *ys_av[64];
    Connection *ys_Conn;
	MuxCtx *yx_Mc;
	MStr(	ys_clver,64);
	MStr(	ys_svver,64);
	MStr(	ys_svsoft,64);	/* server-side software */
	MStr(	ys_svdate,64);	/* server-side date */
	MStr(	ys_svhost,64);	/* server-side gethostname() */
	MStr(	ys_svclif,64);	/* server-side client-IF-addr */
	MStr(	ys_svclnt,64);	/* server-side cleint-addr */
	MStr(	ys_svuser,64);	/* server-side user-name */
	MStr(	ys_svwdir,256);	/* server-side working-dir. */
	int	ys_svINTR;      /* ^C by default */
} yyshCtx;

#define YxFlag	Yc->ys_flag
#define YxTmout	Yc->ys_Tmout
#define YxKAIntvl Yc->ys_KAIntvl
#define YxReq	Yc->ys_request
#define YxDest	Yc->ys_dest
#define YxHost	Yc->ys_host
#define YxPort	Yc->ys_port
#define YxUser	Yc->ys_user
#define YxPass	Yc->ys_pass
#define YxOpts	Yc->ys_opts
#define YxLogFp	Yc->ys_logfp

#define YxShell	Yc->ys_shell
#define YxShAv	Yc->ys_shav
#define YxShAb	Yc->ys_shab
#define YxShEv	Yc->ys_shev
#define YxShEb	Yc->ys_sheb
#define YxSHELL	Yc->ys_SHELL
#define YxYYUID	Yc->ys_YYUID
#define YxYYGUID Yc->ys_YYGUID

#define YxWdir	Yc->ys_wdir
#define YxProl	Yc->ys_prol
#define YxCmdb	Yc->ys_cmdb
#define YxEnvs	Yc->ys_cmdb
#define YxConn	Yc->ys_Conn
#define YxMc	Yc->ys_Mc
#define YxCCxCL Yc->ys_ccx2cl
#define YxCCxSV Yc->ys_ccx2sv
#define YxCols	Yc->ys_cols
#define YxRows	Yc->ys_rows
#define YxStart	Yc->ys_Start
#define YxAc	Yc->ys_ac
#define YxAv	Yc->ys_av
#define YxLfile	Yc->ys_Lfile
#define YxLfmod	Yc->ys_Lfmod

#define YxClVer  Yc->ys_clver
#define YxSvVer  Yc->ys_svver
#define YxSvSoft Yc->ys_svsoft
#define YxSvDate Yc->ys_svdate
#define YxSvHost Yc->ys_svhost
#define YxSvClif Yc->ys_svclif
#define YxSvClnt Yc->ys_svclnt
#define YxSvUser Yc->ys_svuser
#define YxSvWdir Yc->ys_svwdir
#define YxSvINTR Yc->ys_svINTR

/* internal status of the YYSH (may be set remotely via symbolic stat. req.) */
enum _YF {
	YF_ALLOC   =	0x0001, /* to be freed */
	YF_HOSTSET =	0x0002, /* YxHost is specified */
	YF_INSHELL =	0x0004, /* with command filtering and aliasing */
	YF_NOTTY   =	0x0008, /* force no tty (pty) at remote */
	YF_SUTTY   =	0x0010, /* force su tty at remote */
	YF_SUACC   =	0x0020, /* force su tty doesn't use socketpair() */
	YF_SUSELF  =    0x0040, /* force su tty don't use annex dgforkpty */
	YF_NOSSOCK =	0x0080, /* don't use socket as stdio for remote com. */
	YF_INFYY   =    0x0100, /* inherit the socket of YYSH to children */
	YF_RDSENT  =	0x0200, /* detailed response is sent */
} YF;

static yyshCtx *newYYSH(yyshCtx *Yc,Connection *Conn){
	BufDesc *Bp;
	if( Yc == 0 ){
		Bp = BUF_get("YYSH",sizeof(yyshCtx));
		Yc = (yyshCtx*)Bp->buf_data;
		bzero(Yc,sizeof(yyshCtx));
		YxFlag |= YF_ALLOC;
	}else{
		bzero(Yc,sizeof(yyshCtx));
	}
	strcpy(YxHost,"localhost");
	YxPort = 6023;
	YxKAIntvl = 60;
	clearVStr(YxOpts);
	clearVStr(YxWdir);
	YxConn = Conn;
	YxAc = 0;
	return Yc;
}
static int endYYsh(yyshCtx *Yc){
	if( YxFlag & YF_ALLOC ){
		BUF_free("YYSH",Yc,sizeof(yyshCtx));
	}
	return 0;
}

void decomp_URL_siteX(PCStr(site),PVStr(userpass),PVStr(user),PVStr(pass),PVStr(hostport),PVStr(host),PVStr(port));
static int scanYYSHhost(MuxCtx *Mc,yyshCtx *Yc,PCStr(spec)){
	IStr(auth,256);
	IStr(hosts,256);
	refQStr(hp,hosts);
	IStr(hostport,256);
	IStr(ports,256);
	refQStr(pp,ports);
	int porti;

	strcpy(YxDest,spec);
	decomp_URL_siteX(spec,AVStr(auth),AVStr(YxUser),AVStr(YxPass),
		AVStr(hostport),AVStr(hosts),AVStr(ports));
	if( hosts[0] ){
		if( hp = strchr(hosts,'/') ){
			setVStrPtrInc(hp,0);
			strcpy(YxWdir,hp);
		}
		strcpy(YxHost,hosts);
	}
	if( porti = atoi(ports) ){
		YxPort = porti;
	}
	if( pp = strchr(ports,'/') ){
		setVStrPtrInc(pp,0);
		strcpy(YxWdir,pp);
	}
	if( pp = strchr(ports,'.') ){
		strcpy(YxOpts,pp+1);
	}
	return 0;
}
static int getYYdate(PVStr(date),int dsiz,int gmt){
	int now,usec;
	now = Gettimeofday(&usec);
	if( gmt )
		StrftimeGMT(BVStr(date),dsiz,"%H:%M:%S %d/%b/%Y GMT",now,usec);
	else	StrftimeLocal(BVStr(date),dsiz,"%H:%M:%S %d/%b/%Y %z",now,usec);
	return 0;
}
static int getHeader1(PCStr(wh),MuxCtx *Mc,FILE *fp,int timeout,PVStr(line),int lsiz){
	refQStr(lp,line);
	char *ret;
	int rcc = 0;
	int bin = 0;

	if( fPollIn(fp,timeout) <= 0 ){
		return -1;
	}
	ret = fgetsByLine(BVStr(line),lsiz,fp,timeout,&rcc,&bin);
	if( ret == 0 ){
		return -2;
	}
	if( bin ){
		sv1log("----%s bin=%d rcc=%d len=%d: %s\n",
			wh,bin,rcc,istrlen(line),line);
		if( strlen(line) < rcc ){
			return -3;
		}
	}
	if( lp = strpbrk(line,"\r\n") ){
		clearVStr(lp);
	}
	YYlogComm(Mc,"s---",wh,line);
	if( line[0] == 0 ){
		return -3;
	}
	return 0;
}

static int sendYyshQ(MuxCtx *Mc,yyshCtx *Yc,FILE *ts,int sno){
	const char *env;
	IStr(date,128);
	int col,row;
	int ai;

	getYYdate(AVStr(date),sizeof(date),1);
	YYlfprintf(Mc,"YYSH-Q-Sent",ts,"%s yysh:- HTTP/1.1",YY_SH);
	YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Date: %s",date);
	YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Version: %s",myYYVER);
	YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-YYSH-Version: %s",myYYSHVER);
	if( MxFlagsWITH_YYM || MxFlagsWITH_Y11 ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Upgrade: %s",myYYVER);
	}
	if( MxFlagsWITH_Y11 ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Upgrade: %s",myYY11VER);
	}
	if( MxFlagsX11UNIX ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-X11: unix");
	}
	if( MxFlagsX11LOCAL ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-X11: local");
	}
	if( MxFlagsX11INET ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-X11: inet");
	}
	if( MxFlagsSTLS && sno == 0 ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Upgrade: SSL");
	}
	if( sno == 0 && MxFlagsCREDHY ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Upgrade: %s",ZCredhy);
	}
	if( sno == 0 && MxFlagsWITH_FTP ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Accept-Protocol: ftp");
	}
	if( sno == 0 && MxFlagsWITH_HTT ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Accept-Protocol: http");
	}
	if( sno == 0 && MxFlagsDEFLATE1 ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Accept-Encoding: %s","deflate");
	}
	if( 0 < MxMaxPending ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Max-Pending: %d",MxMaxPending);
	}
	if( sno == 0 ){
		sendAuthenticate(Mc,"YYSH-Q-Sent",ts);
	}
	if( sno == 0 ){ /* genAutho() */
		generateCredhyKey(Mc,ts,"YYSH-Q-Sent",0);
	}
	if( genAutho(Mc) ){
		putAutho("YYSH-Q-Sent",Mc,ts);
	}
	if( sno == 0 ){
		sendYYKEY(Mc,ts);
	}
	sendYYUID("YYSH-Q-Sent",Mc,ts);
	if( YxWdir[0] ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Chdir: %s",YxWdir);
	}
	if( YxProl[0] ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Prolog: %s",YxProl);
	}
	if( YxCmdb[0] ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Command: %s",YxCmdb);
	}
	for( ai = 0; ai < YxAc; ai++ ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Arg: %s",YxAv[ai]);
	}
	if( YxFlag & YF_NOSSOCK ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Options: No-StdioSock");
	}
	if( YxFlag & YF_NOTTY ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-NoTty: 1");
	}

	if( YxFlag & YF_SUTTY ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-SuTty: do-annex-pty");
	}
	if( YxFlag & YF_SUACC ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-SuTty: no-socketpair");
	}
	if( YxFlag & YF_SUSELF ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-SuTty: no-external");
	}

	if( getTTySize(fileno(stdin),&col,&row) == 0 ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Env: LINES=%d",row);
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Env: COLUMNS=%d",col);
	}
	if( env = getenv("TERM") ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Env: TERM=%s",env);
	}
	/*
	if( env = getenv("TERM_PROGRAM") ){
		lfprintf("YYSH-Q-Sent",ts,"Y-Env: TERM_PROGRAM=%s",env);
		if( env = getenv("TERM_PROGRAM_VERSION") ){
		lfprintf("YYSH-Q-Sent",ts,"Y-Env: TERM_PROGRAM_VERSION=%s",env);
		}
	}
	*/
	if( MxUserPROMPT[0] ){
		YYlfprintf(Mc,"YYSH-Q-Sent",ts,"Y-Env: %s",MxUserPROMPT);
	}
	YYlfprintf(Mc,"YYSH-Q-Sent",ts,"");
	fflush(ts);
	return 0;
}
static int scanYyshQ(MuxCtx *Mc,yyshCtx *Yc,FILE *fc){
	Connection *Conn = MxConn;
	IStr(req,1024);
	IStr(nam,128);
	IStr(val,1024);
	IStr(auth,512);

	MxWithAuth = CTX_withAuth(Conn);
	for(;;){
		if( getHeader1("YYSH-Q-Recv",Mc,fc,60*1000,AVStr(req),sizeof(req)) < 0 ){
			break;
		}
		if( YxReq[0] == 0 ){
			strcpy(YxReq,req);
			sv1log("----YxReq[%s]\n",req);
			if( strneq(YxReq,YY_CON,strlen(YY_CON)) ){
				break;
			}
			continue;
		}
		fieldScan(req,nam,val);
		if( streq(nam,"Y-YYSH-Version") ){
			strcpy(YxClVer,val);
		}else
		if( streq(nam,"Authenticate") ){
			scanAuthenticate(Mc,val);
		}else
		if( strcaseeq(nam,"Upgrade") ){
			if( streq(val,myYYVER) ){
				MxFlags |= MX_WITH_YYM;
			}else
			if( streq(val,myYY11VER) ){
				MxFlags |= MX_WITH_Y11;
			}else
			if( strneq(val,"SSL",3) ){
				MxFlags |= MX_STLS;
			}else
			if( strneq(val,"TLS",3) ){
				MxFlags |= MX_STLS;
			}else
			if( strheadstrX(val,ZCredhy,1) ){
				MxFlags |= MX_CREDHY_SV | MX_CREDHY_CL;
			}
		}else
		if( strcaseeq(nam,"Y-Accept-Protocol") ){
			if( isinListX(val,"http","c") ){
				MxFlags |= MX_WITH_HTTP;
			}
			if( isinListX(val,"ftp","c") ){
				MxFlags |= MX_WITH_FTP;
			}
			if( isinListX(val,"y11","c") ){
				MxFlags |= MX_WITH_Y11;
			}
		}else
		if( strcaseeq(nam,"Accept-Encoding") ){
			if( streq(val,"deflate") ){
				MxFlags |= MX_DEFLATE1;
				MxFlags |= MX_DEFLATE2;
			}
		}else
		if( strcaseeq(nam,"Y-X11") ){
			if( streq(val,"unix") ){
				MxFlags |= MX_X11_UNIX; 
			}else
			if( streq(val,"local") ){
				MxFlags |= MX_X11_LOCAL; 
				/* 1 = 127.0.0.1 */
			}else
			if( streq(val,"inet") ){
				MxFlags |= MX_X11_INET; 
				/* 0 = 0.0.0.0 */
				/* xx.xx.xx.xx */
			}
		}else
		if( strcaseeq(nam,"Y-Credhy-Key") ){
			agreedCredhyKey(Mc,"Req",val);
		}else
		if( strcaseeq(nam,"Y-YYUID") ){
			strcpy(MxYYUID,val);
		}else
		if( strcaseeq(nam,"Y-Options") ){
			if( isinListX(val,"No-StdioSock","c") ){
				YxFlag |= YF_NOSSOCK;
			}
		}else
		if( strcaseeq(nam,"Y-NoTty") ){
			YxFlag |= YF_NOTTY;
		}else
		if( strcaseeq(nam,"Y-SuTty") ){
			YxFlag |= YF_SUTTY;
			if( isinList(val,"no-socketpair") ){
				YxFlag |= YF_SUACC;
			}
			if( isinList(val,"no-external") ){
				YxFlag |= YF_SUSELF;
			}
		}else
		if( strcaseeq(nam,"Y-Chdir") ){
			strcpy(YxWdir,val);
		}else
		if( strcaseeq(nam,"Y-Prolog") ){
			strcpy(YxProl,val);
		}else
		if( strcaseeq(nam,"Y-Command") ){
			strcpy(YxCmdb,val);
		}else
		if( strcaseeq(nam,"Y-Arg") ){
			if( YxAc < elnumof(YxAv) ){
				YxAv[YxAc++] = MxStralloc(Mc,val);
			}
		}else
		if( strcaseeq(nam,"Y-Env") ){
			YYpushenv(Mc,val);
			if( strneq(val,"LINES=",6) ){
				YxRows = atoi(val+6);
			}
			if( strneq(val,"COLUMNS=",8) ){
				YxCols = atoi(val+8);
			}
		}else
		if( strcaseeq(nam,"Authorization") ){
			strcpy(auth,req);
		}
	}
	YxAv[YxAc] = 0;
	if( auth[0] ){
		scanAuthorization(Mc,auth);
	}
	if( MxWithAuth && MxAuthOK == 0 ){
		MxAuthErr = 1;
	}
	return 0;
}
#if _MSC_VER
int getcuser(PVStr(name),int size,PVStr(group),int gsiz);
#else
#define getcuser(name,size,group,gsiz) -1
#endif

const char *ZlibVersion();
const char *SSLVersion();
int sslway_dl();
static int getServVers(PVStr(serv)){
	refQStr(sp,serv);
	IStr(name,64);
	IStr(ver,64);

	Rsprintf(sp,"DeleGate/%s",DELEGATE_ver());
	if( withZlib() ){
		Rsprintf(sp,"; Zlib/%s",ZlibVersion());
	}
	if( isCYGWIN() ){
		return 0;
	}
	if( sslway_dl() ){
		Xsscanf(SSLVersion(),"%s %s",AVStr(name),AVStr(ver));
		Rsprintf(sp,"; %s/%s",name,ver);
	}
	return 0;
}
static int sendYyshR(MuxCtx *Mc,yyshCtx *Yc,FILE *tc,int sno,int hcode){
	Connection *Conn = YxConn;
	IStr(host,MaxHostNameLen);
	IStr(clif,64);
	IStr(clnt,64);
	IStr(date,128);
	IStr(cwd,256);
	IStr(user,32);
	IStr(grp,32);
	char *ret;
	int aerr;
	IStr(authdomain,128);
	int aucb = 0;
	int auyy = 0;

	getYYdate(AVStr(date),sizeof(date),0);
	if( aerr = (CTX_withAuth(Conn) && MxAuthOK == 0) ){
		sprintf(authdomain,"-");
		hcode = 401;
		aucb = 1;
	}
	if( MxAuthOK == 0 ){
		if( MxAuthFlags & MA_YYKEY ){
			sprintf(authdomain,"-");
			hcode = 401;
			auyy = 1;
		}
	}
	lfprintf("YYSH-R-Sent",tc,"HTTP/1.1 %d yysh",hcode);
	lfprintf("YYSH-R-Sent",tc,"Y-Date: %s",date);
	lfprintf("YYSH-R-Sent",tc,"Y-Version: %s",myYYVER);
	lfprintf("YYSH-R-Sent",tc,"Y-YYSH-Version: %s",myYYSHVER);
	if( hcode == 401 ){
		if( aucb ){
			lfprintf("YYSH-R-Sent",tc,"Authenticate: %s realm=\"\"",
				CredhyBasic,authdomain);
		}
		if( auyy ){
			sendAuthenticate(Mc,"YYSH-R-Sent",tc);
		}
	}
	if( MxAuthFlags & MA_YYKEYr ){
		sendYYKEY(Mc,tc);
	}
	if( sno == 0 ){
		generateCredhyKey(Mc,tc,"YYSH-R-Sent",0);
	}
	if( !aerr ){
		if( hcode != 100 && hcode != 101 )
		if( (YxFlag & YF_RDSENT) == 0 ){
			IStr(serv,256);
			YxFlag |= YF_RDSENT;
			getpairName(ClientSockX,AVStr(clif),AVStr(clnt));
			gethostname(host,sizeof(host));
			getUsername(getuid(),AVStr(user));
			if( isWindows() && streq(user,"?") ){
			getcuser(AVStr(user),sizeof(user),AVStr(grp),sizeof(grp));
			}
			lfprintf("YYSH-R-Sent",tc,"Y-YY11-Version: %s",myYY11VER);
			getServVers(AVStr(serv));
			lfprintf("YYSH-R-Sent",tc,"Y-Server: %s",serv);
			lfprintf("YYSH-R-Sent",tc,"Y-Server-Host: %s",host);
			lfprintf("YYSH-R-Sent",tc,"Y-Server-Addr: %s",clif);
			lfprintf("YYSH-R-Sent",tc,"Y-Client-Addr: %s",clnt);
			lfprintf("YYSH-R-Sent",tc,"Y-Server-User: %s",user);
		}
		ret = getcwd(cwd,sizeof(cwd));
		lfprintf("YYSH-R-Sent",tc,"Y-Server-Wdir: %s",cwd);
	}

	/* getting INTR char. ... */
	/* send Y-Authenticate: CandR seed */
	lfprintf("YYSH-R-Sent",tc,"");
	fflush(tc);
	return 0;
}
int chrsubst(PVStr(str),int c1,int c2);
static int scanYyshR(MuxCtx *Mc,yyshCtx *Yc,FILE *fs){
	IStr(resp,512);
	IStr(nam,256);
	IStr(val,512);
	int ecode;

	YxSvINTR = 'C'-0x40;
	clearVStr(MxServstat);
	MxServcode = -1;
	for(;;){
		ecode = getHeader1("YYSH-R-Recv",Mc,fs,60*1000,AVStr(resp),sizeof(resp));
		if( ecode < 0 ){
			break;
		}
		fieldScan(resp,nam,val);
		if( MxServstat[0] == 0 ){
			strcpy(MxServstat,resp);
			sscanf(resp,"%*s %d",&MxServcode);
		}else
		if( streq(nam,"Authenticate") ){
			scanAuthenticate(Mc,val);
		}else
		if( streq(nam,"Authorization") ){
			scanAuthorization(Mc,resp);
		}else
		if( streq(nam,"Upgrade") ){
			strcpy(MxUpgrade,val);
		}else
		if( strcaseeq(nam,"Accept-Encoding") ){
			if( streq(val,"deflate") ){
				MxFlags |= MX_DEFLATE2;
			}
		}else
		if( streq(nam,"Y-Credhy-Key") ){
			generateCredhyKey(Mc,0,"yyResp",0);
			agreedCredhyKey(Mc,"Resp",val);
		}else
		if( streq(nam,"Y-Date") ){
			strcpy(YxSvDate,val);
		}else
		if( streq(nam,"Y-YYSH-Version") ){
			strcpy(YxSvVer,val);
		}else
		if( streq(nam,"Y-Server") ){
			strcpy(YxSvSoft,val);
		}else
		if( streq(nam,"Y-Server-Host") ){
			strcpy(YxSvHost,val);
		}else
		if( streq(nam,"Y-Server-Addr") ){
			strcpy(YxSvClif,val);
		}else
		if( streq(nam,"Y-Client-Addr") ){
			strcpy(YxSvClnt,val);
		}else
		if( streq(nam,"Y-Server-User") ){
			strcpy(YxSvUser,val);
		}else
		if( streq(nam,"Y-Server-Wdir") ){
			chrsubst(AVStr(val),'\\','/');
			if( CCXactive((CCXP)YxCCxCL) ){
				CCXexec((CCXP)YxCCxCL,val,strlen(val),
					AVStr(YxSvWdir),sizeof(YxSvWdir));
			}else{
				strcpy(YxSvWdir,val);
			}
		}
	}
	return 0;
}
static void pipe2sock(int ipipe,int osock,int raw){
	FILE *pin;
	FILE *sout;
	int ch;

	pin = fdopen(ipipe,"r");
	sout = fdopen(osock,"a");
	putfLog("---[%X] pipe2sock[%d %d]",TID,ipipe,osock);

	for(;;){
		if( ready_cc(pin) <= 0 ){
			fflush(sout);
		}
		ch = getc(pin);
		if( ch == EOF ){
			putfLog("---[%X] pipe2sock[%d %d] ch=%X",TID,
				ipipe,osock,ch);
			break;
		}
		if( 0 ){
			/* this breaks binary data as .get */
			if( ch == '\n' ){
				putc('\r',sout);
			}
		}
		if( putc(ch,sout) == EOF ){
			break;
		}
	}
	fflush(sout);
	fcloseFILE(pin);
	fcloseFILE(sout);
}
static void sock2pipe(int isock,int opipe,int raw){
	FILE *sin;
	FILE *sout;
	FILE *pout;
	int ch;
	int ci;

	sin = fdopen(isock,"r");
	sout = fdopen(isock,"a");
	pout = fdopen(opipe,"a");
	putfLog("---[%X] sock2pipe[%d %d]",TID,isock,opipe);
	for( ci = 0; ; ci++ ){
		if( ready_cc(sin) <= 0 ){
			fflush(pout);
		}
		ch = getc(sin);
		if( ch == EOF ){
			putfLog("---[%X] sock2pipe[%d %d] ch=%X (%d)",TID,
				isock,opipe,ch,ci);
			break;
		}
		if( 0 ){
			if( ch == 'D'-0x40 ){
				putfLog("---- EOS from Socket [%X]",ch);
				break;
			}
		}
		/* if in raw mode
		if( raw ){
			putc(ch,sout);
			fflush(sout);
		}
		 */
		if( ch == '\r' ){
			ch = '\n';
		}
		if( putc(ch,pout) == EOF ){
			break;
		}
	}
	dupclosed(opipe);
	fcloseFILE(sin);
	fcloseFILE(sout);
	fcloseFILE(pout);
}

int setInheritance(int ifd,int inherit);
#if defined(_MSC_VER) /*{*/
#if UNDER_CE
#define spawnve(m,p,a,e) -1
#endif
#else
#define _P_NOWAIT 1
#define GetLastError() errno
int spawnve(int mode,PCStr(path),const char *av[],char *ev[]){
	int pid;
	if( mode == _P_NOWAIT ){
		pid = fork();
		if( pid == 0 ){
			execve(path,(char**)av,ev);
			exit(-1);
			return -1;
		}
		return pid;
	}else{
	}
	return 0;
}
#endif

static int unixsystem(yyshCtx *Yc,FILE *fc,FILE *tc){
	int pid,ph,xpid;
	int sin,sout,serr;

	sv1log("--[%d][%d]--unixsystem(%s)\n",fileno(fc),fileno(tc),YxCmdb);
	sin = dup(0);
	sout = dup(1);
	serr = dup(2);
	dup2(fileno(fc),0);
	dup2(fileno(tc),1);
	/*
	dup2(fileno(tc),2);
	suppress local log output for -fv to be sent to the remote client
	*/
	dup2(curLogFd(),2);

	pid = bgexecyy(YxCmdb,(char**)YxAv,environ,&ph);
	xpid = bgwait(pid,ph,60);
	sv1log("--wait pid=%d xpid=%d e%d\n",pid,xpid,errno);

	dup2(serr,2);
	dup2(sout,1);
	dup2(sin,0);
	close(serr);
	close(sout);
	close(sin);

	return 0;
}
static int winargv(const char *av[],int nac,const char *nav[],PVStr(nab),int nsz){
	refQStr(nap,nab);
	const char *arg1;
	int enc = 0;
	int ai;

	for( ai = 0; av[ai] && ai < nac-1; ai++ ){
		nav[ai] = nap;
		arg1 = av[ai];
		if( strpbrk(arg1," \t") ){
			setVStrPtrInc(nap,'"');
			strcpy(nap,arg1);
			strsubst(AVStr(nap),"\"","\\\"");
			nap += strlen(nap);
			setVStrPtrInc(nap,'"');
			enc++;
		}else{
			strcpy(nap,arg1);
			nap += strlen(nap);
		}
		setVStrPtrInc(nap,0);
	}
	setVStrPtrInc(nap,0);
	nav[ai] = 0;
	return enc;
}
static int winsystem(yyshCtx *Yc,FILE *fc,FILE *tc){
	int fromC = fileno(fc);
	int toC = fileno(tc);
	int toCe = fileno(tc);
	const char *cmd;
	int psins[2],psout[2],pserr[2];
	int sins,sout,serr;
	int tins,tout,terr;
	int eins,eout,eerr;
	int xstat;
	int ph;
	int pid = 0;
	int xpid;
	IStr(cmdb,256);
	int raw = 0;
	const char *av[2];
	const char **argv;
	const char *nav[512];
	IStr(nab,0x10000);

	sv1log("--[%d][%d]--winsystem(%s)\n",fromC,toC,YxCmdb);
	if( 1 ){
		toCe = curLogFd();
		/* it should be directed to remote Stderr chan. if with Mux */
	}
	if( YxCmdb[0] ){
		cmd = YxCmdb;
		if( fullpathCOM(YxCmdb,"r",AVStr(cmdb)) == 0 ){
			IStr(xcom,128);
			sprintf(xcom,"%s.exe",YxCmdb);
			fullpathCOM(xcom,"r",AVStr(cmdb));
		}
		if( cmdb[0] ){
			cmd = cmdb;
		}
		if( isWindows() ){
			winargv(YxAv,elnumof(nav),nav,AVStr(nab),sizeof(nab));
			argv = nav;
		}else{
			argv = YxAv;
		}
		raw = 0;
	}else{
		if( isWindows() ){
			cmd = "C:\\WINDOWS\\system32\\command.com";
			cmd = "C:\\cygwin\\bin\\bash.exe";
		}else{
			cmd = "/bin/bash";
			cmd = "/bin/sh";
		}
		av[0] = cmd;
		av[1] = 0;
		argv = av;
		raw = 1;
	}
	sv1log("---- command{%s}\n",cmd);

	sins = dup(0);
	sout = dup(1);
	serr = dup(2);

	pipeX(psins,0x4000);
	pipeX(psout,0x4000);
	pipeX(pserr,0x4000);

	sv1log("---- i[%d %d] o[%d %d] e[%d %d]\n",
		psins[0],psins[1], psout[0],psout[1], pserr[0],pserr[1]);

	if( isWindows() ){
		setInheritance(psins[1],0);
	}else{
		setCloseOnExec(psins[1]);
	}
	setCloseOnExecSocket(fromC);
	if( fromC != toC ){
		setCloseOnExecSocket(toC);
	}
	dup2(psins[0],0);
	dup2(psout[1],1);
	dup2(pserr[1],2);
	close(psins[0]);
	close(psout[1]);
	close(pserr[1]);

	if( isyycom(cmd) ){
		pid = bgexecyy(cmd,(char**)argv,environ,&ph);
	}else{
		ph = spawnve(_P_NOWAIT,cmd,argv,environ);
	}

	close(0);
	close(1);
	close(2);
	dup2(sins,0);
	dup2(sout,1);
	dup2(serr,2);
	close(sins);
	close(sout);
	close(serr);

	sv1log("---- spawn=%d {%s} e%d/%d\n",ph,cmd,errno,GetLastError());
	if( ph < 0 ){
	}else{
		tins = thread_fork(0,0,"Stdins",(IFUNCP)sock2pipe,fromC,psins[1],raw);
		tout = thread_fork(0,0,"Stdout",(IFUNCP)pipe2sock,psout[0],toC,raw);
		terr = thread_fork(0,0,"Stderr",(IFUNCP)pipe2sock,pserr[0],toCe,raw);
		sv1log("---- %u/%d [%04X %04X %04X]\n",pid,ph,
			PRTID(tins),PRTID(tout),PRTID(terr));
		xstat = 0;
		if( isWindows() ){
			xpid = _cwait(&xstat,ph,0);
		}else{
			xpid = wait(0);
		}
		close(psins[1]);
		eout = thread_wait(tout,1*1000);
		eerr = thread_wait(terr,1*1000);
		if( isWindows() ){
			ShutdownSocketRDWR(fromC);
		}
		eins = thread_wait(tins,1*1000);
		sv1log("---- %u/%d [%04X %04X %04X][%d %d %d] %d/%d\n",
			pid,ph,PRTID(tins),PRTID(tout),PRTID(terr),
			eins,eout,eerr,xpid,xstat);

		close(psout[0]);
		close(pserr[0]);
	}
	return 0;
}
static int setupShellEnv(MuxCtx *Mc,yyshCtx *Yc,Connection *Conn,PCStr(yshell)){
	IStr(shellb,1024);
	const char *shell;
	const char *sp;
	int ai;

	shell = getenv("SHELL");
	if( shell == 0 || shell[0] == 0 || !isatty(0) && !isatty(1) ){
		/* v9.9.10 mod-140630a invocation from cron, inetd, ... */
		if( getSHELL(getuid(),AVStr(shellb)) && shellb[0] != 0 ){
			sv1log("-- SHELL=%s <- [%s]\n",shellb,shell?shell:"");
			shell = shellb;
		}
	}
	if( strneq(MxUserSHELL,"SHELL=",6) ){
		shell = MxUserSHELL+6;
	}
	if( shell == 0 || shell[0] == 0 ){
		shell = "/bin/sh";
	}
	if( *shell == '[' ){
		for( sp = shell+1; *sp; sp++ ){
			if( *sp == ']' ){
				QStrncpy(YxShell,shell+1,sp-shell);
				shell = sp+1;
				break;
			}
		}
	}
	decomp_args(YxShAv,elnumof(YxShAv),shell,AVStr(YxShAb));
	if( YxShell[0] == 0 ){
		strcpy(YxShell,YxShAv[0]);
	}
	if( MxFlagsVERBOSE ){
		sv1log("YxShell: %s\n",YxShell);
		for( ai = 0; YxShAv[ai]; ai++ ){
			sv1log("YxShAv[%d]: %s\n",ai,YxShAv[ai]);
		}
	}
	return 0;
}
static void setupYYshenv(MuxCtx *Mc,yyshCtx *Yc,Connection *Conn){
	if( YxShell[0] ){
		sprintf(YxSHELL,"SHELL=%s",YxShell);
		putenv(YxSHELL);
	}
	if( MxUserPROMPT[0] ){
		putenv(MxUserPROMPT);
	}
	if( MxYYUID[0] ){
		sprintf(YxYYUID,"YYUID=%s",MxYYUID);
		putenv(YxYYUID);
	}
	if( MxYYGUID ){
		sprintf(YxYYGUID,"YYGUID=%X",MxYYGUID);
		putenv(YxYYGUID);
	}
}

int CTX_withYY_SV(Connection *Conn){
	if( Conn ){
		return ServerFlags & PF_WITH_YYMUX;
	}else{
		return 0;
	}
}
int CTX_withYY_CL(Connection *Conn){
	if( Conn ){
		return ClientFlags & PF_WITH_YYMUX;
	}else{
		return 0;
	}
}
int CTX_withYY(Connection *Conn){
	if( CTX_withYY_CL(Conn) ){
		return 1;
	}
	if( CTX_withYY_SV(Conn) ){
		return 2;
	}
	return 0;
}
int CTX_withYY_BROKEN(Connection *Conn){
	if( STX_yy ){
		if( yy_gotSIG ){
			finishServYY(FL_ARG,Conn);
			finishClntYY(FL_ARG,Conn);
			signal(SIGINT,SIG_DFL);
			signal(SIGTERM,SIG_DFL);
			return yy_gotSIG;
		}
	}
	return 0;
}
/* -yyc or SERVER=proto://host:port.yymux */
int YY_connect(Connection *Conn,int sock,int initfrom){
	MuxCtx *Mc = yy_gMc;
	int yysock;
	double St = Time();
	FILE *ts;
	FILE *fs;
	IStr(req,1024);
	int rcc;

	if( 1 < yy_gotSIG ){
		sv1log("##YY_connect[%d] disabled gotSIG=%d\n",sock,yy_gotSIG);
		if( lMULTIST() ){
			/* yy_gotSIG should be cleared or ignored */
			return 0;
		}
		return -1;
	}
	if( ConnectFlags & COF_RESUMING ){
		return 0;
	}
	if( yy_gMc == 0 ){
		return 0;
	}
	Mc = yy_gMc;
	if( MxFlagsMUXCON == 0 ){
		return 0;
	}
	if( initfrom & PI_SERV ){
		/* Server-First: ftp, smtp, pop, nntp, telnet */
		if( 0 )
		if( PollIn(sock,3*1000) ){
		rcc = recvPeekTIMEOUT(sock,AVStr(req),sizeof(req)-1);
		}
		/* peek and detect YYMUX header */
	}
	ServerFlags |= PF_WITH_YYMUX;
	fs = fdopen(sock,"r");
	if( fs == 0 ){
		return 0;
	}
	setbuffer(fs,0,0);
	ts = fdopen(sock,"w");

	Mc = newYY(Conn,ET_CLNT|ET_NOX);
	sv1log("--------1---Upgrade CL-side conn. to YYMUX\n");

	strcpy(MxServ,DST_HOST);
	MxServport = DST_PORT;
	saveYYserver(Mc,"yymux",DST_HOST,DST_PORT);
	MxFlags ^= MX_SHUTIMM;
	MxRsmkey ^= trand1(0xFFFFFFFF);

	yysock = insertMuxCL(Mc,Conn,-1,fileno(ts),ts,fs,1,0);
	sv1log("--------2---Upgraded CL-side to YYMUX-%d [%d] th=%d/%d\n",
		STX_yy,yysock,actthreads(),numthreads());
	if( MxFlagsVERBOSE ){
		dumpFds(curLogFp());
	}
	if( yysock < 0 ){
		//salvageClnt(Mc,CST_CLEARED,MxRsmport,MxRsmkey);
		return -1;
	}
	return 1;
}
/* -yya or -Qport/yymux or with */
int YY_accept(Connection *Conn,FILE *tc,int initfrom){
	MuxCtx *Mc;
	int yysock;
	FILE *fc;
	IStr(req,1024);
	int rcc;

	if( yy_gMc == 0 ){
		return 0;
	}
	Mc = yy_gMc;
	if( MxFlagsMUXACC == 0 ){
		return 0;
	}
	if( initfrom & PI_CLNT ){
		/* Client-First: http, socks, gopher */
		/* peek and detect non-YYMUX request */
		if( 0 )
		if( PollIn(FromC,3*1000) ){
		rcc = recvPeekTIMEOUT(ClientSockX,AVStr(req),sizeof(req)-1);
		}
	}
	ClientFlags |= PF_WITH_YYMUX;
	fc = fdopen(ClientSockX,"r");
	if( fc == 0 ){
		return 0;
	}
	setbuffer(fc,0,0);
	tc = fdopen(ClientSockX,"w");
	Mc = newYY(Conn,ET_SERV|ET_NOX);
	sv1log("--------1---Upgrade SV-side conn. to YYMUX\n");
	yysock = insertMuxSV(Mc,Conn,fileno(fc),fc,tc,1);
	sv1log("--------2---Upgraded SV-side to YYMUX [%d][%d %d][%d %d]\n",
		yysock,fileno(fc),fileno(tc),FromC,ToC);
	fcloseFILE(fc);
	fcloseFILE(tc);
	if( MxRsmstate == CST_RESUME || yysock < 0 ){
		/* finished RSM proxy, don't cont. the service of the app. */
		return -1;
	}
	return 1;
}

int getpass1(FILE *in,FILE *out,PVStr(pass),PCStr(xpass),PCStr(echoch));
static int retryAuthR(MuxCtx *Mc,yyshCtx *Yc,FILE *tc,FILE *fc){
	int ri;
	for( ri = 0; ri < 3; ri++ ){
		lfprintf("Resp",tc,"HTTP/1.0 401 auth. error");
		lfprintf("Resp",tc,"Y-Version: %s",myYYVER);
		lfprintf("Resp",tc,"");
		fflush(tc);

		if( fPollIn(fc,30*1000) <= 0 ){
			lfprintf("Resp",tc,"HTTP/1.0 504 timeout");
			lfprintf("Resp",tc,"");
			fflush(tc);
			break;
		}

		MxAuthErr = 0;
		scanYyshQ(Mc,Yc,fc);
		if( MxAuthErr == 0 ){
			lfprintf("Resp",tc,"HTTP/1.0 100 auth. OK");
			lfprintf("Resp",tc,"");
			fflush(tc);
			break;
		}
	}
	return 0;
}
/* password must be saved to be reused for RSM ... */
static int retryAuthQ(MuxCtx *Mc,yyshCtx *Yc,FILE *ts,FILE *fs){
	IStr(user,128);
	refQStr(up,user);
	IStr(pass,128);
	int ri;

	for( ri = 0; ri < 3; ri++ ){
		if( !IsAlive(fileno(ts)) ){
			break;
		}
		clearVStr(user);
		fprintf(stderr,"~~~~ Username: ");
		fflush(stderr);
		fgets(user,sizeof(user),stdin);
		if( up = strpbrk(user,"\r\n") ){
			truncVStr(up);
		}
		clearVStr(pass);
		fprintf(stderr,"~~~~ Password: ");
		fflush(stderr);
		getpass1(stdin,stderr,AVStr(pass),0,"*");
		fprintf(stderr,"\r\n");

		setMyAuth(Mc,user,pass);
		sendYyshQ(Mc,Yc,ts,1);
		clearMyAuth(Mc);
		bzero(pass,sizeof(pass));
		scanYyshR(Mc,Yc,fs);
		fprintf(stderr,"~~~~ %s\n",MxServstat);
		if( MxServcode != 401 ){
			break;
		}
	}
	return 0;
}

int service_Y11a(Connection *Conn,int svsock,int svport,int ct);
int service_yymux(Connection *Conn,int svsock,int svport){
	return service_Y11a(Conn,svsock,svport,ET_SERV|ET_NOX);
}
int service_Y11(Connection *Conn,int svsock,int svport){
	return service_Y11a(Conn,svsock,svport,ET_SERV);
}
static void YSigPIPE(int sig){
	sv1log("##YYSH GOT SIGPIPE\n");
	Finish(-1);
}
struct _Netsh *openNetsh(struct _Netsh *Nsh,PCStr(shell),char*const sav[],char*const sev[],int sync,int fromkey,int todisp,int sutty,int cols,int rows,Int64 inheritfds);
int waitNetsh(struct _Netsh *Nsh,int timeout);
int withDGForkpty(PVStr(path));
int service_yysh1(Connection *Conn,int svsock,int svport,MuxCtx *Mc,yyshCtx *Yc,FILE *fc,FILE *tc);
static void sigALRM(int sig){
	Vsignal(SIGALRM,sigALRM);
	sv1log("##FATAL sigALRM(%d) ignored\n",sig);
}
int service_yysh3(Connection *Conn,int svsock,int svport,MuxCtx *Mc,yyshCtx *Yc,FILE *fc,FILE *tc){
	void (*sigalrm)(int);
	int rcode;

	sigalrm = Vsignal(SIGALRM,sigALRM);
	rcode = service_yysh1(Conn,svsock,svport,Mc,Yc,fc,tc);
	Vsignal(SIGALRM,sigalrm);
	return rcode;
}
int service_yysh(Connection *Conn,int svsock,int svport){
	yyshCtx YcBuf,*Yc = newYYSH(&YcBuf,Conn);
	MuxCtx *Mc;
	FILE *tc = 0;
	FILE *fc = 0;
	int rcode;
	int yyid = 0;

	tc = fdopen(ToC,"w");
	fc = fdopen(FromC,"r");
setbuffer(fc,0,0); /* yysh-server */

	initgMc(Conn);
	if( STX_yy && (ClientFlags & PF_WITH_YYMUX) ){
		yyid = STX_yy;
		STX_yy = 0; /* for -yyac not to be broken by newYY() */
	}
	Mc = newYY(Conn,ET_SERV);
	rcode = service_yysh3(Conn,svsock,svport,Mc,Yc,fc,tc);
	if( yyid ){
		STX_yy = yyid;
		finishClntYY(FL_ARG,Conn);
	}

	fcloseFILE(tc);
	fcloseFILE(fc);
	endYY(Conn,Mc);
	if( MxFlagsVERBOSE ){
		dumpFds(curLogFp());
	}
	return rcode;
}
int service_yysh2(Connection *Conn,int svsock,int svport,MuxCtx *Mc,FILE *fc,FILE *tc,PCStr(req)){
	yyshCtx YcBuf,*Yc = newYYSH(&YcBuf,Conn);
	int rcode;
	/* strcpy(YxReqline,req); */
	rcode = service_yysh3(Conn,svsock,svport,Mc,Yc,fc,tc);
	return rcode;
}
int insertFCLF(Connection *Conn,int fromC,PCStr(filter));
int service_yysh1(Connection *Conn,int svsock,int svport,MuxCtx *Mc,yyshCtx *Yc,FILE *fc,FILE *tc){
	struct _Netsh *Nsh;
	int rcode;
	int rcc;
	int immSSL = -1;
	int withSTLS = -1;
	int fcl;
	FILE *afc = fc;
	FILE *atc = tc;
	int pollreq_timeout = 100;
	int ygid = ++yy_gid;
	int ytgid = getthreadid();

	sv1log("----yysh server\n");
	setthreadgid(getthreadid(),getthreadid());

MxStatISMAIN = 1;
Mc->mc_ygid = ygid;
Mc->mc_ytgid = ytgid;

	setupYYenv(Mc);
	/* should detect YYMUX ... */
	/* should relay dividing stdout/stderr on MUX */

	if( fPollIn(fc,pollreq_timeout) ){
		if( isinSSL(fileno(fc)) ){
			sv1log("#### yysh in immediate SSL ####\n");
			fcl = insertFCLF(Conn,fileno(fc),"sslway -ac");
			if( 0 <= fcl ){
				immSSL = fcl;
				fc = fdopen(fcl,"r");
				tc = fdopen(fcl,"w");
				setbuffer(fc,0,0);
			}else{
				goto EXIT;
			}
		}
	}
	sendYyshR(Mc,Yc,tc,0,100);
	if( fPollIn(fc,60*1000) <= 0 ){
		sv1log("----yysh timeout\n");
		goto EXIT;
	}
	scanYyshQ(Mc,Yc,fc);
	if( !streq(myYYSHVER,YxClVer) ){
		/*
		lfprintf("Resp",tc,"HTTP/1.0 500 bad YY version");
		lfprintf("Resp",tc,"");
		goto EXIT;
		*/
	}
	if( strneq(YxReq,YY_CON,strlen(YY_CON)) ){
		IStr(xcom,128);
		Xsscanf(YxReq,"%*s %s",AVStr(xcom));
		sv1log("----yysh [%s]\n",YxReq);
		if( 1 ){
			scanYYrequest(Mc,elnumof(YxAv),YxAv,0,fc);
			yyMUXproxy(Mc,Conn,fc,tc,YY_CON,xcom,0,YxAv);
		}else{
			scanYyshQ(Mc,Yc,fc);
			lfprintf("TEST",tc,"HTTP/1.0 410 testing shut.");
			lfprintf("TEST",tc,"");
		}
		goto EXIT;
	}
	if( MxAuthErr ){
		retryAuthR(Mc,Yc,tc,fc);
		if( MxAuthErr ){
			goto EXIT;
		}
	}

	if( YxWdir[0] ){
		rcode = chdir(YxWdir);
		if( rcode != 0 ){
			/* return error */
		}
	}
	if( feof(fc) || ferror(tc) ){
		sv1log("----yysh reset by client (%d %d)\n",feof(fc),ferror(tc));
		goto EXIT;
	}

	/* start YYMUX here if necessary */
	if( MxFlagsWITH_YYM
	 || MxFlagsWITH_Y11
	 || MxFlagsWITH_FTP
	 || MxFlagsWITH_HTT
	 || MxFlagsWITH_SOC
	 || MxFlagsWITH_PMA
	){
		int yysock;

		sv1log("--------1---Upgrade SV conn. to YYMUX\n");
		lfprintf("SYNC",tc,"HTTP/1.1 101 Upgrading to YYMUX");
		lfprintf("SYNC",tc,"Upgrade: %s",myYYVER);
		if( withZlib() )
		lfprintf("Resp",tc,"Accept-Encoding: %s","deflate");
		lfprintf("SYNC",tc,"");
		fflush(tc);
		if( feof(fc) || ferror(tc) ){
			sv1log("--------x---Upgrade SV reset (%X %X)\n",
				feof(fc),ferror(tc));
			goto EXIT;
		}

		MxDebug = 2;
		yysock = insertMuxSV(Mc,Conn,fileno(fc),fc,tc,1);
		sv1log("--------2---Upgraded conn. YYMUX [%d][%d %d][%d %d]\n",
			yysock,fileno(fc),fileno(tc),FromC,ToC);
	}

	/* SSL should be applied selectiverly to each connection ? */
	if( MxFlagsSTLS ){
		lfprintf("Resp",tc,"HTTP/1.1 101 START TLS");
		lfprintf("Resp",tc,"Upgrade: SSL");
		lfprintf("Resp",tc,"");
		fflush(tc);

		sv1log("----START TLS@SV A %X[%d]\n",ClientFlags,ClientSockX);
		if( ClientFlags & (PF_STLS_ON|PF_SSL_ON) ){
			pushPFilter(Conn,"yysh",&ClientFilter);
		}
		fcl = insertFCLF(Conn,fileno(fc),"sslway -ac");
		sv1log("----START TLS@SV B %X[%d]\n",ClientFlags,fcl);
		if( 0 <= fcl ){
			//FromC = ToC = fcl;
			if( fc != afc ){
				fcloseFILE(fc);
				fcloseFILE(tc);
			}
			tc = fdopen(fcl,"w");
			fc = fdopen(fcl,"r");
setbuffer(fc,0,0); /* yysh-server STLS */
			withSTLS = fcl;
		}else{
		}
	}

	/* compression must be applied to the original data, before SSL */
	if( MxFlagsCREDHY || MxFlagsDEFLATE2 ){
		int fcl = -1;
		sv1log("----Credhy Start SV C%X Z%X\n",MxFlagsCREDHY,MxFlagsDEFLATE2);
		lfprintf("Resp",tc,"HTTP/1.1 101 START Credhy");
		lfprintf("Resp",tc,"Upgrade: %s",ZCredhy);
		if( withZlib() )
		lfprintf("Resp",tc,"Accept-Encoding: %s","deflate");
		lfprintf("Resp",tc,"");
		fflush(tc);

		fcl = insertZCredhy(Mc,fileno(fc),XF_FCL);
		if( 0 <= fcl ){
			if( fc != afc ){
				fcloseFILE(fc);
				fcloseFILE(tc);
			}
			tc = fdopen(fcl,"w");
			fc = fdopen(fcl,"r");
setbuffer(fc,0,0); /* yysh-server Credhy */
		}
	}

	setupShellEnv(Mc,Yc,Conn,YxShell);
	setupYYshenv(Mc,Yc,Conn);
	addX11PATH(elnumof(MxEnv),MxEnv,AVStr(MxStrbuf));

	if( YxCmdb[0] ){
		/* should clean-up YYMUX on exit */
		if( 1 ){
			Vsignal(SIGPIPE,YSigPIPE);
			Vsignal(SIGTERM,SIG_DFL);
			Vsignal(SIGINT,SIG_DFL);
		}
		/* relaying stderr as OOB ? */
		sendYyshR(Mc,Yc,tc,2,200);
		if( isWindows() || (YxFlag & YF_NOSSOCK) ){
			/* socket handle not used as stdio */
			winsystem(Yc,fc,tc);
		}else{
			unixsystem(Yc,fc,tc);
		}
	}else{
		int withdgpty;
		IStr(dgptypath,256);
		withdgpty = withDGForkpty(AVStr(dgptypath));
		sv1log("--dgpty %d [%s]\n",withdgpty,dgptypath);

		if( isWindows() ){
			if( withdgpty ){
				YxFlag |= YF_SUTTY;
			}else{
				YxFlag |= YF_NOTTY;
			}
		}
		if( YxFlag & YF_NOTTY ){
			sendYyshR(Mc,Yc,tc,2,200);
			winsystem(Yc,fc,tc);
		}else{
			int sutty = 0;
			if( YxFlag & YF_SUTTY ) sutty = 1;
			if( YxFlag & YF_SUACC ) sutty = 3;
			if( YxFlag & YF_SUSELF ) sutty |= 4;
			if( YxFlag & YF_INFYY ){
				/* direct access might be useful */
			}else{
				/* not to block diconn. by background
				 * processes forked from the shell
				 */
				setCloseOnExecSocket(ClientSock);
			}

			sendYyshR(Mc,Yc,tc,2,200);
			Nsh = openNetsh(0,YxShell,(char*const*)YxShAv,
				(char*const*)YxShEv,1,fileno(fc),fileno(tc),
				sutty,YxCols,YxRows,0x7|(1<<curLogFd()));

			/* return HTTP/1.1 200 */
			waitNetsh(Nsh,0);
		}
	}

	if( MxFlagsCREDHY || MxFlagsDEFLATE2 ){
		double St = Time();
		shutdownWR(fileno(tc));
		popPFilter(Conn,10*1000,XF_FCL);
	}
	if( 0 <= withSTLS ){
		shutdownWR(withSTLS);
		/* should wait SSLway thread here ? */
		if( MxFlagsVERBOSE ){
			dumpFds(curLogFp());
		}
	}
	if( 0 <= immSSL ){
		shutdownWR(fileno(tc));
		sv1log("--yysh C=%d Z=%d CF=%X iS[%d] wS[%d] [%d][%d][%d]\n",
			MxFlagsCREDHY,MxFlagsDEFLATE2,ClientFlags,
			immSSL,withSTLS,ClientSockX,fileno(fc),fileno(tc));
	}
	if( MxFlagsYYACTIVE ){
		/*---- end yyMux ----*/
		int rdy;
		double St = Time();
		double Lt;
		shutdownWR(fileno(tc));
		rdy = PollIn(fileno(fc),1000);
		Lt = Time();
		CTX_endYY(Conn);
			/* this may close self ? */
		sv1log("--yy fin. rdy=%d (%.3f)(%.3f)\n",rdy,Lt-St,Time()-St);
		/*
		CTX_sweepYY(Conn);
		*/
	}
	if( fc != afc ){
		fcloseFILE(fc);
		fcloseFILE(tc);
	}
	if( 0 <= withSTLS ){
		sv1log("----STLS close[%d] [%d][%d] th=%d/%d\n",
			withSTLS,ClientSock,ToC,
			actthreads(),numthreads());
		close(withSTLS);
	}
EXIT:
	YY_endYYs("end-yysh",Conn,ygid,ytgid);
	return 0;
}

/* internal status of a local file */
enum _Fmode {
	FM_READ		= 0x0001,
	FM_WRITE	= 0x0002,
	FM_APPEND	= 0x0004,
	FM_COPYTIME	= 0x0008,
} Fmode;

static int scanArg1(MuxCtx *Mc,yyshCtx *Yc,int ac,const char *av[]){
	const char *a1 = av[0];

	if( 2 <= ac )
	if( streq(a1,".get") || streq(a1,".put") ){
		if( streq(a1,".get") ){
			YxLfmod |= FM_WRITE; /* write to local file */
		}
		if( streq(a1,".put") ){
			YxLfmod |= FM_READ; /* read from local file */
		}
		strcpy(YxLfile,av[1]);
		if( 3 <= ac ){
			YxAv[YxAc++] = MxStralloc(Mc,av[2]);
			return 2;
		}else{
			YxAv[YxAc++] = MxStralloc(Mc,av[1]);
			return 1;
		}
	}
	return 0;
}
static void setCCX(MuxCtx *Mc,yyshCtx *Yc,PCStr(arg)){
	CCXP ccx = (CCXP)YxCCxCL;
	const char *icode = "*";
	const char *icodep;
	const char *ocode = 0;

	if( *arg == '-' ){
	    arg++;
	    if( *arg == 'j' ){
		arg++;
		if( *arg == '^' ){
			ccx = (CCXP)YxCCxSV;
			arg++;
		}
		if( icodep = strchr(arg,'/') ){
			icode = icodep + 1;
		}
		switch( *arg ){
		    case 'e': case 'E': /* EUC-JP */
			ocode = arg;
			break;
		    case 's': case 'S': /* Shift_JIS */
			ocode = arg;
			break;
		    case 0:
			ocode = "UTF-8";
			break;
		    case 'u': case 'U':
			ocode = arg;
			break;
		    case 'j': case 'J':
			ocode = "ISO-2022-JP";
			break;
		    case 't': case 'T':
			ocode = arg;
			break;
		}
		if( ocode ){
			CCXcreate(icode,ocode,ccx);
 sv1log("----JC %s [%s]\n",ocode,icode);
		}
	    }
	}
}


/* to be used for RIDENT */
/*
 * [0] version
 * [1] item-existence-bits
 */
enum _YYCertItem {
	YC_CIPHER =  1, /* 4i cipher type */
	YC_SIGNA  =  2, /* 4i sign type */
	YC_SIGN   =  3, /* 4i sign CRC32(CRC32(thisKey)+signerKey) */
	YC_IDATE  =  4, /* 4i issued date (UNIX time seconds) */
	YC_IDATEU =  5, /* 4i issued date (micro seconds) */
	YC_VFROM  =  6, /* 4i valid from (UNIX time seconds) */
	YC_VTILL  =  7, /* 4i valid until (UNIX time seconds) */
	YC_DOMAIN =  8, /* 4i CRC32(domainName) */
	YC_HOST   =  9, /* 4i CRC32(hostName) */
	YC_ISSUER = 10, /* 4i CRC32(issuerName) */
	YC_SIGNER = 11, /* 4i CRC32(signerName) */
	YC_USER   = 12, /* Vc user name ended with '\0' */
	YC_PASS   = 13, /* Vc password ended with '\0' */
	YC_CAPS   = 14, /* Vc list of capabilities ended with '\0' */
} YYCertItem;
typedef struct _YYID {
	int	yc_ver;
	int	yc_cipher;
	int	yc_idate;
	int	yc_idate_usec;
	int	yc_vfrom;
	int	yc_vtill;
	int	yc_host;
	int	yc_domain;
	int	yc_issuer;
	int	yc_signer; /* Approved by */
	MStr(	yc_user,64);
	MStr(	yc_pass,64);
	MStr(	yc_caps,256);
} YYID;
static int encYYCert(PVStr(cert),YYID *YI){
	return 0;
}
static int verifyKey(PCStr(arg),PCStr(skey)){
	IStr(nonce,128);
	IStr(okey,128);
	const unsigned char *up = (const unsigned char*)okey;
	int len;
	int oi;
	int iuid,secd,usec;
	int sign;
	IStr(sdate,64);

	NonceKey(AVStr(nonce));
	len = deCreys("b",nonce,skey,AVStr(okey),sizeof(okey));
	if( len < 0 ){
		return -1;
	}
	iuid = up[0] | (up[1] << 8);
	usec = up[2] | (up[3] << 8);
	usec = usec << 4;
	secd = up[4] | (up[5] << 8) | (up[6] << 16) | (up[7] << 24);
	sign = up[8] | (up[9] << 8);
	StrftimeLocal(AVStr(sdate),sizeof(sdate),"%Y %m %d %H:%M:%S%.6s",secd,usec);

	fprintf(stderr,"Date: %s\n",sdate);
	if( okey[10] ){
		fprintf(stderr,"User: %s\n",okey+10);
	}
	/*
	id to symbol
		fprintf(stderr,"Domain: %s\n",okey+10);
		fprintf(stderr,"Issuer: %d\n",iuid);
		fprintf(stderr,"Signer: %s\n",signer);
		fprintf(stderr,"Host: %s\n",host);

		fprintf(stderr,"Term: %s\n",validUntil);
		fprintf(stderr,"Caps: %s\n",capsList);
		fprintf(stderr,"Cipher: Crey\n");
		fprintf(stderr,"Sign: %08X\n",sign);
	*/
	return 0;
}
static int generateKey(PCStr(arg),PVStr(skey),int ssiz){
	IStr(userdom,MaxHostNameLen);
	IStr(nonce,128);
	IStr(key,36);
	IStr(ekey,36);
	IStr(user,32);
	IStr(pass,64);
	IStr(dom,MaxHostNameLen);
	const char *dp;
	int sec,usec;
	int ki;
	int iuid;

	if( strneq(arg,"-KG",3) ){
		if( arg[3] ){
			strcpy(userdom,arg+3);
			dp = wordScanY(userdom,user,"^@");
			if( *dp == '@' ){
				strcpy(dom,dp+1);
			}
			if( strchr(user,':') ){
			}
		}
	}
	NonceKey(AVStr(nonce));
	sec = Gettimeofday(&usec);
	usec = usec >> 4;
	iuid = getuid();

	key[0] = iuid;
	key[1] = iuid >> 8;

	key[2] = usec;
	key[3] = usec >> 8;
	key[4] = sec;
	key[5] = sec >> 8;
	key[6] = sec >> 16;
	key[7] = sec >> 24;
	key[8] = 0;
	key[9] = 0;
	for( ki = 10; ki < sizeof(key); ki++ ){
		key[ki] = userdom[ki-10];
	}
	enCreysX("b",nonce,key,sizeof(key),AVStr(skey),ssiz);
	if( userdom[0] ){
		if( user[0] ){
			strcat(skey,".");
			strcat(skey,user);
		}
		if( dom[0] ){
			strcat(skey,"@");
			strcat(skey,dom);
		}
	}
	return 1;
}
static int updateKey(PVStr(skey),int ssiz){
	return 0;
}

static void putYYSHhelp(int ac,const char *av[]){
printf(": ////////////////////////////// 2010/03/27 Y.Sato @ @ AIST.Gov.Japan\r\n");
printf(":  Yet another remote shell on the top of YYMUX   ( - ) {%s,%s} \r\n",myYYSHVER,myYYVER);
printf(":  Usage:                                        _<   >_ \r\n");
printf(":    server                                              \r\n");
printf(":      Serv%% delegated SERVER=yysh -P6023               \r\n");
printf(":    client\r\n");
printf(":      Clnt%% delegated -Fyysh Serv[:Port][/Dir] [Options] [Remote-command]\r\n");
printf(":  Options:\r\n");
printf(":    -p Port  the port number of the server other than 6023 (or -pPort)\r\n");
printf(":    -d Dir   the initial directory on the server (or -dDir)\r\n");
printf(":    -b Str   send Str to the remote shell on the beginning (or -bStr)\r\n");
printf(":    -j[uesj] convert Japanese char. code (to display) to utf-8, EUC-JP or so\r\n");
printf(":    -yi      show YYSH status info. on login, resumption and logout\r\n");
printf(":    -yj      show the negotiation dialog on the YYSH/YYMUX protocol\r\n");
printf(":    -yl      logging YYSH display output (to ./yysh-disp-md-HM.log)\r\n");
printf(":    -yc      apply Credhy encryption to YYSH\r\n");
printf(":    -ys      apply SSL encryption to YYSH (with the OpenSSL lib.)\r\n");
printf(":    -yz      apply Zlib compression (deflate) to YYSH\r\n");
printf(":    -yy      enable YYMUX multiplexing and connection persistency\r\n");
printf(":    -yx      enable X Window proxy\r\n");
printf(":    -yf      enable forwarding to remote proxies (-yfd -yff -yfh -yfs -yfv)\r\n");
printf(":    -yfd[:Map] enable DNS server/proxy at the server side\r\n");
printf(":    -yff[:Map] enable FTP server/proxy at the server side\r\n");
printf(":    -yfh[:Map] enable HTTP server/proxy at the server side\r\n");
printf(":    -yfm[:Map] enable SMTP proxy at the server side\r\n");
printf(":    -yfp[:Map] enable POP proxy at the server side\r\n");
printf(":    -yfs[:Map] enable SOCKS proxy at the server side\r\n");
printf(":    -yfv[:Map] enable VNC proxy\r\n");
printf(":    -yf:Map    add port forwarding\r\n");
printf(":    Map        [localPort][/localHost][:[remotePort][/remoteHost]]\r\n");
printf(":    Port       portNumber[.udp]\r\n");
printf(":  Remote-command:\r\n");
printf(":    .lst Remote-dir\r\n");
printf(":    .get [Local-file] Remote-file\r\n");
printf(":    .put Local-file [Remote-File]\r\n");
printf(":    other commands available on the server\r\n");
printf(":  Optional parameters:\r\n");
printf(":    AUTHORIZER,MYAUTH,PERMIT,REJECT,SOCKS,STLS,YYMUX,YYCONF,DGROOT\r\n");
printf(": ///////////////////////////////////////////////////////////////////\r\n");
}

/*
 * YYKEY -- [proto://][user:]Y.XXXXXXXX[@host[:port][/path]]
 * Y -- type of the key {0,1,r}
 * XXXX -- encrypted key in hexa-decimal
 */
static int scan_keyopts(MuxCtx *Mc,PCStr(aarg)){
	const char *arg = aarg;
	IStr(skey,1024);
	int rcode;
	const char *argK;

	if( *arg != '-' )
		return 0;
	arg++;
	if( *arg == 'y' )
		arg++;
	if( *arg != 'K' && *arg != 'k' )
		return 0;
	argK = arg;
	arg++;

	if( MxRSA == 0 ){
		MxRSA = _RSA_new();
	}
	switch( *arg ){
		case 'I': /* initial setup of secret-keys (cannot be changed) */
			_RSA_newkey(MxRSA);
			break;
		case 'P': /* change passphrase for the secret-keys and IDKey */
			_RSA_chpass(MxRSA);
			break;
		case 'q': /* verify RSA key */
 {
 IStr(fex,1024);
 IStr(ey,1024);
 int dlen;
 int flen;
 flen = hextoStr(arg+1,AVStr(fex),sizeof(fex));
 dlen = _RSA_decrypt(MxRSA,fex,flen,AVStr(ey),sizeof(ey),0);
 fprintf(stdout,"Decrypt: %s\n",ey);
 }
			break;
		case 'r': /* issue RSA key */
			if( _RSA_avail(MxRSA) == 0 ){
				_RSA_newkey(MxRSA);
				if( _RSA_avail(MxRSA) == 0 ){
					fprintf(stderr,"RSA failed\n");
					exit(-1);
				}
			}
 {
 IStr(ex,1024);
 IStr(xex,1024);
 IStr(fex,1024);
 IStr(ey,1024);
 int elen;
 int dlen;
 int flen;
 elen = _RSA_encrypt(MxRSA,arg+1,strlen(arg+1),AVStr(ex),sizeof(ex),0);
 strtoHex(ex,elen,AVStr(xex),sizeof(xex));
 flen = hextoStr(xex,AVStr(fex),sizeof(fex));
 dlen = _RSA_decrypt(MxRSA,fex,flen,AVStr(ey),sizeof(ey),0);
 fprintf(stderr,"Source: %s\n",arg+1);
 fprintf(stderr,"Decrypt: %s\n",ey);
 fprintf(stdout,"%s:r:%s\n",xex,arg+1);
 }
			break;
		case 'G':
			generateKey(aarg,AVStr(skey),sizeof(skey));
			printf("%s\n",skey);
			verifyKey(skey,skey);
			break;
		case 'A': /* Approve or Update */
			break;
		case 'V': /* Verify */
			rcode = verifyKey(aarg,arg+1);
			exit(rcode);
			break;
		case 'S': // store a key to be sent automatically (user:rand+key@domain)
			break;
		case 's': // send a key to the server
			//strcpy(MxAuthKey,arg+1);
			break;
		case 'd': /* @domain to be sent Authenticate: YYKey realm=domain */
			//strcpy(MxAuthDomain,arg+1);
			break;
		case 'v': /* verify the IDKey in Authorization: YYKey IDKey */
			MxAuthFlags |= MA_YYKEY;
			break;
	}
	if( *argK == 'K' ){
		exit(0);
	}
	return 0;
}
static int scanYyshArgs(MuxCtx *Mc,yyshCtx *Yc,int ac,const char *av[]){
	int ai;
	const char *a1;
	refQStr(ap,YxCmdb);
	int myopts = 1;
	int localcom = 0;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( isDGARGS(MxConn,av,ai) ){
			continue;
		}
		if( myopts ){
		    if( *a1 == ':' ){
			/* local command ? local options ? */
			localcom = 1;
		    }
		    if( *a1 == '|' ){
			/* pipe to a local command ? */
			localcom = 1;
		    }
		    if( *a1 == '-' ){
			if( strcaseeq(a1,"-help") ){
				putYYSHhelp(ac,av);
				exit(0);
			}
			switch( a1[1] ){
			    case 0:
			    case ':':
				myopts = 0;
				/* or local command spec. ? */
				continue;
			    case 'f':
				if( a1[2] == 'v' ){
					LOG_type |= L_CONSOLE; break;
				}
				break;

				/*
			    case 'I': // local "< file"
				break;
			    case 'O': // local "> file"
				break;
				*/
			    case 'K':
			    case 'k':
				scan_keyopts(Mc,a1);
				break;
			    case 't':
				switch( a1[2] ){
				  case 'i':
					YxKAIntvl = atoi(a1+3);
					break;
				default:
				YxTmout = Scan_period(a1+2,'s',(double)0);
					break;
				}
				break;
			    case 'l':
				if( a1[2] ){ strcpy(YxUser,a1+2); }else
				if( av[ai+1] ){ ai++; strcpy(YxUser,av[ai]); }
				break;
			    case 'h':
				if( a1[2] ){ strcpy(YxHost,a1+2); }else
				if( av[ai+1] ){ ai++; strcpy(YxHost,av[ai]); }
				break;
			    case 'p':
				if( a1[2] ){ YxPort = atoi(a1+2); }else
				if( av[ai+1] ){ ai++; YxPort = atoi(av[ai]); }
				break;
			    case 'd':
				if( a1[2] ){ strcpy(YxWdir,a1+2); }else
				if( av[ai+1] ){ ai++; strcpy(YxWdir,av[ai]); }
				break;
			    case 'b':
				if( a1[2] ){ strcpy(YxProl,a1+2); }else
				if( av[ai+1] ){ ai++; strcpy(YxProl,av[ai]); }
				break;
			    case 'c':
				/* begining of remote command */
				myopts = 0;
				continue;
			    case 'j':
				setCCX(Mc,Yc,a1);
				break;
			    case 'y':
				MxFlags = scan_yopts(Mc,MxConn,MxFlags,a1);
				break;
			    case 'n':
				switch( a1[2] ){
				    case 'w': /* emulate WinSock */
					YxFlag ^= YF_NOSSOCK;
					break;
				    case 't':
					YxFlag ^= YF_NOTTY;
					break;
				    case 's':
					YxFlag ^= YF_SUTTY;
					break;
				    case 'p':
					YxFlag ^= YF_SUACC;
					break;
				    case 'x':
					YxFlag ^= YF_SUSELF;
					break;
				}
				break;
			}
		    }else{
			if( (YxFlag & YF_HOSTSET) == 0 ){
				YxFlag |= YF_HOSTSET;
				scanYYSHhost(Mc,Yc,a1);
			}else{
				myopts = 0;
			}
		    }
		}
		if( myopts == 0 ){
			if( YxAc < elnumof(YxAv) ){
				YxAv[YxAc++] = MxStralloc(Mc,a1);
			}
			if( YxCmdb[0] == 0 ){
				strcpy(YxCmdb,a1);
				ai += scanArg1(Mc,Yc,ac-ai,av+ai);
			}
		}
	}
	return 0;
}
static int flushinbuf(FILE *ifp,int out){
	FILE *ofp = fdopen(out,"a");
	int ch;

	if( ofp == NULL ){
		fprintf(stderr,"--flushinbuf FATAL cannot open for write[%d]\n",out);
		return -1;
	}
	while( 0 < ready_cc(ifp) ){
		ch = getc(ifp);
		if( ch == EOF ){
			break;
		}
		putc(ch,ofp);
	}
	fflush(ofp);
	fcloseFILE(ofp);
	return 0;
}
static int relay2fC(CCXP ccxCL,CCXP ccxSV,int fromC,int toC,FILE *fs,FILE *ts){
	flushinbuf(fs,toC); /* with CCX ... */
	relay2C(ccxCL,ccxSV,fromC,toC,fileno(fs),fileno(ts));
	return 0;
}
static int relay2f(int fromC,int toC,FILE *fs,FILE *ts){
	flushinbuf(fs,toC);
	relay2C(NULL,NULL,fromC,toC,fileno(fs),fileno(ts));
	return 0;
}
static int relayYYSH(MuxCtx *Mc,yyshCtx *Yc,int fromC,int toC,FILE *fs,FILE *ts){
	Connection *Conn = YxConn;
	CCXP ccx[2];
	FILE *fc = fdopen(fromC,"r");
	FILE *tc = fdopen(toC,"a");
	FILE *fv[2];
	int rv[2];
	int ch;
	int tccol = 0;
	void *tty = 0;
	int flushing = 0;
	int nready;
	double LastActive = Time();
	double Idle = 0;
	int row0,col0,row,col;
	int ctrlC = 0;
	double ctrlCSt = 0;
	IStr(line,2*1024);
	IStr(xline,8*1024);
	int icc,occ,wcc;
	int rcode;
	int pch = -1;
	int numINTR = 0;
	double prevKey = 0;
	double prevDisp = 0;
	double Now;
	char obuf[16*1024];
	setvbuf(tc,obuf,STDIO_IOFBF,sizeof(obuf));

	tty = dumpTTyStat(0);
	if( MxSttyRaw[0] ){
		rcode = system(MxSttyRaw);
	}else{
		rcode = system("stty raw -echo");
	}
	setTTyMode(0,"raw");
	setTTyMode(0,"-echo");

	fv[0] = fc;
	fv[1] = fs;
	ccx[0] = CCXactive((CCXP)YxCCxSV)?(CCXP)YxCCxSV:0;
	ccx[1] = CCXactive((CCXP)YxCCxCL)?(CCXP)YxCCxCL:0;

	getTTySize(0,&col0,&row0); /* should watch SIGWINCH */
	/*
	sendTTySize(ts,col0,row0);
	fflush(ts);
	*/

	if( YxProl[0] ){
		IStr(prol,1024);
		strcpy(prol,YxProl);
		strsubst(AVStr(prol),"%r","\r");
		strsubst(AVStr(prol),"%n","\n");
		fprintf(ts,"%s\n",prol);
		fflush(ts);
	}
	for(;;){
		if( fPollIns(TIMEOUT_IMM,2,fv,rv) == 0 ){
			fflush(tc);
			fflush(ts);
		}
		for(;;){
			nready = fPollIns(1000,2,fv,rv);
			Now = Time();
			Idle = Now - LastActive;
			if( 0 < nready ){
				LastActive = Now;
				break;
			}
			if( nready < 0 ){
 sv1log("--yysh rdy=%d e%d SIG=%d PIPE=%d\n",
	nready,errno,yy_gotSIG,yy_nsigPIPE);
				if( 1 < yy_gotSIG ){
					goto EXIT;
				}
				continue;
			}
			getTTySize(0,&col,&row);
			if( col != col0 || row != row0 ){
 porting_dbg("-- rdy=%d %dx%d <= %dx%d",
	nready,col,row,col0,row0);
				sendTTySize(ts,col,row);
				fflush(ts);
				col0 = col;
				row0 = row;
			}
			else
			/* v9.9.10 new-140626b  sending TTySize packet
			 * periodically for keep-alive the connection.
			 */
			if( ((int)(Idle)) % YxKAIntvl == 0 ){
				sendTTySize(ts,col,row);
				fflush(ts);
 porting_dbg("-- rdy=%d %dx%d sent-for-keep-alive, idle=%4.1f",
	nready,col,row,Idle);
			}

			if( 0 < YxTmout ){
			    Now = Time();
			    if( YxTmout < Now-prevKey
			     && YxTmout < Now-prevDisp
			    ){
 fprintf(stderr,"~~~~ TIMEOUT: K%.1f D%.1f [%d][%s]\r\n",
	Now-prevKey,Now-prevDisp,getpid(),MxDstHost);
				tccol = 0;
				goto EXIT;
			    }
			}
		}
		/*
		if( fPollIns(0,2,fv,rv) <= 0 ){
			break;
		}
		*/
		if( rv[0] ){
			ch = getc(fc);
			if( ch == EOF ){
				break;
			}
			MxIO.sent++;
			if( ch == '~' ){
				/* should care ~. ~^Z locally */
			}
			if( ch == '.' ){
				if( pch == '~' ){
					double St1;
					double St2;

					/* if without echo to the '~'.
					 * to break frozen connection without
					 * knowning the cuurent tty status
					 */
					St1 = Time();
					if( prevDisp <= prevKey )
					if( 1.0 < Time()-prevDisp )
					if( fPollIn(fs,300) == 0 )
					{
						/* '~' not echoed */
						putc('.',ts);
						fflush(ts);
						St2 = Time();
						if( fPollIn(fs,300) <= 0 ){
 sv1log("--yysh no-echo ~. (%.3f %.3f K=%.3f D=%.3f)\n",Time()-prevDisp,
	prevKey-prevDisp,prevKey,prevDisp);
							break;
						}else{
 sv1log("--yysh echo for ~. (%.3f %.3f)'\n",Time()-St1,Time()-St2);
						}
						continue;
					}
				}
			}
			if( ch == YxSvINTR ){
				int omf = MxFlags;

				MxFlags |= MX_VV_TOMUX;
				if( putc(ch,ts) == EOF ){
 fprintf(stderr,"\r\n(disconn.-1)\r\n");
					break;
				}
				fflush(ts);
				numINTR++;
				yy_showStats++;
 sv1log("----CTRL-C #%d (%d)(%.2f) f%d SIG=%d IoStat{%s}\n",numINTR,ctrlC,
	0<ctrlCSt?Time()-ctrlCSt:0,fPollIn(fs,1),yy_gotSIG,IoStat);
				ctrlC++;
				if( ctrlCSt == 0 ){
					ctrlCSt = Time();
				}
				/* send in OOB ? IAC/Telnet ? */
				/* if not ^V ^C */
				/* suppress CL-SV */
				/* flush pending SV-CL */
				/* and resume */
				flushing = 1;
				if( 3<ctrlC && 0<ctrlCSt && 1<Time()-ctrlCSt ){
					if( fPollIn(fs,100) == 0 ){
						/* repetitive ^C for ~. */
						break;
					}
				}
				pch = ch;
				fPollIn(fc,300);
				MxFlags = omf;
				continue;
			}else{
				if( putc(ch,ts) == EOF ){
 fprintf(stderr,"\r\n(disconn.-2)\r\n");
					break;
				}
				ctrlC = 0;
				ctrlCSt = 0;
				pch = ch;
				if( ready_cc(fc) <= 0 ){
					fflush(ts);
					prevKey = Time();
				}
			}
		}
		if( rv[1] ){
			ctrlC = 0;
			ctrlCSt = 0;
			errno = 0;
			ch = getc(fs);
			if( ready_cc(fs) <= 0 ){
				prevDisp = Time();
			}
			if( ch == EOF ){
 sv1log("--yysh SV EOS [%c] r%d E%d e%d\n",ConnType?ConnType:' ',
	rv[1],feof(fs),errno);
				break;
			}
			if( YxLogFp ){
				putc(ch,YxLogFp);
				if( ready_cc(fs) <= 0 ){
					fflush(YxLogFp);
				}
			}
			MxIO.recv++;
			if( ccx[1] ){
				line[0] = ch;
				icc = fgetBuffered(DVStr(line,1),sizeof(line)-1,fs);
				if( 0 < icc ){
					if( YxLogFp ){
						fwrite(line+1,1,icc,YxLogFp);
					}
					icc += 1;
				}else{
					icc = 1;
				}
				occ = CCXexec(ccx[1],line,icc,
					AVStr(xline),sizeof(xline));
				wcc = fwrite(xline,1,occ,tc);
				if( strtailstr(xline,"\r\n")
				 || strtailstr(xline,"\r") )
					tccol = 0;
				else	tccol = 1;
			}else
			if( putc(ch,tc) == EOF ){
 fprintf(stderr,"\r\n(disconnected-2)\r\n");
				break;
			}
			if( ch == '\r' ){
				tccol = 0;
			}else{
				tccol++;
			}
			if( ready_cc(fs) <= 0 ){
				fflush(tc);
			}
		}
	}
EXIT:
	if( tccol != 0 ){
		fprintf(tc,"\r\n");
	}
	fflush(tc);
	fcloseFILE(fc);
	fcloseFILE(tc);

	setTTyMode(0,"echo");
	setTTyMode(0,"-raw");
	rcode = system("stty -raw echo");
	restoreTTyStat(0,tty);
	freeTTyStat(tty);
	return 0;
}

static void cumZS(PCStr(wh),MuxCtx *Mc,ZStat *Zs){
	IStr(stat,128);
	refQStr(sp,stat);

	Zs->zs_lototal += MxZ1.zs_lototal;
	Zs->zs_zitotal += MxZ1.zs_zitotal;
	Zs->zs_zototal += MxZ1.zs_zototal;
	Zs->zs_litotal += MxZ1.zs_litotal;

	if( Mc->mc_ilen ){
		Rsprintf(sp," recv %u",ll2i(Mc->mc_ilen));
	}
	if( MxZ1.zs_lototal ){
		Rsprintf(sp," (%u / %u.z %.1f%%)",
			MxZ1.zs_lototal,MxZ1.zs_zitotal,
			100.0*MxZ1.zs_zitotal/MxZ1.zs_lototal);
	}
	if( Mc->mc_olen ){
		Rsprintf(sp," sent %u",ll2i(Mc->mc_olen));
	}
	if( MxZ1.zs_litotal ){
		Rsprintf(sp," (%u / %u.z %.1f%%)",
			MxZ1.zs_litotal,MxZ1.zs_zototal,
			100.0*MxZ1.zs_zototal/MxZ1.zs_litotal);
	}
 if( stat < sp )
 yprintf(Mc,"---- %s:%s",wh,stat);
}

static void printFwdPort1(PortMap1 *P1,PCStr(wh)){
	if( P1->pm_local.p1_port == 0 ){
		return;
	}
	fprintf(stderr,":::: %s port: %d%s",wh,P1->pm_local.p1_port,
		P1->pm_local.p1_flags&P1_UDP?".udp":"");
	if( P1->pm_remote.p1_port ){
		fprintf(stderr," => %s:%d",
			P1->pm_remote.p1_host,P1->pm_remote.p1_port);
	}
	fprintf(stderr,"\r\n");
}
static void printFwdPorts(MuxCtx *Mc){
	printFwdPort1(&MxPmapDns,"DNS");
	printFwdPort1(&MxPmapVnc,"VNC");
	printFwdPort1(&MxPmapFtp,"FTP");
	printFwdPort1(&MxPmapPop,"POP");
	printFwdPort1(&MxPmapSmtp,"SMTP");
	printFwdPort1(&MxPmapHttp,"HTTP");
	printFwdPort1(&MxPmapSocks,"SOCKS");
}

#define MX_WITH_YYANY (\
 MX_WITH_DNS|\
 MX_WITH_VNC|\
 MX_WITH_FTP|\
 MX_WITH_POP|\
 MX_WITH_SMTP|\
 MX_WITH_HTTP|\
 MX_WITH_SOCKS|\
 MX_WITH_PMAP)

int yysh_main(int ac,const char *av[],Connection *Conn){
	MuxCtx *Mc;
	yyshCtx YcBuf,*Yc;
	double mxStart;
	MuxCtx *pMc = 0;
	MuxCtx *sMc = 0;
	int ysock = -9;
	int rcode = 0;
	FILE *fs = 0;
	FILE *ts = 0;
	FILE *nfs;
	int bch = EOF;
	int withSTLS = -1;
	IStr(xdisp,128);
	int mc_lcsock = -1;
	int yyid;
	IStr(displfile,256);
	int YYsock = -1;
	int ZCsock = -1;
	int Vport = 0;
	int Vflags = 0;
	PortMaps maps;
	int willSSL = 0;
	double St;

	if( ac < 2 || strcaseeq(av[1],"-help") ){
		putYYSHhelp(ac,av);
		return 0;
	}

	mxStart = Time();
	Mc = initgMc(Conn);
	if( MxRsmholdSet == 0 ){
		MxRsmhold = 12*60*60;
	}
	MxStart = mxStart;

	Yc  = newYYSH(&YcBuf,Conn);
	scanYyshArgs(Mc,Yc,ac,av); /* set gMc (global/default MuxCtx) */

	bzero(&maps,sizeof(maps));
	if( 1 ){ /* to be done in the inner YYMUX */
		if( Vflags = MxFlags & MX_WITH_YYANY ){
			MxFlags &= ~Vflags;
			MxFlags |= MX_WITH_YYM;
			maps = Mc->mc_portmap;
			bzero(&Mc->mc_portmap,sizeof(Mc->mc_portmap));
		}
	}
	Mc = newYY(Conn,ET_CLNT);
	MxStart = mxStart;

	if( MxFlagsINTERACT ){
		fprintf(stderr,"---- yysh host [%s] = {%s:%s@ %s :%d.%s/%s}\n",
			YxDest,YxUser,YxPass,YxHost,YxPort,YxOpts,YxWdir);
	}
	/*
	fprintf(stderr,"----Client[%d][%d]\n",FromC,ToC);
	*/
	if( FromC < 0 ){
		FromC = 0;
		/* SIGINT=>^C SIGTSTP=>^Z ~CH=>interpret */
	}
	if( ToC < 0 ){
		ToC = 1;
	}

	set_realserver(Conn,"yysh",YxHost,YxPort);
	proc_title("yysh %s:%d (connecting)",YxHost,YxPort);
	Conn->from_myself = 1;
	if( MxFlagsINTERACT ){
		IStr(date,64);
		int col=0,row=0;
		getTTySize(0,&col,&row);
		StrftimeLocal(AVStr(date),sizeof(date),"%H:%M:%S %a %d/%b",time(0),0);
 fprintf(stderr,"----  @ @ connecting to yysh://%s:%d ... [%d]\n",YxHost,YxPort,uGetpid());
 fprintf(stderr,"---- ( - ) %s {DeleGate/%s} %dx%d\n",date,DELEGATE_ver(),col,row);
	}
	if( 1 ){
		yyid = STX_yy;
		STX_yy = 0; /* for -yyco not to clear in YY_connect() */
	}
	if( needSTLS_SVi(Conn,ysock,"yysh")
	 || (ConnectFlags = scanConnectFlags("yysh",YxOpts,ConnectFlags))
	){
		willSSL = 1;
	}
	/*
	ysock = connect_to_serv(Conn,FromC,ToC,0);
	*/
	St = Time();
	ysock = connect_to_serverY(Conn,Mc,DST_PROTO,DST_HOST,DST_PORT,
		FromC,ToC,0);
	if( 1 ){
		STX_yy = yyid;
	}
	Mc = getLastMc(Conn);
	if( ToS < 0 ){
		fprintf(stderr,"---- cannot connect. orz..\n");
		return -1;
	}
	if( MxFlagsYYACTIVE ){
		sv1log("##Y%d [%d][%c] YYSH SF=%X\n",
			MxId,ysock,ConnType?ConnType:' ',ServerFlags);
		YYsock = ysock;
	}
	if( willSSL ){
		int fsv;
		fsv = insertTLS_SVi(Conn,ClientSock,ysock,"yysh");
		if( 0 <= fsv ){
			dup2(fsv,ysock);
			close(fsv);
		}else{
			fprintf(stderr,"---- willSSL=%d Failed (%.3f)\r\n",
				willSSL,Time()-St);
		}
	}

	getTTyStat(0,MxTtystat,sizeof(MxTtystat));
	ts = fdopen(ToS,"w");
	fs = fdopen(FromS,"r");
setbuffer(fs,0,0); /* yysh-client */

	if( 1 ){ /* MYAUTH */
		scanYyshR(Mc,Yc,fs); /* greeting message with CredhyKey */
		sendYyshQ(Mc,Yc,ts,0); /* my request */
	}else
	if( PollIn(FromS,30) ){
		scanYyshR(Mc,Yc,fs); /* greeting message */
		sendYyshQ(Mc,Yc,ts,0); /* my request */
	}else{
		sendYyshQ(Mc,Yc,ts,0); /* my request */
		scanYyshR(Mc,Yc,fs); /* greeting message */
	}
	scanYyshR(Mc,Yc,fs); /* response to my request */
	if( !strcaseeq(myYYSHVER,YxSvVer) ){
		fprintf(stderr,"---- Bad YYSH Version: '%s'(%s) me(%s)\n",
			YxSvVer,YxSvSoft,myYYSHVER);
		/*
		goto EXIT;
		*/
	}
	if( MxServcode == 401 ){
		retryAuthQ(Mc,Yc,ts,fs);
		if( MxServcode == 100 ){
			/* this indicates the success of retryAuthQ() */
			scanYyshR(Mc,Yc,fs);
		}
	}
	if( MxServcode <= 0 || 400 <= MxServcode ){
		if( MxFlagsINTERACT ){
			fprintf(stderr,"----_<   >_ Error. (%.3f) %s\n",
				Time()-MxStart,MxServstat);
		}else{
			fprintf(stderr,">>>> %s\r\n",MxServstat);
		}
		fprintf(stderr,"\n");
		rcode = -2;
		goto EXIT;
	}

	pMc = Mc;
	/* start YYMUX here if necessary */
	if( MxServcode == 101 && strheadstrX(MxUpgrade,"YYMUX/",1) ){
		MuxCtx *Mc;
		int yyid;
		int yysock;
		double St = Time();

		yyid = STX_yy;
		STX_yy = 0;
		Mc = newYY(Conn,ET_CLNT);
		MxStart = mxStart;
		sMc = Mc;
		sv1log("--------1---Upgrade CL connection to YYMUX\n");
		clearVStr(MxServstat);

		strcpy(MxServ,DST_HOST);
		MxServport = DST_PORT;
		saveYYserver(Mc,"yymux",DST_HOST,DST_PORT);
		MxFlags ^= MX_SHUTIMM;
		MxFlags |= Vflags;
		MxRsmkey ^= trand1(0xFFFFFFFF);
		MxDebug = 2;
		Mc->mc_portmap = maps;
		if( pMc ){
			MxFlags |= (pMc->mc_flags & MX_CREDHY);
			MxFlags |= (pMc->mc_flags & MX_DEFLATE);
		}
		yysock = insertMuxCL(Mc,Conn,mc_lcsock,fileno(ts),ts,fs,1,0);
		sv1log("--------2---Upgraded the conn. to YYMUX (#%d #%d)\n",
			yyid,STX_yy);
		STX_yy = yyid;
		if( yysock < 0 ){
			//salvageClnt(Mc,CST_CLEARED,MxRsmport,MxRsmkey);
		}
		if( MxFlagsINTERACT ){
			IStr(msg,128);
			sprintf(msg,"inserted %s (%.3f)",myYYVER,Time()-St);
			YYlogComm(Mc,"----","yysh",msg);
		}
		strcpy(xdisp,MxServDISPLAY);
		if( pMc ){
			if( pMc->mc_flags & MX_YYACTIVE ){
				pMc->mc_flags |= MX_HOLDONNX;
				sendREQ(pMc,"HOLDONNX=on");
 sv1log("##sent PY_REQ HOLDONNX=on %X\n",p2i(pMc));
			}
			scanYyshR(pMc,Yc,fs);
		}
	}
	if( MxFlagsSTLS && MxServcode == 101 && strneq(MxUpgrade,"SSL",3) ){
		int fsv;
		sv1log("----START TLS@CL A %X[%d]\n",ServerFlags,ServerSockX);
		fsv = insertFSVF(Conn,-1,fileno(ts),"sslway -co");
		sv1log("----START TLS@CL B %X[%d]\n",ServerFlags,fsv);
		sv1log("----START TLS [%d][%s][%s] [%d]\n",
			MxServcode,MxServstat,MxUpgrade,fsv);
		if( 0 <= fsv ){
			ToSX = ToS;
			ToS = FromS = fsv;
			fcloseFILE(ts);
			fcloseFILE(fs);
			ts = fdopen(FromS,"w");
			fs = fdopen(FromS,"r");
setbuffer(fs,0,0); /* yysh-client STLS */
			withSTLS = fsv;
		}else{
			/* close the YYMUX connection */
		}
		scanYyshR(Mc,Yc,fs);
	}
	if( MxServcode == 101 && strheadstrX(MxUpgrade,ZCredhy,1) ){
		int fsv = -1;
		int tsd;

		sv1log("----Credhy Start CL\n");
		tsd = fileno(ts);
		fsv = insertZCredhy(Mc,fileno(fs),XF_FSV);
		ZCsock = fsv;
		if( 0 <= fsv ){
			if( 1 ){ /* necessary to SSL + Credhy + YYMUX_RSM */
				/* "was" necessary in pre26 where SSL is after Credhy ? */
				if( ToS == fileno(fs) ){
					/* this is passed as the end-point of ZCredhy */
					/* thus must not be closed as ToSX in clearSSLway */
				}else{
				ToSX = ToS;
				}
				ToS = FromS = fsv;
			}
			fcloseFILE(ts);
			fcloseFILE(fs);
			ts = fdopen(fsv,"w");
			fs = fdopen(fsv,"r");
setbuffer(fs,0,0); /* yysh-client Credhy */
			if( 1  ){
		//YYdisableZ1(Mc,tsd); /* disable duplicated & genefic zip */
			}
		}
		scanYyshR(Mc,Yc,fs);
	}
	/*
	if( MxServcode == 100 || MxServcode == 101 ){
		scanYyshR(Mc,Yc,fs);
	}
	*/
	if( MxFlagsWITH_Y11 ){
		/* 6000 causes loop on the same host without X serv.
		mc_lcport = 6001;
		mc_lcsock = createYdisp(AVStr(mc_lchost),&mc_lcport);
		if( 0 <= mc_lcsock ){
			FD_new(mc_lcsock,"clntYdisp",0);
		}
		sprintf(lcenv,"DISPLAY=%s:%d.0",mc_lchost,mc_lcport-6000);
		YYpushenv(Mc,lcenv);
		*/
	}
	if( MxServcode == 100 || MxServcode == 101 ){
		scanYyshR(Mc,Yc,fs);
	}

	if( MxFlagsINTERACT ){
 fprintf(stderr,"----_<   >_ connected (%.3f)",Time()-MxStart);
		if( MxSSLok || (ServerFlags & PF_SSL_ON) ){
 fprintf(stderr,"((with SSL))");
		}
		if( YxCmdb[0] == 0 ){ /* wait prompt */
			fflush(stderr);
			fPollIn(fs,5*1000);
			fprintf(stderr,"(%.3f)",Time()-MxStart);
		}
 fprintf(stderr,"\r\n");
	}
	if( MxFlagsISILENT == 0 ){
		if( sMc ){
			printFwdPorts(sMc);
		}
		if( sMc ){
			dumpPortMaps(sMc);
		}
		dumpPortMaps(Mc);
	}
	if( MxFlagsINTERACT ){
		if( YxSvSoft[0] ){
 fprintf(stderr,"~~~~ %s\r\n",YxSvSoft);
		}
 fprintf(stderr,"~~~~ %s [%s <= %s]\r\n",YxSvDate,YxSvClif,YxSvClnt);
 fprintf(stderr,"~~~~ %s@%s%s%s",YxSvUser,YxSvHost,
	YxSvWdir[0]=='/'?"":"/",YxSvWdir);
		if( xdisp[0] ){
			fprintf(stderr," DISPLAY=%s",xdisp);
		}
		fprintf(stderr,"\r\n");
	}

	if( 0 < ready_cc(fs) ){
		/* Win */
		bch = getc(fs);
	}
	/* let fs be buffered */
	nfs = fdopen(fileno(fs),"r");
	fcloseFILE(fs);
	fs = nfs;
	if( bch != EOF ){
		ungetc(bch,fs);
	}

	proc_title("yysh %s:%d",YxHost,YxPort);
	if( YxLfmod ){
		FILE *fp = 0;
		/* open the file and redirect */
		if( YxLfmod & FM_READ ){
			if( fp = fopen(YxLfile,"r") ){
				FromC = fileno(fp);
				fcloseFILE(fp);
			}else{
			}
		}else
		if( YxLfmod & FM_WRITE ){
			if( File_is(YxLfile) ){
				/* warning and Q/A */
				/* rename it to YxLfile~ */
 fprintf(stderr,"~~~~yy get to local: %s\n",YxLfile);
			}
			if( fp = fopen(YxLfile,"w") ){
				ToC = fileno(fp);
				fcloseFILE(fp);
			}else{
			}
		}
	}
	if( YxCmdb[0] ){
		if( MxFlagsINTERACT ){
			fprintf(stderr,"---- Command: %s\r\n",YxCmdb);
		}
		fprintf(stderr,"\r\n");
		relay2fC((CCXP)YxCCxCL,(CCXP)YxCCxSV,FromC,ToC,fs,ts);
	}else{
		if( MxFlagsLOG_YYSH ){
			/* might be sent via UDP with encryption */
			StrftimeLocal(AVStr(displfile),sizeof(displfile),
				"yysh-disp-%m%d-%H%M.log",time(0),0);
			YxLogFp = fopen(displfile,"a");
			if( YxLogFp ){
				IStr(date,128);

				fclose(YxLogFp);
				chmod(displfile,0600);
				YxLogFp = fopen(displfile,"a");
				fprintf(YxLogFp,"-----BEGIN YYSH %s %s:%d\r\n",
					stimes(1),DST_HOST,DST_PORT);
				getYYdate(AVStr(date),sizeof(date),1);
				fprintf(YxLogFp,"Y-Date: %s\r\n",date);
				fprintf(YxLogFp,"\r\n");
				fprintf(stderr,"~~~~ ## logging to %s\r\n",
					displfile);
			}else{
			}
		}
		if( MxFlagsINTERACT ){
			fprintf(stderr,"\r\n");
		}
		relayYYSH(Mc,Yc,FromC,ToC,fs,ts);
	}
	if( YxLfmod ){
		/* set the modifiled time */
		if( YxLfmod & FM_WRITE ){
			if( isWindows() ){
				/* to get the file size by name */
				dupclosed(ToC);
			}
			fprintf(stderr,"~~~~yy got to local (%d) : %s\n",
				File_size(YxLfile),YxLfile);
		}
	}
	if( sMc ){
		MuxCtx *Mc = sMc;
		double St = Time();
		int rdy;

		sv1log("----Ending inner Y%d/%d\n",MxId,MxParentId);
		sendSHUT(Mc);
		MxDoupdate = "YYSH-Child-Ending";
		rdy = PollIn(fileno(fs),1000);
		sv1log("----Ended inner Y%d/%d r%d(%.3f)\n",MxId,MxParentId,
			rdy,Time()-St);
	}
	if( MxFlagsHOLDONNX ){
		MxFlags &= ~MX_HOLDONNX;
		MxDoupdate = "YYSH-Ending";
		sendREQ(Mc,"HOLDONNX=off");
		sendSHUT(Mc);
	}

	if( 0 <= ZCsock ){
		double St = Time();
		int alv = IsAlive(fileno(ts));
		shutdownWR(fileno(ts));
		popPFilter(Conn,10*1000,XF_FSV);
		sv1log("--ZCwait[%d] alv=%d (%.3f)\n",fileno(ts),alv,Time()-St);
	}
	if( MxFlagsINTERACT ){
		ZStat Zs = {0,0,0,0};

 sv1log("--Y%d SadEnd=%d SIG=%d PIPE=%d\n",MxId,MxSadEnd,yy_gotSIG,yy_nsigPIPE);
 fprintf(stderr,"\n");
 fprintf(stderr,"----  @%c@  ~~~~ %s (%.3f sec.) [%d] [%s:%d] Y%d\r\n",
	MxSadEnd?'"':' ',stimes(0),Time()-MxStart,
	getpid(),MxDstHost[0]?MxDstHost:DST_HOST,
	MxDstPort?MxDstPort:DST_PORT,MxId);
 fprintf(stderr,"---- ( %s )/~~~~ {Bye.}",MxSadEnd?"~":"-");

		if( MxIO.sent || MxIO.recv ){
 fprintf(stderr," (tty: recv %u, sent %u)",MxIO.recv,MxIO.sent);
		}
 fprintf(stderr,"\r\n");
		{
			cumZS("yysh",Mc,&Zs);
		}
		if( pMc && Mc != pMc ){
			cumZS("pmux",pMc,&Zs);
		}
		if( sMc ){
			cumZS("cmux",sMc,&Zs);
		}
		if( MxParent ){
			cumZS("pmux",MxParent,&Zs);
		}
		if( MxFlagsDEFLATE1 ){
			double Rr = 100;
			double Rs = 100;
			if( Zs.zs_lototal ){
				Rr = (100.0 * Zs.zs_zitotal) / Zs.zs_lototal;
			}
			if( Zs.zs_litotal ){
				Rs = (100.0 * Zs.zs_zototal) / Zs.zs_litotal;
			}
 fprintf(stderr,"----Zlib1: recv %u / %u.z (%.1f%%), sent %u.z / %u (%.1f%%)\n",
	Zs.zs_lototal,Zs.zs_zitotal,Rr,Zs.zs_zototal,Zs.zs_litotal,Rs);
 sv1log("----Zlib1: recv %u / %u.z (%.1f%%), sent %u.z / %u (%.1f%%)\n",
	Zs.zs_lototal,Zs.zs_zitotal,Rr,Zs.zs_zototal,Zs.zs_litotal,Rs);
		}
	}
	if( YxLogFp ){
		fprintf(stderr,"~~~~ ## logged to %s (%d bytes)\r\n",
			displfile,iftell(YxLogFp));
		fprintf(YxLogFp,"\r\n");
		fprintf(YxLogFp,"-----END YYSH %s %s:%d\r\n",
			stimes(1),DST_HOST,DST_PORT);
		fclose(YxLogFp);
		YxLogFp = 0;
	}

EXIT:
	if( 0 <= withSTLS ){
		if( IsAlive(withSTLS) ){
			shutdownWR(withSTLS);
		}
		close(withSTLS);
		withSTLS = -1;
	}
	if( MxShutting & YS_REMOTE ){
		/* if YYMUX finished normally with remote SHUT */
		salvageClnt(Mc,CST_CLEARED,MxRsmport,MxRsmkey);
	}
	if( MxFlagsYYACTIVE ){
		/*---- end yyMux ----*/
		finishServYY(FL_ARG,Conn);
	}
	if( fs ){
		fcloseFILE(fs);
	}
	if( ts ){
		fclose(ts);
	}
	sv1log("--yysh finished ---- %s:%d\n",DST_HOST,DST_PORT);
	return rcode;
}
