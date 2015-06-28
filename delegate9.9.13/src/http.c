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
Program:	http.c (HTTP/1.0 proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940316	created
	99Aug	restructured
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include "delegate.h"
#include "fpoll.h"
#include "file.h"
#include "auth.h"
#include "proc.h"
#include "filter.h"
#include "http.h"
#include "vsignal.h"

#if defined(_AIX) || defined(__hpux)
#define AVAIL_alloca 0
#define alloca(z) malloc(z)
#else
#define AVAIL_alloca 1
#endif

#define fcloseTIMEOUT(fp) fcloseTIMEOUT_FL(__FILE__,__LINE__,fp)
#define fflushTIMEOUT(fp) fflushTIMEOUT_FL(FL_ARG,fp)
#if !isWindowsCE()
#define fputs(s,f) Xfputs_FL(FL_ARG,s,f)
#endif
UTag UTset(const void *bp,int size);
#define UTonstack(siz) UTset(alloca(siz),siz)
int waitPreFilter(Connection *Conn,int msec);

int SINGLEP_LINGER = 5;

void fclosesX(Connection *Conn);
void addfcloseX(Connection *Conn,FILE *fp,const char *F,int L);
#define addfclose(fp)	addfcloseX(Conn,fp,__FILE__,__LINE__)
#define fcloses()	fclosesX(Conn)

#define MAX_VIALEN 512

static int _thfprintf(FILE *fp,PCStr(fmt),...){
	CStr(hmsg,1024);
	VARGS(8,fmt);

	sprintf(hmsg,"%08X -- [%5d]%-8X ",p2i(&fp),getpid(),getthreadid());
	Xsprintf(TVStr(hmsg),fmt,VA8);
	daemonlog("E","%s",hmsg);
	return 0;
}
#define thfprintf lTHREAD()==0?0:_thfprintf

void HTCCX_init();
void HTCCX_putSVCC(Connection *Conn,FILE *tc,int rcode,PCStr(resphead));
void HTCCX_getSVCC(Connection *Conn,PVStr(field));
void HTCCX_setReqSVCC(Connection *Conn,PCStr(pr),PCStr(si),int po,PCStr(up));
int  HTCCX_replaceCharset(Connection *Conn,PVStr(line),int fnlen,FILE *fs);
int  HTCCX_restoreCharset(Connection *Conn,PVStr(field),int fnlen,PCStr(where));
int  HTCCX_guessCharset(Connection *Conn,PCStr(ctype));
void HTCCX_setGuessedCharset(Connection *Conn,PVStr(line));
#define guessCharset HTCCX_guessCharset
#define setGuessedCharset HTCCX_setGuessedCharset
void HTCCX_reqHead(Connection *Conn);
int  HTCCX_reqBody(Connection *Conn,FILE *ts,PCStr(q),PCStr(f),PCStr(b),int l);
void HTCCX_Qhead(Connection *Conn,PVStr(head));
void HTCCX_Rhead(Connection *Conn,PVStr(head));
int  HTCCX_html(Connection *Conn,PCStr(ctype),int size,PVStr(src),PVStr(dst));
void HTCCX_setindflt(Connection *Conn);


int HTTP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc);
int insertTLS_CL(Connection *Conn,int client,int server);
int fPollInSX(FILE *fp,int timeout);

#define F_AccEncodeX	"X-Q-Accept-Encoding:"

int HttpGopher(Connection *Conn,int vno,int svsock,PCStr(server),int iport,int gtype,PCStr(path));
int HttpWais(Connection *Conn,int vno,int sv,PCStr(server),int iport,PCStr(path));
int service_whois(Connection *Conn);

int getMountExpires(Connection *Conn,PVStr(date),int size);
int HTTP_setRetry(Connection *Conn,PCStr(req),int rcode);
int HttpNews(Connection *Conn,int vno,FILE *fc,int sv,PCStr(host),int port,PCStr(groupanumsearch),PCStr(req),xPVStr(user),PVStr(pass),int KeepAlive,int *stcodep);
FileSize httpftp_cached(Connection *Conn,FILE *tc,PCStr(user),PCStr(pass),PCStr(host),int port,PCStr(path),int *stcodep);
FileSize httpftp(Connection *Conn,FILE *fc,FILE *tc,PCStr(ver),PCStr(method),int svsock,PCStr(auth),PCStr(uuser),PCStr(upass),PCStr(host),int port,int gtype,PCStr(path),int *stcodep);

void http_log(Connection *Conn,PCStr(proto),PCStr(server),int iport,PCStr(req),int rcode,PCStr(ctype),FileSize rsize,int mtime,double ctime,double dtime);
/*
int CTX_cache_remove(Connection *ctx,PCStr(proto),PCStr(host),int port,PCStr(path));
*/
int CTX_cache_remove(Connection *ctx,PCStr(proto),PCStr(host),int port,PCStr(path),int dir);

/*
int KeepAliveWithProxyClient = 0;
*/
#define KeepAliveWithProxyClient (HTTP_opts&HTTP_NOKEEPALIVEPROXY)==0
int HTTP11_toserver = 1;
int HTTP11_toclient = 1;
int HTTP11_clientTEST = 0;
#define CHUNKED_VER "6.0.0" /* DeleGate version when "chunked" is supported */
#define ENCODE_THRU	"-thru"
#define ENCODE_THRUGZIP	"-thrugzip"
const char *HTTP_accEncoding = ENCODE_THRUGZIP;
const char *HTTP_genEncoding = "gzip";

int HTTP09_reject = 0;

int HTTP_noXLocking = 1;
int HTTP_ignoreIf = 0;
int HTTP_warnApplet = 0;
int HTTP_rejectBadHeader = 0;
/*
int HTTP_cacheopt = CACHE_NOCACHE;
*/
void minit_http(){
	HTTP_cacheopt = CACHE_NOCACHE;
}
int HTCKA_opts = 0;
int HTCFI_opts = 0;

#define clntClose	HTTP_clntClose
#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,buf,siz)
#define getFV(str,fld,buf)             getFieldValue2(str,fld,AVStr(buf),sizeof(buf))

extern int MAX_BUFF_SOCKRECV;
extern int MAX_BUFF_SOCKSEND;
extern int RES_CACHE_DISABLE;
extern int IO_TIMEOUT;
extern int CACHE_TAKEOVER;
extern int TAGCONV_KILL;
extern int TAGCONV_JAVA;
extern int TAGCONV_APPLET;
extern int TAGCONV_nKILL;
extern int URICONV_nFULL;
extern int URICONV_nPARTIAL;
extern int DELEGATE_LastModified;

/*
 *	Connection: Keep-Alive
 */
int HTTP_CKA_PERCLIENT      = 8;
/*
int HTTP_CKA_MAXREQ         = 20;
mod-140518d
*/
int HTTP_CKA_MAXREQ         = 50;
int HTTP_MAX_SSLTURNS       = 100;
/*
double HTTP_TOUT_CKA        = 5;
*/
double HTTP_TOUT_CKA        = 10;
double HTTP_TOUT_CKA_MARGIN = 2;
int HTTP_CKA_CFI = 0;
int HTTP_MIN_CHUNKED = 4*1024;
/*
int HTTP_CHUNKED_CLENG = 64*1024;
*/
int HTTP_CHUNKED_CLENG = 0;

int HTTP_TOUT_THREAD_PIPELINE = 30;
double HTTP_TOUT_RESPLINE = 0;
double HTTP_TOUT_CKA_RESPLINE = 10;
double HTTP_WAIT_BADSERV = 3; /* max period to care bad protocol server */

double HTTP_WAIT_REQBODY = 30;
double HTTP_TOUT_IN_REQBODY = 15;
double HTTP_TOUT_BUFF_REQBODY = 5;
double HTTP_TOUT_QBODY = 120;

int HTTP_MAX_BUFF_REQBODY = 1024*1024;

double HTTP_TOUT_BUFF_RESBODY = 8; 

int HTTP_MAXHOPS = 20;
/*
int HTTP_MAX_REQLINE = (4*1024);
*/
int HTTP_MAX_REQLINE = (8*1024);
int HTTP_MAX_REQHEAD = (12*1024);
int HTTP_GW_MAX_REQLINE = 512;
int HTTP_WARN_REQLINE = 1024;

int HTTP_MAX_PARAS = 5;
int HTTP_MAX_PARAS_PROXY = 0;
/*
double HTTP_TOUT_PACKINTVL = 0.30;
*/
double HTTP_TOUT_PACKINTVL = 10.0; /* mod-140716e *//* mod-140518c */

#define protoGopher(proto)	strcaseeq(proto,"gopher")

typedef struct {
	int	 on;
	int	 pid;
  const	char	*cpath;
	FILE	*cachefp;
	FILE	*tc;
     Connection *Conn;
} relaying;

static struct {
	int	 g_dontTruncate; /* keep the cache in the current state */
	relaying g_relaying;
  const	char	*g_where;
	int	 g_nsigPipe;
	int	 g_exiting;

  const char	*g_CacheID;
	int	 g_gotCLX;
	int	 g_RX_CODE;
	int	 g_RX_RdTotalG;
	int	 g_RX_RdTruncated;
	int	 g_authOK;

} HTTP_currents[MAX_THREADS];
static int HTTP_gix(FL_PAR){
	static int ngix;
	int gix;

	if( lMULTIST() == 0 ){
		return 0;
	}
	gix = getthreadgix(0);
	/*
	ngix++;
	fprintf(stderr,"%d [%d] %X <= %s:%d\n",ngix,gix,TID,FL_BAR);
	*/
	return gix;
}
#define GIX()		HTTP_gix(FL_ARG)
#define HTTP_current	HTTP_currents[GIX()]

#define Relaying	HTTP_current.g_relaying
#define DontTruncate	HTTP_current.g_dontTruncate
#define Where		HTTP_current.g_where
#define nsigPIPE	HTTP_current.g_nsigPipe
#define exiting		HTTP_current.g_exiting

#define CacheID		HTTP_current.g_CacheID
#define gotCLX		HTTP_current.g_gotCLX
#define RX_CODE		HTTP_current.g_RX_CODE
#define RX_RdTotalG	HTTP_current.g_RX_RdTotalG
#define RX_RdTruncated	HTTP_current.g_RX_RdTruncated
#define authOK		HTTP_current.g_authOK

static void abortCache()
{	FILE *cachefp;

	cachefp = Relaying.cachefp;
	if( cachefp == NULL )
		return;

	if( Relaying.Conn && Relaying.cpath )
		stopDistribution(Relaying.Conn,cachefp,Relaying.cpath);

	/* discards the half done cache file */
	if( !DontTruncate ){
		sv1log("CACHE discards half written cache.\n");
		fflush(cachefp);
		Ftruncate(cachefp,0,0);
		fseek(cachefp,0,0);
	}
}

static int HTrace(int lev,PCStr(fmt),...){
	CStr(xfmt,1024);
	VARGS(16,fmt);

	if( LOGLEVEL < lev )
		return 0;
	sprintf(xfmt,"#HT11 %s",fmt);
	sv1log(xfmt,VA16);
	return 0;
}
#define HTR LOGLEVEL<2?0:HTrace

int setgotsigTERM(int sig);
int getXf_list(PVStr(Xf));
void putsLogXf(PCStr(wh),int isig);
/* 9.9.4 MTSS immediate exit from Xfxxxxx() to avoid freezing in flockfile() */
void exitfromXf(PCStr(wh),int isig){
	IStr(Xf,64);

	putsLogXf(wh,isig);
	if( lMTSS_NOSSIG() )
		return;

	if( actthreads() )
	if( getXf_list(AVStr(Xf)) ){
		if( ismainthread() )
			putfLog("%s SIGTERM imm. exit in %s",wh,Xf);
		else	putfLog("%s SIGTERM imm. exit in %s non-main",wh,Xf);
		_exit(0);
	}
}

#define sigTERM HTTP_sigTERM
static void sigTERM(int sig)
{	int now;

	finishServYY(FL_ARG,0);
	setgotsigTERM(sig);
	exitfromXf("HT",sig);

	if( !ismainthread() ){
		putsLog("##HT SIGTERM non-main"); /* may not happen */
		thfprintf(stderr,"SIGTERM to non-main thread\n");
		signal(sig,sigTERM);
		msleep(10); /* main-thread may get the orginal signal */
		thread_kill(MAINTHREADID,SIGTERM);
		thread_exit(0);
		return;
	}
	putsLog("HT SIGTERM");
	signal(sig,sigTERM);
	now = time(0);
	if( exiting ){
		sv1log("#### duplicate sigTERM in %d seconds\n",now-exiting);
		if( exiting && now-exiting < 10 )
			return;
		else	_Finish(0);
	}
	exiting = now;

	if( Relaying.on ){
		sv1log("HTTP SC got sigTERM(%d) %x\n",sig,p2i(Relaying.cpath));
		abortCache();
		if( Relaying.tc != NULL )
		{
			/* 9.9.5 it might have been closed already */
			FILE *tc;
			tc = Relaying.tc;
			Relaying.tc = 0;
			if( fileno(tc) < 0 ){
				putfLog("HT SIGTERM don't fcloseLinger(%d)#",fileno(tc));
			}else{
				putfLog("HT SIGTERM fcloseLinger(%d)",fileno(tc));
				fcloseLinger(tc);
			}
			/*
			fcloseLinger(Relaying.tc);
			*/
		}
		if( actthreads() ){
			/* 9.6.3 might be with gzip or SSL thread/process to
			 * block Finish()->exit()->fflush() in LinuxThreads.
			 * should be done mildly by close(ToC) + close(ToS)
			 * or something like kill_childthreads()
			 */
			_Finish(0);
		}
		Finish(0); /* flush outputs and exit */
	}else{
		sv1log("HTTP CS got sigTERM(%d)\n",sig);
		_Finish(0);
	}
}
static void setRelaying(Connection *Conn,FILE *tc,FILE *cachefp,PCStr(cpath))
{
	if( Conn == NULL ){
		Relaying.on = 0;
	}else{
		Relaying.on = 1;
		Relaying.pid = getpid();
		Relaying.tc = tc;
		Relaying.cachefp = cachefp;
		Relaying.cpath = cpath;
		Relaying.Conn = Conn;
		Vsignal(SIGTERM,sigTERM);
	}
}
static void abortHTTP(PCStr(msg))
{
	fprintf(stderr,"[%d.%X] abortHTTP: %s\n",getpid(),TID,msg);
	sv1log("#### EMERGENCY EXIT (%s)\n",msg);
	abortCache();
	_Finish(-1);
}
#define sigPIPE HTTP_sigPIPE
static void sigPIPE(int sig)
{
	if( !ismainthread() ){
		putsLog("HT SIGPIPE non-main"); /* may not happen */
		thfprintf(stderr,"SIGPIPE to non-main thread\n");
		signal(sig,sigPIPE);
		return;
	}
	signal(SIGPIPE,SIG_IGN); /* sv1log may cause SIGPIPE ... */
	putfLog("HT SIGPIPE: %s",Where?Where:"");
	if( nsigPIPE++ % 10 == 0 )
	{
		selfLocaltime++; /* 9.9.4 MTSS */
		sv1log("## got SIGPIPE [%d] in HTTP: %s\n",
			nsigPIPE,Where?Where:"");
		selfLocaltime--;
	}
	signal(SIGPIPE,sigPIPE);
	if( 10 < nsigPIPE ){
		/* to avoid a rush of SIGPIPE ... */
		msleep(10);
	}
}
static void setClientEOF(Connection *Conn,FILE *tc,PCStr(fmt),...)
{	CStr(where,256);
	VARGS(8,fmt);

	ClientEOF = 1;
	if( fmt ){
		sprintf(where,fmt,VA8);
		sv1log("ClientEOF: %s [%d %d] %X %X %X\n",where,
			/*
			fileno(tc),ClientSock,
			*/
			tc?fileno(tc):-1,ClientSock,
			ClientFlags,ServerFlags,Conn->xf_filters);
	}
}
/*
static int checkClientEOF(Connection *Conn,FILE *tc,PCStr(where))
*/
#define checkClientEOF(Conn,tc,wh) checkClientEOFX(FL_ARG,Conn,tc,wh)
static int checkClientEOFX(FL_PAR,Connection *Conn,FILE *tc,PCStr(where))
{	const char *conn_stat;

	if( ClientEOF )
		return ClientEOF;
	if( Conn->from_myself )
		return 0;

	if( ClientSock < 0 ){
		/* maybe this is a internal ResponseFilter process on Win32
		 * spawned without inherited Client-Socket ...
		 */
		return 0;
	}

	if( IsConnected(ClientSock,&conn_stat) )
		return 0;
	if( ClientFlags & PF_MITM_ON ){
		sv1log("--[%s] MITM ClientEOF DisConnected[%d] [%d][%d]\n",
			where?where:"",ClientSock,FromC,ToC);
	}

	if( where ){
		clntClose(Conn,"p:premature client EOF (%s)",where);
		sv1log("## premature client close: %s (%s)\n",where,conn_stat);
	}

	if( lSINGLEP() ){
		if( lMULTIST() ){
		}else
		fprintf(stderr,"-- %X checkClientEOF %d %X/%d <= %s:%d\n",
			TID,ClientSock,p2i(tc),fileno(tc),FL_BAR);
	}else
	detachFile(tc);
	setClientEOF(Conn,tc,where);

	return 1;
}
/*
static void fclosesTIMEOUT(FILE *ff,FILE *ft)
*/
#define fclosesTIMEOUT(ff,ft) fclosesTIMEOUTX(Conn,ff,ft)
static void fclosesTIMEOUTX(Connection *Conn,FILE *ff,FILE *ft)
{	int df,dt;

	df = fileno(ff);
	dt = fileno(ft);

	if( isWindowsCE() || lMULTIST() ){ /* avoid duplicated closes */
		if( df == ClientSock )
			fcloseFILE(ff);
		else	fcloseTIMEOUT(ff);
		if( dt == ClientSock || dt == df )
			fcloseFILE(ft);
		else	fcloseTIMEOUT(ft);
		closed("fclosesTIMEOUT",df,dt);
		return;
	}

	if( lSINGLEP() && df == ClientSock ){
		fcloseFILE(ff);
	}else
	fcloseTIMEOUT(ff);
	if( df != dt )
		fcloseTIMEOUT(ft);
	else
	if( lSINGLEP() ){
		fcloseFILE(ft);
	}
	else	fclose(ft);
	closed("fclosesTIMEOUT",df,dt);
}

int CTX_doSockShutdown(FL_PAR,Connection *Conn,FILE *fp,int clnt);
int Xfshutdown(FL_PAR,Connection *Conn,FILE *fp,int force){
	if( CTX_doSockShutdown(FL_BAR,Conn,fp,1) ){
		return 0;
	}
	return fshutdown(fp,force);
}
#define fshutdown(fp,force) Xfshutdown(FL_ARG,Conn,fp,force)


/*
 * unexpected disconnection from the client
 */
int init_socketpair(int port);
#define setCLX(ws,wf)	(gotCLX |= (1 << wf))
enum {
	CLX_EMPTY_REQ_LINE,
	CLX_EMPTY_REQ_LINEK,
	CLX_AFTER_REQ_FIELDS,
	CLX_AFTER_REQ_REWRITING,
	CLX_BEFORE_CONNECT,
	CLX_BEFORE_RESP,	/* client disconnected before response */
	CLX_DURING_RESP_BUFF,	/* in response buffering */
	CLX_DURING_RESP		/* in response */
};

/*
 * HTTPCONF=uaspec:{listOfOpts}:listOfUser-Agent
 *   clver:v1.0
 *   bugs:no-keepalive
 */
char *HTTP_thruUA;
static void UAspecific(Connection *Conn,PCStr(UA),int direct)
{	const char *dp;

	if( HTTP_thruUA ){
		const char *ua;
		if( UA[0] )
			ua = UA;
		else	ua = "unknown";
 fprintf(stderr,"---- UA[%s]\n",ua);
		if( isinListX(HTTP_thruUA,ua,"cs") ){
 fprintf(stderr,"---- UA[%s] THRU\n",ua);
			clntClose(Conn,"u:thru UA");
		}
	}

	if( dp = strstr(UA,"MSIE ") )
	{
		appletFilter = 1;
		ServerFlags |= PF_UA_MSIE;
	}

	if( direct ){
		if( dp = strstr(UA,"MSIE ") ){
			if( dp[5] < '3'
			 || strncmp(dp+5,"3.0",3) == 0 && atoi(dp+8) < 1 )
				clntClose(Conn,"o:old MSIE");
		}else
		if( dp = strstr(UA,"Mozilla/") ){
			if( dp[8] < '2' )
				FlushHead = 50;
			else
			if( dp[8] < '3' && WillKeepAlive )
				FlushIfSmall = 1;
		}
	}

	if( dp = strstr(UA,"MSIE ") )
	if( dp[5] < '3' || strncmp(dp+5,"3.0",3)==0 && atoi(dp+8) < 1 )
		SimpleContType = 1;

	if( dp = strstr(UA,"MSIE ") )
	if( REQ_URL[0] != '/' ) /* acting as an origin HTTP server */
	if( URL_toMyself(Conn,REQ_URL) == NULL )
		ProxyAuth = 1;

	if( dp = strstr(UA,"Mosaic") )
	if( dp = strstr(dp,"/") )
	if( strcmp(dp+1,"2.6") < 0 )
		SimpleContType = 1;

/* Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.3)
 * Gecko/20040910 prematurely disconnects (discard the response?)
 * in reloading gzip response when the gzip is partially flushed.
 */ {
	extern int Gzip_NoFlush;
	Gzip_NoFlush = 0;
	if( dp = strstr(UA,"Mozilla/5.0") )
	if( dp = strstr(dp,"rv:1.7") )
	if( HttpReload == 2 ){
		Gzip_NoFlush = 1;
	}
 }

	if( dp = strstr(UA,"Lynx") )
	if( dp = strstr(dp,"/") )
		SimpleContType = 1;

	if( strheadstrX(UA,"ESS Update",1) ){
		ClntAccChunk = 0;
		ClntKeepAlive = 0;
	}
	if( strheadstrX(UA,"PowerSketch/Viewer",1) ){
		if( ClntAccChunk ){
			sv1log("## no chunked for %s\n",UA);
			ClntAccChunk = 0;
		}
	}

	if( strheadstrX(UA,"DoCoMo/",0) ){
		ClientFlags |= PF_DO_RESPBUFF;
	}
}

static
void getFileUID(PVStr(fileId),PCStr(path)/*,char *peerver*/)
{	CStr(host,MaxHostNameLen);
	CStr(fileid,URLSZ);
	const char *addr;

	/* if the file is on NFS, should use the name of NFS server */
	GetHostname(AVStr(host),sizeof(host));

	/* if( peerver < 5.3.1 ) */
		sprintf(fileId,"%s:%s",gethostaddrX(host),path);
		/*
		sprintf(fileId,"%s:%s",gethostaddr(host),path);
		*/
	/*
	else{
		strcpy(fileid,"file://");
		strcat(fileid,host);
		strcat(fileid,"/");
		strcat(fileid,path);
		toMD5(fileid,fileId);
		sv1log("%s = %s\n",fileId,fileid);
	}
	*/
}
static void getCacheID(PVStr(cid),PCStr(path))
{
	sprintf(cid,"%x/%x",File_ctime(cachedir()),File_ctime(path));
}

int thruFilter(Connection *Conn){
	int xf = Conn->xf_filters;

	if( (xf & ~(XF_FSV|XF_FCL)) == 0 ){
		 if( xf & XF_FSV ){
			if( (ServerFlags & PF_SSL_ON) == 0 )
				return 0;
		}
		 if( xf & XF_FCL ){
			if( (ClientFlags & PF_SSL_ON) == 0 )
				return 0;
		}
		/* 9.9.8 SSL filter only, no content rewriting */
		return 1;
	}
	return 0;
}

#define withConversion(Conn,checkxf) withConversionX(Conn,checkxf,0)
static int withConversionX(Connection *Conn,int checkxf,int woURI)
{
	if( !woURI ){
	/* URL CONVERSIONS */
/*
	if( DO_DELEGATE || IsMounted || URICONV_nFULL || URICONV_nPARTIAL )
URICONV_nPARTIAL alone does not indicate Conversion...
*/
	if( DO_DELEGATE || IsMounted || URICONV_nFULL )
		return 1;

	if( NOJAVA || TAGCONV_nKILL )
		return 1;

	/* CHARACTER CODE CONVERSION */
	/*
	if( CCXactive(CCX_TOCL) || CTX_cur_codeconvCL(Conn,VStrNULL) )
	*/
	if( CCXactive(CCX_TOCL) ){
		if( !CCXguessing(CCX_TOCL) )
			return 1;
	}
	if( CTX_cur_codeconvCL(Conn,VStrNULL) ){
		return 1;
	}

	/* HTML CONVERSIONS */
	}

	/* EXTERNAL FILTERS */
	if( checkxf && Conn->xf_filters )
	{
		if( thruFilter(Conn) ){
			/* with filters but without rewriting */
		}else
		return 1;
	}

	return 0;
}
/*
 * Check if some setup of proxy for some conversion have changed
 * after the client cached the data.  If so, whole data should be sent
 * as the response regardless of the modification of original data.
 * So ignore If-Modified-Since to get the body if cache is not.
 * and ignore 304 Not Modified response when the cache is.
 */
static int forceBodyResponse(Connection *Conn)
{
	if( !withConversion(Conn,1) )
		return 0;

	if( HTCFI_opts & (HTCFI_THRU_304 | HTCFI_GEN_304) ){
		/* 9.9.8 thru 304 from the server or gen. by self */
		return 0;
	}
	if( 0 < ClntIfModClock )
	if( ClntIfModClock < DELEGATE_LastModified ){
		sv1log("DeleGated is Modified after the data: %d > %d\n",
			DELEGATE_LastModified,ClntIfModClock);
		return 1;
	}
	return 0;
}
static int LockedByC(Connection *Conn,PCStr(cpath),FILE *fc)
{	CStr(fileId,URLSZ);

	if( cpath == NULL || cpath[0] == 0 )
		return -1;

	if( CacheID ){
		getCacheID(AVStr(fileId),cpath);
		if( isinList(CacheID,fileId) ){
			goto LOCKED;
		}
	}

	if( LockedByClient == 0 )
		return 0;

	getFileUID(AVStr(fileId),cpath);
	if( streq(LockedByClient,fileId) ){
LOCKED:
		sv1log("--- cache is locked by client: %s\n",cpath);
		DontUseCache = 1;
		DontReadCache = DontWriteCache = DontWaitCache = 1;
		return 1;
	}
	return 0;
}
/*
 * generate `If-Modified-Since: cdate' if not specified by the client.
 */
static void genIfModified1(Connection *Conn,FILE *cachefp,PCStr(cpath),int cdate)
{	CStr(scdate,64);
	CStr(mod,sizeof(scdate)+32);
	/*
	CStr(mod,64);
	*/
	int lastmod;

	if(forceBodyResponse(Conn)
	 && cachefp == NULL
	 && !LockedByC(Conn,cpath,NULL)){
		/* need data anyway to produece the body response regardless
		 *  of the modified date, so ignore and don't produce If-Mod.
		 */
		sv1log("ignore and don't produce If-Modified-Since\n");
		return;
	}
	if(cpath==NULL||cdate==-1||cachefp==NULL||DontUseCache||DontReadCache){
		/* local cache is not useful, pass Client's request as is */
		if( ClntIfMod[0] )
			RFC822_addHeaderField(AVStr(REQ_FIELDS),ClntIfMod);
		return;
	}

	/*
	 * local cache file is available
	 */
	lastmod = HTTP_getLastModInCache(AVStr(scdate),sizeof(scdate),cachefp,cpath);

	if( ClntIfMod[0] && lastmod <= ClntIfModClock ){
		RFC822_addHeaderField(AVStr(REQ_FIELDS),ClntIfMod);
		CacheLastMod = ClntIfModClock;
		return;
	}

	if( lastmod == 0 )
		lastmod = HTTP_genLastMod(AVStr(scdate),sizeof(scdate),cachefp,cpath);
	CacheLastMod = lastmod;

	sprintf(mod,"If-Modified-Since: %s\r\n",scdate);
	RFC822_addHeaderField(AVStr(REQ_FIELDS),mod);
	Verbose("+ %s",mod);
}
int getVserv(Connection *Conn,PCStr(head),PVStr(hostport));
#define setReferer HTTP_setReferer
void HTTP_setReferer(Connection *Conn,PCStr(proto),PCStr(host),int port,PCStr(req),Referer *referer,PVStr(refbuf))
{
	const char *bp;
	const char *up;
	refQStr(rp,refbuf); /**/

	referer->r_cType = 0;
	referer->r_tagctx.r_curscript[0] = 0;
	referer->r_tagctx.r_curstyle[0] = 0;
	referer->r_tagctx.r_curtag[0] = 0;

	referer->r_my.u_hostport = rp;
	HTTP_ClientIF_HP(Conn,AVStr(rp));
	rp += strlen(rp) + 1;

	referer->r_my.u_proto = CLNT_PROTO;
	referer->r_my.u_host = rp;
	referer->r_my.u_port = HTTP_ClientIF_H(Conn,AVStr(rp));
	rp += strlen(rp) + 1;

	if( REMOTE_HOST[0] ){
		proto = REMOTE_PROTO;
		host = REMOTE_HOST;
		port = REMOTE_PORT;
	}

	referer->r_sv.u_proto = rp;
	strcpy(rp,proto);
	rp += strlen(rp) + 1;

	referer->r_sv.u_host = rp;
	strcpy(rp,host);
	rp += strlen(rp) + 1;

	referer->r_sv.u_port = port;

	referer->r_sv.u_hostport = rp;
	if( getVserv(Conn,REQ_FIELDS,AVStr(rp)) ){
		Verbose("Vserv: %s\n",rp);
	}else
	HostPort(AVStr(rp),proto,host,port);
	rp += strlen(rp) + 1;

	referer->r_sv.u_method = rp;
	up = wordscanX(req,AVStr(rp),32);
	rp += strlen(rp) + 1;
	
	referer->r_sv.u_path = rp;
	if( up[0] == ' ' ){
		/* v9.9.12 fix-140814e, strip '/' of "METHOD /upath" */
		up++;
		if( up[0] == '/' ){
			up++;
		}
	}
	wordscanX(up,AVStr(rp),1024);
	/*if( toProxy )*/
	strip_urlhead(AVStr(rp),VStrNULL,VStrNULL);
	rp += strlen(rp) + 1;

 {	int blen;
	referer->r_sv.u_base = rp;
	up = referer->r_sv.u_path;
	/* v9.9.12 fix-140814e, leading '/' is already stripped above and
	 * the URL path might start with '/' as "METHOD //upath" althogh
	 * it shold be URL encoded.
	if( *up == '/' )
		up++;
	 */
	blen = url_upathbaselen(up,strlen(up));
	Bcopy(up,rp,blen); XsetVStrEnd(AVStr(rp),blen);
	rp += blen + 2;
 }

	referer->r_my.u_path = rp;
	strcpy(rp,Conn->cl_baseurl);
	rp += strlen(rp) + 1;

	/* the above code for r_my.u_path is strange and seems not used
	 * anywhere. To get full-url of relative ?query without script name,
	 * the script name information in URL is necessary (in r_requurl).
	 */
	if( ToMyself ) /* for safety from possibe side effects or abuses */
	{
	    /* v9.9.11 new-140812a, for URL of relative "?query" */
	    bzero(&referer->r_requrl,sizeof(referer->r_requrl));
	    if( OREQ[0] ){ /* maybe always true */
		const char *get_UrlX(Connection *Conn,UrlX *up,PCStr(url),PVStr(buff));
		IStr(ourl,URLSZ);
		refQStr(qp,ourl);
		HTTP_originalURLPath(Conn,AVStr(ourl));
		if( qp = strchr(ourl,'?') ){
			setVStrEnd(qp,0);
		}
		rp = get_UrlX(Conn,&referer->r_requrl,ourl,AVStr(rp));
	    }

	    /* v9.9.11 new-140810f, SSI vbase */
	    referer->r_qvbase = Conn->rq_vbase;
	    if( referer->r_qvbase.u_proto ){ /* if set by SSI vbase */
		int blen;
		referer->r_qvbase.u_base = rp;
		up = referer->r_qvbase.u_path;
		if( *up == '/' )
			up++;
		blen = url_upathbaselen(up,strlen(up));
		Bcopy(up,rp,blen); XsetVStrEnd(AVStr(rp),blen);
		rp += blen + 2;
	    }

	    referer->r_flags |= UMF_QUERY_FULL;
	}

	referer->r_vb = Conn->my_vbase; /* when BASEURL is a FULL-URL */

	setQStr(referer->r_altbuf,rp,(UTail(refbuf)-rp)+1);
}

typedef struct {
	const char *dc_what;
	int dc_line;
} DumpCtx;
typedef struct {
	Connection *q_Conn;
	int	q_cpid;
       FileSize	q_totalc;
	int	q_rcode;
	int	q_hcode; /* HTTP response code */
	int	q_tsfd;
	int	q_fsfd;
	int	q_emptyResp;

  const	char   *q_proto;
  const	char   *q_site;
	MStr(	q_site_buf,MaxHostNameLen);
	int	q_port;
  const	char   *q_upath;

	int	q_useCache;
	int	q_expire;
	MStr(	q_cpath,1024);
	FILE   *q_cachefp;
	int	q_cdate;
	int	q_cacheRemove;

	MMap   *q_cachemmap;
	int	q_cachefilesiz;
	defQStr(q_cacheheadbuf);
	int	q_cacheheadlen;
	int	q_cachebodysiz;
	int	q_cacheretcode;

       FileSize	q_range[2];
	MStr(	q_accEncoding,32);
	MStr(	q_upgrade,32);
	int	q_svclose;
	double	q_lastrecv;
	double	q_lastsent;

	FILE   *q_tcf;
	DumpCtx	q_dumpCD;
	DumpCtx	q_dumpDS;
} QueryContext;

#define QX_Conn		QX->q_Conn
#define QX_cpid		QX->q_cpid
#define QX_totalc	QX->q_totalc
#define QX_rcode	QX->q_rcode
#define QX_hcode	QX->q_hcode
#define QX_tsfd		QX->q_tsfd
#define QX_fsfd		QX->q_fsfd
#define QX_emptyResp	QX->q_emptyResp

#define QX_proto	QX->q_proto
#define QX_site		QX->q_site
#define QX_site_buf	QX->q_site_buf
/**/
#define QX_port		QX->q_port
#define QX_upath	QX->q_upath

#define QX_useCache	QX->q_useCache
#define QX_expire	QX->q_expire
#define QX_cpath	QX->q_cpath
/**/
#define QX_cachefp	QX->q_cachefp

#define QX_cachemmap	QX->q_cachemmap
#define QX_cachefilesiz	QX->q_cachefilesiz
#define QX_cacheheadbuf	QX->q_cacheheadbuf
#define QX_cacheheadlen	QX->q_cacheheadlen
#define QX_cachebodysiz	QX->q_cachebodysiz
#define QX_cacheretcode	QX->q_cacheretcode

#define QX_cdate	QX->q_cdate
#define QX_cacheRemove	QX->q_cacheRemove

#define QX_range	QX->q_range
#define QX_accEnc	QX->q_accEncoding
#define QX_upgrade	QX->q_upgrade
#define QX_svclose	QX->q_svclose
#define QX_lastRecv	QX->q_lastrecv
#define QX_lastSent	QX->q_lastsent

#define QX_tcf		QX->q_tcf
#define QX_dumpCD	QX->q_dumpCD
#define QX_dumpDS	QX->q_dumpDS

/*###################################### RESPONSE */
typedef struct {
	MStr(	l_buffer,IBUFSIZE+1);
} LineBuf;
typedef struct {
	FILE   *t_fp;		/* FILE pointer */
	int	t_fd;		/* file descriptor */
	int	t_issock;	/* it is a socket */
	int	t_EOF;		/* (soft) EOF reached */
	int	t_feof;		/* disconnected by feof() */
	int	t_buffered;	/* bytes in buffer */
	int	t_nready;	/* I/O ready */
	int	t_lastRcc;	/* bytes read in the last */
	int	t_tid;		/* thread-id for gzip/gunzip */

       FileSize	t_contLeng;	/* Content-Length got / put */
	int	t_contLengGot;	/* Content-Length is got */
	int	t_headTotal;	/* transferred header size */
       FileSize	t_bodyTotal;	/* transferred body size */
	double	t_ready;	/* recevied enough from recvbody */
	int	t_done;		/* reading finished */
	int	t_keepAlive;	/* Connection: keep-alive or HTTP/1.1 */

	int	t_remsize;	/* remaining (input) body size */
	UTag	t_buffer;

	int	t_chunked;	/* is chunked */
	int	t_chunk_ser;	/* serial number of the current chunk */
	int	t_chunk_siz;	/* size of the current chunk */
	int	t_chunk_rem;	/* remaining bytes of the current chunk */
} TransCode;

typedef struct {
	int	d_start;
	MStr(	d_cpath,URLSZ);
	FILE *d_fp;
	int	d_ready;
} Dcx;

typedef struct {
	Connection *r_Conn;
	QueryContext *r_QX;
	Referer *r_referer;
	int	r_ovw;

	int	r_qWithHeader;
	MStr(	r_qmethod,128);	/* method of the request */
	int	r_reqHEAD;	/* qmethod is HEAD */

   HttpResponse	r_status;		/* decomposed status line */
	MStr(	r_connection,256);	/* Connection: */
	MStr(	r_ctype,256);		/* Content-Type: */
	MStr(	r_ctypeline,256);	/* Content-Type: with parameters */
	MStr(	r_servername,256);	/* Server: */
	MStr(	r_cencoding,256);	/* Content-Encoding: */
	int	r_cencoded;		/* with Content-Encoding: */
	MStr(	r_tencoding,256);	/* Transfer-Encoding: */
	MStr(	r_setCookie,2048);	/* Set-Cookie: */
	MStr(	r_cachecontrol,256);	/* Cache-Control: */
	MStr(	r_lastVia,MAX_VIALEN);	/* Via: */
	int	r_guessCharset;		/* guessing charset */

	MStr(	r_expires,64);	/* Expires: */
	int	r_lastMod;	/* with Last-Modified: */
	int	r_lastModTime;	/* Last-Modified: */

	int	r_errori;
	int	r_tryKeepAlive;

	int	r_convChar;	/* with character conversion */
	int	r_deEnt;	/* decode char. entitiy encoding &xx; */
	int	r_putPRE;	/* with <PRE> body </PRE> insertion */

	Partf	r_partf;

	int	r_noBody;	/* response without body */
	int	r_inHeader;	/* processing header part of resp. */
	int	r_isText;	/* type of text */
	int	r_isBin;	/* body is binary data */
	int	r_woURI;	/* no URI to be rewriten is included */
	int	r_FBI;		/* flush buffer immediately */
	int	r_didUnzip;	/* did Gunzip to the response */
	int	r_didZip;	/* did Gzip to the response */

	int	r_bodyLines;	/* line# of text body got from server */
       FileSize	r_txtLen;
       FileSize	r_binLen;

	double	r_Start;	/* begining of response relay */
	double	r_Resp1;	/* first response */
	double	r_firstResp;
	double	r_connDelay;
	double	r_lastFlush;
	double	r_inTakeOver;	/* doing CACHE_TAKEOVER till the time */

	int	r_nflush;	/* flush count */
	int	r_ninput;
	int	r_noutput;
	int	r_nsigreport;

	int	r_fromcache;
	int	r_fsTimeout;	/* TIMEOUT of end of serv resp in Keep-Alive */
	TransCode r_fsx;	/* transfer coding from server */
	TransCode r_tcx;	/* to client */
	int	r_xrdLen;	/* content length after gunzip */
	int	r_xinLen;	/* input length to putMIMEmsg() */
	int	r_discardResp;	/* 9.9.3 don't forward resp. */

  const	char   *r_tmpFileId;
	FILE   *r_respBuff;	/* tmporary file to receive response */
	FILE   *r_tc_sav;	/* saved original FILE to client */

	int	r_niced;
	FILE   *r_cachefp;
  const	char   *r_cpath;
	FILE   *r_cachefpSav;	/* did conv. 304 response to 200 with cache */
	UTag	r_dcxp;
	UTag	r_Anchor_rem;
		/* Pushed back fragment of anchor tag which is folded
		 * into multiple lines.
		 * Should be treated in general way in the input buffer
		 * operation... (-_-;
		 */
	UTag	r_line0t;
	UTag	r_line1t;
	DumpCtx	r_dumpSD;
	DumpCtx	r_dumpDC;
} ResponseContext;

#define RX_Conn		RX->r_Conn
#define RX_QX		RX->r_QX
#define RX_referer	RX->r_referer
#define RX_ovw		RX->r_ovw
#define RX_qWithHeader	RX->r_qWithHeader
#define RX_qmethod	RX->r_qmethod
#define RX_reqHEAD	RX->r_reqHEAD

#define RX_status	RX->r_status
#define RX_isHTTP09	RX->r_status.hr_isHTTP09
#define RX_ver		RX->r_status.hr_ver
#define RX_code		RX->r_status.hr_rcode
#define RX_reason	RX->r_status.hr_reason

#define RX_connection	RX->r_connection
/**/
#define RX_ctype	RX->r_ctype
#define RX_ctypeline	RX->r_ctypeline
#define RX_servername	RX->r_servername
#define RX_cencoding	RX->r_cencoding
#define RX_cencoded	RX->r_cencoded
#define RX_tencoding	RX->r_tencoding
#define RX_setCookie	RX->r_setCookie
#define RX_cachecontrol	RX->r_cachecontrol
#define RX_lastVia	RX->r_lastVia
/**/

#define RX_expires	RX->r_expires
#define RX_lastMod	RX->r_lastMod
#define RX_lastModTime	RX->r_lastModTime

#define RX_errori	RX->r_errori
#define RX_tryKeepAlive	RX->r_tryKeepAlive

#define RX_convChar	RX->r_convChar
#define RX_deEnt	RX->r_deEnt
#define RX_putPRE	RX->r_putPRE

#define RX_noBody	RX->r_noBody
#define RX_inHeader	RX->r_inHeader
#define RX_isText	RX->r_isText
#define RX_isBin	RX->r_isBin
#define RX_woURI	RX->r_woURI
#define RX_FBI		RX->r_FBI
#define RX_didUnzip	RX->r_didUnzip
#define RX_didZip	RX->r_didZip

#define RX_bodyLines	RX->r_bodyLines
#define RX_txtLen	RX->r_txtLen
#define RX_binLen	RX->r_binLen

#define RX_Start	RX->r_Start
#define RX_Resp1	RX->r_Resp1
#define RX_firstResp	RX->r_firstResp
#define RX_connDelay	RX->r_connDelay
#define RX_lastFlush	RX->r_lastFlush
#define RX_inTakeOver	RX->r_inTakeOver

#define RX_nflush	RX->r_nflush
#define RX_ninput	RX->r_ninput
#define RX_noutput	RX->r_noutput
#define RX_nsigreport	RX->r_nsigreport

#define RX_fromcache	RX->r_fromcache
#define RX_fsTimeout	RX->r_fsTimeout
#define RX_fsx		RX->r_fsx
#define RX_fsp		RX->r_fsx.t_fp
#define RX_fsd		RX->r_fsx.t_fd
#define RX_rdBuff	(*(LineBuf*)(RX->r_fsx.t_buffer.ut_addr)).l_buffer
/**/
#define RX_rdContLen	RX->r_fsx.t_contLeng
#define RX_xrdLen	RX->r_xrdLen
#define RX_rdContLenGot	RX->r_fsx.t_contLengGot
#define RX_emptyBody	( RX_rdContLenGot && RX_rdContLen == 0 )
#define RX_xinLen	RX->r_xinLen
#define RX_rdHeadTotal	RX->r_fsx.t_headTotal
#define RX_rdTotal	RX->r_fsx.t_bodyTotal
#define RX_rdReady	RX->r_fsx.t_ready
#define RX_rdDone	RX->r_fsx.t_done
#define RX_remsize	RX->r_fsx.t_remsize
#define RX_guessCharset	RX->r_guessCharset

#define RX_tc_sav	RX->r_tc_sav
#define RX_tmpFileId	RX->r_tmpFileId
#define RX_respBuff	RX->r_respBuff

#define RX_discardResp	RX->r_discardResp
#define RX_tcx		RX->r_tcx
#define RX_tcp		RX->r_tcx.t_fp
#define RX_tcpissock	RX->r_tcx.t_issock
#define RX_tcd		RX->r_tcx.t_fd
#define RX_wrbufed	RX->r_tcx.t_buffered
#define RX_wrHeadTotal	RX->r_tcx.t_headTotal
#define RX_wrContLen	RX->r_tcx.t_contLeng
#define RX_wrTotal	RX->r_tcx.t_bodyTotal
#define RX_niced	RX->r_niced

#define RX_cachefp	RX->r_cachefp
#define RX_cpath	RX->r_cpath
#define RX_cachefpSav	RX->r_cachefpSav
#define RX_dcx		(*(Dcx*)(RX->r_dcxp.ut_addr))
#define Line0t		RX->r_line0t
#define Line1t		RX->r_line1t
#define Anchor_rem	RX->r_Anchor_rem.ut_addr
/**/

#define RX_dumpSD	RX->r_dumpSD
#define RX_dumpDC	RX->r_dumpDC

static void url_abs_delegateS(Connection *Conn,int do_delegate,Referer *referer,PCStr(src),PVStr(dst),PVStr(rem))
{	struct {
		MStr(e_buf,RESP_LINEBUFSZ);
		char *ptr; /**/
	} buf;
	TagCtx stagctx;

	stagctx = referer->r_tagctx;
	buf.ptr = buf.e_buf;
	/*if( do_delegate || something-MOUNTed )*/
		url_absoluteS(referer,src,QVStr(buf.ptr,buf.e_buf),AVStr(rem));
	referer->r_tagctx = stagctx;

/*
	CTX_url_delegateS(Conn,referer,buf.ptr,dst,do_delegate?Conn:NULL);
*/
	CTX_url_delegateS(Conn,referer,buf.ptr,AVStr(dst),do_delegate);
	referer->r_tagctx = stagctx;

	/*
	if( DO_DELEGATE || IsMounted )
	*/
	if( DO_DELEGATE || IsMounted || ToInternal )
	if( URICONV_nPARTIAL )
	if( RespCode != 301 && RespCode != 302 )
	if( referer->r_cType && streq(referer->r_cType,"text/xml") ){
		/* 9.2.0 */
		/* RSS interpreter does not accept relative URL ? */
		sv1log("## suppressed partialzing URL for XML\n");
	}else
	if( url_partializeS(referer,dst,QVStr(buf.ptr,buf.e_buf)) )
		strcpy(dst,buf.ptr);
}
static void redirect_HTMLS(Connection *Conn,int dont_rewrite,int do_delegate,Referer *referer,PCStr(src),PVStr(dst),PVStr(rem))
{
	if( dont_rewrite )
		url_absoluteS(referer,src,AVStr(dst),AVStr(rem));
	else	url_abs_delegateS(Conn,do_delegate,referer,src,AVStr(dst),AVStr(rem));
}
void HTTP_redirect_HTML0(Connection *Conn,PCStr(proto),PCStr(host),int port,PCStr(req),PCStr(src),PVStr(dst))
{	Referer referer;
	CStr(refbuf,URLSZ);

	setReferer(Conn,proto,host,port,req,&referer,AVStr(refbuf));
	redirect_HTMLS(Conn,DONT_REWRITE,DO_DELEGATE,&referer,src,AVStr(dst),VStrNULL);
}

#define Line(line0,ln)	((ln)==0?line0:((ln)%2==0?Line0t.ut_addr:Line1t.ut_addr))
#define Cline	Line(line0,linex+0)
#define Nline	Line(line0,linex+1)

static char *rewriteResponse(Connection *Conn,ResponseContext *RX,Referer *referer,PVStr(line0),PCStr(ctype),int doconv,int deent,FILE *tc)
{	int linex;

	dumpstacksize("rewriteResponse","");
	linex = 0;

	if( !RelayTHRU )
	if( BORN_SPECIALIST || ACT_SPECIALIST ){
		if( referer->r_cType ){
			ctype = referer->r_cType;
		}
		if( ctype == NULL )
			ctype = "message/rfc822";

	    if( RX_inHeader
	     || RX_isText == TX_HTML
	     || RX_isText == TX_CSS
	     || RX_isText == TX_XML
	     || RX_isText == TX_JAVASCRIPT
	    ){
		if( Anchor_rem[0] ){
			Xstrcpy(ZVStr(Nline,RESP_LINEBUFSZ),Anchor_rem);
			Xstrcat(ZVStr(Nline,RESP_LINEBUFSZ),Cline);
			linex++;
			setVStrEnd(Anchor_rem,0);
		}
		if( !DONT_REWRITE || URICONV_nFULL )
    {
	TagCtx stagctx = referer->r_tagctx;
		if( html_nextTagAttrX(referer,Cline,ctype,AVStr(Anchor_rem),NULL,NULL,NULL) ){
	/* v9.9.11 fix-140724f, tag context set in
	 * search must be restored before rewriting.
	 */
	if( bcmp(&referer->r_tagctx.r_curtag,&stagctx,sizeof(TagCtx)) != 0 ){
		Verbose("--HTTP restore TagCtx, curtag[%s]\n",
			referer->r_tagctx.r_curtag);
		referer->r_tagctx = stagctx;
	}
			redirect_HTMLS(Conn,DONT_REWRITE,DO_DELEGATE,referer,Cline,ZVStr(Nline,RESP_LINEBUFSZ),AVStr(Anchor_rem));
			linex++;
		}
    }
		if( NOJAVA || TAGCONV_nKILL ){
		    if( !RX_inHeader ){
			int uconv = 0;
			if( NOJAVA & RELAY_OBJECT ) uconv |= TAGCONV_JAVA;
			if( NOJAVA & RELAY_APPLET ) uconv |= TAGCONV_APPLET;
			if( TAGCONV_nKILL ) uconv |= TAGCONV_KILL;

			if( java_conv(Cline,ZVStr(Nline,RESP_LINEBUFSZ),uconv) )
				linex++;
		    }
		}
		if( deent ){
			decode_entities(Cline,ZVStr(Nline,RESP_LINEBUFSZ));
			linex++;
		}
	    }
		if( doconv )
		if( HTCCX_html(Conn,ctype,RESP_LINEBUFSZ,
		    ZVStr(Cline,RESP_LINEBUFSZ),ZVStr(Nline,RESP_LINEBUFSZ)) ){
			linex++;
		}
	}
	return (char*)Cline;
}
static int DOrewriteResponse(Connection *Conn,ResponseContext *RX){
	if( !RelayTHRU )
	if( BORN_SPECIALIST || ACT_SPECIALIST ){
		switch( RX_isText ){
			case TX_HTML:
			case TX_CSS:
			case TX_XML:
			case TX_JAVASCRIPT:
				return 1; /* can be MOUNTed */
		}
		if( RX_isText ){
			if( RX_convChar ){
				if( CCXguessing(CCX_TOCL) ){
					/* 9.9.8 not to remove Cont-Leng */
				}else
				return 2;
			}
		}
	}
	if( Conn->xf_filters & (XF_FTOCL|XF_FFROMSV|XF_FFROMMD) ){
		return 3;
	}
	return 0;
}

void LOGFILE_fputs(PCStr(str)){
	FILE *lfp = curLogFp();
	if( *str == 0 )
		fflush(lfp);
	else	fputs(str,lfp);
	if( lCONSOLE() && lfp != stderr ){
		if( *str == 0 )
			fflush(stderr);
		else	fputs(str,stderr);
	}
}
static void dumpmsg(DumpCtx *Dtx,PCStr(what),PCStr(str)){
	FILE *lfp = curLogFp();
	const char *sp;
	IStr(vb,1024);
	refQStr(vp,vb);
	int ch;
	int top;
	int pch = 0;
	int id;

	if( lSINGLEP() )
		id = TID;
	else	id = getpid();
	for( sp = str; ch = *sp; sp++ ){
		if( (top = (pch==0 || pch=='\n')) || sizeof(vb)-4 <= vp-vb ){
			fprintf(lfp,"%s",vb);
			vp = vb;
			if( top ){
				if( lSINGLEP() )
					sprintf(vp,"--[%X]",id);
				else	sprintf(vp,"--[%u]",id);
				vp += strlen(vp);
				sprintf(vp," %2d %s: ",++Dtx->dc_line,what);
				fprintf(lfp,"%s",vb);
				vp = vb;
			}
		}
		pch = ch;
		switch( ch ){
			default: setVStrPtrInc(vp,ch); setVStrEnd(vp,0); break;
			case '\r': strcpy(vp,"^M"); vp += 2; break;
		}
	}
	fprintf(lfp,"%s",vb);
	fflush(lfp);
}
/* FTPxHTTP client will make half shutdown POST */
int ignore_isNotAlive(Connection *Conn,FL_PAR){
	if( isinFTPxHTTP(Conn) ){
		if( strcaseeq(REQ_METHOD,"POST") ){
			return 1;
		}
	}
	return 0;
}
static const char *GETRESPTXT(Connection *Conn,ResponseContext *RX,int fromcache)
{	int timeout;
	int remleng;
	int niced = RX_niced;
	FILE *fs = RX_fsp;
	MrefQStr(line,RX_rdBuff); /**/
	int byline = RX_inHeader || (HTTP_opts & HTTP_LINEBYLINE);
	int size = RX_remsize + 1;
	int *lengp = &RX_fsx.t_lastRcc;
	int *isbinp = &RX_isBin;
	int cc;
	const char *rcode;
	double St = Time();

	if( !RX_inHeader && RX_emptyBody && RX_rdTotal == 0 )
		timeout = 100;
	else
	if( Conn->io_timeout ){
		timeout = (int)(Conn->io_timeout * 1000);
	}else
	if( HTTP_TOUT_RESPLINE )
		timeout = (int)(HTTP_TOUT_RESPLINE * 1000);
	else	timeout = (int)(IO_TIMEOUT * 1000);
	if( CACHE_TAKEOVER && RX_inTakeOver ){
		/* 9.9.1 shorten the timeout in CACHE_TAKEOVER */
		int rem = (int)((RX_inTakeOver - Time()) * 1000);
		if( rem <= 0 ){
			Verbose("CACHE_TAKEOVER: timeout=%d (%d) <= %d\n",
				1,rem,timeout);
			timeout = 1;
		}else
		if( rem < timeout ){
			Verbose("CACHE_TAKEOVER: timeout=%d <= %d\n",
				rem,timeout);
			timeout = rem;
		}
	}

	if( !RX_inHeader && 0 < RX_rdContLen ){
		if( RX_xrdLen )
			remleng = RX_xrdLen - RX_rdTotal;
		else
		remleng = RX_rdContLen - RX_rdTotal;
		if( !fromcache ){
			if( remleng <= 0 )
				timeout = 3*1000;
		}
	}else	remleng = RX_remsize;

	/*
	if( 1000 < timeout ){
		int nready;
		nready = fPollIn(fs,1000);
		fprintf(stderr,"-- %X fgetsBB nready=%d/%d (%d)\n",
			TID,nready,READYCC(fs),timeout);
	}
	*/
	if( ignore_isNotAlive(Conn,FL_ARG) ){
	rcode = fgetsByBlockX(-1,AVStr(line),size,fs,
		niced,timeout,byline,fromcache,remleng,lengp,isbinp);
	}else
	rcode = fgetsByBlockX(ClientSock,AVStr(line),size,fs,
		niced,timeout,byline,fromcache,remleng,lengp,isbinp);
	if( lPEEPSVDG() ){
	    if( rcode != 0 ){
		if( RX_inHeader ){
			dumpmsg(&RX_dumpSD,RX_fromcache?"C-D":"S-D",line);
		}
	    }
	}

	if( !RX_inHeader && rcode == 0 )
	if( remleng != 0 )
	if( !(isWindows() && SocketOf(fileno(fs)) == 0) )
	if( !(RX_rdContLenGot && RX_rdContLen == 0 && RX_rdTotal == 0) )
	{
		int serrno = errno;
porting_dbg("--GETRESPTXT null %.1f err=%d (%x,%x,[%d/%d],%d) %d",
Time()-St,serrno,remleng,fromcache,SocketOf(fileno(fs)),fileno(fs),feof(fs),(int)RX_rdTotal);
     sv1log("--GETRESPTXT null %.1f err=%d (%x,%x,[%d/%d],%d) %d\n",
Time()-St,serrno,remleng,fromcache,SocketOf(fileno(fs)),fileno(fs),feof(fs),(int)RX_rdTotal);
	}

	if( rcode != NULL )
	if( RX_inHeader && RX_QX ){
		if( strtailstr(line,"\r\n") == 0 ){
			QueryContext *QX = RX_QX;
			QX_cacheRemove = R_BAD_FORMAT;
			QX_svclose = 1;
			daemonlog("F","ERROR: not end with CRLF: %s",line);
		}
	}

	cc = *lengp;
	if( RESP_SAV ){
		if( RESP_MSGFP != NULL || RESP_SIZ == 0 || RESP_SIZ < RESP_LEN+cc+1 ){
			if( RESP_MSGFP == NULL ){
				RESP_MSGFP = TMPFILE("RESP_MSG");
			}
			fputs(line,RESP_MSGFP);
		}else{
			Xbcopy(line,DVStr(RESP_MSG,RESP_LEN),cc+1);
			RESP_LEN += cc;
		}
	}
	return rcode;
}

/*
fflush after the header is put makes separated header/body and let
the server on Solaris2.X be slower...  But, this is necessary in
BSDI-1.x to avoid the header from being put after the body X-<
*/
#ifdef __bsdi__
#include <sys/param.h>
#if !defined(_BSDI_VERSION) || _BSDI_VERSION < 199501
#define HeadFlush 1
#endif
#endif
#ifndef HeadFlush
#define HeadFlush 0
#endif

static int flushHead(Connection *Conn,FILE *tc,int length)
{
/*
	if( 0 < length && length < 1024 )
*/
 	if( !HeadFlush && !FlushHead )
		return 0;

	if( fflush(tc) == EOF ){
		setClientEOF(Conn,tc,"flushHead");
		return EOF;
	}

	Verbose("HeadFlush:%d, FlushHead:%d(msec)\n",HeadFlush,FlushHead);
	if( FlushHead )
		msleep(FlushHead);

	return 0;
}


/*
 * rewriting/adding header field based on body
 * other than Content-Length
 */
static int genHeadByBody(Connection *Conn,PCStr(phead))
{	CStr(ctype,256);

	if( getFV(phead,"Content-Type",ctype) == 0 )
		return 0;

	if( guessCharset(Conn,ctype) )
		return 1;

	return 0;
}

static void putProxyCookie(Connection *Conn,FILE *tc,int rcode,PCStr(head)){
	HTCCX_putSVCC(Conn,tc,rcode,head);
}
void getProxyCookie(Connection *Conn,QueryContext *QX,PVStr(field)){
	HTCCX_getSVCC(Conn,BVStr(field));
}

int checkGzip(Connection *Conn);
static FILE *threadGzip(Connection *Conn,ResponseContext *RX,FILE *ofp);

int HTTP_MIN_GZIP_SIZE = 256;
int HTTP_putMIMEmsgX(Connection *XConn,FILE *in,FILE *out,ResponseContext *RX);
int HTTP_putMIMEmsg(Connection *XConn,FILE *in,FILE *out)
{
	return HTTP_putMIMEmsgX(XConn,in,out,0);
}
int HTTP_putMIMEmsgX(Connection *XConn,FILE *in,FILE *out,ResponseContext *RX)
{	CStr(line,1024);
	int hsize,msize;
	int chunked = 0;
	int oleng,nleng,wleng;
	/* SHOULD rewrite "Line:" header also */
	int fnlen;
	FILE *zip;
	int cencoded = 0;
	IStr(oenc,32);
	CStr(cencode,64);
	CStr(ctype,128);
	int dosign = 0;
	CStr(md5d,16);

	if( lDONTHT() && XConn ){
		Connection *Conn = XConn;
		if( RX_code == 401 && withNTHT ){
			sv1log("----NTHT %X putMIMEmsg (%d)\n",withNTHT,RX_code);
			if( (withNTHT & NTHT_REQ) == 0 ){
				sv1log("----NTHT %X NO putMIMEmsg\n",withNTHT);
				out = WRNULLFP();
			}
		}
	}
	oleng = 0;
	cencode[0] = 0;
	ctype[0] = 0;
	for(;;){
		if( fgets(line,sizeof(line),in) == NULL ) break;
		if( line[0] == '\r' || line[0] == '\n' ) break;
		if( fnlen = STRH(line,F_ContType) )
			wordScan(line+fnlen,ctype);
		else
		if( fnlen = STRH(line,F_ContLeng) )
			oleng = atoi(line+fnlen);
		else
		if( fnlen = STRH(line,F_TransEncode) ){
			if( strcasestr(line+fnlen,"chunked") )
				chunked = 1;
			sv1log("#HT11 chunked=%d %s",chunked,line);
		}
		else
		if( fnlen = STRH(line,F_ContEncode) ){
			cencoded = 1;
			wordScan(line+fnlen,oenc);
		}
		else
		if( fnlen = STRH(line,F_AccEncodeX) ){
			wordScan(line+fnlen,cencode);
		}
		else
		if( fnlen = STRH(line,F_ContMD5) ){
			dosign = 1;
		}
	}
	msize = file_size(fileno(in));
	hsize = ftell(in);
	nleng = msize - hsize;

	if( XConn ){
		Connection *Conn = XConn;
		if( RESP_DoZIP && ImResponseFilter ){
thfprintf(stderr,"----putMIMEmsg cencode[%s] [%s][%s]%d\n",
	cencode,oenc,ctype,oleng);
		}
	}

	if( cencode[0] && nleng < HTTP_MIN_GZIP_SIZE ){
		sv1log("putMIMEmsg: suppressed [%s] for small body(%d)\n",
			cencode,nleng);
		clearVStr(cencode);
	}

	zip = 0;
	if( !chunked && !cencoded && cencode[0] ){
		if( isinList(cencode,"gzip") || isinList(cencode,"x-gzip") ){
			int ci,ch,isbin;

			isbin = 0;
			for( ci = 0; ci < 256; ci++ ){
				ch = getc(in);
				if( ch == EOF )
					break;
				if( ch == 0 ){
					isbin = 1;
					break;
				}
			}
			if( isbin ){
			  /* might be GIF in malinformed text/html */
			  Verbose("#CEcl is-binary data(%d), don't gzip\n",ci);
			}

			if( !isbin ){
			/* flush input buffer before sending it to system() */
				{
					fseek(in,0,0);
					fseek(in,hsize,0);
				}
				/*
				if( zip = Gzip(cencode,in) ){
				*/
				checkGzip(MainConn()); /* for CFI process/Win */
				if( zip = Gzip(AVStr(cencode),in) ){
					fseek(zip,0,0);
					nleng = file_size(fileno(zip));
					msize = hsize + nleng;
					if( RX ) RX_didZip = 2;
				}
			}
		}
	}

	sv1log("putMIMEmsg: Content-Length: %d -> %d (%d - %d) [%s]\n",
		oleng,nleng,msize,hsize,cencode);

	if( dosign ){
		fMD5(in,md5d);
	}
	fseek(in,0,0);

	for(;;){
		if( fgets(line,sizeof(line),in) == NULL ) break;
		if( fnlen = STRH(line,F_ContMD5) ){
			Connection *Conn = XConn;
			if( dosign && Conn && (ClientFlags & PF_AS_PROXY) ){
				/* 9.9.3 don't overwrite the original MD5 */
				if( MountOptions
				 && isinListX(MountOptions,"sign=","h") ){
					/* 9.0.5 signed MD5 */
				}else
				if( zip ){
					/* MD5 must be after gzip */
					continue;
				}else
				if( DOrewriteResponse(Conn,RX)
				 || RX_didUnzip
				){
					/* modified the content */
				}else{
					fputs(line,out);
					continue;
				}
			}
			putSignedMD5(out,md5d,XConn?XConn->mo_options:NULL);
			continue;
		}
		if( line[0] == '\r' || line[0] == '\n' ){
			if( XConn ){
				/* if( strncaseeq(ctype,"text/",5) ) */
				putProxyCookie(XConn,out,RX_CODE,"");
			}
			if( zip ){
			  sv1log("#CEcl put Content-Encoding:%s\n",cencode);
			  fprintf(out,"%s %s\r\n",F_ContEncode,cencode);
			  fprintf(out,"%s %s\r\n",F_Vary,"Accept-Encoding");
			}
			else
			if( XConn ){
			  /* 9.6.3 to apply gzip to the output from CFIscript */
			  Connection *Conn = XConn;
			  if( REQ_AccEnc[0] ) /* is set if RESP_DoZIP is true */
			  if( strheadstrX(ctype,"text/",1) || RESP_DoUNZIP )
			  if( Conn->xf_filtersCFI & XF_FTOCL ){
			    sv1log("--gzip for CFI[%s] %s\n",REQ_AccEnc,ctype);
			    fprintf(out,"%s %s\r\n",F_AccEncodeX,REQ_AccEnc);
			  }
			}

			if( (HTTP_opts & HTTP_ADDCONTLENG) ){
				/* will be ignored but necessary for some U-A */
				sv1log("#ACLN ADDED %s %d\n",F_ContLeng,nleng);
				fprintf(out,"%s %d\r\n",F_ContLeng,nleng);
			}else
			if( HTTP_head2kill(F_ContLeng,KH_OUT|KH_RES) ){
			}else
			if( !chunked )
			fprintf(out,"%s %d\r\n",F_ContLeng,nleng);
			fputs(line,out);
			break;
		}
		if( fnlen = STRH(line,F_ContType) ){
			HTCCX_restoreCharset(XConn,AVStr(line),fnlen,"putMIME");
		}
		else
		if( fnlen = STRH(line,F_ContLeng) ) continue;
		if( fnlen = STRH(line,F_AccEncodeX) ) continue;
		if( XConn ){
			setGuessedCharset(XConn,AVStr(line));
		}
		fputs(line,out);
	}

	if( XConn && flushHead(XConn,out,nleng) != 0 ){
 sv1log("## stop relay-3: flush()=EOF, client seems dead\n");
		wleng = -1;
	}else{
		if( zip ){
			in = zip;
		}
		wleng = copy_fileTIMEOUT(in,out,NULL);
		if( wleng != nleng ){
 sv1log("## stop relay-4: FWRITE(%d)=%d, SIGPIPE=%d, client seems dead\n",
 nleng,wleng,nsigPIPE);
			wleng = -1;
		}
	}
	if( zip ){
		fclose(zip);
		if( XConn ) XConn->xf_clprocs |= XF_FTOCL;
	}
	if( wleng <= 0 ){
		if( nleng != 0 || lFILEDESC() )
		sv1log("--putMIMEmsg wrote %d/%d\n",wleng,nleng);
	}
	if( RX ){
		RX_xinLen = nleng;
	}
	return wleng;
}
static void attach_respbuff(Connection *Conn,ResponseContext *RX)
{
	RX_respBuff = getTmpFile(RX_tmpFileId/*,Conn*/);
	RX_tc_sav = RX_tcp;
	RX_tcp = RX_respBuff;
	if( lFILEDESC() ){
		sv1log("{F} >>[%d]+[%d][%d] attach_respbbuff\n",
			fileno(RX_tcp),fileno(RX_tc_sav),ClientSock);
	}
	RX_tcd = -1;
}
/*
static FILE *detach_respbuff(Connection *Conn,FILE *tc_buf,FILE *tc,int checkHead,PCStr(reason))
*/
#define detach_respbuff(C,tcbuf,tc,H,r) detach_respbuffX(C,RX,tcbuf,tc,"",0,H,r)

static int todoZipType(PCStr(ctype)){
	if( strncaseeq(ctype,"image/",6) ){
		if( isinListX("bmp,x-bmp,x-ms-bmp",ctype+6,"c") ){
			return 1;
		}
	}
	return 0;
}
static int todoZip(Connection *Conn,ResponseContext *RX){
	int dozip = 0;
	if( RX_didUnzip ){
		dozip = 1;
	}else
	if( strncaseeq(RX_ctype,"text/",5) ){
		if( strcaseeq(RX_ctype,"text/css") ){
			dozip = -2;
			/* don't gzip CSS for old Mozilla */
		}else{
			dozip = 2;
		}
	}
	else
	if( todoZipType(RX_ctype) ){
		dozip = 3;
	}

	if( 0 < dozip )
	if( !enbugGZIP_STREAM() )
	if( RX_rdContLenGot == 0 )
	if( RX_fromcache == 0 )
	if( RX_rdTotal < 16*1024 )
	/* if( ClientFlags & PF_VIA_PROXY ) */
	{
		/* 9.9.3 suppress gzip for slow "push server" */
		porting_dbg("## DONT gzip endless [%s] %d/%d (%.1f)",
			RX_ctype,(int)RX_rdTotal,(int)RX_rdContLen,
			Time()-CONN_DONE
		);
		dozip = -4;
	}
	/*
	fprintf(stderr,"----todoZip? %d type[%s] T=%d B=%d\n",
		dozip,RX_ctype,RX_isText,RX_isBin);
	*/
	return 0 < dozip;
}

/* 9.8.2 to detect client's reset as fast as possible. */
static int clientIsReset(PCStr(wh),Connection *Conn,int forcetest){
	int rdy;

	if( ClientSock < 0 )
		return 0;

	if( !forcetest ){
		if( !lSINGLEP() || lMULTIST() )
			return 0;
	}

	if( isWindows() ) /* or Linux-2.6.17 */
	if( rdy = exceptionReady(ClientSock) ){
		sv1log("--- %s: detected disconn. of client [%d]%d %d\n",
			wh,ClientSock,rdy,inputReady(ClientSock,0));
		return 1;
	}
	if( !IsConnected(ClientSock,0) ){
		return 1;
	}
	if( !isWindowsCE() ){
		/*
		this cause significant delay on fast machines
		if( !IsAlive(ClientSock) ){
			return 1;
		}
		*/
	}
	return 0;
}
static FILE *detach_respbuffX(Connection *Conn,ResponseContext *RX,FILE *tc_buf,FILE *tc,PCStr(cenc),FILE *encbody,int checkHead,PCStr(reason))
{	CStr(field,1024);
	CStr(fname,1024);
	CStr(fbody,1024);
	int fnlen;
	int sent_closed = 0;
	FILE *xencbody = 0;

	if( clientIsReset("detach_respbuff",Conn,1) ){
		fclose(tc_buf);
		return tc;
	}

	sv1log("detach respBuff: %s\n",reason);

Verbose("--detach_respbuff %X %d %d %d [%s]\n",p2i(encbody),RESP_DoZIP,RESP_DoUNZIP,RX_cencoded,RX_cencoding);
	if( encbody == 0 )
	if( todoZip(Conn,RX) <= 0 ){
	}else
	if( RESP_DoZIP && isinListX(REQ_AccEnc,"gzip","c") ){
		if( RX_cencoding[0] && RESP_DoUNZIP == 0 ){
			/* thru data already in gzip */
		}else
		if( checkGzip(MainConn()) ) /* for RFilter on Win,FreeBSD */
		if( xencbody = threadGzip(Conn,RX,tc) ){
			cenc = "gzip";
			encbody = xencbody;
			sv1log("detach_respbuff/gzip unzip=%d [%s] %s %d/%d\n",
				RESP_DoUNZIP,REQ_AccEnc,reason,
				(int)RX_rdTotal,(int)RX_rdContLen
			);
		}
	}

	fflush(tc_buf);
	Ftruncate(tc_buf,0,1);
	fseek(tc_buf,0,0);

	if( checkClientEOF(Conn,tc,"detach_respbuff") )
		httpStat = CS_EOF;

	/* copy header removing Connection: Keep-Alive */
	if( checkHead )
	while( fgets(field,sizeof(field),tc_buf) ){
		if( STRH_Connection(field) ){
			scan_field1(field,AVStr(fname),sizeof(fname),AVStr(fbody),sizeof(fbody));
			if( strncasecmp(fbody,"keep-alive",10) == 0 )
			{
				sv1log("ERASED %s",field);
				clntClose(Conn,"b:temp. buff. detached (%s)",
					reason);
			}
			sprintf(field,"%s: close\r\n",fname);
			SentKeepAlive = 0;
			sent_closed = 1;
		}
		if( fnlen = STRH(field,F_ContType) ){
			HTCCX_restoreCharset(Conn,AVStr(field),fnlen,"detach");
		}
		if( STRH(field,F_AccEncodeX) ) continue;
		if( STRH(field,F_ContLeng) ){
		{
			/* remove wrong Content-Length if with some conv. */
			/*
			if( HTTP_opts & HTTP_DELWRONGCONTLENG )
			  9.6.2 this is mandatory when not in the "chunked"
			  encoding and the real result is longer than
                          Content-Length by MOUNT or CHARCODE
			*/
			if( withConversion(Conn,0) ){
			    if( (HTTP_opts & HTTP_ADDCONTLENG) ){
				sv1log("#ACLN DONT-ERASE ka=%d ch=%d nb=%d %s",
					WillKeepAlive,RX_tcx.t_chunked,
					RX_noBody,field);
			    }else
			    if( HTTP_head2kill(F_ContLeng,KH_OUT|KH_RES) ){
			    }else
			    if( !DOrewriteResponse(Conn,RX) ){
				/* it's useful info. when waiting huge data */
			    }else{
				sv1log("ERASED %s",field);
				continue;
			    }
			}
			if( encbody ){
				/* incorrect Content-Length seems fatal
			 	 * for zipped resp. mssg. without chunked
				 */
				sv1log("ERASED %s",field);
				continue;
			}
		}

		}
		setGuessedCharset(Conn,AVStr(field));

		if( !ClientEOF )
		{
			if( field[0] == '\r' || field[0] == '\n' ){
			    putProxyCookie(Conn,tc,RX_CODE,""); /*9.6.2 SVCC*/
			    if( encbody ){
				fprintf(tc,"%s %s\r\n",F_ContEncode,cenc);
				fprintf(tc,"%s %s\r\n",F_Vary,"Accept-Encoding");
			    }
			    if( !sent_closed ){
				/* only with HTTP/1.1 without Connection */
				sv1log("INSERT Connection: close\n");
				fprintf(tc,"Connection: close\r\n");
			    }
			}
		if( fputs(field,tc) == EOF )
			setClientEOF(Conn,tc,"detach_respbuff-1");
		}

		if( field[0] == '\r' || field[0] == '\n' )
			break;
	}

	if( !ClientEOF ){
		if( encbody ){
			int oc;
			fflush(tc);
			oc = copy_fileTIMEOUT(tc_buf,encbody,NULL);
			fflush(encbody);
		}else
		copy_fileTIMEOUT(tc_buf,tc,NULL);
		if( feof(tc) )
			setClientEOF(Conn,tc,"detach_respbuff-2");
	}
	fclose(tc_buf);
	if( xencbody ){
		return xencbody;
	}
	return tc;
}
static int lastmtime(PCStr(line))
{	CStr(scdate,1024);

	lineScan(line,scdate);
	return scanHTTPtime(scdate);
}
static void scanRespHead1(Connection *Conn,ResponseContext *RX,PCStr(line))
{	int fnlen;

	if( fnlen = STRH(line,F_ContEncode) )
	{
		wordScan(line+fnlen,RX_cencoding);
		RX_cencoded = 1;
	}
	else
	if( fnlen = STRH(line,F_ContLeng) )
	{
		if( RX_rdContLenGot )
		if( RX_QX )
		if( fnlen = STRH(line,F_ContLeng) ){
			QueryContext *QX = RX_QX;
			daemonlog("F","ERROR: multiple Content-Length: %lld /%s",RX_rdContLen,line+fnlen);
			QX_cacheRemove = R_BAD_FORMAT;
			QX_svclose = 1;
		}
		/*
		RX_rdContLen = atoi(line+fnlen);
		*/
		Xsscanf(line+fnlen,"%lld",&RX_rdContLen);
		RX_rdContLenGot = 1;
	}
	else
	if( fnlen = STRH(line,F_ContRange) ){
		sv1log("#HT11 %s",line);
	}else
	if( fnlen = STRH(line,F_LastMod) ){
		RX_lastMod = 1;
		RX_lastModTime = lastmtime(line+fnlen);
	}else
	if( fnlen = STRH(line,F_ContType) ){
		const char *pp;
		lineScan(line+fnlen,RX_ctypeline);
		wordScan(line+fnlen,RX_ctype);
		if( pp = strchr(RX_ctype,';') )
		{   const char *cp;
		    if( cp = strstr(pp+1,"charset=") )
		    wordscanY(cp+8,AVStr(SVRespCharset),sizeof(SVRespCharset),"^;");
			truncVStr(pp);
		}
		if( strncaseeq(RX_ctype,"text/",5) ){
			if( strcaseeq(RX_ctype,"text/plain") ){
				if( plain2html() ){
					RX_isText = TX_HTML;
					RX_putPRE = 1;
				}else	RX_isText = TX_PLAIN;
			}else
			if( strcaseeq(RX_ctype,"text/html") )
				RX_isText = TX_HTML;
			else
			if( strcaseeq(RX_ctype,"text/css") )
				RX_isText = TX_CSS;
			else
			if( strcaseeq(RX_ctype,"text/xml") )
				RX_isText = TX_XML;
			else
			if( strcaseeq(RX_ctype,"text/x-component")
			 || strcaseeq(RX_ctype,"text/javascript") )
				RX_isText = TX_JAVASCRIPT;
			else	RX_isText = TX_MISC;
		}else{
			if( strcaseeq(RX_ctype,"application/x-javascript") )
				RX_isText = TX_JAVASCRIPT;
			else
			if( strcaseeq(RX_ctype,"application/xml") )
				RX_isText = TX_XML;
			else
			if( strcaseeq(RX_ctype,"application/soap+xml") )
				RX_isText = TX_XML;
		}
		if( guessCharset(Conn,line) ){
			RX_guessCharset = 1;
		}
	}else
	if( fnlen = STRH(line,F_Server) ){
		lineScan(line+fnlen,RX_servername);
if(LOG_GENERIC){
fputLog(Conn,"Server","%s://%s:%d; version=%s\n",
DST_PROTO,DST_HOST,DST_PORT,RX_servername);
}
	}else
	if( fnlen = STRH(line,F_Pragma) ){
		if( RX_cachecontrol[0] == 0 )
		lineScan(line+fnlen,RX_cachecontrol);
	}else
	if( fnlen = STRH(line,F_CacheControl) ){
		lineScan(line+fnlen,RX_cachecontrol);
	}else
	if( line[0] == '\r' || line[0] == '\n' ){
		RX_inHeader = 0;
	}
	if( RX_errori )
	if( RX_code != 404 )
		sv1log("HTTP error header: %s",line);
}

static int appendVia(Connection *Conn,int isreq,PVStr(fields),int fsize)
{	CStr(via,MaxHostNameLen);
	CStr(vb,MaxHostNameLen);
	refQStr(ovia,fields); /**/
	const char *nvia;

	HTTP_genVia(Conn,isreq,AVStr(via));
	if( *via == 0 )
		return 0;

	if( ovia = findFieldValue(fields,"Via") ){
		for(;;){
			if( ovia = strpbrk(ovia,"\r\n") ){
				/* find the last Via */
				if( nvia = findFieldValue(ovia,"Via") ){
					ovia = (char*)nvia;
					continue;
				}
			}
			break;
		}
	}
	if( fsize < strlen(fields) + strlen(vb) + 1 + 8 ){
		daemonlog("F","Via too long:[%s]%s",via,fields);
		return 0;
	}
	if( ovia ){
		sprintf(vb,", %s",via);
		Strins(AVStr(ovia),vb);
	}else{
		sprintf(vb,"Via: %s\r\n",via);
		RFC822_addHeaderField(AVStr(fields),vb);
	}
	return 1;
}

static void setServKeepAlive(Connection *Conn,ResponseContext *RX)
{
	ServKeepAlive = 0;
	if( !RX_fromcache )
	if( !(toMaster && vercmp(MediatorVer,CHUNKED_VER) < 0) )
	if( streq(RX_ver,"HTTP/1.1") && strncasecmp(RX_connection,"close",6) != 0
	 || strncasecmp(RX_connection,"keep-alive",10) == 0
	)
	if( ImResponseFilter
	){
		/* 9.5.0-pre7 responseFilter will be noticed with EOF
		 * and the header might include Connection:keep-alive
		 * (for the client not for the filter)
		 * and the Content-Length could be wrong (ex. from .shtml)
		 * which will cause truncation of data when it indicates
		 * shorter than real (or cause delay when longer than real?)
		 */
		sv1log("#HT11 don't Keep-Alive as RespFil: %s\n",REQ_URL);
	}else
	{
		ServKeepAlive = 1;
		RX_fsx.t_keepAlive = 1;
		Verbose("#HT11 server KEEP-ALIVE\n");
	}
}

extern int MasterXi;
extern int MasterXo;
static const char *DGC_MASTER = "DeleGate-Control-MASTER";
extern const char *TIMEFORM_COOKIE;
const char *DeleGateMId(PVStr(pn)){
	sprintf(pn,"%s-%s-IX",DGC_MASTER,DeleGateId());
	return pn;
}
const char *DeleGateSId(PVStr(pn)){
	sprintf(pn,"DGSID-%s",DeleGateId());
	return pn;
}

static int getDGC_ROUTE(Connection *Conn,PVStr(req)){
	CStr(pn,64);
	CStr(mx,128);
	int mi;

	if( strstr(req,DGC_MASTER) == 0 )
		return 0;

	DeleGateMId(AVStr(pn));
	if( !extractParam(AVStr(req),"Cookie",pn,AVStr(mx),sizeof(mx),1) )
		return 0;
	mi = atoi(mx);

	sv1log("MasterXi=%d\n",mi);
	MasterXi = mi;
	return 1;
}
static int putDGC_ROUTE(Connection *Conn,FILE *tc){
	int exp;
	CStr(ex,128);
	CStr(cookie,128);
	CStr(pn,64);
	int nput = 0;

	if( HTTP_opts & HTTP_NODGC_ROUTE )
		return 0;

	if( 0 < MasterXo ) /* MASTER is applied in this connection */
	if( MasterXi != MasterXo )
	{
		exp = time(0) + 10*60;
		StrftimeGMT(AVStr(ex),sizeof(ex),TIMEFORM_COOKIE,exp,0);
		sprintf(cookie,"%s=%d",DeleGateMId(AVStr(pn)),MasterXo);
		Xsprintf(TVStr(cookie),"; Expires=%s; Path=/",ex);
		sv1log("MasterXi=%d -> MasterXo=%d\n",MasterXi,MasterXo);
		fprintf(tc,"Set-Cookie: %s\r\n",cookie);
		nput++;
	}
	return nput;
}

/*
 * do something before ending response header
 * with empty CRLF line
 */
#if defined(UNDER_CE)
int XfputsCRLF(PVStr(str),FILE *fp);
#else
int XfputsCRLF(PVStr(str),FILE *fp){
	int err = 0;
	int ch;
	int lastch = 0;
	const char *sp;

	for( sp = str; ch = *sp; sp++ ){
		assertVStr(str,sp);
		if( putc(ch,fp) == EOF ){
			return 1;
		}
		lastch = ch;
		if( sp[1] == '\n' ){
			if( ch != '\r' ){
				if( putc('\r',fp) == EOF ){
					return 2;
				}
			}
		}
	}
	if( lastch != '\n' ){
		syslog_ERROR("ADDED CRLF: %s\n",str);
		if( lastch != '\r' ){
			if( putc('\r',fp) == EOF ){
				return 3;
			}
		}
		if( putc('\n',fp) == EOF ){
			return 4;
		}
	}
	return 0;
}
#endif

static void endRespHead(Connection *Conn,ResponseContext *RX){
	/*
	CStr(head,256);
	*/
	CStr(head,4*1024);

	if( RX_ctype[0] == 0 )
	if( RX_code != 304 ){
		const char *ctype;
		refQStr(rp,head);

		strcpy(head,REQ_URL);
		if( rp = strchr(head,'?') ){
			setVStrEnd(rp,0);
		}
		if( ctype = filename2ctype(head) ){
		}else{
			ctype = "application/octet-stream";
		}
		sv1log("Guessed Content-Type:%s %s://%s:%d%s\n",ctype,
			DST_PROTO,DST_HOST,DST_PORT,head);
		sprintf(head,"Content-Type: %s\r\n",ctype);
		scanRespHead1(Conn,RX,head);
	}
	putDGC_ROUTE(Conn,RX_tcp);
	if( !ClientEOF && RX_qWithHeader ){
		head[0] = 0;
		if( HTTP_genhead(Conn,AVStr(head),KH_OUT|KH_RES) )
			XfputsCRLF(AVStr(head),RX_tcp);
	}
	if( lDONTHT() ){
		if( (HTTP_opts & HTTP_DOAUTHCONV) == 0 )
		if( withNTHT & (NTHT_REQ|NTHT_RES) )
		if( (withNTHT & (NTHT_CLBASIC|NTHT_CLAUTHOK)) == 0 )
		{
			sv1log("----NTHT %X added Proxy-Support header\n",withNTHT);
			fputs("Proxy-support: Session-Based-Authentication\r\n",RX_tcp);
		}
	}
	if( !ImResponseFilter ){
		if( !ClientEOF && RX_qWithHeader ){
			appendVia(Conn,0,AVStr(RX_lastVia),sizeof(RX_lastVia));
			/*
			if( HTTP_opts & HTTP_SESSION ){
			*/
				if( genSessionCookie(Conn,AVStr(head)) )
					XfputsCRLF(AVStr(head),RX_tcp);
			/*
			}
			*/
			refreshDigestNonce(Conn,RX_tcp);
			if( RESP_ADD[0] ){
				XfputsCRLF(AVStr(RESP_ADD),RX_tcp);
			}
		}
	}
	if( RX_lastVia[0] ){
		if( !HTTP_head2kill(RX_lastVia,KH_OUT|KH_RES) )
			XfputsCRLF(AVStr(RX_lastVia),RX_tcp);
	}
	if( !HTTP_head2kill(F_Expires,KH_OUT|KH_RES) ){
		strcpy(head,RX_expires);
		if( !ImResponseFilter || head[0] == 0 )
			getMountExpires(Conn,AVStr(head),sizeof(head));
		if( head[0] )
			fprintf(RX_tcp,"Expires: %s\r\n",head);
	}

	HTTP_editResponseHeader(Conn,RX_tcp);
	sv1log("#HT11 SERVER ver[%s] conn[%s]\n",RX_ver,RX_connection);

	setServKeepAlive(Conn,RX);

	/* asked Keep-Alive in the request, so must reply
	 * int the respose.
	 */
	if( !ClientEOF && ClntKeepAlive ){
		if( !RX_noBody )
			HTTP_modifyConnection(Conn,RX_rdContLen);

		if( RX_tryKeepAlive ){
/*
if( !RX_noBody && RX_tcp != RX_respBuff && RX_rdContLen==0 )
clntClose(Conn,"u:unbound length data");
*/
			if( RX_errori )
				if( lDONTHT()
				/*
				 && (RX_code == 401 || RX_code == 404)
				*/
				 && (RX_code == 401 || RX_code == 404 || RX_code == 407)
				 && (withNTHT & (NTHT_REQ|NTHT_RES)) ){
					sv1log("----NTHT Keep-Alive on err. (%d) %X\n",
					RX_errori,withNTHT);
				}else
				clntClose(Conn,"s:bad status: %d",RX_errori);

			if( !HTTP_CKA_CFI )
			if( Conn->xf_filters & (XF_FTOCL|XF_FCL) )
				if( lDONTHT() ){
					Verbose("----NTHT Keep-Avlie (A)\n");
				}else
				if( doKeepAliveWithSTLS(Conn) ){
					Verbose("Keep-Avlie with TLS (A)\n");
				}else
				clntClose(Conn,"x:external filter");

			if( RX_noBody ){
				/* 9.8.2 the following code is introduced at
				 * 8.10.6 to stop clnt-KA on Content-Length:0
				 * in the header with a non-empty body.
				 */
			}else
			/*if( HTTP_opts & HTTP_STOPKA_CONT0 )*/
			if( RX_fsx.t_chunked == 0 && RX_rdContLen == 0 )
			if( 0 < fPollIn(RX_fsp,1) )
			if( 0 < READYCC(RX_fsp) || 0 < Peek1(fileno(RX_fsp)) )
			{
				/* chunked encoding with client is suppressed
				 * when guessed as "emptyBody" (why?). But
				 * here, going to relay a non-empty body
				 * which will break the message boundary for
				 * keep-alived connection with the client.
				 */
				int dontclose = 0;
				if( lDONTHT() ){
					sv1log("--NTHT CKA=%d ContLeng:0\n",
						WillKeepAlive);
					dontclose = 1;
				}else
				if( (HTCKA_opts & HTCKA_RESPNOLENG) ){
					if( WillKeepAlive == 0 ){
						/* "Closed" by other reason */
					}else
					sv1log("##CKA ContLeng:0\n");
					dontclose = 2;
				}else
				if( RX_rdContLenGot == 0
				 && RX_fromcache
				 && (ClientFlags & PF_MITM_ON)
				){
					/* 9.9.3 too heavy to close */
					dontclose = 3;
				}else
				if( RX_rdContLenGot == 0
				 && RX_tcx.t_chunked
				){
					/* 9.9.3 ContLeng unnecessary */
					dontclose = 4;
				}
				if( dontclose ){
			sv1log("##CKA ContLeng:0 (%d) KA%d LG%d CA%d BF%d CK%d %s\n",
					dontclose,WillKeepAlive,
					RX_rdContLenGot,RX_fromcache,
					RX_tcp==RX_respBuff,RX_tcx.t_chunked,
					(ClientFlags&PF_MITM_ON)?"MITM":"");
				}else
				clntClose(Conn,"0:Content-Length: 0");
			}
		}
		if( lDONTHT() && (withNTHT & NTHT_START) ){
			sv1log("----NTHT Connection(%d)\n",RX_code);
			/* should set the timeout longer ... */
		}
		putKeepAlive(Conn,RX_tcp);
	}

	if( !ClientEOF ){
		if( RX_emptyBody ){
		}else
		if( RX_tcx.t_chunked && !RX_noBody ){
			sv1log("#HT11 --putChunk-Header: %s chunked\r\n",
				F_TransEncode);
			fprintf(RX_tcp,"%s chunked\r\n",F_TransEncode);
		}
	}
}

int gotSIGPIPE();
#define putChunk(RX,buff,leng)	putChunkX(Conn,RX,buff,leng)
static int putChunkX(Connection *Conn,ResponseContext *RX,PCStr(buff),int leng)
{	int wcc,chunked;

	if( RX_discardResp ){
		return leng;
	}
	if( ClientEOF ){
		/* canbe in "takeover" or "Distribution" */
Verbose("+++EPIPE putChunkX() already EOF SIG*%d [%d/%X]\n",gotSIGPIPE(),fileno(RX_tcp),p2i(RX_tcp));
		return 0;
	}
	if( RX_emptyBody ){
		chunked = 0;
	}else
	if( RX_isHTTP09 )
		chunked = 0;
	else	chunked = !RX_inHeader && RX_tcx.t_chunked;
	if( chunked ){
		RX_tcx.t_chunk_ser += 1;
		Verbose("#HT11 --putChunk[%d] %d\n",RX_tcx.t_chunk_ser,leng);
		fprintf(RX_tcp,"%x\r\n",leng);
	}
	if( 0 < leng )
	{
		wcc = fwriteTIMEOUT(buff,1,leng,RX_tcp);
		if( wcc < leng || gotSIGPIPE() ){
Verbose("+++EPIPE putChunkX() fwrite %d/%d SIG*%d\n",wcc,leng,gotSIGPIPE());
			dupclosed(fileno(RX_tcp));
			return wcc;
		}
	}
	else	wcc = 0;
	if( chunked ){
		fputs("\r\n",RX_tcp);
		if( HTTP_opts & HTTP_FLUSHCHUNK ){
			fflush(RX_tcp);
			sv1log("#HT11 -- flush-chunk #%d %d/%d\n",
				RX_tcx.t_chunk_ser,wcc,leng);
		}
	}

	if( !RX_inHeader )
	if( (HTTP_opts & HTTP_NOFLUSHCHUNK) == 0 ){
		if( HTTP_opts & HTTP_DUMPSTAT ){
			if( RX_wrTotal == 0 ){
				int elps;
				elps = (int)(1000*(Time()-CONN_DONE));
				if( RX_fromcache )
					elps -= 1000;
			fprintf(stderr,"[%d]%c 1stFlushChunk(%4dms) %5d %s\n",
				getpid(),RX_fromcache?'H':' ',
				elps,wcc,REQ_URL);
			}
		}
		if( RX_tcpissock ){
			if( clientIsReset("putChunk-fflush-A",Conn,0) ){
				setClientEOF(Conn,RX_tcp,"putChunk-fflush-A");
			}else
			if( 300 <= RX_code ){
				/* 9.8.2 don't flush not to cause SIGPIPE
				 * (with Firefox) in the middle of the 404
				 * responses of the chunked encoding.
				 */
				if( 0 )
				porting_dbg("don't flush: %d #%d %d/%d [%d]%d",
					RX_code,RX_tcx.t_chunk_ser,
					(int)RX_wrTotal,(int)RX_rdContLen,
					fileno(RX_fsp),fPollIn(RX_fsp,1)
				);
			}else
			if( fflushTIMEOUT(RX_tcp) == EOF ){
				setClientEOF(Conn,RX_tcp,"putChunk-fflush-B");
			}
		}else
		fflush(RX_tcp);
		RX_lastFlush = Time();
		RX_wrbufed = 0;
	}
	return wcc;
}
static int getChunk(ResponseContext *RX)
{	CStr(line,1024);

	if( 0 < RX_fsx.t_chunk_ser ){
		while( fgets(line,sizeof(line),RX_fsp) != NULL ){
			Verbose("#HT11 --getChunk[%d] footer: %s",
				RX_fsx.t_chunk_ser,line);
			if( *line == '\r' ) /* CRLF */
				break; 
				/* entitiy-headers in the last chunk */
		}
		if( RX_fsx.t_chunk_siz == 0 )
			return -1;
	}
	line[0] = 0;
	fgets(line,sizeof(line),RX_fsp);
	RX_fsx.t_chunk_rem = 0;
	sscanf(line,"%x",&RX_fsx.t_chunk_siz);
	/* this does not cope with a huge chunk > 4GB */
	RX_remsize = RX_fsx.t_chunk_siz;
	if( sizeof(RX_rdBuff)-1 < RX_remsize )
		RX_remsize = sizeof(RX_rdBuff)-1;
	RX_fsx.t_chunk_rem = RX_fsx.t_chunk_siz; 
	RX_fsx.t_chunk_ser++;

	Verbose("#HT11 --getChunk[%d] header: (%d) %s",RX_fsx.t_chunk_ser,
		RX_fsx.t_chunk_siz,line);
	return RX_fsx.t_chunk_ser;
}

int escNullChar(char line[],int leng,int size){
	int ci;
	int xi = 0;
	for( ci = 0; ci < leng && ci < size; ci++ ){
		if( line[ci] == '\1' ){
			sv1log("## escNullChar() found original '\\1'\n");
		}else
		if( line[ci] == '\0' ){
			line[ci] = '\1';
			xi++;
		}
	}
	return xi;
}
int unescNullChar(char line[],int leng,int size){
	int ci;
	int xi = 0;
	for( ci = 0; ci < leng && ci < size; ci++ ){
		if( line[ci] == '\0' ){
			sv1log("## unescNullChar() found premature '\\0'\n");
			break;
		}else
		if( line[ci] == '\1' ){
			line[ci] = '\0';
			xi++;
		}
	}
	return xi;
}

static int fputsResponseChunk(Connection *Conn,ResponseContext *RX,PVStr(line),PCStr(ctype),int doconv,int deent)
{	const char *oline;
	int leng,wcc;

	if( lPEEPDGCL() ){
	    if( RX_inHeader ){
		dumpmsg(&RX_dumpDC,RX_fromcache?"C-T":"D-T",line);
	    }
	}
	if( ClientEOF && ferror(RX_tcp) ){
		/* doing "takeover" caching after client's disconnection */
		/* suppress fwrite() to cause SIGPIPE */
		return 0;
	}
	if( ClientEOF && (ClientFlags & PF_IS_DISTRIB) ){
		/* 9.6.3 doing "Distribution" to parallel updating receivers */
		return 0;
	}
	if( RX_isBin && RX_isText ){ /* 9.6.1 text including '\0' */
		escNullChar((char*)line,RX_fsx.t_lastRcc,IBUFSIZE);
	}
	if( RelayTHRU || !BORN_SPECIALIST && !ACT_SPECIALIST ){
		oline = line;
		leng = strlen(line);
	}else{
		if( !RX_inHeader && Conn->dg_putpart[0] ){
			if( Partfilter(Conn,&RX->r_partf,AVStr(line),IBUFSIZE) == 0 )
				return 0;
		}
	oline = rewriteResponse(Conn,RX,RX_referer,AVStr(line),ctype,doconv,deent,RX_tcp);
	leng = strlen(oline);
	}
	if( RX_isBin && RX_isText ){
		unescNullChar((char*)line,RX_fsx.t_lastRcc,IBUFSIZE);
		if( oline != line )
			unescNullChar((char*)oline,leng,RESP_LINEBUFSZ);
	}

	if( 0 < leng ){
		wcc = putChunk(RX,oline,leng);
		if( wcc < leng ){
			setClientEOF(Conn,RX_tcp,"fputsResponse");
			return 0;
		}else	return wcc;
	}else{
		sv1log("#HT11 fputsResponse(leng=%d)\n",leng);
		return leng;
	}
}
#define FPUTS(line,ctype,doconv,deent) \
	fputsResponseChunk(Conn,RX,line,RX_inHeader?0:ctype,doconv,deent)

static int fwriteResponseChunk(Connection *Conn,ResponseContext *RX,PCStr(buff),int leng)
{	int wcc;

	if( leng <= 0 )
		return leng;
	return putChunk(RX,buff,leng);
}
static void log_codeconv(Connection *Conn,ResponseContext *RX)
{	const char *xcharset;

	if( CCXactive(CCX_TOCL) ){
		if( xcharset = HTTP_outCharset(Conn) )
			sv1log("Code Conversion [CHARCODE=%s][%s]\n",xcharset,RX_ctype);
	}else{
		CTX_check_codeconv(Conn,1);
	}
}

static void filterApplet(Connection *Conn,ResponseContext *RX,PVStr(line))
{	FILE *tmp;
	refQStr(dp,line); /**/
	CStr(userAgent,64);
	CStr(warn,URLSZ);
	int rcc;

	dp = strcasestr(line,"<APPLET ");
	if( dp == NULL )
		return;

	if( strstr(proxyCookie,"APPLET") ){
		sv1log("#DONT CHECK APPLET: Cookie=%s\n",proxyCookie);
		return;
	}

	strcpy(userAgent,"UA-TEST");
	tmp = TMPFILE("AppletWarning");
	putBuiltinHTML(Conn,tmp,"AppletWarning","applet.dhtml",NULL,
		(iFUNCP)DHTML_printConn,NULL);
	fflush(tmp); fseek(tmp,0,0);
	rcc = fread(warn,1,sizeof(warn),tmp);
	if( rcc < 0 )
		rcc = 0;
	warn[rcc] = 0;
	fclose(tmp);
	Strins(AVStr(dp),warn);
	daemonlog("E","#Inserted Warning for APPLET\n");
}

static int NoRelayField(Connection *Conn,ResponseContext *RX,PCStr(field))
{	int fnlen;
	CStr(val,64);

	if( RESP_DoUNZIP ){
		if( fnlen = STRH(field,F_ContEncode) ){
			wordScan(field+fnlen,val);
			if( strcaseeq(val,"gzip") )
				return 1;
			if( strcaseeq(val,"x-gzip") )
				return 2;
		}
		if( fnlen = STRH(field,F_Vary) ){
			wordScan(field+fnlen,val);
			if( strcaseeq(val,"Accept-Encoding") )
				return 1;
		}
	}
	return 0;
}

static void Fpurge(FILE *tc);
static void relayTxtResp1(Connection *Conn,ResponseContext *RX,QueryContext *QX,PCStr(req))
{	int wcc;
	MrefQStr(line,RX_rdBuff); /**/
	int fnlen;
	CStr(buf,1024);
	refQStr(out,buf); /**/

	if( !RX_inHeader ){
		if( HTTP_warnApplet )
		if( appletFilter )
			filterApplet(Conn,RX,AVStr(line));

		wcc = FPUTS(AVStr(line),RX_ctype,!RX_inHeader && RX_convChar,RX_deEnt);
		RX_wrTotal += wcc;
		return;
	}

	if( SimpleContType && STRH(line,F_ContType) ){
		refQStr(dp,line); /**/
		if( dp = strchr(line,';') ){
			sv1log("Discard Parameter -- %s",dp);
			strcpy(dp,"\r\n");
		}
	}

	if( RX_deEnt && STRH(line,F_DGVer) )
		RX_deEnt = 0;

	/*
	 * the charset should be rewritten only when
	 * the code conversion in the body is made ...
	 */
	/*
	if( RX_convChar && !SimpleContType && STRH(line,F_CtypeText) ){
	*/
	if( RX_convChar && !SimpleContType )
	if( fnlen = STRH(line,F_ContType) ){
		HTCCX_replaceCharset(Conn,AVStr(line),fnlen,RX_fsp);
	}

	if( NoRelayField(Conn,RX,line) ){
		Verbose("#CEsv DONT relay %s",line);
		return;
	}else
	if( line[0] == '\r' || line[1] == '\n' ){
		if( RESP_DoZIP )
		if( RX_isText ){
			/* if without non-CFI FTOCL */
			if( (Conn->xf_filters & XF_FTOCL) == 0
			 || (Conn->xf_filtersCFI & XF_FTOCL) != 0
			)
			if( RX_noBody ){
				/* don't generate X-Q-Accept-Encoding for
				 * head only response (HEAD or 304)
				 */
			}else
			{
				/*
				sprintf(buf,"%s %s\r\n",F_AccEncodeX,"gzip");
				*/
				sprintf(buf,"%s %s\r\n",F_AccEncodeX,QX_accEnc);
				wcc = strlen(buf);
				fputs(buf,RX_tcp);
				RX_wrHeadTotal += wcc;
			}
		}else{
			/* detach_respbuff() if it's just for DoZIP */
		}
	}else
	if( fnlen = STRH(line,F_ContLeng) ){
		if( RX_tcx.t_chunked && RX_noBody ){
			/* don't skip Content-Length for HEAD */
		}else
		if( RX_tcx.t_chunked ){
			if( HTTP_opts & HTTP_DELWRONGCONTLENG ){
				sv1log("#HT11 chunked, skip %s",line);
				return;
			}
			if( atoi(line+fnlen) < HTTP_CHUNKED_CLENG ){
				sv1log("#HT11 chunked, skip short %s",line);
				return;
			}
			sv1log("#HT11 chunked, should skip: %s",line);
		}
		else
		if( QX_hcode == 304 && !enbugCONTLENG304() ){
			/* 9.9.5 for Safari */
			sv1log("#HT11 304 skip: Content-Length:%d\n",atoi(line+fnlen));
			return;
		}else
		if( RESP_DoUNZIP
		 && RX_isText && RX_cencoded && (Conn->xf_filters & XF_FTOCL)
		 && RX_respBuff == 0
		){
			/* 9.9.5 gunzip for FTOCL, without respbuff */
			sv1log("#HT11 gunzip/FTOCL skip: %s",line);
			return;
		}
	}else
	if( fnlen = STRH(line,F_PAuthenticate) ){
		IStr(atype,64);
		wordScan(line+fnlen,atype);
		if( lDONTHT() ){
			lineScan(line+fnlen,NTHT_nego);
			if( strcaseeq(atype,"Negotiate") ){
				withNTHT |= NTHT_RESNEGO;
				sv1log("----NTHT R %s %X\n",atype,withNTHT);
			}else
			if( strcaseeq(atype,"NTHT") ){
				withNTHT |= NTHT_RESNTLM;
				sv1log("----NTHT R %s %X\n",atype,withNTHT);
			}
		}
	}else
	if( fnlen = STRH(line,F_Authenticate) ){
		IStr(atype,64);
		wordScan(line+fnlen,atype);
		Verbose("WWW-Authenticate: %s\n",atype);
		if( lDONTHT() ){
			lineScan(line+fnlen,NTHT_nego);
			if( strcaseeq(atype,"Negotiate") ){
				withNTHT |= NTHT_RESNEGO;
				sv1log("----NTHT R %s %X\n",atype,withNTHT);
			}else
			if( strcaseeq(atype,"NTHT") ){
				withNTHT |= NTHT_RESNTLM;
				sv1log("----NTHT R %s %X\n",atype,withNTHT);
			}
		}
	}else
	if( fnlen = STRH(line,F_SetCookie) ){
		lineScan(line+fnlen,RX_setCookie);
		MountCookieResponse(Conn,req,QVStr(line+fnlen,RX_rdBuff));
		if( lCCXCOOKIE() && CCXactive(CCX_TOCL) ){
			HTCCX_Rhead(Conn,AVStr(line));
		}
		/*
		if( HTTP_cacheopt & CACHE_COOKIE ){
			Verbose("caching resp. with Set-Cookie\n");
		}else
		*/
		if( RX_cachefp ){
			Ftruncate(RX_cachefp,0,0);
			fseek(RX_cachefp,0,0);
			RX_cachefp = NULL;
			QX_cacheRemove = R_PRIVATE;
		}
	}else
	if( fnlen = STRH(line,F_Location) ){
		if( RX_code == 301 || RX_code == 302 ){
			sv1log("%s",line);
			if( isMovedToSelf(Conn,line+fnlen) ){
				RX_errori = R_MOVED_LOOP;
				sv1log("#### don't cache MOVED loop\n");
			}
			if( WillKeepAlive && isMovedToAnotherServer(Conn,line+fnlen) )
				if( lDONTHT() ){
					sv1log("----NTHT hold KA on moved\n");
				}else
				clntClose(Conn,"m:moved to another server");
		}
	}

	out = NULL;
	if( HTTP_ignoreIf && (
	    (fnlen = STRH(line,F_Etag))
	 || (fnlen = STRH(line,F_LastMod))
	)){
		sv1log("IGNORE IF-: %s",line);
	}else
	if( fnlen = STRH(line,F_KeepAlive) ){
		sv1log("HCKA:[R] %s",line);
		strcpy(RX_connection,"Keep-Alive");
	}else
	if( fnlen = STRH(line,F_Upgrade) ){
		sv1log("IGNORE response: %s",line);
	}else
	if( fnlen = STRH_Connection(line) ){
		Verbose("HCKA:[R] %s",line);
		lineScan(line+fnlen,RX_connection);
	}else
	if( fnlen = STRH(line,F_TransEncode) ){
		wordScan(line+fnlen,RX_tencoding);
		if( strcaseeq(RX_tencoding,"chunked") ){
			sv1log("#HT11 --getChunk-Header: %s",line);
			RX_fsx.t_chunked = 1;
		}
	}else
	/* Content-Encoding: must be removed with RESP_DoUNZIP/RESP_DoZIP */
	if( fnlen = STRH(line,F_ContMD5) ){
		int err;
		err = verifySignedMD5(line,NULL,MountOptions);
		if( err < 0 ){
fprintf(stderr,"[%d]-- Verify ERROR(%d) [%s] %s",getpid(),err,REQ_URL,line);
			if( RX_tc_sav != NULL )
				Fpurge(RX_tc_sav);
			Fpurge(RX_tcp);
			fprintf(RX_tcp,"HTTP/1.0 500 Content-MD5 Error\r\n");
			fprintf(RX_tcp,"Connection: close\r\n");
			fprintf(RX_tcp,"\r\n");
			fprintf(RX_tcp,"Content-MD5 Error\r\n");
			daemonlog("F","Bad MD5: %s",line);
			RX_errori = R_BAD_MD5;
		}else
		if( err == 0 ){
			if( withConversion(Conn,0) ){
				sprintf(buf,"%s\r\n",F_ContMD5);
				cpyQStr(out,buf);
fprintf(stderr,"[%d]-- Verify OK [%s] removed %s",getpid(),REQ_URL,line);
			}else{
				/* thru it if without modification ... */
				cpyQStr(out,line);
			}
		}
		else{
fprintf(stderr,"[%d]-- Verify OK(%d) [%s] %s",getpid(),err,REQ_URL,line);
			if( !withConversion(Conn,0) ){
				cpyQStr(out,line);
			}
		}
	}else
	if( (fnlen = STRH(line,F_LastMod))
	 && (HTCFI_opts & HTCFI_GEN_304)
	 && (HTCFI_opts & HTCFI_THRU_304) == 0
	){
		IStr(lmod,128);
		int olmod;
		olmod = lastmtime(line+fnlen);
		if( olmod < DELEGATE_LastModified ){
			/* 9.9.8 gen. 304 based on the date of DeleGate */
			StrftimeGMT(AVStr(lmod),sizeof(lmod),
				TIMEFORM_RFC822,DELEGATE_LastModified,0);
			sprintf(buf,"%s %s\r\n",F_LastMod,lmod);
			cpyQStr(out,buf);
		}else{
			cpyQStr(out,line);
		}
	}else
	if( fnlen = STRH(line,F_Expires) ){
		lineScan(line+fnlen,RX_expires);
	}else
	if( fnlen = STRH(line,"Via:") ){
		if( RX_lastVia[0] ){
			FStrncpy(buf,RX_lastVia);
			cpyQStr(out,buf);
		}
		FStrncpy(RX_lastVia,line);
		if( strtailchr(RX_lastVia) != '\n' ){
			/* RX_lastVia must ends with (CR)LF to be
			 * properly processed in appendVia()
			 * and put to client in endRespHead()
			 */
			refQStr(vp,RX_lastVia);
			daemonlog("F","truncated Via:<<%s>>%s",RX_lastVia,line);
			vp = RX_lastVia + sizeof(RX_lastVia) - 3;
			strcpy(vp,"\r\n");
		}
	}else
	if( RX_qWithHeader && plain2html() && STRH(line,F_CtypePlain) ){
		sprintf(buf,"%s\r\n",F_CtypeHTML);
		cpyQStr(out,buf);
	}else
	if( RX_qWithHeader ){
		cpyQStr(out,line);
	}
	if( out && !ClientEOF && !HTTP_head2kill(out,KH_OUT|KH_RES) ){
		wcc = FPUTS(AVStr(out),RX_ctype,!RX_inHeader && RX_convChar,RX_deEnt);
		RX_wrHeadTotal += wcc;
	}
}
static int GETRESPBIN(Connection *Conn,ResponseContext *RX,int fromcache,int nready)
{	int rcc;
	MrefQStr(buff,RX_rdBuff); /**/

	if( clientIsReset("GETRESPBIN-A",Conn,0) ){
		return RX_fsx.t_lastRcc = 0;
	}
	if( fromcache ){
		rcc = fread((char*)buff,1,RX_remsize,RX_fsp);
		return RX_fsx.t_lastRcc = rcc;
	}
	if( rcc = fgetBuffered(AVStr(buff),RX_remsize,RX_fsp) ){
		Verbose("buffered(%d)\n",rcc);
		return RX_fsx.t_lastRcc = rcc;
	}

	/* MASTER-DeleGate (5.X) may keep connection even after said
	 * "Connection:close" ...
	  if( RX_rdTotal == RX_rdContLen )
	  if( nready == 0 && (nready = PollIn(fileno(RX_fsp),1000)) == 0 ){
	     sv1log("#### SOFT EOF %lld/%lld %s,%s\n",RX_rdTotal,RX_rdContLen,
			RX_ver,RX_connection);
		RX_fsx.t_EOF = 1;
		return RX_fsx.t_lastRcc = 0;
	  }
	 */

	if( nready == 0 && (nready = PollIn(fileno(RX_fsp),2000)) == 0 ){
		if( RX_tcp == NULL ){
		}else
		if( RX_tcp == RX_respBuff ){
			RX_tcp = detach_respbuff(Conn,RX_tcp,RX_tc_sav,
				RX_qWithHeader,"flush slow binary body.");
		}else
		if( !ClientEOF ){
			RX_nflush++;
			if( fflushTIMEOUT(RX_tcp) == EOF )
				setClientEOF(Conn,RX_tcp,"binary");
		}
	}

	HTR(4,"READ-BIN: %d [%lld/%lld]\n",RX_remsize,RX_rdTotal,RX_rdContLen);

	if( nready == 0 ){
		double Start = Time();
		double Et;
		IStr(sstat,128);
		int watchboth = watchBothside(fileno(RX_fsp),ClientSock);
		int fsd = fileno(RX_fsp);
		int tcd = ClientSock;
		int ri;
		for( ri = 0;; ri++ ){
			if( isWindowsCE() && watchboth ){
				if( receiverReset("GETRESPBIN-B",2.0,fsd,tcd) ){
					return RX_fsx.t_lastRcc = 0;
				}
				nready = PollIn(fileno(RX_fsp),1);
			}else
			nready = PollIn(fileno(RX_fsp),2*1000);
			Et = Time() - Start;
			sprintf(sstat,"p%d/%d s%d/%d c%d/%d %.1f",
				fileno(RX_fsp),IsAlive(fileno(RX_fsp)),
				ServerSock,IsAlive(ServerSock),
				ClientSock,IsAlive(ClientSock),
				Et);
			sv1log("{T}[%X]%d/%d GETRESPBIN %d,%d r%d %s\n",
				TID,actthreads(),numthreads(),
				ri,(int)RX_rdTotal,nready,
				sstat
			);
			if( nready ){
				break;
			}
			if( HTTP_TOUT_THREAD_PIPELINE < Et ){
				return RX_fsx.t_lastRcc = 0;
			}
			if( ClientSock < 0 ){
				/* 9.7.0 dget ? */
			}else
			if( !IsAlive(ClientSock) ){
				return RX_fsx.t_lastRcc = 0;
			}
			if( ServerSock < 0 ){
				/* 9.7.0 via PROXY */
			}else
			if( !IsAlive(ServerSock) ){
				RX_fsx.t_EOF = 1;
				return RX_fsx.t_lastRcc = 0;
			}
		}
	}

	if( nready == 0 )
		rcc = readTIMEOUT(fileno(RX_fsp),AVStr(buff),RX_remsize);
	else	rcc = read(fileno(RX_fsp),(char*)buff,RX_remsize);
	if( rcc <= 0 && !feof(RX_fsp) ){
		/* should set EOF to detect completion (non-trunc.) of resp. */
		if( fPollIn(RX_fsp,100) ){
			getc(RX_fsp);
		}
	}

	if( rcc <= 0 )
		RX_fsx.t_EOF = 1;
	else
	while( rcc < RX_remsize ){
	    if( 0 < PollIn(fileno(RX_fsp),10) ){
		int rcc1;
		rcc1 = read(fileno(RX_fsp),(char*)buff+rcc,RX_remsize-rcc);
		if( rcc1 <= 0 ){
			RX_fsx.t_EOF = 1;
			break;
		}else{
			rcc += rcc1;
			RX_ninput++;
		}
	    }else	break;
	}
	return RX_fsx.t_lastRcc = rcc;
}

static void fflushKeepAlive(Connection *Conn,PCStr(where),FILE *fc,FILE *tc,int wtotal)
{	int nready;

	if( fc == NULL ){
		if( fflushTIMEOUT(tc) == EOF )
			setClientEOF(Conn,fc,"%s-fflushKeepAlive-1",
				where);
	}else
	/*
	if( wtotal == 0 || 1024*8 < wtotal ){
	this code is introduced on 4.0.7 to reduce flush() for pipelined
	responses, but it rearly occurs while it causes usual delay.
	*/
	{
		nready = ready_cc(fc);
		if( 0 < nready )
		{
			/*
			sv1log("%s-fflushKeepAlive-PipelinedRequest\n",where);
			*/
			sv1log("%s-fflushKeepAlive-PipelinedRequest[%d](%d)\n",
				where,tc?fileno(tc):-2,tc?pendingcc(tc):-2);
		}
		else
		if( nready < 0 )
			setClientEOF(Conn,fc,"%s-fflushKeepAlive-2-RESET",
				where);
		else
		if( nready == 0 ){
			set_nodelay(fileno(tc),1);
			if( fflushTIMEOUT(tc) == EOF )
				setClientEOF(Conn,fc,"%s-fflushKeepAlive-3",
					where);
			else	set_nodelay(fileno(tc),0);
		}
	}
}
static void abortKeepAlive(Connection *Conn,ResponseContext *RX)
{
	if( ClientEOF ){
	 clntClose(Conn,"r:by client (response EOF) %lld/%lld (%lld/%lld)",RX_wrTotal,RX_wrContLen,RX_rdTotal,RX_rdContLen);
	}else
	if( !RX_tcx.t_chunked && !RX_noBody && RX_wrTotal != RX_wrContLen ){
 clntClose(Conn,"l:##FATAL:inconsistent body length %lld/%lld (%lld/%lld)",RX_wrTotal,RX_wrContLen,RX_rdTotal,RX_rdContLen);
	}else
	if( lDONTHT()
	/*
	 && (RX_code == 401 || RX_code == 404 )
	*/
	 && (RX_code == 401 || RX_code == 404 || RX_code == 407 )
	 && (withNTHT & (NTHT_REQ|NTHT_RES)) ){
		sv1log("----NTHT keep-alive %d %d\n",RX_code,RX_errori);
	}else
	if( RX_errori ){
	   clntClose(Conn,"s:##FATAL:bad status(%d) %lld/%lld (%lld/%lld)",RX_errori,RX_wrTotal,RX_wrContLen,RX_rdTotal,RX_rdContLen);
	}
}

/* 9.6.3-pre7 wait the finish of gunzip() thread to avoid the batting between
 * dupclosed() at the end of gunzip() and TMPFILE() at the beginning for Gzip()
 */
static int RX_putMIMEmsg(Connection *Conn,ResponseContext *RX){
	int leng;
	int gutid = RX->r_fsx.t_tid;
	if( gutid && threadIsAlive(gutid) ){
		int ri;
		double St = Time();
		msleep(5);
		for( ri = 0; threadIsAlive(gutid) && ri < 50; ri++ ){
			msleep(10);
		}
		if( threadIsAlive(gutid) || 0.1 < Time()-St ){
			porting_dbg("--Gunzip/Gzip alive(%X) = %d [%.3f]",
				gutid,threadIsAlive(gutid),Time()-St);
			dumpthreads("releaseRespbuf-B",stderr);
		}
	}
	/*
	leng = HTTP_putMIMEmsg(Conn,RX_tcp,RX_tc_sav);
	*/
	leng = HTTP_putMIMEmsgX(Conn,RX_tcp,RX_tc_sav,RX);
	return leng;
}
static void releaseRespbuf(Connection *Conn,ResponseContext *RX)
{
	fflush(RX_tcp);
	Ftruncate(RX_tcp,0,1);
	fseek(RX_tcp,0,0);

	if( lFILEDESC() ){
		sv1log("{F} >>[%d]-[%d][%d] releaseRespbuf %d/%d %d\n",
			fileno(RX_tcp),fileno(RX_tc_sav),ClientSock,
			(int)RX_wrTotal,(int)RX_rdTotal,(int)RX_rdContLen);
	}
	if( RX_discardResp ){
		RX_wrTotal = RX_wrContLen = 0;
	}else
	if( checkClientEOF(Conn,RX_tcp,"flush_respbuff") ){
		httpStat = CS_EOF;
		RX_wrTotal = RX_wrContLen = 0;
	}else
	/*
	if( 0 < (RX_wrTotal = HTTP_putMIMEmsg(Conn,RX_tcp,RX_tc_sav)) ){
	*/
	if( 0 < (RX_wrTotal = RX_putMIMEmsg(Conn,RX)) ){
		RX_wrContLen = RX_wrTotal;
	}else
	if( RX_wrTotal == 0 && RX_rdTotal == 0 && RX_xinLen == 0 ){
		/* 9.8.2 it's the result of a normal empty body, so don't set
		 * ClientEOF to indicate disconnection with the client
		 * 1) not to break keep-alive with the client with some rewriting
		 * 2) to close RX_tcp/FTOCL normally on the exit of relay_response
		 */
		RX_wrContLen = 0;
		if( lFILEDESC() ){
			sv1log("{F} >>[%d]-[%d][%d] release EmptyBody\n",
				fileno(RX_tcp),fileno(RX_tc_sav),ClientSock);
		}
	}else{
		sv1log("## HTTP RESPONSE CLOSE: NO (client dead)\n");
		setClientEOF(Conn,RX_tcp,"flush_respbuff.FAILED");
		freeTmpFile(RX_tmpFileId /*,Conn*/);
	}
	fclose(RX_tcp);
	RX_tcp = RX_tc_sav;
}
static int cacheTobeDiscared(ResponseContext *RX,int bin,int wcc){
	if( RX_rdContLenGot ){
		if( RX_rdContLen+0x100000 < RX_binLen ){
			return 1;
		}
	}else{
		if( 4*1024*1024 < RX_rdTotal ){
			return 2;
		}
	}
	return 0;
}
static int relayBinResp1(Connection *Conn,ResponseContext *RX,int rcc)
{	int wcc = -9;
	int serrno;
	const char *buff = RX_rdBuff;

	if( rcc <= 0 ){
		Verbose("read(%d) = %d\n",RX_remsize,rcc);
		return -1;
	}

	RX_rdTotal += rcc;

	if( RX_cachefp ){
		wcc = fwrite(buff,1,rcc,RX_cachefp);
		sendDistribution(Conn,RX_cachefp,RX_fsp,RX_tcp,buff,rcc);
		RX_binLen += wcc;

		/*
		if( wcc == 0 || RX_rdContLen+0x100000 < RX_binLen ){
		*/
		if( wcc == 0 || cacheTobeDiscared(RX,1,wcc) ){
			sv1log("discard cache: wcc=%d leng=%lld/%lld %s\n",wcc,RX_binLen,RX_rdContLen,RX_cpath);
			Ftruncate(RX_cachefp,0,0);
			fseek(RX_cachefp,0,0);
			RX_cachefp = NULL;
		}
	}

	if( !ClientEOF ){
	    wcc = fwriteResponseChunk(Conn,RX,buff,rcc);
	    serrno = errno;
	    RX_wrTotal += wcc;
	    if( wcc == 0 ){
		/* don't break to relay response data into the cache */
 sv1log("## HTTP out to client TIMEOUT[%d]\n",fileno(RX_tcp));
		/*fcloseTIMEOUT(RX_tcp);*/
		setClientEOF(Conn,RX_tcp,"binary flush-1");
	    }
	    if( wcc < rcc ){
		if( !ClientEOF )
			setClientEOF(Conn,RX_tcp,"binary flush-2");
 sv1log("## HTTP ERROR incomplete fwrite(%d)=%d %lld/%lld, SIGPIPE=%d\n",rcc,wcc,RX_rdTotal,RX_rdContLen,nsigPIPE);
		if( RX_tcp == RX_respBuff )
		{
			if( lMULTIST() ){
				int fd = fileno(RX_tcp);
				sv1log("## FATAL relayBinR [%d]%d %d/%d e%d\n",
					fd,file_isreg(fd),wcc,rcc,serrno);
				return -1;
			}
			fclose(RX_tcp);
			abortHTTP("disk full?");
		}

		if( RX_cachefp == NULL ){
 sv1log("## stop relay-2: FWRITE(%d)=%d, SIGPIPE=%d, no cache & no recipient\n",
 rcc,wcc,nsigPIPE);
			return -1;
		}
	    }
	    RX_noutput++;

	    HTR(4,"RELAY-BIN: read %d / %lld bytes / %d blocks; %d flush.\n",
		rcc,RX_rdTotal,RX_ninput,RX_nflush);
	}
	else{
		if( CACHE_TAKEOVER ){
			/* 9.9.8 not to break the caller to take-over cache. */
			/* thru the wcc for the cache (to judge cache stat.) */
		}else{
			/* 9.9.8 to cause immediate break without take-over */
 			wcc = -9;
		}
	}
	return wcc;
}

/*
 * distFromCache is introduced in 3.0.35 [DeleGate-ML:4000]
 * it has become needless in 9.2.4 because cache has come to be
 * updated without being locked nor being overwritten.
 */
static void distFromCacheSetup(Connection *Conn,ResponseContext *RX,PCStr(cpath),FILE *cachefp)
{	CStr(scdate,256);
	int lastmod;
	FileSize fsize;
	MrefQStr(dcpath,RX_dcx.d_cpath); /**/

	lock_sharedNB(fileno(cachefp));
	stopDistribution(Conn,cachefp,cpath);

/*
 * copying too large file (larger than 1M bytes ?) should be avoided not to
 * make slower response to ther client and headvy load the the server...
 */
	/* 9.2.4 did as commented above */
	fsize = file_sizeX(fileno(cachefp));
	if( 1024*1024 < fsize ){
		sv1log("distFromCache: don't copy large file: %llX %s\n",
			fsize,cpath);
		DontTruncate = 4; /* avoid to be truncated and ulinked by
				   * client side premature disconnection */
		RX_dcx.d_cpath[0] = 0;	/* no path to be unlinked */
		RX_dcx.d_start = 0;	/* not used when d_cpath[0] == 0 */
		RX_dcx.d_fp = fdopen(dup(fileno(cachefp)),"r");
		RX_dcx.d_ready = -1;
		return;
	}

	dcpath = RX_dcx.d_cpath;
	RX_dcx.d_cpath[0] = 0;
	RX_dcx.d_fp = NULL;
	RX_dcx.d_ready = 0;
	RX_dcx.d_start = time(0);

	lastmod = HTTP_getLastModInCache(AVStr(scdate),sizeof(scdate),cachefp,cpath);
	if( lastmod ){
		sprintf(dcpath,"%s#%d",cpath,lastmod);
		RX_dcx.d_fp = fopen(dcpath,"r");
		if( RX_dcx.d_fp != NULL ){
			lock_unlock(fileno(cachefp));
			Verbose("distFromCache: share %s\n",dcpath);
			RX_dcx.d_ready = 1;
		}else{
			RX_dcx.d_fp = dirfopen("distFromCache",QVStr(dcpath,RX_dcx.d_cpath),"w+");
			Verbose("distFromCache: created %s\n",dcpath);
		}
	}
	if( RX_dcx.d_fp == NULL ){
		RX_dcx.d_fp = TMPFILE("distFromCache");
		if( RX_dcx.d_fp == NULL ){
			RX_dcx.d_fp = fdopen(dup(fileno(cachefp)),"r");
			Verbose("distFromCache: WITHOUT-LOCK %s\n",cpath);
			RX_dcx.d_ready = -1;
		}
	}
	if( RX_dcx.d_ready == 0 ){
		copyfile1(cachefp,RX_dcx.d_fp);
		fflush(RX_dcx.d_fp);
		fseek(RX_dcx.d_fp,0,0);
		lock_unlock(fileno(cachefp));
	}
}
static void distFromCacheDone(Connection *Conn,ResponseContext *RX)
{
	if( RX_dcx.d_ready )
		lock_unlock(fileno(RX_cachefp));
	lock_unlock(fileno(RX_dcx.d_fp));
	fclose(RX_dcx.d_fp);

	if( RX_dcx.d_cpath[0] ){
		int ucode;
		ucode = unlink(RX_dcx.d_cpath);
		Verbose("dcxFromCache: %d unlink=%d [%ds] %s\n",
			RX_dcx.d_ready,ucode,
			ll2i(time(0)-RX_dcx.d_start),RX_dcx.d_cpath);
	}
}
static void logCookie(Connection *Conn,ResponseContext *RX,PCStr(resCookie))
{	CStr(reqCookie,URLSZ);

	if( withCookie || *resCookie ){
		getFV(REQ_FIELDS,"Cookie",reqCookie);
		/*
		sv1log("[Cookie:%s][Set-Cookie:%s][Cache-Control:%s]\n",
		*/
		LSEC("[Cookie:%s][Set-Cookie:%s][Cache-Control:%s]\n",
			reqCookie,resCookie,RX_cachecontrol);
	}
}

static void Fpurge(FILE *tc)
{	int cfd,sfd;
	int tfd;
	FILE *tmp;

	if( tc == NULL )
		return;

	/*
	tmp = fopen("/dev/null","w");
	*/
	tfd = open("/dev/null",1); tmp = fdopen(tfd,"w");

	if( tmp == NULL )
		tmp = tmpfile();
	if( tmp == NULL )
		return;
	cfd = fileno(tc);
	sfd = dup(cfd);
	dup2(fileno(tmp),cfd);
	fclose(tmp);
	fflush(tc);
	dup2(sfd,cfd);
	close(sfd);
	Ftruncate(tc,0,0);
}

extern const char *TIMEFORM_mdHMS;
int modwatch_enable;
const char *modwatch_notify;
int modwatch_approver;
static int modwatchHead(Connection *Conn,ResponseContext *RX)
{	CStr(md5,64);
	CStr(mdpath,URLSZ);
	CStr(appath,URLSZ);
	CStr(approver,URLSZ);
	CStr(acap,128);
	CStr(old,URLSZ);
	CStr(xnew,URLSZ);
	refQStr(cp,xnew); /**/
	CStr(msg,URLSZ);
	CStr(lmtime,64);
	CStr(event,URLSZ);
	refQStr(ep,event); /**/
	const char *op;
	CStr(omtime,64);
	CStr(ctime,64);
	CStr(lpath,URLSZ);
	CStr(url,URLSZ);
	CStr(req,URLSZ);
	FILE *afp,*log;
	int rcc,len,osize,oapproved;


	HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
	sprintf(req,"%s/%s %s",REQ_METHOD,REQ_VER,url);
	/* should use REQ_URL + Host: filed ? */
	toMD5(req,md5);
	Strins(QVStr(md5+2,md5),"/");

	sprintf(appath,"${ADMDIR}/approved/%s",md5);
	DELEGATE_substfile(AVStr(appath),"",VStrNULL,VStrNULL,VStrNULL);
	sprintf(mdpath,"${ADMDIR}/modified/%s",md5);
	DELEGATE_substfile(AVStr(mdpath),"",VStrNULL,VStrNULL,VStrNULL);

	afp = dirfopen("modwatchHead",AVStr(appath),"r+");
	if( afp != NULL ){
		oapproved = 1;
	}else{
		oapproved = 0;
		afp = dirfopen("modwatchHead",AVStr(mdpath),"r+");
	}
	if( afp != NULL ){
		rcc = fread(old,1,sizeof(old),afp);
		old[rcc] = 0;
		fseek(afp,0,0);
	}else{
		afp = dirfopen("modwatchHead",AVStr(mdpath),"w");
		if( afp == NULL )
			return 0;
		rcc = 0;
		old[rcc] = 0;
	}
	StrftimeLocal(AVStr(lmtime),sizeof(lmtime),TIMEFORM_mdHMS,RX_lastModTime,0);
	for( op = lmtime; *op; op++ )
		if( *op == ' ' )
			*(char*)op = '-';

	setVStrEnd(xnew,0);
	cp += strlen(cp); sprintf(cp,"RQ=\"%s/%s %s\";",REQ_METHOD,REQ_VER,url);
	cp += strlen(cp); sprintf(cp,"CT=%s;",RX_ctype);
	cp += strlen(cp); sprintf(cp,"CL=%lld;",RX_rdContLen);
	cp += strlen(cp); sprintf(cp,"MT=%s;",lmtime);
	cp += strlen(cp);
	len = cp - xnew;

	makeClientLog(Conn,AVStr(approver));
	StrftimeLocal(AVStr(ctime),sizeof(ctime),TIMEFORM_mdHMS,time(0),0);
	cp += strlen(cp); sprintf(cp,"AT=%s;",ctime);
	cp += strlen(cp); sprintf(cp,"AU=%s;",approver);

	if(  strncmp(old,xnew,len) == 0 ){
		fclose(afp);
		return 0;
	}

	sprintf(lpath,"${ADMDIR}/modified.log");
	DELEGATE_substfile(AVStr(lpath),"",VStrNULL,VStrNULL,VStrNULL);
	log = dirfopen("modified.log",AVStr(lpath),"a");

	if( strstr(old+len,"DT=") == NULL ){
		/* the first detection of modification */
		if( old[0] )
			fseek(afp,-1,2);
		fprintf(afp,"DT=%s;\n",ctime);
		Ftruncate(afp,0,1);
		fseek(afp,0,0);

		ep = event;
		if( old[0] )
			sprintf(event,"modified: ");
		else	sprintf(event,"detected: ");
		ep += strlen(ep); sprintf(ep,"%s [%s]%lld",url,lmtime,RX_rdContLen);
		ep += strlen(ep);
		if( old[0] ){
			osize = 0;
			if( op = strstr(old,"CL=") )
				sscanf(op,"CL=%d",&osize);
			omtime[0] = 0;
			if( op = strstr(old,"MT=") )
				Xsscanf(op,"MT=%[^;]",AVStr(omtime));
			sprintf(ep," %d[%s]",osize,omtime);
		}
		sprintf(msg,"\tFILE:%s\n\tWHAT:%s\n\tOLD:%s\tNEW:%s\n",
			mdpath,event,old[0]?old:"\n",xnew);
		if( log ){
			fseek(log,0,2);
			fprintf(log,"-%s\n%s",event,msg);
			fflush(log);
		}
		if( modwatch_notify ){
			for( op = msg; *op; op++ )
				if( *op == '\t' )
					*(char*)op = ' ';
			notify_ADMINX(Conn,modwatch_notify,event,msg);
		}
	}

	if( modwatch_approver == 0 ){
		if( log != NULL )
			fclose(log);
		goto APPROVED;
	}

	ep = event;
	sprintf(event,"approved: ");
	ep += strlen(ep); sprintf(ep,"%s [%s]%lld",url,lmtime,RX_rdContLen);
	ep += strlen(ep); sprintf(ep," %s",old[0]?"M":"D");
	ep += strlen(ep); sprintf(ep," [%s][%d]",approver,getpid());
	sprintf(msg,"\tFILE:%s\n\tWHAT:%s\n\tOLD:%s\tNEW:%s\n",
		mdpath,event,old[0]?old:"\n",xnew);

	if( old[0] )
	if( find_CMAP(Conn,CMAP_APPROVER,AVStr(acap)) < 0
		 /* the client is not an approver */
	 /* && age < 1week ? */
	){
		Fpurge(RX_tc_sav);
		Fpurge(RX_tcp);
		fprintf(RX_tcp,"HTTP/%s 503 Service Unavailable\r\n",
			MY_HTTPVER);
		fprintf(RX_tcp,"\r\n");
		fprintf(RX_tcp,"Service Unavailable\r\n");
		fflush(RX_tcp);
		RespCode = RX_code = 503;

		if( oapproved ){
			renameRX(appath,mdpath);
		}
		if( log ){
			fseek(log,0,2);
			fprintf(log,"-un%s\n",event);
			fclose(log);
		}
		fclose(afp);
		return -1;
	}
	if( log ){
		fseek(log,0,2);
		fprintf(log,"-%s\n%s",event,msg);
		fclose(log);
	}
	if( modwatch_notify ){
		for( op = msg; *op; op++ )
			if( *op == '\t' )
				*(char*)op = ' ';
		notify_ADMINX(Conn,modwatch_notify,event,msg);
	}
	if( !oapproved ){
		renameRX(mdpath,appath);
	}
	sv1tlog("modwatch-old: %s",old);
	sv1tlog("modwatch-new: %s",xnew);

APPROVED:
	fprintf(afp,"%s\n",xnew);
	Ftruncate(afp,0,1);
	fclose(afp);
	return 0;
}

static int checkServ(Connection *Conn)
{
	if( 0 < CheckServ ) return 1;
	if( CheckServ < 0 ) return 0;

	if( 1024 <= DST_PORT ){
		CheckServ = -1;
		return 0;
	}
	if( DST_PORT == 80 || DST_PORT == 443 )
	if( BadRequest == 0 && Normalized == 0 ){
		CheckServ = -1;
		return 0;
	}

	CheckServ = 1;
	return 1;
}

#define BS_CONNECT	0
#define BS_QLINE	1
#define BS_QHEAD	2
#define BS_QBODY	3
#define BS_RHEAD	4


static const char *rvers;
void HTTP_setRespVers(PCStr(vers))
{
	rvers = stralloc(vers);
}
int HTTP_accRespVer(PCStr(statline))
{	CStr(ver,16);
	int acc;

	if( rvers ){
		wordScan(statline,ver);
		if( strcmp(rvers,"*") == 0 ){
			sv1log("Accepted: %s",statline);
			return 1;
		}
		if( acc = isinListX(rvers,ver,"h") ){
			sv1log("Accepted: %s",statline);
			return acc;
		}
	}
	return 0;
}
static int badServ(Connection *Conn,PCStr(where),int whid,FILE *ts,FILE *fs,PCStr(statline))
{	CStr(buf,128);
	int rcc,timeout;

	if( 0 < BadServ ) return 1;
	if( BadServ < 0 ) return 0;

	if( BS_RHEAD <= whid && !HTTP_reqWithHeader(Conn,REQ) ){
		BadServ = -1;
		return 0;
	}

	if( statline != NULL ){
		rcc = strlen(statline);
		goto check;
	}
	if( !checkServ(Conn) )
	{
		if( rvers ){
		}else
		return 0;
	}

	if( file_isreg(fileno(fs)) ){ /* maybe NULLFP() */
		BadServ = -1;
		return 0;
	}

	if( ts != NULL )
		fflush(ts);
	if( (HTTP_WAIT_BADSERV*1000) < WaitServ )
		return 0;

	if( whid == BS_QBODY ){
		if( DST_PORT == 80 || DST_PORT == 443 )
			timeout = 10;
		else	timeout = 500;
	}else
	if( BadRequest || Normalized ){
		if( DST_PORT == 80 || DST_PORT == 443 )
			timeout = 100;
		else	timeout = 500;
	}else{
		if( DST_PORT == 80 || DST_PORT == 443 )
			timeout = 1;
		else	timeout = 10;
	}

	WaitServ += timeout;
	if( fPollIn(fs,timeout) <= 0 )
		return 0;
	rcc = fgetBuffered(AVStr(buf),QVZsizeof(buf),fs);
	if( rcc == 0 )
		rcc = recvPeekTIMEOUT(fileno(fs),AVStr(buf),sizeof(buf)-1);
	if( rcc <= 0 )
		return 0;
	setVStrEnd(buf,rcc);
	statline = buf;
	if( whid == BS_QBODY && !HTTP_methodWithBody(REQ_METHOD) ){
		/* 9.8.2 it's very normal to get HTTP resp. for GET or so. */
	}else
	sv1log("## badServer? %s: BQ=%d+%d %d: %s",
		where,BadRequest,Normalized,rcc,statline);

check:
	if( statline[0] == 0 ){
		return 0;
	}
/*
	if( strncmp(statline,"HTTP/",5) == 0 ){
*/
    if( rvers == 0 ){
	if( strncmp(statline,"HTTP/",4) == 0 ){
		BadServ = -1;
		return 0;
	}
    }else{
	if( HTTP_accRespVer(statline) ) {
		BadServ = -1;
		return 0;
	}
    }

	sv1log("## badServer! %s: BQ=%d+%d %d: %s",
		where,BadRequest,Normalized,rcc,statline);
	lineScan(where,BadServDetected);
	lineScan(statline,BadServResponse);
	httpStat = CS_BADREQUEST;
	BadServ = 1;
	return 1;
}
static void putBadRequest(Connection *Conn,FILE *tc,PCStr(reason))
{
	if( reason ){
		sv1log("## badRequest: [%s] Request[%s]\n",reason,OREQ_MSG);
	}else{
	sv1log("## badRequest: Server[%s/%dms][%s] Request[%d+%d][%s]\n",
		BadServDetected,WaitServ,
		BadServResponse,BadRequest,Normalized,OREQ_MSG);
	}

	fprintf(tc,"HTTP/%s 400 Bad Request\r\n",MY_HTTPVER);
	fprintf(tc,"Content-Type: text/plain\r\n");
	fprintf(tc,"Connection: close\r\n");
	fprintf(tc,"\r\n");
	fprintf(tc,"<plaintext>\r\n");
	if( reason )
		fprintf(tc,"Bad Request: %s\r\n",reason);
	else	fprintf(tc,"Bad Request\r\n");
	fprintf(tc,"%s",OREQ_MSG);
	http_Log(Conn,400,CS_BADREQUEST,REQ,0);
}
static void putBadResponse(Connection *Conn,FILE *tc)
{
	sv1log("## badServer: Server[%s/%dms][%s] Request[%d+%d][%s]\n",
		BadServDetected,WaitServ,BadServResponse,
		BadRequest,Normalized,OREQ_MSG);

	fprintf(tc,"HTTP/%s 502 Bad Response\r\n",MY_HTTPVER);
	fprintf(tc,"Content-Type: text/plain\r\n");
	fprintf(tc,"Connection: close\r\n");
	fprintf(tc,"\r\n");
	fprintf(tc,"<plaintext>\r\n");

	fprintf(tc,"Bad Response:\r\n%s\r\n\r\n",BadServResponse);
	fprintf(tc,"Original Request:\r\n%s\r\n\r\n",OREQ_MSG);
	http_Log(Conn,502,CS_BADREQUEST,REQ,0);
}

int relay_responseX(Connection *Conn,QueryContext *QX,int cpid,PCStr(proto),PCStr(server),int iport,PCStr(req),PCStr(acpath),int fromcache, FILE *afs,FILE *atc,FILE *afc,FILE *acachefp,int cache_rdok, ResponseContext *RX,PVStr(refbuf));

/**/
static int relay_response(Connection *Conn,QueryContext *QX,int cpid,PCStr(proto),PCStr(server),int iport,PCStr(req),PCStr(acpath),int fromcache,FILE *afs,FILE *atc,FILE *afc,FILE *acachefp,int cache_rdok)
{	UTag RXut;
	UTag refbufut;
	int rcode;
	ResponseContext *RX;

	if( lSINGLEP() && AVAIL_alloca ){
		RXut = UTonstack(sizeof(ResponseContext));
		refbufut = UTonstack(URLSZ);
		RX = (ResponseContext*)RXut.ut_addr;
		bzero(RX,sizeof(ResponseContext));
		RX->r_line0t = UTonstack(RESP_LINEBUFSZ);
		RX->r_line1t = UTonstack(RESP_LINEBUFSZ);
		RX->r_Anchor_rem = UTonstack(1024);
		setVStrEnd(Anchor_rem,0);
		RX->r_dcxp = UTonstack(sizeof(Dcx));
		RX->r_fsx.t_buffer = UTonstack(sizeof(LineBuf));
	}else{
	RXut = UTalloc(SB_CONN,sizeof(ResponseContext),8);
	refbufut = UTalloc(SB_CONN,URLSZ,1);
	RX = (ResponseContext*)RXut.ut_addr;
	bzero(RX,sizeof(ResponseContext));
	RX->r_line0t = UTalloc(SB_CONN,RESP_LINEBUFSZ,1);
	RX->r_line1t = UTalloc(SB_CONN,RESP_LINEBUFSZ,1);
	RX->r_Anchor_rem = UTalloc(SB_CONN,1024,1);
	setVStrEnd(Anchor_rem,0);
	RX->r_dcxp = UTalloc(SB_HEAP,sizeof(Dcx),1);
	RX->r_fsx.t_buffer = UTalloc(SB_HEAP,sizeof(LineBuf),1);

Verbose("--UTalloc %X/%d %X/%d %X/%d %X/%d %X/%d %X/%d %X/%d\n",
p2i(RXut.ut_addr), RXut.ut_size,
p2i(refbufut.ut_addr), refbufut.ut_size,
p2i(RX->r_line0t.ut_addr), RX->r_line0t.ut_size,
p2i(RX->r_line1t.ut_addr), RX->r_line1t.ut_size,
p2i(RX->r_Anchor_rem.ut_addr), RX->r_Anchor_rem.ut_size,
p2i(RX->r_dcxp.ut_addr), RX->r_dcxp.ut_size,
p2i(RX->r_fsx.t_buffer.ut_addr), RX->r_fsx.t_buffer.ut_size,
0
);
	}

	rcode =
	relay_responseX(Conn,QX,cpid,proto,server,iport,req,acpath,fromcache,
		afs,atc,afc,acachefp,cache_rdok,
		(ResponseContext*)RXut.ut_addr,AVStr(refbufut.ut_addr));

	if( RX_cachefpSav ){
		/* saved in cacheReadOK()/popCurrentCache() */
		fclose(RX_cachefpSav);
	}

	if( lMULTIST() ){
	}else{
	UTfree(&RX->r_fsx.t_buffer);
	UTfree(&RX->r_dcxp);
	UTfree(&RX->r_Anchor_rem);
	UTfree(&RX->r_line1t);
	UTfree(&RX->r_line0t);
	UTfree(&refbufut);
	UTfree(&RXut);
	}

	QX_rcode = rcode; /* 9.8.2 to be used via fromCache() */
	return rcode;
}
int HTTP_relay_response(Connection *Conn,int cpid,PCStr(proto),PCStr(server),int iport,PCStr(req),PCStr(acpath),int fromcache, FILE *afs,FILE *atc,FILE *afc,FILE *acachefp,int cache_rdok)
{	QueryContext QXbuf, *QX = &QXbuf;

#if 0
	/*
	 * This code makes absolute URL (/path) be fullified with
	 * the prefix as file://localhost/path, but is unlikely that
	 * an absolute URL is written/generated intending a physical
	 * file path. At least it is uncertain that an absolute path
	 * is a logical (virtual) URL in this server or the physical
	 * path.
	 * So leave this code commented out to interpret an absolute
	 * path as a virtual URL.
	 * If it is necessary to be interpreted as a physical path,
	 * prefixing the URL as file:/path will do.
	 */
	HttpRequest reqx;
	IStr(rproto,64);
	IStr(rhostport,MaxHostNameLen);
	IStr(rhost,MaxHostNameLen);
	int rport;

	decomp_http_request(req,&reqx);
	if( isFullURL(reqx.hq_url) ){
		decomp_absurl(reqx.hq_url,AVStr(rproto),AVStr(rhostport),VStrNULL,0);
		if( strcaseeq(rproto,"file") ){ /* v9.9.11 fix-140726a */
			/* reverse MOUNT of file included from SSI */
			rport = scan_hostport(rproto,rhostport,AVStr(rhost));
			proto = rproto;
			server = rhost;
			iport =  rport;
		}
	}
#endif

	bzero(QX,sizeof(QueryContext));
	if( ImResponseFilter && RESP_DoZIP && REQ_AccEnc[0] ){
		strcpy(QX_accEnc,REQ_AccEnc);
thfprintf(stderr,"----ReponseFilter set accept-encoding[%s]\n",
REQ_AccEnc);
	}
	return
  relay_response(Conn,QX,cpid,proto,server,iport,req,acpath,fromcache,
afs,atc,afc,acachefp,cache_rdok);
}

static int NoCacheField(Connection *Conn,ResponseContext *RX,PCStr(field)) 
{
	if( STRH(field,F_DGVer)       ) return 1;
	if( STRH(field,F_TransEncode) ) return 1;
	if( STRH(field,F_KeepAlive)   ) return 1;
	if( STRH_Connection(field)    ) return 1;
	if( STRH(field,F_ContLeng) ){
		if( RX_cencoded ){
			/* don't cache Content-Length for Content-Encoding */
			return 1;
		}
	}
	return 0;
}

int gotSIGPIPE();
int fwrites(PCStr(buf),int siz,int nel,FILE *fp){
	int wel1;
	int wel = 0;
	int nerr = 0;

	for(; wel < nel; ){
		wel1 = fwrite(buf+wel*siz,siz,nel-wel,fp);
		if( wel1 != nel-wel ){
			nerr++;
thfprintf(stderr,"----fwrites(%d)=%d %d/%d errno=%d\n",
nel-wel,wel1,wel,nel,errno);
			if( ferror(fp) || 10 < nerr ){
Verbose("+++EPIPE fwrites() %d/%d err*%d=%d %d SIG*%d\n",wel1,nel-wel,nerr,ferror(fp),wel,gotSIGPIPE());
				break;
			}
		}else{
			nerr = 0;
		}
		if( ferror(fp) || gotSIGPIPE() ){
Verbose("+++EPIPE fwrites() %d/%d err*%d=%d %d SIG*%d\n",wel1,nel-wel,nerr,ferror(fp),wel,gotSIGPIPE());
			break;
		}
		if( 0 < wel1 ){
			wel += wel1;
		}
		if( errno == EPIPE ){
			break;
		}
		if( wel1 <= 0 ){
			/* should do pollOut() */
			msleep(10);
			clearerr(fp);
		}
	}
	return wel;
}

static int respSutisfied(ResponseContext *RX){
	if( RX_fsx.t_chunked && RX_fsx.t_chunk_siz == 0 ){
		return 1; /* got end-of-chunk */
	}
	if( RX_rdContLenGot ){
		if( RX_rdContLen == RX_rdTotal || RX_rdContLen == RX_txtLen ){
			return 1; /* length completed */
		}
	}
	if( RX_rdContLen == 0 ){
		if( RX_fsx.t_EOF || RX_fsx.t_feof ){
			return 1;
		}
	}
	return 0;
}
int strCRC32add(int crc,PCStr(str),int len);
FILE *recvHTTPbody(Connection *Conn,ResponseContext *RX,FILE *fp)
{   int rcc,wcc,lastRcc;
    ResponseContext RXbuf;
	double Now,Next = 0;
 double Start = Time();
	int ni;
	int isreg = (fp != NULL) ? file_isreg(fileno(fp)) : 0;
	int buffed = 0;
	double prevFlush = 0;

	RX_RdTruncated = 0;

    if( RX_ovw == 0 ){
    RXbuf = *RX;
    RX = &RXbuf;
    }
    RX_tcp = fp;

	/*
    for(;;){
	*/
    for( ni = 0;; ni++ ){
	if( actthreads() ){
		if( gotsigTERM("recvHTTPbody ni=%d",ni) ){
			thread_exit(0);
		}
	}
	/* 8.1.0: detect connection reset from client during buffering.  It
	 * shold be PollIns([fileno(fsp),ClientSock]) to reduce overhead
	 * for checking.
	 */
	if( 0 < ClientSock ){
	Now = Time();
	if( fp != NULL )
	if( Next <= Now )
	if( READYCC(fp) <= 0 ){ /* to reduce checking (no buffered chunks) */
		/* this READYCC(fp) seems to have been READYCC(RX_fsp),
		 * but seems not to work well to reduce checking, anyway ... */
		if( 0 <= ClientSock && IsAlive(ClientSock) == 0 ){
			setClientEOF(Conn,RX_tcp,"recvHTTPbody");
			break;
		}
		Next = Now + 1;
	}
	}

	if( RX_fsx.t_EOF )
		break;
	if( feof(RX_fsp) )
		break;
	if( RX_fsx.t_chunked ){
		lastRcc = RX_fsx.t_lastRcc;
		if( RX_fsx.t_chunk_ser && 0 < lastRcc ){
			HTR(2,"--getChunk[%d] data  : %d / %d / %d\n",
				RX_fsx.t_chunk_ser,lastRcc,
				RX_fsx.t_chunk_rem,RX_fsx.t_chunk_siz);

			RX_fsx.t_chunk_rem -= lastRcc;
			RX_remsize = RX_fsx.t_chunk_rem;
			if( sizeof(RX_rdBuff)-1 < RX_remsize )
				RX_remsize = sizeof(RX_rdBuff) -1;
		}
		if( RX_fsx.t_chunk_rem == 0 ){
			if( getChunk(RX) < 0 )
				break;
			RX_fsx.t_lastRcc = 0;
			continue;
		}
	}else
	if( RX_fsx.t_keepAlive && 0 < RX_rdContLen ){
		RX_remsize = RX_rdContLen - RX_rdTotal;
		if( sizeof(RX_rdBuff)-1 < RX_remsize )
			RX_remsize = sizeof(RX_rdBuff)-1;
		HTR(2,"--Length=%lld = %lld + %d\n",RX_rdContLen,RX_rdTotal,
			RX_remsize);
		if( RX_rdContLen <= RX_rdTotal )
		{
 Verbose("---- [%.4f] KA=%d recvHTTPbody X2 %lld < %lld\n",
 Time()-Start,RX_fsx.t_keepAlive,RX_rdContLen,RX_rdTotal);
			break;
		}
	}

	if( 0 < RX_fsTimeout ){
		if( RX_rdTotal && RX_rdTotal <= RX_rdContLen ){
			if( fPollIn(RX_fsp,RX_fsTimeout) == 0 ){
 sv1log("---- [%.4f] KA=%d recvHTTPbody X1 %lld < %lld\n",
 Time()-Start,RX_fsx.t_keepAlive,RX_rdContLen,RX_rdTotal);
				break;
			}
		}
	}
	rcc = GETRESPBIN(Conn,RX,0,RX_fsx.t_nready);
	if( rcc <= 0 ){
		if( RX_rdContLen == 0 && feof(RX_fsp) ){
		}else
		if( respSutisfied(RX) ){
		}else{
			RX_RdTruncated = 1;
		}
		break;
	}
	if( EmiActive(Conn) ){
		/* for -Fdget */
		EmiUpdateMD5(Conn,RX_rdBuff,rcc);
	}
	RX_rdTotal += rcc;
	RX_RdTotalG = RX_rdTotal;
	if( RX_tcp == NULL ){
		wcc = rcc;
	}else{
	/*
	wcc = fwrite(RX_rdBuff,1,rcc,RX_tcp);
	*/
	wcc = fwrites(RX_rdBuff,1,rcc,RX_tcp);
	if( wcc < rcc ){
		dupclosed(fileno(RX_fsp));
		addfclose(RX_tcp);
		if( isreg ){
		abortHTTP("disk full in recvHTTPbody?");
		}
		RX_RdTruncated = 2;
		break;
	}

//fflush(RX_tcp);
		if( isWindows() ){
			/* 9.6.3-pre2 to avoid gzread() error */
			fflush(RX_tcp);
		}else
		if( ni == 0 ){
			fflush(RX_tcp);
		}else
		if( RX_rdTotal <= 2048 || finputReady(RX_fsp,NULL) == 0 ){
			fflush(RX_tcp);

if( ni < 3 )
thfprintf(stderr,"----recvbody: rcc=%d EOF=%d FLUSHED\n",
(int)RX_rdTotal,feof(RX_fsp));

		}
		else
		if( 3 < Time()-prevFlush ){
			fflush(RX_tcp);
			if( prevFlush == 0 ) prevFlush = Time();
			sv1log("-- %X rb flush %.3f %lld/%lld\n",
				TID,Time()-prevFlush,
				RX_rdTotal,RX_rdContLen);
			prevFlush = Time();
		}
	}
	RX_wrTotal += wcc;
	RX_noutput++;
    }
    if( RX_RdTruncated == 0 ){
	if( RX_rdContLen == 0 && feof(RX_fsp) ){
	}else
	if( respSutisfied(RX) ){
	}else{
		RX_RdTruncated = 3;
	}
    }

thfprintf(stderr,"----recvbody: rcc=%d EOF=%d DONE\n",
(int)RX_rdTotal,feof(RX_fsp));

    RX_rdDone = 1;
    return RX_tcp;
}
FileSize recvHTTPbodyX(Connection *Conn,int chunked,FILE *in,FILE *out){
	ResponseContext RXbuf,*RX = &RXbuf;

	bzero(RX,sizeof(RXbuf));
	RX_ovw = 1;
	RX_fsp = in;
	RX_fsx.t_chunked = chunked;
	if( RX_rdBuff == 0 ){ /* from -Fdget */
		RX->r_fsx.t_buffer = UTalloc(SB_HEAP,sizeof(LineBuf),1);
		recvHTTPbody(Conn,RX,out);
		UTfree(&RX->r_fsx.t_buffer);
	}else
	recvHTTPbody(Conn,RX,out);
	return RX_wrTotal;
}
static void recvHTTPmssg(Connection *Conn,ResponseContext *RX,FILE *fp){
	CStr(stat,URLSZ);
	refQStr(line,RX_rdBuff);

	strcpy(stat,RX_rdBuff);
	while( GETRESPTXT(Conn,RX,RX_fromcache) ){
		if( fp != NULL ) fputs(line,fp);
		scanRespHead1(Conn,RX,line);
		if( *line == '\r' || *line == '\n' ){
			break;
		}
	}
	/*
	endRespHead(Conn,RX);
	*/
	setServKeepAlive(Conn,RX);
	recvHTTPbody(Conn,RX,fp);
}

/*
 * maybe should not fdopen/fdclose (malloc) in threads
 */

/* 9.9.5 too small pipe (siz < 25) makes write() block on Win2K */
static int MIN_PIPESIZE = 32;

int withZlib();
int withDGZlib();
int withDG_Zlib();
int gunzipFilterX(FILE *in,FILE *out,int(*func)(void*,int),void*,int);
static int gunzipSync(void *RXv,int sync){
	ResponseContext *RX = (ResponseContext*)RXv;
	RX_rdReady = Time();
	IGNRETP write(sync,"",1);
	return 0;
}
/*
int gunzipFilter(FILE *in,FILE *out);
*/
static void recvbodyF(Connection *Conn,ResponseContext *RX,FILE *ofp,int sync){
	/*
	int synci = dup(sync);
	*/
	int synci;

	setthreadgid(0,STX_tid);
	synci = dup(sync);
	Verbose("---rcbodyF %8X base=%X %X\n",getthreadid(),p2i(&Conn),p2i(RX));
	thfprintf(stderr,"#### recvbodyF thread start (%d)\n",
		RX_rdContLen);
	if( 0x10000 < RX_rdContLen ){
		expsockbuf(fileno(RX_fsp),0x20000,0);
	}
	recvHTTPbody(Conn,RX,ofp);
	/*
	fclose(ofp);
	*/
	fflush(ofp);

	/* 9.6.3-pre7 need to wait fdopen() in gzopen/gunzip thread,
	 * otherwise gzread() will fail in "buffer error"
	 */
	syslog_ERROR("--- Gunzip/recvbody SYNC %.3f\n",Time()-RX_rdReady);
	/* 9.7.5 (Win) should close the output (the input of gunzip)
	 * to let it finish gzopen/gunzip without Non-blocking I/O on Win.
	 */
	dupclosed(fileno(ofp));

	if( RX_rdReady == 0 ){
		int ready;
		double St;
		St = Time();
		if( isWindows() )
			ready = pollPipe(synci,2*1000);
		else	ready = PollIn(synci,2*1000);
		if( RX_rdReady == 0 || 0.1 < Time()-St )
			porting_dbg("--Gunzip/recvbody %.3f rdy=%d %X=%.3f",
				Time()-St,ready,p2i(&RX_rdReady),RX_rdReady);
		syslog_ERROR("--- Gunzip/recvbody SYNC DONE %.3f %.3f\n",
			Time()-RX_rdReady,Time()-St);
	}
	msleep(5);
	close(synci);

	/*
	dupclosed(fileno(ofp));
	*/
	thfprintf(stderr,"#### recvbodyF done\n");
}
int destroyCCSV(PCStr(what),Connection *Conn,int svsock);
int pollPipe(int fd,int toms);
static int nGzip;
static void HTgunzipF(Connection *Conn,const ResponseContext *aRX,FILE *ofp,int sync){
	ResponseContext myRX,*RX = &myRX;
	int leng;
	int mio[2];
	int sio[2];
	FILE *mofp = 0;
	FILE *mifp = 0;
	int tid = 0;
	int terr = 0;
	double Start = Time();
	int wi;
	/*
	int synci = dup(sync);
	*/
	int synci;
	LineBuf lbuff;

	setthreadgid(0,STX_tid);
	synci = dup(sync);
	*RX = *aRX;
	RX->r_fsx.t_buffer = UTset(&lbuff,sizeof(LineBuf));

	RX_ovw = 1; /* this RX (myRX) is shared with the recvbody thread */
	Verbose("---GunzipF %8X base=%X %X<%X\n",getthreadid(),p2i(&Conn),p2i(RX),p2i(aRX));
	thfprintf(stderr,"#### HTgunzipF thread start\n");
	RX_rdReady = 0;
	RX_rdDone = 0;
	mifp = RX_fsp;
	setbuffer(ofp,NULL,0); /* unbuffered for smooth relay */
	if( isWindows() )
		pipeX(sio,MIN_PIPESIZE);
	else
	{IGNRETZ pipe(sio);}

	if( 1 /* KeepAlive or chunked or Socket/Win */ ){
	/* if( RX_fsx.t_keepAlive || RX_fsx.t_chunked ){ */
		int IsSolaris();
		if( IsSolaris() ){
			/* 9.6.1 for non-blocking fread() on Solaris */
			Socketpair(mio);
		}else
		if( isWindows95() ){
			Socketpair(mio); /* 9.9.5 for Win95 */
			expsockbuf(mio[1],16*1024,0);
		}else
		if( isWindows() ){
			/* necessary for the workaround in 9.6.3-pre2 */
			pipeX(mio,16*1024);
		}else
		{IGNRETZ pipe(mio);}
		setInheritHandle(mio[1],0);
		mofp = fdopen(mio[1],"w");
		setbuffer(mofp,NULL,0);
		mifp = fdopen(mio[0],"r");

thfprintf(stderr,"---1 gunzipf fork recvbody ready=%d+%d (%d)\n",
finputReady(mifp,NULL),fPollIn(mifp,1),sizeof(ResponseContext));

		tid = thread_fork(0x40000,STX_tid,"recvbodyF",(IFUNCP)recvbodyF,Conn,RX,mofp,sio[0]);
		/*
		if( thread_PollIn(mio[0],10*1000) == 0 ){
		*/
		if( PollIn(mio[0],HTTP_TOUT_THREAD_PIPELINE*1000) == 0 ){
			sv1log("{T} timeout waiting 'recvbody' thread\n");
porting_dbg("{T} timeout waiting 'recvbody' thread rcc=%d %ds",
RX_RdTotalG,HTTP_TOUT_THREAD_PIPELINE);
		}
	}

thfprintf(stderr,"---3 gunzipf start ready=%d+%d\n",
finputReady(mifp,NULL),fPollIn(mifp,1));

	/*
	 * wait enough zipped data to be received
	 * it will be fread() in gzdopen() in NonblockingIO() mode
	 */
	if( withDG_Zlib() ){
		Verbose("NO wait-resp with DGZlib/%d\n",withDG_Zlib());
	}else
	if( !withDGZlib() )
	for( wi = 0; wi < 50; wi++ ){

thfprintf(stderr,"---- waiting resp: %.3f [%2d]%c cc=%d\n",
Time()-Start,wi,RX_rdDone?'F':' ',(int)RX_rdTotal);

		if( RX_rdDone ){
			break;
		}
		if( isWindows() ){
			/* 9.6.3-pre2 to avoid gzread() error */
			int piped = pollPipe(mio[0],TIMEOUT_IMM);
			if( 16*1024 <= piped ){
				sv1log("wait-resp %d/%d/%d %d %.2f\n",
				(int)RX_rdTotal,(int)RX_wrTotal,(int)RX_rdContLen,
					piped,Time()-Start);
				break;
			}
			if( 10 < (Time() - Start) ){
				sv1log("wait-resp %d/%d/%d %d %.2f (timeout)\n",
				(int)RX_rdTotal,(int)RX_wrTotal,(int)RX_rdContLen,
					piped,Time()-Start);
				break;
			}
			msleep(20*wi);
			continue;
		}
		if( 0 < RX_rdTotal && 1 < (Time() - Start) ){
			break;
		}
		if( 10 < (Time() - Start) ){
			break;
		}
		if( 2048 <= RX_rdTotal ){
			break;
		}
		/* should be thread_wait(tid,100); */
		msleep(20*wi);
	}
	/*
	RX_rdReady = Time();
	close(sio[0]);
	close(sio[1]);
	leng = gunzipFilter(mifp,ofp);
	*/
	if( lTHREADLOG() ){
		putfLog("thread-Gunzip start [%d]%d",sync,++nGzip);
		leng = gunzipFilterX(mifp,ofp,gunzipSync,RX,sio[1]);
		putfLog("thread-Gunzip done [%d]%d",sync,--nGzip);
	}else
	leng = gunzipFilterX(mifp,ofp,gunzipSync,RX,sio[1]);
	thfprintf(stderr,"#### HTgunzipF thread done\n");
	IGNRETP write(sio[1],"",1); /* 9.9.5 for Win95 */
	close(sio[0]);
	close(sio[1]);

	if( 0 < leng ){
		double St = Time();
		int to;
		int ready;
		if( 30 < (to = HTTP_TOUT_THREAD_PIPELINE) )
			to = 30;
		ready = pollPipe(synci,to*1000);
if( 1.0 < Time()-St )
porting_dbg("+++EPIPE gunzipFilter() %X/%d/%d mio[%d,%d] ready=%d %.3f leng=%d",
p2i(ofp),SocketOf(fileno(ofp)),fileno(ofp),mio[0],mio[1],ready,Time()-St,leng);
	}
	close(synci); /* 9.8.2 must be closed independently of leng */
	if( tid ){
		addfclose(mifp);
		terr = thread_wait(tid,30*1000);
		addfclose(mofp);
	}
	addfclose(ofp);
	thfprintf(stderr,"#### HTgunzipF thread exit\n");
}
static int threadGunzipB(Connection *Conn,ResponseContext *RX){
	int fio[2];
	int sio[2];
	FILE *fsp;
	FILE *ofp;

	setthreadgid(0,STX_tid);
	Verbose("---GunzipB %8X base=%X\n",getthreadid(),p2i(&Conn));
	IGNRETZ pipe(fio);
/*
sv1log("-- threadGunzipB() %X/%d/%d fio[%d,%d] init...\n",
RX_fsp,SocketOf(fileno(RX_fsp)),fileno(RX_fsp),fio[0],fio[1]);
*/
	setInheritHandle(fio[1],0);
	fsp = fdopen(fio[0],"r");
	if( fsp == NULL ){
		sv1log("##FATAL: fdopen([%d]) in threadGunzipB, e%d\n",
			fio[0],errno);
		close(fio[0]);
		close(fio[1]);
		return 0;
	}
	ofp = fdopen(fio[1],"w");

thfprintf(stderr,"---0 gunzipf start ready=%d+%d\n",
inputReady(fio[0],NULL),PollIn(fio[0],1));

	if( isWindows() )
		pipeX(sio,MIN_PIPESIZE);
	else
	{IGNRETZ pipe(sio);}
	/* 0x30000 is necessary for KURO-BOX-PRO */
	RX->r_fsx.t_tid = thread_fork(0x40000,STX_tid,"HTgunzipF",(IFUNCP)HTgunzipF,Conn,RX,ofp,sio[0]);
	if( PollIn(fio[0],1000) == 0 ){
	    double St = Time();
	    double Et;
	    int rcc = RX_RdTotalG;
	    for(;;){
		/*
		if( 0 < PollIn(fio[0],10*1000) )
			break;
		Et = Time() - St;
		if( Et < HTTP_TOUT_THREAD_PIPELINE ){
			sv1log("{T}[%d]%d/%d threadGunzipB c%d/%d %.1f\n",
		*/
		if( 0 < PollIn(fio[0],10*1000) ){
			break;
		}
		Et = Time() - St;
		if( !procIsAlive(serverPid()) ){
			porting_dbg("{T} GunzipB server [%d] dead",serverPid());
		}else
		if( Et < HTTP_TOUT_THREAD_PIPELINE
		 || RX_RdTotalG != rcc && Et < IO_TIMEOUT && IsAlive(ClientSock)
		    /* 9.7.0 very slow but serv seems active and clnt alive */
		){
			sv1log("{T}[%d]%d/%d threadGunzipB c%d/%d %d %.1f\n",
				getthreadix(),actthreads(),numthreads(),
				ClientSock,IsAlive(ClientSock),
				RX_RdTotalG,
				Et);
			rcc = RX_RdTotalG;
			continue;
		}
		sv1log("{T} timeout waiting 'gunzip' thread\n");
porting_dbg("+++EPIPE timeout waiting 'gunzip' thread %X %.1f/%d",
RX->r_fsx.t_tid,Et,HTTP_TOUT_THREAD_PIPELINE);
		if( EccEnabled() ){
			destroyCCSV("gunzip",Conn,fileno(RX_fsp));
		}
		if( lSINGLEP() ){
			fprintf(stderr,"-- %X timeout waiting gunzip\n",TID);
			fflush(stderr);
			break;
		}
		close(fio[0]);
		close(fio[1]);
		// thread_wait(RX->r_fsx.t_tid);
		// return 0;
		_Finish(1);
	    }
	}

thfprintf(stderr,"---4 gunzipf started ready=%d+%d\n",
inputReady(fio[0],NULL),PollIn(fio[0],1));

	/*
	RX_fsp = fdopen(fio[0],"r");
	*/
	RX_fsp = fsp;
/*
sv1log("-- threadGunzipB() %X/%d/%d fio[%d,%d] ready=%d eof=%d\n",
fsp,SocketOf(fileno(fsp)),fileno(fsp),fio[0],fio[1],pollPipe(fileno(fsp),1),feof(fsp));
*/
	IGNRETP write(sio[1],"",1); /* 9.9.5 for Win95 */
	close(sio[0]);
	close(sio[1]);
	return 1;
}

int HTTP_MIN_THREAD_GUNZIP = 0;
static int threadGunzip(Connection *Conn,ResponseContext *RX){
	if( 0 < RX_rdContLen && RX_rdContLen < HTTP_MIN_THREAD_GUNZIP ){
		sv1log("--NO threadGunzip %d/%d\n",ll2i(RX_rdContLen),
			HTTP_MIN_THREAD_GUNZIP);
		return 0;
	}
	if( lNOTHREAD() ) return 0;
	if( !INHERENT_thread() ) return 0;
	if( !withZlib() ) return 0;
	return threadGunzipB(Conn,RX);
}

int gzipFilterX(FILE *in,FILE *out,int(*func)(void*,int,int),void*,int);
static int gzipSync(void *RXv,int sync,int code){
	ResponseContext *RX = (ResponseContext*)RXv;
	IStr(scode,1);
	setVStrElem(scode,0,code);
	IGNRETP write(sync,scode,1);
	return 0;
}
/*
int gzipFilter(FILE *in,FILE *out);
*/
static int relayio(FILE *in,FILE *out,int doflush){
	CStr(buf,4*1024);
	int rcc;
	int wcc;
	int total = 0;

	thfprintf(stderr,"#### relayio thread start\n");
	while( 1 ){
		rcc = fread(buf,1,QVSSize(buf,sizeof(buf)),in);
		if( rcc <= 0 ){
			break;
		}
		wcc = fwrite(buf,1,rcc,out);
		if( wcc < rcc ){
Verbose("+++EPIPE relayio() %d/%d %d SIG*%d\n",wcc,rcc,total,gotSIGPIPE());
			dupclosed(fileno(in));
			dupclosed(fileno(out));
			break;
		}
		total += rcc;
		if( doflush ){
			fflush(out);
		}
	}
	return total;
}
/*
static void gzipF(FILE *ifp,FILE *ofp){
*/
static void gzipF(FILE *ifp,FILE *ofp,ResponseContext *RX,int sync){
	Connection *Conn = RX_Conn;
	int pio[2];
	int leng;
	int tid = 0;
	FILE *pifp = 0;
	FILE *pofp = 0;
	int terr;

	setthreadgid(0,STX_tid);
	Verbose("---GzipF   %8X base=%X\n",getthreadid(),p2i(&ifp));
	thfprintf(stderr,"#### gzipF thread start\n");
	if( withDG_Zlib() ){
		if( isWindows() )
		Verbose("### NO relayio() with DGZlib\n");
	}else
	if( isWindows() ){
		IGNRETZ pipe(pio);
		setInheritHandle(pio[0],0);
		pifp = fdopen(pio[0],"r");
		pofp = fdopen(pio[1],"w");
		tid = thread_fork(0x20000,STX_tid,"relayio",(IFUNCP)relayio,pifp,ofp,1);
		setbuffer(pofp,NULL,0);
		ofp = pofp;
	}

	/*
	if( fPollIn(ifp,10*1000) ){
		thfprintf(stderr,"#### gzipF input-ready\n");
	}
	*/
	/*
	leng = gzipFilter(ifp,ofp);
	*/
	if( lTHREADLOG() ){
		putfLog("thread-Gzip start [%d]%d",sync,++nGzip);
		leng = gzipFilterX(ifp,ofp,gzipSync,RX,sync);
		putfLog("thread-Gzip done [%d]%d",sync,--nGzip);
	}else
	leng = gzipFilterX(ifp,ofp,gzipSync,RX,sync);
	fflush(ofp);
	if( tid ){
		addfclose(pofp);
		terr = thread_wait(tid,30*1000);
		addfclose(pifp);
	}
	addfclose(ifp);

	/* original ofp will be closed at fclosesTIMEOUT(tc,fc) */
}
static FILE *threadGzipA(Connection *Conn,ResponseContext *RX,FILE *ofp);
static FILE *threadGzip(Connection *Conn,ResponseContext *RX,FILE *ofp){
	FILE *nofp = ofp;
	int dummy; /* to expand main thread stack */

	if( lNOTHREAD() ) return 0;
	if( !INHERENT_thread() )
		return 0;
	if( !withZlib() ) return 0;

	nofp = threadGzipA(Conn,RX,ofp);
	RX_didZip = 1;
	return nofp;

}
static FILE *threadGzipA(Connection *Conn,ResponseContext *RX,FILE *ofp){
	int fio[2];
	FILE *in;
	FILE *out;
	int gio[2];
	CStr(stat,1);
	int gready;
	double St;

	setthreadgid(0,STX_tid);
	Verbose("---GzipA   %8X base=%X\n",getthreadid(),p2i(&Conn));
	IGNRETZ pipe(fio);
	setInheritHandle(fio[0],0);
	in = fdopen(fio[0],"r");
	out = fdopen(fio[1],"w");
	setbuffer(out,NULL,0);

	IGNRETZ pipe(gio);
	St = Time();
	RX->r_tcx.t_tid = thread_fork(0x40000,STX_tid,"gzipF",(IFUNCP)gzipF,in,ofp,RX,gio[1]);
	gready = PollIn(gio[0],10*1000);
	setVStrElem(stat,0,255);
	if( 0 < gready ){
		IGNRETP read(gio[0],stat,1);
	}
	sv1log("gzipThread ready=%d [%d] %.3f\n",gready,stat[0],Time()-St);
	close(gio[0]);
	close(gio[1]);

	return out;
}

#define RF_CACHED	1
#define RF_DECODED	2

static int gotEnoughResp(Connection *Conn,ResponseContext *RX,int fromcache){
	double Now;

	if( 1024*1024 < RX_rdTotal ){
		return 1;
	}
	Now = Time();
	if( isWindowsCE() ){
		/* to let tmpfile smaller */
	}else
	if( Now-CONN_DONE < 0.5 || Now-RX_Resp1 < 0.5 ){
		return 0;
	}
	if( CCXactive(CCX_TOCL) ){
		/* enough for detection of input charset */
		if( CCXgotincharcode(CCX_TOCL) ){
			return 1;
		}
		if( 2*1024 < RX_rdTotal ){
			/* might be US-ASCII or non-JP */
			return 1;
		}
	}else{
		return 1;
	}
	return 0;
}
static void flushRespLog(Connection *Conn,ResponseContext *RX,PCStr(flush)){
	sv1log("#### flushResp: %s (%lld/%lld/%.2f/%.2f/%s)\n",flush,
		RX_rdTotal,RX_rdContLen,
		Time()-RX_Resp1,Time()-CONN_DONE,
		CCXactive(CCX_TOCL)&&CCXgotincharcode(CCX_TOCL)?"C":""
	);
}
static void flushSlowResponse(Connection *Conn,ResponseContext *RX,int fromcache)
{	CStr(flush,128);
	const char *ics;

	flush[0] = 0;

        if( RX_tcp == RX_respBuff && !RX_inHeader && !ClientEOF )
	if( fromcache & RF_DECODED ){
	    if( RESP_DoZIP ){
		/* The slowness can be due to narrow band-width with the
		 * client, but can be due to that with the server.
		 * If the client is local, gzip should be suppressed,
		 * and Keep-Alive should be enabled instead.
		 */
/*
		if( 1.0 < Time()-CONN_DONE
		 || 1024*1024 < RX_rdTotal
		){
*/
		if( gotEnoughResp(Conn,RX,fromcache) ){
			FILE *ofp;
			if( ofp = threadGzip(Conn,RX,RX_tc_sav) ){

thfprintf(stderr,"--HZT flushSlow! with GZIP %f rcc=%d,FBI=%d [%s]\n",
Time()-CONN_DONE,(int)RX_rdTotal,RX_FBI,InCharset);

				flushRespLog(Conn,RX,"threadGzip");
				detach_respbuffX(Conn,RX,RX_tcp,RX_tc_sav,
					"gzip",ofp,
					RX_qWithHeader,"detach for threadGzip");
				RX_tcp = ofp;
				return;
			}
		}
	    }
	}

	if( (fromcache & RF_DECODED) == 0 )
	/*
        if( WillKeepAlive )
		9.2.2 commented this condition out.
		why? this code for detaching is introduced in 3.0.58 to
		stop buffering for KeepAlive. But at least, huge-data
		should be unbuffered even in non-Keep-Alive.
	*/
        if( RX_tcp == RX_respBuff && !RX_inHeader && !ClientEOF )
	{
		if( RX_FBI && 0 < RX_rdTotal && ( 2*1024 < RX_rdTotal
		 || InCharset[0]
		 || CCXgotincharcode(CCX_TOCL)
		)){
			ics = CCXgotincharcode(CCX_TOCL);
			sprintf(flush,"FBI charset=%s,%s,%s / %lld",
				InCharset,ics?ics:"",CCXident(CCX_TOCL),
				RX_rdTotal);
		}else
		if( 1024*1024 < RX_rdContLen
		 && !(RX_guessCharset && RX_rdTotal==0) )
			sprintf(flush,"too large ContLen: %lld",RX_rdContLen);
		else
		if( 1024*1024 < RX_rdTotal )
			sprintf(flush,"too much read: %lld",RX_rdTotal);
		else
		/*
		if( !WillKeepAlive ){
		}else
		*/
		/*
		if( 8 < Time()-CONN_DONE )
		*/
		if( RX_rdTotal == 0
		 && CCXactive(CCX_TOCL)
		 && Time() - RX_Resp1 < HTTP_TOUT_BUFF_RESBODY
		){
			/* 9.5.6 don't flush on the first response */
			if( HTTP_TOUT_BUFF_RESBODY < Time()-CONN_DONE
			){
				flushRespLog(Conn,RX,"supp. for CHARCODE");
			}
		}else
		if( HTTP_TOUT_BUFF_RESBODY < Time()-CONN_DONE )
		{
			sprintf(flush,"too long time:%.1f",Time()-CONN_DONE);
		}
		else
		if( !fromcache
		 && 5 < Time()-CONN_DONE
		 && RX_fsx.t_nready == 0
		 && (RX_fsx.t_nready = fPollIn(RX_fsp,100)) == 0 )
		{
			sprintf(flush,"time out: %.2f",Time()-CONN_DONE);
		}
	}
	if( flush[0] ){
		flushRespLog(Conn,RX,flush);
		RX_tcp = detach_respbuff(Conn,RX_tcp,RX_tc_sav,
			RX_qWithHeader,"flush slow response.");
		/* CCX should be cleared too when charset is restored ... */
	}
}

/*
 * flush buffer immediately
 */
static void setFBI(Connection *Conn,ResponseContext *RX,int isbin){
	if( RX_tcx.t_chunked ){
		/* Content-Length is not mandatory */
		RX_FBI = 1;
	}else
	if( CCXguessing(CCX_TOCL)
	 && !withConversionX(Conn,0,RX_woURI) ){
		/* Content-Length will not be changed */
		RX_FBI = 2;
	}else
	if( !WillKeepAlive ){
	}
}

/*
 * set the original charset in Set-Cookie
 */
static void setSVCC(Connection *Conn,ResponseContext *RX,PCStr(rhead)){
	if( CCXactive(CCX_TOCL) == 0 ){
		/* not necessary, charset will not be converted */
		return;
	}
	if( RX_tcx.t_chunked == 0 ){
		/* not necessary, charset will be set in putMIME_msg() */
		/* 9.6.2 or in detach_respbuff() for threadGzip() or so */
		return;
	}
	if( RX_isText )
	{
	putProxyCookie(Conn,RX_tcp,RX_code,rhead);
	}
}

/*
static void resetSVCC(Connection *Conn,ResponseContext *RX,FILE *afp,PCStr(rhead)){
	CStr(xrhead,1024);
	refQStr(xp,xrhead);
	int hlen;
	int off;
	int rcc;

	strcpy(xrhead,rhead);
	if( xp = strstr(xrhead,"\r\n\r\n") ){
		xp += 4;
		setVStrEnd(xp,0);
	}else{
		strcat(xrhead,"\r\n\r\n");
	}
	removeFields(AVStr(xrhead),"Content-Encoding",0);
	hlen = strlen(xrhead);
	off = ftell(afp);
	rcc = fread(xrhead+hlen,1,sizeof(rhead)-1-hlen,afp);
	fseek(afp,off,0);

	if( 0 < rcc ){
		setVStrEnd(xrhead,rcc);
		setSVCC(Conn,RX,xrhead);
	}
}
*/

int IsCFI(PCStr(filter));
const char *CFI_searchSpecEnv(Connection *Conn,PCStr(sp),PCStr(st),PCStr(he));
static FILE *insertFTOCL_X(Connection *Conn,FILE *tc);
static const char *findCFI(Connection *Conn,PCStr(CFIscript),PCStr(rhead)){
	CStr(stat,128);
	/*
	CStr(headb,1024);
	*/
	CStr(headb,URLSZ);
	const char *head;
	const char *hx;
	const char *spec;

	head = lineScan(rhead,stat);

	if( *head == '\r' ) head++;
	if( *head == '\n' ) head++;
	if( hx = strSeekEOH(head) ){
		QStrncpy(headb,head,hx-head+1);
		head = headb;
	}else{
		sv1log("ERROR: findCFI(NO HEAD)\n");
		return "";
	}
	if( strcasestr(CFIscript,"X-Request") ){
		/* 9.9.4 headers to be put in HTTP_echoRequestHeader() ... */
		Xsprintf(TVStr(headb),"X-Request-User-Agent: %s\r\n",REQ_UA);
		Xsprintf(TVStr(headb),"X-Request-Original: %s",OREQ);
		Xsprintf(TVStr(headb),"X-Request: %s",REQ);
	}

	spec = CFI_searchSpecEnv(Conn,CFIscript,stat,head);
	if( spec == 0 ){
		Verbose("No filter in #!cfi to be applied.\n");
		return NULL;
	}else{
		Verbose("Found a filter in #!cfi to be applied.\n");
		/*
		strfree((char*)spec);
		UTfree();
		*/
		return spec;
	}
}
FILE *CFI_insertFTOCL(Connection *Conn,FILE *atc,PCStr(rhead)){
	const char *spec;

	if( Conn->xf_filters & XF_FTOCL )
		return atc;

	if( sav_FTOCL && IsCFI(sav_FTOCL) ){
		CStr(cntrl,128);
		if( (spec = findCFI(Conn,sav_FTOCL,rhead)) == 0  ){
			return atc;
		}
		if( getFV(spec,"Control/Cache-Control",cntrl) ){
			if( isinListX(cntrl,"no-cache","cw;") ){
				DontWriteCache |= CACHE_DONTCARE;
			}
		}
		if( getFV(spec,"Control/CFI-Control",cntrl) ){
			if( isinListX(cntrl,"no-filter","cw") ){
				return atc;
			}
		}
	}

	if( sav_FTOCL )
		setFTOCL(sav_FTOCL);
	atc = insertFTOCL_X(Conn,atc);
	setFTOCL(NULL);
	return atc;
}
static void logEmptyResp(Connection *Conn,QueryContext *QX,int cleof){
	sv1log("emptyResp [%s] %.1fs+%.1fs*%d %s(%s)\n",
		DST_HOST,
		CONN_DONE-ServConnTime,
		Time()-CONN_DONE,
		ServReqSerno,
		(cleof||!isAlive(ClientSock))?"CLE":"",
		REQ_UA
	);
}
/* 9.8.2 to remove the cache truncated by the premature disconnection
 * from the client and without completion with takeover by DeleGate
 */
static int removeTruncated(Connection *Conn,QueryContext *QX,ResponseContext *RX){
	if( RX_cachefp == 0 ){
		return 0; /* not updating a cache file */
	}
	if( ServerFlags & PF_IS_DISTRIB ){
		return 0; /* a receiver of distrib. */
	}
	if( RX_didUnzip ){
		if( RX_RdTruncated == 0 ){
			return 0;
		}
	}else{
		if( respSutisfied(RX) ){
			return 0;
		}
	}
	QX_cacheRemove = R_TRUNCATED;
	QX_svclose = 2; /* don't reuse the server connection */
	LOGX_app_respIncomplete++;
	fprintf(stderr,"----TRUNCATE %d,%c,%d ck=%d/%d ln=%lld/%lld/%lld %s %s\n",
		ClientEOF,RX_didUnzip?'z':'-',RX_RdTruncated,
		RX_fsx.t_chunked,RX_fsx.t_chunk_siz,
 		RX_rdContLen,RX_rdTotal,RX_txtLen,
		DST_HOST,REQ_URL
	);
	return 1;
}
static int svIncomplete(Connection *Conn,QueryContext *QX,ResponseContext *RX){
	/* if in keep-alive with the server */
	if(  RX_inHeader
	 || !RX_noBody && (RX_didUnzip ? RX_RdTruncated : !respSutisfied(RX))
	){
		QX_svclose = 2; /* don't reuse the server connection */
		LOGX_app_respIncomplete++;
		sv1log("Incomplete %d H%d B%d (%lld / %lld)\n",
			QX_hcode,RX_inHeader,!RX_noBody,
			RX_rdTotal,RX_rdContLen);
	}
	return 0;
}

/* set RESP_SAV to get WWW-Authorization in the resp. head */
static int NTHT_bufResp(Connection *Conn,ResponseContext *RX){
	if( lDONTHT() == 0 )
		return 0;
	sv1log("----NTHT buffResp %X RX_code=%d\n",withNTHT,RX_code);
	if( RX_code != 401 )
	if( RX_code != 407 )
		return 0;
	if( (withNTHT & NTHT_RES) )	/* set by peeping resp. head */
	if( (withNTHT & NTHT_REQ) == 0	/* non-NTHT client with auth. conv. */
	 || (withNTHT & NTHT_CLAUTHOK)	/* NTHT client with auth. forw. */
	){
		return 1;
	}
	return 0;
}
static int NTHT_endHead(Connection *Conn,ResponseContext *RX){
	if( lDONTHT() == 0 )
		return 0;
	if( RX_code != 401 )
		return 0;
	if( (withNTHT & NTHT_RES) ){
		withNTHT |= NTHT_START;
		if( ServKeepAlive && RX_fsx.t_keepAlive ){
			withNTHT |= NTHT_SERVKA;
		}
		sv1log("----NTHT start session %X\n",withNTHT);
		return 1;
	}
	return 0;
}
static void setupRespNTHT(Connection *Conn,PCStr(rhead),PCStr(fname)){
	IStr(line,128);
	IStr(atyp,64);
	const char *rp,*np;

	for( rp = rhead; rp != 0; ){
		np = findFieldValue(rp,fname);
		if( np == 0 )
			break;
		rp = strchr(np,'\n');
		wordScan(np,atyp);
		if( strcaseeq(atyp,"Negotiate") ) withNTHT |= NTHT_RESNEGO;
		if( strcaseeq(atyp,"NTLM") )      withNTHT |= NTHT_RESNTLM;
	}
}

int HTTP_MAX_RHPEEP = 1024;
static int foundBrokenCache(QueryContext *QX);
static int HTTP_ContLengOkQX(FILE *fs,QueryContext *QX);
static int cacheReadOK(Connection *Conn,ResponseContext *RX);
const char *HTTP_thruType = "application/zip,application/x-rpm,application/microsoftpatch";
int relay_responseX(Connection *Conn,QueryContext *QX,int cpid,PCStr(proto),PCStr(server),int iport,PCStr(req),PCStr(acpath),int fromcache, FILE *afs,FILE *atc,FILE *afc,FILE *acachefp,int cache_rdok, ResponseContext *RX,PVStr(refbuf))
{	Referer refererb;
	vfuncp osigpipe;
	int lastRcc;
	MrefQStr(line,RX_rdBuff); /**/
	double Start = Time();
	int ready1 = -1;
	const char *got1;
	int rcc;
	int mytype;
	FILE *tmp_fsp = 0;
	CStr(rhead,4*1024); /* peeked response header */
	int rhsiz = HTTP_MAX_RHPEEP;
	int ifd = fileno(afs);
	double Now,Next = 0;
	int SWF_MOUNT = 0;
	int contLen = 0;
	int isText = 0;
	int isBin = 0;
	int asBin = 0;
	const char *thruType = 0;
	CStr(ctype,64);
	int fromcacheX = fromcache;
	int psigPIPE;
	IStr(genf,URLSZ);
	const char *igp = 0;
	int gen_irhead = 0;
	const char *stx = "";
	int te1,te2;
	int didUnzip = 0;
	int pipelined = afc?READYCC(afc):0;
	FILE *nullfp = 0;

if( Conn->sv_reusing )
if( getenv("EMUCLOSE3") ){
	sv1log("--EMULATE EOF AT START ON KEEP-ALIVE WITH SERVER (%d)\n",
		Conn->sv_reusing);
	return R_EMPTY_RESPONSE;
}

	scan_CCXTOCL(Conn);

	if( DONT_REWRITE )
	if( (HTTP_opts & HTTP_DONT_REWRITE_PX) == 0 )
	if( (HTTP_opts & HTTP_DO_REWRITE_PX) || IsMounted )
	if( MountOptions == 0 || !isinList(MountOptions,"px-thruresp") )
	{
		/* 9.2.0 */
		sv1log("## rewriting resp. as a proxy ##\n");
		DONT_REWRITE = 0;
	}

	RX_didUnzip = 0;
	RX_didZip = 0;
	RX_woURI = 0;
	RX_cencoded = 0;
	rhead[0] = 0;
	setVStrEnd(ctype,0);
	/*
	if( ready_cc(afs) <= 0 ){
		int ifd = fileno(afs);
	*/
	if( lNOGZIP() ){
		/* 9.8.2 don't gzip if the client is local */
		/* this is very siginificant on the performance on WinCE */
		RESP_DoZIP = 0;
	}

	rcc = -1;
	if( QX_cachemmap ){
		if( QX_cacheheadlen < rhsiz )
			rcc = QX_cacheheadlen;
		else	rcc = rhsiz - 1;
		bcopy(QX_cacheheadbuf,rhead,rcc);
	}else
	if( isWindowsCE() ){
		/* no MSG_PEEK on WinCE */
		/* could be simulated in buff. in FILE */

		if( fromcache ){
		}else
		if( watchBothside(ifd,ClientSock) ){
			double timeout;
			int reset;
			if( HTTP_TOUT_RESPLINE )
				timeout = HTTP_TOUT_RESPLINE;
			else	timeout = IO_TIMEOUT;
			if( lSINGLEP() ){
				timeout = IOTIMEOUT((int)(timeout*1000))/1000.0;
			}
			reset = receiverReset("relayR",timeout,ifd,ClientSock);
			if( reset ){
				/* should dupclosed(fileno(afs));
				 * and stop keep-alive, flush the buff. in fc
				 */
				setClientEOF(Conn,afc,"relay_response.RESET");
				return R_EMPTY_RESPONSE;
			}
		}
	}else
	if( ready_cc(afs) <= 0 || file_isreg(ifd) ){
		if( rhsiz < 256 )
			rhsiz = 256;
		if( sizeof(rhead) < rhsiz )
			rhsiz = sizeof(rhead);

		if( file_isreg(ifd) ){
			int off;
			off = ftell(afs);
			rcc = fread(rhead,1,QVSSize(rhead,rhsiz-1),afs);
			fseek(afs,off,0);
		}else
		if( file_ISSOCK(ifd) ){
			int timeout;
			int timeout0;
			if( Conn->sv_reusing ){
				timeout = (int)(1000 * HTTP_TOUT_CKA_RESPLINE);
			}else
			if( Conn->io_timeout ){
				timeout = (int)(1000 * Conn->io_timeout);
			}else
			if( HTTP_TOUT_RESPLINE )
				timeout = (int)(1000 * HTTP_TOUT_RESPLINE);
			else	timeout = (int)(1000 * IO_TIMEOUT);
			if( lSINGLEP() ){
				timeout = IOTIMEOUT(timeout);
			}
			if( timeout == 0 ){
				timeout = 60*60*1000;
				/* 9.9.7 timeout==0 causes timeout unconditionally */
			}
			timeout0 = timeout;
			if( !Conn->from_myself && 0 <= ClientSock ){
				int nready;
				int fdv[2];
				int rdv[2];
				double StartR = Time();

				fdv[0] = ClientSock;
				fdv[1] = ifd;
				nready = PollIns(timeout,2,fdv,rdv);
				ready1 = nready;

				/* IsAlive() might block ? */
				if( 0 < nready && 0 < rdv[0]
				 && !IsAlive(ClientSock) ){
			daemonlog("E","client disconn. before resp.(%.2f/%d)\n",
				Time()-StartR,timeout);
					http_Log(Conn,500,CS_EOF,req,0);
					logEmptyResp(Conn,QX,1);
					setCLX("BR",CLX_BEFORE_RESP);
/* must abandon the response or the connection to the server */
					return R_EMPTY_RESPONSE;
				}
				timeout -= (int)(1000*(Time()-StartR));
			}
			/*
			if( PollIn(ifd,timeout) == 0 ){
			*/
			if( timeout <= 0
			 || PollIn(ifd,timeout) == 0 ){
		sv1log("HTTP relay_response: TIMEOUT at resp. peek (%d/%d)\n",
		timeout,timeout0);
				http_Log(Conn,500,CS_TIMEOUT,req,0);
				if( Conn->sv_reusing )
					logEmptyResp(Conn,QX,0);
				return R_EMPTY_RESPONSE;
			}
			/* blocked on FTOSV error (request is not sent) */
			rcc = RecvPeek(ifd,rhead,QVSSize(rhead,rhsiz-1));
			if( rcc < 0 ){
				int ch;
 porting_dbg("ERROR resp. peek %d %.1f/%d c%d e%d %s:%d",
 rcc,Time()-Start,timeout/1000,IsConnected(ifd,0),errno,DST_HOST,DST_PORT);
				ch = getc(afs);
 porting_dbg("ERROR resp. peek %d %.1f/%d c%d e%d %s:%d %X",
 rcc,Time()-Start,timeout/1000,IsConnected(ifd,0),errno,DST_HOST,DST_PORT,ch);
				if( ch == EOF ){
					http_Log(Conn,500,CS_TIMEOUT,req,0);
					logEmptyResp(Conn,QX,1);
					return R_EMPTY_RESPONSE;
				}else{
					ungetc(ch,afs);
				}
			}
		}
	}
	if( 1 ){
		if( 0 < rcc ){
			int hi,isbin,iszip,istxt;
			char ch;
			const char *val;
			CStr(cenc,16);
			setVStrEnd(rhead,rcc);

			istxt = 0;
			iszip = 0;
			isbin = 0;

			if( val = findFieldValue(rhead,"Content-Type") ){
				wordScanY(val,ctype,"^;\r\n");
				if( strncasecmp(val,"image/",6) == 0
				 || strncasecmp(val,"video/",6) == 0
				){
					RX_woURI = 1;
					isBin = 1;
				}
				if( HTTP_thruType
				 && isinListX(HTTP_thruType,ctype,"c") ){
					thruType = ctype;
				}
				if( strncasecmp(val,"text/",5) == 0 ){
					istxt = 1;
					isText = 1;
					if( strcaseeq(val,"text/plain") ){
						RX_woURI = 1;
					}
				}
				if( strncasecmp(val,"text/css",8) == 0 ){
					/* for Mozilla/4.7 */
					sv1log("#CEcl no gzip for CSS\n");
					RESP_DoZIP = 0;
				}
				if( URL_SEARCH & URL_IN_SWF )
		if( strncasecmp(val,"application/x-shockwave-flash",29)==0 )
					SWF_MOUNT = 1;
			}
			if( val = findFieldValue(rhead,"Content-Encoding") ){
				RX_cencoded = 1;
				wordScan(val,cenc);
				if( isinList("gzip,deflate",cenc) ){
					iszip = 1;
				}
				if( isinList("x-gzip",cenc) ){
					iszip = 2;
				}
			}
			if( val = findFieldValue(rhead,"Content-Length") ){
				contLen = atoi(val);
			}
			for( hi = 0; hi < rcc; hi++ ){
				ch = rhead[hi];
				if( ch == 0 ){
					isbin = 1;
					break;
				}
			}
			if( val = findFieldValue(rhead,"X-Pragma") ){
				wordScan(val,cenc);
				if( strcaseeq(cenc,"no-gzip") ){
					RESP_DoZIP = 0;
				}
			}
			if( val = findFieldValue(rhead,"Proxy-Authenticate") ){
				if( lDONTHT() ){
					setupRespNTHT(Conn,rhead,"Proxy-Authenticate");
				}
			}
			if( val = findFieldValue(rhead,"WWW-Authenticate") ){
				IStr(atyp,64);
				wordScan(val,atyp);
				if( lDONTHT() ){
					setupRespNTHT(Conn,rhead,"WWW-Authenticate");
					if( strcaseeq(atyp,"Negotiate") )
						withNTHT |= NTHT_RESNEGO;
					if( strcaseeq(atyp,"NTLM") )
						withNTHT |= NTHT_RESNTLM;
				}
			}
			if( RESP_DoZIP ){
				if( iszip ){
					/* do zip anyway */
				}else
				if( todoZipType(ctype) ){
					/* binary data to be gzip */
				}else
				if( !istxt ){
					Verbose("#CEcl no gzip for non text\n");
					RESP_DoZIP = 0;
				}else
				if( istxt && isbin && !iszip ){
					/* mal-typed binary ? */
					Verbose("#CEcl no gzip for binary\n");
					RESP_DoZIP = 0;
				}
			}
		}
	}
	if( RESP_DoUNZIP || RESP_DoZIP ){
		/* thru .gz file for efficiency of relay and cache */
		if( strtailstr(REQ_URL,".gz") )
		/*
		if( !isText )
		the type might be text for binary data...
		*/
		{
			sv1log("#CEcl thru %d/%d %s\n",RESP_DoUNZIP,RESP_DoZIP,
				REQ_URL);
			RESP_DoUNZIP = 0;
			RESP_DoZIP = 0;
		}
	}
	if( QX_tcf ){
		sv1log("--retrying... DONT redo insertFTOCL");
		atc = QX_tcf;
		QX_tcf = 0;
	}else{
		FILE *oatc = atc;
	atc = CFI_insertFTOCL(Conn,atc,rhead);
		if( atc != oatc ){
			QX_tcf = atc;
		}
	}
	if( DontWriteCache & CACHE_DONTCARE ){
		if( acachefp ){
			sv1log("cache disabled: %X %s\n",p2i(acachefp),acpath);
			acachefp = 0;
			acpath = 0;
		}
	}
	if( RESP_DoUNZIP == 0 ){
		if( isText )
		if( RX_cencoded )
		if( Conn->xf_filters & XF_FTOCL )
		{
			sv1log("enable DoUNZIP for text to FTOCL\n");
			RESP_DoUNZIP = 1;
		}
	}

	RX_Conn = Conn;
	RX_QX = QX;
	RX_tmpFileId = "HTTP-respBuff";
	RX_ovw = 0;
	RX_cachefp = acachefp;
	RX_cpath = (char*)acpath;
	bzero(&refererb,sizeof(Referer));
	RX_referer = &refererb;
	RX_inHeader = 1;

	RX_tc_sav = 0;
	RX_tcp = atc;
	RX_tcpissock = file_isSOCKET(fileno(atc));
	RX_fromcache = fromcache;
	RX_fsTimeout = 0;
	RX_fsp = afs;
	RX_fsx.t_EOF = 0;
	RX_fsx.t_feof = 0;
	RX_fsx.t_lastRcc = 0;
	RX_fsx.t_chunked = 0;
	RX_fsx.t_chunk_ser = 0;
	RX_fsx.t_chunk_siz = 0;
	RX_fsx.t_chunk_rem = 0;
	RX_fsx.t_keepAlive = 0;
	RX_remsize = sizeof(RX_rdBuff) - 1;

	RX_fsx.t_tid = 0;
	RX_tcx.t_tid = 0;

	line = RX_rdBuff;

	if( ClntAccChunk && 0 < contLen && contLen < HTTP_MIN_CHUNKED ){
		Verbose("#CEcl disable chunk for small data: %d\n",contLen);
		RX_tcx.t_chunked = 0;
	}else
	if( thruType ){
		sv1log("#HT11 thru-type:%s no-chunked/buff\n",thruType);
		RX_tcx.t_chunked = 0;
	}else
	if( HTTP_opts & HTTP_NOCHUNKED ){
		RX_tcx.t_chunked = 0;
	}else
	if( ClntAccChunk && RESP_DoZIP ){
		Verbose("#CEcl disable chunk for Content-Encoding\n");
		RX_tcx.t_chunked = 0;
	}else
	if( SWF_MOUNT )
		RX_tcx.t_chunked = 0;
	else
	if( Conn->xf_filters & (XF_FCL|XF_FTOCL) )
		RX_tcx.t_chunked = 0;
	else
	if( RX_fromcache && !withConversionX(Conn,0,RX_woURI) ){
		RX_tcx.t_chunked = 0;
	}
	else	RX_tcx.t_chunked = ClntAccChunk;
	RX_tcx.t_chunk_ser = 0;

	RX_Start = Time();
	RX_qWithHeader = HTTP_reqWithHeader(Conn,req);
	wordScan(req,RX_qmethod);
	RX_reqHEAD = strcasecmp(RX_qmethod,"HEAD") == 0;

	RX_tryKeepAlive = 0;
	if( ClntKeepAlive ){
		if( strcaseeq(RX_qmethod,"GET")||strcaseeq(RX_qmethod,"HEAD") )
			RX_tryKeepAlive = 1;
		else
		if( strcaseeq(RX_qmethod,"POST") && (HTCKA_opts & HTCKA_POST) ){
			RX_tryKeepAlive = 2;
		}else
		clntClose(Conn,"M:Method is ``%s'' cpid=[%d]",RX_qmethod,cpid);
	}

	QX_hcode = 0;
	for(;;){
		got1 = GETRESPTXT(Conn,RX,fromcache);
		/* 8.11.2: test for badServ
		sprintf(line,"<html>\r\n");
		*/

		if( !fromcache && badServ(Conn,"RESP",BS_RHEAD,NULL,afs,line) )
			return R_EMPTY_RESPONSE;

		lastRcc = RX_fsx.t_lastRcc;
		RespCode = decomp_http_status(line,&RX_status);
if( RX_CODE == 0 )
RX_CODE = RespCode;
		RX_Resp1 = Time();

		if( RX_code == 100 ){
			sv1log("#HT11 [%s] Skip %s",REQ_VER,line);
			if( 0 <= vercmp(REQ_VER,"1.1") )
				fputs(line,RX_tcp);
			while( got1 = GETRESPTXT(Conn,RX,fromcache) ){
				if( 0 <= vercmp(REQ_VER,"1.1") )
					fputs(line,RX_tcp);
				sv1log("#HT11 [%s] Skip %s",REQ_VER,line);
				if( line[0] == '\r' || line[0] == '\n' )
					break;
			}
			if( feof(RX_fsp) ){
				sv1log("#HT11 Skip ... EOF\n");
			}else{
				fflush(RX_tcp);
				continue;
			}
		}
		if( RX_code == 101 ){
			/* Connection upgrade ... */
		}
		break;
	}
	QX_hcode = RX_code;
	if( RX_tcx.t_chunked )
	if( RX_reqHEAD || RX_code == 204 || RX_code == 304 ) /*REQ_noBody*/
	{
		Verbose("NO chunked for %s/%d\n",RX_reqHEAD?"HEAD":"",QX_hcode);
		RX_tcx.t_chunked = 0;
	}

	if( RX_code != 1200 )
	if( RX_tcx.t_chunked ){
		if( strcmp(RX_ver,"HTTP/1.1") < 0 ){ 
			sv1log("#HT11 resp version: %s -> %s\n",RX_ver,"1.1");
			sprintf(line,"HTTP/1.1 %d %s\r\n",RX_code,RX_reason);
			lastRcc = RX_fsx.t_lastRcc = strlen(line);
		}
	}

	if( cpid )
		Kill(cpid,SIGTERM);

	/*
	if( Conn->sv_reusing ){
		fprintf(stderr,"-- TEST to emulate EOF on HCKA-SV\n");
		got1 = NULL;
	}
	*/

	if( got1 == NULL )
	if( EccEnabled() ){
		if( Conn->sv_retry == 0 && got1 == NULL )
		if( feof(RX_fsp) && IsAlive(ClientSock) ){
		porting_dbg("-Ecc(%2d){%d}*%d ##RETRY on EOS-at-start %s:%d",
			Conn->ccsv.ci_ix,Conn->ccsv.ci_id,Conn->ccsv.ci_reused,
				DST_HOST,DST_PORT);
			HTTP_setRetry(Conn,req,503);
			sprintf(line,"HTTP/1.1 500 emulating\r\n");
			RespCode = decomp_http_status(line,&RX_status);
			got1 = line;
		}
	}
	if( got1 == NULL ){
		sv1log("HTTP relay_response: EOF at start (%d %d %.2f)\n",
			ready1,rcc,Time()-Start);
		/* CS_EOF does not mean client-EOF in this case */
		http_Log(Conn,500,CS_EOF,req,0);
		return R_EMPTY_RESPONSE;
	}
	if( RX_QX ){
		if( strncmp(line,"HTTP/1.",7) != 0 ){
			QueryContext *QX = RX_QX;
			QX_cacheRemove = R_BAD_FORMAT;
			QX_svclose = 1;
			daemonlog("F","ERROR: bad HTTP resp. ver.: %s",line);
		}
	}

	if( RX_cachefp != NULL && 500 <= RX_code ){
		if( cache_rdok ){
			sv1log("HTTP temporary error ? %s",line);
			http_Log(Conn,RX_code,CS_EOF,req,0);
			RX_fsTimeout = 200;
			recvHTTPmssg(Conn,RX,NULL);
			/*
			copy_fileTIMEOUT(RX_fsp,NULLFP(),NULL);
			*/
			if( QX_tcf ){
				fclose(QX_tcf);
				QX_tcf = 0;
			}
			return R_EMPTY_RESPONSE;
		}
		RX_cachefp = NULL;
		DontTruncate = 1;
	}
	QX_tcf = 0;

	if( lSINGLEP() ){
	}else
	if( RX_cachefp != NULL ){
		Verbose("CacheMtime: %d : %d\n",CacheMtime,
			file_mtime(fileno(RX_cachefp)));

		if( CacheMtime != file_mtime(fileno(RX_cachefp)) ){
			int fd;

			sv1log("## !!! Cache is updated by someone else.\n");
/*
RX_cachefp = NULL;
*/
			fd = open(RX_cpath,0);
			dup2(fd,fileno(RX_cachefp));
			close(fd);
			DontTruncate = 1;
		}
	}

	/*
	 *	If the transmission speed from the server is slow,
	 *	do flush frequently.
	 */
	if( fromcache ){
		RX_connDelay = 0;
	}else{
		int delay;

		RX_connDelay = CONN_DONE - CONN_START;
		RX_firstResp = Time() - CONN_DONE;
		daemonlog("D","connDelay:%5.2fsec, firstResp:%5.2fsec\n",
			RX_connDelay,RX_firstResp);
	}

	if( checkClientEOF(Conn,RX_tcp,"start_response") ){
		httpStat = CS_EOF;
		return R_UNSATISFIED;
	}

	RX_noBody = RX_reqHEAD;

/*
	if( ToMyself )
*/
	if( ToMyself || IsMounted )
	{
		mytype = 0;
		if( !IsMounted && IsVhost )
		if( httpStat != CS_LOCAL )
		if( ClientFlags & PF_MITM_ON ){
			/* 9.9.2 not VHOST but MITM (resp. filter) */
		}else
		if( (ClientFlags & PF_AS_PROXY) == 0 ){
			/* forwarding by RELAY=vhost */
			mytype = RELAY_VHOST;
		}
	}
	else
	if( DO_DELEGATE )
		mytype = RELAY_DELEGATE;
	else	mytype = RELAY_PROXY;

	NOJAVA = 0;
	if( do_RELAY(Conn,mytype|RELAY_APPLET) == 0 )
		NOJAVA |= RELAY_APPLET;
	if( do_RELAY(Conn,mytype|RELAY_OBJECT) == 0 )
		NOJAVA |= RELAY_OBJECT;
	if( NOJAVA ){
		sv1log("## NOJAVA=%X ty=%X mo=%d px=%X vh=%d\n",NOJAVA,
			mytype,IsMounted,ClientFlags&PF_AS_PROXY,IsVhost);
	}

	RX_errori = 0;
	RX_isText = 0;
	RX_isBin = 0;
	RX_rdHeadTotal = 0;
	RX_rdTotal = 0;
	RX_wrTotal = 0;
	RX_wrHeadTotal = 0;
	RX_wrbufed = 0;
	RX_FBI = 0;
	RX_putPRE = 0;
	clearPartfilter(&RX->r_partf);
	RX_isHTTP09 = 0;
	RX_lastMod = 0;
	RX_lastModTime = 0;
	RX_setCookie[0] = 0;
	RX_cachecontrol[0] = 0;
	RX_lastVia[0] = 0;

	RX_ctype[0] = 0;
	RX_connection[0] = 0;
	RX_expires[0] = 0;
	RX_cencoding[0] = 0;
	RX_servername[0] = 0;
	RX_tencoding[0] = 0;
	RX_rdContLen = 0;
	RX_rdContLenGot = 0;
	RX_xrdLen = 0;
	RX_txtLen = 0;
	RX_binLen = 0;
	RX_bodyLines = 0;
	RX_nflush = 0;
	RX_noutput = 0;
	RX_niced = 0;
	RX_respBuff = NULL;
	RX_guessCharset = 0;
	RX_discardResp = 0;

	if( 400 <= RX_code ){
		if( EccEnabled() ){
		    if( RX_code == 503 ){
		porting_dbg("-Ecc(%2d){%d}*%d ##RETRY on 503 resp. %s:%d",
			Conn->ccsv.ci_ix,Conn->ccsv.ci_id,Conn->ccsv.ci_reused,
				DST_HOST,DST_PORT);
		    }
		}
		HTTP_setRetry(Conn,req,RX_code);
	}
	if( Conn->sv_retry & SV_RETRY_DONE ){
		/* 9.7.7 the result of a retrial */
		Verbose("-- RETRY[%X] >>> (%d)\n",Conn->sv_retry,RX_code);
	}else
	if( Conn->sv_retry != 0 ){
		sv1log("ERROR (%d) to be RETRYed\n",RX_code);
		if( RESP_DoZIP ){
			/* 9.9.3 supp. gzip on retrial (maybe in diff. type) */
			sv1log("suppressed gzip=%d/%d/%d %d [%s]\n",
				RESP_DoZIP,RESP_DoUNZIP,RX_cencoded,
				RX_code,ctype
			);
			RESP_DoZIP = 0;
		}
		RX_tcp = NULLFP();
		RX_discardResp = 1;
		nullfp = RX_tcp;
		/* RX_tcp must not be fclose() ... */
	}else
	if( RX_code == 403 )
	{
		if( Conn->reject_reason[0] == 0 )
		sprintf(Conn->reject_reason,"%d %s",RX_code,RX_reason);
		HTTP_delayReject(Conn,req,line,0);
	}
	else
	if( RX_code == 204 ){
		RX_noBody = 1;
	}else
	if( RX_code == 404 )
	{
		if( isinFTPxHTTP(Conn) ){
			/* 9.9.8 ex. RETR for dir, CWD for file */ 
		}else
		if( streq(REQ_URL,"/favicon.ico") ){
			sv1log("DONT DELAY [%s]\n",REQ_URL);
		}else
		delayUnknown(Conn,DO_DELEGATE||IsMounted,OREQ);
	}

/* This will not work well when the client is DeleGate with cache
 * and  its cache is newer than the cache of this DeleGate.
 */
	if( RX_code == 304 ){
		int cacheOk;
		int forceBody;

		/*
		cacheOk = cacheReadOK(RX_cachefp);
		*/
		cacheOk = cacheReadOK(Conn,RX);
		sv1log("HTTP status: %d %s => %x/%d\n",
			RX_code,RX_reason,p2i(RX_cachefp),cacheOk);

		if( cacheOk ){
			/*
			ftouch(RX_cachefp,time(0));
			*/
			file_touch(fileno(RX_cachefp));
			forceBody = forceBodyResponse(Conn);
		}else{
			forceBody = 0;
			if( ClntIfMod[0] == 0 )
			sv1log("No-Cache to reuse\n");
		}

		if( RX_cachefp )
		if( ClntIfMod[0] && forceBody && CacheLastMod<=ClntIfModClock )
		{
			if( fgetsHF(RX_cachefp,"Content-Type",ctype) ){
				if( strncmp(ctype,"image/",6) == 0
				 || strncmp(ctype,"video/",6) == 0
				){
					forceBody = 0;
				}
			}
			if( forceBody == 0 )
			sv1log("don't replace 304 with 200 [%s]\n",ctype);
		}

		sv1log("sz=%d ok=%d fb=%d If[%x %x %x]\n",
			RX_cachefp?file_size(fileno(RX_cachefp)):-1,
			cacheOk,forceBody,
			ClntIfMod[0],CacheLastMod,ClntIfModClock);
		if( cacheOk == 0 ){
			/* there is No-Cache to reuse, never try "<=+= 304".
			 * 304 can be returned for non If-Mod. as If-None-Match
			 * then the following condition to thru. the 304 is
			 * not satisified, so relaying from the cache is tried
			 * anyway.  But (RX_cachefp != NULL) does not mean that
			 * the reusable cache exists.
			 */
			if( RX_cachefp ){
				RX_cachefp = NULL;
				DontTruncate = 5;
			}
		}else
		/*
		if( !forceBody && ClntIfNoneMatch[0] && streq(qETag,cETag) ){
		}else
		*/
		if( ClntIfMod[0] && !forceBody && CacheLastMod<=ClntIfModClock){
			Verbose("%d is relayed to the client.\n",RX_code);
			if( RX_cachefp ){
				Verbose("DontWriteCache 304 not modified.\n");
				/*fclose(RX_cachefp);*/
				RX_cachefp = NULL;
				DontTruncate = 2;
			}
		}else
		if( HTCFI_opts & HTCFI_THRU_304 ){
			sv1log("#### DONT <=+=304 %X fB=%d Ho=%X (%s)\n",
				p2i(RX_cachefp),forceBody,HTTP_opts,ClntIfMod);
			if( RX_cachefp ){
				RX_cachefp = NULL;
				DontTruncate = 9;
			}
		}else
		if( RX_cachefp ){
/*
 * 304 should be passed thru to the client if it is a delegated
 * with cache file which is very same with this delegated.
 */
			while( GETRESPTXT(Conn,RX,fromcache) != NULL ){
				int fnlen;
				if( *line == '\r' || *line == '\n' )
					break;
				if( fnlen = STRH_Connection(line) ){
					Verbose("HCKA:[R] %s",line);
					lineScan(line+fnlen,RX_connection);
				}
			}

			sv1log("HTTP <=+= %d [%s] %s",RespCode,RX_cpath,req);
			httpStat = CS_STABLE;
			DontTruncate = 3; /* 9.8.2 to avoid truncation in
				doTruncateCache() if httpStat != CS_STABLE */

			if( HTTP_opts & HTTP_OLDCACHE ){
			distFromCacheSetup(Conn,RX,RX_cpath,RX_cachefp);
			RX_code = relay_response(Conn,QX,0,proto,server,iport,req,
				RX_dcx.d_cpath,1,RX_dcx.d_fp,RX_tcp,NULL,NULL,1);
			distFromCacheDone(Conn,RX);
			}else{
				RX_code = relay_response(Conn,QX,0,
					proto,server,iport,req,
					RX_cpath,1,RX_cachefp,
					RX_tcp,NULL,NULL,1);

				if( RX_code == R_UNSATISFIED )
				if( (HTTP_cacheopt & CACHE_SHORT) == 0 ){
					foundBrokenCache(QX);
				}
			}

			setServKeepAlive(Conn,RX);
			return RX_code;
		}
		RX_noBody = 1;
		RX_lastMod = 1;
	}else{
		if( DontReadCache ){
			httpStatX = CS_RELOAD;
		}else
		if( RX_cachefp != NULL && cache_rdok )
			httpStat = CS_OBSOLETE;
	}

	if( RX_code == 1200 ){
		CStr(xline,64);

		RX_rdTotal = lastRcc;
		RX_isHTTP09 = 1;
		RX_inHeader = 0;

		if( strchr(line,'\n') )
			RX_isText = TX_HTML; /* HTML is assumed */

		XStrncpy(AVStr(xline),line,sizeof(xline)-8);
		if( strtailchr(xline) != '\n' )
			strcat(xline," ...\n");

		sv1log("No header (HTTP/0.9) : %s assumed : [%x][%x]%s",
			(RX_isText?"text":"binary"), xline[0],xline[1],xline);
	}else{
		RX_rdHeadTotal = lastRcc;
		switch( RX_code ){
		case 200:
		case 204:
		case 301:
		case 302: /* OK and cachable */
			break;
		case 303:
			if( vercmp(REQ_VER,"1.1") < 0 ){
				refQStr(dp,line); /**/
				sv1log("#HT11 303 resp. converted to 302\n");
				RX_code = 302;
				if( dp = strstr(line,"303") )
					Bcopy("302",dp,3);
			}
			break;
		case 304:
			break;
		case 305:
		case 306:
			break;
		case 206:
		case 207: /* WebDAV */
			if( RX_cachefp == NULL )
				break;
			sv1log("-- %d is NOT error but no-cache ...\n",RX_code);
		case 503:
			if( Conn->sv_retry == SV_RETRY_DO ){
				sv1log("HTTP retry: %d %s\n",RX_code,RX_reason);
				break;
			}
		default:
			if( RX_code != 404 )
			if( RX_code != 400 )
			if( lSINGLEP() ){
			fprintf(stderr,"-- %X HTTP error[%d][%d %s]%s:%d/%s",
				TID,afc?fileno(afc):-1,RX_code,RX_reason,
				DST_HOST,DST_PORT,req);
			}
			sv1log("HTTP error request: %s",req);
			sv1log("HTTP error status: %d %s\n",RX_code,RX_reason);
			RX_errori = -RX_code;
		}
	}

	setReferer(Conn,proto,server,iport,req,RX_referer,AVStr(refbuf));

	RX_convChar = CTX_cur_codeconvCL(Conn,VStrNULL) || CCXactive(CCX_TOCL);
	RX_deEnt = toProxy && protoGopher(DST_PROTO);

	if( (RX_code==305 || RX_code==306) && (ConnType=='p' || ConnType=='m') 
	 || (RX_code==401 || RX_code==407) && (HTTP_opts & HTTP_DOAUTHCONV)
	 || lDONTHT() && (400 <= RX_code) && NTHT_bufResp(Conn,RX)
	){
		RESP_SAV = 1;
		/* RX_tcp = NULLFPW(); */
		RX_tcp = TMPFILE("RESP_MSG");
		strcpy(RESP_MSG,line);
		RESP_LEN = strlen(line);
	}else{
		if( ConnType=='p' || ConnType=='m' || toProxy || toMaster )
		/* connected via an upstream proxy */
		if( RX_code==407 )
		/* auth. error from the upstream proxy */
		if( REQ_AUTH.i_stype == AUTH_APROXY )
		/* this proxy is authenticated with Proxy-Authorization */
		/* ... and if it is not forw. to the upstream proxy by %U:%P */
		{
			/* 9.7.0 don't relay hop-by-hop auth. error */
			refQStr(dp,line);
			if( dp = strstr(line,"407") )
				Bcopy("502",dp,3);
			sv1log("[%X P%d M%d / %d %d] %d converted to %d",
				ConnType,toProxy,toMaster,
				REQ_AUTH.i_stype,ClientAuth.i_stype,
				RX_code,502);
			RX_code = 502;
		}

		if( !RX_inHeader && RX_isText==TX_HTML ){
			RX_wrTotal += FPUTS(AVStr(line),"text/html",!RX_inHeader && RX_convChar,RX_deEnt);
		}else{
			if( lPEEPDGCL() ){
			    if( RX_inHeader ){
				dumpmsg(&RX_dumpDC,RX_fromcache?"C-T":"D-T",line);
			    }
			}
			if( RX_qWithHeader || !RX_inHeader )
			if( Conn->dg_putpart[0] && !RX_noBody ){
				/* v9.9.12 new-140819b, return 404 if no part.
				 * v9.9.12 fix-140823a, if the body exists.
				 */
				sv1log("#Pf part[%s] postpone status\n",Conn->dg_putpart);
			}else{
				RX_wrHeadTotal += fwrite(line,1,lastRcc,RX_tcp);
			}
		}

		if( !RX_isHTTP09 && RX_inHeader ){
			if( !ImResponseFilter )
			if( RX_qWithHeader )
				HTTP_putDeleGateHeader(Conn,RX_tcp,fromcache);
				/* also X-Request-XXX is echoed */
		}

		if( RX_cachefp ){
			fwrite(line,1,lastRcc,RX_cachefp);
			sendDistribution(Conn,RX_cachefp,RX_fsp,RX_tcp,line,lastRcc);
		}
	}


	if( !ClientEOF )
	if( 0 < DELEGATE_LINGER )
	if( lSINGLEP() ){
		set_linger(fileno(RX_tcp),SINGLEP_LINGER);
	}else
		set_linger(fileno(RX_tcp),DELEGATE_LINGER);
	if( fromcache )
		RX_fsd = -1;
	else	RX_fsd = fileno(RX_fsp);
	RX_tcd = fileno(RX_tcp);

	if( WillKeepAlive ){
		if( CKA_RemAlive <= 1 )
			clntClose(Conn,"f:finished lifetime");
		else
		if( lDONTHT()
		/*
		 && (RX_code == 401 || RX_code == 404)
		*/
		 && (RX_code == 401 || RX_code == 404 || RX_code == 407 )
		 && (withNTHT & (NTHT_REQ|NTHT_RES)) /* set in peeping */
		){
			sv1log("----NTHT KeepAlive for 401 (%d)\n",RX_errori);
		}else
		if( RX_errori != 0 )
			clntClose(Conn,"s:bad status: %d",RX_errori);
	}
	if( RX_noBody ){
		/* 9.8.2 no need to gunzip/gzip the empty body */
		if( RESP_DoUNZIP || RESP_DoZIP ){
			RESP_DoUNZIP = 0;
			RESP_DoZIP = 0;
		}
	}

	if( RX_noBody ){
		/* 9.8.2 no need to prepair the buff. for the empty body */
	}else
	if( Conn->dg_putpart[0] ){ /* v9.9.12 new-140819b */
		sv1log("#Pf DO-response-buffering for Partfilter\n");
		attach_respbuff(Conn,RX);
		fprintf(RX_respBuff,"%s",RX_rdBuff);
	}else
	if( (HTTP_opts & HTTP_ADDCONTLENG) ){
		sv1log("#ACLN DO-response-buffering to add Content-Length\n");
		attach_respbuff(Conn,RX);
	}else
	if( thruType ){
	}else
	if( lDONTHT() && RX_code == 401 && withNTHT ){
		sv1log("#HT11 DO-response-buffering for NTHT\n");
		attach_respbuff(Conn,RX);
	}else
	if( RX_code == 206 ){
		sv1log("#HT11 NO-response-buffering: 206 Partial\n");
	}else
	if( ServerFlags & PF_DO_RESPBUFF ){
		sv1log("#HT11 DO-response-buffering for Content-Length\n");
		attach_respbuff(Conn,RX);
	}else
	if( RESP_DoZIP
	 && (Conn->xf_filters&(XF_FTOCL))==0
	 && !ClientEOF
	 && !RX_noBody && !RX_isHTTP09 && RX_qWithHeader ){
		Verbose("#CEcl DO-response-buffering for Content-Encoding\n");
		attach_respbuff(Conn,RX);
	}else
	if( SWF_MOUNT ){
		Verbose("DO-response-buffering for SWF MOUNT\n");
		attach_respbuff(Conn,RX);
	}else
	if( 1 /* (HTTP_opts & HTTP_NOBUFF_FORCCX) */
	 && !isBin && CCXactive(CCX_TOCL)
	 && !ClientEOF
	 && !RX_noBody && !RX_isHTTP09 && RX_qWithHeader ){
		/* 9.5.1 to get and set appropriate charset in Content-Type
		 * header regardless if the client is with chunked or not
		 */
		sv1log("#HT11 {C} DO-response-buffering: for charset\n");
		attach_respbuff(Conn,RX);
		setFBI(Conn,RX,isBin);
	}else
	if( RX_tcx.t_chunked && !genHeadByBody(Conn,rhead) ){
		sv1log("#HT11 NO-response-buffering: chunked mode\n");
	}else
	if( !ClientEOF )
	if( !RX_noBody && !RX_isHTTP09 && RX_qWithHeader )
	if( withConversionX(Conn,0,RX_woURI)
	 || WillKeepAlive
	    && (!fromcache || fromcache && !HTTP_ContLengOkQX(RX_fsp,QX)) ){
	/*
	 || WillKeepAlive && (!fromcache || fromcache && !HTTP_ContLengOk(RX_fsp)) ){
	*/
		attach_respbuff(Conn,RX);
	}

	RX_lastFlush = Time();
	RX_inTakeOver = 0;
	RX_nsigreport = 0;
	nsigPIPE = 0;
	psigPIPE = 0;
	osigpipe = Vsignal(SIGPIPE,sigPIPE);
	Where = "header";

	for( RX_ninput = 0;;RX_ninput++ ){
	    QX_lastSent = Time();
	    if( !RX_inHeader && RX_noBody ){
		sv1log("#HT11 NO-BODY: remsize=%d\n",RX_remsize);
		break;
	    }
	    if( RX_fsx.t_EOF )
		break;
	    if( feof(RX_fsp) )
	    {
		RX_fsx.t_feof = 1;
		break;
	    }
	    if( nsigPIPE ){
		if( !ClientEOF )
			setClientEOF(Conn,RX_tcp,"relay_response.SIGPIPE");
		if( psigPIPE < nsigPIPE ){
			psigPIPE = nsigPIPE;
		if( RX_nsigreport++ % 100 == 0 ){
			sv1log(
"## (%d) SIGPIPE * %d: the recipient seems to be dead, Ctype:%s\n",
			RX_nsigreport,nsigPIPE, RX_ctype);
		}
		}
	    }
	    Now = Time();

	/*
	    if( !ClientEOF && RX_tcp == RX_respBuff && Next < Now ){
	*/
	    if( !ClientEOF )
	    if( RX_tcp == RX_respBuff /* 8.7.7 buffered locally */
	     || (Conn->xf_filtersCFI & XF_FTOCL) /* 9.8.2 buffered in the CFI */
	    )
	    if( Next < Now ){
		if( ClientSock < 0 && Conn->from_myself ){
			/* No client originally */
		}else
		if( 0 <= ClientSock && !IsAlive(ClientSock /*,NULL*/) ){
			setClientEOF(Conn,RX_tcp,"client-reset");
			setCLX("RB",CLX_DURING_RESP_BUFF);
		}
		Next = Now + 1;
	    }
	    if( ClientEOF && RX_cachefp == NULL ){
 sv1log("## stop relay-1: no recipient & no cache\n");
		setCLX("RR",CLX_DURING_RESP);
		break;
	    }
	    if( ClientEOF && RX_cachefp != NULL && CACHE_TAKEOVER ){
		if( (ClientFlags & PF_IS_DISTRIB)
		 && (ClientEOF & CLEOF_NOACTCL) == 0
		){
			/* I'm a Distributor with alive receiver(s) */
		}else
		if( CACHE_TAKEOVER < time(0) - RX_Start ){
			/* should be Time() - RX_Start */
			sv1log("CACHE_TAKEOVER: TIMEOUT=takeover:%d\n",
				ll2i(time(0)-(int)RX_Start));
			break;
		}
		else{
			RX_inTakeOver = RX_Start + CACHE_TAKEOVER;
			sv1log("CACHE_TAKEOVER: %d > %.3f (%.3f)\n",
				CACHE_TAKEOVER,Time()-RX_Start,
				RX_inTakeOver-Time());
		}
	    }

	    if( lSINGLEP() ){
	    }else
	    if( (ClientFlags & PF_IS_DISTRIB)||(ServerFlags & PF_IS_DISTRIB) ){
		/* 9.6.3 shuld be done in high priority */
	    }else
	    if( 10 < RX_ninput )
	    if( 8*1024 < RX_rdContLen - RX_rdTotal )
		RX_niced = doNice("HTTPresponse",Conn,RX_fsd,RX_fsp,RX_tcd,RX_tcp,
			RX_niced,RX_rdTotal,RX_ninput,RX_Resp1);

 	/*
 	 * stop buffering for Keep-Alive when the response data is large
 	 * or response speed is slow.
 	 */
	RX_fsx.t_nready = 0;

	flushSlowResponse(Conn,RX,fromcacheX);

	if( fromcacheX & RF_DECODED )
	if( RX_tcpissock )
	if( !ClientEOF )
	if( !RX_inHeader )
	if( (fromcacheX & RF_CACHED) == 0 )
	if( READYCC(RX_fsp) < 2*1024 )
	if( READYCC(RX_fsp) == 0
	 || RX_rdTotal < 4*1024 && 0.5 < Now-RX_Start
	 || RX_ninput < 50 && Now-RX_Start < 5.0 && 0.5 < Now-RX_lastFlush
	 || 1.0 < Now-RX_lastFlush
	){
		/* 9.8.2 flush resp. to smoothly relay slow (text) data and
		 * immediately show headlines of each page
		 */
		if( lZLIB() ) fprintf(stderr,
			"-- %4X %2d/%4d/%5d/%d %cT%d [%d]%d/%4d %5.2f %5.2f\n",
			TID,RX_ninput,lastRcc,(int)RX_rdTotal,(int)RX_rdContLen,
			RX_inHeader?'H':'B',RX_isText,
			fileno(RX_fsp),fPollIn(RX_fsp,1),ll2i(READYCC(RX_fsp)),
			Now-RX_lastFlush,Time()-RX_Start);

		if( fflushTIMEOUT(RX_tcp) == EOF ){
			setClientEOF(Conn,RX_tcp,"slow-resp");
		}
		RX_noutput++;
		RX_wrbufed = 0;
		RX_lastFlush = Time();
	}

	/*
	if( RX_fsx.t_nready < 0 ){
		sv1log("Polling server response failed, maybe EOF\n");
		break;
	}
	*/

	    if( !RX_inHeader && RX_fsx.t_chunked ){
		lastRcc = RX_fsx.t_lastRcc;
		if( RX_fsx.t_chunk_ser && 0 < lastRcc ){
			Verbose("#HT11 --getChunk[%d] data  : %d / %d / %d\n",
				RX_fsx.t_chunk_ser,lastRcc,
				RX_fsx.t_chunk_rem,RX_fsx.t_chunk_siz);

			RX_fsx.t_chunk_rem -= lastRcc;
			RX_remsize = RX_fsx.t_chunk_rem;
			if( sizeof(RX_rdBuff)-1 < RX_remsize )
				RX_remsize = sizeof(RX_rdBuff) -1;
		}
		if( RX_fsx.t_chunk_rem == 0 ){
			if( getChunk(RX) < 0 )
				break;
			RX_fsx.t_lastRcc = 0;
			continue;
		}
	    }else
	    if( !fromcacheX )
	    if( !RX_inHeader && RX_fsx.t_keepAlive && 0 < RX_rdContLen ){
		FileSize rem;
		rem = RX_rdContLen - RX_rdTotal;
		/*
		RX_remsize = RX_rdContLen - RX_rdTotal;
		if( sizeof(RX_rdBuff)-1 < RX_remsize )
		*/
		if( sizeof(RX_rdBuff)-1 < rem )
			RX_remsize = sizeof(RX_rdBuff)-1;
		else	RX_remsize = rem;
		HTR(2,"--Length=%lld = %lld + %d\n",RX_rdContLen,RX_rdTotal,
			RX_remsize);
		if( RX_rdContLen <= RX_rdTotal )
			break;
	    }
 
	/*
	    if( RX_inHeader || RX_isText ){
	*/
	    if( RX_inHeader || RX_isText && !asBin ){
		if( !RX_inHeader && RX_bodyLines == 0 ){
			RX_convChar = CTX_cur_codeconvCL(Conn,VStrNULL)
				   || CCXactive(CCX_TOCL);
			log_codeconv(Conn,RX);

			if( !ClientEOF && RX_putPRE == 1 ){
				RX_wrTotal += FPUTS(CVStr("\n<PRE>"),RX_ctype,
					RX_convChar,0);
				RX_putPRE = 2;
			}
		}
		if( !RX_inHeader && !fromcacheX && !ClientEOF
		 && RX_fsx.t_nready == 0 && (RX_fsx.t_nready = fPollIn(RX_fsp,200)) == 0 ){
			RX_noutput++;
			if( fflushTIMEOUT(RX_tcp) == EOF )
				setClientEOF(Conn,RX_tcp,"text flush-1");
			else
			if( RX_rdContLen == 0 && RX_tcp == RX_respBuff ){
				RX_tcp = detach_respbuff(Conn,RX_tcp,RX_tc_sav,
					RX_qWithHeader,"flush endless text.");
			}
		}

		if( igp ){
			if( *igp == 0 ){
				break;
			}
			igp = lineScan(igp,RX_rdBuff);
			if( *igp == '\r' ){ strcat(line,"\r"); igp++; }
			if( *igp == '\n' ){ strcat(line,"\n"); igp++; }
			if( *line != '\r' && *line != '\n' )
				sv1log("R++ %s",line);
		}else
		if( GETRESPTXT(Conn,RX,fromcacheX) == NULL ){
textEOF:
			if( !ClientEOF && !RX_inHeader )
			if( !RX_noBody )
			{
				setVStrEnd(line,0); /* could be target of rewriting */
				RX_wrTotal += FPUTS(AVStr(line),RX_ctype,RX_convChar,0);
			}
			break;
		}
		QX_lastRecv = Time();
		lastRcc = RX_fsx.t_lastRcc;

		if( RX_inHeader && (line[0] == '\r' || line[0] == '\n') )
		{
			if( gen_irhead == 0 )
			if( HTTP_genhead(Conn,TVStr(genf),KH_IN|KH_RES) ){
				gen_irhead = 1;
				igp = genf;
				strcat(genf,"\r\n");
				continue;
			}
/*
using rhead for charset guessing is not good when it is GZIPed
 */
			setSVCC(Conn,RX,rhead);
			endRespHead(Conn,RX);
		}
		if( HTTP_head2kill(line,KH_IN|KH_RES) ){
			sv1log("## HTTPCONF=kill-irhead:%s",line);
			continue;
		}

		if( !RX_inHeader && RX_isText && RX_isBin ){ /* RX_isBin is set in GETRESPTXT() */
			sv1log("non-text in text type%d resp.(%lld/%d)%d [%s]%s\n",RX_isText,RX_rdTotal,RX_ninput,RX_isBin,QX_site,REQ_URL);

			/*
			if( RX_isBin == 1
			*/
			if( RX_isBin <= 2
			 && RX_isText == TX_HTML
			 && (CCXactive(CCX_TOCL) || IsMounted || DO_DELEGATE)
			){
				sv1log("## allow '\\0' in HTML [%s]%s\n",
					QX_site,REQ_URL);
fprintf(stderr,"## allow '\\0' in HTML [%s]%s\n",QX_site,REQ_URL);
			}else{
			RX_errori = R_NONTEXT_INTEXT;
			rcc = lastRcc;
			Where = "binaryBody";
			RX_isText = 0;
			goto GOT_BINARY;
			}
		}

		/* let space in header be canonical ... */
		if( RX_inHeader ){
			refQStr(sp,line); /**/
			const char *dp;
			char ch,nch;
		    for( sp = line; ch = *sp; sp++ ){
		      if( ch == ':' ){
			nch = *++sp;
			if( nch == '\t' ){
				sv1log("##LWS replace: %s",line);
				nch = ' ';
				setVStrElem(sp,0,' ');
			}
			if( nch == ' ' ){
				for( dp = sp; dp[1]==' '||dp[1]=='\t'; dp++ );
				if( dp != sp ){
					sv1log("##LWS delete: %s",line);
					ovstrcpy((char*)sp+1,dp+1);
				}
			}else
			if( nch != '\r' && nch != '\n' ){
				sv1log("##LWS insert: %s",line);
				Strins(QVStr(sp,RX_rdBuff)," ");
			}
			break;
		    }
		  }
		}

		/* output to the cache should be
		 * before "FPUTS()" which may rewrite input line
		 * after "goto GOT_BINARY" to cache binary line with fwrite()
		 */
		if( RX_cachefp && !RX_isHTTP09 ){
			if( !(RX_inHeader && NoRelayField(Conn,RX,line)) )
			if( !(RX_inHeader && NoCacheField(Conn,RX,line)) ){ 
				fputs(line,RX_cachefp);
				sendDistribution(Conn,RX_cachefp,RX_fsp,RX_tcp,line,lastRcc);
				if( RX_fsx.t_chunked )
				if( ServerFlags & PF_IS_DISTRIB ){
			sv1log("#### receive from Distribution / no chunked\n");
					RX_fsx.t_chunked = 0;
				}
			}
			if( !RX_inHeader )
				RX_txtLen += lastRcc;
		}

		relayTxtResp1(Conn,RX,QX,req);
		if( RX_errori == R_BAD_MD5 ){
			break;
		}
		if( !RX_inHeader ){
			RX_rdTotal += lastRcc;
			RX_bodyLines += 1;

			if( RX_lastFlush == Now ){
				/* flushed already in this cycle */
			}else
			/* don't cause automatic flush at
			 * non line boundary.  */
			if( OBUFSIZE <= RX_wrbufed+lastRcc
			|| !fromcacheX && READYCC(RX_fsp) == 0 ){ 
				if( RX_tcx.t_chunked ){
					/* flushing before the last chunk "0"
					 * is halmful for NS6.X
					 */
				}else
				if( !ClientEOF && fflushTIMEOUT(RX_tcp) == EOF )
					setClientEOF(Conn,RX_tcp,"text flush-2");
				RX_noutput++;
				RX_wrbufed = lastRcc;
				RX_lastFlush = Time();
			}else{
				RX_wrbufed += lastRcc;
				/* should be length of converted string. */
			}
		}

		if( RX_inHeader ){
			RX_rdHeadTotal += lastRcc;
			scanRespHead1(Conn,RX,line);
			if( !RX_inHeader ){

 sv1log(
 "%s %d Content-{Type:%s Encoding:[%s/%s] Leng:%lld} KA:%d/%d Server:%s\n",
 RX_ver,RX_code,RX_ctype,RX_cencoding,RX_tencoding,RX_rdContLen,
 ServKeepAlive,RX_fsx.t_keepAlive,
 RX_servername);
				if( QX_hcode == 304 && RX_rdContLenGot ){
					/* 9.9.5 bad for Safari */
					porting_dbg("#HT warning 304 with Cont-Leng Server:%s %s://%s:%d",
						RX_servername,DST_PROTO,DST_HOST,DST_PORT);
				}
				if( lDONTHT() ){
					NTHT_endHead(Conn,RX);
				}

				if( RX_emptyBody && RX_fsx.t_keepAlive )
				if( RX_tencoding[0] == 0 )
				if( READYCC(RX_fsp) == 0 ){
					break;
				}

				if( !RX_noBody )
				if( modwatch_enable )
				if( modwatchHead(Conn,RX) != 0 )
					break;

				Where = "headerFlush";
				if( !ClientEOF && RX_tcp != RX_respBuff )
					flushHead(Conn,RX_tcp,RX_rdContLen);
				RX_noutput++;

				if( RX_reqHEAD )
					break;

				if( RX_isText )
					Where = "textBody";
				else	Where = "binaryBody";

				switch( RX_isText ){
				   case TX_CSS:
					refererb.r_cType = "text/css";
					break;
				   case TX_XML:
					refererb.r_cType = "text/xml";
					break;
				   case TX_JAVASCRIPT:
					refererb.r_cType = "text/javascript";
					break;
				}

				if( RX_cencoding[0] )
				if( RESP_DoUNZIP ){
					if( threadGunzip(Conn,RX) ){
RX_xrdLen = 0x7FFFFFFF; /* is this necessary ? */
						RX_fsx.t_keepAlive = 0;
						RX_fsx.t_chunked = 0;
						fromcacheX |= RF_DECODED;
						RX_didUnzip =
						didUnzip = 1;
					}else{
/*
				  if( RX_fsx.t_keepAlive || RX_fsx.t_chunked ){
*/
					FILE *tmp;
					tmp = TMPFILE("recvHTTPbody");
					recvHTTPbody(Conn,RX,tmp);
					if( ClientEOF ){
						fclose(tmp);
						break;
					}
					fflush(tmp);
					fseek(tmp,0,0);
					tmp_fsp = Gunzip(RX_cencoding,tmp);
					if( tmp_fsp != tmp )
						fclose(tmp);
				  	RX_fsp = tmp_fsp;
					RX_xrdLen = file_size(fileno(RX_fsp));
					RX_fsx.t_keepAlive = 0;
					RX_fsx.t_chunked = 0;
					RX_didUnzip =
					didUnzip = 2;
/*
				  }else{
					tmp_fsp = Gunzip(RX_cencoding,RX_fsp);
					if( tmp_fsp == RX_fsp )
						tmp_fsp = 0;
				  	else	RX_fsp = tmp_fsp;
				  }
*/
				  if( RX_fsp == tmp_fsp ){
				  /* 8.1.0: probably be intended to disable
				   * flushSlowResponse -> detach_respbuff
				   * to adjust Content-Length
				   */
					fromcacheX |= RF_DECODED;
					/*
					resetSVCC(Conn,RX,tmp_fsp,rhead);
					*/
				  }
					}
				}
				if( isText ){
					if( strcaseeq(RX_cencoding,"gzip") )
					if( RX_xrdLen == 0 )
					{
				Verbose("relaying [%s]encoded text as bin.\n",
					RX_cencoding);
						asBin = 1;
					}
				}

				if( HTTP_opts & HTTP_SUPPCHUNKED )
				if( RX_tcx.t_chunked && !WillKeepAlive ){
				sv1log("#HT11 less-chunked / non-KeepAlive\n");
					RX_tcx.t_chunked = 0;
				}
/*
if( RX_isText == TX_XML ){
fprintf(stderr,"XML %s\r\n",REQ_URL);
fprintf(RX_tcp,"<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n");
}
*/
			}
		}
		if( RX_rdContLen+0x100000 < RX_txtLen ){
			if( RX_tcp == RX_respBuff ){
				RX_tcp = detach_respbuff(Conn,RX_tcp,RX_tc_sav,
					RX_qWithHeader,"huge data");
			}
			if( RX_cachefp ){
				sv1log("discard cache: leng=%lld/%lld %s\n",RX_txtLen,RX_rdContLen,RX_cpath);
				Ftruncate(RX_cachefp,0,0);
				fseek(RX_cachefp,0,0);
				RX_cachefp = NULL;
			}
		}
	    }else{
		if( RX_tcp == RX_respBuff && !WillKeepAlive ){
			RX_tcp = detach_respbuff(Conn,RX_tcp,RX_tc_sav,
				RX_qWithHeader,"non-text data, non keep-alive");
		}
		rcc = GETRESPBIN(Conn,RX,fromcacheX,RX_fsx.t_nready);
		QX_lastRecv = Time();
GOT_BINARY:
		if( relayBinResp1(Conn,RX,rcc) < 0 )
		{
			break;
		}
	    }
	}
	if( ClientEOF && ImResponseFilter ){
Verbose("+++EPIPE ImRespFilter SIG*%d [%d/%X]\n",gotSIGPIPE(),fileno(RX_tcp),p2i(RX_tcp));
		dupclosed(fileno(RX_fsp));
	}
	if( Anchor_rem[0] ){
		putChunk(RX,Anchor_rem,strlen(Anchor_rem));
		setVStrEnd(Anchor_rem,0);
	}

	if( !RX_noBody ){
		putChunk(RX,"",0);
		Where = "bodyFlush";

		/* 3.0.56: removal of cache of inconsistent length shold be
		 * tried anytime except when it is read from cache incompletely
		 * where rdTotal does not show the length of the content
		if( !(fromcache && ClientEOF) )
		 */
		if( !fromcache /* not reading from cache */
		 || !ClientEOF /* or read cache completely */
		)
		if( RX_rdTotal < RX_rdContLen )
		if( RESP_DoUNZIP && RX_didUnzip && feof(RX_fsp) && !ClientEOF ){
			/* 9.9.3 maybe image/* in gzip */
		sv1log("## ContLeng:%d<%d [%s] unzip=%d,%d CA%d sE%d cE%d\n",
				(int)RX_rdTotal,(int)RX_rdContLen,RX_ctype,
				RESP_DoUNZIP,RX_didUnzip,
				RX_fromcache,feof(RX_fsp),ClientEOF
			);
		}else
		{
			if( RX_cachefp )
			if( ClientEOF ) /* broken by client's reset */
			if( (HTTP_cacheopt & CACHE_SHORT) == 0 ){
				/* 9.7.8 erase incomplete cache by EPIPE */
				fflush(RX_cachefp);
				Ftruncate(RX_cachefp,0,0);
				fseek(RX_cachefp,0,0);
				sv1log("## Discard Truncated (%d / %d)\n",
					(int)RX_rdTotal,(int)RX_rdContLen);
			}
			RX_errori = R_UNSATISFIED;
		}

		if( !ClientEOF ){
			if( RX_putPRE == 2 ){
			RX_wrTotal += FPUTS(CVStr("</PRE>\n"),RX_ctype,RX_convChar,0);
			}
		}
	}

	if(  Conn->dg_putpart[0] ){ /* v9.9.12 new-140819b */
	  if( RX_tcp == RX_respBuff ){
	    if( Conn,RX->r_partf.p_NumParts == 0 ){
		IStr(uquery,URLSZ);

		strcpy(uquery,Conn->dg_putpart);
		if( strpbrk(uquery,"<>&\"") )
			URL_reescape(Conn->dg_putpart,AVStr(uquery),0,1);
		daemonlog("E","#Pf part[%s] not found\n",Conn->dg_putpart);
		fseek(RX_tcp,0,0);
		fprintf(RX_tcp,"HTTP/1.0 404 Part Not Found\r\n");
		fprintf(RX_tcp,"\r\n");
		fprintf(RX_tcp,"## NO SUCH PART ?%s\n",uquery);
		QX_hcode = 404;
	    }else{
		sv1log("#Pf part[%s] found, size=%d parts=%d\n",
			Conn->dg_putpart,ftell(RX_tcp),RX->r_partf.p_NumParts);
	    }
	  }
	}

	RX_wrContLen = RX_rdContLen;
	if( RX_tcp == RX_respBuff )
	{
		Where = "finishRespbuf";
		if( SWF_MOUNT ){
			FILE *tmp;
			tmp = TMPFILE("SWF");
			fflush(RX_tcp);
			fseek(RX_tcp,0,0);
			{
				CStr(line,1024);
				while( fgets(line,sizeof(line),RX_tcp) ){
					fputs(line,tmp);
					if( *line == '\r' || *line == '\n' )
						break;
				}
			}
			swfFilter(Conn,RX_tcp,tmp,"");
			fflush(tmp);
			fclose(RX_tcp);
			RX_tcp = tmp;
		}
		releaseRespbuf(Conn,RX);
	}

	if( RX_errori == R_NONTEXT_INTEXT )
		if( RX_rdTotal == RX_rdContLen )
			RX_errori = 0;

	if( WillKeepAlive )
		abortKeepAlive(Conn,RX);

	if( RX->r_fsx.t_tid || RX->r_tcx.t_tid ){
		Where = "finishThreads";
		te1 = te2 = 0;
		if( RX->r_fsx.t_tid ){
			if( RX_fsp != afs ){
				/* necessary to avoid SIGSUSP in gunzip() */
				while( 0 < fPollIn(RX_fsp,1) ){
					CStr(buf,1024);
					int rcc;
					rcc = fread(buf,1,sizeof(buf),RX_fsp);
					if( rcc <= 0 )
						break;
				}
			}
			/* this may cause freezing in SIGSUSP */
			if( ClientEOF ){
Verbose("+++EPIPE FSV xfclose SIG*%d [%X/%d] an=%d/%d\n",gotSIGPIPE(),p2i(RX_fsp),fileno(RX_fsp),actthreads(),numthreads());
				dupclosed(fileno(RX_fsp));
				dupclosed(fileno(RX_tcp));
			}
			te1 = thread_wait(RX->r_fsx.t_tid,30*1000);
			if( RX_fsp != afs ){
				fclose(RX_fsp);
			}
		}
		if( RX->r_tcx.t_tid ){
			if( ClientEOF && actthreads() ){
				double Lt = Time();
int tcfd = fileno(RX_tcp);
Verbose("+++EPIPE x xfclose SIG*%d [%X/%d] an=%d/%d\n",gotSIGPIPE(),p2i(RX_tcp),tcfd,actthreads(),numthreads());
				dupclosed(fileno(RX_tcp));
				te2 = thread_wait(RX->r_tcx.t_tid,30*1000);
Verbose("+++EPIPE y xfclose SIG*%d [%X/%d] an=%d/%d\n",gotSIGPIPE(),p2i(RX_tcp),tcfd,actthreads(),numthreads());
				fcloseTIMEOUT(RX_tcp);
				RX_tcp = atc;
Verbose("+++EPIPE z xfclose SIG*%d %d/%d [%X/%d] %X/%d %.3f\n",gotSIGPIPE(),actthreads(),numthreads(),p2i(RX_tcp),tcfd,p2i(atc),fileno(atc),Time()-Lt);
			}else{
			fclose(RX_tcp);
			RX_tcp = atc;
			te2 = thread_wait(RX->r_tcx.t_tid,30*1000);
			}
		}
	}
	fcloses();
	svIncomplete(Conn,QX,RX);
	removeTruncated(Conn,QX,RX);

	if( file_isreg(fileno(RX_tcp)) ){
		sv1log("DON'T CLOSE RESPONSE:(%d) %s\n",
			reqRobotsTxt(Conn),REQ_URL);
		stx = "isREG";
	}else
	if( RX_tcp == nullfp ){
		/* 9.9.2 */
		porting_dbg("DON'T CLOSE NULLFP:%X %s",p2i(nullfp),REQ_URL);
		stx = "isNULLFP";
	}else
	if( RESP_SAV )
	{
		fclose(RX_tcp);
		stx = "inSAV";
	}
	else
	if( checkClientEOF(Conn,RX_tcp,"flush_body") ){
		httpStat = CS_EOF;
		stx = "clntEOF";
		sv1log("{F} SET checkClientEOF[%d][%d][%d] flush_body\n",
			fileno(RX_tcp),ToC,ClientSock);
		if( EccEnabled() ){
			int id,fd,al,ok;
			/* 9.9.4 */
			id = Conn->ccsv.ci_id;
			fd = fileno(afs);
			al = IsAlive(fd);
			ok = destroyCCSV("flush_body",Conn,fd);
			porting_dbg("-Ecc(%2d){%d}*%d ## EOS on flush_body [%d]%d,%d %s:%d",
				Conn->ccsv.ci_ix,id,Conn->ccsv.ci_reused,
				fd,al,ok,DST_HOST,DST_PORT);
		}
	}else{
		Verbose("HTTP RESPONSE FLUSH: DO (HCKA=%d)\n",WillKeepAlive);
		if( WillKeepAlive ){
			fflushKeepAlive(Conn,"flush_response",
				afc,RX_tcp,RX_wrHeadTotal+RX_wrTotal);
			if( nsigPIPE || ClientEOF )
				clntClose(Conn,"p:premature EOF on flush");
			if( nsigPIPE && !ClientEOF )
				setClientEOF(Conn,RX_tcp,"flush_response.SIGPIPE");
			if( ClientEOF )
			{
				httpStat = CS_EOF;
				stx = "stopKA";
			}else{
				stx = "contKA";
			}
		}else{
			tcCLOSED = 1;
			if( tmp_fsp
			 || (Conn->xf_filters & XF_FTOCL)
			 || (Conn->xf_clprocs & XF_FTOCL)
			){
				/* force shutdown() to avoid system() for
				 * filter program from keeping the client-side
				 * socket open after finished on Win32
				 */
				fshutdown(RX_tcp,1);
				stx = "noKAwithFTOCL";
			}else
			{
			fshutdown(RX_tcp,0);
				stx = "noKAnoFTOCL";
			}

			if( lFILEDESC() ){
				sv1log("{F} >>[%d]-[%d] relay_response (%s)\n",
					fileno(RX_tcp),ClientSock,stx);
			}
			if( isWindowsCE() || lMULTIST() ){
				fcloseFILE(RX_tcp);
			}else
			{
				int tcd = fileno(RX_tcp);
				if( fcloseTIMEOUT(RX_tcp) == EOF ){
					httpStat = CS_EOF;
				}
				closed("relayResp",tcd,-1);
			}
			setClientEOF(Conn,0,NULL);

			/*
			if( fcloseTIMEOUT(RX_tcp) == EOF )
				httpStat = CS_EOF;
			setClientEOF(Conn,RX_tcp,NULL);
			 */
		}
	}
	if( RX->r_fsx.t_tid || RX->r_tcx.t_tid ){
thfprintf(stderr,"--HZT --DONE --%s-- Thread fsx:%X/%d tcx:%X/%d %d/%d[%s]\n",
stx,RX->r_fsx.t_tid,te1,RX->r_tcx.t_tid,te2,
(int)RX_rdTotal,(int)RX_wrTotal,RX_ctype);
	}

	if( RX_cachefp )
		fflush(RX_cachefp);

	Vsignal(SIGPIPE,osigpipe);

	http_log(Conn,proto,server,iport,req,RX_code,RX_ctype,RX_rdTotal,
		RX_lastModTime,CONN_DONE-CONN_START,Time()-CONN_DONE);

/*
sprintf(line,"HTTP transmitted: %dhead+%lld/%lldbody=>%lldtxt+%lldbin->%lld/%lld, %di/%do/%df/%3.1f %c%c%c%c%c",
*/
	strcpy(line,"HTTP transmitted: ");
	Xsprintf(TVStr(line),"%dhead+%lld/%lldbody=>%lldtxt+%lldbin->%lld/%lld",
		RX_rdHeadTotal,RX_rdTotal,RX_rdContLen,
		RX_txtLen,RX_binLen,
		RX_wrTotal,RX_wrContLen,
		0
	);
	Xsprintf(TVStr(line),", %di/%do/%df/%3.1f %c%c%c%c%c",
		RX_ninput,RX_noutput,RX_nflush,
		Time()-RX_Start,
		RX->r_fsx.t_chunked?'C':'-',
		didUnzip?'Z':'-',
		RX->r_tcx.t_chunked?'c':'-',
		RESP_DoZIP?'z':'-',
		pipelined?'p':'-'
	);
 	sv1log("%s\n",line);

	if( lTRANSMIT() || 5 < Time()-RX_Start ){
		extern int CHILD_SERNO_MULTI;
		IStr(procid,64);
		IStr(tstamp,128);
		static int xn;
		xn++;
		if( !lSINGLEP() ){
			sprintf(procid,"[%u][%u]",getppid(),getpid());
		}
		sprintf(tstamp,"%s[%04X] %3d %.2f #%d %d/%d",
			procid,TID,xn,Time()-RX_Start,
			CHILD_SERNO_MULTI,REQUEST_SERNO,SERVREQ_SERNO);

		fprintf(stderr,
			"%s %c%c [%d] %c%c%d %d %c%c %x%c[%s] %d/%d %s\n",
			tstamp,
			ClntKeepAlive?'k':'-',RX_fsx.t_keepAlive?'K':'-',
			ToS,
			(fromcache?'H':RX_cachefpSav?'S':'-'),
			0<ClntIfModClock?'i':'-',HttpReload,
			RX_code,RX_didUnzip?'Z':'-',RX_didZip?'z':'-',
			RX_isText,RX_isBin?'B':'-',RX_ctype,
			(int)RX_wrTotal,(int)RX_rdTotal,
			DST_HOST
		);
		fflush(stderr);
	}

	if( withCookie || *RX_setCookie )
		logCookie(Conn,RX,RX_setCookie);

	if( tmp_fsp ){
		fclose(tmp_fsp);
	}

	Where = "finishResponse";
	if( RX_errori == R_UNSATISFIED )
		return RX_errori;

	if( RX_cachecontrol[0] ){
		if( (HTTP_cacheopt & CACHE_NOCACHE) == 0 )
		if( strheadstrX(RX_cachecontrol,"no-cache",1) ){
			QX_cacheRemove = 1;
		}
	}
	if( RX_lastMod == 0 ){
		if( RX_code == 302 ){
			/* relatively shorter expire time is desired ? */
		}else{
			Verbose("No Last-Modified:\n");
#ifndef CACHE_NOLM
			return R_GENERATED;
#endif
		}
	}

	return RX_errori;
}

static int HTTP_relayCachedHeader(Connection *Conn,FILE *cache,FILE *tc,HttpResponse *resx)
{	CStr(line,1024);
	CStr(buff,1024);
	int lines;
	int total;

	total = 0;
	for(lines = 0;;lines++){
		if( fgets(line,sizeof(line),cache) == NULL )
			break;
		if( lines == 0 ){
			if( strncasecmp(line,F_HTTPVER,F_HTTPVERLEN) == 0 ){
				decomp_http_status(line,resx);
				continue;
			}
		}
		if( strncasecmp(line,"Date:",5) == 0 ){
			StrftimeGMT(AVStr(buff),sizeof(buff),TIMEFORM_RFC822,time(0),0);
			replaceFieldValue(AVStr(line),"Date",buff);
		}
		else
		if( strncasecmp(line,"Content-",8) == 0 ){
			if( strncasecmp(line,"Content-Location",16) != 0 )
				continue;
		}

		if( line[0] == '\r' || line[0] == '\n' )
		{
			buff[0] = 0;
			appendVia(Conn,0,AVStr(buff),sizeof(buff));
			fputs(buff,tc);
			total += strlen(buff);
			total += putKeepAlive(Conn,tc);
		}

		total += strlen(line);
		fputs(line,tc);
		if( line[0] == '\r' || line[0] == '\n' )
			break;
	}
	return total;
}
int disableWinCtrl(FILE *fp);
static int relay_response_fromCache(Connection *Conn,QueryContext *QX,PCStr(proto),PCStr(server),int iport,PCStr(req),PCStr(cpath),FILE *cachefp,FILE *tc,FILE *fc)
{	int rcode;
	int mycache;
	CStr(scdate,256);
	int rtotal;
	HttpResponse resx;

	httpStat = CS_HITCACHE;
	ConnType = 'c';

	if( reqRobotsTxt(Conn) ){
		rtotal = putRobotsTxt(Conn,tc,cachefp,1);
		http_log(Conn,proto,server,iport,req,200,"text/plain",rtotal,0,
			-1.0,Time()-CONN_DONE);
		return 0;
	}

	if( 0 < ClntIfModClock && !forceBodyResponse(Conn) ){
		mycache = HTTP_getLastMod(AVStr(scdate),sizeof(scdate),cachefp,cpath);
		if( mycache <= ClntIfModClock ){
			CStr(ctype,128);

			/* dont send the same or older resource */
			fprintf(tc,"HTTP/1.0 304 Not Modified (cached)\r\n");
			rtotal = HTTP_relayCachedHeader(Conn,cachefp,tc,&resx);
			flushHead(Conn,tc,0);
			sv1log("HTTP <=S= %d [%s] %s",resx.hr_rcode,cpath,req);

			ctype[0] = 0;
			http_log(Conn,proto,server,iport,req,304,ctype,rtotal,0,
				-1.0,Time()-CONN_DONE);
			return 0;
		}
	}
	disableWinCtrl(tc);
	rcode = relay_response(Conn,QX,0,proto,server,iport,req,cpath,1,
		cachefp,tc,fc,NULL,1);

	sv1log("HTTP <=-= %d [%s] %s",RespCode,cpath,req);

	if( rcode < 0 || /*rcode == 304 ||*/ RespCode == 304 ){
		if( rcode==R_GENERATED && (HTTP_cacheopt&CACHE_NOLASTMOD)
		){
		}
		else
		if( rcode==R_UNSATISFIED && (HTTP_cacheopt & CACHE_SHORT) ){
			sv1log("## leave truncated(%s) Rd\n",cpath);
		}else{
			int ucode;
		sv1log("----------- UNLINK:%d:%d:%s\n",rcode,RespCode,cpath);
		ucode =
		unlink(cpath);
			if( ucode != 0 ){
				sv1log("postponed unlink(%s)\n",cpath);
				QX_cacheRemove = R_BAD_FORMAT;
			}
		}
		return rcode;
	}
	if( /*rcode == 304*/ RespCode == 304 ){
		sv1log("ERROR  304 Not modified messages was cached?\n");
		return 304;
	}
	return 0;
}


/*###################################### REQUEST */
static void editRequestHeader(Connection *Conn,FILE *fs)
{
}
static int HTTP_repairRequest(PVStr(req))
{	int nsp,repaired;
	CStr(xreq,URLSZ);
	refQStr(dp,xreq); /**/
	const char *xp = &xreq[sizeof(xreq)-1];
	const char *sp;
	char sc;

	nsp = 0;
	repaired = 0;
	for( sp = req; sc = *sp; sp++ ){
		if( xp <= dp+3 )
			break;
		if( sc == ' ' || sc == '\t' ){
			nsp++;
			if( 2 <= nsp && strncmp(sp+1,F_HTTPVER,F_HTTPVERLEN) != 0 ){
				sprintf(dp,"%%%02x",sc);
				dp += strlen(dp);
				repaired++;
				continue;
			}
		}
		setVStrPtrInc(dp,sc);
	}
	setVStrEnd(dp,0);
	if( repaired ){
		strcpy(req,xreq);
		sv1log("REQUEST REPAIRED: %s",xreq);
	}
	return repaired;
}

#define SPorHT(ch)	(ch == ' ' || ch == '\t')
#define CRorLF(ch)	(ch == '\r' || ch == '\n')
static const char *fgets822FromC(Connection *Conn,PVStr(buff),int size,FILE *fc,int normalize)
{	const char *rcode;
	const char *rcode1;
	refQStr(bp,buff); /**/
	const char *hp;
	int rsize,ch;

	rcode = 0;
	rsize = size;
	while( 1 < rsize ){
		rcode1 = DDI_fgetsFromC(Conn,QVStr(bp,buff),rsize,fc);
		if( bp == buff )
			rcode = rcode1;
		if( rcode == NULL || !normalize )
			break;
		ch = buff[0];
		if( CRorLF(ch) )
			break;

		if( bp != buff && normalize ){
			for( hp = bp; ch = *hp; hp++ )
				if( !SPorHT(ch) )
					break;
			if( hp != bp + 1 ){
				sv1log("##HHu reduce leading spaces<<%s",bp);
				Xstrcpy(QVStr(bp+1,buff),hp);
				Normalized++;
			}
		}
		if( strtailchr(bp) != '\n' )
			break;
		ch = DDI_peekcFromC(Conn,fc);
		if( ch == EOF )
			break;
		if( !SPorHT(ch) )
			break;

		sv1log("##HHu unfold header<<%s",bp);
		hp = bp;
		for( bp += strlen(bp) - 1; buff < bp; bp-- ){
			ch = *bp;
			if( normalize && SPorHT(ch) ){
				sv1log("##HHu reduce trail spaces<<%s<<\n",hp);
				setVStrEnd(bp,0);
			}else
			if( !CRorLF(ch) ){
				bp++;
				break;
			}
		}
		rsize = size - (bp - buff); 
		Normalized++;
	}
	return rcode;
}
/*
 * this function will not detect nor fix multiple anomaly in a line ...
 */
static void check_header(Connection *Conn,PVStr(head))
{	char ch;
	refQStr(wp,head); /**/
	const char *hp;
	CStr(tmp,URLSZ);
	int nctl,nbin,leng;
	int bad = 0;

	nctl = 0;
	nbin = 0;
	for( hp = head; ch = *hp; hp++ ){
		if( ch & 0x80 )
			nbin++;
		else
		if( ch < 0x20 && ch != '\t' && ch != '\r' &&  ch != '\n' )
			nctl++;
	}
	leng = hp - head;
	/*
	if( nctl || nbin || 256 < leng ){
	*/
	if( nctl || nbin || HTTP_WARN_REQLINE <= leng ){
		strfConnX(Conn,"%h",AVStr(tmp),sizeof(tmp));
		daemonlog("F",
		"Suspicious HTTP header [%s][CTL=%d,BIN=%d,LEN=%d] %s\n",
			tmp,nctl,nbin,ll2i(hp-head),head);
	}

	for( hp = &head[leng]; head+1 < hp && CRorLF(hp[-1]); hp-- );
	if( head+1 < hp && CRorLF(*hp) ){
		wp = (char*)hp - 1;
		if( SPorHT(*wp) ){
			for( ; head+1 < wp && SPorHT(wp[-1]); wp-- );
			sv1log("##HHn remove space before CRLF<<%s",head);
			ovstrcpy((char*)wp,hp);
		}
	}

	ch = head[0];
	if( CRorLF(ch) ){
		/* End of header */
	}else
	if( SPorHT(ch) ){
		sv1log("##HHe bad space at the top of header<<%s",head);
		bad =
		BadRequest = 1;
	}else
	if( ch == ':' ){
		sv1log("##HHe empty field-name<<%s",head);
		bad =
		BadRequest = 2;
	}else{
	  for( hp = head; ch = *hp; hp++ ){
	    if( ch == ':' ){
		wp = (char*)++hp;
		while( SPorHT(*hp) )
			hp++;
		if( *hp == '\r' || *hp == '\n' ){
			/* empty body */
		}else
		if( hp == wp ){
			sv1log("##HHn insert space after ':'<<%s",head);
			strcpy(tmp,hp);
			sprintf(wp," %s",tmp);
			Normalized++;
		}else
		if( hp != wp + 1 ){
			sv1log("##HHn reduce space after ':'<<%s",head);
			ovstrcpy((char*)wp+1,hp);
			Normalized++;
		}
		break;
	    }
	    if( CRorLF(ch) ){
		sv1log("##HHe lacking ':field-value'<<%s",head);
		bad =
		BadRequest = 3;
		break;
	    }
	    if( SPorHT(ch) ){
		wp = (char*)hp;
		while( ch = *++hp )
			if( !SPorHT(ch) )
				break;
		if( ch == ':' ){
			sv1log("##HHn remove space before ':'<<%s",head);
			ovstrcpy((char*)wp,hp);
			Normalized++;
		}else{
			sv1log("##HHe multi-tokens as a field-name<<%s",head);
			bad =
			BadRequest = 4;
		}
		break;
	    }
	  }
	}

	if( bad && !HTTP_rejectBadHeader ){
		sv1log("##HHn remove bad-header<<%s",head);
		setVStrEnd(head,0);
	}
}

#include <ctype.h>
static void escape_request(Connection *Conn,PVStr(request),int size)
{	refQStr(hostport,request); /**/
	const char *hp;
	MrefQStr(dp,OREQ_MSG); /**/
	const char *xp = &OREQ_MSG[sizeof(OREQ_MSG)-1];
	unsigned char hc;
	int encode;
	refQStr(up,request); /**/

	if( HTTP_urlesc )
	if( up = strchr(request,' ') ){
		up++;
		url_unescape(AVStr(up),AVStr(up),size,HTTP_urlesc);
		encode = url_escapeX(up,AVStr(up),size,HTTP_urlesc," \t\r\n");
	}

	hostport = strstr(request,"://");
	if( hostport == NULL )
		return;

	hostport += 3; 
	encode = 0;
	for( hp = hostport; hc = *hp; hp++ ){
		if( xp <= dp+3 )
			break;
		if( hc == 0 || hc == ' ' || hc == '\r' || hc == '\n'
		 || hc == '/' || hc == '?' )
			break;
		if( isalnum(hc) || hc == '-' || hc == '.' || hc == ':'
		 || hc == '@' || hc == '%' || strchr("$_!~*'(),;&=+#",hc) ){
			setVStrPtrInc(dp,hc);
		}else{
			encode = 1;
			sprintf(dp,"%%%02x",hc);
			dp += 3;
		}
	}
	if( encode == 0 )
		return;
	strcpy(dp,hp); /* OREQ_MSG is terminated here */
	strcpy(hostport,OREQ_MSG);
	sv1log("## pre-escape request with URL including unsafe char.\n");
}

static const char *fgetsRequestX(Connection *Conn,QueryContext *QX,PVStr(buff),int size,FILE *fc,int normalize)
{	const char *rcode;
	int len;

	if( 0 < OREQ_LEN )
	if( 30 < IO_TIMEOUT )
	if( WillKeepAlive )
	if( strncasecmp(OREQ_MSG,"POST",4) == 0 )
	{
		/* Mozilla/3.? stops sending in the middle of a POST
		 * request header after the connection is broken which
		 * is notified as Proxy-Connection: keep-alive ...
		 */
		int timeout;
		timeout = 5 * 1000;
		if( DDI_PollIn(Conn,fc,timeout) <= 0 ){
			sv1log("#### fgetsRequest: TIMEOUT\n");
			return NULL;
		}
	}

	rcode = fgets822FromC(Conn,AVStr(buff),size,fc,normalize);

	if( rcode != NULL ){
		refQStr(dp,buff); /**/
		if( lPEEPCLDG() ){
			dumpmsg(&QX_dumpCD,"T-D",buff);
		}
		dp = strtail(buff);
		if( *dp == '\n' ){
			if( dp == buff || dp[-1] != '\r' ){
				sv1log("##HHn replaced LF to CRLF: %s",buff);
				strcpy(dp,"\r\n");
			}
		}
	}

	if( rcode != NULL && OREQ_LEN == 0 )
		escape_request(Conn,AVStr(buff),size);

	if( rcode != NULL && strtailchr(buff) != '\n' ){
		CStr(tmp,64);
		FStrncpy(tmp,buff);
		sv1log("##HHe bad header ending without LF (leng=%d) [%s]...\n",
			istrlen(buff),tmp);
		setVStrEnd(buff,0);
		rcode = NULL;
	}
	if( rcode != NULL && normalize )
		check_header(Conn,AVStr(buff));

	if( rcode != NULL ){
		if( OREQ_LEN == 0 )
		if( HTTP_isMethod(buff) )
			HTTP_repairRequest(AVStr(buff));
		len = strlen(buff);
		if( OREQ_LEN + len < sizeof(OREQ_MSG) ){
			Xstrncpy(NVStr(OREQ_MSG) OREQ_MSG+OREQ_LEN,buff,len+1);
			OREQ_LEN += len;
		}
	}
	return rcode;
}
#define fgetsRequest(Conn,bf,sz,fc,nm) fgetsRequestX(Conn,QX,bf,sz,fc,nm)

static void clientAskedKeepAlive(Connection *Conn,PCStr(fname),PCStr(value))
{
#if 0
	if( strncaseeq(ConnFname,"Connection",10)
	 && strncaseeq(fname,"Proxy-",6)
	 && (ClientFlags & PF_MITM_ON) ){
		/* ignore Proxy-Connection in MITM (for Safari) */
	}else
#endif
	FStrncpy(ConnFname,fname);
	if( strcasecmp(value,"keep-alive") == 0 ){
		ClntKeepAlive = 1; /* client requests so */
		/*
		if( !strcaseeq(REQ_METHOD,"POST")
		*/
		if((!strcaseeq(REQ_METHOD,"POST")||(HTCKA_opts & HTCKA_POST))
		 && !DontKeepAlive && 1 < CKA_RemAlive )
			WillKeepAlive = 1; /* I will do so */
		else	WillKeepAlive = 0;
	}else
	if( strcasecmp(value,"close") == 0 ){
		clntClose(Conn,"c:client's will");
		ClntKeepAlive = 0;
		WillKeepAlive = 0;
	}
}
static char *addBuf(PVStr(sp),PCStr(xp),PCStr(str))
{	int len;

	len = strlen(str);
	if( xp <= sp + len ){
		sv1log("##FATAL: addBuf over flow: %s\n",str);
		return (char*)sp;
	}
	strcpy(sp,str);
	return (char*)sp + len;
}

static int fpoll2(int timeout,FILE *fc,FILE *fs)
{	FILE *fpv[2];
	int rdv[2],nready,mask;

	fpv[0] = fc;
	fpv[1] = fs;
	nready = fPollIns(timeout,2,fpv,rdv);
	mask = 0;
	if( rdv[0] != 0 ) mask |= 1;
	if( rdv[1] != 0 ) mask |= 2;
	return mask;
}
static int poll2(int timeout,int sock1,int sock2){
	int fdv[2],rdv[2],nready,mask;

	fdv[0] = sock1;
	fdv[1] = sock2;
	nready = PollIns(timeout,2,fdv,rdv);
	mask = 0;
	if( rdv[0] != 0 ) mask |= 1;
	if( rdv[1] != 0 ) mask |= 2;
	return mask;
}

typedef struct {
	int sp_tid;
	int sp_fx;
	int sp_sio[2];
	int sp_timeout;
	int sp_rcc;
	int sp_wcc;
} PipeSelect;
static int SelectRelay1(PipeSelect *PSel,int in,int out){
	int rdy,rcc,wcc;
	IStr(buf,4*1024);
	for(;;){
		rcc = read(in,buf,sizeof(buf));
		if( rcc <= 0 ){
			break;
		}
		PSel->sp_rcc += rcc;
		wcc = write(out,buf,rcc);
		if( 0 < wcc ){
			PSel->sp_wcc += wcc;
		}
		if( wcc < rcc ){
			syslog_ERROR("SelectRelay1 %d/%d\n",wcc,rcc);
			break;
		}
	}
	return rcc;
}
/*
 * filter -P->[fd] -P-> DeleGate
 * filter -P->[fx] -P-> relay1 -S-> sio[1] -> sio[0]/[fd] -S-> DeleGate
 */
int pushPipeSelect(int fd,PipeSelect *PSel){
	bzero(PSel,sizeof(PipeSelect));
	if( !isWindows() || file_isSOCKET(fd) )
		return -1;

	Socketpair(PSel->sp_sio);
	PSel->sp_fx = dup(fd);
	dup2(PSel->sp_sio[0],fd);
	close(PSel->sp_sio[0]);
	PSel->sp_timeout = (int)(HTTP_TOUT_IN_REQBODY*1000);
	PSel->sp_tid = thread_fork(0,0,"POSTrelay",(IFUNCP)SelectRelay1,PSel,
		PSel->sp_fx,PSel->sp_sio[1]);
	return 0;
}
int popPipeSelect(int fd,PipeSelect *PSel){
	int tid = PSel->sp_tid;
	int err;

	if( tid == 0 )
		return 0;
	dup2(PSel->sp_fx,fd);
	close(PSel->sp_fx);
	err = thread_destroy(tid);
	/*
	don't wait non-existent thread
	thread_kill(tid,9);
	err = thread_wait(tid,1000);
	*/
	sv1log("-- wait SelectPipe tid=%X err=%d %d/%d (%d/%d)\n",PRTID(tid),
		err,PSel->sp_wcc,PSel->sp_rcc,actthreads(),numthreads());
	return 0;
}

static int skipIfContinue(Connection *Conn,FILE *fs,FILE *tc){
	CStr(line,1024);
	int code;
	int relaycont;

	if( fgetsTimeout(AVStr(line),sizeof(line),fs,1000) == NULL )
		return -1;
	if( sscanf(line,"HTTP/%*s %d",&code) == 1 && code == 100 ){
		relaycont = tc != NULL && (0 <= vercmp(REQ_VER,"1.1"));
		/* or if with Expect: 100-continue ... */
		if( relaycont )
			fputs(line,tc);
		sv1log("%s-RESP: %s",relaycont?"RELAY":"IGNORE",line);
		while( fgetsTimeout(AVStr(line),sizeof(line),fs,1000) != NULL ){
			sv1log("%s-RESP: %s",relaycont?"RELAY":"IGNORE",line);
			if( relaycont )
				fputs(line,tc);
			if( line[0] == '\r' || line[0] == '\n' )
				break;
		}
		if( relaycont )
			fflush(tc);
		return 1;
	}
	return 0;
}
int HTCCX_reqBodyWithConv(Connection *Conn,PCStr(req),PCStr(fields));

extern int URICONV_ANY;
const char *MountReqURL(Connection *Conn,PVStr(url));
void rewriteContentLength(FILE *ts,PCStr(fields),int len){
	const char *hp;
	const char *np;
	for( hp = fields; *hp; hp = np ){
		np = nextField(hp,0);
		if( STRH(hp,F_ContLeng) ){
			fprintf(ts,"Content-Length: %d\r\n",len);
		}else{
			fwrite(hp,1,np-hp,ts);
		}
	}
}
int MountRequestBody(Connection *Conn,FILE *ts,PCStr(req),PCStr(fields),PCStr(body),int bn){
	const char *sp;
	const char *np;
	const char *tag;
	const char *attr;
	int uconv;
	IStr(rem,1024);
	IStr(ctypef,256);
	IStr(ctype,128);
	int len;
	IStr(url,URLSZ);
	const char *up;
	CStr(serv,MaxHostNameLen);
	int rew = 0;
	int slen = strlen(body);
	int xlen;

	int nsz;
	defQStr(xb);
	defQStr(xp);
	nsz = bn * 2 + 1024;
	setQStr(xb,(char*)malloc(nsz),nsz);
	cpyQStr(xp,xb);

	getFV(fields,"Content-Type",ctypef);
	wordScanY(ctypef,ctype,"^; ");
	for( sp = body; *sp; ){
		uconv = URICONV_ANY;
		np = html_nextTagAttrX(NULL,sp,ctype,AVStr(rem),&tag,&attr,&uconv);
		if( np == NULL )
			break;
		if( sp < np ){
			len = np - sp;
			Bcopy(sp,xp,len);
			xp += len;
		}
		up = wordScanY(np,url,"^\" \t\r\n>");
		sp = up;
		if( MountReqURL(Conn,AVStr(url)) ){
			rew++;
		}else{
		}
		if( url[0] == '/' ){
			sprintf(serv,"http://%s:%d",DST_HOST,DST_PORT);
			Strins(AVStr(url),serv);
		}
		strcpy(xp,url);
		xp += strlen(xp);
	}
	if( rew ){
		strcpy(xp,sp);
		xlen = strlen(xb);
		sv1log("-- POST mounted body (%d <- %d)*%d\n",xlen,slen,rew);
		if( HTCCX_reqBody(Conn,ts,req,fields,xb,xlen) == 0 ){
			fputs(req,ts);
			if( bn != xlen ){
				rewriteContentLength(ts,fields,xlen);
			}else{
				fputs(fields,ts);
			}
			fwrite(xb,1,xlen,ts);
		}
	}
	free((char*)xb);
	return rew;
}

/*
 * relayRequest in background is to simplify implementation of request
 * relay without knowing whether or not the request method has request body
 * which EOF could not be determined without knowledge, thus difficult to be
 * done in foreground before relaying the response.
 * HINT: HTTP header can be relayed in foreground without any knowledge :-D
 */
static int relayRequestBodyX(Connection *Conn,FILE *tc,FILE *fc,FILE *ts,FILE *fs,PCStr(req),PCStr(fields),FileSize bleng)
{	FileSize bsize;
	int ch;
	FileSize bn;
	defQStr(bbuff); /*alloc*/
	defQStr(hbuff);
	int nready;
	int start,lastflush,now;
	int buffered;
	int senthead = 0;
	int mountbody = 0;
	PipeSelect PSelfc;
	PipeSelect PSelfs;

#define fflushbbuff(why) { \
	buffered = 0; \
	if( senthead == 0 ){ \
		sv1log("-- POST flush head %lld/%lld\n",bn,bleng); \
		senthead = 1; \
	fputs(req,ts); \
	fputs(fields,ts); \
	} \
	fwrite((char*)bbuff,1,bn,ts); \
	free((char*)bbuff); \
	now = time(0); \
	sv1log("#### [%s] detach reqBuff: (%lldB/%lldB) / (%ds/%ds)\n",why,bn,bleng,now-lastflush,now-start); \
 }

	hbuff = 0;
	if( IsMounted /* or Mounted() */ ){
		IStr(ctypef,128);
		IStr(ctype,128);
		getFV(fields,"Content-Type",ctypef);
		wordScanY(ctypef,ctype,"^; ");
		if( strtailstr(ctype,"/xml")
		 || strtailstr(ctype,"+xml")
		 /*|| strcaseeq(ctype,"text/html")*/
		){
			mountbody = 1;
		}
	}

	OREQ_BODYOFF = OREQ_LEN;

	bsize = bleng + 1024;
	if( HTTP_MAX_BUFF_REQBODY < bsize )
		bsize = HTTP_MAX_BUFF_REQBODY + 1024;
	setQStr(bbuff,(char*)malloc(bsize),bsize);

	bn = DDI_flushCbuf(Conn,AVStr(bbuff),bsize,NULL);
	DDI_proceedFromC(Conn,fc); /* it clears Cbuf ... */

	if( checkServ(Conn) ){
		buffered = 0;
		if( *req ){
			if( badServ(Conn,"beforeREQLINE",BS_QLINE,ts,fs,NULL) )
				ts = NULLFP();
			fputs(req,ts);
			fflush(ts);
		}
		if( *fields ){
			if( badServ(Conn,"beforeREQHEAD",BS_QHEAD,ts,fs,NULL) )
				ts = NULLFP();
			fputs(fields,ts);
			fflush(ts);
		}
		senthead = 1;
		if( badServ(Conn,"beforeREQBODY",BS_QBODY,ts,fs,NULL) )
			ts = NULLFP();

		fwrite(bbuff,1,bn,ts);
		free((char*)bbuff);
	}else{
		buffered = 1;
		if( (HTTP_opts & HTTP_POSTPONE_REQHEAD) == 0  )
		if( 0 <= vercmp(REQ_VER,"1.1") ){
			if( mountbody ){
			}else
			if( HTCCX_reqBodyWithConv(Conn,req,fields) ){
				/* with rewriting body with CCX or so */
				sv1log("-- POST buff head for rew. body...\n");
			}else{
				fputs(req,ts);
				fputs(fields,ts);
				fflush(ts);
				senthead = 1;
			}
		}
	}
	start = lastflush = time(0);
	if( Conn->xf_filtersCFI & (XF_FTOSV|XF_FTOMD) ){
		/* 9.9.4 Content-Length will be adjusted in CFI */
		if( !enbugPOST_BUFF() ){
			fflushbbuff("FTOSV+CFI");
		}
	}

	if( 16*0x10000 < bleng ){
		expsockbuf(fileno(fc),0x10000,0);
		expsockbuf(fileno(ts),0,0x10000);
	}

	if( isWindows() && !isWindowsCE() ){
		pushPipeSelect(fileno(fc),&PSelfc);
		pushPipeSelect(fileno(fs),&PSelfs);
	}
	if( bleng == 0 && READYCC(fc) == 0 ){
		/* 9.9.8 can be flushed after header, without Content-Length */
		if( 0 < PollIn(fileno(fc),30) ){
			int ch;
			ch = getc(fc);
			if( ch != EOF ){
				ungetc(ch,fc);
			}
			sv1log("#### POST BODY [%X] rdy=%d\n",ch,READYCC(fc));
		}
	}
	/*
	for( ; bn < bleng || 0 < READYCC(fc); bn++ ){
	*/
	for( ; ; bn++ ){
		if( bn < bleng /* not yet reached to the Content-Length */
		 || 0 < READYCC(fc) /* input from the client is ready */
		){
		}else
		if( bleng == 0 && 0 < fPollIn(fc,(int)(HTTP_TOUT_BUFF_REQBODY*1000)) ){
			/* fix-110521c to do get more with Content-Length:0 */
			sv1log("fix-110521c No Content-Length + buff(%d) with HTTPCONF=tout-buff-reqbody:%.2f\n",
				ll2i(bn),HTTP_TOUT_BUFF_REQBODY);
		}else{
			 break;
		}

		if( buffered == 0 && READYCC(fc) == 0 ){
			if( fPollIn(fc,30) == 0 ){
				/* 9.9.4 slow and/or intermittent upload */
				if( !enbugPOST_BUFF() ){
					fflush(ts);
				}
			}
		}
		if( bn < bleng && READYCC(fc) <= 0 ){
			int tout = (int)(HTTP_TOUT_IN_REQBODY*1000);
			nready = fpoll2(tout,fc,fs);
			if( nready & 2 ){
				if( skipIfContinue(Conn,fs,tc) <= 0 ){
			sv1log("#### ERROR: RESP. DURING REQ. (%lld/%lld)\n",
					bn,bleng);
				break;
				}
			}
			/*
			nready = fPollIn(fc,(int)(HTTP_TOUT_IN_REQBODY*1000));
			*/
			if( nready <= 0
			 || HTTP_TOUT_BUFF_REQBODY < time(0) - lastflush
			){
				now = time(0);
				if( buffered ){
					fflushbbuff("timeout");
				}
				fflush(ts);
				lastflush = now;
			}
			if( nready < 0 )
				setClientEOF(Conn,fc,"relayRequestBody-1");
			if( nready <= 0 ){
			sv1log("#### ERROR: IMMATURE REQUEST BODY (%lld/%lld)\n",bn,bleng);
				break;
			}
		}
		ch = getc(fc);
		if( ch == EOF ){
			setClientEOF(Conn,fc,"relayRequestBody-2");
			break;
		}
		if( bn == bleng && (HTCKA_opts & HTCKA_POSTPIPELINE) ){
			/* the head of the next pipelined request */
			if( 'A' <= ch && ch <= 'Z' ){
				/*
				IStr(req,16);
				fgetsBuffered(DVStr(req,1),sizeof(req)-1,fc);
				if( HTTP_isMethod(req) ){
					DDI_pushCbuf(Conn,req,strlen(req));
				}
				*/
				ungetc(ch,fc);
				sv1log("##CKA POST PIPELN (%d/%d) %X\n",
					(int)bn,(int)bleng,ch);
				break;
			}else{
				sv1log("##CKA POST NON-PIPELN (%d/%d) %X\n",
					(int)bn,(int)bleng,ch);
			}
		}
		if( buffered ){
			if( HTTP_MAX_BUFF_REQBODY <= bn ){
				fflushbbuff("bufsize");
			}
		}
		if( buffered ){
			if( bsize <= bn ){
				bsize += 1024;
				setQStr(bbuff,(char*)realloc((char*)bbuff,bsize),bsize);
			}
			setVStrElem(bbuff,bn,ch);
		}else{
			putc(ch,ts);
		}
		/*
		if( OREQ_LEN < sizeof(OREQ_MSG) )
		*/
		if( OREQ_LEN < sizeof(OREQ_MSG)-1 )
		OREQ_MSG[OREQ_LEN++] = ch;

		if( ch == '\n' ){
			if( badServ(Conn,"inBODY",BS_QBODY,ts,fs,NULL) )
				ts = NULLFP();
		}
	}
	if( isWindows() && !isWindowsCE() ){
		popPipeSelect(fileno(fc),&PSelfc);
		popPipeSelect(fileno(fs),&PSelfs);
	}
	if( OREQ_LEN < sizeof(OREQ_MSG) )
	OREQ_MSG[OREQ_LEN] = 0;

	if( buffered ){
		setVStrEnd(bbuff,bn);
		/* do necessary rewriting for the body, the header fields
		 * and request line here, or return body data to the caller
		 * of this function without sending to the server.
		 */
		if( senthead == 0 && mountbody
		 && MountRequestBody(Conn,ts,req,fields,bbuff,bn) ){
		}else
		if( senthead ){
			Verbose("-- POST flush body without rew. %lld/%lld\n",
				bn,bleng);
			fwrite(bbuff,1,bn,ts);
		}else
		if( HTCCX_reqBody(Conn,ts,req,fields,bbuff,bn) == 0 ){
			sv1log("-- POST flush mssg without rew. %lld/%lld\n",
				bn,bleng);
		fputs(req,ts);
		fputs(fields,ts);
		fwrite(bbuff,1,bn,ts);
		}
		else{
			Verbose("-- POST flush head rewriten with body\n");
		}
		free((char*)bbuff);
	}

	fflush(ts);
	/*
	sv1log("relayRequestBody1 done (%lld/%lld)\n",bn,bleng);
	*/
	sv1log("relayRequestBody1 done (%lld/%lld %lld)\n",bn,bleng,bsize);
	if( hbuff ) free((char*)hbuff);
	return bn;
}
static int relaydata(Connection *Conn,FILE *tc,FILE *fc,FILE *ts,FILE *fs,int timeout)
{
	return relayRequestBodyX(Conn,tc,fc,ts,fs,"","",0);
}

/* new-110521a for fix-110513a
 * todo-110521b conversion : chunk/chunk, chunk/no-chunk, no-chunk/chunk
 */
FileSize relayChunkedBody(Connection *Conn,FILE *fc,FILE *ts,FILE *fs,PCStr(areq),PCStr(afields)){
	int inChunk = 1; /* input is in chunked by default */
	int outChunk = 1; /* should remove chunk and add ContLeng for 1.0 server */
	int eoc = 0; /* encountered "0 CR LF header" */
	FileSize nchunk = 0; /* number of chunks relayed */
	FileSize total = 0; /* total size of chunks relayed */
	IStr(fields,8*1024);
	IStr(buff,8*1024);
	int rcc;
	int occ; /* coverted length */
	int wcc;
	FileSize ckz; /* current chunk size */
	double St = Time();

	strcpy(fields,afields);
	if( outChunk ){
	}else{
		removeFields(AVStr(fields),"Transfer-Encoding",0);
	}
	fputs(areq,ts);
	fputs(fields,ts);

	for(;;){
		if( inChunk ){ /* get the chunk header "HexSize CR LF" */
			if( eoc ){
				if( fPollIn(fc,1) <= 0 ){
					sv1log("## relayChunked: timeout 1\n");
					break;
				}
			}
			ckz = -1;
			if( fPollIn(fc,(int)(HTTP_TOUT_IN_REQBODY*1000)) == 0 ){
				sv1log("## relayChunked: timeout %d\n",HTTP_TOUT_IN_REQBODY);
				break;
			}
			if( fgets(buff,sizeof(buff),fc) == NULL ){
				sv1log("## relayChunked: header EOS from client\n");
				break;
			}
			sscanf(buff,"%llX",&ckz);
			if( total == 0 ){
				sv1log("## the first Chunk size=%d\n",ll2i(ckz));
			}
			if( 0 < ckz ){
				nchunk++;
			}
			if( ckz == 0 ){
				eoc++;
			}
			if( ckz < 0 ){
				sv1log("#### bad chunksize=%d\n",ll2i(ckz));
				break;
			}
		}else{
			ckz = sizeof(buff);
		}
		if( 0 < ckz ){
			/* relay (a chunked) data */
			rcc = fread(buff,1,ckz,fc);
			if( rcc <= 0 ){
				sv1log("#### read error (e%d)\n",errno);
				break;
			}
			total += rcc;

			/* conversion if necessary */
			occ = rcc;
		}else{
			rcc = 0;
			occ = 0;
		}
		if( outChunk ){
			/* put the chunk header */
			fprintf(ts,"%x\r\n",occ);
		}
		if( 0 < rcc ){
			/* relay the data */
			wcc = fwrite(buff,1,rcc,ts);
			if( wcc <= 0 ){
				sv1log("#### write error (e%d)\n",errno);
				break;
			}
		}
		if( inChunk ){ /* relay the chunk footer "CR LF" */
			for(;;){
				if( fgets(buff,sizeof(buff),fc) == NULL ){
					sv1log("#### relayChunked: footer EOS from client\n");
					break;
				}
				if( outChunk ){
					fputs(buff,ts);
				}
				if( strcmp(buff,"\r\n") == 0 ){
					break;
				}			
				sv1log("## not end-of-chunk: %s",buff);
			}
		}
	}
	sv1log("#### relay Chunked: %lld / %lld (%.2f) eoc=%d\n",total,nchunk,
		Time()-St,eoc);
	return total;
}
static int relayRequestBody1(Connection *Conn,FILE *tc,FILE *fc,FILE *ts,FILE *fs,PCStr(req),PCStr(fields))
{	CStr(cleng,128);
	IStr(cenc,128);
	FileSize bleng;

	if( getFV(fields,"Content-Length",cleng) == 0 )
	{
		/* fix-110513a relaying POST req. with chunked body */
		if( getFV(fields,"Transfer-Encoding",cenc) ){
			if( streq(cenc,"chunked") ){
				bleng = relayChunkedBody(Conn,fc,ts,fs,req,fields);
				fflush(ts);
				return 1;
			}
		}
		return 0;
	}
	Xsscanf(cleng,"%lld",&bleng);
	if( bleng < 0 ){
		daemonlog("F","## Bad Content-Length: %s (client=%s)\n",
			cleng,Client_Host);
		bleng = 0;
	}
	relayRequestBodyX(Conn,tc,fc,ts,fs,req,fields,bleng);
	return 1;
}

static char *add_OREQ_MSG(Connection *Conn,PCStr(fname),PCStr(fmt),...){
	int len;
	char *hp;
	CStr(f1,512);
	VARGS(8,fmt);

	sprintf(f1,"%s: ",fname);
	Xsprintf(TVStr(f1),fmt,VA8);
	strcat(f1,"\r\n");
	len = strlen(f1);
	if( OREQ_LEN + len < sizeof(OREQ_MSG) ){
		if( 4 <= OREQ_LEN && streq(OREQ_MSG+OREQ_LEN-4,"\r\n\r\n") ){
			hp = OREQ_MSG+OREQ_LEN-2;
			Strins(NVStr(OREQ_MSG)hp,f1);
		}else{
			hp = OREQ_MSG+OREQ_LEN;
			Xstrncpy(NVStr(OREQ_MSG)hp,f1,len+1);
		}
		OREQ_LEN += len;
		return hp;
	}
	return 0;
}
char *DFLT_VHOST;
int extractSessionCookie(Connection *Conn,PVStr(req));

/*
 * This should be splited into relayRequestHead() and relayRequestBody()
 */
static int relay_request(Connection *Conn,QueryContext *QX,PCStr(request),PVStr(fields),FILE *tc,FILE *fc,FILE *ts,FILE *fs,int headonly,int in_header,PCStr(cpath),int cdate)
{	CStr(req,URLSZ);
	CStr(value,256);
	int lines;
	int bytes;
	int sentFrom;
	int tsEOF;
	refQStr(tail,fields); /**/
	const char *tx = 0;
	CStr(UA,1024);
	CStr(ViaBuf,2048);
	refQStr(vp,ViaBuf); /**/
	const char *vx;
	CStr(connection,256);
	CStr(fname,256);
	int fnlen;
	const char *igp = 0;
	IStr(genf,URLSZ);
	int gen_iqhead = 0;
	int withHost = 0;

	if( headonly && !in_header )
		return 0;

	RequestLength = 0;
	sentFrom = 0;
	ClntIfMod[0] = 0;
	ClntIfModClock = -1;
	if( LockedByClient ){ free((char*)LockedByClient); LockedByClient = 0; }
	if( CacheID){ free((char*)CacheID); CacheID = 0; }
	tsEOF = 0;
	lines = bytes = 0;
	if( tail ){
		tx = tail + (sizeof(REQ_FIELDS) - 1);
	}
	D_HOPS = 0;
	UA[0] = 0;
	REQ_UA[0] = 0;
	ViaBuf[0] = 0;
	vx = ViaBuf + sizeof(ViaBuf);
	connection[0] = 0;
	QX_upgrade[0] = 0;

	if( in_header )
	for(;;){
		if( igp ){
			if( *igp == 0 ){
				break;
			}
			igp = lineScan(igp,req);
			if( *igp == '\r' ){ strcat(req,"\r"); igp++; }
			if( *igp == '\n' ){ strcat(req,"\n"); igp++; }
			if( *req != '\r' && *req != '\n' )
				sv1log("++ %s",req);
		}else
		if( fgetsRequest(Conn,AVStr(req),sizeof(req),fc,1) == NULL ){
			setClientEOF(Conn,fc,"relay_request");
			break;
		}
		else
		if( req[0] == '\r' || req[0] == '\n' ){
			if( DFLT_VHOST && withHost == 0 ){
				CStr(vh,512);
				HostPort(AVStr(vh),CLNT_PROTO,DFLT_VHOST,
					Conn->clif._acceptPort);
				igp = add_OREQ_MSG(Conn,"Host","%s",vh);
				if( igp == NULL ){
					break;
				}
				continue;
			}
		}
		if( req[0] == '\r' || req[0] == '\n' ){
			if( gen_iqhead == 0 )
			if( HTTP_genhead(Conn,TVStr(genf),KH_IN|KH_REQ) ){
				gen_iqhead = 1;
				igp = genf;
				strcat(genf,"\r\n");
				continue;
			}
		}

		lines += 1;
		bytes += strlen(req);

		if( HTTP_head2kill(req,KH_IN|KH_REQ) ){
			sv1log("## HTTPCONF=kill-iqhead:%s",req);
			continue;
		}

		value[0] = 0;
		if( STRH(req,F_KeepAlive) ){
			sv1log("IGNORE request: %s",req);
			continue;
		}else
/*
		if( STRH(req,F_Upgrade) ){
			sv1log("IGNORE request: %s",req);
*/
		if( fnlen = STRH(req,F_Upgrade) ){
			lineScan(req+fnlen,QX_upgrade);
			sv1log("Upgrade: %s\n",QX_upgrade);
			continue;
		}else
		if( STRH_Connection(req) ){
			scan_field1(req,AVStr(fname),sizeof(fname),AVStr(value),sizeof(value));
			clientAskedKeepAlive(Conn,fname,value);

			if( connection[0] != 0 )
				strcat(connection,",");
			strcat(connection,value);
			continue;
		}else
		if( fnlen = STRH(req,F_ContType) ){
			lineScan(req+fnlen,value);
			sv1vlog("Request Content-Type: %s\n",value);
		}else
		if( fnlen = STRH(req,F_ContLeng) ){
			if( (HTCKA_opts & HTCKA_REQWITHLENG) ){
				sv1log("##CKA Keep-Alive [%s] with body: %s",
					REQ_METHOD,req);
			}else{
			sv1log("#HT11 Don't Keep-Alive [%s] with body: %s",
				REQ_METHOD,req);
			WillKeepAlive = 0;
			DontKeepAlive = 1;
			}
			RequestLength = atoi(req+fnlen);
		}else
		if( fnlen = STRH(req,F_AccEncode) ){
			CStr(enc,64);
			extern int withGzip;
			lineScan(req+fnlen,enc);

			/* if without non-CFI FTOCL */
			if( (Conn->xf_filters & XF_FTOCL) == 0
			 || (Conn->xf_filtersCFI & XF_FTOCL) != 0
			)
			if( !reqRobotsTxt(Conn)  )
			if( withGzip )
			if( (HTTP_opts & HTTP_NOGZIP ) == 0 )
			if( isinList(HTTP_genEncoding,"gzip") )
			if( isinList(enc,"gzip") || isinList(enc,"x-gzip") )
			{
				Verbose("#CEcl prepare ContEncoding:%s\n",enc);
				lineScan(enc,QX_accEnc);
				strcpy(REQ_AccEnc,QX_accEnc);
				RESP_DoZIP = 1;
				/*
				should set DoUNZIP=1 too ?
				*/
			}
		}else
		if( strncasecmp(req,"Host:",5) == 0 ){
			withHost = 1;
		}else
		if( strncasecmp(req,"From:",5) == 0 ){
			sv1log("%s",req);
			if( strpbrk(req,"/(") )
				vp = addBuf(AVStr(vp),vx,req);
		}else
		if( strncasecmp(req,"Forwarded:",10) == 0 ){
			vp = addBuf(AVStr(vp),vx,req);
			D_HOPS++;
		}else
		if( strncasecmp(req,"Via:",4) == 0 ){
			vp = addBuf(AVStr(vp),vx,req);
			D_HOPS += num_ListElems(req+4,',');
		}else
		if( strncasecmp(req,"User-Agent:",11) == 0 ){
			lineScan(req+11,UA);
			lineScan(req+11,REQ_UA);
		}else
		if( strncasecmp(req,"Referer:",8) == 0 ){
			/*sv1log("%s",req);*/
			/*stripDeleGate(Conn,req+8);*/
			lineScan(req+8,value);
			PageCountUpURL(Conn,CNT_REFERER|CNT_INCREMENT,value,NULL);
			PageCountUpURL(Conn,CNT_REFERER|CNT_TOTALINC,value,NULL);
		}else
		if( (fnlen = STRH(req,"Authorization:"))
		 || (fnlen = STRH(req,"Proxy-Authorization:"))
		){
			IStr(atype,64);
			wordScan(req+fnlen,atype);
			if( lSECRET() ){
				IStr(auth,1024);
				lineScan(req,auth);
				porting_dbg("-dS %s %s",REQ_METHOD,auth);
			}
			Verbose("(Proxy)Authorzation: %s\n",atype);
			if( lDONTHT() ){
				if( strcaseeq(atype,"Negotiate") ){
					withNTHT |= NTHT_REQNEGO;
					sv1log("----NTHT Q %s",req);
				}
			}
		}else
		if( strncasecmp(req,"Accept-Language:",16) == 0 ){
			HTTP_scanAcceptCharcode(Conn,AVStr(req));
			if( *req == 0 )
				continue;
		}else
		if( HTTP_ignoreIf && strncasecmp(req,"If-",3) == 0 ){
			sv1log("IGNORE IF-: %s",req);
			continue;
		}else
		if( strncasecmp(req,"If-Modified-Since:",18) == 0 ){
			wordscanY(req,AVStr(ClntIfMod),sizeof(ClntIfMod),"^");
			lineScan(ClntIfMod+18,value);
			ClntIfModClock = scanHTTPtime(value);
			sv1log("= (%d) %s",ClntIfModClock,req);
			continue;
		}else
		if( strncasecmp(req,"Cookie:",7) == 0 ){
			CStr(cookie,256);
			HTCCX_setindflt(Conn);
			getProxyCookie(Conn,QX,AVStr(req));
			getDGC_ROUTE(Conn,AVStr(req));
			lineScan(req+7,cookie);
			if( strncmp(cookie,"DeleGate-Control=",17) == 0 ){
				sv1log("#Proxy-Cookie: %s",req);
				lineScan(cookie+17,proxyCookie);
			}
			/*
			extractParam(AVStr(req),"Cookie",DeleGateSId(AVStr(sn)),
				AVStr(ClientSession),sizeof(ClientSession),1);
			*/
			extractSessionCookie(Conn,AVStr(req));
		}else
		if( strncasecmp(req,"Pragma:",7) == 0 ){
			Verbose("%s",req);
			wordScan(req+7,value);
			if( strcaseeq(value,"no-cache")){
				DontReadCache = 1;
				PragmaNoCache = 1;
				HttpReload = 2;
				RES_CACHE_DISABLE = 1;
			}else
			if( strcaseeq(value,"cache-readonly") ){
				DontWriteCache = 1;
				continue;
			}else
			if( strcaseeq(value,"cache-only") ){
				CacheOnly = 1;
				DontWriteCache = 1;
				continue;
			}
		}else
		/*
		if( STRH(req,F_CacheControl) ){
		*/
		if( fnlen = STRH(req,F_CacheControl) ){
			lineScan(req+fnlen,value);
			if( isinListX(value,"only-if-cached","cw;") ){
				CacheOnly = CACHE_ONLY;
				DontWriteCache = 1;
				continue;
			}else
			if( strcasestr(req,"no-cache") ){
				DontReadCache = 1;
				PragmaNoCache = 1;
				HttpReload = 2;
				RES_CACHE_DISABLE = 1;
			}else
			if( strcasestr(req,"max-age=0") ){
				if( (HTTP_cacheopt & CACHE_LESSRELD) == 0 ){
					DontReadCache = 1;
					PragmaNoCache = 1;
				}
				HttpReload = 1;
			}
			/*
			if( strcasestr(req,"max-age=0")
			 || strcasestr(req,"no-cache") ){
				DontReadCache = 1;
				PragmaNoCache = 1;
				if( strcasestr(req,"no-cache") ){
					HttpReload = 2;
					RES_CACHE_DISABLE = 1;
				}else{
					HttpReload = 1;
				}
			}
			*/
		}else
		if( STRH(req,F_Range) ){
			int scanHttpRange(Connection *Conn,PCStr(req),FileSize *from,FileSize *to);
			scanHttpRange(Conn,req,&QX_range[0],&QX_range[1]);
			sv1log("#HT11 (%lld) %s",QX_range[1]-QX_range[0]+1,req);
			DontReadCache = 1;
			DontWriteCache = 1;
		}else
		if( strncmp(req,"X-Locking: ",11) == 0 ){
			lineScan(req+11,value);
			LockedByClient = stralloc(value);
			continue;
		}else
		if( strncmp(req,"X-Cache-ID: ",12) == 0 ){
			lineScan(req+12,value);
			CacheID = stralloc(value);
			continue;
		}

		if( *req == '\r' || *req == '\n' ){
			/* Append some fields at the end of header fields */
			if( !sentFrom ){
				sentFrom = 1;
/*
This should be the E-mail address of proxy for security consideration.
if( tail )tail = Sprintf(tail,"From: %s\r\n",D_FROM);
if( ts != NULL ) fprintf(ts,  "From: %s\r\n",D_FROM);
*/
			}
		}

		if( tail ){
			if( tx <= tail+strlen(req) ){
				daemonlog("F",
					"request header overflow: %d/%d: %s",
					bytes,lines,req);
			}else{
				QStrncpy(tail,req,tx-tail);
				tail += strlen(tail);
			}
		}

if( ts != NULL ){
			if( fputs(req,ts) == EOF ){
				tsEOF = 1;
				break;
			}
		}

		if( *req == '\r' || *req == '\n' ){
			if( AcceptLanguages && AcceptLanguages[0] )
				Verbose("Accept-Language: %s\n",AcceptLanguages);
			Verbose("HTTP Relay_request_head (%d bytes/%d lines)\n",
				bytes,lines);
			break;
		}
	}

	if( in_header ){
		const char *user;
		CStr(host,MaxHostNameLen);
		CStr(UaVia,4096);
		const char *dp;
		int port,direct;

		strcpy(host,"-");
		port = getClientHostPort(Conn,AVStr(host));

		for( dp = ViaBuf; *dp; dp++ ){
			switch( *dp ){
				case '\r': *(char*)dp = ';'; break;
				case '\n': *(char*)dp = ' '; break;
			}
		}
		direct = ViaBuf[0] == 0 && strstr(UA," via ") == NULL;
		sprintf(UaVia,"host=%s; User-Agent: %s; %s",host,UA,
			direct?"DIRECT":ViaBuf);
		if( !LOG_GENERIC || !fputLog(Conn,"Proxy","%s\n",UaVia) )
			    sv1log("Proxy: %s\n",UaVia);
		if( LOG_GENERIC ){
			if( (user = getClientUserC(Conn)) == NULL )
				user = "-";
			fputLog(Conn,"Client","%s@%s; agent=%s\n",user,host,UA);
		}

		if( connection[0] && RequestSerno == 0 )
		sv1log("HCKA:[%d] %s; host=%s; (%sUser-Agent: %s)\n",
			RequestSerno,connection,host,ViaBuf,UA);

		if( WillKeepAlive ){
			if( ImMaster ){
				if( vercmp(ClientVER,CHUNKED_VER) < 0 )
					clntClose(Conn,"v:via old DeleGate");
			}else
			if( !direct ){
				if( KeepAliveWithProxyClient ){
					sv1log("HCKA: Via=%s\n",ViaBuf);
				}else	clntClose(Conn,"v:via proxy");
			}
		}

		/* if this is the front most DeleGate for the client ... */
		if( !ImMaster )
			UAspecific(Conn,UA,direct);
	}

	if( ts != NULL && !tsEOF ){
		if( !ClientEOF && !headonly ){
			lines = 0;
			DDI_proceedFromC(Conn,fc);
			bytes = relaydata(Conn,tc,fc,ts,fs,(int)HTTP_TOUT_QBODY);
		}
		fflush(ts);
	}

	Verbose("HTTP Relay_request done (%d bytes/%d lines)\n",bytes,lines);
	return lines;
}
static void relayBuffered(FILE *in,FILE *out)
{	int rcc;
	CStr(buf,1024);

	fflush(out);
	while( rcc = fgetBuffered(AVStr(buf),sizeof(buf),in) ){
		if( Fwrite(buf,1,rcc,out) <= 0 )
			return;
	}
	while( 0 < PollIn(fileno(in),1000) ){
		rcc = read(fileno(in),buf,sizeof(buf));
		if( rcc <= 0 )
			break;
		if( write(fileno(out),buf,rcc) != rcc )
			break;
	}
}
static void genProxyReqFields(Connection *Conn,PVStr(fields),PCStr(cpath))
{	refQStr(gfp,fields); /**/
	CStr(forwarded,MaxHostNameLen);
	CStr(received_by,MaxHostNameLen);
	const char *auth;
	CStr(atype,128);
	CStr(genauth,256);
	CStr(buf,1024);
	CStr(buf2,1024);
	const char *dp;
	int withAuth;
	CStr(cacheid,256);

	setVStrEnd(gfp,0);

	if( findFieldValue(REQ_FIELDS,"From") == NULL )
	if( makeFrom(Conn,AVStr(buf)) ){
		Verbose("## GEN From: %s\n",buf);
		gfp = Sprintf(AVStr(gfp),"From: %s\r\n",buf);
	}
	if( makeForwarded(Conn,AVStr(forwarded) )){
		Verbose("## GEN Forwarded: %s\n",forwarded);
		gfp = Sprintf(AVStr(gfp),"Forwarded: %s\r\n",forwarded);
	}

	withAuth = 0;
	if( auth = findFieldValue(REQ_FIELDS,"Authorization") )
	if( HTTP_decompAuth(auth,AVStr(atype),sizeof(atype),AVStr(buf),sizeof(buf)) ){
		if( buf[0] == 0 || buf[0] == ':' )
			sv1log("## ignore empty Authorization [%s]\n",buf);
		else{
			Verbose("## PASS Authorization: %s %s\n",atype,"");
			withAuth = 1;
		}
	}
	if( IsMounted && strchr(REAL_SITE,'@') ){
		strcpy(buf2,REAL_SITE);
		*strchr(buf2,'@') = 0;
		str_to64(buf2,strlen(buf2),AVStr(buf),sizeof(buf),1);
		if( dp = strpbrk(buf,"\r\n") )
			truncVStr(dp);
		strcpy(atype,"Basic");
		sprintf(genauth,"%s %s",atype,buf);
		sv1log("## MOUNT Authorization: %s [%s]\n",genauth,buf2);
		gfp = Sprintf(AVStr(gfp),"Authorization: %s\r\n",genauth);
	}else
	if( withAuth == 0 )
	if( makeAuthorization(Conn,AVStr(genauth),0) ){
		HTTP_decompAuth(genauth,AVStr(atype),sizeof(atype),AVStr(buf2),sizeof(buf2));
		sv1log("## GEN Authorization: %s [%s]\n",genauth,buf2);
		gfp = Sprintf(AVStr(gfp),"Authorization: %s\r\n",genauth);
	}

	if( toProxy /* or ConnType != 'h'(i.e. SSLTUNNEL/HTTP) */ )
	/*
	if( (ServerFlags & PF_VIA_CONNECT) ){
	*/
	if( (ServerFlags & PF_VIA_CONNECT)
	 && (ServerFlags & PF_MITM_ON) == 0 /*Proxy-Auth/MITM should be forw.*/
	){
		/* already sent proxy auth. */
	}else
	if( (ServerFlags & PF_VIA_CONNECT)
	 && (ServerFlags & PF_MITM_ON) && !lFORWPAUTH() ){
		/* 9.7.0 - 9.8.4 it's already sent in Proxy-Auth for CONNECT */
	}else
	if( makeAuthorization(Conn,AVStr(genauth),1) ){
		HTTP_decompAuth(genauth,AVStr(atype),sizeof(atype),AVStr(buf2),sizeof(buf2));
		sv1log("## GEN Proxy-Authorization: %s [%s]\n",genauth,buf2);
		gfp = Sprintf(AVStr(gfp),"Proxy-Authorization: %s\r\n",genauth);
	}

	if( CacheID )
		lineScan(CacheID,cacheid);
	else	cacheid[0] = 0;

	if( cpath != NULL )
	if( toProxy || toMaster )
	{	CStr(fileId,URLSZ);
		refQStr(dp,cacheid); /**/

		if( !HTTP_noXLocking ){
			getFileUID(AVStr(fileId),cpath);
			gfp = Sprintf(AVStr(gfp),"X-Locking: %s\r\n",fileId);
		}
		if( cacheid[0] ){
			dp = cacheid + strlen(cacheid);
			setVStrPtrInc(dp,',');
		}else	dp = cacheid;
		getCacheID(AVStr(dp),cpath);
	}
	if( cacheid[0] ){
		gfp = Sprintf(AVStr(gfp),"X-Cache-ID: %s\r\n",cacheid);
	}
}

static int ReqVer(PCStr(req1),int v1,PVStr(req2),int v2)
{	const char *ver; /**/

	if( ver = strstr(req1," HTTP/1.") )
	if( ver[8] == v1 )
	if( streq(ver+9,"\r\n") || streq(ver+9,"\n") )
	{
		ver += 8;
		if( req1 != req2 ){
			strcpy(req2,req1);
			ver = (char*)req2 + (ver - req1);
		}
		if( *ver != v2 ){
			*(char*)ver = v2; /**/
			Verbose("#HT11 1.%c -> 1.%c: %s",v1,v2,req2);
		}
		if( streq(ver+1,"\n") ){
			Xstrcpy(QVStr((char*)ver+1,req2),"\r\n");
			sv1log("##HHn replaced LF to CRLF: %s",req2);
		}
		return 1;
	}
	return 0;
}

static int setAcceptEncoding(Connection *Conn,QueryContext *QX,PVStr(head))
{	extern int withGzip;
	int rewrite;
	CStr(cencb,128);
	const char *cenc;
	CStr(ehead,128);
	const char *denc;

	denc = HTTP_accEncoding;

	if( streq(denc,ENCODE_THRU) )
		return 0;

	if( streq(denc,"gzip") || streq(denc,"x-gzip") ){
		Verbose("#CEsv SEND Accept-Encoding:%s\n",denc);
		goto ACCGZIP;
	}

	rewrite = QX_cpath[0]
	 || withConversion(Conn,0)
	 || (ClientFlags & PF_CFI_DELAY_ON)
	 || (Conn->xf_filters & (XF_FFROMSV|XF_FTOCL));
	if( !rewrite )
		return 0;

	if( (Conn->xf_filters & XF_FFROMSV) != 0
	 && (Conn->xf_filtersCFI & XF_FFROMSV) == 0 ){
		replaceFieldValue(AVStr(head),"Accept-Encoding","identity");
		return 1;
	}

	cenc = getFV(head,"Accept-Encoding",cencb);
	if( streq(denc,ENCODE_THRUGZIP) ){
		if( cenc ){
			if( isinList(cenc,"gzip") || isinList(cenc,"x-gzip") ){
				Verbose("#CEsv THRU Accept-Encoding:%s\n",cenc);
				denc = "gzip";
				goto ACCGZIP;
			}
			Verbose("#CEsv KILL Accept-Encoding:%s\n",cenc);
			removeFields(AVStr(head),"Accept-Encoding",0);
			return 1;
		}
		return 0;
	}

	replaceFieldValue(AVStr(head),"Accept-Encoding",denc);
	return 0;

ACCGZIP:
	if( withGzip == 0 ){
		denc = "identity";
		Verbose("#CEsv SEND Accept-Encoding:%s (NO gzip)\n",denc);
	}
	replaceFieldValue(AVStr(head),"Accept-Encoding",denc);
	RESP_DoUNZIP = 1;
	return 1;
}

void savReqAuthorization(Connection *Conn,PCStr(head));
static void rewrite_requesthead(Connection *Conn){
	HTCCX_reqHead(Conn);
}

static int fputsRequestX(Connection *Conn,QueryContext *QX,PCStr(req),FILE *ts){
	int rcode;
	if( lPEEPDGSV() ){
		dumpmsg(&QX_dumpDS,"D-S",req);
	}
	rcode = fputs(req,ts);
	return rcode;
}
#define fputsRequest(req,ts)	fputsRequestX(Conn,QX,req,ts)

static int relayRequest(Connection *Conn,QueryContext *QX,PCStr(cpath),int cdate,FILE *tc,FILE *fc,FILE *ts,FILE *fs)
{	register int ppid,cpid;
	CStr(method,128);
	int in_header;
	int with_reqbody;
	CStr(genfields,0x8000);
	CStr(req,URLSZ);

	if( badServ(Conn,"beforeREQ",BS_CONNECT,ts,fs,NULL) )
		ts = NULLFP();

	scan_CCXTOSV(Conn);

	rewrite_requesthead(Conn);
	if( toProxy ){
		if( (ServerFlags & PF_VIA_CONNECT) ){
			/* already connected with the server */
		}else
		makeProxyRequest(Conn /*,REQ,REQ*/);
	}

	if( !HTTP_reqWithHeader(Conn,REQ) ){
		fputsRequest(REQ,ts);
		if( !HTTP_isMethod(REQ) ){
			relayBuffered(fc,ts);
			/* should be relayed by parallel thread/process */
		}
		fflush(ts);
		return 0;
	}

	wordScan(REQ,method);
	with_reqbody = HTTP_methodWithBody(method);

	genProxyReqFields(Conn,AVStr(genfields),cpath);
	MountReferer(Conn,AVStr(REQ_FIELDS));
	strcat(genfields,REQ_FIELDS);
	if( lDONTHT() ){
		/* don't add Via for IIS NTHT server */
	}else
	appendVia(Conn,1,AVStr(genfields),sizeof(genfields));
	HTTP_killhead(AVStr(genfields),KH_OUT|KH_REQ);
	HTTP_genhead(Conn,AVStr(genfields),KH_OUT|KH_REQ);
	if( !REQ_ASIS )
		rewriteReqBasicToDigest(Conn,AVStr(genfields));
	savReqAuthorization(Conn,genfields);
	setAcceptEncoding(Conn,QX,AVStr(genfields));

	if( lCCXCOOKIE() && CCXactive(CCX_TOSV) ){
		HTCCX_Qhead(Conn,AVStr(genfields));
	}
	if( with_reqbody ){
		if( relayRequestBody1(Conn,tc,fc,ts,fs,REQ,genfields) )
			return 0;
		if( ClientEOF )
			return 0;

		ppid = getpid();
		if( cpid = Fork("relayRequest") ){
			if( cpid == -1 ){
				/* should send TOO BUSY message to the client */
				sv1tlog("CANNOT FORK\n");
				Finish(1);
			}
			return cpid;
		}
		setRelaying(NULL,NULL,NULL,NULL);
		Vsignal(SIGTERM,sigTERM);
	}

	if( badServ(Conn,"beforeREQLINEx",BS_QLINE,ts,fs,NULL) )
		ts = NULLFP();

	if( (Conn->xf_filters & (XF_FFROMSV|XF_FFROMMD)) ){
		if( ReqVer(REQ,'1',AVStr(req),'0') )
			fputsRequest(req,ts);
		else	fputsRequest(REQ,ts);
		fputsRequest("Connection: close\r\n",ts);
		sv1log("#HT11 FORCE HTTP/1.0 or Connection:close [%X %X %X]\n",
			ServerFlags,ClientFlags,Conn->xf_filters);
	}else
	if( toMaster && vercmp(MediatorVer,CHUNKED_VER) < 0 ){
		/* DeleGate/5.9.3 or older don't support HTTP/1.1 but
		 * don't rewrite HTTP/1.1 to HTTP/1.0 when acting as
		 * a MASTER DeleGate.
		 */
		if( ReqVer(REQ,'1',AVStr(req),'0') ){
			fputsRequest(req,ts);
			sv1log("#HT11 FORCE HTTP/1.0 for MASTER-DeleGate/5\n");
		}else	fputsRequest(REQ,ts);
	}else
	if( HTTP11_toserver && ReqVer(REQ,'0',AVStr(req),'1') ){
		fputsRequest(req,ts);
		fputsRequest("Connection: keep-alive\r\n",ts);
		sv1log("#HT11 FORCE HTTP/1.1 or Connection:keep-alive\n");
	}else{
		fputsRequest(REQ,ts);
	}
	if( badServ(Conn,"beforeREQHEADx",BS_QHEAD,ts,fs,NULL) )
		ts = NULLFP();
	fputsRequest(genfields,ts);
	if( lDONTHT() && lSECRET() ){
		sv1log("----NTHT relay_request %s%s\n",REQ,genfields);
	}

	if( badServ(Conn,"beforeREQBODYx",BS_QBODY,ts,fs,NULL) )
		ts = NULLFP();
	Verbose("HTTP relayed request %dhead\n",istrlen(REQ_FIELDS));

	if( with_reqbody ){
		relay_request(Conn,QX,REQ,VStrNULL,tc,fc,ts,fs,0,0,cpath,-1);
		if( feof(fc) ){
			sv1log("Kill (%d/%d, SIGTERM)\n",ppid,getppid());
			Kill(ppid,SIGTERM);
		}else{
			Verbose("C-S relay TIMEOUT\n");
		}
		Finish(0);
	}else{
		if( ts != NULL )
			fflush(ts);
		return 0;
	}
	return 0;
}

static void recvRequestFields(Connection *Conn,QueryContext *QX,FILE *tc,FILE *fc)
{
	if( REQ_FIELDS[0] != 0 ){
		/* already got */
		return;
	}
	if( HTTP_reqIsHTTP(Conn,REQ) ){
		if( HTTP_reqWithHeader(Conn,REQ) )
			relay_request(Conn,QX,REQ,AVStr(REQ_FIELDS),tc,fc,NULL,NULL,1,1,NULL,-1);
		else	DontWriteCache = 1;
	}else{
		/* a Gopher request without such request fields */
	}
}

static int decomp_gopherURL(Connection *Conn,PCStr(req),PVStr(rpath))
{	int gtype;
	HttpRequest reqx;
	MrefQStr(path,reqx.hq_url); /**/

	if( decomp_http_request(req,&reqx) ){
	/* Gopher/HTTP where path is URL with gtype */
		/* from client expecting proxy */
		if( path[0] == '/' && path[1] != 0 ){
			/* this should be gtype in URL */
			gtype = path[1];
			ovstrcpy((char*)path,path+2);
		}else
		/* from client without proxy support */
	    		gtype = get_gtype(path,AVStr(path));

		if( rpath ) strcpy(rpath,path);
		CTX_set_clientgtype(Conn,gtype);
		return gtype;
	}else{
	/* Gopher/Gopher */
		linescanX(req,AVStr(path),sizeof(reqx.hq_url));
	    	gtype = get_gtype(path,AVStr(path));
		if( rpath ) strcpy(rpath,path);
		CTX_set_clientgtype(Conn,gtype);
		return 0;
	}
}
static const char *rewrite_request(Connection *Conn,FILE *fp)
{	MrefQStr(url,REQ); /**/
	const char *urltop;
	CStr(rproto,256);
	CStr(rhost,MaxHostNameLen);
	int riport;
	const char *cproto;
	const char *rcode = REQ;
	int dgurl;
	const char *ver;

	sv1log("REQUEST %s %s",BORN_SPECIALIST?"-":"=",REQ);

strcpy(rproto,"http");
riport = 80;
rhost[0] = 0;

	if( BORN_SPECIALIST
	 || ACT_SPECIALIST
	 || Port_Proto == serviceport("http")
	 || Port_Proto == serviceport("https")
	){
		if( 0 < REQ_VNO ){
			url = REQ + strlen(REQ_METHOD);
			while( *url == ' ' || *url == '\t' )
				url++;
			cproto = "http";
		}else{
			url = REQ;
			cproto = "gopher";
		}
		urltop = url;

		getProxyControlPart(Conn,AVStr(url));

		/*
		 * This stuff should be passed multiple times
		 * for indirect MOUNT, but it should be executed
		 * only for the first original reuqest URL.
		 */
		if( CLIENTS_PROXY[0] == 0 ){
			if( ClientFlags & PF_MITM_ON ){
				/* 9.9.8 to supp. URL rew. in MITM w/o MOUNT */
				DONT_REWRITE = 1;
			}else
			if( fromProxyClient(url) ){
				setProxyOfClient(Conn,1,url);
				DONT_REWRITE = 1;
			}else	setProxyOfClient(Conn,0,NULL);
		}

		MountRequestURL(Conn,AVStr(url));
		rhost[0] = 0;
		dgurl = 0;

/*
 * How to treat a request sent form a proxy client like "http://proxy/-_-URL"
 * should be cleary defined... (^_^;
 *
 * 951113: such URL (and optional flags) sould be passed through to the
 * target Proxy in the form  /-_-=flags=URL  because the flags should be
 * used in the Proxy (DeleGate).
 */

		if( strncasecmp(url,"pop://",6) == 0
		 && strchr(" \t\r\n",url[6]) ){
			strcpy(rproto,"pop");
			strcpy(rhost,"*");
			riport = 110;
			set_realserver(Conn,rproto,rhost,riport);
		}else
		if( strncasecmp(url,"news:",5) == 0
		 && strncmp(url+5,"//",2) != 0 ){
			strcpy(rproto,"nntp");
			strcpy(rhost,"*");
			riport = 119;
			set_realserver(Conn,rproto,rhost,riport);
		}else
		if( URL_toMyself(Conn,url) == NULL ){
			Verbose("To another server or proxy, THRU >>> %s",url);
		}else
		if( CTX_url_derefer(Conn,cproto,AVStr(url),AVStr(Modifier),AVStr(DELEGATE_FLAGS),AVStr(rproto),AVStr(rhost),&riport) ){
			dgurl = 1;
			url_delport(AVStr(url),&riport);
			set_realserver(Conn,rproto,rhost,riport);
			if( !IsMounted )
			if( !do_RELAY(Conn,RELAY_DELEGATE) ){
				sv1log("Forbidden: RELAY DELEGATE\n");
				RelayForbidden |= RELAY_DELEGATE;
				sprintf(Conn->reject_reason,"NO RELAY=delegate");
/*
 * can't strictly forbid the relaying if some host is allowed ...
 * (it's not problem if the restriction is all or nothing way)
 *
 * It's so expensive to check all of URLs in the RESPONSE about whether or
 * not they are RELAYable.  So all of them are rewritten if the URL in the
 * REQUEST is RELAYable, thus access to them will visit the delegated again.
 * And they should be relayed because they are directed to the delegated by
 * the delegated.
 * But RESPONSE to them will not rewritten if they are not RELAYable, thus
 * the recursive relay by URL rewriting of delegated will stop there.
 */
			}else	DO_DELEGATE = 1;
		}

		if( url_deproxy(Conn,AVStr(REQ),AVStr(url),AVStr(rproto),AVStr(rhost),&riport) ){
			url_delport(AVStr(url),&riport);
			set_realserver(Conn,rproto,rhost,riport);
			if( !IsMounted )
			if( !do_RELAY(Conn,RELAY_PROXY) ){
				RelayForbidden |= RELAY_PROXY;
				sv1log("Forbidden: RELAY PROXY\n");
				sprintf(Conn->reject_reason,"NO RELAY=proxy");
			}
		}

		/*
		if( ClientAuth.i_stat == 0 )
		if( ClientAuthUser[0] == 0 )
		if( strchr(rhost,'@') ){
		*/
		if( strchr(rhost,'@') )
		if( (ClientAuth.i_stat || ClientAuthUser[0])
		 && (GatewayFlags & GW_SSI_INCLUDE) == 0
		){
			sv1log("## Don't overwrite auth[%s]%X <= [%s]\n",
				ClientAuthUser,ClientAuth.i_stat,rhost);
		}else{
			CStr(user,128);
			CStr(pass,128);
			scan_url_userpass(rhost,AVStr(user),AVStr(pass),"");
			if( user[0] ){
				strcpy(ClientAuthUser,user);
				strcpy(ClientAuthPass,pass);
				ClientAuth.i_stat = AUTH_FORW;
				sv1log("Forwarding auth. in URL [%s]\n",user);
			}
		}

		/*
		 * cancel `DONT_REWRITE' if the URL is in form http://myself/-_-url
		 */
		if( ToMyself && dgurl )
			DONT_REWRITE = 0;

		if( rhost[0] == 0 )
			ToMyself = 1;

		if( strchr(" \t\r\n",url[0]) ){
			Strins(AVStr(url),"/");
			Verbose("HTTP EMPTY URL to %s",REQ);
		}

		if( REAL_HOST[0] )
			Verbose("REMOTE > %s",REQ);

		wordScan(urltop,REQ_URL);
	}

	if( rproto[0] == 0 ){
		sv1log("What? %s",REQ);
		return NULL;
	}

	if( !strcaseeq(rproto,"httpft") )
	if( !strcaseeq(rproto,"https") )
	if( !strcaseeq(rproto,"http") ){
		IAM_GATEWAY = 1;

		add_localheader(Conn,DONT_REWRITE);
		add_DGinputs(Conn,"%s",REQ);
		sv1log("HTTP GateWay > %s://%s:%d/%s",rproto,rhost,riport,REQ);

		if( protoGopher(rproto) )
			decomp_gopherURL(Conn,REQ,VStrNULL);
	}

	return rcode;
}

static FILE *insertFTOCL_X(Connection *Conn,FILE *tc)
{	int toC;
	FILE *ntc;

	if( GatewayFlags & GW_DONT_FTOCL ){
		if( getFTOCL(Conn) ){
			sv1log("## don't insert FTOCL (%X)\n",ClientFlags);
		}
		return tc;
	}
	toC = ToC;
	setConnX(Conn,FromC,ToC,FromS,ToS);
	if( RESP_DoZIP ){
		if( (Conn->xf_filters & XF_FTOCL) ){
			/* maybe inserted FTOCL as a MountOption */
			sv1log("Cancelled DoZIP filter:%X\n",Conn->xf_filters);
			RESP_DoZIP = 0;
		}
	}
	if( ToC == toC ){
		/* filter is not inserted */
		return tc;
	}else{
		ntc = fdopen(ToC,"w");
		if( ntc == 0 ){
			return tc;
		}
		/* if( fileno(tc) != ClientSock )
		/* fclose(tc); */
		if( lFILEDESC() ){
			sv1log("{F} >>[%d]+[%d][%d] insertFTOCL_X\n",
				ToC,toC,ClientSock);
		}
		return ntc;
	}
}


#define FORWARD_AUTH "forward-auth"
static scanListFunc strmatch(PCStr(s1),PCStr(s2)){ return strcmp(s1,s2) == 0; }
static int forwardOK(Connection *Conn,PCStr(what),PCStr(fname))
{	CStr(forw,1024);

	if( 0 <= find_CMAP(Conn,what,AVStr(forw)) ){
		if( scan_commaList(forw,0,scanListCall strmatch,fname) )
			return 1;
	}
	return 0;
}
/*
 * reply 302 Moved "/-_-proto://server/" to the "/-_-proto://server" request
 */
static int delegate_moved(Connection *Conn,FILE *tc)
{	const char *dp;
	CStr(url,URLSZ);
	int totalc;

	if( dp = strchr(REQ,' ') )
	if( dp[1] == '/' && strchr(" \t\r\n",dp[2]) )
	if( dp = strchr(OREQ_MSG,' ') ){
		wordScan(dp+1,url);
		if( strtailchr(url) != '/' ){
			strcat(url,"/");
			totalc = putMovedTo(Conn,tc,url);
			http_Log(Conn,302,CS_INTERNAL,REQ,totalc);
			return 1;
		}
	}
	return 0;
}

static void decompREQUEST(Connection *Conn,QueryContext *QX)
{
	if( REAL_HOST[0] ){
		QX_proto  = REAL_PROTO;
		QX_site = REAL_HOST;
		QX_port  = REAL_PORT;

		if( REAL_SITE[0] == 0 ){
			HostPort(AVStr(QX_site_buf),REAL_PROTO,REAL_HOST,REAL_PORT);
			sv1log("#### REAL_SITE = empty => [%s]\n",QX_site_buf);
		}else	strcpy(QX_site_buf,REAL_SITE);
		QX_site = QX_site_buf;

		log_PATH(Conn,">");
	}else{
		if( ImMaster )
			log_PATH(Conn,">");
		QX_proto = "http";
		/*
		if( QX_site == 0 ){
			QX_site = QX_site_buf;
			clearVStr(QX_site_buf);
		}
		*/
	}

	/*
	ProcTitle(Conn,"%s://%s/)",QX_proto,QX_site);
	*/
	ProcTitle(Conn,"%s://%s/",QX_proto,QX_site);
	sv1log("REQUEST = %s[%s://%s:%d/] %s",PragmaNoCache?"(no-cache)":"",
		QX_proto,QX_site,QX_port,REQ);
}
static void lookCacheOnly(Connection *Conn,QueryContext *QX,FILE *tc,FILE *fc)
{	const char *proto;
	const char *host;
	int port;
	const char *req;
	const char *method;
	const char *url;
	const char *ver;
	HttpRequest reqx;
	CStr(uproto,64);
	CStr(usite,MaxHostNameLen);
	CStr(upath,1024);
	CStr(cpath,URLSZ);
	int useCache;
	FILE *cachefp;
	int expire,cdate;
	CStr(smtime,URLSZ);
	int mtime;

	cachefp = NULL;

	if( DontReadCache ){
		returnAckCANTCON(Conn,tc,"don't read cache");
		return;
	}

	proto = DFLT_PROTO;
	host = DFLT_HOST;
	port = DFLT_PORT;
	req = D_REQUESTtag.ut_addr;
	if( req == NULL ){
		sv1log("lookCacheOnly: no D_REQUEST set.\n");
		return;
	}

	decomp_http_request(req,&reqx);
	method = reqx.hq_method;
	url = reqx.hq_url;
	ver = reqx.hq_ver;
	decomp_absurl(url,AVStr(uproto),AVStr(usite),AVStr(upath),sizeof(upath));

	sv1log("#### [%s][%s][%d] [%s][%s][%s]\n",
		proto,host,port, method,url,ver);

	if( !service_permitted(Conn,proto) ){
		returnAckDENIED(Conn,tc,"not permitted");
		return;
	}

	useCache = CTX_cache_path(Conn,proto,host,port,upath,AVStr(cpath));
	expire = 0x7FFFFFFF;

	if( useCache )
	if( cachefp = cache_fopen_rd("HTTP",AVStr(cpath),expire,&cdate) )
	if( lock_sharedNB(fileno(cachefp)) == 0 )
	{
		if( CacheLastMod != 0 ){
			mtime = HTTP_getLastMod(AVStr(smtime),sizeof(smtime),cachefp,cpath);
			sv1log("LastModified: %d <= %d ?\n",
				CacheLastMod,mtime);
			if( mtime <= CacheLastMod ){
				returnAckCANTCON(Conn,tc,"cache is obsolete");
				goto EXIT;
			}
		}
		returnAckOK(Conn,tc,"found in cache");
		relay_response_fromCache(Conn,QX,proto,host,port,req,cpath,cachefp,tc,fc);
		goto EXIT;
	}
	returnAckCANTCON(Conn,tc,"not found in cache");
EXIT:
	if( cachefp != NULL )
		fclose(cachefp);
}

/* 9.2.3 When this code is introduced in 8.6.3, it is placed before the
 * rewriting of request which is necessary to be performed before complete
 * access checking by service_permitted() to use destination information
 * which is to be got by interpretation in the rewriting.
 * Thus source_permitted() is used here, but now it is called after
 * all necessary information is set, and source_permitted() is harmful
 * with REJECT by its proto/dstHost as REJECT="proto:dstHost:srcHost"
 */
#define MOUNT_AUTHORIZER	4

int service_permitted2x(Connection *Conn,PCStr(proto),int silent){
	CStr(sproto,128);
	int ok;

	strcpy(sproto,REAL_PROTO);
	strcpy(REAL_PROTO,proto);
	ok = service_permitted2(Conn,proto,silent);
	strcpy(REAL_PROTO,sproto);
	return ok;
}

/*
int UpdateSession(AuthInfo *ident,int expire);
*/
int UpdateSession(Connection *Conn,AuthInfo *ident,int expire);
int SessionCookieExpired(Connection *Conn,AuthInfo *ident){
	if( AuthTimeout(Conn) == 0 )
		return 0;
	/*
	if( (HTTP_opts & HTTP_SESSION) == 0 )
	*/
	if( ClientSession[0] == 0 /* no SessionCookie to expire */
	 || strcaseeq(ClientAuth.i_atyp,"Digest") /* don't use SessionCookie */
	)
		return 0;

	strcpy(ident->i_opaque,ClientSession);
	/*
	if( UpdateSession(ident,AuthTimeout(Conn)) < 0 ){
	*/
	if( UpdateSession(Conn,ident,AuthTimeout(Conn)) < 0 ){
		ClientAuth.i_error |= AUTH_ESTALE;
		strcpy(ClientSession,ident->i_opaque);
		sv1log("--SessionExpired [%s] %s {%s}\n",ClientAuth.i_user,
			ClientSession,ident->i_realm);
		return 1;
	}
	return 0;
}
int iamServer();
static int doauth(Connection *Conn,FILE *tc)
{	AuthInfo ident;
	int pauth = REQ_FLAGS & HQF_ISPROXY;
	int cc;
	int auok;
	int pmok;

	if( RequestFlags & QF_NO_AUTH ){
		return 0;
	}
	/* if Authorization is not given
	 * or if it is not successfully authenitcated
	 * (or if it does not sutisfy permission, if required)
	if( HTTP_getAuthorization(Conn,pauth,&ident,0) == 0
	 || doAuth(Conn,&ident) < 0
	 || source_permitted(Conn) == 0
	){
	 */
	if( ClientFlags & PF_MITM_ON ){
		pauth = 1;
		if( ClientAuth.i_xstat & (AUTH_XOK|AUTH_XMITM) ){
			/* kept with AUTH_SET+AUTH_APROXY during keep-alive */
			return 0; /* auth. done already in CONNECT/MITM */
		}else
		if( (ClientAuth.i_stat == AUTH_SET)
		 && (ClientAuth.i_stype == AUTH_APROXY) ){
			ident = ClientAuth;
		}else{
			bzero(&ident,sizeof(AuthInfo));
		}
	}else
	/*
	if( HTTP_getAuthorization(Conn,pauth,&ident,0) == 0 ){
	*/
	if( HTTP_getAuthorization(Conn,pauth,&ident,4) == 0 ){
		/* the ident structure must be marked as
		 * "without authentication info." if distinguishing it
		 * from "empty username & password" is necessary
		 */
	}
	/*
	if( doAuth(Conn,&ident) < 0 || source_permitted(Conn) == 0 ){
	*/
	auok = doAuth(Conn,&ident);

	if( AuthTimeout(Conn) ){
		/* for genSessionID() or UpdateSession() */
		strcpy(ClientAuth.i_realm,ident.i_realm);
		strcpy(ClientAuth.i_atyp,ident.i_atyp);
		strcpy(ClientAuth.i_user,ident.i_user);
		ClientAuth.i_stat = ident.i_stat;
		ClientAuth.i_error = ident.i_error;
		if( 0 <= auok ){
			if( SessionCookieExpired(Conn,&ident) ){
				auok = -1;
			}
		}
	}

	if( lDONTHT() )
	if( auok < 0 )
	if( ident.i_error & AUTH_EDONTHT ){
		sv1log("----NTHT accept %X MO=%d UT=%X\n",withNTHT,
			IsMounted,p2i(NTHT_utoken));
		if( withNTHT & (NTHT_CLAUTHOK|NTHT_SVAUTHOK) ){
			/* this connection is authorized already */
			return 0;
		}
		if( IsMounted ){ /* if the server is with NTLM domain ? */
		}
		if( NTHT_accept(pauth,ToC,FromC,REQ,REQ_FIELDS,AVStr(NTHT_user),&NTHT_utoken) == 0 ){
			withNTHT |= NTHT_CLAUTHOK;
			sv1log("----NTHT accept OK: %X MO=%d [%s]\n",withNTHT,
				IsMounted,NTHT_user,NTHT_utoken);
			auok = 1;
		}else{
		}
	}

	pmok = 0;
	if( 0 <= auok ){
		if( HTTP_opts & HTTP_DOAUTH_BYSOURCE ){
			/* emulate older-buggy-versions */
			if( source_permitted(Conn) )
				pmok =  1;
			else	pmok = -1;
		}else
		if( strcaseeq(REQ_METHOD,"ACCEPT") ){
			if( source_permitted(Conn) )
				pmok =  5;
			else	pmok = -1;
		}else
		if( strcaseeq(REQ_METHOD,"CONNECT")||(ClientFlags&PF_MITM_ON) ){
			if( service_permitted2x(Conn,"https",1) ){
				pmok = 3;
			}else
			if( service_permitted2x(Conn,"ssltunnel",1) ){
				pmok = 4;
			}else{
				pmok = -3;
			}
		}else{
			if( service_permitted2(Conn,DST_PROTO,1) )
				pmok =  2;
			else{
				pmok = -2;
				/* Authenticated but not Authorized/Permitted */
			}
		}
	}
	if( lVERB() || lACCESSCTL() ){
		sv1log("-dA doauth() %X %X auth=%d perm=%d realm[%s]\n",
			ident.i_stat,ident.i_error,auok,pmok,ident.i_realm);
	}

	if( auok < 0 || pmok < 0 ){
		if( Conn->from_myself && ClientSock < 0 && iamServer() ){
			return 0;
		}

/*
if( -a appear in RELIABLE or in PERMIT )
if( service_permitted2(Conn,DST_PROTO,1) ){
	sv1log("######### NOT AUTHOZIED but PERMITTED\n");
	return 0;
}
*/
		REQ_AUTH = ident;
		if( REQ_AUTH.i_error & AUTH_ENOAUTH )
		if( ident.i_realm[0] == 0 )
		/*obsolete... it was necessay when coded in 8.8.1 but not now*/
		{
			doAuth(Conn,&REQ_AUTH); /* get Basic realm */
		}

		if( ident.i_error & AUTH_ENOSERV ){
			cc = putConfigError(Conn,tc,"Authentication");
			addAccHist(Conn,ACC_AUTH_CFGERR);
			return -1;
		}

		/* the resonse should be 407 if there is a PERMIT for the dst.
		 * protocol and server which is satisfied if an appropriate
		 * authentication is given.  otherwise the code should bd 403.
		 */
		if( 0 < auok ){
			int dstok,srcok;
			IStr(reason,128);
			strcpy(reason,Conn->reject_reason);
			dstok = isREACHABLE(DST_PROTO,DST_HOST);
	 		srcok = source_permitted(Conn);

			/* 9.9.1 port restriction by REMITTABLE typically by
			 * REMITTABLE=http/{80,443} should not be applied to
			 * the entrance ports of this DeleGate itself.
			 */
			if( ToMyself && dstok && srcok ){
				sv1log("IGN (%s) %s://%s:%d <- %s [%s]\n",
					reason,DST_PROTO,DST_HOST,DST_PORT,
					ClientAuthUser,Client_Host);
				goto AUTH_OK;
			}

			daemonlog("E",
			"Auth.OK but Forbidden (%d,%d) %s://%s:%d <- %s [%s]\n",
				dstok,srcok,DST_PROTO,DST_HOST,DST_PORT,
				ClientAuthUser,Client_Host);
			daemonlog("E","Forbidden (%s)\n",reason);
			if( !dstok /* || !srcok */ ){
				/* 9.6.0 never satisified with any auth. */
				cc = putHttpRejectmsg(Conn,tc,DST_PROTO,
					DST_HOST,DST_PORT,AVStr(REQ));
				http_Log(Conn,403,CS_AUTHERR,REQ,cc);
				clntClose(Conn,"f:forbidden");
				addAccHist(Conn,ACC_FORBIDDEN);
				return -3;
			}
		}

		cc = putNotAuthorized(Conn,tc,REQ,pauth,NULL,"");
		http_Log(Conn,Conn->statcode,CS_AUTHERR,REQ,cc);
		clntClose(Conn,"a:authentication failure");
		addAccHist(Conn,ACC_AUTH_DENIED);
		return -2;
	}
AUTH_OK:
	REQ_AUTH = ident;
	REQ_AUTH.i_stype = pauth ? AUTH_APROXY : AUTH_AORIGIN;

	/*
	if( ClientFlags & PF_MITM_ON ){
	*/
	if( (ServerFlags & PF_MITM_ON) && lFORWPAUTH() ){
		/* 9.7.0 - 9.8.4 dup. sent in Proxy-Auth for CONNECT ? */
	}else
	if( pauth )
		HTTP_delRequestField(Conn,"Proxy-Authorization");
	else	HTTP_delRequestField(Conn,"Authorization");
	return 0;
}
static int checkAUTH(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc,PCStr(proto),PCStr(site),int port,int mandatory)
{	int auth,pauth;
	int totalc;

	if( !Conn->from_myself && NotREACHABLE(Conn,proto,site,port) ){
		service_permitted2(Conn,proto,0); /* cause delayReject */
		totalc = putHttpRejectmsg(Conn,tc,proto,site,port,AVStr(REQ));
		http_Log(Conn,403,CS_AUTHERR,REQ,totalc);
		return -1;
	}
	if( authOK ){
		/* this is not necessary if doauth() has been done.
		if( service_permitted2(Conn,proto,1) == 0 ){
			sv1log("Authenticated but not Authorized/Permitted\n");
			if( 1 ){ // if correct auth. makes it succeed
				auth = 1;
				pauth = (ClientFlags & PF_AS_PROXY);
			}else{
				auth = pauth = 0;
			}
			goto FAILED;
		}
		*/
		return 0;
	}
	if( ClientAuthUser[0] != 0 )
	if( ClientAuth.i_stat & AUTH_MAPPED )
	{
		syslog_ERROR("??? AUTHORIZED ALREADY %X (%s)(%s)\n",
			ClientAuth.i_stat,ClientAuth.i_user,ClientAuth.i_Host);
/*
		return 0;
*/
	}

	 auth = auth_proxy_auth() || auth_origin_auth(/*Conn*/);
	pauth = auth_proxy_pauth();
	if( getMountAuthorizer(Conn,VStrNULL,0) ){
		auth |= MOUNT_AUTHORIZER;
	}
	if( mandatory && (auth || pauth) ){
		if(  auth && !findFieldValue(REQ_FIELDS,"Authorization")
		 || pauth && !findFieldValue(REQ_FIELDS,"Proxy-Authorization")
		)	goto FAILED;
	}

if( (auth & MOUNT_AUTHORIZER) == 0 )
	if( service_permitted2(Conn,proto,1) )
		return 0;

	if( auth || pauth ){
		if(HTTP_proxyAuthorized(Conn,REQ,REQ_FIELDS,pauth,tc)){
			const char *fname;
			if( pauth )
				fname = "Proxy-Authorization";
			else	fname = "Authorization";
			if( !forwardOK(Conn,FORWARD_AUTH,fname) )
				HTTP_delRequestField(Conn,fname);
			return 0;
		}

		if( !auth && pauth )
		if( WillKeepAlive && RequestSerno )
		{
			/* reuse Proxy-Authorization ? */
		}
	}

FAILED:
	service_permitted2(Conn,proto,0); /* cause delayReject */
	if( auth || pauth ){
		/*
		totalc = putNotAuthorized(Conn,tc,REQ,pauth,"</>","");
		*/
		totalc = putNotAuthorized(Conn,tc,REQ,pauth,NULL,"");
		http_Log(Conn,Conn->statcode,CS_AUTHERR,REQ,totalc);
	}else{
		totalc = putHttpRejectmsg(Conn,tc,proto,site,port,AVStr(REQ));
		http_Log(Conn,403,CS_AUTHERR,REQ,totalc);
	}
	return -1;
}

int doACCEPT(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	int rcc;

	if( !strcaseeq(REQ_METHOD,"ACCEPT") )
		return 0;

	if( lHTTPACCEPT() ){
		set_realserver(Conn,"htaccept","-",0);
		if( checkAUTH(Conn,QX,fc,tc,"htaccept","-",0,0) != 0 )
			return -1;
	}else{
	set_realserver(Conn,"tcprelay","-",0);
	if( checkAUTH(Conn,QX,fc,tc,"tcprelay","-",0,0) != 0 )
		return -1;
	}
	rcc = HTTP_ACCEPT(Conn,REQ,REQ_FIELDS,fc,tc);
	return 1;
}

int relaysxX(RelayCtrl *relayCtrl,int timeout,int sdc,int sdv[][2],int sdx[],int rccs[],IFUNCP funcv[],void *argv[]);
int relayfX(Connection *Conn,RelayCtrl *relayCtrl,FILE *fc,FILE *tc,FILE *fs,FILE *ts){
	int cc;
	CStr(buf,512);
	int fdv[2][2];
	int rcv[2];
	int rcode;
	int timeout;
	double St = Time();

	while( 0 < (cc = fgetBuffered(AVStr(buf),sizeof(buf),fc)) ){
		fputs(buf,ts);
	}
	fflush(ts);
	while( 0 < (cc = fgetBuffered(AVStr(buf),sizeof(buf),fs)) ){
		fputs(buf,tc);
	}
	fflush(tc);

	fdv[0][0] = fileno(fc);
	fdv[0][1] = fileno(ts);
	fdv[1][0] = fileno(fs);
	fdv[1][1] = fileno(tc);
	rcv[0] = rcv[1] = 0;
	timeout = IO_TIMEOUT * 1000;
	if( lSINGLEP() ){
		if( 10*1000 < timeout ){
			timeout = 10*1000;
		}
	}
        rcode = relaysxX(relayCtrl,timeout,2,fdv,NULL,rcv,NULL,NULL);
	if( lSINGLEP() && 5 < Time() - St ){
		if( lTRANSMIT() )
		fprintf(stderr,"-- %X CONNECT %s://%s:%d %dS/%dR/%d/%.3f\n",
			TID,DST_PROTO,DST_HOST,DST_PORT,
			rcv[0],rcv[1],RELAY_num_turns,Time()-St);
	}
	return rcv[1];
}
/*
static int idle_callback(double elps,int turns){
*/
static int idle_callback(RelayCtrl *relayCtrl,double elps,int turns){
	if( 5 <= elps ){
		checkCloseOnTimeout(0);
		stopStickyServer("httpCONNECT");
		RELAY_idle_cb = 0;
	}
	return (int)((5 - elps)*1000) + 1;
}

static void put_forbidden(Connection*,QueryContext*,FILE*,int);
static void closeCONNECT(Connection *Conn,FILE *fs,FILE *ts){
	int fsd,tsd;
	fsd = tsd = -1;

	finishServYY(FL_ARG,Conn);
	if( fs ){ fsd = fileno(fs); fcloseFILE(fs); }
	if( ts ){ tsd = fileno(ts); fcloseFILE(ts); }
	if( 0 <= fsd ) close(fsd);
	if( 0 <= tsd && tsd != fsd ) close(tsd);
	closed("closeCONNECT",tsd,fsd);
	if( tsd == ServerSock || fsd == ServerSock ){
		if( lCONNECT() )
		porting_dbg("closeCONNECT([%d][%d])[%d]",tsd,fsd,ServerSock);
		ServerSock = -1;
	}
}
static int retryCONNECT(Connection *Conn,FILE *fs,FILE *ts,FILE *fc,FILE *tc,int connerr,PVStr(rhead)){
	int ofsd,otsd;
	int hcode;

	if( lDONTHT() && connerr == 407 ){
		if( feof(fs) || ferror(ts) || !IsAlive(fileno(fs)) ){
			ofsd = fileno(fs);
			otsd = fileno(ts);
			if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
				sv1log("----NTHT reconnect failed\n");
				return connerr;
			}
			dup2(FromS,ofsd);
			dup2(ToS,otsd);
			close(FromS);
			if( FromS != ToS ) close(ToS);
			FromS = ofsd;
			ToS = otsd;
			clearerr(ts);
			clearerr(fs);
		}
		hcode = NTHT_connect(5,ToS,FromS,
			REQ,"","","",
			NTHT_utoken,NTHT_nego);
		if( hcode <= 200 ){
			connerr = 0;
			sprintf(rhead,"HTTP/1.0 %d\r\n\r\n",hcode);
			sv1log("----NTHT reconnect OK %d\n",hcode);
		}else{
			sv1log("----NTHT reconnect NG %d\n",hcode);
		}
	}
	return connerr;
}
static int doCONNECT(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	const char *rproto;
	CStr(rhost,MaxHostNameLen);
	int rport;
	CStr(ctype,128);
	FILE *ts,*fs;
	int vno;
	CStr(genfields,0x8000);
	CStr(shost,512);
	int sport;
	int relayany;
	CStr(statline,256);
	int statcode;
	int connerr = 0;
	IStr(pxa,128);
	int oldDGpx = 0;
	RelayCtrl relayCtrlBuf,*relayCtrl = &relayCtrlBuf;

	if( strncasecmp(REQ,"CONNECT",7) != 0 )
		return 0;

	ts = fs = 0;

	ClientFlags |= PF_DO_STICKY;
	DDI_proceedFromC(Conn,fc);

	rport = scan_hostportX("",REQ+8,AVStr(rhost),sizeof(rhost));
	if( rport <= 0 ){
		sv1log("CONNECT: Unknown Request? %s",REQ);
		return -1;
	}

	rproto = "ssltunnel";
	set_realserver(Conn,rproto,rhost,rport);

    if( lHTTPACCEPT() ){
	relayany = 1;
	if( service_permitted2(Conn,rproto,1) == 0 ){
		rproto = "https";
		set_realserver(Conn,rproto,rhost,rport);
		/* 9.9.2 for HTMUX=sv + REMITTABLE=+,https (9.9.0-pre1) */
	}
    }else
    if( lNOSSLCHECK() ){
	Conn->no_dstcheck_proto = serviceport("ssltunnel");
	relayany = 1;
    }else{
	if( !do_RELAY(Conn,RELAY_PROXY) ){
		strcpy(Conn->reject_reason,"NO RELAY=proxy");
		put_forbidden(Conn,QX,tc,1);
		return -1;
	}

	relayany = service_permitted2(Conn,rproto,1);
	if( !relayany )
		rproto = "https";

	set_realserver(Conn,rproto,rhost,rport);
    }
	if( checkAUTH(Conn,QX,fc,tc,rproto,rhost,rport,0) != 0 )
	{
		addAccHist(Conn,ACC_FORBIDDEN);
		return -1;
	}
	addAccHist(Conn,ACC_OK);/* not set in serivce_permitted2(silent) */
				/* & will not set hereafter with from_myself */

	if( !relayany ){
	    CStr(conf,256);
	    if( 0 <= find_CMAP(Conn,"HTTPCONF",AVStr(conf)) ){
		if( isinListX(conf,"thru-CONNECT","c") ){
			sv1log("WARNING: CONNECT [%s] %s://%s:%d <- %s:%d\n",
				conf,rproto,DST_HOST,DST_PORT,
			Client_Host,Client_Port);
			relayany = 1;
		}
	    }
	}

	/* close ServPort because it might not be released for long time
	 * in relay_svcl()
	 */
	/* 9.6.0 replaced by idle_callback() */
	/*
	checkCloseOnTimeout(0);
	stopStickyServer("httpCONNECT");
	*/

	Conn->from_myself = 1; /* permission already checked by checkAUTH() */
	Conn->from_client = 1;
	set_realserver(Conn,"https",rhost,rport);
	setConnStart(Conn);

	if( MountSpecialResponse(Conn,tc) ){
		/* 9.9.8 MOUNT="hostPattern:* = forbidden" */
		return 2;
	}

	/* 9.2.0
	 * don't apply STLS="fsv:https" for CONNECT method
	 * if it's necessary, it can be done with CMAP=sslway:FSV:https ...
	 */
	if( (ServerFlags & PF_STLS_CHECKED) == 0 )
	{
		Verbose("## disabled STLS=fsv for CONNECT\n");
		ServerFlags |= PF_STLS_CHECKED;
	}

	if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
		putHttpCantConnmsg(Conn,tc,rproto,rhost,rport,OREQ);
		http_Log(Conn,500,CS_CONNERR,REQ,0);
		return -1;
	}

if( 0 <= ToSX )
	set_nodelay(ToSX,1);
else	set_nodelay(ToS,1);
set_nodelay(ClientSock,1);

	setConnDone(Conn);
	genProxyReqFields(Conn,AVStr(genfields),NULL);

	fs = fdopen(FromS,"r");
	truncVStr(statline);
	statcode = -1;

	if( toMaster || toProxy ){
		if( ToServ )
			ts = ToServ;
		else	ts = fdopen(ToS,"w");
		fputs(REQ,ts);
		fputs(genfields,ts);
		fputs(REQ_FIELDS,ts);
		fflush(ts);
		{	CStr(line,256);
			IStr(rhead,2*1024);
			refQStr(rp,rhead);
			int fnlen;

			while( fgets(line,sizeof(line),fs) != NULL ){
				Verbose("S-C %s",line);
				if( statline[0] == 0 ){
					strcpy(statline,line);
					statcode = 0;
					sscanf(line,"%*s %d",&statcode);
					if( statcode != 200 ){
						connerr = statcode;
						sv1log("## S-C %s",line);
					}

				/*
				if( HTTP11_toclient == 0 )
				*/
				if( HTTP11_toclient == 0 || connerr )
				if( strncmp(line,"HTTP/1.",7) == 0 )
				if( line[7] != '0' )
					line[7] = '0';
				}else
				if( strneq(line,"Connection:",11) ){
					if( connerr ){
					strcpy(line,"Connection: close\r\n");
					}
				}
				if( strneq(line,"Proxy-Agent:",12) ){
					sv1log("CONNECT -> %s",line);
					lineScan(line+12,pxa);
				}
				if( fnlen = STRH(line,F_PAuthenticate) ){
					if( lDONTHT() ){
						sv1log("----NTHT %s",line);
						continue;
					}
				}
				if( lDONTHT() && connerr ){
					Rsprintf(rp,"%s",line);
				}else
				fputs(line,tc);
				if( line[0] == '\r' || line[0] == '\n' )
					break;
			}

			/*
			 * Ignore surplus CRLF after header generated by an
			 * upstream DeleGate of old version (6.1.5 to 7.8.3)
			 */
			if( !feof(fs) && ready_cc(fs) ){
				int ch;
				ch = getc(fs);
				if( ch != '\r' ){
					ungetc(ch,fs);
				}else{
					ch = getc(fs);
					if( ch != '\n' ){
						ungetc(ch,fs);
						ungetc('\r',fs);
					}else{
				sv1log("##IGNORED surplus CRLF from server.\n");
					}
				}
			}

			/* 9.1.1 retrying after auth. err. should be the
			 * default, and necessary for Digest and NTHT auth.
			 */
			if( lDONTHT() && connerr ){
				connerr = retryCONNECT(Conn,fs,ts,fc,tc,
					connerr,AVStr(rhead));
				fputs(rhead,tc);
				fflush(tc);
			}
/*
This is not good with buggy upstream DeleGate which returns duplicate
CRLFs as Connection:close<CRLF><CRLF><CRLF>
			fflush(tc);
			... 8.9.1: this fflush() become harmless by skipping
			surplus CRLF like above, and become necessary not to
			freeze on detection of greeting message
			from non-HTTP servers (since 8.8.8)
*/
			fflush(tc);
		}
	}else{
		ts = fdopen(ToS,"w");
		vno = HTTP_reqIsHTTP(Conn,REQ);
		if( 100 <= vno ){
			CStr(line,256);
			fprintf(tc,"HTTP/%s 200 Connection established.\r\n",
				HTTP11_toclient==0 ? "1.0":
				MY_HTTPVER);
			clntClose(Conn,"C:CONNECT method");
			if( getKeepAlive(Conn,AVStr(line)) )
				fputs(line,tc);
			fprintf(tc,"Proxy-Agent: DeleGate/%s\r\n",
				DELEGATE_ver());
/*
This code generates a surplus <CRLF>
				fprintf(tc,"%s\r\n",line);
*/
			if( lHTTPACCEPT() ){
				IStr(host,MaxHostNameLen);
				IStr(peer,MaxHostNameLen);
				gethostName(ToS,AVStr(host),"%A:%P");
				getpeerName(ToS,AVStr(peer),"%A:%P");
				fprintf(tc,"X-Host: %s\r\n",host);
				fprintf(tc,"X-Peer: %s\r\n",peer);
			}
			fprintf(tc,"\r\n");
			fflush(tc);
		}
	}

	sport = getClientHostPort(Conn,AVStr(shost));

	if( connerr ){
		daemonlog("F","WARNING: CONNECT to %s:%d failed (%d) <=%s:%d\n",
			DST_HOST,DST_PORT,connerr,shost,sport);
		if( connerr <= 0 )
			connerr = 500;
		fprintf(tc,"CONNECT failure in the upstream proxy (%d)\r\n",
			connerr);
		http_Log(Conn,connerr,CS_AUTHERR,REQ,0);
		strcpy(Conn->reject_reason,"CONNECT failure in upstream");
		HTTP_delayReject(Conn,REQ,"",1);
		closeCONNECT(Conn,fs,ts);
		return -1;
	}
	/* if( DST_PORT == 443 ) */
	if( relayany && lHTTPACCEPT() ){
		/* anything should be relayed without detection */
	}else
	if( fpoll2(10*1000,fc,fs) & 2 ){
	    if( !IsAlive(fileno(fs)) ){ /* v9.9.12 new-140823e */
			daemonlog("E","CONNECT reset by server //%s:%d => %s:%d\n",
				DST_HOST,DST_PORT,shost,sport);
			http_Log(Conn,500,CS_EOF,REQ,0);
			closeCONNECT(Conn,fs,ts);
			return -1;
	    }else{
		/* response from the server before sending request */
		daemonlog("F","WARNING: //%s:%d seems not HTTPS <=%s:%d\n",
			DST_HOST,DST_PORT,shost,sport);
		if( !relayany ){
			http_Log(Conn,403,CS_AUTHERR,REQ,0);
			strcpy(Conn->reject_reason,"server seems not HTTPS");
			HTTP_delayReject(Conn,REQ,"",1);
			closeCONNECT(Conn,fs,ts);
			return -1;
		}
	    }
	}
	else
	if( !relayany && lHTTPSCLONLY() ){ /* 9.9.6 -Ess */
		int isinSSL(int fd);
		if( isinSSL(fileno(fc)) ){
		}else{
			http_Log(Conn,403,CS_AUTHERR,REQ,0);
			strcpy(Conn->reject_reason,"client seems not HTTPS");
			HTTP_delayReject(Conn,REQ,"",1);
			closeCONNECT(Conn,fs,ts);
			return -1;
		}
	}

	/*
	ProcTitle(Conn,"https://%s:%d/)",rhost,rport);
	*/
	ProcTitle(Conn,"https://%s:%d/",rhost,rport);
	ctype[0] = 0;

	bzero(&relayCtrlBuf,sizeof(RelayCtrl));
	RELAY_ctrl = 0;
	RELAY_num_paras = 0;

	if( (ConnType == 'p' || ConnType == 'm' )
         && (pxa[0]==0 || strneq(pxa,"DeleGate/",9) && vercmp(pxa+9,"9.6.0")<0)
	){
		oldDGpx = 1;
		RELAY_concat = 30;
		RELAY_max_paras = HTTP_MAX_PARAS_PROXY;
	}else{
		RELAY_concat = 1;
		RELAY_max_paras = HTTP_MAX_PARAS;
	}

	if( relayany ){
		if( HTTP_opts & HTTP_NOPIPELINE )
			RELAY_ctrl |= RELAY_HALFDUP;
		if( HTTP_opts & HTTP_TOUTPACKINTVL )
			RELAY_max_packintvl = HTTP_TOUT_PACKINTVL;
	}else{
		if( HTTP_opts & HTTP_NOPIPELINE ){ /* mod-140716d "HTTPCONF=halfdup" */
		RELAY_ctrl |= RELAY_HALFDUP;
		}
		if( lBLOCKNONSSL() ){ /* mod-140518a */
			RELAY_ctrl |= RELAY_SSL_ONLY;
		}
		if( lPEEKSSL() ){ /* new-140518b */
			RELAY_ctrl |= RELAY_SSL_PEEK;
		}
		RELAY_max_packintvl = HTTP_TOUT_PACKINTVL;
		if( HTTP_MAX_SSLTURNS ){ /* mod-140518e */
			RELAY_max_turns = HTTP_MAX_SSLTURNS;
		}else
		RELAY_max_turns = 6 + HTTP_CKA_MAXREQ*2;
		/* should check the handshake of SSL here ... */
		RELAY_thru_time = 5;
	}

	if( strcaseeq(CLNT_PROTO,"https") )
	if( rport == 80 )
	if( HTTP_STARTTLS_withCL(Conn,fc,tc) ){
		/* seems to be relaying https://serv:80 to http://serv
		/* so the request/response should be rewritten
		 * with MOUNT="https://host:80/* http://host/*
		 */
		sv1log("## HTTPS client to HTTP server\n");
	}

	/*
	if( lSINGLEP() && !lMULTIST() ){
	*/
	if( (lSINGLEP()||lFXNUMSERV()) && !lMULTIST() ){
		/* in single thread/process, to detect the next accept */
		int ServSock();
		double St = Time();
		if( lCONNECT() )
		fprintf(stderr,"--{c} CONNECT relay start[%d]%s:%d <= %s:%d\n",
			fileno(ts),DST_HOST,DST_PORT,shost,sport
		);
		RELAY_setxfd(ServSock());
		/*
		QX_totalc = relayf_svcl(Conn,fc,tc,fs,ts);
		*/
		QX_totalc = relayfX(Conn,relayCtrl,fc,tc,fs,ts);
		if( lCONNECT() )
		fprintf(stderr,"--{c} CONNECT %d/%d turns (%.3f) i%.3f F%d\n",
			RELAY_num_turns,RELAY_max_turns,Time()-St,
			RELAY_packintvl,(RELAY_stat&RELAY_NOTHALFDUP)
		);
	}else{
	RELAY_idle_cb = idle_callback;
	/*
	QX_totalc = relayf_svcl(Conn,fc,tc,fs,ts);
	*/
	QX_totalc = relayfX(Conn,relayCtrl,fc,tc,fs,ts);
	RELAY_idle_cb = 0;
	}
	if( RELAY_max_turns && RELAY_max_turns <= RELAY_num_turns ){
		daemonlog("E","WARNING: %d/%d turns / CONNECT %s:%d <= %s:%d\n",
			RELAY_num_turns,RELAY_max_turns,
			DST_HOST,DST_PORT,shost,sport);
	}
	RELAY_max_turns = 0; 
	if( RELAY_max_packintvl && RELAY_max_packintvl <= RELAY_packintvl ){
	daemonlog("E","WARNING: %f/%f tout-pack-intvl / CONNECT %s:%d <= %s:%d\n",
			RELAY_packintvl,RELAY_max_packintvl,
			DST_HOST,DST_PORT,shost,sport);
	}
	RELAY_max_packintvl = 0; 
	if( RELAY_ctrl & RELAY_HALFDUP ){
		/*
		if( RELAY_stat != 0 ){
		*/
		if( RELAY_stat & RELAY_NOTHALFDUP ){
		daemonlog("F","WARNING: non-half-dup CONNECT %s:%d <= %s:%d\n",
			DST_HOST,DST_PORT,shost,sport);
			strcpy(Conn->reject_reason,"non-half-dup CONNECT");
			if( oldDGpx ){
				/* delay might be in the upstream proxy */
			}else
			HTTP_delayReject(Conn,REQ,"",1);
		}
		RELAY_ctrl = 0;
	}

	httpStat = CS_WITHOUTC;
	http_log(Conn,rproto,rhost,rport,REQ,200,ctype,QX_totalc,0,
		CONN_DONE-CONN_START,Time()-CONN_DONE);
	closeCONNECT(Conn,fs,ts);
	/*
	close(ToS);
	close(FromS);
	*/
	return 1;
}

void HTTP_reject(Connection *Conn,PCStr(why),PCStr(how));
static int nonHTTP(Connection *Conn,FILE *ftc[2],PVStr(request))
{	CStr(method,32);
	CStr(methods,256);
	refQStr(dp,request); /**/
	char dc;
	FILE *fc,*tc;
	const char *errmsg;
	CStr(erequest,URLSZ);

	fc = ftc[0];
	tc = ftc[1];
	errmsg = "not in HTTPCONF=methods";

	dp = wordScan(request,method);
	dc = *dp;
	if( dc != 0 && dc != ' ' && dc != '\t' && dc != '\r' && dc != '\n' )
		goto non_http;

	if( strcaseeq(method,"XECHO") ){
		if( isspace(*dp) )
			dp++;
		doXECHO(tc,dp);
		return 1;
	}

	if( strcaseeq(method,"X-CACHE-GET") ){
		GET_CACHE = 1;
		ovstrcpy((char*)request,request+8);
		return 0;
	}
	/* destination is not set yet ...
	if( !method_permitted(Conn,"http",method,1) ){
		if( Conn->reject_reason[0] )
			errmsg = Conn->reject_reason;
		else	errmsg = "forbidden method";
		sv1log("forbidden HTTP/%s (%s)\n",method,errmsg);
		goto non_http;
	}
	*/

	if( HTTP_allowMethod1(Conn,request) )
		return 0;

	if( strcaseeq(method,"!SET") ){
		DELEGATE_setenv(fc,tc,request);
		return 1;
	}

	if( isHelloRequest(request)
	 || VSAP_isMethod(request)
	 || streq(method,"HELO")
	 || streq(method,"CPORT")
	 || streq(method,"PARAM")
	 || streq(method,"FTPGET")
	){
		sv1log("---- WARNING! HTTP switched to GENERALIST[%s]\n",
			method);
		signal(SIGPIPE,SIG_DFL);
		DDI_proceedFromC(Conn,fc);
		beGeneralist(Conn,fc,tc,request);
		ftc[0] = ftc[1] = 0; /* fclose() in beGeneralist() */
		return 1;
	}

non_http:
/*
	sv1log("#### Method Not Allowed: %s",request);
*/
	HTTP_reject(Conn,"Method not allowed",errmsg);
	fprintf(tc,"HTTP/%s 405 Method Not Allowed\r\n",MY_HTTPVER);
	HTTP_allowMethods(Conn,AVStr(methods));
	fprintf(tc,"Allow: %s\r\n",methods);
	fprintf(tc,"Connection: close\r\n");
	fprintf(tc,"Content-Type: text/plain\r\n");
	fprintf(tc,"Content-Transfer-Encoding: quoted-printable\r\n");
	fprintf(tc,"\r\n");
	url_escapeX(request,AVStr(erequest),sizeof(erequest),"","\r\n");
	/*
	fprintf(tc,"Method Not Allowed: %s\r\n",erequest);
	*/
	QPfprintf(tc,"<>'\"","Method Not Allowed: %s",erequest);
	fprintf(tc,"\r\n");
	return 1;
}
void HTTP_reject(Connection *Conn,PCStr(why),PCStr(how))
{	CStr(shost,MaxHostNameLen);
	CStr(req,128);
	int sport;

	sport = getClientHostPort(Conn,AVStr(shost));
	lineScan(REQ,req);
	daemonlog("F","E-P: %s: %s:%d => %s (%s)\n",why,shost,sport,req,how);
}

static void gotNullRequest(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	CStr(clhost,MaxHostNameLen);

	if( getClientHostPort(Conn,AVStr(clhost)) == 0 )
		strcpy(clhost,"?");
	if( REQ[0] != 0 && clientIsReset("gotNullRequest",Conn,1) ){
		sv1log("already disconnected (%s)\n",clhost);
		http_Log(Conn,500,CS_ERROR,REQ,0);
	}else{
	sv1log("HTTP empty_request ? from %s (%d)\n",clhost,Conn->cl_count);
	http_Log(Conn,500,CS_ERROR,"ERR /empty_request",0);
	}
	delayConnError(Conn,REQ);
}
static int rewriteRequest(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{ 
	if( rewrite_request(Conn,fc) == NULL ){
		gotNullRequest(Conn,QX,fc,tc);
		setCLX("QW",CLX_AFTER_REQ_REWRITING);
		return -1;
	}
	return 0;
}
static int checkCookie(Connection *Conn)
{	MrefQStr(val,REQ_FIELDS); /**/

	if( val = findFieldValue(REQ_FIELDS,"Cookie") ){
		MountCookieRequest(Conn,OREQ,AVStr(val));
		if( (HTTP_cacheopt & CACHE_COOKIE) == 0 ){
			DontReadCache = 1;
			DontWriteCache = 1;
		}
		withCookie = 1;
	}else	withCookie = 0;
	return 0;
}
static int DELAY_RESPCLOSE = 0;
int requestToMe(Connection *Conn){
	if( REQ_URL[0] == '/' )
	if( Ismyself(Conn,DST_PROTO,DST_HOST,DST_PORT) )
	{
		return 1;
	}
	return 0;
}
static int doMyself(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc,FILE *ftc[2])
{	int stcode;
	int mtime;
	CStr(ctype,256);
	double start;

	if( ToMyself && (Conn->sv_retry & SV_RETRY_DONE) ){
		/* 9.5.7 retrying in MITM */
	}else
	/*
	if( (ClientFlags|ServerFlags) & PF_MITM_ON ){
	*/
	if( ((ClientFlags|ServerFlags) & PF_MITM_ON) && !requestToMe(Conn) ){
		/* (ClientFlags & PF_MITM_ON) is left true in Keep-Alive */
		return 0;
	}

	if( isMYSELF(QX_site) )
		ToMyself = 1;

	if( strstr(REQ,"?-_-") )
		ToMyself = 1;

	if( !ToMyself )
		return 0;

	Conn->no_dstcheck_port = 1; /* 9.9.7 permit origin server's -Pxxx */
	if( auth_origin_auth(/*Conn*/)
	 || getMountAuthorizer(Conn,VStrNULL,0)
	){
		if( checkAUTH(Conn,QX,fc,tc,QX_proto,QX_site,QX_port,1) != 0 )
			return 1;
	}

	/* is public thus permission is not necessary? */
	stcode = 200;
	start = Time();
	mtime = 0;

	if( (Conn->xf_filters & XF_FTOCL) == 0 ){
		if( sav_FTOCL )
			setFTOCL(sav_FTOCL);
		tc = insertFTOCL_X(Conn,tc);
		ftc[1] = tc;
		setFTOCL(NULL);
	}

	if( QX_totalc = HttpToMyself(Conn,AVStr(REQ),REQ_FIELDS,fc,tc,&stcode) ){
		CONN_DONE = CONN_START = start;
		if( httpStat == 0 )
			httpStat = CS_INTERNAL;
		ctype[0] = 0;
		http_log(Conn,DST_PROTO,DST_HOST,DST_PORT,REQ,
			stcode,ctype,QX_totalc,mtime, 0.0,Time()-start);
		if( DELAY_RESPCLOSE ){
			fflush(tc);
			sv1log("## SLEEP BEFORE CLOSE: %d\n",DELAY_RESPCLOSE);
			sleep(DELAY_RESPCLOSE);
		}
		return 1;
	}

	return 0;
}
static const char *getuserpass(Connection *Conn,PCStr(site),PVStr(uuser),PVStr(upass),xPVStr(auth),int asiz)
{	const char *host;
	const char *dfltuser;
	CStr(authb,512);
	CStr(myauth,256);
	CStr(myauthx,1024);

	/*
	 * HTTPCONF=dfltuser-ftp:name might be necessary...
	 */

	if( CTX_with_auth_anonftp(Conn) ) /* AUTH=anonftp */
		dfltuser = "anonymous";
	else	dfltuser = "";
	host = scan_url_userpass(site,AVStr(uuser),AVStr(upass),dfltuser);

	if( asiz == 0 ){
		asiz = sizeof(authb);
		setPStr(auth,authb,sizeof(authb)); /* for cache hit */
	}
	HTTP_authuserpass(Conn,AVStr(auth),asiz);

	if( IsMounted && uuser[0] && upass[0] ){
		/* 9.7.5 ftp://user:pass@serv/ in rURL of a MOUNT */
		IStr(uu,256);
		IStr(up,256);
		strfConnX(Conn,uuser,AVStr(uu),sizeof(uu));
		strfConnX(Conn,upass,AVStr(up),sizeof(up));
		strcpy(uuser,uu);
		strcpy(upass,up);
		clearVStr(auth); /* it should not be used */
	}else
	if( get_MYAUTH(Conn,AVStr(myauth),"ftp",DST_HOST,DST_PORT) ){
		strfConnX(Conn,myauth,AVStr(myauthx),sizeof(myauthx));
		scan_field1(myauthx,AVStr(uuser),64,AVStr(upass),64);
	}

	if( strcmp(uuser,"-auth") == 0
	 || *uuser == 0 && auth == authb /* for cache hit */
	){
		scan_field1(auth,AVStr(uuser),256,AVStr(upass),256);
	}
	if( *uuser == 0 ){
		if( *auth )
			wordscanY(auth,AVStr(uuser),256,"^:");
		if( *uuser == 0 )
			strcpy(uuser,"anonymous");
	}
	return host;
}

static FileSize HttpFtp(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc,int svsock,PCStr(server),int iport,PCStr(req),int *stcodep)
{	const char *method;
	const char *ver;
	HttpRequest reqx;
	MrefQStr(path,reqx.hq_url); /**/
	CStr(gpath,1024);
	char gtype;
	CStr(user,256);
	CStr(pass,256);
	CStr(auth,512);
	const char *host;

	Conn->body_only = !HTTP_reqWithHeader(Conn,req);
	decomp_http_request(req,&reqx);
	method = reqx.hq_method;
	ver = reqx.hq_ver;

	lineScan(path,gpath);
	gtype = get_gtype(gpath,AVStr(path));

/*
	host = scan_url_userpass(server,user,pass,"anonymous");
	HTTP_authuserpass(Conn,auth,sizeof(auth));
*/
	host = getuserpass(Conn,server,AVStr(user),AVStr(pass),AVStr(auth),sizeof(auth));

	return httpftp(Conn,fc,tc,ver,method,svsock,
		auth,user,pass,host,iport,gtype,path,stcodep);
}
static int HttpFinger(Connection *Conn,int vno,int sv,PCStr(server),int iport,PCStr(path))
{
	if( sv == -1 )
		return 0;
	return httpfinger(Conn,sv,server,iport,path,vno);
}
static void http_gateway(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc,int sv)
{	const char *proto = QX_proto;
	const char *server = QX_site;
	int iport = QX_port;
	MrefQStr(req,REQ); /**/
	const char *method;
	HttpRequest reqx;
	MrefQStr(path,reqx.hq_url); /**/
	const char *ver;
	CStr(user,256);
	CStr(pass,256);
	CStr(request,URLSZ);
	CStr(rserver,MaxHostNameLen);
	CStr(hostport,MaxHostNameLen);
	AuthInfo ident;
	int vno;
	int msock;
	int rcode;
	FileSize rtotal;
	CStr(ctype,128);
	char gtype;
	const char *dp;
	int qlen;

	Where = "Gatewaying";
	nsigPIPE = 0;

	vno = decomp_http_request(req,&reqx);
	method = reqx.hq_method;
	ver = reqx.hq_ver;
	HostPort(AVStr(hostport),proto,server,iport);

	rcode = 200;
	ctype[0] = 0;
	rtotal = 0;
	setConnStart(Conn);
	msock = -1;
	DDI_proceedFromC(Conn,fc);

	qlen = strlen(OREQ);
	if( HTTP_GW_MAX_REQLINE < qlen ){
		sv1log("## HTTPCONF=%s:%d<%d -- %s",
			HTTP_GW_MAX_REQLINE_sym,HTTP_GW_MAX_REQLINE,qlen,OREQ);
		putBadRequest(Conn,tc,"request-line-too-long");
		return;
	}

	/* if( strcaseeq(proto,"ftp") || strcaseeq(proto,"file") ) */
	/*
	if( strcaseeq(proto,"ftp") ){
	*/
	if( strcaseeq(proto,"ftp") || strcaseeq(proto,"sftp") ){
		setConnDone(Conn);
		get_gtype(path,AVStr(path));
		rtotal = HttpFtp(Conn,QX,fc,tc,sv,server,iport,req,&rcode);
		sprintf(request,"%s %s://%s%s%s HTTP/%s",method,proto,hostport,
			(*path=='/'?"":"/"),path,ver);
		goto EXIT;
	}

	/*
	sprintf(request,"GET %s://%s",proto,hostport);
	*/
	sprintf(request,"%s %s://%s",method,proto,hostport);
	if( *path == '/' )
		strcat(request,path);
	Xsprintf(TVStr(request)," HTTP/%s",ver);

	if( strcaseeq(proto,"wais") ){
		setConnDone(Conn);
		rtotal = HttpWais(Conn,vno,sv,server,iport,path);
		/*goto EXIT;*//* log was done in HttpWais */
		return;
	}
	if( strcaseeq(proto,"finger") ){
		setConnDone(Conn);
		rtotal = HttpFinger(Conn,vno,sv,server,iport,path);
		goto EXIT;
	}
	if( strcaseeq(proto,"news") || strcaseeq(proto,"nntp")
	 || strcaseeq(proto,"pop") ){
		setConnDone(Conn);
		if( path[0] == '/' )
			ovstrcpy((char*)path,path+1);
		else
		if( strncasecmp(path,"news:",5) == 0 )
			ovstrcpy((char*)path,path+5);

		HTTP_getAuthorization(Conn,0,&ident,0);
		rtotal = HttpNews(Conn,vno,fc,sv,server,iport,path,request,
				AVStr(ident.i_user),AVStr(ident.i_pass),
				ClntKeepAlive&&WillKeepAlive,&rcode);

		if( dp = strchr(ident.i_user,'@') ){
			server = dp + 1;
		}
		goto EXIT;
	}
	if( strcaseeq(proto,"whois") ){
		if( 100 <= vno ){
			putHEAD(Conn,tc,200,"Whois/HTTP gateway",NULL,
				"text/plain",NULL,0,-1,-1);
			fputs("\r\n",tc);
			fflush(tc);
		}
		sprintf(req,"whois://%s?%s\r\n",hostport,*path=='/'?path+1:path);
		DDI_pushCbuf(Conn,req,strlen(req));
		service_whois(Conn);
		goto EXIT;
	}

	if( protoGopher(proto) ){
		if( gtype = decomp_gopherURL(Conn,req,AVStr(path)) ){
			vno = HTTP_reqIsHTTP(Conn,req);
			rtotal = HttpGopher(Conn,vno,sv,server,iport,gtype,path);
			sprintf(request,"GET %s://%s/%s",proto,hostport,path);
			goto EXIT;
		}
	}
	sprintf(request,"GET %s://%s/%s",proto,hostport,path);

	if( 0 <= (msock = openMaster(Conn,sv,server,1)) ){
		setConnDone(Conn);
		if( protoGopher(proto) )
			rtotal = relay_svcl(Conn,-1,ToC,msock,-1 /*,1,512*/);
		else	rtotal = relay_svcl(Conn,FromC,ToC,msock,msock /*,1,512*/);
	}else{
		sv1log("ERROR: cannot connect to a MASTER\n");
		rcode = 403;
		rtotal = 0;
	}

EXIT:
	if( Conn->statcode )
		rcode = Conn->statcode;

	if( 0 < Conn->sv.p_range[0] ){
		rcode = 206;
		rtotal = Conn->sv.p_range[1] - Conn->sv.p_range[0] + 1;
	}

	http_log(Conn,proto,server,iport,request,rcode,ctype,rtotal,0,
		CONN_DONE-CONN_START,Time()-CONN_DONE);

	if( nsigPIPE ){
		clntClose(Conn,"p:premature client EOF on gatewaying");
		setClientEOF(Conn,tc,"gatewaying_%s.SIGPIPE",proto);
	}
}
static int doFtpCached(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	const char *method;
	const char *path;
	const char *ver;
	HttpRequest reqx;
	CStr(user,256);
	CStr(pass,256);
	const char *host;
	int vno;
	int rc;

	vno = decomp_http_request(REQ,&reqx);
	method = reqx.hq_method;
	path = reqx.hq_url;
	ver = reqx.hq_ver;

	if( vno < 100 )
		return 0;
	if( !streq(method,"GET") )
		return 0;

/*
	host = scan_url_userpass(QX_site,user,pass,"anonymous");
*/
	host = getuserpass(Conn,QX_site,AVStr(user),AVStr(pass),VStrNULL,0);
	if( is_anonymous(user) && *pass == 0 ){
		AuthInfo ident;
		if( HTTP_getAuthorization2(Conn,&ident,0) )
			textScan(ident.i_pass,pass);
		if( *pass == 0 )
			strcpy(pass,"-");
	}

	rc = 200;
	if( QX_totalc = httpftp_cached(Conn,tc,user,pass,host,QX_port,path,&rc) ){
		http_Log(Conn,rc,CS_HITCACHE,REQ,QX_totalc);
		return 1;
	}
	return 0;
}

#define LOADING "#LOADING"
static int genIfModifiedC(Connection *Conn,QueryContext *QX,PCStr(cpath)){
	CStr(ocpath,URLSZ);
	refQStr(dp,ocpath);
	FILE *fp;
	int cdate;

	if( HTTP_opts & HTTP_OLDCACHE )
		return 0;
	if( strtailstr(cpath,LOADING) == 0 )
		return 0;

	strcpy(ocpath,cpath);
	if( dp = strtailstr(ocpath,LOADING) ){
		truncVStr(dp);
		fp = expfopen("HTTP",CACHE_DONTEXP,AVStr(ocpath),"r",&cdate);
		if( fp ){
			genIfModified1(Conn,fp,ocpath,cdate);
			fclose(fp);
			return 1;
		}
	}
	return 0;
}
static void genIfModified(Connection *Conn,QueryContext *QX,FILE *cachefp,PCStr(cpath),int cdate)
{
	if( QX_cdate != -1 ){
		/* 9.8.2 don't generate If-Mod based on an error message */
		if( 400 <= QX_cacheretcode ){
			switch( QX_cacheretcode ){
				case 404:
				case 410:
				case 501:
					break;
				default:
					return;
			}
		}
	}
	if( genIfModifiedC(Conn,QX,cpath) ){
		/* generated If-Mod based on the cache in update */
		return;
	}
	/* generating If-Mod maybe without a cache */
	genIfModified1(Conn,cachefp,cpath,cdate);
}

/*
 * make shift with the cache (not in reload and QX_cdate != -1)
 */
static void makeshift(Connection *Conn,QueryContext *QX,FILE *tc,FILE *fc){
	refQStr(dp,QX_cpath);
	int rcode;

	if( dp = strtailstr(QX_cpath,LOADING) ){
		FILE *fp;
		int cdate;

		stopDistribution(Conn,QX_cachefp,QX_cpath);
		rcode = unlink(QX_cpath);
		truncVStr(dp);
		if( fp=expfopen("HTTP",CACHE_DONTEXP,AVStr(QX_cpath),"r",&cdate) ){
			if( QX_cachefp ){
				dup2(fileno(fp),fileno(QX_cachefp));
				fclose(fp);
			}else{
				QX_cachefp = fp;
			}
		}
	}
	rcode = relay_response(Conn,QX,0,QX_proto,QX_site,QX_port,REQ,
		QX_cpath,1,QX_cachefp,tc,fc,NULL,1);
}
static FILE * popCurrentCache(Connection *Conn,ResponseContext *RX){
	CStr(cpath,URLSZ);
	const char *dp;
	FILE *fp;
	int cdate;

	if( (dp = strtailstr(RX_cpath,LOADING)) == 0 )
		return RX_cachefp;

	if( RX_cachefp ){
		stopDistribution(Conn,RX_cachefp,RX_cpath);
		unlink(RX_cpath);
	}

	strcpy(cpath,RX_cpath);
	if( dp = strtailstr(cpath,LOADING) )
		truncVStr(dp);

	fp = expfopen("HTTP",CACHE_DONTEXP,AVStr(cpath),"r+",&cdate);
	/* "+" might be necessary for ftouch() */
	Verbose("{L} verified %d %s\n",fp!=NULL,cpath);

	if( fp ){
		if( RX_cachefp && isWindows() ){
			RX_cachefp = fp;
			RX_cachefpSav = fp; /* to be closed by the caller */
		}else
		if( RX_cachefp ){
			dup2(fileno(fp),fileno(RX_cachefp));
			fclose(fp);
		}else{
			RX_cachefp = fp;
		}
	}
	return RX_cachefp;
}
/*
 * if there is a cache, might be obsolete, but can be used to makeshift.
 */
static int cacheReadOK(Connection *Conn,ResponseContext *RX){
	FILE *cachefp = RX_cachefp;

	if( (HTTP_opts & HTTP_OLDCACHE) == 0 ){
		if( RX_cpath )
			cachefp = popCurrentCache(Conn,RX);
	}

	if( cachefp == NULL )
		return 0;
	if( file_size(fileno(cachefp)) <= 0 )
		return 0;

	/* should check broken or not ? */
	return 1;
}
static int HTcache_make(Connection *Conn,QueryContext *QX){
	CStr(xcpath,URLSZ);

	if( HTTP_opts & HTTP_OLDCACHE ){
		QX_cachefp = cache_fopen_rw("HTTP",AVStr(QX_cpath));
		return QX_cachefp != NULL;
	}
	if( strtailstr(QX_cpath,LOADING) ){
		strcpy(xcpath,QX_cpath);
	}else	sprintf(xcpath,"%s%s",QX_cpath,LOADING);
	if( QX_cachefp = cache_fopen_rw("HTTP",AVStr(xcpath)) ){
		strcpy(QX_cpath,xcpath);
		CacheControl |= CACHE_RENAME;
		return 1;
	}
	return 0;
}
static FILE *recvDistributionX(Connection *Conn,QueryContext *QX,int *updated){
	FILE *rfp;
	CStr(xcpath,URLSZ);

	if( HTTP_opts & HTTP_OLDCACHE ){
		rfp = recvDistribution(Conn,QX_cpath,updated);
		return rfp;
	}
	if( strtailstr(QX_cpath,LOADING) ){
		rfp = recvDistribution(Conn,QX_cpath,updated);
	}else{
		sprintf(xcpath,"%s%s",QX_cpath,LOADING);
		rfp = recvDistribution(Conn,xcpath,updated);
	}
	return rfp;
}
static void CacheClose(QueryContext *QX){
	if( QX_cachefp ){
		fflush(QX_cachefp);
		lock_unlock(fileno(QX_cachefp));
		stopDistribution(QX_Conn,QX_cachefp,QX_cpath);
		fclose(QX_cachefp);
		QX_cachefp = NULL;
		if( QX_cachemmap ){
			free((char*)QX_cacheheadbuf);
			freemmap(QX_cachemmap);
			QX_cachemmap = 0;
		}
	}
}
static int foundBrokenCache(QueryContext *QX){
	refQStr(cp,QX_cpath);
	if( cp = strtailstr(QX_cpath,LOADING) ){
		clearVStr(cp);
		QX_cacheRemove = 1;
		return 1;
	}
	return 0;
}
static void HTcache_done(Connection *Conn,QueryContext *QX){
	CStr(opath,URLSZ);
	refQStr(op,opath);
	int nretry;
	int done;
	int rcode;

	if( HTTP_opts & HTTP_OLDCACHE )
		return;

	if( QX_cpath[0] == 0 ){
		return;
	}

	if( strtailstr(QX_cpath,LOADING) == 0 ){
		/*
		if( isWindows() )
		*/
		{
			sprintf(opath,"%s#DONE",QX_cpath);
			if( File_is(opath) ){
				if( File_mtime(QX_cpath) < File_mtime(opath) ){
					if( renameRX(opath,QX_cpath) == 0 )
					Verbose("{L} UPDATED [%s]\n",opath);

				}
				if( unlink(opath) == 0 ){
					Verbose("{L} DISCARDED [%s]\n",opath);
				}
			}
		}
		return;
	}

	if( QX_cacheRemove ){
		if( unlink(QX_cpath) == 0 ){
			sv1log("## REMOVED:%d[%s]\n",QX_cacheRemove,QX_cpath);
		}else{
			sv1log("## CANTREM:%d[%s]\n",QX_cacheRemove,QX_cpath);
		}
		return;
	}
	if( !File_is(QX_cpath) ){
		/* might be 304 */
		Verbose("{L} HTcache_done: NONE %s\n",QX_cpath);
		return;
	}
	if( File_size(QX_cpath) == 0 ){
		Verbose("{L} HTcache_done: EMPTY %s\n",QX_cpath);
		unlink(QX_cpath);
		return;
	}

	strcpy(opath,QX_cpath);
	if( op = strtailstr(opath,LOADING) ){
		truncVStr(op);
		done = 0;
		if( fileIsdir(opath) || strtailchr(opath) == '/' ){
			FILE *fp;
			if( fp = dirfopen("HTTPcache",AVStr(opath),"w") ){
				/* create the cache with the escaped name */
				fclose(fp);
			}
		}
		if( 400 <= QX_hcode && File_is(opath) ){
			FILE *fp;
			IStr(ostat,128);
			if( fp = fopen(opath,"r") ){
				fgets(ostat,sizeof(ostat),fp);
				strsubst(AVStr(ostat),"\r\n","");
				fclose(fp);
			}
			fprintf(stderr,"-- don't replace %d %d %d [%s] %s\n",
				QX_hcode,File_size(QX_cpath),
				File_size(opath),ostat,opath);
			unlink(QX_cpath);
			/* if( QX_hcode == 404 ) unlink(opath) */
			return;
		}
		if( renameRX(QX_cpath,opath) == 0 ){
			Verbose("{L} RENAMED [%s]\n",opath);
		}else{
			strcat(opath,"#DONE");
			if( renameRX(QX_cpath,opath) == 0 ){
				Verbose("{L} ESCAPED [%s]\n",opath);
			}else{
				Verbose("{L} DISCARD [%s]\n",opath);
				unlink(QX_cpath);
			}
		}
	}
}
int SHlockTO(Connection *Conn,FILE *lkfp,int timeout){
	double Until;
	int ntry;
	int rem;

	Until = Time() + timeout;
	for( ntry = 0; ntry < 20; ntry++ ){
		if( lock_sharedNB(fileno(lkfp)) == 0 ){
			return 0;
		}
		rem = (int)((Until - Time()) * 1000);
		if( rem <= 0 )
			break;
		if( 500 < rem )
			rem = 500;
		PollIn(ClientSock,rem);
		if( !IsAlive(ClientSock) )
			return -2;
	}
	return -1;
}

static void setQXmmap(Connection *Conn,QueryContext *QX){
	int msize;
	const char *mdata;
	const char *cp;
	int ch;
	int size;
	int ci;
	int bsiz;
	int cachebufsize;
	IStr(hver,128);
	int hcode;

	if( isWindows() && !isWindowsCE() ){
		return;
	}
	QX_cachemmap = filemmap(QX_cpath,"r",0,0);
	if( QX_cachemmap == 0 ){
		return;
	}
	cachebufsize = 4*1024;
	setQStr(QX_cacheheadbuf,malloc(cachebufsize),cachebufsize);
	QX_cachefilesiz = QX_cachemmap->m_size;
	msize = QX_cachefilesiz;
	mdata = (const char*)QX_cachemmap->m_addr;
	if( cachebufsize < msize+1 )
		size = cachebufsize;
	else	size = msize+1;
	QStrncpy(QX_cacheheadbuf,mdata,size);
	QX_cacheheadlen = size-1;

	hcode = -1;
	Xsscanf(QX_cacheheadbuf,"%s %d",AVStr(hver),&hcode);
	QX_cacheretcode = hcode;

	cp = mdata;
	bsiz = 0;
	for( ci = 0; ci < msize && ci < 16*1024; ci++ ){
		ch = *cp++;
		if( ch == '\r' ){
			if( ci+3 < msize
			 && cp[0]=='\n' && cp[1]=='\r' && cp[2]=='\n' ){
				bsiz = msize - (ci+4);
				break;
			}
		}else
		if( ch == '\n' ){
			if( ci+1 < msize
			 && cp[0]=='\n' ){
				bsiz = msize - ci+2;
				break;
			}
		}
	}
	QX_cachebodysiz = bsiz;
	if( 0 )
	fprintf(stderr,"--setQXmmap:%X %X/%d copied %d bsiz=%d\n",
		p2i(QX_cachemmap),p2i(mdata),QX_cachefilesiz,
		QX_cacheheadlen,QX_cachebodysiz);
}
static int HTTP_staleCache(Connection *Conn,QueryContext *QX){
	FILE *fp = QX_cachefp;
	CStr(stat,URLSZ);
	int off;
	IStr(hver,128);
	int hcode;

	if( fp == NULL )
		return 1;

	if( QX_cachemmap ){
		lineScan(QX_cacheheadbuf,stat);
		hcode = QX_cacheretcode;
	}else{
	off = ftell(fp);
	if( fgets(stat,sizeof(stat),fp) == NULL )
		return 1;
	fseek(fp,off,0);
	hcode = -1;
	Xsscanf(stat,"%s %d",AVStr(hver),&hcode);
	}

	switch( hcode ){
		/* 9.8.2 don't reuse temporary error due to the client side */
		case 400:
		case 401:
		case 407:
		case 416:
			porting_dbg("HTTP ignore cache: %s",stat);
			return 1;
	}

	if( (HTTP_cacheopt & CACHE_ANYVER) == 0 ){
		if( strncmp(stat,"HTTP/1.",7) != 0 ){
			/* it'll be abandoned in relay_response() anyway */
			sv1log("Broken Cache [%s] %s",QX_cpath,stat);
			return 1;
		}
	}
	return 0;
}
int HTTP_selfExpiredX(FILE *fp,PCStr(head));
static int HTTP_selfExpiredQX(Connection *Conn,QueryContext *QX){
	const char *head;
	if( QX_cachemmap )
		head = QX_cacheheadbuf;
	else	head = 0;
	return HTTP_selfExpiredX(QX_cachefp,head);
}
static int HTTP_ContLengOkQX(FILE *fs,QueryContext *QX){
	IStr(cleng,128);
	int leng;
	if( QX_cachemmap ){
		if( getFV(QX_cacheheadbuf,"Content-Length",cleng) ){
			leng = atoi(cleng);
			if( leng != QX_cachebodysiz ){
				porting_dbg("--ContLengOk NG %d / %d",
					QX_cachebodysiz,leng);
				return 0;
			}
		}
		return 1;
	}
	return HTTP_ContLengOk(fs);
}

/* with CACHEARC=... for multiple cache directory */
FILE* fopenCACHEARC(Connection *Conn,PCStr(proto),PCStr(host),int port,PCStr(upath),PVStr(cpath));
int genHEADX(Connection *Conn,FILE *tc,int code,PCStr(reason),int cleng);

static int doCache(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	int cretry;
	int dontWaitCache;
	refQStr(dp,QX_cpath);

	if( HttpReload ){
	}else
	if( !DontReadCache ){
		FILE *fp;
		CStr(cpath,1024);
		fp = fopenCACHEARC(Conn,QX_proto,QX_site,QX_port,QX_upath,AVStr(cpath));
		if( fp ){
			DontTruncate = 8;
			sv1log("---- from Archive[%s]\n",cpath);
			setConnStart(Conn);
			CONN_DONE = CONN_START - 1;
			if( relay_response_fromCache(Conn,QX,
			    QX_proto,QX_site,QX_port,REQ,
			    cpath,fp,tc,fc) != 0 )
			{
				/* sent something broken to the client X-< */
			}
			fclose(fp);
			return 1;
		}
	}

	if( QX_useCache == 0 )
		return 0;

	cretry = 0;
	set_DG_EXPIRE(Conn,QX_expire);
	dontWaitCache = DontWaitCache;

retry_read:
	if( dp = strtailstr(QX_cpath,LOADING) ){
		truncVStr(dp);
	}
	if( QX_cachefp != NULL )
		CacheClose(QX);
	QX_cdate = -1;
	/*
	if( 5 < cretry++ )
	*/
	if( 1 < cretry++ )
		return 0;

	/* QX_cachemm should be used to lookup fields and lookahead */
	if( !DontReadCache )
	if( QX_cachefp = cache_fopen_rd("HTTP",AVStr(QX_cpath),QX_expire,&QX_cdate) ){
		CStr(val,128);
		setQXmmap(Conn,QX);
		if( (HTTP_cacheopt & CACHE_VARY) == 0 )
		if( fgetsHeaderField(QX_cachefp,"Vary",AVStr(val),sizeof(val)) ){
			sv1log("ignore cache with Vary: %s\n",val);
			CacheClose(QX);
			return 0;
		}

		if( LockedByC(Conn,QX_cpath,fc) ){ CacheClose(QX); return 0; }
		if( (HTTP_opts & HTTP_OLDCACHE) == 0 ){
			/* cache become read-only thus lock is unnecessary */
		}else
		if( lock_sharedNB(fileno(QX_cachefp)) != 0 ){
			FILE *rfp;
			int updated;
			/*
			rfp = recvDistribution(Conn,QX_cpath,&updated);
			*/
			rfp = recvDistributionX(Conn,QX,&updated);
			if( updated )
				goto retry_read;
			if( rfp != NULL ){
				sv1log("---- from Distribution[%s]\n",QX_cpath);
				setConnStart(Conn);
				CONN_DONE = CONN_START;
				relay_response(Conn,QX,0,QX_proto,QX_site,QX_port,
					REQ,NULL,0,rfp,tc,fc,NULL,0);
				fclose(rfp);
				return 1;
			}
			if( SHlockTO(Conn,QX_cachefp,CACHE_RDRETRY_INTERVAL)!=0 ){
				if( !IsAlive(ClientSock) )
					return -1;
				goto retry_read;
			}
		}
		/*
		if( lock_for_rd("HTTP",cretry,QX_cpath,QX_cachefp) != 0 ){
			sleep(CACHE_RDRETRY_INTERVAL);
			goto retry_read;
		}
		*/
		if( HTTP_staleCache(Conn,QX) ){
			CacheClose(QX);
		}else
		/*
		if( HTTP_selfExpired(QX_cachefp) && !Conn->co_nonet ){
		*/
		if( HTTP_selfExpiredQX(Conn,QX) && !Conn->co_nonet ){
			CacheClose(QX);
		}else
		if( HttpReload ){
			/* it'll be re-opened if necessary for 304->200
			 * conversion with cacheReadOK()/popCurrentCache()
			 */
			CacheClose(QX);
		}else{
			setConnStart(Conn);
			CONN_DONE = CONN_START - 1;
			/* minus value represent no connection ... */

			if( relay_response_fromCache(Conn,QX,
			    QX_proto,QX_site,QX_port,REQ,
			    QX_cpath,QX_cachefp,tc,fc) != 0 )
			{
				/* sent something wrong to client X-< */
			}
			LOGX_appHit++;
			return 1;
		}
	}

	if( CacheOnly & CACHE_ONLY ){
		int cleng;

		cleng = EMPTYBODY_SIZE;
		genHEADX(Conn,tc,504,"Not in the cache",cleng);
		fprintf(tc,"\r\n");
		http_Log(Conn,504,CS_TIMEOUT,REQ,0);
		return -1;
	}

	if( !DontWriteCache )
	/*
	if( QX_cachefp = cache_fopen_rw("HTTP",AVStr(QX_cpath)) ){
	*/
	if( HTcache_make(Conn,QX) ){
		if( LockedByC(Conn,QX_cpath,fc) ){ CacheClose(QX); return 0; }
		if( file_lock_wr("HTTP",QX_cachefp) != 0 ){
			FILE *rfp;
			int updated;

			rfp = recvDistribution(Conn,QX_cpath,&updated);
			if( updated )
				goto retry_read;

			if( rfp != NULL ){
				setConnStart(Conn);
				CONN_DONE = CONN_START;
				relay_response(Conn,QX,0,QX_proto,QX_site,QX_port,
					REQ,NULL,0,rfp,tc,fc,NULL,0);
				fclose(rfp);
				return 1;
			}
			if( !DontReadCache && !dontWaitCache ){
				sleep(CACHE_WRRETRY_INTERVAL);
				goto retry_read;
			}
			CacheClose(QX);
		}else{
			makeDistribution(Conn,QX_cachefp,QX_cpath);
			DontWaitCache = 1;
		}
	}else{
		/* readable but not writable */
		if( QX_cdate != -1 )
			QX_cdate = -1;
	}
	return 0;
}
static int doMaxHops(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{
	if( HTTP_MAXHOPS < D_HOPS ){
		sv1log("#### MAX_HOPS %d < %d HOPS\n",HTTP_MAXHOPS,D_HOPS);
		fprintf(tc,"HTTP/%s 502 too many hops\r\n",MY_HTTPVER);
		fprintf(tc,"\r\n");
		fprintf(tc,"Too many hops: %d\r\n",D_HOPS);
		return 1;
	}
	return 0;
}
static void pollRequestBody(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	CStr(cleng,128);
	int nready;
	int timeout;

	if( (HTTP_opts & HTTP_DOPOLL_REQBODY) == 0  )
	if( 0 <= vercmp(REQ_VER,"1.1") ){
		Verbose("-- POST don't wait req body to get 100-continue\n");
		return;
	}

	if( getFV(REQ_FIELDS,"Content-Length",cleng) )
	if( 0 < atoi(cleng) )
	if( DDI_PollIn(Conn,fc,100) == 0 ){
		timeout = (int)(HTTP_WAIT_REQBODY * 1000);
		sv1log("#### start polling body of %s %dms\n",REQ_METHOD,
			timeout);
		nready = DDI_PollIn(Conn,fc,timeout);
		sv1log("#### polling done: %d\n",nready);
	}
}

static int tryICP(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{	CStr(msg1,64);
	CStr(msg2,64);

	if( select_icpconf(Conn,VStrNULL) )
		connect_to_serv(Conn,FromC,ToC,0);
	if( FromS < 0 )
		return 0;

	sprintf(msg1,"ConnType=%c%s%s%s%s",
		ConnType?ConnType:'?',
		IAM_GATEWAY?"/GateWay":"",
		toProxy?"/Proxy":"",
		toMaster?"/Master":"",
		0<=Conn->ca_objsize?"/HIT_OBJ":"");

	if( ConnType == 'i' ){
		if( 0 <= Conn->ca_objsize ){
			sprintf(msg2,"RECEIVED HIT_OBJ=%d",
				Conn->ca_objsize);
		}else
		if( toProxy ){
			ConnType = 'p';
			strcpy(msg2,"FORWARDING to HTTP proxy");
			IAM_GATEWAY = 0;
			connected_to_proxy(Conn,REQ,FromS);
		}else
		if( toMaster ){
			ConnType = 'm';
			strcpy(msg2,"FORWARDING to MASTER DeleGate");
		}else{
			strcpy(msg2,"FORWARDING to ORIGIN server");
		}
	}else{
		msg2[0] = 0;
		if( toProxy ){
			ConnType = 'p';
			strcpy(msg2,"FORWARDING to HTTP proxy");
			IAM_GATEWAY = 0;
			connected_to_proxy(Conn,REQ,FromS);
		}
	}
	sv1log("(ICP) %s{%s}(%s:%d) %s",msg1,msg2,QX_site,QX_port,REQ);

	if( IAM_GATEWAY ){
		http_gateway(Conn,QX,fc,tc,FromS);
		return -1;
	}
	return 0;
}
static int tryConnects(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{
	if( tryICP(Conn,QX,fc,tc) < 0 )
		return -1;

	if( streq(QX_proto,"nntp") || streq(QX_proto,"news")
	 || streq(QX_proto,"pop")
	 || streq(QX_proto,"sftp")
	 || streq(QX_proto,"ftp" ) || streq(QX_proto,"file") ){
		/* don't try direct routes, just check PROXY.  */
		tryProxyOnly = 1;
	}
	if( FromS < 0 ){
		if( EccEnabled() ){
			if( Conn->sv_retry & SV_RETRY_DO ){
				int waitCCSV(Connection *Conn,int msec);
				fprintf(tc,"HTTP/1.1 100 retrying\r\n");
				fprintf(tc,"\r\n");
				fflush(tc);
				waitCCSV(Conn,10*1000);
			}
		}
		connect_to_serv(Conn,FromC,ToC,0);
	}
	tryProxyOnly = 0;

	if( IAM_GATEWAY && !toProxy ){
		int comask;

		comask = Conn->co_mask;
		Conn->co_mask |= CONN_NOPROXY;
		http_gateway(Conn,QX,fc,tc,FromS);
		Conn->co_mask = comask;
		return -1;
	}
	if( FromS < 0 ){
		sv1log("cannot connect to server: %s://%s:%d\n",
			DST_PROTO,DST_HOST,DST_PORT);

		if( checkClientEOF(Conn,tc,"cant_connect") ){
			http_Log(Conn,500,CS_CONNERR,REQ,0);
		}else
		if( QX_cachefp != NULL && QX_cdate != -1 ){
			setConnDone(Conn);
			sv1log("makeshift with old cache (A).\n");
			httpStat = CS_MAKESHIFT;
			makeshift(Conn,QX,tc,NULL);
			/*
			relay_response(Conn,QX,0,QX_proto,QX_site,QX_port,
				REQ,QX_cpath,1,QX_cachefp,tc,NULL,NULL,1);
			*/
		}else{
			QX_totalc = putHttpCantConnmsg(Conn,tc,
				QX_proto,QX_site,QX_port,OREQ);

			/* when Pragma: no-cache */
			if( QX_cachefp != NULL && 0 < file_size(fileno(QX_cachefp)) ){
				int ooff = ftell(QX_cachefp);
				fseek(QX_cachefp,0,2);
				sv1log("preserved old cache (%d->%d) %s\n",
					ooff,iftell(QX_cachefp),QX_cpath);
			}
			http_Log(Conn,500,CS_CONNERR,REQ,0);
			HTTP_delayCantConn(Conn,REQ,"500 cannot connect\r\n",1);
		}
		if( QX_cachefp != NULL && file_size(fileno(QX_cachefp)) <= 0 )
			QX_cacheRemove = 1;
		return -1;
	}

/*
set_nodelay(ToC,1);
set_nodelay(ToS,1);
*/

	if( toMaster ){
		sv1log("HTTP -> (%s:%d) %s",QX_site,QX_port,REQ);
	}else{
		std_setsockopt(ToS);
		sv1log("HTTP => (%s:%d) %s",QX_site,QX_port,REQ);
	}

	if( checkClientEOF(Conn,tc,"connected") ){
		http_Log(Conn,500,CS_EOF,REQ,0);
		return -1;
	}

	/* do getsockopt(client) immediately after EOF check */
	expsockbuf(ToC,0,MAX_BUFF_SOCKSEND);

	set_keepalive(FromS,1);
	expsockbuf(FromS,MAX_BUFF_SOCKRECV,0);
	if( Conn->cl_count <= 2 ){
		/* to make the transfer first, when the load is not so high */
		expsockbuf(FromS,0x8000,0);
	}

	setConnDone(Conn);
	return 0;
}
static void doTruncateCache(Connection *Conn,QueryContext *QX,FILE *fc,FILE *tc)
{
	if( QX_rcode == R_EMPTY_RESPONSE && QX_cdate != -1 ){
		sv1log("makeshift with old cache (B).\n");
		Verbose("cache-file: %s\n",QX_cpath);
		makeshift(Conn,QX,tc,fc);

		/*
		lock_sharedNB(fileno(QX_cachefp));
		relay_response(Conn,QX,0,QX_proto,QX_site,QX_port,
			REQ,QX_cpath,1,QX_cachefp,tc,fc,NULL,QX_cdate != -1);
		*/
	}else
	if( QX_cacheRemove ){
		sv1log("remove=%d rcode=%d size=%d unlink %s\n",
			QX_cacheRemove,QX_rcode,File_size(QX_cpath),QX_cpath);
	}else
	if( DontTruncate ){
		Verbose("DontTruncate: rcode=%d ftell:%d\n",
			QX_rcode,iftell(QX_cachefp));
	}else
	if( QX_rcode < 0 ){
		if( QX_hcode == 404 && (HTTP_cacheopt & CACHE_404) ){
		}else
		if( QX_rcode==R_GENERATED && (HTTP_cacheopt&CACHE_NOLASTMOD) ){
			CStr(url,URLSZ);
			url[0] = 0;
			HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
			sv1log("WARNING:cached without Last-Modified:%s\n",url);
		}else
		if( ServerFlags & PF_IS_DISTRIB ){
			sv1log("---- abort recv. from Distributor[%s]\n",QX_cpath);
		}else
		if( QX_rcode==R_UNSATISFIED && (HTTP_cacheopt & CACHE_SHORT) ){
			sv1log("## leave truncated(%s) Wr\n",QX_cpath);
		}else{
		sv1log("rcode=%d unlink %s (%d)\n",QX_rcode,QX_cpath,
			File_size(QX_cpath));
		QX_cacheRemove = 1;
		}
	}else{
		if( httpStat == CS_STABLE ){
		}else{
			sv1log("%lld bytes written to [%s]\n",Lseek(fileno(QX_cachefp),0,1),QX_cpath);
			Ftruncate(QX_cachefp,0,1);
			/* truncation should be disabled when relaying cache */
		}
	}
}
static void closeQXfd(Connection *Conn,QueryContext *QX,PCStr(wh)){
	_heapLock lock;

	/*
	if( lWINSOCK() )
	*/
	sv1log("## close svsokcs %d[%d] %d[%d] (%s)\n",
		SocketOf(QX_tsfd),QX_tsfd,
		SocketOf(QX_fsfd),QX_fsfd,wh);

	closed("closeServ",QX_tsfd,QX_fsfd);

	/* was a trial to avoid batting in closing fds mapped to
	 * the same handle ???
	 */
	heapLock(FL_ARG,lock);
	close(QX_tsfd);
	if( QX_fsfd != QX_tsfd ){
		close(QX_fsfd);
	}
	heapUnLock(FL_ARG,lock);
	QX_tsfd = -1;
	QX_fsfd = -1;

	if( lWINSOCK() )
	sv1log("#HT11 close svsokcs %d[%d] %d[%d] ... %s DONE\n",
		SocketOf(QX_tsfd),QX_tsfd,
		SocketOf(QX_fsfd),QX_fsfd,wh);
}
char *strSeekEOHX(PCStr(head),int len);
static void closeServ(Connection *Conn,QueryContext *QX,FILE *ts,FILE *fs)
{
	int fileno_ts = fileno(ts);
	int fileno_fs = fileno(fs);
	porting_dbg("## closeServ C[%d][%d][%d] F[%d][%d] Q[%d][%d]",
		ToS,FromS,ServerSock,fileno_ts,fileno_fs,QX_tsfd,QX_fsfd);
	if( EccEnabled() ){
		if( Conn->ccsv.ci_id ){
			destroyCCSV("closeServ",Conn,fileno_ts);
		}
	}

	finishServYY(FL_ARG,Conn);
	closeQXfd(Conn,QX,"closeServ");
	closed("closeServ",fileno_ts,fileno_fs);
	fclosesTIMEOUT(fs,ts);
	/* (0 <= ServerSock) will be closed in delServ() */
	delServ(Conn,fileno_ts,fileno_fs);

	if( Conn->xf_filters & XF_SERVER ){
		sv1log("closeServ() clear xf=%X\n",Conn->xf_filters&XF_SERVER);
		Conn->xf_filters &= ~XF_SERVER;
	}
	FromS = -1;
	if( 0 < QX_cpid ){
		Kill(QX_cpid,SIGTERM);
		wait(0);
		QX_cpid = 0;
	}
	/* push the body of the POST message to FILE fc to be re-read */
	if( 0 < OREQ_LEN && 0 < OREQ_BODYOFF && OREQ_BODYOFF < OREQ_LEN ){
		const char *bp;
		int blen;

		bp = OREQ_MSG + OREQ_BODYOFF;
		blen = OREQ_LEN - OREQ_BODYOFF;
		/*
		this should be enough as long as the headear is not rewritten
		sv1log("HCKA-SV: push POST body (%d)\n",blen);
		DDI_pushCbuf(Conn,bp,blen);
		*/
		if( bp = strSeekEOHX(OREQ_MSG,OREQ_LEN) ){
			if( bp[0] == '\r' && bp[1] == '\n' ){
				bp += 2;
			}else
			if( bp[0] == '\n' ){
				bp += 1;
			}
			blen = OREQ_LEN - (bp - OREQ_MSG);
			if( 0 < blen && blen == OREQ_LEN-OREQ_BODYOFF ){
				sv1log("HCKA-SV: push POST body (%d)\n",blen);
				DDI_pushCbuf(Conn,bp,blen);
			}
		}
	}
	Conn->sv_reusing = 0;
}

static int forbiddenMethod(Connection *Conn)
{ 
	if( HTTP_opts & HTTP_NOMETHODCHECK )
		return 0;

	if( method_permitted(Conn,"http",REQ_METHOD,1) )
		return 0;

	if( strcmp(DST_PROTO,"http") != 0 )
	if( method_permitted(Conn,DST_PROTO,REQ_METHOD,1) )
		return 0;

	sprintf(Conn->reject_reason,"forbidden method:%s",REQ_METHOD);
	return 1;
}

void closingServ(Connection *Conn,int fsd,int tsd);
int clearServ(Connection *Conn);
static void put_forbidden(Connection *Conn,QueryContext *QX,FILE *tc,int delay)
{
	QX_totalc = putHttpRejectmsg(Conn,tc,QX_proto,QX_site,QX_port,AVStr(REQ));
	http_Log(Conn,403,CS_AUTHERR,REQ,QX_totalc);
	if( delay )
		HTTP_delayReject(Conn,REQ,"",1);
}
static void service_http2X(Connection *Conn,FILE *ftc[4],QueryContext *QX)
{	FILE *ts,*fs;
	FILE *respFile,*tc_sav;
	int chunksav;
	FILE *fc,*tc;
	int qlen;
	CStr(oreq_url,URLSZ);
	const char *vurl;
	int QX_emptyQ = 0;
	int Fromcache = 0; /* read-out from cache without update */

	LOGX_appReq++;

	PageCountUpURL(Conn,CNT_TOTALINC,"#total",NULL);

	HTCCX_init();
	HttpReload = 0;
RX_CODE = 0;
	authOK = 0;

	fc = ftc[0];
	tc = ftc[1];

/*
fflushTrace(tc,1);
*/
	httpStat = 0;
	httpStatX = 0;

	QX_Conn = Conn;
	QX_site = DFLT_HOST;
	QX_port = DFLT_PORT;

	QX_rcode = R_BEFORE_RESPONSE;
	QX_hcode = -1;
	QX_emptyResp = 0;

	QX_lastRecv = 0;
	QX_lastSent = 0;

	QX_cpath[0] = 0;
	QX_cachefp = NULL;
	QX_cacheretcode = 0;
	QX_cachemmap = 0;
	QX_cdate = -1;
	QX_cacheRemove = 0;

	QX_range[0] = QX_range[1] = -1;
	Conn->cl.p_range[0] = Conn->cl.p_range[1] = -1;

	QX_tcf = 0;
	QX_dumpCD.dc_line = 0;
	QX_dumpDS.dc_line = 0;

	PragmaNoCache = 0;
	DontTruncate = 0;
	ToMyself = 0;

	CheckServ = 0;
	WaitServ = 0;
	BadServ = 0;

	if( ImMaster && CacheOnly ){
		lookCacheOnly(Conn,QX,tc,fc);
		goto EXIT;
	}

	/*
	 * This code is introduced in 6.1.0 to forbid relaying by (origin)
	 * HTTP-DeleGate (with SERVER=http) with RELAY=no after metamo. to
	 * MASTER-DeleGate (indicated by ACT_GENERALIST=1).
	 */
	if( ImMaster && ACT_GENERALIST ){ /* metamo. */
		if( !do_RELAY(Conn,RELAY_DELEGATE)
		 && !do_RELAY(Conn,RELAY_VHOST)
		 && !do_RELAY(Conn,RELAY_PROXY) ){ 
			sv1log("Forbidden: RELAY by switch to GENERALIST\n");
			returnAckDENIED(Conn,tc,"relay forbidden");
			goto EXIT;
		}
	}

	returnAckOK(Conn,tc,"http");

	/* possibly bare MASTER protocol finished, (re)try TLS negotiation */
	if( GatewayFlags & GW_SSI_INCLUDE ){
		/* 9.9.2 from_myself is not set, and -Pxxx/admin may be set  */
		/* (not to initiate SSL detection for -Pxxx/admin) */
		if( ClientFlags )
		sv1log("## SSI self=%d ClientFlags=%X\n",
			Conn->from_myself,ClientFlags);
	}else
	if( HTTP_STARTTLS_withCL(Conn,fc,tc) ){
		if( (ClientFlags & PF_MITM_ON) && ClientSock != FromC ){
			/* 9.8.6 set ToC/FromC instead of dup2(ClientSock) */
			/*
			fcloseFILE(fc);
			fcloseFILE(tc);
			*/
			ftc[2] = fc;
			ftc[3] = tc;
			fc = fdopen(FromC,"r");
			tc = fdopen(ToC,"w");
			ftc[0] = fc;
			ftc[1] = tc;
		}
		syslog_ERROR("**** delayed detection of SSL\n");
	}

	REQ[0] = 0;
	/*
	if( fgetsRequest(Conn,AVStr(REQ),sizeof(REQ),fc,0) == NULL || REQ[0] == 0 ){
	*/
	if( fgetsRequest(Conn,AVStr(REQ),sizeof(REQ),fc,0) == NULL
	 || REQ[0] == 0
	 || clientIsReset("getRequest",Conn,1)
	){
		if( RequestSerno ){
			clntClose(Conn,"q:by client (request EOF-8)");
			setClientEOF(Conn,fc,"request-EOF-8");
			setCLX("EK",CLX_EMPTY_REQ_LINEK);
			goto EXIT;
		}
		gotNullRequest(Conn,QX,fc,tc);
		QX_emptyQ = 1;
		setCLX("EQ",CLX_EMPTY_REQ_LINE);
		goto EXIT;
	}
	qlen = strlen(REQ);
	if( HTTP_MAX_REQLINE < qlen ){
		sv1log("## HTTPCONF=%s:%d<%d -- %s",
			HTTP_MAX_REQLINE_sym,HTTP_MAX_REQLINE,qlen,REQ);
		putBadRequest(Conn,tc,"request-line-too-long");
		goto EXIT;
	}

	if( nonHTTP(Conn,ftc,AVStr(REQ)) )
		goto NHEXIT;

	if( HTTP09_reject && !HTTP_reqWithHeader(Conn,REQ) ){
		sv1log("## rejected HTTP/0.9 non-header message\n");
		putBadRequest(Conn,tc,"ver-0.9-not-allowed");
		goto EXIT;
	}

	if( HTTP11_clientTEST && ReqVer(REQ,'0',AVStr(REQ),'1') ){
		sv1log("#HT11 emulate HTTP/1.1 client's request.\n");
	}

	HTTP_decompRequest(Conn);
	if( isFullURL(REQ_URL) ){
		ClientFlags |= PF_AS_PROXY;
	}
	if( strcaseeq(REQ_METHOD,"CONNECT") ){
		ClientFlags |= PF_AS_PROXY; /* to be tested in doauth() */
	}
	strcpy(OREQ,REQ);
	Xstrcpy(ZVStr(OREQ_HOST,OREQ_HOST_SIZ),DFLT_HOST);
	OREQ_PORT = DFLT_PORT;

	if( ReqVer(REQ,'1',AVStr(REQ),HTTP11_toserver?'1':'0') ){
		if( HTTP11_toclient )
		ClntAccChunk = 1;
		clientAskedKeepAlive(Conn,"Connection","keep-alive");
		if( HTTP11_toclient == 0 )
			WillKeepAlive = 0;
		/* This set-up for keep-alive must be done before interpreting
		 * Request-Header (Connection: field)
		 */
	}
	if( HTTP_opts & HTTP_NOKEEPALIVE ){
		WillKeepAlive = 0;
	}

	BadRequest = 0;
	Normalized = 0;
	recvRequestFields(Conn,QX,tc,fc);
	if( 0 <= ClientSock /* !URLget() */ )
	if( feof(fc) || isWindows() && !IsAlive(ClientSock) ){
		setCLX("AF",CLX_AFTER_REQ_FIELDS);
		goto EXIT;
	}

	HL_setClientAgent(REQ_UA);
	SVREQ_ATYP[0] = 0;
	Conn->xf_reqrecv = 1;

	if( strneq(QX_upgrade,"HTMUX/",6) ){
		Verbose("## Upgrade: %s\n%s",QX_upgrade,REQ_FIELDS);
	}else
	if( needSTLS(Conn) ){
		if( strcaseeq(QX_upgrade,"TLS/1.0") ){
			fprintf(tc,"HTTP/1.1 101 Switching Protocol\r\n");
			fprintf(tc,"Upgrade: TLS/1.0, HTTP/1.1\r\n");
			fprintf(tc,"Connection: upgrade\r\n");
			fprintf(tc,"\r\n");
			fflush(tc);
			{
				int fcl;
				fcl = insertTLS_CL(Conn,ClientSock,-1);
				dup2(fcl,ClientSock);
				close(fcl);
			}
		}else{
			if( OREQ_VHOST[0] == 0 ){
				/* 9.9.5 to show hostname in client's view */
				getFV(REQ_FIELDS,"Host",OREQ_VHOST);
			}
			http_Log(Conn,426,CS_ERROR,REQ,0);
			strcpy(Conn->reject_reason,"Not with SSL");
			HTTP_delayReject(Conn,REQ,"",1);

			/*
			fprintf(tc,"HTTP/1.1 426 Upgrade Required\r\n");
			fprintf(tc,"Upgrade: TLS/1.0, HTTP/1.1\r\n");
			fprintf(tc,"Connection: Upgrade\r\n");
			fprintf(tc,"Content-Type: text/html\r\n");
			fprintf(tc,"\r\n");
			fprintf(tc,"protocol error, must be in HTTPS/SSL.\r\n");
			*/
			putUpgrade(Conn,tc);
			goto EXIT;
		}
	}

	if( HTTP_opts & HTTP_SESSION ){
		if( ClientSession[0] == 0 ){
			genSessionID(Conn,AVStr(ClientSession),0);
		}
	}

	if( HTTP_MAX_REQHEAD < OREQ_LEN ){
		sv1log("## HTTPCONF=%s:%d<%d -- %s%s",
			HTTP_MAX_REQHEAD_sym,HTTP_MAX_REQHEAD,
				OREQ_LEN,REQ,REQ_FIELDS);
		putBadRequest(Conn,tc,"request-head-too-long");
		goto EXIT;
	}
	if( 0 <= QX_range[0] ){
		sv1log("#HT11 Don't use chunked encoding for Range: %lld-%lld\n",QX_range[0],QX_range[1]);
		ClntAccChunk = 0;
	}

	if( BadRequest && HTTP_rejectBadHeader ){
		sv1log("##HHe ILLEGAL HEADER##\n");
		if( HTTP_methodWithBody(REQ_METHOD) ){
			FILE *xs = NULLFP();
			relayRequestBody1(Conn,tc,fc,xs,xs,REQ,REQ_FIELDS);
		}
		lineScan("beforeConnnect",BadServDetected);
		lineScan("NOT-CONNECTED",BadServResponse);
		httpStat = CS_BADREQUEST;
		putBadRequest(Conn,tc,NULL);
		goto EXIT;
	}

	bzero(&REQ_AUTH,sizeof(AuthInfo));

	/*
	 * parse request to set destination info. REAL_{PROTO,HOST,PORT}
	 * before applying AUTHORIZER with ConnMap
	 */
	HTTP_getHost(Conn,REQ,REQ_FIELDS);

	if( ConfigFlags & CF_WITH_CCXTOCL )
	if( !CCXactive(CCX_TOCL) )
	{
		if( scan_CCXTOCL(Conn) ){
			/* activate SVCC on conditional CCX_TOCL */
			HTCCX_getSVCC(Conn,AVStr(REQ_FIELDS));
		}
	}

	strcpy(oreq_url,REQ_URL);
	if( rewriteRequest(Conn,QX,fc,tc) < 0 )
	{
		QX_emptyQ = 2;
		goto EXIT;
	}

	if( (COUNTERflag(CNT_MOUNTVURL) || strcaseeq(DST_PROTO,"nntp")) 
	 && MountOptions && (vurl = MountVbase(MountOptions)) ){
		PageCountUpURL(Conn,CNT_ACCESSINC,vurl,NULL);
	}else{
		PageCountUpURL(Conn,CNT_ACCESSINC,oreq_url,NULL);
	}

	if( streq(REQ_METHOD,"CONNECT") ){
		int port;
		CStr(host,MaxHostNameLen);
		port = scan_hostport1X(REQ_URL,AVStr(host),sizeof(host));
		if( port == 443 )
			set_realsite(Conn,"https",host,port);
		else	set_realsite(Conn,"tcprelay",host,port);
	}

#if 0
	if( CTX_auth(Conn,NULL,NULL) ) /* with AUTHORIZER */
#endif
	if( CTX_withAuth(Conn) )
/*
	if( ClientAuthUser[0] == 0 )
*/
	if( ClientAuthUser[0] == 0 || (ClientFlags & PF_MITM_ON) )
	{
		if( doauth(Conn,tc) < 0 )
			goto EXIT;
		else	authOK = 1;
	}

	if( 0 <= ClientSock /* !URLget() */ )
	if( feof(fc) || isWindows() && !IsAlive(ClientSock) ){
		setCLX("BC",CLX_BEFORE_CONNECT);
		goto EXIT;
	}
	if( doCONNECT(Conn,QX,fc,tc) )
		goto EXIT;

RETRY:
	if( Conn->sv_retry == SV_RETRY_DO ){
		sv1log("RETRYing with [%s]...\n",REQ_URL);
		sprintf(REQ,"%s %s HTTP/%s\r\n",REQ_METHOD,REQ_URL,REQ_VER);
		if( ToMyself || IAM_GATEWAY ){
			/* 9.7.7 error in origin/gateway-server */
			Verbose("-- ToMe:%d ImGw:%d fm=%d\n",
				ToMyself,IAM_GATEWAY,Conn->from_myself);
			ToMyself = 0;
			IAM_GATEWAY = 0;
		}
		Conn->from_myself = 1;
		Where = "retryingRequest";
		if( rewriteRequest(Conn,QX,fc,tc) < 0 )
			goto EXIT;
		Conn->sv_retry |= SV_RETRY_DONE;

		/* for ImMaster, IsMyself will not be set in rewrite_request
		 * then doMyself() is not called thus substituting with a URL
		 * MOUNTed to builtin/local will never succeed...
		 */
		if( ImMaster && !ToMyself ){
			if( strneq(REQ_URL,"builtin:",8)
			 || strneq(REQ_URL,"file:",5)
			 || strneq(REQ_URL,"data:",5)
			){
				ToMyself = 1;
			}
		}
	}

	{
	/* 8.10.4: in 8.9.6-pre8, MountMoved() came to be applied after
	 MountRequest() which could rewrite {DFLT,REAL}_PROTO as its
	 side effect when MOUNT for the same vURL without "moved" exists,
	 but DFLT_PROTO is used for MOUNT for MountMoved() as the
	 implicit protocol name for MOUNT="... //host", so it must be
	 left as the original one (iSERVER_PROTO) here.
	 It should be fixed not to rewrite DFLT_PROTO,
	 or to suppress retrying MOUNT both for with/without VHOST,
	 by returning "FOUND as unmatch" when MOVED_TO is found
	 during search for non-MOVED_TO MOUNT
	fprintf(stderr,"-- [%s][%s][%s]\n",iSERVER_PROTO,DFLT_PROTO,REAL_PROTO);
	*/
	CStr(dflt,256);
	strcpy(dflt,DFLT_PROTO); strcpy(DFLT_PROTO,iSERVER_PROTO);
	if( MountMoved(Conn,tc /*,REQ,REQ_URL*/) )
		goto EXIT;
	strcpy(DFLT_PROTO,dflt);
	}

	if( MountSpecialResponse(Conn,tc) )
		goto EXIT;
	if( doMaxHops(Conn,QX,fc,tc) )
		goto EXIT;


	/*
	8.9.6 unified into CTX_auth() above.
	if( withMountAUTHORIZER(Conn) )
	if( ClientAuthUser[0] == 0 )
	{
		if( doauth(Conn,tc) < 0 )
			goto EXIT;
		else	authOK = 2;
	}
	*/
	if( strncmp(REQ_URL,"data:",5) == 0 ){
		HTTP_putData(Conn,tc,REQ_VNO,REQ_URL+5);
		goto EXIT;
	}

	if( DO_DELEGATE && delegate_moved(Conn,tc) )
		goto EXIT;

	setREQUEST(Conn,REQ);
	decompREQUEST(Conn,QX);

	if( doACCEPT(Conn,QX,fc,tc) )
		goto EXIT;

	if( RelayForbidden || HTTP_forgedAuthorization(Conn,REQ_FIELDS) ){
		put_forbidden(Conn,QX,tc,RelayForbidden);
		goto EXIT;
	}

	setupConnect(Conn);
	if( Conn->co_nonet ){
		DontReadCache = 0;
		DontWriteCache = 1;
	}

/*
 if( 1 ){
CStr(head,1024);
CStr(body,1024);
sprintf(body,"Upgrade to TLS/1.0 ...\r\n");
head[0] = 0;
Xsprintf(TVStr(head),"HTTP/1.1 426\r\n");
Xsprintf(TVStr(head),"Upgrade: TLS/1.0, HTTP/1.1\r\n");
Xsprintf(TVStr(head),"Connection: upgrade\r\n");
Xsprintf(TVStr(head),"Content-Type: text/plain\r\n");
Xsprintf(TVStr(head),"Content-Length: %d\r\n",strlen(body));
Xsprintf(TVStr(head),"\r\n");
 fprintf(tc,"%s%s",head,body);
fflush(tc);
sv1log("##### CONNECITION UPGRADE TEST:\n%s%s\n%s%s\n",
	REQ,REQ_FIELDS,head,body);
sleep(1);
SentKeepAlive = 1;
goto EXIT;
 }
*/

	if( ToMyself && (Conn->sv_retry & SV_RETRY_DONE) ){
		/* 9.5.7 retrying in MITM */
		ServerFlags &= ~PF_MITM_ON;
	}
	/*
	if( 0 <= ToS && (ServerFlags & PF_MITM_ON) ){
	*/
	if( 0 <= ToS && (ServerFlags & PF_MITM_ON) && !requestToMe(Conn) ){
		/* peeping proxy mode Bp */
	}else
	/*
	if( doMyself(Conn,QX,fc,tc) )
	*/
	if( doMyself(Conn,QX,fc,tc,ftc) )
	{
		int linger = lSINGLEP()?SINGLEP_LINGER:DELEGATE_LINGER;
		/*
		waitShutdownSocket(FL_ARG,fileno(tc),linger*1000);
		*/
		goto EXIT;
	}

	if( (Conn->xf_filters & XF_CLIENT) && tc != ftc[1] ){
		/* might occur in MASTER or transparent-proxy (since 8.8.0) */
		Verbose("## inserted FTOCL %X->%X\n",p2i(ftc[1]),p2i(tc));
		tc = ftc[1];
	}
	if( Conn->sv_retry == SV_RETRY_DO ){
		goto RETRY;
	}

	/* this check should be applied to doMyself() too, but access to
	 * local "/-/..." etc. might be better to be exempted...
	 * because representation of "self" in access control is not clear. 
	 */
	if( forbiddenMethod(Conn) ){
		put_forbidden(Conn,QX,tc,1);
		goto EXIT;
	}

	if( ImMaster ){
		/* MASTER receives HTTP request for an origin server */
	}else
	if( !IsMounted && !DO_DELEGATE && IsVhost )
	if( ClientFlags & PF_MITM_ON ){
		/* 9.9.2 not VHOST but MITM (req. filter) */
	}else
	if( !do_RELAY(Conn,RELAY_VHOST) ){
		sv1log("relaying to virtual host is not allowed\n");
		sprintf(Conn->reject_reason,"\"vhost\" is not in RELAY");
		RelayForbidden |= RELAY_VHOST;
		put_forbidden(Conn,QX,tc,1);
		goto EXIT;
	}

	if( checkAUTH(Conn,QX,fc,tc,QX_proto,QX_site,QX_port,0) != 0 )
		goto EXIT;

	if( findFieldValue(REQ_FIELDS,"Authorization") ){
		AuthInfo ident;
		without_cache(); /* to get CACHE=do,auth to CacheFlags */
		if( (HTTP_cacheopt|CacheFlags) & CACHE_WITHAUTH ){
			sv1log("Authorzation: DO-Cache for %s\n",ident.i_user);
		}else
		if( streq(DST_PROTO,"ftp")
		 && HTTP_getAuthorization2(Conn,&ident,1)
		 && is_anonymous(ident.i_user) ){
			Verbose("Authorzation: Do-Cache for %s\n",ident.i_user);
		}else{
		sv1log("Authorization: Dont-Read/Write-Cache ON\n");
		DontReadCache = 1;
		DontWriteCache = 1;
		}
	}
	if( checkCookie(Conn /*,QX,fc,tc*/) < 0 )
		goto EXIT;

	if( (Conn->xf_filters & XF_FTOCL) == 0 )
	if( sav_FTOCL && IsCFI(sav_FTOCL)
	 && (ClientFlags & PF_NO_CFI_DELAY) == 0 ){
		ClientFlags |= PF_CFI_DELAY_ON;
		Verbose("Delay #!cfi insertion\n");
	}else
	if( (Conn->xf_filters & XF_FTOCL) == 0 ){
	if( sav_FTOCL )
		setFTOCL(sav_FTOCL);
	tc = insertFTOCL_X(Conn,tc);
	ftc[1] = tc;
	setFTOCL(NULL);
	}

	if( IAM_GATEWAY && ClntKeepAlive )
		if( isinFTPxHTTP(Conn) ){
			/* 9.9.8 don't close Keep-Alive for FTPxHTTP */
		}else
		if( !strcaseeq(DST_PROTO,"nntp")
		 && !strcaseeq(DST_PROTO,"news")
		 && !strcaseeq(DST_PROTO,"pop") )
			clntClose(Conn,"g:gateway for: %s",DST_PROTO);

		/* should do ReadCache if the reason is with Range: filter */
	if( !DontReadCache && streq(QX_proto,"ftp") ){
		if( doFtpCached(Conn,QX,fc,tc) )
			goto EXIT;
	}

	if( GET_CACHE ){
		int tfd;
		/*fclose(tc);*/
		/*
		tc = fopen("/dev/null","w");
		*/
		tfd = open("/dev/null",1); tc = fdopen(tfd,"w");
	}

	if( QX_upath = strchr(REQ,'/') )
		QX_upath = QX_upath + 1;
	else	QX_upath = "?";

	if( IAM_GATEWAY
	 || 512 < (int)strlen(REQ)
	 || without_cache()
	 || strncasecmp(REQ,"GET ",4) != 0 ){
		QX_useCache = 0;
		QX_cpath[0] = 0;
		httpStat = CS_WITHOUTC;
	}else{
		QX_useCache =
		CTX_cache_path(Conn,QX_proto,QX_site,QX_port,QX_upath,AVStr(QX_cpath));
		if( QX_useCache )
			httpStat = CS_NEW;
		else	httpStat = CS_WITHOUTC;
	}
	if( CacheOnly )
		QX_expire = 0x7FFFFFFF;
	else
	if( Conn->co_nonet )
		QX_expire = 0x7FFFFFFF;
	else	QX_expire = http_EXPIRE(Conn,QX_site);

	if( IAM_GATEWAY ){
	}else{
		if( doCache(Conn,QX,fc,tc) )
		{
			if( 0 <= ToS && (ServerFlags & PF_MITM_ON) ){
				/* 9.6.1 unused server is regarded as in
				 * keep-alive to be detected by aliveServ(),
				 * or it will block the main thread to finish
				 * in waitFilterThread()
				 */
				ServKeepAlive = 1;
				sv1log("KeepAlive the unused server %X %X\n",
					ServerFlags,ClientFlags);
				putServ(Conn,ToS,FromS);
			}
			if( QX_rcode == 0 && QX_cacheRemove == 0 ){
				Fromcache = 1;
			}
			goto EXIT;
		}
		if( QX_cachefp == NULL )
			httpStat = CS_WITHOUTC;
		if( !reqRobotsTxt(Conn)  )
			genIfModified(Conn,QX,QX_cachefp,QX_cpath,QX_cdate);
	}
	if( HTTP_reqWithHeader(Conn,REQ) ){
		HTTP_setHost(Conn,AVStr(REQ_FIELDS));
	}
	if( HTTP_methodWithBody(REQ_METHOD) )
		pollRequestBody(Conn,QX,fc,tc);

	if( QX_cachefp != NULL )
		CacheMtime = file_mtime(fileno(QX_cachefp));

	setConnStart(Conn);
	if( lDONTHT() && 0 <= ToS && (withNTHT) ){
		sv1log("----NTHT retrying [%d][%d]\n",ToS,FromS);
	}else
	if( 0 <= ToS && (ServerFlags & PF_MITM_ON) ){
		/* peeping proxy mode Bp */
	}else
	{
if( 0 <= FromS && strcmp(iSERVER_PROTO,"vsap") == 0 )
sv1log("##### HTTP/VSAP: %d/%d\n",ToS,FromS);
else
	FromS = -1;

	Conn->sv_reusing = 0;
	}
	if( FromS < 0 ){
		if( Conn->sv_reusing = getServ(Conn) ) /* FromS is set ... */
			setConnDone(Conn);
		else
		if( ClientFlags & PF_MITM_ON ){
			/* 9.8.2 MITM connection should be (re)establised
			 * only in beManInTheMiddle()
			 */
			sv1log("-- MITM broken keep-alive with the server\n");
			goto EXIT;
		}
	}
	if( lDONTHT() && withNTHT && (withNTHT & NTHT_REQ) == 0 ){
		if( removeFields(AVStr(REQ_FIELDS),"Authorization",0) )
			sv1log("----NTHT %X Q Authorization removed\n",withNTHT);
		if( removeFields(AVStr(REQ_FIELDS),"Proxy-Authorization",0) )
			sv1log("----NTHT %X Q Proxy-Authorization removed\n",withNTHT);
		if( removeFields(AVStr(REQ_FIELDS),"Via",0) )
			sv1log("----NTHT %X Q Via removed\n",withNTHT);
	}

CONNECT_RETRY:

	HTCCX_setReqSVCC(Conn,QX_proto,QX_site,QX_port,QX_upath);

	/* don't (re)try connection with server in vain */
	if( !Conn->from_myself ) /* downloading CCX tables or so */
	if( ignore_isNotAlive(Conn,FL_ARG) ){
	}else
	if( FromS < 0 && !isAlive(ClientSock) ){
		/* ClientSock can be socketpair() by STLS=fcl */
		sv1log("Client[%d] reset before conn. to serv.\n",ClientSock);
		goto EXIT;
	}
	if( FromS < 0 && tryConnects(Conn,QX,fc,tc) < 0 )
	{
		if( Conn->sv_retry == SV_RETRY_DO )
			goto RETRY;
		goto EXIT;
	}

	fs = fdopen(FromS,"r");

if( Conn->sv_reusing )
if( getenv("EMUCLOSE1") ){
	fprintf(stderr,"---------EMULATE CLOSE1\n");
	fs = NULL;
}
	if( fs == NULL ){
		sv1log("##FATAL: fdopen(FromS=%d)=NULL errno=%d\n",FromS,errno);
		if( Conn->sv_reusing ){
			clearServ(Conn);
			ServerFlags = 0; /* 9.5.7 clear PF_SSL_ON */
			Conn->sv_reusing = 0;
			FromS = -1;
			goto CONNECT_RETRY;
		}else{
			goto EXIT;
		}
	}
	if( ToServ )
		ts = ToServ;
	else{
		ts = fdopen(ToS,"w");

if( Conn->sv_reusing )
if( getenv("EMUCLOSE2") ){
	fprintf(stderr,"---------EMULATE CLOSE2\n");
	ts = NULL;
}
		if( ts == NULL ){
		    sv1log("##FATAL: fdopen(ToS=%d)=NULL errno=%d\n",ToS,errno);
			if( Conn->sv_reusing ){
				closed("fdopen(ToS)ERROR",fileno(fs),-1);
				fclose(fs);
				fs = NULL;
				clearServ(Conn);
				ServerFlags = 0;
				Conn->sv_reusing = 0;
				FromS = -1;
				goto CONNECT_RETRY; /* 9.5.7 */
			}
			goto EXIT;
		}
	}

	QX_svclose = 0;
	if( 0 <= Conn->ca_objsize && ConnType == 'i' ){
		/* response data is got by HIT_OBJ of ICP */
		QX_cpid = 0;
		QX_tsfd = -1;
		QX_fsfd = -1;
	}else{
		const char *cpath = (QX_cachefp == NULL) ? NULL : QX_cpath;
		QX_tsfd = dup(fileno(ts));
		QX_fsfd = dup(fileno(fs));

		if( lWINSOCK() )
		sv1log("-- new svsock [%d][%d,%d]->[%d,%d]\n",
			SocketOf(fileno(ts)),fileno(ts),fileno(fs),QX_tsfd,QX_fsfd);

		QX_cpid = relayRequest(Conn,QX,cpath,QX_cdate,tc,fc,ts,fs);
		if( ferror(ts) || feof(fs) ){
			if( Conn->sv_reusing ){
			sv1log("#### SERVER REUSE: closed after request\n");
				closeServ(Conn,QX,ts,fs);
				goto CONNECT_RETRY;
			}
		}
		if( 0 < BadServ ){
			/* this check should be after EOF check on server reusing */
			goto SVEXIT;
		}

		/* let non-CFI FTOSV filter detect the end of req. message */
		if( Conn->xf_filters & XF_FTOSV ){
			fflush(ts);
			close(QX_tsfd); QX_tsfd = -1;
			close(QX_fsfd); QX_fsfd = -1;
			QX_cpid = 0;
			closeFDs(ts,ts);
		}
	}

	if( DontWriteCache && QX_cachefp != NULL )
		CacheClose(QX);

	if( reqRobotsTxt(Conn) ){
		respFile = TMPFILE("HTTP-Reponse");
		tc_sav = tc;
		tc = respFile;
		chunksav = ClntAccChunk;
		ClntAccChunk = 0;
	}else	respFile = NULL;

	setRelaying(Conn,tc,QX_cachefp,QX_cpath);
	QX_rcode = relay_response(Conn,QX,
			QX_cpid,
			QX_proto,QX_site,QX_port,
			REQ,
			QX_cpath,
			0,fs,tc,fc,
			QX_cachefp,
			QX_cdate != -1);

	if( respFile ){
		ClntAccChunk = chunksav;
		tc = tc_sav;
		fflush(respFile);
		fseek(respFile,0,0);
		if( QX_rcode != R_EMPTY_RESPONSE ){
			if( reqRobotsTxt(Conn) ){
				putRobotsTxt(Conn,tc_sav,respFile,1);
			}
		}
		closed("respFile",fileno(respFile),-1);
		fclose(respFile);
		respFile = 0;
	}

	if( QX_rcode == R_EMPTY_RESPONSE ){
		if( Conn->sv_reusing ){
			sv1log("#### SERVER REUSE: got empty response\n");
			closeServ(Conn,QX,ts,fs);
			goto CONNECT_RETRY;
		}
		if( EccEnabled() )
		if( Conn->ccsv.ci_reused && Conn->ccsv.ci_reusing < 30 ){
			Conn->ccsv.ci_reusing++;
			porting_dbg("-Ecc(%2d){%d}*%d (%.2f){%d}: retry on empty response %s://%s:%d",
				Conn->ccsv.ci_ix,Conn->ccsv.ci_id,
				Conn->ccsv.ci_reused,
				Time()-Conn->ccsv.ci_connSt,
				Conn->ccsv.ci_reusing,
				DST_PROTO,DST_HOST,DST_PORT);
			closeServ(Conn,QX,ts,fs);
			Conn->ccsv.ci_reused = 0;
			goto CONNECT_RETRY;
		}
	}
	if( EccEnabled() ){
		if( Conn->ccsv.ci_reusing ){
			Conn->ccsv.ci_reusing = 0;
		}
	}

	Verbose("relay_response()=%d, cache=%x, httpStat=%c DontTruncate=%d\n",
		QX_rcode,p2i(QX_cachefp),httpStat,DontTruncate);

	if( QX_cachefp != NULL )
		doTruncateCache(Conn,QX,fc,tc);

SVEXIT:
	if( 0 <= QX_tsfd ){
		int svkeep;
		const char *reason = "";
		const char *stopcc = 0;

		if( 0 < BadServ )
		{
			svkeep = 0;
			stopcc = "BadServ";
			reason = "BadServ";
		}
		else
		if( QX_svclose & 2 ){
			svkeep = 0;
			stopcc = "Incomplete";
			reason = "Incomplete";
		}else
		if( QX_svclose ){
			svkeep = 0;
			stopcc = "Closed";
			reason = "Closed";
		}else
		if( GatewayFlags & GW_NO_HTTP_CKA ){
			svkeep = 0;
			stopcc = "Suppressed";
			reason = "Suppressed";
		}else
		if( HTTP_opts & HTTP_NOKEEPALIVE ){
			svkeep = 0;
			reason = "no-keepalive";
		}else
		if( httpStat == CS_EOF
		 && (ClientFlags & PF_MITM_ON) /* could be generic but... */
		 && (Conn->xf_filters & (XF_FTOSV|XF_FFROMSV)) == 0
		 && !finputReady(fs,ts)
		){
			/* keeping alive a server connection for other clients
			 * sould be restricted...
			 */
			sv1log("#HT11 EOF from the client (%d)(server alive)\n",
				finputReady(fc,tc));
			svkeep = putServ(Conn,QX_tsfd,QX_fsfd);
			reason = "MITM-EOF";
		}else
		if( httpStat == CS_EOF
		 || feof(fs)
		 || ferror(ts)
		 || finputReady(fs,NULL)
		/*
		 || 0 < fPollIn(fs,1)
		*/
		){
			int ch = 0xFF;
			if( httpStat != CS_EOF )
			{
				if( feof(fs) ){
					ch = EOF;
				}else
				if( READYCC(fs) <= 0
				 && !IsConnected(fileno(fs),0) ){
					ch = EOF;
				}else
				ch = getc(fs);
			}
			if( QX_emptyResp ){
				sv1log("#HT11 empty resp. from the server\n");
			}else
			if( httpStat == CS_EOF ){
				sv1log("#HT11 EOF from the client (%d)\n",
					finputReady(fs,ts));
			}else
			if( httpStat == CS_EOF || ch == EOF )
			{
				sv1log("#HT11 EOF from the server(%.2f %.2f)\n",
					Time()-QX_lastRecv,Time()-QX_lastSent);
			}
			else
			{
 sv1log("#HT11 pending data from the server, httpStat=%c [%X]\n",httpStat,ch);
 if( EccEnabled() )
 if( Conn->ccsv.ci_id )
    porting_dbg("-Ecc(%2d){%X} pending data from the server, httpStat=%c [%X]%d",
    Conn->ccsv.ci_ix,Conn->ccsv.ci_id,httpStat,ch,ll2i(READYCC(fs)));
				stopcc = "Pending";
			}
			svkeep = 0;
			reason = "feof";
		}else
		if( !feof(fs) && !ferror(ts) )
		{
			svkeep = putServ(Conn,QX_tsfd,QX_fsfd);
			reason = "putServ";
		}
		else	svkeep = 0;

		if( EccEnabled() ){
			if( QX_rcode == R_EMPTY_RESPONSE ){
				if( stopcc == 0 ){
					stopcc = "emptyResp";
				}
			}
		}
		if( svkeep == 0 ){
			if( lMULTIST() ){
				closeQXfd(Conn,QX,reason);
			}else{
			sv1log("#HT11 close svsokcs[%d,%d]\n",QX_tsfd,QX_fsfd);
			if( EccEnabled() ){
				if( stopcc ){
					destroyCCSV(stopcc,Conn,QX_tsfd);
				}
			}
			close(QX_tsfd);
			close(QX_fsfd);
			}
			if( Conn->sv_reusing ){
				sv1log("#### SERVER REUSE: got EOF\n");
				delServ(Conn,fileno(ts),fileno(fs));
			}
		}
	}

	finishServYY(FL_ARG,Conn);
	/* don't do shutdown() for keep-alive connection to server */
	closingServ(Conn,fileno(fs),fileno(ts));
	if( lMULTIST() ){
		/* 9.9.8 for HTTP/yyshd but should be done anytime */
		closed("HTTP/yyshd",fileno(fs),fileno(ts));
	}
	fclosesTIMEOUT(fs,ts);
	if( QX_cpid )
		wait(0);

	if( Conn->sv_retry == SV_RETRY_DO ){
		goto RETRY;
	}

EXIT:
	if( 0 < BadServ ){
		if( tcCLOSED ){
			/* 8.11.2: tc was closed */
		}else{
		httpStat = CS_BADREQUEST;
		putBadResponse(Conn,tc);
		}
	}
	if( QX_emptyQ )
	if( 0 <= ToS && (ServerFlags & PF_MITM_ON) ){
		/* 9.6.3-pre4 */
		ServKeepAlive = 1;
		sv1log("KeepAlive the unused server[%d,%d] %X %X\n",
			ToS,FromS,ServerFlags,ClientFlags);
		putServ(Conn,ToS,FromS);
	}

NHEXIT: /* NOTE:
	 * CurEnv might be released already after metamo. to Generalist
	 */

	ToServ = NULL;
	CacheClose(QX); /* unlock and remove AF_UNIX socket */
	if( Fromcache ){
		/* read-out from the cache without update */
	}else
	if( QX_cpath[0] && File_size(QX_cpath) == 0 ){
		sv1log("unlink empty cache: %s\n",QX_cpath);
		QX_cacheRemove = 1;
	}

	if( QX_cpath[0] && QX_rcode == R_BEFORE_RESPONSE && QX_hcode == -1 ){
		/* 9.7.8 no relay and download to cache was done yet */
	}else                           
	if( ServerFlags & PF_IS_DISTRIB ){
		/* 9.6.3 don't touch (rename as success) cache */
	}else
	if( QX_cacheRemove )
	{
		/*
		CTX_cache_remove(Conn,QX_proto,QX_site,QX_port,QX_cpath);
		9.8.2 don't try removing upper dir. on DontTruncate
		      which means 304 resp. and so on (non 404).
		*/
		int dir = 1;
		if( QX_hcode < 400
		 || DontTruncate
		){
			dir = 0;
		}
		CTX_cache_remove(Conn,QX_proto,QX_site,QX_port,QX_cpath,dir);
	}
	else
	if( Fromcache ){
	}
	else	HTcache_done(Conn,QX);
	setRelaying(NULL,NULL,NULL,NULL);
	Where = 0;

	if( numthreads() )
	if( 0 <= ToS && SocketOf(ToS) ){
		sv1log("--left connected ToS=%d/%d/%d\n",
			SocketOf(ToS),ToS,IsConnected(ToS,0));
	}
}
static void service_http2(Connection *Conn,FILE *ftc[4])
{	UTag QXut;

	setDGLEV(Conn,SB_SERV);
	if( lSINGLEP() && AVAIL_alloca ){
		QXut = UTonstack(sizeof(QueryContext));
		service_http2X(Conn,ftc,(QueryContext*)QXut.ut_addr);
	}else{
	QXut = UTalloc(SB_CONN,sizeof(QueryContext),8);
	service_http2X(Conn,ftc,(QueryContext*)QXut.ut_addr);
	UTfree(&QXut);
	}
	mem_pops(SB_SERV);
	setDGLEV(Conn,SB_CONN);
}

static void flushRESP(Connection *Conn,FILE *ftc[2])
{
	fputs(RESP_MSG,ftc[1]);
	if( RESP_MSGFP ){
		fflush(RESP_MSGFP);
		fseek(RESP_MSGFP,0,0);
		copyfile1(RESP_MSGFP,ftc[1]);
		fclose(RESP_MSGFP);
		RESP_MSGFP = NULL;
	}
}

void savReqAuthorization(Connection *Conn,PCStr(head))
{	const char *fvp;
	CStr(up,128);

	if( fvp = findFieldValue(head,"Authorization") ){
		HTTP_decompAuthX(fvp,AVStr(SVREQ_ATYP),sizeof(SVREQ_ATYP),
			AVStr(up),sizeof(up),NULL);
	}
}
int NTLM_HTTP_connect(Connection *Conn,int toproxy,AuthInfo *qa,PCStr(req),PCStr(head)){
	int svka = 0;
	int hcode;

	if( withNTHT & NTHT_SERVKA ){
		if( getServ(Conn) ){
			svka = IsAlive(ToS);
		}
	}
	sv1log("----NTHT connect %s@%s:%d ka=%X,%d\n",qa->i_user,
		DST_HOST,DST_PORT,withNTHT&NTHT_SERVKA,svka);
	if( svka ){
	}else
	if( connect_to_serv(Conn,FromC,ToC,0) < 0 ){
		return -1;
	}
	hcode = NTHT_connect(toproxy,ToS,FromS,req,head,qa->i_user,qa->i_pass,NTHT_utoken,NTHT_nego);
	if( hcode < 0 )
		return -1;
	if( CurEnv == 0 ){
		return hcode;
	}

	if( 0 < hcode )
	if( 0 < PollIn(FromS,300) )
	if( !IsAlive(FromS) ){
		IStr(resp,1024);
		sprintf(resp,"HTTP/1.0 %d\r\n\r\n%d\r\n",
			hcode,hcode);
		IGNRETP write(ToC,resp,strlen(resp));
		withNTHT = 0;
		clntClose(Conn,"a:auth. result");
		sv1log("----HTLM hcode=%d server closed\n",hcode);
		return hcode;
	}
	return 0;
}
static void retryAuth(Connection *Conn,FILE *ftc[2])
{ 	CStr(resauth,1024);
	CStr(ratyp,32);
	const char *dgv;
	const char *rfname;
	const char *qfname;
	const char *fvp;
	MrefQStr(qp,OREQ_MSG); /**/
	refQStr(rp,RESP_MSG);
	CStr(reqauth,URLSZ);
	CStr(qatyp,32);
	const char *nqatyp;
	CStr(user,64);
	CStr(pass,64);
	CStr(up,128);
	AuthInfo seed,qauth;
	CStr(resp_add,256);
	int req_asis = 0;

	if( lDONTHT() && withNTHT ){
		sv1log("----NTHT retryAuth: %X NTHT=%X\n",RESP_SAV,withNTHT);
		if( lSECRET() ){
			sv1log("----NTHT retryAuth: %s%sX\n",REQ,REQ_FIELDS);
		}
		/*
		if( (withNTHT & NTHT_REQ) && (withNTHT & NTHT_RES) ){
		*/
		if( withNTHT & NTHT_RES ){
			if( withNTHT & NTHT_CLAUTHOK ){
				sv1log("----NTHT with client's auth.\n");
			}else
			if( (HTTP_opts & HTTP_DOAUTHCONV) == 0 ){
				sv1log("----NTHT without auth. conv.\n");
				flushRESP(Conn,ftc);
				return;
			}
		}
	}
	if( !RESP_SAV ){
		return;
	}

	/*
	 * hop-by-hop header must be removed from RESP_MSG
	 */
	removeFields(AVStr(RESP_MSG),"Connection",0);
	removeFields(AVStr(RESP_MSG),"Transfer-Encoding",0);

	resp_add[0] = 0;
	if( RespCode == 401 ){
		rfname = "WWW-Authenticate";
		qfname = "Authorization";
	}else
	if( RespCode == 407 ){
		rfname = "Proxy-Authenticate";
		qfname = "Proxy-Authorization";
	}else{
		flushRESP(Conn,ftc);
		return;
	}

	user[0] = 0;
	pass[0] = 0;
	clearVStr(qatyp);
	bzero(&qauth,sizeof(AuthInfo));
	if( fvp = findFieldValue(OREQ_MSG,qfname) ){
		HTTP_decompAuthX(fvp,AVStr(qatyp),sizeof(qatyp),AVStr(up),sizeof(up),&qauth);
		if( strcaseeq(qatyp,"Digest") ){
			flushRESP(Conn,ftc);
			return;
		}
	}

	if( getFV(RESP_MSG,rfname,resauth) == NULL ){
		sv1log("retryAuth: NO %s field\n",rfname);
		flushRESP(Conn,ftc);
		return;
	}
	dgv = wordScan(resauth,ratyp);

	if( lDONTHT() )
	if( withNTHT & NTHT_RES )
	if( strcaseeq(ratyp,"NTLM")
	 || strcaseeq(ratyp,"Negotiate")
	){
		IStr(vhost,128);
		IStr(realm,128);
		const char *vpath;
		int hcode;

		sv1log("----NTHT retryAuth: %X [%s][%s][%s]\n",
			withNTHT,ratyp,qatyp,qauth.i_user);
		if( withNTHT & NTHT_CLAUTHOK ){
			/*
			hcode = NTLM_HTTP_connect(Conn,0,&qauth,REQ,REQ_FIELDS);
			*/
			hcode = NTLM_HTTP_connect(Conn,toProxy,&qauth,REQ,REQ_FIELDS);
			if( hcode == 0 ){
				sv1log("----NTHT forward OK [%s]%X\n",
					NTHT_user,p2i(NTHT_utoken));
				withNTHT |= NTHT_SVAUTHOK;
				withNTHT |= NTHT_CLNTHT;
				removeFields(AVStr(OREQ_MSG),qfname,0);
				OREQ_LEN = strlen(OREQ_MSG);
				nqatyp = "Negotiate";
				goto RETRY;
			}
			sv1log("----NTHT forward connect NG=%d\n",hcode);
			if( 0 < hcode ){
				return;
			}
			sv1log("----NTHT forward connect NG %X\n",p2i(NTHT_utoken));
			/* the response for the original request was
			 * already done with HTTP/1.1 100. code.
			 * can be due to proctectection of the URL.
			 */
			replaceFieldValue(AVStr(RESP_MSG),
				"Proxy-Support","Session-Based-Authentication");
			flushRESP(Conn,ftc);
			return;
		}
		if( strcaseeq(qatyp,"Basic") ){
			hcode = NTLM_HTTP_connect(Conn,0,&qauth,REQ,REQ_FIELDS);
			if( hcode == 0 ){
				sv1log("----NTHT gateway connect OK\n");
				// withNTHT |= NTHT_CONNECTED;
				withNTHT |= NTHT_SVAUTHOK;
				withNTHT |= NTHT_CLBASIC;
				removeFields(AVStr(OREQ_MSG),qfname,0);
				OREQ_LEN = strlen(OREQ_MSG);
				nqatyp = "Negotiate";
				goto RETRY;
			}
			sv1log("----NTHT gateway connect NG=%d\n",hcode);
			if( 0 < hcode ){
				return;
			}
		}
		if( IsMounted && (vpath = MountVbase(MountOptions)) ){
			HTTP_getHost(Conn,REQ,REQ_FIELDS);
			HTTP_ClientIF_HP(Conn,AVStr(vhost));
			sprintf(realm,"Basic realm=%s%s",vhost,vpath);
		}else	sprintf(realm,"Basic realm=proxy");
		removeFields(AVStr(RESP_MSG),rfname,0);
		replaceFieldValue(AVStr(RESP_MSG),rfname,realm);
		sv1log("RESP_MSG:\n%s",RESP_MSG);
		flushRESP(Conn,ftc);
		return;
	}
	if( strcaseeq(ratyp,"Basic")
	 && (HTTP_opts & HTTP_AUTHBASIC_DELAY_SV) ){
		/* Basic was blocked not to send cleartext password
		 * for Digest server */
		if( strcaseeq(qatyp,"Basic") ){
			req_asis = 1;
			nqatyp = "Basic";
			if( getDigestInCookie(AVStr(OREQ_MSG),NULL) )
				resetDigestInCookie(Conn,AVStr(resp_add));
			goto RETRY;
		}
	}
	if( !strcaseeq(ratyp,"Digest") ){
		flushRESP(Conn,ftc);
		return;
	}
	nqatyp = "Digest";

	if( qauth.i_user[0] ){
		wordScan(qauth.i_user,user);
		wordScan(qauth.i_pass,pass);
		removeFields(AVStr(OREQ_MSG),qfname,0);
		OREQ_LEN = strlen(OREQ_MSG);
	}
	bzero(&seed,sizeof(AuthInfo));
	scanDigestParams((char*)dgv,&seed,VStrNULL,0);
	if( strcaseeq(SVREQ_ATYP,"Digest") ){
		if( seed.i_error & AUTH_ESTALE ){
			sv1log("retryAuth: STALE\n");
		}else{
			/* don't retry if new Digest is the same with old ...*/
		}
	}
	setDigestInCookie(Conn,&seed,AVStr(resp_add));

	if( user[0] == 0 ){
		if( (HTTP_opts&HTTP_THRUDIGEST_CL) == 0 )
		if( (HTTP_opts&HTTP_FORCEBASIC_CL) || UAwithoutDigest(Conn) ){
			sprintf(resauth,"Basic realm=\"%s\"",seed.i_realm);
			replaceFieldValue(AVStr(RESP_MSG),rfname,resauth);
		}
		if( resp_add[0] ){
			if( rp = strSeekEOH(RESP_MSG) )
				RFC822_addHeaderField(AVStr(rp),resp_add);
		}
		RESP_LEN = strlen(RESP_MSG);
		flushRESP(Conn,ftc);
		return;
	}

	genAuthDigest(Conn,"Authorization",AVStr(reqauth),sizeof(reqauth),&seed,
		user,pass);
	if( sizeof(OREQ_MSG) <= OREQ_LEN+strlen(reqauth) ){
		sv1log("retryAuth: too large request.\n");
		flushRESP(Conn,ftc);
		return;
	}
	if( qp = strSeekEOH(OREQ_MSG) )
		RFC822_addHeaderField(QVStr(qp,OREQ_MSG),reqauth);
	OREQ_LEN += strlen(reqauth);

RETRY:

	sv1log("retryAuth: client:%s -> server:[%s -> %s]\n",
		qatyp,SVREQ_ATYP[0]?SVREQ_ATYP:"NULL",nqatyp);

	ConnType = 0;
	DDI_pushCbuf(Conn,OREQ_MSG,OREQ_LEN);
	resetHTTPenv(Conn,CurEnv);

	REQ_ASIS = req_asis;
	Xstrcat(AVStr(RESP_ADD),resp_add);
	service_http2(Conn,ftc);

	if( RespCode == 401 || RespCode == 407 ){
		if( resp_add[0] ){
			if( rp = strSeekEOH(RESP_MSG) )
				RFC822_addHeaderField(AVStr(rp),resp_add);
			RESP_LEN = strlen(RESP_MSG);
		}
		flushRESP(Conn,ftc);
	}
}
/*
 * To cope with 305/306 response, current DeleGate implements it like this:
 * Whole request message including message body must be kept for
 * transparent automatic retry by the proxy, and two transactions
 * will occur always.
 * One another way is recording a triple (method,URL,proxy) for each
 * 305/306 response to be looked by succeeding proxy processes to decide
 * their routing.  But, it seems expensive too.
 */
static void proxyRedirect(Connection *Conn,FILE *ftc[2])
{	int redirects;
	CStr(proxy,1024);
	int comask;
	HtResp htResp;

	htResp = CurEnv->r_resp;
	for( redirects = 0; redirects < 4; redirects++ ){
		if( RespCode != 305 && RespCode != 306 )
			break;
		if( getFV(RESP_MSG,"Set-Proxy",proxy) == NULL )
			break;
		if( sizeof(OREQ_MSG) <= OREQ_LEN )
			break; /* incompletely buffered */
		if( strncasecmp(proxy,"DIRECT",5) == 0 ){
			sv1log("#### must be accessed without proxy: %s",OREQ);
			if( ConnType == 'p' || ConnType == 'm' ){
				ConnType = 0;
				DDI_pushCbuf(Conn,OREQ_MSG,OREQ_LEN);
				comask = Conn->co_mask;
				Conn->co_mask = (CONN_NOPROXY | CONN_NOMASTER);
				resetHTTPenv(Conn,CurEnv);
				service_http2(Conn,ftc);
				Conn->co_mask = comask;
				continue;
			}
		}
		break;
	}
	if( RESP_LEN == 0 ) /* redirection might be aborted */
		CurEnv->r_resp = htResp;

	if( RespCode == 305 || RespCode == 306 || ConnType == 0 )
	{
		flushRESP(Conn,ftc);
		/*
		fputs(RESP_MSG,ftc[1]);
		if( RESP_MSGFP ){
			fflush(RESP_MSGFP);
			fseek(RESP_MSGFP,0,0);
			copyfile1(RESP_MSGFP,ftc[1]);
			fclose(RESP_MSGFP);
			RESP_MSGFP = NULL;
		}
		*/
	}

	/*
	 * if Proxy-Authorization is required, retry with it... ?
	 */
}

void service_httpY(Connection *Conn,HTTP_env *httpEnvp);
void service_httpX(Connection *Conn)
{	HTTP_env httpEnv;

	if( lTHREADLOG() ){
		putfLog("thread-main %X %X",getthreadid(),ismainthread());
	}
	if( lSINGLEP() && AVAIL_alloca ){
		httpEnv.r_resp.r_msg = UTonstack(1024);
		httpEnv.r_i_buff = UTonstack(URLSZ);
		httpEnv.r_o_buff = UTonstack(OBUFSIZE);
		httpEnv.r_savConn = UTonstack(sizeof(Connection));
		httpEnv.r_acclangs = UTonstack(1024);
		httpEnv.r_ohost = UTonstack(1024);
	}else{
	httpEnv.r_resp.r_msg = UTalloc(SB_CONN,1024,1);
	httpEnv.r_i_buff = UTalloc(SB_CONN,URLSZ,1);
	httpEnv.r_o_buff = UTalloc(SB_CONN,OBUFSIZE,1);
	httpEnv.r_savConn = UTalloc(SB_CONN,sizeof(Connection),8);
	httpEnv.r_acclangs = UTalloc(SB_CONN,1024,1);
	httpEnv.r_ohost = UTalloc(SB_CONN,1024,1);
	}

	service_httpY(Conn,&httpEnv);

	if( lSINGLEP() ){
	}else{
	UTfree(&httpEnv.r_ohost);
	UTfree(&httpEnv.r_acclangs);
	UTfree(&httpEnv.r_savConn);
	UTfree(&httpEnv.r_o_buff);
	UTfree(&httpEnv.r_i_buff);
	UTfree(&httpEnv.r_resp.r_msg);
	}

	if( 1 ){
		void DDI_clearCbuf(Connection *Conn);
		if( FromCbuff ){
			if( 1 < lMALLOC() )
			fprintf(stderr,"-dm HTTP free FromCbuf %X %d\n",
				p2i(FromCbuff),FromCsize);
			DDI_clearCbuf(Conn);
		}
		if( lSINGLEP() ){
			/* 9.8.2 reuse the buffer */
		}else
		if( D_REQUESTtag.ut_addr ){
			if( 2 < lMALLOC() )
			fprintf(stderr,"-dm HTTP free D_REQ %X strg=%d\n",
				p2i(D_REQUESTtag.ut_addr),D_REQUESTtag.ut_strg);
			UTfree(&D_REQUESTtag);
		}
		if( GatewayPath ){
			if( 1 < lMALLOC() )
			fprintf(stderr,"-dm HTTP free GWP %X\n",p2i(GatewayPath));
			free((char*)GatewayPath);
			GatewayPath = 0;
		}
	}

 if(0){
 IStr(rusg,128);
 strfRusage(AVStr(rusg),"%A",1,NULL);
 sv1tlog("---- %s\n",rusg);
 }
}

int alive_peers();
int MAX_DELEGATEP(int dyn);
#define MAX_DELEGATE MAX_DELEGATEP(0)
int heavy_load(){
	if( MAX_DELEGATE/2 <= alive_peers() ){
		sv1log("Heavy? %d / %d\n",alive_peers(),MAX_DELEGATE);
		return 1;
	}
	return 0;
}

int isNonAdminRequest(Connection *Conn,FILE *fc,FILE *tc){
	CStr(req,32);
	HttpRequest reqx;

	if( (ClientFlags & PF_ADMIN_SW) == 0 )
		return 0;
	if( Conn->clif._adminPort == Conn->clif._userPort )
		return 0;

	if( DDI_fgetsFromC(Conn,AVStr(req),sizeof(req),fc) == NULL )
		return 0;
	DDI_pushCbuf(Conn,req,strlen(req));

	decomp_http_request(req,&reqx);
	if( strncmp(reqx.hq_url,"/-/",3) == 0 ){
		return 0;
	}
	fprintf(tc,"HTTP/1.0 500 Non-Admin request\r\n");
	fprintf(tc,"Content-Type: text/plain\r\n");
	fprintf(tc,"Connection: close\r\n");
	fprintf(tc,"\r\n");
	fprintf(tc,"*** Non-Admin request for a non-HTTP server ***\r\n");
	daemonlog("F","Non-Admin request [%s] <= [%s:%d] %s",iSERVER_PROTO,
		Client_Host,Client_Port,req);
	return 1;
}

int closeNNTPserver(Connection *Conn);
int timeoutWait(int to);
void WaitShutdown(Connection *Conn,FILE *tc,int force);
extern int HTTP_flags;
void service_httpY(Connection *Conn,HTTP_env *httpEnvp)
{	FILE *fc,*tc;
	FILE *ftc[4];
	vfuncp osigint = NULL;
	vfuncp osigterm = NULL;
	vfuncp osigpipe = NULL;
	int keepAlive,clntKeepAlive,Serno,tm0;
	int nka;
	int timeout,timeout1,timeout2,rtimeout,ptimeout,nready,till;
	double Start = Time();
	int linger = lSINGLEP()?SINGLEP_LINGER:DELEGATE_LINGER;
	const char *FTOCL;
	FTOCL = getFTOCL(Conn);

	bzero(&httpEnvp->r_env0,sizeof(httpEnvp->r_env0));
	if( isWindowsCE() ){
		set_linger(ClientSock,linger);
	}
	if( HTTP_opts & HTTP_NODELAY )
		set_nodelay(ClientSock,1);

	tc = fdopen(ToC,"w");
	if( tc == 0 ){
	http_Log(Conn,500,CS_ERROR,"ERR cannot_fdopen(to_client)",0);
	Exit(-1,"fdopen(ToC=%d) failed\n",ToC);
	}
	tcCLOSED = 0;

	fc = fdopen(FromC,"r");
	if( fc == NULL ){
	http_Log(Conn,500,CS_ERROR,"ERR cannot_fdopen(from_client)",0);
	Exit(-1,"fdopen(FromC=%d) failed\n",FromC);
	}

	ftc[0] = fc;
	ftc[1] = tc;
	ftc[2] = 0;
	ftc[3] = 0;

	/* setbuff tc after for IRIX-5.3 ... ?_? */
	setbuffer(fc,(char*)httpEnvp->r_i_buff.ut_addr,httpEnvp->r_i_buff.ut_size);
	setbuffer(tc,(char*)httpEnvp->r_o_buff.ut_addr,httpEnvp->r_o_buff.ut_size);
	/*
	this is bad with ImMaster, it must be after returnAckOK()
	if( HTTP_STARTTLS_withCL(Conn,fc,tc) ){
		syslog_ERROR("**** delayed detection of SSL\n");
	}
	*/

	osigint = Vsignal(SIGINT,sigTERM);
	osigterm = Vsignal(SIGTERM,sigTERM);
	osigpipe = Vsignal(SIGPIPE,sigPIPE);
	nsigPIPE = 0;

	Conn->sv_dfltsav = Conn->sv_dflt;
	*(Connection*)httpEnvp->r_savConn.ut_addr = *Conn;
	keepAlive = 0;
	clntKeepAlive = 0;
	Serno = 0;
	WhyClosed[0] = 0;

	timeout = (int)HTTP_TOUT_CKA;
	CKA_RemAlive = HTTP_CKA_MAXREQ;
	StopKeepAlive = 0;

	if( lNOCLNTKA() ){
		CKA_RemAlive = 0;
	}else
	if( HTTP_opts & HTTP_NOKEEPALIVE ){
		sprintf(WhyClosed,"H:HTTPCONF=bugs:no-keepalive");
		CKA_RemAlive = 0;
	}else
	if( 0 < CKA_RemAlive && Conn->cl_count > HTTP_CKA_PERCLIENT ){
		CStr(clhost,MaxHostNameLen);
		if( getClientHostPort(Conn,AVStr(clhost)) == 0 )
			strcpy(clhost,"?");
		Verbose("HCKA: too many connections %d/%d for %s\n",
			Conn->cl_count,HTTP_CKA_PERCLIENT,clhost);
		sprintf(WhyClosed,"X:too many Keep-Alive (%s*%d)",clhost,Conn->cl_count);
		CKA_RemAlive = 0;
	}else
	if( 0 < CKA_RemAlive && Conn->cl_count == 1 && 1 < HTTP_CKA_PERCLIENT ){
		timeout = timeout * 10;
		if( timeout < 20 ) timeout = 20;
		if( 60 < timeout ) timeout = 60;
		CKA_RemAlive = CKA_RemAlive * 10;
		if( CKA_RemAlive < 20 ) CKA_RemAlive = 20;
		if( HTTP_CKA_MAXREQ < 60 )
		if( 60 < CKA_RemAlive ) CKA_RemAlive = 60;
	}

	if( heavy_load() ){
		int sIO_TIMEOUT = IO_TIMEOUT;
		int stimeout = timeout;
		/* don't increase idle processes waiting in I/O */
		if( 10 < IO_TIMEOUT ){
			IO_TIMEOUT = 10;
		}
		/* don't increase idle processes waiting in Keep-Alive */
		if( 10 < timeout ){
			timeout = 10;
		}
		sv1log("Heavy, Shorten TIMEOUT: io:%d->%d cka:%d->%d\n",
			sIO_TIMEOUT,IO_TIMEOUT,stimeout,timeout);
	}

	rtimeout = (int)(timeout + HTTP_TOUT_CKA_MARGIN);
	ptimeout = 20;
	if( rtimeout <= ptimeout ){
		timeout1 = rtimeout;
		timeout2 = 0;
	}else{
		timeout1 = ptimeout;
		timeout2 = rtimeout - ptimeout;
	}

	nka = 0;
	do {
		if( keepAlive ){
			int fkeep,xf,sf;
			/* second or later request in Keep-Alive mode */
			LOGX_app_keepAliveCL++;

			/*
			if( lSINGLEP() ){
			*/
			if( lSINGLEP() || lFXNUMSERV() ){
			    int ready;
			    int tout1 = lMULTIST() ? 500 : 50;
			    ready = DDI_PollIn(Conn,fc,tout1);
			    if( ready == 0 ){
				int tout = 0;
				double St = Time();
				ready = poll2(3*1000,fileno(fc),ServSockX());
				if( (ready & 1) == 0 ){
					linger = 0;
					tout = 1;
				}
				if( lCONNECT() )
				fprintf(stderr,
				"--{c} keep-alive %d %d (%.2f) %d %s %d %s\n",
					nka,REQUEST_SERNO,Time()-Start,
					SERVREQ_SERNO+1,DST_HOST,
					ready,tout?"TIMEOUT":"");
				if( tout ){
					break;
				}
			    }
			}
			if( DDI_proceedFromC(Conn,fc) < 0 ){
				/* Flush possibly bufferd previous request in
				 * input buff. not read but peeked only.
				 * This must be done before clear_DGref() which
				 * will clear control data of the peeking.
				 */
				clntClose(Conn,"d:by client(request EOF-0)");
				setClientEOF(Conn,fc,"request-EOF-0");
				break;
			}
			fkeep = ClientFlags & PF_MITM_ON;
			if( fkeep ){
				xf = Conn->xf_filters & XF_FCL;
				if( aliveServ(Conn) ){
					xf |= Conn->xf_filters & XF_FSV;
					sf = ServerFlags;
				}else	sf = 0;
			}
			clear_DGreq(Conn);
			if( actthreads() && ServerFilter.f_tid ){
				/* 9.9.4 before restore ServerFilter */
				if( waitFilterThread(Conn,1,XF_FSV) ){
					putfLog("FSV thread-SSLway cleared-A");
				}else{
					putfLog("FSV thread-SSLway remaining-A");
				}
			}
			restoreConn(Conn,(Connection*)httpEnvp->r_savConn.ut_addr);
			if( fkeep ){
				Conn->xf_filters = xf;
				ServerFlags = sf;
			}
		}
		setHTTPenv(Conn,httpEnvp);
		if( lDONTHT() && keepAlive ){
			sv1log("----NTHT %X KA=%d\n",withNTHT,keepAlive);
		}
		sav_FTOCL = FTOCL;
		if( 0 < CKA_RemAlive ){
			setKeepAlive(Conn,timeout);
		}
		if( keepAlive == 0 ){
			if( ImMaster ){
				/* should returnAckOK() immediately in http2X */
			}else
			if( DDI_PollIn(Conn,fc,IO_TIMEOUT*1000) <= 0 ){
				httpStat = CS_REQTIMEOUT;
http_log(Conn,CLNT_PROTO,"",0,"",500,"",-1,0,Time()-Start,0.0);
				break;
			}
		}
		if( keepAlive ){
			if( feof(fc) ){
				clntClose(Conn,"d:by client(request EOF-1)");
				setClientEOF(Conn,fc,"request-EOF-1");
				break;
			}
			if( checkClientEOF(Conn,tc,"keep_alive") ){
				clntClose(Conn,"d:by client(request EOF-2)");
				break;
			}

			fflushKeepAlive(Conn,"request-EOF-3",fc,tc,0);
			if( ClientEOF ){
				clntClose(Conn,"d:by client(request EOF-3)");
				break;
			}
			/* if the flush of the response to the client is
			 * postponed here, it must be flushed when
			 * the connection to or the response from
			 * the next server is blocked... (may be in 
			 * service_http2())
			 */

			till = time(0) + timeout;

			tm0 = time(0);
			nready = DDI_PollIn(Conn,fc,timeout1*1000);
			if( nready < 0 ){
				clntClose(Conn,"d:by client(request EOF-4)");
				setClientEOF(Conn,fc,"request-EOF-4");
				break;
			}

			if( nready == 0 && 0 < timeout2 ){
				ProcTitle(Conn,"(HTTP:keep-alive=%02d:%02d)",
					(till%3600)/60,till%60);

				/* close ServPort not to block other clients
				 */
				checkCloseOnTimeout(0);
				LOG_flushall();
				/*
				nready = fPollIn(fc,timeout2*1000);
				*/
				nready = fPollInSX(fc,timeout2*1000);
			}

			if( nready < 0 ){
				clntClose(Conn,"d:by client(request EOF-5)");
				setClientEOF(Conn,fc,"request-EOF-5");
				break;
			}
			if( nready == 0 ){
				clntClose(Conn,"t:timeout: %d",time(0)-tm0);

				/* to finish FCL=sslway filter */
				if( Conn->xf_filters & XF_FCL )
				if( ClientFlags & (PF_SSL_ON|PF_STLS_ON) ){
					fshutdown(fc,1);
				}
				break;
			}
			if( READYCC(fc) == 0 )
			if( file_isSOCKET(fileno(fc)) ) /* without FFROMCL */
			if( Peek1(fileno(fc)) < 1 ){
				clntClose(Conn,"d:by client(request EOF-6)");
				setClientEOF(Conn,fc,"request-EOF-6");
				break;
			}
			if( isNonAdminRequest(Conn,fc,tc) )
				break;

			/* close ServPort because this delegated may be
			 * devoted to a single client
			 */
			checkCloseOnTimeout(0);
			LOGX_app_keepAliveCLreu++;
		}
		if( actthreads() && ServerFilter.f_tid ){
			/* 9.9.4 before ServerFilter is abandoned */
			if( waitFilterThread(Conn,1,XF_FSV) ){
				putfLog("FSV thread-SSLway cleared-B");
			}else{
				putfLog("FSV thread-SSLway remaining-B");
			}
		}

		strcpy(REQ_METHOD,"?");
		if( keepAlive )
			WhyClosed[0] = '-';
		else
		if( WhyClosed[0] == 0 )
			WhyClosed[0] = '?';
		SentKeepAlive = 0;
		ClntAccChunk = 0;
		setFTOCL(NULL);
		ClientFlags |= HTTP_flags;
		gotCLX = 0;
		service_http2(Conn,ftc);
		if( isWindows() )
		if( gotCLX ){
			/* 9.6.3 incomplete relay by premature reset from
			 * the client. */
			sv1log("---CLX 0x%X (%d %d %d %d) %d/%d\n",
				gotCLX,tcCLOSED,ClientEOF,
				!IsAlive(ClientSock),
				!IsConnected(ClientSock,NULL),
				actthreads(),numthreads()
			);
			init_socketpair(0);
			gotCLX = 0;
			break;
		}
		if( ftc[0] == NULL || ftc[1] == NULL )
		{
			if( fc == ftc[2] )
			porting_dbg("##MITM broken?? [%X %X][%X %X][%X %X]",
				p2i(fc),p2i(tc),p2i(ftc[0]),p2i(ftc[1]),p2i(ftc[2]),p2i(ftc[3]));
			break;
		}
		if( (ClientFlags & PF_MITM_ON) && ftc[1] && tc != ftc[1] ){
			int KA = WillKeepAlive && SentKeepAlive && CKA_RemAlive;
			porting_dbg("##MITM SSL [%d %X %X][%d %X %X]",
				fileno(fc),p2i(fc),p2i(ftc[2]),fileno(tc),p2i(tc),p2i(ftc[3]));
			if( fc != 0 && fc == ftc[2] ){
				if( KA && fileno(fc) == ClientSock ){
					/* 9.9.4 */
					Verbose("##MITM KA:fc %d\n",fileno(fc));
					fcloseFILE(fc);
				}else
				if( fc == tc )
					fcloseFILE(fc);
				else{
					closed("MITM-fc",fileno(fc),-1);
					fclose(fc);
				}
				/*
				else	fclose(fc);
				*/
				ftc[2] = 0;
			}
			if( tc != 0 && tc == ftc[3] ){
				if( KA && fileno(tc) == ClientSock ){
					Verbose("##MITM KA:tc %d\n",fileno(tc));
					fcloseFILE(tc);
				}else
				{
					closed("MITM-tc",fileno(tc),-1);
				fclose(tc);
				}
				ftc[3] = 0;
			}
			fc = ftc[0];
			tc = ftc[1];
		}

		if( RespCode == 305 || RespCode == 306 )
			proxyRedirect(Conn,ftc);
		else
		if( RespCode == 401 || RespCode == 407 )
			retryAuth(Conn,ftc);

		CKA_RemAlive--;
		clntKeepAlive |= ClntKeepAlive;
		RES_CACHE_DISABLE = 0;

		if( tcCLOSED || ClientEOF )
			break;

		if( fflushTIMEOUT(tc) == EOF ){
			clntClose(Conn,"d:by client(request EOF-7)");
			setClientEOF(Conn,fc,"request-EOF-7");
			break;
		}

		if( getSoftBreak(Conn,"") ){
			clntClose(Conn,"b:soft Break-1 detected");
			break;
		}
		if( StopKeepAlive ){
			clntClose(Conn,"b:soft Break-2 detected");
			break;
		}

		if( 0 < CKA_RemAlive ){
			if( !streq(REQ_METHOD,"?") ) /* not empty request */
				Serno = incRequestSerno(Conn);
			if( keepAlive || WillKeepAlive )
				Verbose("HCKA:[%d] KeepAlive: %s %c =>%d\n",
					Serno,REQ_METHOD,httpStat,WillKeepAlive);
		}
		keepAlive = WillKeepAlive && SentKeepAlive;
		if( keepAlive )
			nka++;
	} while( keepAlive && 0 < CKA_RemAlive );
	setHTTPenv(Conn,NULL);

	if( clntKeepAlive && 1 < HTTP_CKA_MAXREQ ){
		if( streq(WhyClosed,"-") && CKA_RemAlive == 0 )
			strcpy(WhyClosed,"Max-KeepAlive");
		http_logplus(Conn,WhyClosed[0]);
		if( lNOCLNTKA() || (HTTP_opts & HTTP_NOKEEPALIVE) ){
		}else
		sv1log("HCKA:[%d] closed -- %s\n",RequestSerno,WhyClosed);
	}
	if( HTTP_opts & HTTP_DUMPSTAT )
	fprintf(stderr,"[%d][%2d]%2d %s\n",getpid(),nka,CKA_RemAlive,WhyClosed);

	Where = "closeClient";

	waitPreFilter(Conn,300);
	if( ftc[0] == NULL || ftc[1] == NULL ){
		sv1log("fclose() already: fc=%X/%d tc=%X/%d\n",
			p2i(fc),p2i(ftc[0]),p2i(tc),p2i(ftc[1]));
	}else
	if( tcCLOSED )
	{
		if( isWindowsCE() || lMULTIST() ){
			fcloseFILE(fc);
		}else
		if( 0 < actthreads() && fileno(fc) != FromC ){
			/* 9.8.6 fileno(fc) is closed already and could
			 * be reused by other threads
			 * --- this must not happen:
			 * it is not closed with tcCLOSED=1. it was closed in
			 * insert_FPROTO() but was fixed in 9.8.6-pre9
			 */
			sv1log("## tcCLOSED fc=%d FromC=%d ToC=%d CS=%d\n",
				fileno(fc),FromC,ToC,ClientSock);
			fcloseFILE(fc);
		}else
		{
		closed("HTTPexit(fc)",fileno(fc),-1);
		fclose(fc);
		}
	}
	else{
		if( ftc[1] != 0 && ftc[1] != tc ) /* with on-demand FTOCL */
		{
			closed("HTTPexit(ftc[1])",fileno(ftc[1]),-1);
			fclose(ftc[1]);
			timeoutWait(100);
		}

		if( checkClientEOF(Conn,tc,NULL) ){
			int fd = fileno(tc);
			if( isWindowsCE() || lSINGLEP() || lMULTIST() ){
				linger = 0;
				set_linger(fd,linger);
				/* keep the descriptor valid for fclose() */
				dupclosed(fd);
			}else
			{
			closed("HTTPexit(tc)",fd,-1);
			close(fd);
			}
			Verbose("## [%d] don't flush to cause SIGPIPE\n",fd);
		}else{
			if( 0 < DELEGATE_LINGER )
			if( lSINGLEP() ){ /* not to block in closesocket() */
				set_linger(fileno(tc),linger);
			}else
				set_linger(fileno(tc),DELEGATE_LINGER);
		}
		/*
		fshutdown(tc,0);
		*/
		if( lSINGLEP() ){
			int waitFilterThreadX(Connection *Conn);
			/* tc might be closed in the ResponseFilter thread,
			 * which is indicated by ClientEOF&2 and tcCLOSED&2.
			 */
			if( waitFilterThreadX(Conn) == 0 ){
				/* it might be already waited in httpd.c
				 * for local data as an origin server
				 */
			}
			if( ClientEOF & 2 ){
			}else{
				fcloseFILE(tc);
			}
			fcloseFILE(fc);
		}else{
			if( actthreads() ){
				/* 9.9.4 should wait zombi threads */
			}
		WaitShutdown(Conn,tc,0);
		fclosesTIMEOUT(tc,fc); /* close tc first */
		}
	}
	Vsignal(SIGPIPE,osigpipe);
	Vsignal(SIGTERM,osigterm);
	Vsignal(SIGINT,osigint);

	setFTOCL(FTOCL);
	clear_DGreq(Conn); /* 9.8.2 */
	if( lSINGLEP() && 0 <= ClientSock ){
		/*
		this causes truncation of resp. on WinCE
		set_linger(ClientSock,0);
		*/
	}
}

#undef fshutdown
/*
 * Wait child processes before doing shutdown() the client side connection.
 * Client side filter process might not have been finished (not wait()ed)
 * at this point because of bugs.  An existed example of the problem:
 *  1) FSV process for FTP by FTP/HTTP-gw. finishes
 *  2) wait(0) for respFilter -> detects the exit of FSV instead of respFilter
 *  3) FILE *tc points not to filter but to original ClientSock in this case,
 *     thus fshutdown(tc) of the connection truncated the response data.
 */
int NumBits(int i32);
#define nbits NumBits
void WaitShutdown(Connection *Conn,FILE *tc,int force)
{	int x,xpid,nproc,xproc;
	int noshut = 0;

	if( Conn->xf_filters & XF_FTOCL )
	if( 0 <= ToC && ToC != fileno(tc) ){
		/* 9.7.8 close the pipe with the filter before waiting it */
		if( lFILEDESC() ){
			sv1log("{F} >>ToC[%d]-tc[%d] ClS[%d]\n",
				ToC,fileno(tc),ClientSock);
		}
		close(ToC);
		closed("WaitShutdown",ToC,-1);
	}

	if( Conn->xf_pidFFROMCL ){
		sv1log("Terminate FFROMCL: %d\n",Conn->xf_pidFFROMCL);
		Kill(Conn->xf_pidFFROMCL,SIGTERM);
		Conn->xf_pidFFROMCL = 0;
	}
	/*
	nproc = nbits(Conn->xf_filters & ~XF_CLIENT)
	*/
	nproc = nbits(Conn->xf_filters)
	      + nbits(Conn->xf_clprocs)
	      + nbits(Conn->fi_builtin);

	if( 0 < nproc )
	if( Conn->xf_filters & XF_FSV ){
		if( aliveServ(Conn) ){
			if( ServerFlags & (PF_MITM_ON|PF_SSL_ON) ){
daemonlog("E","WaitShutdown Flags=%X FSV=sslway alive:%d\n",ServerFlags,nproc);
				nproc--;
			}
		}
	}
	if( 0 < nproc )
	if( ClientFlags & (PF_STLS_ON|PF_SSL_ON) ){
		/* the SSLway process will not exit until the connection with
		 * this delegated is closed. maybe it is desirable to reset
		 * it by close() than shutdown() not to loose data.
		 */
		nproc--;
		noshut = 1;
	}

	if( nproc ){
	    double Start = Time();
	    xproc = 0;
	    if( ServKeepAlive && (Conn->xf_filters & XF_SERVER) )
		nproc--;

	    for( x = 0; x < 10; x++ ){
		int serrno;
		errno = 0;
		xpid = NoHangWait();
		serrno = errno;
		sv1log("WaitShutdown %d/%d xpid=%d errno=%d/%d %X %X %X %.3f\n",
			nproc,xproc,xpid,errno,ECHILD,
			Conn->fi_builtin,Conn->xf_filters,Conn->xf_clprocs,
			Time()-Start);
		if( xpid < 0 ){
			if( serrno == ECHILD ){
				break;
			}
			msleep(50);
			continue;
		}
		syslog_DEBUG("WaitShutdown %d/%d[bi=%X xf=0x%X cl=0x%X] = %d\n",
			xproc,nproc,
			Conn->fi_builtin,Conn->xf_filters,Conn->xf_clprocs,
			xpid);
		if( xpid < 0 )
			break;
		if( 0 < xpid )
			++xproc;
		if( nproc <= xproc )
			break;
		msleep(10);
	    }
	}

	closeNNTPserver(Conn);
	if( GatewayFlags & GW_DONT_SHUT ){
		if( nproc )
		sv1log("## don't shutdown (%X) np=%d xf=%X cl=%X bi=%X\n",
			ClientFlags,nproc,
			nbits(Conn->xf_filters),
			nbits(Conn->xf_clprocs),
			nbits(Conn->fi_builtin)
		);
		return;
	}
	if( noshut )
		return;

	fshutdown(tc,force);
}
int timeoutWait(int to)
{	int i,tot,to1,pid;

	to1 = 0;
	pid = 0;
	for( tot = 0; tot < to; tot += to1 ){
		pid = NoHangWait();
		if( pid != 0 )
			break;
		to1 += 1;
		msleep(to1);
	}
	return pid;
}
