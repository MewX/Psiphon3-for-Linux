/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	smtp.c (SMTP proxy)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941016	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "ystring.h"
#include <errno.h>
#include "ysocket.h" /* gethostname() for Win32 */
#include "fpoll.h" /* READYCC() */
#include "proc.h"
#include "file.h"
#include "delegate.h"
#include "filter.h"
#include "auth.h"
#define LNSIZE  1024

#undef  sv1log
#define sv1log	syslog_ERROR

int SMTP_STARTTLS_withCL(Connection *Conn,FILE *fc,FILE *tc);
int SMTP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs);

extern const char *TIMEFORM_RFC822;
#define SMT_NOHELO	0x01
#define SMT_NOFROM	0x02
#define SMT_NOPIPELINE	0x04
#define SMT_NOMX	0x10
#define SMT_NOMXSELF	0x20
#define SMT_NOMXHELO	0x40
#define SMT_SRCROUTE	0x80
/*
int SMTP_tolerance = 0xFF;
*/
/*
int SMTP_tolerance = 0xFF & ~SMT_NOHELO;
*/
int SMTP_tolerance = 0xFF & ~(SMT_NOHELO|SMT_SRCROUTE);
int SMTP_helodomain = 0;

int SMTP_TOUT_RESP = 300;
int SMTP_thrudata = 30; /* max. time to wait DATA from client for buffering */
int SMTP_bgdatasize = 64*1024;
int SMTP_nomboxcase = 1;
int SMTP_maxrcpt = 0;
const char *SMTP_myname;

int SMTP_delays = 0;
int SMTP_callback = 0;
#define DFLT_DELAY	20

int ClientRequestTimeout = 60;

#define A_PLAIN	1
#define A_LOGIN	2
int SMTP_doauth;

#define lfprintf	SMTP_lfprintf

/*
 * SMTPCONF="MX:{-MX.*,*}" (default)
 * SMTPCONF="MX:mx-host"
 * SMTPCONF="MX:mx-host,-MX.*"
 * SMTPCONF="MX:{-MX.*,*,mx-host:8025}"
 * SMTPCONF="MX:mx-host:{*.dom1,*.dom2}"
 * SMTPCONF="MX::*.localdomain" (ignore MX)
 */
static int SMTP_withMXMAP = 0;
void setMXMAP(Connection *Conn,PCStr(conf)){
	IStr(nam,32);
	IStr(mx,MaxHostNameLen);
	IStr(map,MaxHostNameLen);
	IStr(cmap,MaxHostNameLen);

	scan_Listlist3(conf,':',AVStr(nam),AVStr(mx),AVStr(map));
	sprintf(cmap,"{%s}:%s:*:%s",mx,"MXMAP",map);
	scan_CMAP(Conn,cmap);
	SMTP_withMXMAP = 1;
}
static scanListFunc conn1(PCStr(mxhost),Connection *Conn,PCStr(host),int port){
	IStr(hx,MaxHostNameLen);
	int px;
	refQStr(pp,hx);
	int mxport = port;
	const char *dl;

	if( mxhost[0] == 0 || streq(mxhost,"-") ){
		mxhost = host;
	}
	if( strstr(mxhost,dl="..") || strstr(mxhost,dl=":") ){
		strcpy(hx,mxhost);
		if( (pp = strstr(hx,dl)) && (px = atoi(pp+strlen(dl))) ){
			truncVStr(pp);
			mxhost = hx;
			mxport = px;
		}
	}
	Verbose("-- MX(%s:%d) = %s:%d\n",host,port,mxhost,mxport);
	set_realserver(Conn,"smtp",mxhost,mxport);
	if( 0 <= connect_to_serv(Conn,FromC,ToC,0) ){
		return 1;
	}
	return 0;
}
static int connectMXMAP(Connection *Conn,PCStr(host),int port){
	IStr(mxhosts,MaxHostNameLen);
	Port sv;
	int conn = 0;

	if( SMTP_withMXMAP == 0 )
		return 0;
	sv = Conn->sv;
	set_realserver(Conn,"smtp",host,port);
	if( 0 <= find_CMAP(Conn,"MXMAP",AVStr(mxhosts)) ){
		strsubst(AVStr(mxhosts),"*",host);
		sv1log("CMAP/MX for %s -> {%s}\n",host,mxhosts);
		if( scan_commaListL(mxhosts,0,scanListCall conn1,Conn,host,port) ){
			conn = 1;
		}
	}
	if( conn == 0 ){
		Conn->sv = sv;
	}
	return conn;
}

#ifndef LIBRARY
const char *MLHOST = "";
const char *MLSOLT = "";
const char *MLADMIN = "";
static scanListFunc scan1(PCStr(conf),void *_)
{	CStr(nam,32);
	CStr(val,32);

	fieldScan(conf,nam,val);
	if( strcaseeq(nam,"reject") ){
		if( isinListX(val,"nohelo","+") )
			SMTP_tolerance &= ~SMT_NOHELO;
		if( isinListX(val,"nofrom","+") )
			SMTP_tolerance &= ~SMT_NOFROM;
		if( isinListX(val,"nopipeline","+") )
			SMTP_tolerance &= ~SMT_NOPIPELINE;
		if( isinListX(val,"pipeline","+") )
			SMTP_tolerance &= ~SMT_NOPIPELINE;
		if( isinListX(val,"nomx","+") )
			SMTP_tolerance &= ~SMT_NOMX;
		if( isinListX(val,"notselfmx","+") )
			SMTP_tolerance &= ~SMT_NOMXSELF;
		if( isinListX(val,"notmxhelo","+") )
			SMTP_tolerance &= ~SMT_NOMXHELO;
	}
	else
	if( strcaseeq(nam,"srcroute") ){
		SMTP_tolerance |= SMT_SRCROUTE;
	}
	else
	if( strcaseeq(nam,"allow") ){
		if( isinListX(val,"nohelo","+") )
			SMTP_tolerance |= SMT_NOHELO;
	}
	else
	if( strcaseeq(nam,"helodomain") ){
		SMTP_helodomain = makePathList("SMTP-helodomain",val);
	}
	else
	if( strcaseeq(nam,"tout-resp") ){
		SMTP_TOUT_RESP = (int)Scan_period(val,'s',(double)0);
	}
	else
	if( strcaseeq(nam,"allow") ){
		if( strcaseeq(val,"nohelo") )
			SMTP_tolerance |= SMT_NOHELO;
	}
	else
	if( strcaseeq(nam,"myname") ){
		SMTP_myname = stralloc(val);
	}
	else
	if( strcaseeq(nam,"MX") ){
		setMXMAP((Connection*)_,conf);
	}
	else
	if( strcaseeq(nam,"mlhost") ){ /* new-140504h */
		MLHOST = (const char*)stralloc(val);
	}
	else
	if( strcaseeq(nam,"mlsolt") ){ /* new-140504i */
		MLSOLT = (const char*)stralloc(val);
	}
	else
	if( strcaseeq(nam,"mladmin") ){ /* new-140504j */
		MLADMIN = (const char*)stralloc(val);
	}
	else
	if( strcaseeq(nam,"callback") ){
		CStr(value,1024);
		CStr(conf1,128);
		CStr(src,1024);
		CStr(cb,1024);
		fieldScan(conf,nam,value);
		fieldScan(value,conf1,src);
		if( *conf1 == 0 )
			sprintf(conf1,"%d",DFLT_DELAY);
		sprintf(cb,"%s:*:*:%s",conf1,src);
		scan_CMAP2((Connection*)_,"HELO_CallBack",cb);
		SMTP_callback = 1;
	}
	else
	if( strcaseeq(nam,"bcc") ){
		IStr(addr,1024);
		IStr(src,1024);
		IStr(bcc,1024);
		if( *src == 0 ) strcpy(src,"*");
		fieldScan(val,addr,src);
		sprintf(bcc,"%s:*:*:%s",addr,src);
		scan_CMAP2((Connection*)_,"SMTPBCC",bcc);
	}
	else
	if( strcaseeq(nam,"bgdatasize") ){
		SMTP_bgdatasize = atoi(val);
		if( strpbrk(val,"kK") )
			SMTP_bgdatasize *= 1024;
		sv1log("SMTPCONF=bgdatasize:%d (bytes)\n",SMTP_bgdatasize);
	}
	else
	if( strcaseeq(nam,"maxrcpt") ){
		SMTP_maxrcpt = atoi(val);
	}
	else
	if( strcaseeq(nam,"thrudata") ){
		SMTP_thrudata = (int)Scan_period(val,'s',(double)30);
	}
	else
	if( strcaseeq(nam,"mboxcase") ){
		SMTP_nomboxcase = 0;
	}
	else
	if( strcaseeq(nam,"tout-req") ){
		ClientRequestTimeout = (int)Scan_period(val,'s',(double)60);
	}else
	if( strcaseeq(nam,"auth") ){
		strtolower(val,val);
		if( val[0] == 0 ){
			SMTP_doauth = A_PLAIN | A_LOGIN;
		}else{
			if( isinList(val,"plain") )
				SMTP_doauth |= A_PLAIN;
			if( isinList(val,"login") )
				SMTP_doauth |= A_LOGIN;
		}
	}
	return 0;
}
void scan_SMTPCONF(Connection*_,PCStr(conf))
{
	scan_commaListL(conf,0,scanListCall scan1,_);
}

static Connection *Conn = 0; /* for functions without Conn */
#undef fclose
#define fclose(fp) CTX_fcloses(FL_ARG,"SMTP",Conn,fp,NULL)

typedef struct {
  const	char   *se_myver;
	MStr(	se_myhost,128);
	MStr(	se_clhost,MaxHostNameLen);
	MStr(	se_peerHELO,256);
	MStr(	se_Sender,MaxHostNameLen);
	MStr(	se_RecipientLocal,256);
	defQStr(se_Recipients);
	int	se_RecipientsSize;
	int	se_doAuth; /* AUTH must be done before starting */

	double	se_doCallBack;
	MStr(	se_claddr,64);
	int	se_isSMTP; /* client host is SMTP server */
	int	se_Ncoms;
	double	se_Start;
	double	se_pTime;
	int	se_didHELO;
	int	se_didDATA;
	int	se_Tolerance;

	const char *se_RESP_cache_com;
	const char *se_EHLO_cache;
	const char *se_HELO_cache;
	const char *se_myver1;
	Connection *se_servConn;
} SmtpEnv;
static SmtpEnv *smtpEnvs[MAX_THREADS];
static SmtpEnv *smtpEnvCur(){
	int gix;
	if( lMULTIST() )
		gix = getthreadgix(0);
	else	gix = 0;
	if( smtpEnvs[gix] == 0 ){
		smtpEnvs[gix] = NewStruct(SmtpEnv);
		smtpEnvs[gix]->se_myver1 = "";
		sv1log("new SmtpEnv[%d] = %X\n",gix,p2i(smtpEnvs[gix]));
	}
	return smtpEnvs[gix];
}
#define smtpEnv smtpEnvCur()

#define RESP_cache_com	smtpEnv->se_RESP_cache_com
#define EHLO_cache	smtpEnv->se_EHLO_cache
#define HELO_cache	smtpEnv->se_HELO_cache
#define servConn	smtpEnv->se_servConn
#define myver1		smtpEnv->se_myver1 /* should be initialized with "" */
#define Tolerance	smtpEnv->se_Tolerance

#else
static const char *RESP_cache_com;
static const char *EHLO_cache;
static const char *HELO_cache;
static const char *myver1 = "";
static Connection *servConn;
#define Tolerance SMTP_tolerance
#endif

void SMTP_lfprintf(FILE *log,FILE *tosc,PCStr(fmt),...)
{	CStr(stime,32);
	CStr(stat,0x8000);
	VARGS(14,fmt);

	getTimestamp(AVStr(stime));
	sprintf(stat,fmt,VA14);

	if( log != NULL ){
		fprintf(log,"%s [%d] ",stime,Getpid());
		if( tosc == NULL
		&& *stat != '<' && *stat != '>' && !isdigit(*stat) )
			fprintf(log,"* "); /* internal action */
		fprintf(log,fmt,VA14);
	}

	syslog_ERROR(fmt,VA14);

	if( tosc )
	fprintf(tosc,fmt,VA14);
}

int SMTP_logged_error(FILE *log,PVStr(resp),int rsiz)
{	int ecode = 0;
	int ec;
	CStr(rbuf,256);
	const char *np;
	refQStr(rp,resp); /**/

	while( fgets(rbuf,sizeof(rbuf),log) != NULL ){
		if( np = strstr(rbuf,"] ") ){ /* Timestamp */
			np += 2;
			ec = atoi(np);
			if( 400 <= ec && ec <= 999 ){
				if( ecode == 0 )
					ecode = ec;
				QStrncpy(rp,np,rsiz-(rp-resp));
				rp += strlen(rp);
				continue;
			}
		}
	}
	clearerr(log);
	return ecode;
}

static void cacheEHLO(PCStr(com),PVStr(resp));

int SMTP_relay_stat(FILE *fs,FILE *tc,xPVStr(resp))
{	CStr(rcode,4);
	CStr(respb,1024);
	CStr(stat,1024);
	double St = Time();
	int serrno;
	int rdy;
	int nint = 0;

	if( resp == 0 )
		setPStr(resp,respb,sizeof(respb));

	rcode[0] = 0;
	if( RESP_cache_com )
		stat[0] = 0;
	for(;;){
		if( (rdy = fPollIn(fs,SMTP_TOUT_RESP*1000)) <= 0 ){
			serrno = errno;
			strcpy(resp,"421 no response from the server.\r\n");
			syslog_ERROR("SC-TIMEOUT. (%dsec)\n",SMTP_TOUT_RESP);

			sv1log("SMTP-SC-%d (%.3f/%d) rdy=%d e%d len=%d %d/%d\n",
				nint,Time()-St,SMTP_TOUT_RESP,rdy,serrno,
				istrlen(resp),actthreads(),numthreads());
			if( serrno == EINTR && nint++ == 0 && numthreads() ){
				/* 9.9.8 might be caused by SIGPIPE/YYMUX */
				if( Time()-St < SMTP_TOUT_RESP ){
					msleep(100);
					continue;
				}
			}
			return -1;
		}
		if( fgets(resp,LNSIZE,fs) == NULL ){
			strcpy(resp,"500 EOF from server\n");
			syslog_ERROR("SC-EOF. errno=%d\r\n",errno);
			return -1;
		}
		if( RESP_cache_com ){
			int len = strlen(stat);
			XStrncpy(QVStr(stat+len,stat),resp,sizeof(stat)-len);
		}
		syslog_ERROR("SMTP > %s",resp);
		if( tc != NULL )
			if( Fputs(resp,tc) == EOF )
				return -1;

		if( resp[3] == '-' ){
			if( rcode[0] == 0 )
				strncpy(rcode,resp,3);
		}else{
			if( rcode[0] == 0 || strncmp(resp,rcode,3) == 0 )
				break;
		}
	}
	if( RESP_cache_com ){
		cacheEHLO(RESP_cache_com,AVStr(stat));
	}
	return atoi(resp);
}

void SMTP_putserv(FILE *log,FILE *fs,FILE *ts,PVStr(resp),PCStr(fmt),...)
{	CStr(req,1024);
	VARGS(8,fmt);

	sprintf(req,fmt,VA8);
	fputs(req,ts);
	fflush(ts);

	if( log != NULL )
		lfprintf(log,NULL,"<<< %s",req);
	else	syslog_ERROR("SMTP < %s",req);

	SMTP_relay_stat(fs,NULL,AVStr(resp));
	if( log != NULL )
		lfprintf(log,NULL,"%s",resp);
}

#define SMQ_COM		0
#define SMQ_FIELD	1
#define SMQ_RCPT	2
#define SMQ_FROM	2
#define SMQ_CLRF	3
typedef struct {
	UTag   *sm_uv[5];
	UTag	sm_ub[4];
} SMTPreq;
static void decomp_req(PCStr(req),SMTPreq *Req)
{
	uvinit(Req->sm_uv,Req->sm_ub,4);
	uvfromsf(req,0,"%s %[^:]: %[^\r\n]%[\r\n]",Req->sm_uv);
}

typedef struct {
  const	char	*al_what;
  const char	*al_list;
  const	char	*al_command;
	FILE	*al_log;
	FILE 	*al_ts;
	FILE	*al_fs;
	defQStr(al_respbuf);
} AddrList;

static void SMTPpath(PCStr(addr),PVStr(path),int siz)
{
	setVStrElem(path,0,'<');
	RFC822_addresspartX(addr,QVStr(path+1,path),siz-3);
	strcat(path,">");
}
char *deSrcroute(PCStr(to),PVStr(tob)){
	refQStr(dp,tob);
	refQStr(op,tob);

	if( strchr(to,'%') == 0 )
		return (char*)to;

	strcpy(tob,to);
	if( dp = strrchr(tob,'%') )
	if( op = strchr(dp,'@') ){
		if( dp[1] == 0 || dp[1] == '@' ){
			clearVStr(dp); /* empty domain */
		}else	setVStrElem(dp,0,'@');
		clearVStr(op);
		sv1log("--deSrcroute[%s][%s]\n",to,tob);
		to = tob;
	}
	return (char*)to;
}
int enSrcroute(PVStr(addr)){
	char *dp;
	int en = 0;

	for( dp = (char*)addr; *dp; dp++ ){
		if( *dp == '@' && strchr(dp+1,'@') ){
			*dp = '%';
			en++;
		}
	}
	if( en ){
		sv1log("--enSrcroute[%s]\n",addr);
		return en;
	}
	return 0;
}
static scanListFunc scan_addr1(PCStr(to),AddrList *addr)
{	CStr(xto,1024);

	IStr(tob,1024);
	if( Tolerance & SMT_SRCROUTE ){
		to = deSrcroute(to,AVStr(tob));
	}
	SMTPpath(to,AVStr(xto),sizeof(xto));
	syslog_ERROR("SMTP : %s: %s -- %s\r\n",xto,addr->al_what,to);
	SMTP_putserv(addr->al_log,addr->al_fs,addr->al_ts,
		AVStr(addr->al_respbuf), "%s%s\r\n",addr->al_command,xto);
	if( addr->al_respbuf[0] != '2' )
		return -1;
	else	return 0;
}
int SMTP_openingXX(FILE *fs,FILE *ts,PCStr(myver),PCStr(to),PCStr(from),int dodata,FILE *log,PCStr(auth),PVStr(resp));
int SMTP_openingX(FILE *fs,FILE *ts,PCStr(myver),PCStr(to),PCStr(from),int dodata,FILE *log,PCStr(auth))
{	CStr(myhost,128);
	CStr(xto,1024);
	CStr(xfrom,1024);
	CStr(resp,2048);

	return SMTP_openingXX(fs,ts,myver,to,from,dodata,log,auth,AVStr(resp));
}

static void cacheEHLO(PCStr(com),PVStr(resp)){
	CStr(resp1,256);
	refQStr(dp,resp);
	const char *sp;
	const char *np;

	if( *resp != '2' ){
		return;
	}
	if( strcaseeq(com,"HELO") ){
		HELO_cache = stralloc(resp);
		return;
	}

	lineScan(resp,resp1);
	strcat(resp1,"\r\n");
	if( resp1[3] == '-' )
		resp1[3] = ' ';
	HELO_cache = stralloc(resp1);

	if( strncmp(resp,"250-",4) == 0 ){
		Strins(QVStr(resp+4,resp),"X-GREETING ");
	}
	cpyQStr(dp,resp);
	for( sp = resp; *sp; sp = np ){
		if( np = strchr(sp,'\n') )
			np += 1;
		if( strncaseeq(sp,"250-AUTH",8) && SMTP_doauth != 0 )
			continue;
		if( strncaseeq(sp,"250-STARTTLS",12) )
		{
			if( servConn ){
				Connection *Conn = servConn;
				ServerFlags |= PF_STLS_CAP;
			}
			continue;
		}

		if( dp != sp )
			Bcopy(sp,dp,np-sp);
		dp += np-sp;
	}
	if( dp != sp ){
		setVStrEnd(dp,0);
	}
	EHLO_cache = stralloc(resp);
}
static int HELO_withSV(PCStr(com),PCStr(myhost),FILE *log,FILE *ts,FILE *fs,PVStr(stat)){
	if( strcaseeq(com,"HELO") && HELO_cache ){
		strcpy(stat,HELO_cache);
	}else
	if( strcaseeq(com,"EHLO") && EHLO_cache ){
		strcpy(stat,EHLO_cache);
	}else{
		RESP_cache_com = "EHLO";
		SMTP_putserv(log,fs,ts,AVStr(stat),"EHLO %s\r\n",myhost);
		if( stat[0] != '2' ){
		RESP_cache_com = "HELO";
		SMTP_putserv(log,fs,ts,AVStr(stat),"HELO %s\r\n",myhost);
		}
		RESP_cache_com = 0;

		if( strcaseeq(com,"EHLO") && EHLO_cache )
			strcpy(stat,EHLO_cache);
		else
		if( strcaseeq(com,"HELO") && HELO_cache )
			strcpy(stat,HELO_cache);
	}
	return atoi(stat);
}

int SMTP_openingXX(FILE *fs,FILE *ts,PCStr(myver),PCStr(to),PCStr(from),int dodata,FILE *log,PCStr(auth),PVStr(resp))
{	CStr(myhost,128);
	CStr(xto,1024);
	CStr(xfrom,1024);
	AddrList addrs;

	SMTP_relay_stat(fs,NULL,AVStr(resp));
	if( resp[0] != '2' ){
		/* 8.10.4 not to say HELO to a server returning error, and
		 * to forward the error resp. from the server to client.
		 */
		return -1;
	}

	if( SMTP_myname ){
		lineScan(SMTP_myname,myhost);
	}else{
	if( gethostName(fileno(ts),AVStr(myhost),"%H") <= 0 )
		gethostname(myhost,sizeof(myhost));
	sv1log("getting FQDN of %s ...\n",myhost);
	getFQDN(myhost,AVStr(myhost));
	}

	/*
	if( auth ){
		SMTP_putserv(log,fs,ts,AVStr(resp),"EHLO %s\r\n",myhost);
	}else
	SMTP_putserv(log,fs,ts,AVStr(resp),"HELO %s\r\n",myhost);
	*/

	HELO_cache = 0; /* not to suppress HELO on new Conn. like sendBCC() */
	EHLO_cache = 0;

	HELO_withSV("EHLO",myhost,log,ts,fs,BVStr(resp));
	if( resp[0] != '2' )
		return -1;

	if( servConn ){
		if( SMTP_STARTTLS_withSV(servConn,ts,fs) < 0 ){
			strcpy(resp,"421 cannot start TLS with the server\r\n");
			return -1;
		}
		if( withSTLS_SV(servConn) ){
			HELO_cache = 0;
			EHLO_cache = 0;

			HELO_withSV("EHLO",myhost,log,ts,fs,BVStr(resp));
			if( resp[0] != '2' )
				return -1;
		}
	}

	if( from ){
		SMTPpath(from,AVStr(xfrom),sizeof(xfrom));
		syslog_ERROR("SMTP : From: %s -- %s\r\n",xfrom,from);
		SMTP_putserv(log,fs,ts,AVStr(resp),"MAIL From: %s\r\n",xfrom);
		if( resp[0] != '2' )
			return -1;
	}
	if( to && to[0] ){
		addrs.al_what = "To";
		addrs.al_list = to;
		addrs.al_command = "RCPT To: ";
		setQStr(addrs.al_respbuf,resp,(UTail(resp)-resp)+1);
		addrs.al_log = log;
		addrs.al_ts = ts;
		addrs.al_fs = fs;
		scan_commaList(to,0,scanListCall scan_addr1,&addrs);
		if( resp[0] != '2' )
			return -1;
	}
	if( dodata )
		SMTP_putserv(log,fs,ts,AVStr(resp),"DATA\r\n");
	return 0;
}

#ifdef LIBRARY
int SMTP_open(Connection *Conn,FILE *fpv[],PCStr(host),int port,PCStr(to),PCStr(from),int dodata,FILE *log){
	int svsock;
	FILE *fs,*ts;

	svsock = client_open("openMailPoster","smtp",host,port);
	if( svsock < 0 ){
		return -1;
	}

	fs = fdopen(svsock,"r");
	ts = fdopen(svsock,"w");
	if( SMTP_openingX(fs,ts,myver1,to,from,1,NULL,NULL) != 0 ){
		return -1;
	}
	fpv[0] = fs;
	fpv[1] = ts;
	return svsock;
}
void ConnInit(Connection *Conn){
	bzero(Conn,sizeof(Connection));
}
int withSTLS_SV(Connection *Conn){
	return 0;
}
int SMTP_STARTTLS_withSV(Connection *Conn,FILE *ts,FILE *fs){
	return 0;
}
int (*MIME_mapPosterAddr)(PCStr(maddr),PVStr(xmaddr));
int (*MIME_mapMessageId)(PCStr(xref),PCStr(msgid),PVStr(xmsgid));
int (*MIME_makeEmailFP)(PVStr(ocrc),PCStr(addr));
int (*MIME_makeEmailCX)(PVStr(ocrc),PCStr(wf),PCStr(addr));
int (*MIME_makeAdminKey)(PCStr(from),PVStr(key),int siz);
int (*MIME_setPosterMasks)(PCStr(from));
#endif

FILE *SMTP_POST(PCStr(host),int port,PCStr(to),PCStr(from));
FILE *SMTP_post(PCStr(host),int port,PCStr(myver),PCStr(to),PCStr(from),FILE *mfp,xPVStr(resp),int rsize)
{
/*
{	int server;
*/
	FILE *ts,*fs,*fc;
	CStr(line,1024);
	CStr(respbuff,1024);
	const char *ep;
	char topChar;
	int inHead,inSkip;
	FILE *fpv[2];
	Connection ConnBuf,*Conn = &ConnBuf;

	if( resp == NULL ){
		setPStr(resp,respbuff,sizeof(respbuff));
		if( sizeof(respbuff) < rsize )
			rsize = sizeof(respbuff);
	}

	syslog_ERROR("SMTP_POST at %s:%d to:%s from:%s\r\n",host,port,to,from);
	/*
	server = client_open("openMailPoster","smtp",host,port);
	if( server < 0 ){
	*/
	ConnInit(Conn);
	Conn->from_myself = 1;
	myver1 = myver;
	if( SMTP_open(Conn,fpv,host,port,to,from,1,NULL) < 0 ){
		syslog_ERROR("SMTP: cannot connect: %s:%d.\r\n",host,port);
		return NULL;
	}

	if( mfp != NULL ){
		fc = mfp;
	}else{
		int io[2];
		Socketpair(io);
		if( Fork("SMTP_POST") != 0 ){
			close(io[0]);
/*
			close(server);
*/
			return fdopen(io[1],"w");
		}
		close(io[1]);
		fc = fdopen(io[0],"r");
	}

	fs = fpv[0];
	ts = fpv[1];
	/*
	fs = fdopen(server,"r");
	ts = fdopen(server,"w");

	if( SMTP_openingX(fs,ts,myver,to,from,1,NULL,NULL) != 0 ){
		if( mfp != NULL ){
			fclose(ts);
			fclose(fs);
			return NULL;
		}
		_Finish(-1);
	}
	*/

	inHead = 1;
	inSkip = 0;
	for(;;){
		if( fgets(line,sizeof(line),fc) == NULL )
			break;

		if( inHead ){
			topChar = line[0];
			if(  topChar == '\r' || topChar == '\n' ){
				inHead = 0;
				inSkip = 0;
			}else
			if( topChar == ' ' || topChar == '\t' )
				;
			else
			if( strncasecmp(line,"Bcc:",4) == 0 ){
				syslog_ERROR("SMTP : erased BCC header\r\n");
				inSkip = 1;
			}else	inSkip = 0; 
		}
		if( !inSkip ){
			if( ep = strpbrk(line,"\r\n") )
				truncVStr(ep);
			if( line[0] == '.' )
				fputc('.',ts);
			fputs(line,ts);
			fputs("\r\n",ts);
		}
	}
	SMTP_putserv(NULL,fs,ts,AVStr(resp),".\r\n");
	SMTP_putserv(NULL,fs,ts,AVStr(resp),"QUIT\r\n");

	if( mfp != NULL )
		return mfp;

	fclose(fc);
	fclose(ts);
	fclose(fs);
	_Finish(0); /* avoid duplicate flush of stream buffer of parent ... */
	return 0;
}

#ifndef LIBRARY
/*
 *	RCPT To: recipients -> Recipients[]
 *	MAIL From: originator -> Sender[]
 */
#define Myver		smtpEnv->se_myver
#define Myhost		smtpEnv->se_myhost
/**/
#define Clhost		smtpEnv->se_clhost
/**/
#define peerHELO	smtpEnv->se_peerHELO
#define Sender		smtpEnv->se_Sender
/**/
#define RecipientLocal	smtpEnv->se_RecipientLocal
/**/
#define Recipients	smtpEnv->se_Recipients
/**/
#define RecipientsSize	smtpEnv->se_RecipientsSize
#define respforEHLO	smtpEnv->se_respforEHLO
#define doAuth		smtpEnv->se_doAuth
#define isSMTP		smtpEnv->se_isSMTP

#define CallBackDelay	smtpEnv->se_doCallBack
#define Claddr		smtpEnv->se_claddr
/**/
#define Ncoms		smtpEnv->se_Ncoms
#define Start		smtpEnv->se_Start
#define pTime		smtpEnv->se_pTime
#define DelayMsec(s)	(int)(1000*s+1)

#define didHELO		smtpEnv->se_didHELO
#define didDATA		smtpEnv->se_didDATA

void minit_smtp()
{
	/*
	if( smtpEnv == 0 )
		smtpEnv = NewStruct(SmtpEnv);
	*/
}

const char *getClientRident(Connection *Conn,PVStr(clntb));
void smtplog(Connection *Conn,PCStr(fmt),...){
	Logfile *log;
	CStr(sdate,128);
	CStr(line,1024);
	const char *clnt;
	CStr(clnta,128);
	CStr(clntb,256);
	double et = Time() - Start;
	VARGS(16,fmt);

	log = LOG_which("smtp",LF_PROTOLOG,0);
	if( log == 0 ){
		return;
	}
	Client_Addr(clnta);
	clnt = getClientRident(Conn,AVStr(clntb));
	StrftimeLocal(AVStr(sdate),sizeof(sdate),"%Y%m%d-%H%M%S",time(0),0);
	sprintf(line,"%s %d %d%s %.1f [%s|%s|%s] ",sdate,getpid(),
		isSMTP,((0<isSMTP)?"S":(isSMTP<0)?"N":"U"),
		et,clnta,clnt,peerHELO);
	Xsprintf(TVStr(line),fmt,VA16);
	strcat(line,"\n");
	LOG_write(log,line,strlen(line));
	LOG_flushall();
}

static int SMTP_mount_rcpt(Connection *Conn,FILE *tc,PCStr(req),PVStr(xreq))
{	CStr(rcpt,LNSIZE);
	CStr(url,LNSIZE);
	SMTPreq Req;
	UTag **reqv,xrcpt;
	const char *opts;

	setVStrEnd(xreq,0);
	decomp_req(req,&Req);
	reqv = Req.sm_uv;
	if( reqv[SMQ_RCPT] == 0 )
		return 0;

	Utos(reqv[SMQ_RCPT],rcpt);
	RFC822_addresspartX(rcpt,AVStr(url),sizeof(url));

	if( SMTP_nomboxcase )
		strtolower(url,url);
	opts =
	CTX_mount_url_to(Conn,NULL,"POST",AVStr(url));

	if( 1 ){ /* 9.8.2 MOUNT by "//serv/usr" and routing "usr%dom@serv" */
	    if( opts == 0 && strchr(url,'@') ){
		/* retry MOUNT matching by "//dom/usr" */
	    	IStr(usr,LNSIZE);
	    	IStr(dom,LNSIZE);
		Xsscanf(url,"%[^@]@%s",AVStr(usr),AVStr(dom));
		sprintf(url,"//%s/%s",dom,usr);
		opts = CTX_mount_url_to(Conn,NULL,"POST",AVStr(url));
	    }
	    if( opts ){
		/* normalize from "//serv/usr" to "usr@serv" */
	    	IStr(usr,LNSIZE);
	    	IStr(dom,LNSIZE);
		Xsscanf(url,"smtp://%[^/]/%s",AVStr(dom),AVStr(usr));
		if( usr[0] ){
			IStr(dom2,LNSIZE);
			IStr(usr2,LNSIZE);
			if( strchr(usr,'/') ){
				/* "//serv/dom/usr" to "//usr@dom@serv" */
				if( *usr == '/' ){
					sprintf(usr,"%s@",usr+1);
				}else{
					Xsscanf(usr,"%[^/]/%s",
						AVStr(dom2),AVStr(usr2));
					sprintf(usr,"%s@%s",usr2,dom2);
				}
			}
			sprintf(url,"smtp://%s@%s",usr,dom);
			sv1log(">>>> %s\n",url);
		}
	    }
	}

	if( opts && strstr(opts,"reject") )
		goto FORBIDDEN;

	if( opts && strstr(opts,"gateway=") ){
		setMountOptions(FL_ARG,Conn,opts);
		/*
		MountOptions = opts;
		*/
	}
	if( strcmp(rcpt,url) != 0 ){
		sv1log("%s => %s\n",rcpt,url);
		if( ufromsf(url,0,"smtp://%[^:/]",&xrcpt)
		 || ufromsf(url,0,"mailto:%s",&xrcpt)
		){
			if( ustrcmp(&xrcpt,"-") == 0 )
				goto FORBIDDEN;

			if( enSrcroute(AVStr(xrcpt.ut_addr)) ){
				Tolerance |= SMT_SRCROUTE;
			}
			reqv[SMQ_RCPT] = &xrcpt;
			uvtosf(AVStr(xreq),LNSIZE,"%s %s:<%s>%s",reqv);
			sv1log(">>>> %s",xreq);
		}
	}
	return 0;

FORBIDDEN:
	sv1log("Rejected: %s",req);
	fprintf(tc,"553 Forbidden recipient (%s)\r\n",rcpt);
	fflush(tc);
	return -1;
}
static int notAvailable(PCStr(com),FILE *tc,FILE *log)
{
	if( doAuth ){
		if( !strcaseeq(com,"XECHO")
		 && !strcaseeq(com,"STARTTLS")
		 && !strcaseeq(com,"HELO")
		 && !strcaseeq(com,"EHLO")
		 && !strcaseeq(com,"AUTH")
		 && !strcaseeq(com,"QUIT") ){
			if( tc != NULL ){
				lfprintf(log,tc,"500 do AUTH first.\r\n");
				fflush(tc);
			}
			return 1;
		}
	}
	return 0;
}

/*
char *SMTP_fgetsResp(PVStr(resp),int size,FILE *fs,int timeoutms)
{	const char *rcode;
	CStr(line,LNSIZE);
	int len,len1,timeout;

	rcode = 0;
	len = 0;
	timeout = (timeoutms+999) / 1000;
	while( fgetsTimeout(QVStr(resp+len,resp),size-len,fs,timeout) != NULL ){
		rcode = resp;
		if( resp[len+3] != '-' )
			break;
		len1 = strlen(resp+len) + 1;
		len += len;
		if( size-len < 1 )
			break;
	}
	return (char*)rcode;
}
*/
static char *SMTP_fgetsResp(PVStr(resp),int size,FILE *fs,int timeoutms){
	const char *rcode = 0;
	refQStr(rp,resp);
	int ri = 0;
	int remlen,rcc,len1,bin;
	int remms;
	double St = Time();
	IStr(xmsg,128);

	clearVStr(resp);
	remms = timeoutms;
	strcpy(xmsg,"A NONE");
	for( remlen = size; 2 < remlen && 0 < remms; ){
		if( fPollIn(fs,remms) <= 0 ){
			sprintf(xmsg,"B TIMEOUT-1");
			break;
		}
		remms = timeoutms - (int)(Time() - St);
		if( remms <= 0 ){
			sprintf(xmsg,"C TIMEOUT-2");
			break;
		}
		if( fgetsByLine(AVStr(rp),remlen,fs,remms,&rcc,&bin) == 0 ){
			sprintf(xmsg,"D EOF");
			break;
		}
		rcode = resp;
		len1 = strlen(rp);
		rp += len1;
		remlen -= len1;
		remms = timeoutms - (int)(Time() - St);
		if( len1 < 4 || rp[3] != '-' ){
			sprintf(xmsg,"E DONE(%d)",len1);
			break;
		}
		if( remms <= 0 ){
			sprintf(xmsg,"F TIMEOUT-3");
			break;
		}
		if( remlen <= 0 ){
			sprintf(xmsg,"G TOOLONG");
			break;
		}
	}
	sv1log("--ckHELO %d/%d %3d EOF=%d %3d ==%s\n",
		(timeoutms-remms),timeoutms,size-remlen,feof(fs),
		rcode?atoi(rcode):-1,xmsg);

	return (char*)rcode;
}
static char *fgetsRequest(PVStr(line),int size,FILE *fc)
{
	return fgetsTimeout(BVStr(line),size,fc,ClientRequestTimeout);
}

static int SMTP_relay_req(Connection *Conn,FILE *fc,FILE *tc,FILE *ts,PVStr(req))
{	CStr(xreq,LNSIZE);
	CStr(com,LNSIZE);
	CStr(arg,LNSIZE);
	CStr(CRLF,8);
	const char *dp;

	/*
	if( fgets(req,LNSIZE,fc) == NULL ){
	*/
	if( fgetsRequest(AVStr(req),LNSIZE,fc) == NULL ){
		sv1log("CS-EOF.\n");
		Fputs("QUIT\r\n",ts);
		return -1;
	}
	dp = wordScan(req,com);
	dp = lineScan(dp,arg);
	strcpy(CRLF,dp);
	if( strcaseeq(com,"AUTH") ){
		CStr(arg1,64);
		dp = wordScan(arg,arg1);
		sv1log("SMTP < %s %s %s\r\n",com,arg1,*dp?"***":"");
	}else{
		sv1log("SMTP < %s",req);
	}

	if( notAvailable(com,NULL,NULL) )
		return 0;

	if( strcasecmp(com,"XECHO") == 0 ){
		fprintf(tc,"%s%s",arg,CRLF);
		fflush(tc);
		return 0;
	}
	if( strcaseeq(com,"HELO")
	 || strcaseeq(com,"EHLO")
	 || strcaseeq(com,"STARTTLS")
	){
		return 0;
	}
	if( needSTLS(Conn) )
	if( !strcaseeq(com,"QUIT") )
	if( !strcaseeq(com,"NOOP") )
	{
		Strins(BVStr(req),"-- ");
		sv1log("%s",req);
		lfprintf(NULL,tc,"530 Say STARTTLS first\r\n");
		fflush(tc);
		return 0;
	}
	if( SMTP_doauth && strcaseeq(com,"AUTH") ){
		return 0;
	}

	/* this conversion to HELO is here originally from 7.4.0 */
	/* maybe to cope with non-ESMTP server */
	/*
	if( SMTP_doauth && strcaseeq(com,"EHLO") ){
		strcpy(com,"HELO");
		respforEHLO = 1;
	}
	*/

	/*
	 * JIS (2byte) codes shuld not be passed to the SMTP server
	 * and must be removed before applying MOUNT ...
	 */
	TO_euc(req,AVStr(xreq),sizeof(xreq));
	if( strcmp(req,xreq) != 0 ){
		del8bits(AVStr(req),xreq);
		sv1log("SMTP < %s",req);
	}

	xreq[0] = 0;
	/*
	if( strcasecmp(com,"HELO") == 0 ){
		sprintf(xreq,"HELO %s%s",arg,CRLF);
	}else
	*/
	if( strcasecmp(com,"RCPT") == 0 ){
		if( SMTP_mount_rcpt(Conn,tc,req,AVStr(xreq)) < 0 )
			return -1;
	}
	if( xreq[0] )
		strcpy(req,xreq);

	if( Fputs(req,ts) == EOF )
		return -1;
	return 0;
}

static int smtpbcc(Connection *Conn,PCStr(to),PVStr(bcc),FILE *ts,FILE *fs){
	IStr(smcc,1024);
	IStr(resp,1024);

	if( bcc[0] )
		return 0;
	if( find_CMAP(Conn,"SMTPBCC",AVStr(smcc)) < 0 )
		return 0;
	sv1log("##SMTPBCC: %s <= %s\n",smcc,Client_Host);
	if( strcaseeq(to,smcc) ){
		return 0;
	}
	strcpy(bcc,smcc);
	if( ts != 0 && fs != 0 ){
		fprintf(ts,"RCPT TO:<%s>\r\n",smcc);
		fflush(ts);
		SMTP_relay_stat(fs,NULL,AVStr(resp));
	}
	return 1;
}
static int doRCPT(Connection *Conn,FILE *indata,FILE *tc,PCStr(arg),UTag *urcpt,FILE *log)
{	CStr(recipient,256);

	Utos(urcpt,recipient);
	RFC822_addresspartX(recipient,AVStr(recipient),sizeof(recipient));

	Xsscanf(recipient,"%[^@]",AVStr(RecipientLocal));

	if( Recipients == NULL ){
		RecipientsSize = 0x8000;
		setQStr(Recipients,(char*)malloc(RecipientsSize),RecipientsSize);
		setVStrEnd(Recipients,0);
		smtpbcc(Conn,arg,AVStr(Recipients),0,0);
	}
	if( Recipients[0] != 0 )
		strcat(Recipients,",");
	strcat(Recipients,recipient);

	sv1log("Recipient: <%s> %s\n",recipient,arg);
	lfprintf(log,tc,"250 %s... Recipient ok\r\n",arg);
	return 0;
}
static int doMAIL(Connection *Conn,FILE *tc,PCStr(arg),UTag *ufrom,FILE *log)
{
	utosX(ufrom,AVStr(Sender),sizeof(Sender));
	RFC822_addresspartX(Sender,AVStr(Sender),sizeof(Sender));

	sv1log("Sender: <%s> %s\n",Sender,arg);
	lfprintf(log,tc,"250 %s... Sender ok\r\n",Sender);
	return 0;
}
static void doRSET(Connection *Conn)
{
	if( Recipients != NULL ){
		free((char*)Recipients);
		setQStr(Recipients,((char*)NULL),0);
	}
	Sender[0] = 0;
}

static void CALLBACKlog(Connection *Conn,PCStr(com),PCStr(fmt),...)
{	CStr(msg,0x10000);
	const char *dp;
	CStr(time,32);
	double Now;
	VARGS(8,fmt);

	sprintf(msg,fmt,VA8);
	if( dp = strchr(msg,'\n') )
		truncVStr(dp);
	if( pTime == 0 )
		pTime = Start;
	Now = Time();
	sprintf(time,"%04.1f/%04.1f",Now-Start,Now-pTime);
	sv1log("CALLBACK[%s] %d %s %s: %s\n",Claddr,Ncoms,time,com,msg);
	pTime = Now;
}

void waitClientDelay(Connection *Conn,int ifd,int delay);
int MAILGATE_returnUID(Connection *Conn,FILE *tc,FILE *indata,PCStr(myhost),PCStr(clhost),FILE *log);
int SMTPgateway(Connection *Conn,FILE *tc,FILE *mfp,PCStr(md5),PCStr(hello),PCStr(sender),PCStr(recipient),FILE *log);

const char *MAILGATE = "mailgate";
static int doDATA(Connection *Conn,FILE *indata,FILE *tc,FILE *fc,PCStr(myhost),PCStr(clhost),FILE *log)
{	CStr(line,1024);
	int off1;
	int off2;
	int sent;
	const char *rb;
	const char *rv[0x2000]; /**/
	int ri,rc;
	char header;
	CStr(Cte,256);
	MD5 *md5;
	CStr(md5b,64);
	CStr(md5a,64);
	int size;
	int delay = 0;

	if( Recipients == NULL ){
		lfprintf(log,tc,"503 Need RCPT (recipient)\r\n");
		fflush(tc);
		return -1;
	}

	if( (SMTP_tolerance & SMT_NOFROM) == 0 )
	if( Sender[0] == 0 ){
		lfprintf(log,tc,"503 Need MAIL (sender)\r\n");
		fflush(tc);
		return -1;
	}

	lfprintf(log,tc,
		"354 Enter mail, end with \".\" on a line by itself\r\n");
	fflush(tc);

	off1 = ftell(indata);
	Cte[0] = 0;
	header = 1;
	md5 = newMD5();

	if( SMTP_callback )
	{
		fprintf(indata,"X-Callback: %d/%s/%s\r\n",isSMTP,Clhost,Claddr);
	}

	/*
	while( fgets(line,sizeof(line),fc) ){
	*/
	while( fgetsRequest(AVStr(line),sizeof(line),fc) ){
		if( line[0] == '.' && (line[1] == '\r' || line[1] =='\n') ){
			lfprintf(log,NULL,">>> %s",line);
			break;
		}

		if( header )
		if( line[0] == '\r' || line[0] == '\n' )
			header = 0;
		else
		if( strncasecmp(line,"Content-Transfer-Encoding",25) == 0 ){
			CStr(fname,256);
			CStr(fvalue,256);
			fieldScan(line,fname,fvalue);
			if( Cte[0] ){
				lfprintf(log,NULL,"ignored -- dup. %s: %s %s\n",
					fname,Cte,fvalue);
				continue;
			}
			strcpy(Cte,fvalue);
		}

		if( !header ){
			addMD5(md5,line,strlen(line));
		}
		fputs(line,indata);
	}
	endMD5(md5,md5b);
	MD5toa(md5b,md5a);

	off2 = ftell(indata);
	size = off2 - off1;
	sent = 0;

	if( Sender[0] && strcaseeq(RecipientLocal,MAILGATE) ){
		fseek(indata,0,0);
		sent = MAILGATE_returnUID(Conn,tc,indata,myhost,clhost,log);
		return sent;
	}

	rb = stralloc(Recipients);

#ifdef OPTIMIZE
	fseek(indata,off1,0);
	sent = SMTPgateway(Conn,tc,indata,md5a,peerHELO,Sender,Recipients,log);
	if( sent < 0 )
		goto EXIT;
#else
	rc = stoV(rb,elnumof(rv),rv,',');
	for( ri = 0; ri < rc; ri++ ){
		fseek(indata,off1,0);
		sent = SMTPgateway(Conn,tc,indata,md5a,peerHELO,Sender,rv[ri],log);
		if( sent < 0 )
			goto EXIT;
	}
#endif
	if( 0 < sent ){ /* "sent" should be SmtpStat */
		if( sent & 0xF0 ){
			delay = sent >> 4;
			sent &= ~0xF0;
		}
	}
	if( 0 < sent )
		lfprintf(log,tc,"250 Mail accepted\r\n");
	else	lfprintf(log,tc,"550 <%s> User Unknown\r\n",Recipients);
	fflush(tc);

	free((char*)Recipients);
	setQStr(Recipients,((char*)NULL),0);
	fseek(indata,off2,0);

EXIT:
	CALLBACKlog(Conn,"DATA","sent=%d, size=%d",sent,size);
	if( 0 < CallBackDelay && sent < 0 /* if rejected */ ){
		CALLBACKlog(Conn,"DATA","REJECTED ... do delay");
		waitClientDelay(Conn,fileno(fc),DelayMsec(CallBackDelay));
	}
	else
	if( 0 < CallBackDelay && 0 < delay ){
		CALLBACKlog(Conn,"DATA","TO BE DELAYED ... do delay");
		waitClientDelay(Conn,fileno(fc),30*1000);
	}

	free((char*)rb);
	if( 0 < sent ){
		PageCountUpURL(Conn,CNT_TOTALINC,"#accepted",NULL);
	}
	return sent;
}

const char *MailGate(Connection *Conn)
{	static const char *mbox;
	CStr(buf,128);
	CStr(host,128);
	CStr(dom,128);

	if( mbox )
		return mbox;
	ClientIF_H(Conn,AVStr(host));
	getFQDN(host,AVStr(dom));
	if( IsInetaddr(dom) )
		sprintf(buf,"%s@[%s]",MAILGATE,dom);
	else	sprintf(buf,"%s@%s",MAILGATE,dom);
	mbox = stralloc(buf);
	return mbox;
}

int mboxid(PVStr(mbox),PCStr(mailer),PVStr(muid),PVStr(date));
int MAILGATE_returnUID(Connection *Conn,FILE *tc,FILE *indata,PCStr(myhost),PCStr(clhost),FILE *log)
{	FILE *fp;
	CStr(from,128);
	CStr(muid,128);
	CStr(date,128);

	if( streq(myhost,clhost) && SERVER_PORT() == 25 ){
		lfprintf(log,tc,"500 don't connect with myself to deliver.\r\n");
		return -1;
	}

	mboxid(AVStr(Sender),clhost,AVStr(muid),AVStr(date));
	if( (fp = SMTP_POST(clhost,25,Sender,MailGate(Conn))) == NULL ){
		lfprintf(log,tc,"500 cannot connect SMTP server to return.\r\n");
		return -1;
	}

lfprintf(log,fp,"To: %s\r\n",Sender);
lfprintf(log,fp,"Subject: receipt to your mail\r\n");
 fprintf(fp,"\r\n");
lfprintf(log,fp,"YOUR MAIL ADDRESS IS REGISTERED AND ASSIGNED A UNIQUE IDENTIFIER:\r\n");
 fprintf(fp,"\r\n");
lfprintf(log,fp,"MUID: %s\r\n",muid);
lfprintf(log,fp,"MBOX: <%s>\r\n",Sender);
lfprintf(log,fp,"DATE: %s\r\n",date);
 fprintf(fp,"\r\n");
 fprintf(fp,"--INPUT--\r\n");
	copyfile1(indata,fp);
 fprintf(fp,"--\r\n");
	pclose(fp);

	lfprintf(log,tc,"250 Mail accepted\r\n",Recipients);
	return 1;
}

FILE *openMbox(int create,PVStr(mbox),PCStr(muid));
int mboxid(PVStr(mbox),PCStr(mailer),PVStr(muid),PVStr(date))
{	CStr(src,256);
	CStr(md5id,128);
	CStr(sdate,32);
	CStr(line,1024);
	int now;
	FILE *fp;
	int exist;

	setVStrEnd(date,0);
	setVStrEnd(muid,0);
	fp = openMbox(0,AVStr(mbox),muid);
	if( fp != NULL ){
		fgets(line,sizeof(line),fp); Xsscanf(line,"MUID: %s",AVStr(muid));
		fgets(line,sizeof(line),fp); Xsscanf(line,"DATE: %[^\r\n]",AVStr(date));
	}
	if( muid[0] && date[0] )
		return 1;

	now = time(0);
/*StrftimeGMT(AVStr(date),ERR_sizeof(date),TIMEFORM_RFC822,now,0);*/
	StrftimeGMT(AVStr(date),64,TIMEFORM_RFC822,now,0);
	sprintf(src,"%d<%s>",now,Sender);
	toMD5(src,md5id);
	md5id[6] = 0;
	strtoupper(md5id,md5id);
	StrftimeGMT(AVStr(sdate),sizeof(sdate),"%y%m%d",now,0);
	sprintf(muid,"%s-%s",sdate,md5id);

	fp = openMbox(1,AVStr(mbox),muid);
	if( fp == NULL )
		return -1;

	fprintf(fp,"MUID: %s\r\n",muid);
	fprintf(fp,"DATE: %s\r\n",date);
	fprintf(fp,"MAILER: %s\r\n",mailer);
	fclose(fp);
	return 0;
}

int strtoB64(PCStr(str),int slen,PVStr(b64),int bsiz,int withnl);
static int SMTP_authLOGIN(Connection *Conn,FILE *log,FILE *ts,FILE *fs,PCStr(auth),PVStr(resp)){
	IStr(user,128);
	IStr(pass,128);
	IStr(userb,256);
	IStr(passb,256);
	int code;

	fieldScan(auth,user,pass);
	strtoB64(user,strlen(user),AVStr(userb),sizeof(userb),0);
	strtoB64(pass,strlen(pass),AVStr(passb),sizeof(passb),0);

	SMTP_putserv(log,fs,ts,BVStr(resp),"AUTH LOGIN\r\n");
	if( (code = atoi(resp)) != 334 ){
		return code;
	}

	SMTP_putserv(log,fs,ts,BVStr(resp),"%s\r\n",userb);
	if( (code = atoi(resp)) != 334 ){
		return code;
	}

	SMTP_putserv(log,fs,ts,BVStr(resp),"%s\r\n",passb);
	if( (code = atoi(resp)) != 235 ){
		return code;
	}
	return code;
}
static int doAUTH_LOGIN_SV(PCStr(myhost),FILE *log,FILE *ts,FILE *fs,PVStr(resp)){
	const char *cache = EHLO_cache;
	int doauth = SMTP_doauth;
	IStr(caps,4*1024);
	const char *dp;

	if( EHLO_cache && strstr(EHLO_cache,"LOGIN") ){
		/* 9.9.8 it should be reused not to repeat EHLO */
		sv1log("#### Reusing EHLO cache\n");
	}else
	EHLO_cache = 0;
	SMTP_doauth = 0;
	HELO_withSV("EHLO",myhost,log,ts,fs,AVStr(caps));
	EHLO_cache = cache;
	SMTP_doauth = doauth;

	lineScan(caps,resp);
	if( strstr(caps,"250-AUTH") ){
		if( strstr(caps,"LOGIN") ){
			return 1;
		}
	}
	return 0;
}
static int SMTP_sendMYAUTH(Connection *Conn,FILE *log,FILE *ts,FILE *fs)
{	CStr(authb,256);
	const char *ap;
	CStr(plain,256);
	refQStr(pp,plain); /**/
	CStr(bplain,256);
	CStr(resp,256);

	if( get_MYAUTH(Conn,AVStr(authb),"smtp",DST_HOST,DST_PORT) ){
		CStr(myhost,MaxHostNameLen);
		if( Conn->sv_sockHOST.a_port ){ /* saved before FSV insertion */
			wordScan(Conn->sv_sockHOST.a_name,myhost);
		}else
		if( gethostNAME(fileno(ts),AVStr(myhost)) <= 0 )
			gethostname(myhost,sizeof(myhost));
		getFQDN(myhost,AVStr(myhost));

		if( doAUTH_LOGIN_SV(myhost,log,ts,fs,AVStr(resp)) ){
			SMTP_authLOGIN(Conn,log,ts,fs,authb,AVStr(resp));
			if( atoi(resp) == 235 ){
				return 0;
			}
		}

		SMTP_putserv(log,fs,ts,AVStr(resp),"EHLO %s\r\n",myhost);
		if( atoi(resp) != 250 ){
			return -1;
		}

		pp = plain;
		ap = authb;
		strcpy(pp,""); /* user-ID */
		pp += strlen(pp) + 1;
		ap = wordscanY(ap,AVStr(pp),128,"^:");
		pp += strlen(pp) + 1;
		if( *ap == ':' ){
			wordscanY(ap+1,AVStr(pp),128,"^\r\n");
		}
		pp += strlen(pp);

		str_to64(plain,pp-plain,AVStr(bplain),sizeof(bplain),1);
		if( pp = strpbrk(bplain,"\r\n") )
			truncVStr(pp);

		SMTP_putserv(log,fs,ts,AVStr(resp),"AUTH PLAIN %s\r\n",bplain);
		if( atoi(resp) != 235 )
			return -1;
	}
	return 0;
}
static int SMTP_AUTH(Connection *Conn,FILE *log,FILE *fc,FILE *tc,PCStr(arg))
{	CStr(buff,256);
	const char *wp;
	CStr(id,256);
	CStr(user,256);
	CStr(pass,256);
	int len,rcode;

	wp = wordScan(arg,buff);
	if( strncasecmp(buff,"PLAIN",5) == 0 ){
		wordScan(wp,buff);
		len = str_from64(buff,strlen(buff),AVStr(id),sizeof(id));
		setVStrEnd(id,len+2);
		setVStrEnd(id,len+1);
		setVStrEnd(id,len);
		wp = strchr(id,'\0');
		wp = lineScan(wp+1,user);
		wp = lineScan(wp+1,pass);
	}
	else
	if( strcaseeq(arg,"LOGIN") ){
		lfprintf(log,tc,"334 VXNlcm5hbWU6\r\n"); /* Username: */
		fflush(tc);
		fgetsTIMEOUT(AVStr(buff),sizeof(buff),fc);
		str_from64(buff,strlen(buff),AVStr(user),sizeof(user));

		lfprintf(log,tc,"334 UGFzc3dvcmQ6\r\n"); /* Password: */
		fflush(tc);
		fgetsTIMEOUT(AVStr(buff),sizeof(buff),fc);
		str_from64(buff,strlen(buff),AVStr(pass),sizeof(pass));
	}
	else
	{
		rcode = 504;
		lfprintf(log,tc,"504 unsupported method: %s\r\n",arg);
		fflush(tc);
		return rcode;
	}

	if( CTX_auth(Conn,user,pass) < 0 ){
		rcode = 500;
		lfprintf(log,tc,"500 Not Authenticated.\r\n");
	}else{
		rcode = 0;
		lfprintf(log,tc,"235 Authenticated and Authorized.\r\n");
	}
	fflush(tc);
	return rcode;
}

int connectToX(PCStr(addr),int port,int delayms,int infd);
int findClientDelay(Connection *Conn);

/*
 * Check if the SMTP client replies as SMTP server, and if the name
 * in its opening message as a server is same with the name in HELO
 * command as a client.
 *
 * client ----SMTP------>> server
 *        << 220 server
 *        >> HELO ClientName1
 * client <<---SMTP------- server
 *        >> 220 ClientName0
 */
static void checkHELO(Connection *Conn,FILE *fc,PCStr(com),PCStr(helo))
{	CStr(preq,1024);
	int age,sock,delayms,nready;
	CStr(resp,256);
	CStr(conf,128);
	double Start1;

	didHELO = 1;
	Start1 = Time();
	CALLBACKlog(Conn,com,"%d <%s> %s %s",DelayMsec(CallBackDelay),
		helo,Clhost,
		0<ready_cc(fc)?"(PIPELINED)":"");

	if( CallBackDelay <= 0 ){
		isSMTP = 1;
		return;
	}

	age = findClientDelay(Conn);
	if( 0 < age && age < 10*60 ){
		delayms = DelayMsec(CallBackDelay);
		CALLBACKlog(Conn,"INIT",
			"<%s> %dsec after last SPAM, delay %dms...",
			Clhost,age,delayms);
		waitClientDelay(Conn,FromC,delayms);
		if( !IsAlive(ClientSock) ){
		CALLBACKlog(Conn,"INIT","disconnected during delay (%dms)",
			(int)(1000*(Time()-Start)));
			return;
		}
	}

	/*
	if( hostcmp(clhost,helo) != 0 ){
		if( 0 < fPollIn(fc,15*1000) ){
			recvPeekTIMEOUT(fileno(fc),preq,sizeof(preq));
			if( pp = strpbrk(pp,"\r\n") )
				truncVStr(pp);
			sv1log("UNMATCH HELO[%s %s][%s] %dms[%s]\n",
				com,helo,clhost,
				(int)(1000*(Time()-Start)),preq);
		}else{
			sv1log("UNMATCH HELO[%s %s][%s]\n",com,helo,clhost);
		}
	}
	*/

	if( sockFromMyself(ClientSock) ){
		isSMTP = 2;
	}else
	{
		delayms = DelayMsec(CallBackDelay);
		CALLBACKlog(Conn,"vrfy","%s:25",Claddr);

		sock = connectToX(Claddr,25,delayms,ClientSock);
		if( 0 <= sock ){
			FILE *xfs;
			xfs = fdopen(sock,"r");
			delayms -= (int)(1000*(Time()-Start1));
			if( SMTP_fgetsResp(AVStr(resp),sizeof(resp),xfs,delayms) != NULL ){
		CALLBACKlog(Conn,"open","%s",resp);
				if( *resp == '2' ){
					FILE *xts;
					xts = fdopen(sock,"w");
					fputs("QUIT\r\n",xts);
					fflush(xts);
					fgetsTimeout(AVStr(resp),sizeof(resp),xfs,15);
		CALLBACKlog(Conn,"quit","%s",resp);
					if( *resp == '2' ){
						isSMTP = 3;
PageCountUpURL(Conn,CNT_TOTALINC,"#SMTPcb-OK",NULL);
					}else{
						isSMTP = -1; /* bad response */
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-BadResponse",NULL);
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-Non-SMTP",NULL);
					}
					fclose(xts);
				}else{
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-BadGreeting",NULL);
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-Non-SMTP",NULL);
					isSMTP = -2; /* bad greeting */
				}
				if( isSMTP < 0 ){
		CALLBACKlog(Conn,"err1","is not SMTP");
				}
			}else{
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-NoResponse",NULL);
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-Non-SMTP",NULL);
				isSMTP = -3; /* no response */
		CALLBACKlog(Conn,"err2","no resp from SMTP, EOF=%d",feof(xfs));
			}
			fclose(xfs);
		}else{
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-CantConnect",NULL);
PageCountUpURL(Conn,CNT_ERRORINC,"#SMTPcb-Non-SMTP",NULL);
			isSMTP = -4; /* could not connect */
			close(sock);
		CALLBACKlog(Conn,"err3","could not connect, errno=%d",errno);
		}

		if( isSMTP < 0 ){
			delayms -= (int)(1000*(Time() - Start1));
		CALLBACKlog(Conn,"wait","delay %dms / %dms...",delayms,
		DelayMsec(CallBackDelay));
			if( 0 < delayms ){
				nready = PollIn(ClientSock,delayms);
			}
		}
		CALLBACKlog(Conn,"stat","isSMTP=%d%s %s ready=%d,%d (%dms)",
			isSMTP,((0<isSMTP)?"S":(isSMTP<0)?"N":"U"),
			IsAlive(ClientSock)?"-":"disconnected",
			PollIn(ClientSock,1),ready_cc(fc),
			(int)(1000*(Time()-Start)));
	}
	/*return isSMTP;*/
}

static int badHELOdomain(Connection *Conn,FILE *log,FILE *tc,PCStr(helo)){
	CStr(hdom,MaxHostNameLen);
	CStr(mx,MaxHostNameLen);
	int match;

	if( SMTP_tolerance & SMT_NOMXHELO )
	if( SMTP_helodomain == 0 ){
		return 0;
	}
	wordScan(helo,hdom);
	if( (SMTP_tolerance & SMT_NOMXHELO) == 0 ){
		sprintf(mx,"-MX.%s",Client_Host);
		if( !hostisin(hdom,mx,0) ){
			lfprintf(NULL,tc,"421 no MX HELO <%s>\r\n",hdom);
			return 1;
		}
	}
	if( SMTP_helodomain ){
		CTX_pushClientInfo(Conn);
		match = matchPath1(SMTP_helodomain,"",hdom,0);
		HL_popClientInfo();
		if( !match ){
			lfprintf(NULL,tc,"421 bad HELO domain <%s>\r\n",
				hdom);
			return 1;
		}
	}
	return 0;
}

static void SMTPserver(Connection *Conn,FILE *fc,FILE *tc)
{	CStr(myhost,MaxHostNameLen);
	CStr(clhost,128);
	CStr(stime,128);
	CStr(req,1024);
	const char *wp;
	CStr(com,1024);
	CStr(arg,1024);
	CStr(rcpt,128);
	CStr(xreq,LNSIZE);
	FILE *indata,*log;
	int sent = 0;
	SMTPreq Req;
	int rcptn = 0;

	getClientHostPort(Conn,AVStr(clhost));
	if( SMTP_myname ){
		lineScan(SMTP_myname,myhost);
	}else{
	ClientIF_name(Conn,FromC,AVStr(myhost));
	getFQDN(myhost,AVStr(myhost));
	}
	peerHELO[0] = 0;

	StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_RFC822,time(0),0);
	indata = TMPFILE("SMTP/DATA");
	log = TMPFILE("SMTP/LOG");

	lfprintf(log,tc,"220 %s SMTP/DeleGate/%s ready at %s\r\n",
		myhost,DELEGATE_ver(),stime);
	fflush(tc);

	rcpt[0] = 0;
	doAuth = SMTP_doauth != 0;
	for(;;){
		/*
		if( fgets(req,sizeof(req),fc) == 0 )
		*/
		if( fgetsRequest(AVStr(req),sizeof(req),fc) == 0 )
		{
			PageCountUpURL(Conn,CNT_ERRORINC,"#ClientReset",NULL);
			break;
		}
		Ncoms++;
		fputs(req,indata);
		lfprintf(log,NULL,">>> %s",req);

		wp = wordScan(req,com);
		lineScan(wp,arg);
		sv1log("SMTP [%s][%s]\r\n",com,arg);

		if( notAvailable(com,tc,log) )
			continue;

		if( (SMTP_tolerance & SMT_NOHELO) == 0 )
		if( peerHELO[0] == 0 )
		if( !strcaseeq(com,"EHLO") && !strcaseeq(com,"AUTH") )
		if( !strcaseeq(com,"NOOP") )
		if( !strcaseeq(com,"STARTTLS") )
		if( !strcaseeq(com,"HELO") && !strcaseeq(com,"QUIT") ){
			lfprintf(log,tc,"503 Say HELO first (%s/%s)\r\n",
				clhost,gethostaddrX(clhost));
				/*
				clhost,gethostaddr(clhost));
				*/
			fflush(tc);
			continue;
		}

		if( strcasecmp(com,"XECHO") == 0 ){
			fprintf(tc,"%s\r\n",arg);
		}else
		if( strcasecmp(com,"NOOP") == 0 ){
			fprintf(tc,"200 OK\r\n");
		}else
		if( strcaseeq(com,"QUIT") ){
			lfprintf(log,tc,"221 %s closing connection\r\n",myhost);
			break;
		}else
		if( strcaseeq(com,"HELO") ){
			lineScan(arg,peerHELO);
			if( badHELOdomain(Conn,log,tc,peerHELO) ){
				break;
			}
			checkHELO(Conn,fc,com,peerHELO);
			lfprintf(log,tc,"250 %s Hello %s (%s)\r\n",myhost,arg,
				clhost);
		}else
		if( strcaseeq(com,"EHLO") ){
			lineScan(arg,peerHELO);
			if( badHELOdomain(Conn,log,tc,peerHELO) ){
				break;
			}
			checkHELO(Conn,fc,com,peerHELO);
			lfprintf(log,tc,"250-%s Hello %s (%s)\r\n",
				myhost,arg,clhost);
			if( willSTLS_CL(Conn) ){
				lfprintf(log,tc,"250-STARTTLS\r\n");
			}
			if( SMTP_doauth ){
				lfprintf(log,tc,"250-AUTH PLAIN LOGIN\r\n");
				lfprintf(log,tc,"250-AUTH=LOGIN\r\n");
			}
			lfprintf(log,tc,"250 XECHO\r\n");
		}else
		if( strcaseeq(com,"STARTTLS") ){
			if( SMTP_STARTTLS_withCL(Conn,fc,tc) < 0 ){
				break;
			}
			fflush(tc);
			continue;
		}else
		if( needSTLS(Conn) ){
			lfprintf(log,tc,"530 Say STARTTLS first\r\n");
			fflush(tc);
			continue;
		}else
		if( strcaseeq(com,"AUTH") ){
			if( SMTP_AUTH(Conn,log,fc,tc,arg) == 0 )
				doAuth = 0;
		}else
		if( strcaseeq(com,"RCPT") ){ /* To */
			if( SMTP_maxrcpt && SMTP_maxrcpt < ++rcptn ){
				lfprintf(log,tc,"500 too many recipients.\r\n");
				break;
			}
			if( SMTP_mount_rcpt(Conn,tc,req,AVStr(xreq)) < 0 )
				continue;
			decomp_req(xreq[0]?xreq:req,&Req);
			if( (sent = doRCPT(Conn,indata,tc,arg,Req.sm_uv[SMQ_RCPT],log)) < 0 )
				break;

			if( Recipients )
				FStrncpy(rcpt,Recipients);
			else	rcpt[0] = 0;
		}else
		if( strcaseeq(com,"MAIL") ){ /* From */
			decomp_req(req,&Req);
			if( (sent = doMAIL(Conn,tc,arg,Req.sm_uv[SMQ_FROM],log)) < 0 )
				break;
		}else
		if( strcaseeq(com,"DATA") ){
			didDATA = 1;
			if( (sent = doDATA(Conn,indata,tc,fc,myhost,clhost,log)) < 0 )
				break;
			fflush(tc);
			fseek(log,0,0);
			continue;
		}else
		if( strcaseeq(com,"RSET") ){
			doRSET(Conn);
			lfprintf(log,tc,"250 Reset state\r\n");
		}else{
			lfprintf(log,tc,"500 Command unrecognized\r\n");
		}
		if( 0 < CallBackDelay && isSMTP <= 0 ){
			if( 0 < fPollIn(fc,DelayMsec(CallBackDelay)) ){
				CStr(preq,1024);
				preq[0] = 0;
				if( 0 < ready_cc(fc) )
					fgetsBuffered(AVStr(preq),sizeof(preq),fc);
				else	recvPeekTIMEOUT(fileno(fc),AVStr(preq),sizeof(preq));
		CALLBACKlog(Conn,"peek","%s [%s] -> %s",
			preq[0]?"PRESENT COMMAND":"PREMATURE CLOSE",com,preq);
				if( (SMTP_tolerance & SMT_NOPIPELINE) == 0 ){
					break;
				}
			}
		}
		fflush(tc);
	}
	if( 0 < fPollIn(fc,1) ){
		/*
		if( fgets(req,sizeof(req),fc) != 0 ){
		*/
		if( fgetsRequest(AVStr(req),sizeof(req),fc) != 0 ){
			if( strncasecmp(req,"QUIT",4) == 0 )
			lfprintf(log,tc,"221 %s closing connection\r\n",myhost);
		}
	}
	fflush(tc);
	fclose(indata);
	fclose(log);
	if( SMTP_callback ){
		CALLBACKlog(Conn,"done","sent=%d/%d%s %s [%s|%s|%s]",
			sent, isSMTP,((0<isSMTP)?"S":(isSMTP<0)?"N":"U"),
			Clhost, peerHELO,Sender,rcpt);
		smtplog(Conn,"done[%d] [%s] [%s]",sent,Sender,rcpt);
		if( isSMTP <= 0 )
		PageCountUpURL(Conn,CNT_ERRORINC,"#Non-SMTP",NULL);
	}
}
int relayDATAwithEOR(FILE *mfp,FILE *ts,int putEOR){
	CStr(line,1024);
	IStr(prev,1024);
	int withEOR = 0;
	int timeout = ClientRequestTimeout;
	int rcc = 0;
	double St,Now,Prev;
	int lines = 0;

	St = Prev = Time();
	if( mfp ){
		while( 1 ){
			Now = Time();
			lines++;
			if( 10 < Now - Prev ){
		sv1log("## DATA+ %d bytes / %d lines / %.1fs (%.1f/s)\n",
					rcc,lines,Now-St,rcc/(Now-St));
				Prev = Time();
			}
			if( feof(mfp) || ferror(ts) ){
				sv1log("## DATA+ abort: %d %d\n",
					feof(mfp),ferror(ts));
				break;
			}
			if( fPollIn(mfp,timeout*1000) == 0 ){
				sv1log("DATA timeout: %d\n",timeout);
				break;
			}
			if( fgets(line,sizeof(line),mfp) == NULL ){
				break;
			}
			rcc += strlen(line);
			fputs(line,ts);
			strcpy(prev,line);
			if( *line=='.' && (line[1]=='\r' || line[1]=='\n') ){
				withEOR = 1;
				if( putEOR ){
					break;
				}
			}else	withEOR = 0;
		}
	}
	if( withEOR ){
		return 1;
	}else{
		daemonlog("E","NOT ended with .CRLF: %s\n",prev);
		if( putEOR ){
			fputs(".\r\n",ts);
		}
		return 0;
	}
}

/*
static int relay_DATA(FILE *fc,FILE *tc,FILE *fs,FILE *ts,PVStr(stat))
*/
#define relay_DATA(fc,tc,fs,ts,stat) CTX_relay_DATA(Conn,fc,tc,fs,ts,stat)
static int CTX_relay_DATA(Connection *Conn,FILE *fc,FILE *tc,FILE *fs,FILE *ts,PVStr(stat))
{	FILE *data;
	int rcode,size;
	CStr(buff,16*1024);
	CStr(req,32);
	int rcc,wcc,qc;
	int nready;
	MimeEnv me;

	if( SMTP_thrudata < 0 ){
		thruRESP(fc,ts);
		return SMTP_relay_stat(fs,tc,AVStr(stat));
	}

	me.me_filter = 0xF; /* O_ALL */
	me.me_ccx = CCX_TOSV;

	if( 0 < SMTP_thrudata ){
		FILE *indata;
		int start,till,rem;
		double St,Now,Prev;
		int lines = 0;

		indata = TMPFILE("SMTP-DATA-IN");
		start = time(0);
		St = Prev = Time();
		till = start + SMTP_thrudata;
		rcc = 0;
		for(;;){
			rem = till - time(0);
			if( rem <= 0 || fPollIn(fc,rem*1000) <= 0 ){
			sv1log("## SMTP unbuffering slow DATA (%dB/%ds).\n",
					rcc,ll2i(time(0)-start));
				fflush(indata);
				fseek(indata,0,0);
				/*
				copyfile1(indata,ts);
				fclose(indata);
				thruRESP(fc,ts);
				*/
				if( relayDATAwithEOR(indata,ts,0) == 0 ){
					relayDATAwithEOR(fc,ts,1);
				}
				fflush(ts);
				fclose(indata);
				return SMTP_relay_stat(fs,tc,AVStr(stat));
			}
			do {
				Now = Time();
				lines++;
				if( 10 <= Now - Prev ){
		sv1log("## DATA %d bytes / %d lines / %.1fs (%.1f/s)\n",
						rcc,lines,Now-St,rcc/(Now-St));
					Prev = Time();
				}

				if( fgets(buff,sizeof(buff),fc) == NULL )
					goto ENDDATA;
				fputs(buff,indata);
				rcc += strlen(buff);

				if( buff[0] == '.' )
				if( buff[1] == '\r' || buff[1] == '\n' )
					goto ENDDATA;
			} while( 0 < READYCC(fc) );
		} ENDDATA:
		fflush(indata);
		fseek(indata,0,0);
		data = TMPFILE("SMTP-DATA");
		/*
		PGPencodeMIME(indata,data);
		*/
		PGPencodeMIMEXX(&me,indata,data);
		fclose(indata);
	}else{
	data = TMPFILE("SMTP-DATA");
		PGPencodeMIMEXX(&me,fc,data);
	/*
	PGPencodeMIME(fc,data);
	*/
	}
	fflush(data);
	size = ftell(data);
	fseek(data,0,0);

	if( feof(fc) ){
		sv1log("C-S disconnected in DATA\n");
	}
	if( size <= SMTP_bgdatasize ){
		/*
		copyfile1(data,ts);
		*/
		relayDATAwithEOR(data,ts,1);
		fflush(ts);
		fclose(data);
		return SMTP_relay_stat(fs,tc,AVStr(stat));
	}

	sv1log("## SMTP relaying large DATA (%d < %d bytes)\n",
		SMTP_bgdatasize,size);
	fprintf(tc,"250 Mail accepted\r\n");
	fflush(tc);

	rcode = 0;
	for(;;){
	    if( (rcc = fread(buff,1,sizeof(buff),data)) <= 0 )
		break;
	    wcc = fwrite(buff,1,rcc,ts);

	    if( rcode == 0 && (nready = fPollIn(fc,1)) ){
		rcode = 1;
		if( nready < 0 ){
			sv1log("## SMTP client EOF ? during DATA relay\n");
			rcode = -1;
		}else{
		    qc = fgetc(fc);
		    if( feof(fc) ){
			sv1log("## SMTP client EOF during DATA relay\n");
			rcode = -2;
		    }else{
			ungetc(qc,fc);
			if( toupper(qc) == 'Q' ){
				fprintf(tc,"221 DeleGate delivering mail\r\n");
				fflush(tc);
				closeFDs(fc,tc);

				sv1log("## SMTP Quit sent during DATA relay\n");
				rcode = -3;
			}
		    }
		}
	    }
	}
	fflush(ts);
	fclose(data);
/*
	if( 0 <= rcode )
*/
	if( 0 <= rcode || 0 < fPollIn(fs,10*1000) )
		rcode = SMTP_relay_stat(fs,NULL,AVStr(stat));
	return rcode;
}

void smtp_datamark(Connection *Conn,FILE *ts)
{
	if( filter_withCFI(Conn,XF_FTOSV)
	 || filter_withCFI(Conn,XF_FTOMD)
	){
		putMESSAGEline(ts,"mime","DATA");
	}
}

int service_smtp(Connection *Conn)
{	FILE *fc,*ts,*fs,*tc;
	CStr(req,LNSIZE);
	CStr(stat,LNSIZE);
	CStr(com,80);
	CStr(arg,80);
	const char *wp;
	int rcode;
	int QUITdone = 0;
	int rcptn = 0;
	int sent = 0;
	CStr(from,MaxHostNameLen);
	CStr(rcpt,MaxHostNameLen);

	PageCountUpURL(Conn,CNT_TOTALINC,"#sessions",NULL);
	if( !IsAlive(ClientSock) ){
		PageCountUpURL(Conn,CNT_ERRORINC,"#PreReset",NULL);
		return -1;
	}
	didHELO = 0;
	didDATA = 0;
	Tolerance = SMTP_tolerance;

	Start = Time();
	Ncoms = 0;

	fc = fdopen(FromC,"r");
	tc = fdopen(ToC,  "w");
	fs = NULL;
	ts = NULL;

	isSMTP = 0;
	getClientHostPort(Conn,AVStr(Clhost));
	getpeerName(ClientSock,AVStr(Claddr),"%A");

	if( (SMTP_tolerance & SMT_NOMX) == 0
	 || (SMTP_tolerance & SMT_NOMXSELF) == 0
	){	int withMX,isMXself = 0;
		CStr(msg,1024);

		CStr(mx,MaxHostNameLen);
		sprintf(mx,"-MX.%s",Client_Host);
		if( withMX = hostIsResolvable(mx) ){
			isMXself = hostisin(Client_Host,mx,0);
		}
		if( !withMX
		 || !isMXself && (SMTP_tolerance & SMT_NOMXSELF) == 0
		){
			sv1log("reject:[nomx](%d %d) %s\n",
				withMX,isMXself,Client_Host);

			if( !withMX )
				sprintf(msg,"no MX record for [%s]",Client_Host);
			else	sprintf(msg,"[%s] is not a MX",Client_Host);
			/*
			lfprintf(NULL,tc,"421 %s\r\n");
			*/
			lfprintf(NULL,tc,"421 %s\r\n",msg);
			fclose(tc);
			fclose(fc);
			return -1;
		}
	}

	CallBackDelay = 0;
	if( SMTP_callback ){
		CStr(conf,256);
		if( 0 <= find_CMAP(Conn,"HELO_CallBack",AVStr(conf)) ){
			CALLBACKlog(Conn,"CONF","do callback:%s\n",conf);
			CallBackDelay = Scan_period(conf,'s',(double)DFLT_DELAY);
		}else{
			CALLBACKlog(Conn,"CONF","no callback\n");
		}
	}

	if( SMTP_myname ){
		lineScan(SMTP_myname,Myhost);
	}else{
		ClientIF_name(Conn,FromC,AVStr(Myhost));
		getFQDN(Myhost,AVStr(Myhost));
	}

	if( SMTP_doauth == 0 ){
		if( CTX_auth(Conn,NULL,NULL) ){
			SMTP_doauth = A_PLAIN | A_LOGIN;
		}
	}

	/* should care SIGPIPE ... */

	if( ToS < 0 || FromS < 0 ){
		if( isMYSELF(DFLT_HOST) )
			SMTPserver(Conn,fc,tc);
		/*
		goto EXIT;
		*/
		goto EXIT2;
	}else{
		fs = fdopen(FromS,"r");
		if( SMTP_relay_stat(fs,tc,AVStr(stat)) < 0 )
			goto EXIT;
		ts = fdopen(ToS,  "w");

		if( willSTLS_SV(Conn) ){
			rcode = HELO_withSV("EHLO",Myhost,NULL,ts,fs,AVStr(stat));
			if( rcode != 250 ){
				fprintf(tc,"421 HELO failed: %d\r\n",rcode);
				fflush(tc);
				goto EXIT;
			}
		}
		if( SMTP_STARTTLS_withSV(Conn,ts,fs) < 0 ){
			fprintf(tc,"421 cannot start TLS with the server\r\n");
			fflush(tc);
			goto EXIT;
		}
		if( ServerFlags & PF_STLS_ON ){
			/* 9.9.7 update the EHLO cache after STARTTLS */
			sv1log("#### Updating EHLO cache, SF=%X\n",ServerFlags);
			EHLO_cache = 0;
			rcode = HELO_withSV("EHLO",Myhost,NULL,ts,fs,AVStr(stat));
		}
		if( SMTP_sendMYAUTH(Conn,NULL,ts,fs) < 0 )
		{
			fprintf(tc,"%s\r\n","500 Authentication error.");
			fflush(tc);
			goto EXIT;
		}
	}

	truncVStr(from);
	truncVStr(rcpt);
	doAuth = SMTP_doauth != 0;
	for(;;){
		if( SMTP_relay_req(Conn,fc,tc,ts,AVStr(req)) < 0 )
			break;
		Ncoms++;
		if( strncmp(req,"-- ",3) == 0 ){
			/* the request is disabled in SMTP_reay_req() */
			continue;
		}

		wp = wordScan(req,com);
		lineScan(wp,arg);
		if( notAvailable(com,tc,NULL) ){
			continue;
		}
		if( strncasecmp(req,"XECHO",5) == 0 )
			continue;

		if( strcaseeq(com,"HELO") || strcaseeq(com,"EHLO") ){
			lineScan(arg,peerHELO);
			if( badHELOdomain(Conn,NULL,tc,peerHELO) ){
				break;
			}
			checkHELO(Conn,fc,com,arg);
		}
		if( strcaseeq(com,"HELO") ){
			rcode = HELO_withSV(com,Myhost,NULL,ts,fs,AVStr(stat));
			fputs(stat,tc);
			fflush(tc);
			continue;
		}

/*
		if( respforEHLO ){
			respforEHLO = 0;
			rcode = SMTP_relay_stat(fs,NULL,AVStr(stat));

*/
		if( strcaseeq(com,"EHLO") ){
			rcode = HELO_withSV(com,Myhost,NULL,ts,fs,AVStr(stat));
			if( rcode != 250 ){
				fputs(stat,tc);
				fflush(tc);
				break;
			}
			fprintf(tc,"250-%s Hello %s (%s)\r\n",
				Myhost,arg,Clhost);
			if( SMTP_doauth ){
			fprintf(tc,"250-AUTH PLAIN LOGIN\r\n");
			fprintf(tc,"250-AUTH=LOGIN\r\n");
			}
			if( willSTLS_CL(Conn) ){
				lfprintf(NULL,tc,"250-STARTTLS\r\n");
			}
			if( EHLO_cache ){
				lfprintf(NULL,tc,"%s",EHLO_cache);
			}else
			fputs(stat,tc);
			fflush(tc);
			continue;
		}
		if( strcaseeq(com,"STARTTLS") ){
			if( SMTP_STARTTLS_withCL(Conn,fc,tc) < 0 ){
				break;
			}
			continue;
		}
		if( SMTP_doauth && strcaseeq(com,"AUTH") ){
			if( SMTP_AUTH(Conn,NULL,fc,tc,arg) == 0 )
				doAuth = 0;
			continue;
		}

		if( (rcode = SMTP_relay_stat(fs,tc,AVStr(stat))) < 0 )
			break;

		if( strcaseeq(com,"MAIL") ){
			Xsscanf(arg,"%*[^:]: %s",AVStr(from));
		}
		if( strcaseeq(com,"RCPT") ){
			if( SMTP_maxrcpt && SMTP_maxrcpt < ++rcptn ){
				fprintf(tc,"500 too many recipients.\r\n");
				fflush(tc);
				break;
			}
			smtpbcc(Conn,arg,AVStr(rcpt),ts,fs);
			Xsscanf(arg,"%*[^:]: %s",AVStr(rcpt));
		}
		if( rcode == 354 ){ /* DATA */
			smtp_datamark(Conn,ts);
			didDATA = 1;

			if( (rcode = relay_DATA(fc,tc,fs,ts,AVStr(stat))) < 0 )
			{
				sent = -1;
				break;
			}
			sent = 1;
		}
		/*
		if( strcasecmp(req,"QUIT\r\n") == 0 ){
		*/
		if( strcasecmp(req,"QUIT\r\n") == 0 || strcaseeq(com,"QUIT") ){
			sv1log("CS-QUIT\n");
			QUITdone = 1;
			break;
		}
	}
	if( !QUITdone ){
		fputs("QUIT\r\n",ts);
		fflush(ts);
		if( 0 < fPollIn(fs,10*1000) )
		SMTP_relay_stat(fs,NULL,AVStr(stat));
	}
EXIT:
	smtplog(Conn,"sent[%d] [%s] [%s]",sent,from,rcpt);
EXIT2:
	if( 0 < sent ){
		PageCountUpURL(Conn,CNT_TOTALINC,"#accepted",NULL);
		PageCountUpURL(Conn,CNT_TOTALINC,"#sent",NULL);
	}
	if( didHELO == 0 ){
		PageCountUpURL(Conn,CNT_ERRORINC,"#Non-HELO",NULL);
	}else
	if( didDATA == 0 ){
		PageCountUpURL(Conn,CNT_ERRORINC,"#Non-DATA",NULL);
	}
	/*
	fclose(fc);
	fclose(tc);
	if( fs != NULL ) fclose(fs);
	if( ts != NULL ) fclose(ts);
	*/
	CTX_fcloses(FL_ARG,"SMTPclnt",Conn,fc,tc);
	CTX_fcloses(FL_ARG,"SMTPserv",Conn,fs,ts);
	return 0;
}

static const char *myver(){
	CStr(tmp,128);

	if( Myver == NULL ){
		sprintf(tmp,"SMTP-DeleGate/%s",DELEGATE_ver());
		Myver = StrAlloc(tmp);
	}
	return Myver;
}
int service_smtps(Connection *Conn){
	if( (ServerFlags & PF_SSL_ON) == 0 ){
		ServerFlags |= PF_SSL_IMPLICIT;
		if( 0 <= ToS ){
			int fsv;
			fsv = insertFSVF(Conn,FromC,ToS,"sslway");
			if( 0 <= fsv ){
				ToSX = ToS;
				ToS = FromS = fsv;
			}
		}
	}
	sv1log("SMTPS to %s://%s:%d SSL=%d\n",DST_PROTO,DST_HOST,DST_PORT,
		(ServerFlags&PF_SSL_ON) != 0);
	return service_smtp(Conn);
}

int SMTP_openX(Connection *Conn,FILE *fpv[],PCStr(host),int port,PCStr(to),PCStr(from),int dodata,FILE *log,PVStr(rresp));
int SMTP_open(Connection *Conn,FILE *fpv[],PCStr(host),int port,PCStr(to),PCStr(from),int dodata,FILE *log)
{
	CStr(resp,1024);
	return SMTP_openX(Conn,fpv,host,port,to,from,dodata,log,AVStr(resp));
}
static int connectToMX(Connection *Conn,PCStr(host),int port)
{	CStr(mxhost,MaxHostNameLen);

	if( *host == 0 ){
		sv1log("ERROR connectToMX(%s)\n",host);
		return -1;
	}
	if( connectMXMAP(Conn,host,port) != 0 ){
		return 0;
	}

	if( !IsInetaddr(host) )
	if( strncmp(host,"-MX.",4) != 0 )
	if( port == 0 || port == serviceport("smtp") )
	{
		sprintf(mxhost,"-MX.%s",host);
		if( IsResolvable(mxhost) ){
			set_realserver(Conn,"smtp",mxhost,port);
			if( 0 <= connect_to_serv(Conn,FromC,ToC,0) )
				return 0;
		}
	}
	set_realserver(Conn,"smtp",host,port);
	if( connect_to_serv(Conn,FromC,ToC,0) < 0 )
		return -1;
	return 0;
}
int SMTP_openX(Connection *Conn,FILE *fpv[],PCStr(host),int port,PCStr(to),PCStr(from),int dodata,FILE *log,PVStr(rresp))
{	FILE *fs,*ts;
	const char *auth;
	CStr(authb,256);

	setVStrEnd(rresp,0);

	if( connectToMX(Conn,host,port) < 0 ){
		sprintf(rresp,"421 cannot open SMTP for forwarding.\r\n");
		return -1;
	}
	/*
	set_realserver(Conn,"smtp",host,port);
	if( connect_to_serv(Conn,FromC,ToC,0) < 0 )
	{
		sprintf(rresp,"421 cannot open SMTP for forwarding.\r\n");
		return -1;
	}
	*/

	{
		CStr(url,1024);
		sprintf(url,"smtp://%s:%d/#total",host,port);
		PageCountUpURL(Conn,CNT_DESTINC,url,NULL);
		if( to[0] ){
			sprintf(url,"smtp://%s:%d/%s",host,port,to);
			PageCountUpURL(Conn,CNT_DESTINC,url,NULL);
		}
	}

	fs = fdopen(FromS,"r");
	ts = fdopen(ToS,"w");

	if( get_MYAUTH(Conn,AVStr(authb),"smtp",host,port) )
		auth = authb;
	else	auth = NULL;

	servConn = Conn;
	ServerFlags |= PF_STLS_DONTTRY;
	/*
	if( SMTP_openingX(fs,ts,myver(),to,from,dodata,log,auth) != 0 ){
	*/
	if( SMTP_openingXX(fs,ts,myver(),to,from,dodata,log,auth,AVStr(rresp)) != 0 ){
		CStr(resp,1024);
		SMTP_putserv(log,fs,ts,AVStr(resp),"QUIT\r\n");
		fclose(ts);
		fclose(fs);
		return -1;
	}
	servConn = 0;

	fpv[0] = fs;
	fpv[1] = ts;
	return ToS;
}

typedef struct {
	int	va_checkuser;
  const	char   *va_addr;
	int	va_valid;
} validAddr;
static validAddr *validAddrs;

int validateEmailAddr(PCStr(addr),int checkuser)
{	Connection ConnBuf,*Conn = &ConnBuf;
	FILE *fpv[2]; /**/
	FILE *log;
	int svsock;
	CStr(user,256);
	CStr(host,MaxHostNameLen);
	CStr(mxhost,MaxHostNameLen);
	CStr(addrb,256);
	validAddr *va;

	if( validAddrs == NULL )
		validAddrs = NewStruct(validAddr);

	va = &validAddrs[0];
	if( va->va_addr != 0 )
	if( strcmp(addr,va->va_addr) == 0 )
	if( checkuser == va->va_checkuser )
		return va->va_valid;

	RFC822_addresspartX(addr,AVStr(addrb),sizeof(addrb));
	addr = addrb;

	if( Xsscanf(addr,"%[^@]@%s",AVStr(user),AVStr(host)) != 2 )
		return -1;
	if( hostcmp("localhost",host) == 0 )
		return -1;

	/*
	sprintf(mxhost,"-MX.%s",host);
	if( IsResolvable(mxhost) )
		strcpy(host,mxhost);
	*/

	if( checkuser == 0 )
	{
		syslog_ERROR("DONT CHECK USER PART[%s]@%s\n",user,host);
		user[0] = 0;
	}

	ConnInit(Conn);
	Conn->from_myself = 1;
	Conn->co_mask |= CONN_NOPROXY | CONN_NOSOCKS;

	log = TMPFILE("emailValid");
	svsock = SMTP_open(Conn,fpv,host,25,user,DELEGATE_ADMIN,0,log);

	va = &validAddrs[0];
	va->va_checkuser = checkuser;
	va->va_addr = stralloc(addr);
	if( svsock < 0 )
	{
		va->va_valid = -1;
		fclose(log);
		return -1;
	}
	else{
		CStr(resp,1024);
		SMTP_putserv(log,fpv[0],fpv[1],AVStr(resp),"RSET\r\n");
		SMTP_putserv(log,fpv[0],fpv[1],AVStr(resp),"QUIT\r\n");
		fclose(fpv[0]);
		fclose(fpv[1]);
		va->va_valid = 0;
		fclose(log);
		return 0;
	}
}

FILE *SMTP_POST(PCStr(host),int port,PCStr(to),PCStr(from))
{
	return SMTP_post(host,port,myver(),to,from,NULL,VStrNULL,0);
}

const char *DELEGATE_SMTPSERVER;
void scan_SMTPSERVER(PCStr(smtpserver))
{
	if( smtpserver )
		Strdup((char**)&DELEGATE_SMTPSERVER,smtpserver);
}

#define MAILER	"/usr/lib/sendmail -t"
FILE *openMailPoster(PCStr(to),PCStr(from))
{	FILE *out;
	CStr(mailer,1024);
	CStr(host,512);
	int port;

	out = NULL;
	if( DELEGATE_SMTPSERVER ){
		sprintf(mailer,"SMTPSERVER %s",DELEGATE_SMTPSERVER);
		port = 25;
		Xsscanf(DELEGATE_SMTPSERVER,"%[^:]:%d",AVStr(host),&port);
		out = SMTP_POST(host,port,to,from);
		sv1log("#### SMTPSERVER [%x] %s\n",p2i(out),DELEGATE_SMTPSERVER);
	}
	if( out == NULL ){
		sprintf(mailer,MAILER,to);
		out = popen(mailer,"w");
	}
	if( out != NULL )
		fprintf(out,"X-Mailer: %s\n",mailer);
	return out;
}


FILE *SMTP_getEXPN(PCStr(addr))
{	CStr(user,256);
	CStr(host,MaxHostNameLen);
	int server;
	FILE *ts,*fs;
	CStr(stat,256);
	FILE *afp;
	int nlines;

	user[0] = host[0] = 0;
	Xsscanf(addr,"%[^@]@%s",AVStr(user),AVStr(host));
	server = client_open("SMTPGATE/EXPN","smtp",host,25);
	if( server < 0 ){
		sv1log("#### cannot EXPN <%s>\n",addr);
		return NULL;
	}

	fs = fdopen(server,"r");
	if( fgets(stat,sizeof(stat),fs) == NULL ){
		sv1log("#### EXPN error -- server closed\n");
		fclose(fs);
		return NULL;
	}
	sv1log("#### %s",stat);
	if( atoi(stat) != 220 ){
		fclose(fs);
		return NULL;
	}

	ts = fdopen(server,"w");
	fprintf(ts,"EXPN %s\r\n",user);
	fflush(ts);

	if( fgets(stat,sizeof(stat),fs) == NULL ){
		sv1log("#### EXPN error -- server closed\n");
/*
		fclose(afp);
*/
		afp = NULL;
	}else
	if( atoi(stat) != 250 ){
		sv1log("#### EXPN error -- %s",stat);
/*
		fclose(afp);
*/
		afp = NULL;
	}else{
		afp = TMPFILE("SMTPGATE/EXPN");
		fputs(stat,afp);
		for( nlines = 1; strncmp(stat,"250-",4) == 0; nlines++ ){
			if( fgets(stat,sizeof(stat),fs) == NULL )
				break;
			fputs(stat,afp);
		}
		fflush(afp);
		fseek(afp,0,0);
		sv1log("#### EXPN got <%s> -- %d lines\n",addr,nlines);
	}
	fclose(ts);
	fclose(fs);
	return afp;
}

/*
 *	-Fsendmail To URL
 *	-Fcopy srcURL dstURL
 *	-Fcopy nntp://server/group/number mailto:user@host.domain
 */
void sendmail1(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log);
int sendmail_main(int ac,const char *av[],Connection *Conn)
{	const char *to;
	const char *from;
	FILE *afp,*log;

	to = "";
	from = DELEGATE_ADMIN;
	afp = stdin;
	log = stderr;

	if( 1 < ac )
		to = av[1];

	sendmail1(Conn,to,from,afp,log);
	if( afp != stdin )
		fclose(afp);
	return 0;
}

int relayMSGdata(FILE *in,FILE *out,int anl,int eom)
{	int cc;
	int nlend;
	CStr(line,1024);

	cc = 0;
	nlend = 1;
	while( fgets(line,sizeof(line),in) != NULL ){
		nlend = strtailchr(line) == '\n';
		if( line[0] == '.' && (line[1] == '\r' || line[1] == '\n') )
			break;
		fputs(line,out);
		cc += strlen(line);
	}
	if( anl && !nlend ){
		sv1log("DATA ended without LF: size=%d\n",cc);
		fputs("\r\n",out);
	}
	if( eom ){
		fputs(".\r\n",out);
	}
	return cc;
}

int sendmail1X(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log);
void sendmail1(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log)
{
	sendmail1X(Conn,to,from,afp,log);
}
int sendmail1X(Connection *Conn,PCStr(to),PCStr(from),FILE *afp,FILE *log)
{	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	FILE *fpv[2]; /**/
	int port;
	int cc;
	IStr(resp,0x1000);

	hostport[0] = 0;
	if( DELEGATE_SMTPSERVER && DELEGATE_SMTPSERVER[0] )
		strcpy(hostport,DELEGATE_SMTPSERVER);
	else	Xsscanf(to,"%*[^@]@%s",AVStr(hostport));
	if( hostport[0] == 0 )
		strcpy(host,"localhost");

	port = scan_hostport("smtp",hostport,AVStr(host));
	Conn->from_myself = 1;

	if( SMTP_post(host,port,myver(),to,from,afp,AVStr(resp),sizeof(resp)) != 0 ){
		return 0;
	}
    if( log != NULL ){ /* v9.9.13 fix-141028b */
	if( resp[0] == 0 ){
		fprintf(log,"Failed connection to mail exchanger of '%s'",host);
	}
	fflush(log);
    }
	/*
	if( SMTP_post(host,port,myver(),to,from,afp,VStrNULL,0) != 0 )
		return;
	*/

	/* the following code is obsolete and will not be used ... */

	if( SMTP_open(Conn,fpv,host,port,to,from,1,log) < 0 ){
		fprintf(stderr,"COULD NOT OPEN %s:%d\n",host,port);
		return -1;
		/*
		return;
		*/
	}
	cc = relayMSGdata(afp,fpv[1],1,1);
	fflush(fpv[1]);
	if( 0 < fPollIn(fpv[0],1000) )
		SMTP_relay_stat(fpv[0],NULL,VStrNULL);
	fprintf(fpv[1],"QUIT\r\n");
	fflush(fpv[1]);
	if( 0 < fPollIn(fpv[0],1000) )
		SMTP_relay_stat(fpv[0],NULL,VStrNULL);
	fclose(fpv[1]);
	fclose(fpv[0]);
	return 0;
}

#endif /* !LIBRARY */
