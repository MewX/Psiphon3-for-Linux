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
#include "delegate.h"
#include "fpoll.h"
#include "file.h"
#include "http.h"
#include "param.h"

void service_httpX(Connection *Conn);
int HTTP_relay_response(Connection *Conn,int cpid,PCStr(proto),PCStr(server),int iport,PCStr(req),PCStr(acpath),int fromcache, FILE *afs,FILE *atc,FILE *afc,FILE *acachefp,int cache_rdok);
void logReject(Connection *Conn,int self,PCStr(shost),int sport);
void delayReject(Connection *Conn,int self,PCStr(method),PCStr(sproto),PCStr(shost),int sport,PCStr(dpath),PCStr(referer),PCStr(reason));

int service_http(Connection *Conn)
{
	service_httpX(Conn);
	return 0;
}

int isinSSL(int fd);
int service_https(Connection *Conn)
{
	/* 9.2.4 relaying bare HTTPS/SSL as a "Generalist" without "CONNECT" */
	if( (ClientFlags & PF_MITM_DO) == 0 )
	if( ImMaster )
	if( PollIn(FromC,1000) <= 0 ){
		sv1log("No SSL detected in MASTER for HTTPS/SSL\n");
	}else
	if( isinSSL(FromC) ){
		connect_to_serv(Conn,FromC,ToC,0);
		sv1log("Bare HTTPS/SSL non-MITM %X %X %s:%d[%d]\n",
			ClientFlags,ServerFlags,DFLT_HOST,DFLT_PORT,ToS);
	}

	if( 0 <= ToS )
		relay_svcl(Conn,FromC,ToC,FromS,ToS);
	else	service_http(Conn);
	return 0;
}

int setupFTPxHTTP(Connection *Conn){
	GatewayFlags = GW_FTPXHTTP;
	if( strncaseeq(CLNT_PROTO,"ftpxhttp",8) )
		ovstrcpy(CLNT_PROTO,CLNT_PROTO+4);
	return 0;
}
int service_ftpxhttp(Connection *Conn){
	setupFTPxHTTP(Conn);
	service_http(Conn);
	return 0;
}
int service_ftpxhttps(Connection *Conn){
	setupFTPxHTTP(Conn);
	/* implicit STLS=fcl,im */
	service_https(Conn);
	return 0;
}

static void sendHttpResponse(Connection *Conn,FILE *in,FILE *out,PCStr(req))
{	CStr(myhost,128);
	int myport;

	if( !lSINGLEP() ){
		if( !INHERENT_fork() || lEXECFILTER() ){
			DELEGATE_scanEnv(Conn,P_HTTPCONF,scan_HTTPCONF);
		}
	}
	ProcTitle(Conn,"RFilter-%d",getppid());
	if( DONT_REWRITE ){
		strcpy(myhost,MYSELF);
		myport = 0;
	}else{	
		/*
		myport = ClientIF_H(Conn,myhost);
		*/
		myport = HTTP_ClientIF_H(Conn,AVStr(myhost));
	}
	ImResponseFilter = 1;
	CONN_DONE = CONN_START = Time();
	HTTP_relay_response(Conn,0,CLNT_PROTO,myhost,myport,req,NULL,0,
		in,out,NULL,NULL,0);
}
FILE *openHttpResponseFilter(Connection *Conn,FILE *tc)
{
	sv1log("## openHttpResponseFilter: clnt=%d will=%d chunk=%d\n",
		ClntKeepAlive,WillKeepAlive,ClntAccChunk);
	if( !ClntAccChunk ){
		/* URLs (in /-/ page for example) may be rewriten in the filter
		 * without correcting Content-Length
		 */
		HTTP_clntClose(Conn,"x:response filter");
	}
	else{
		checkTobeKeptAlive(Conn,"ResponseFilter");
	}

	Conn->fi_builtin = 1;
	return openFilter(Conn,"HttpResponseFilter",(iFUNCP)sendHttpResponse,tc,OREQ);
}
int HTTP_relayThru(Connection *Conn)
{
	return DONT_REWRITE
		&& !CTX_cur_codeconvCL(Conn,VStrNULL) && !CCXactive(CCX_TOCL);

		/* HTTPCONF=add-[qr]head must be checked too... */
}
int service_file(Connection *Conn)
{
	sv1log("access to file ... \n");
	return -1;
}
const char *getUA(Connection *Conn){
	if( Conn == 0 )
		return 0;
	if( CurEnv == 0 )
		return 0;
	return REQ_UA;
}

static const char *URLgetURL;
const char *getURLgetURL(){
	return URLgetURL;
}

int CTX_depthExceed(Connection *Conn){ /* v9.9.12 fix-140814c */
	return ConnDepth.cd_overflow;
}
int CTX_depthPeak(Connection *Conn){
	return ConnDepth.cd_peekdepth;
}
extern unsigned int STACK_SIZE;
extern char *STACK_BASE;

/* v9.9.11 fix-140810a, v9.9.12 fix-140814b */
static FILE* StackTooDeep(Connection *Conn,PCStr(url),FILE* out,int rd){
	unsigned int depth1siz; /* estimated size consumed per recursion */
	unsigned int stackpeak; /* estimated peak in the next recursion */
	int off; /* offset of the HTTP body in the out */
	IStr(stime,128);
	IStr(ourl,URLSZ);
	IStr(lkey,64);
	IStr(emsg,2048);

	if( ConnDepth.cd_prevConn == 0 ){
		ConnDepth.cd_prevConn = Conn;
		return 0;
	}
	depth1siz = ((Int64)ConnDepth.cd_prevConn) - ((Int64)Conn) + 512*1024;
	ConnDepth.cd_prevConn = Conn;

	stackpeak = ((Int64)STACK_BASE) - ((Int64)Conn); /* current peak */
	stackpeak += depth1siz; /* add estimated consumption */
	if( STACK_SIZE == 0 ){
		STACK_SIZE = 4*1024*1024;
		/* small enough, maybe 8MB is the smallest nowadays */
	}
	if( stackpeak < STACK_SIZE ){
		return 0;
	}
	sprintf(lkey,"%X",time(0));
	if( CurEnv == 0 ){
		strcpy(ourl,"(CantGetOriginalURL)"); /* maybe from -Fany2fdif */
	}else{
		HTTP_originalURLx(Conn,AVStr(ourl),sizeof(ourl));
	}

	sprintf(emsg,
"## Stack too deep [KEY=%s] depth=%d+%d consume=%X peak=%X > max=%X {%s -> %s}",
		lkey,ConnDepth.cd_curdepth,rd,depth1siz,stackpeak,STACK_SIZE,
		ourl,url);

	/*
	 * v9.9.12 new-140825c, daemonlog() can consume so much stack to cause
	 * SEGV, thus it should be doen after stack is shrinked.
	daemonlog("F","%s\n",emsg);
	 */
	strcpy(Conn->reject_reason,emsg);
	ConnDepth.cd_putlog = 1;

	if( isatty(fileno(stderr)) ){
		fprintf(stderr,"%s\n",emsg);
	}

	ConnDepth.cd_overflow += 1;
	fprintf(out,"HTTP/1.0 500 Internal Error KEY=%X\r\n",lkey);
	fprintf(out,"Content-Type: text/plain\r\n");
	fprintf(out,"\r\n");
	off = ftell(out);
	StrfTimeLocal(AVStr(stime),sizeof(stime),"%m/%d-%H:%M:%S%.2s",Time());
	if( GatewayFlags & GW_SSI_INCLUDE ){
		fprintf(out,
"(INTERNAL-ERROR-SEE-LOGFILE-AROUND-%s-WITH-KEY=%s)\n",stime,lkey);
	}else{
		fprintf(out,
"## SSI incldue failure: see the ERRORLOG and LOGFILE\n## around %s with KEY=%s\n",
		stime,lkey);
	}
	fflush(out);
	fseek(out,off,0);
	return out;
}
/* v9.9.12 new-140818j */
static int putError(Connection *Conn,PCStr(url),int code,PCStr(resp),FILE *out){
	int off;
	IStr(lkey,128);
	IStr(stime,128);
	IStr(emsg,2048);
	const char *ua = "";

	if( (GatewayFlags & (GW_SSI_INCLUDE|GW_GET_ERRRESP)) == 0 )
		return 0;

	if( GatewayFlags & GW_SSI_INCLUDE )
		ua = "SSI-include";
	else	ua = "DeleGate";

	sprintf(lkey,"%X",time(0));
	StrfTimeLocal(AVStr(stime),sizeof(stime),"%m/%d-%H:%M:%S%.2s",Time());

	if( code == 401 || code == 403 ){
		sprintf(emsg,
"## %s failed with code=%d url=\"%s\" KEY=%s, add necessary RELAY=ssi, PERMIT, \
MOUNT, or so if the access should be permitted ##",ua,code,url,lkey);
	}else{
		sprintf(emsg,
"## %s failed with code=%d url=\"%s\" KEY=%s ##",ua,code,url,lkey);
	}
	daemonlog("E","%s\n",emsg);
	if( isatty(fileno(stderr)) ){
		fprintf(stderr,"%s\n",emsg);
	}

	fseek(out,0,0);
	fprintf(out,"HTTP/1.0 %d Error KEY=%X\r\n",code,lkey);
	fprintf(out,"Content-Type: text/plain\r\n");
	fprintf(out,"\r\n");
	off = ftell(out);
	fprintf(out,
"(INTERNAL-ERROR-SEE-LOGFILE-AROUND-%s-WITH-KEY=%s)",stime,lkey);
	Ftruncate(out,0,1);
	fseek(out,off,0);

	return 1;
}

int isHTTP(PCStr(proto));
int encDecrypt(PCStr(estr),PVStr(dconf),int dsize);
FILE * CTX_URLgetX(Connection *OrigConn,int origctx,PCStr(url),int reload,FILE *out,int rd)
{	Connection ConnBuf,*Conn = &ConnBuf;
	CStr(req,1024);
	refQStr(rp,req); /**/
	CStr(resp,1024);
	CStr(genauth,512);
	int io[2];
	FILE *aout;
	HttpResponse resx;
	IStr(proto,128);
	IStr(hostport,MaxHostNameLen);
	IStr(upath,URLSZ);

	if( URLgetURL )
		free((char*)URLgetURL);
	URLgetURL = strdup(url);

	aout = out;
	if( out == NULL )
		out = TMPFILE("CTX_URLget");

	decomp_absurl(url,AVStr(proto),AVStr(hostport),AVStr(upath),sizeof(upath));
	if( strheadstrX(url,"enc:",0) ){
		CStr(dstr,64*1024);
		int dlen;
		dlen = encDecrypt(url+4,AVStr(dstr),sizeof(dstr));
		if( dlen < 0 )
			return NULL;
		fwrite(dstr,1,dlen,out);
		fflush(out);
		Ftruncate(out,0,1);
		fseek(out,0,0);
		return out;
	}else
	if( strncasecmp(url,"file:",5) == 0 )
	if( !isExecutableURL(url) ){
		FILE *fp;
		CStr(host,128);
		char *path; /**/

		path = file_hostpath(url,VStrNULL,AVStr(host));
		nonxalpha_unescape(path,ZVStr(path,strlen(path)+1),1);
		if( *path == '/' && isFullpath(path+1) )
			path++;

		if( fp = fopen(path,"r") ){
			copyfile1(fp,out);
			fclose(fp);
			fflush(out);
			Ftruncate(out,0,1);
			fseek(out,0,0);
			return out;
		}
		if( aout == NULL && out != NULL )
			fclose(out);
		return NULL;
	}
	if( strncasecmp(url,"data:",5) == 0 ){
		HTTP_putData(OrigConn,out,0,url+5);
		fflush(out);
		Ftruncate(out,0,1);
		fseek(out,0,0);
		return out;
	}
	if( strncasecmp(url,"builtin:",8) == 0 ){
		const char *data;
		int leng;

		sprintf(req,"builtin/%s",url+8);
		data = getMssg(req,&leng);
		if( data == NULL )
			return NULL;
/*
 * eval. if with ".dhtml" extension.
 * on each request based on conditional info.
 */
		fwrite(data,1,leng,out);
		fflush(out);
		Ftruncate(out,0,1);
		fseek(out,0,0);
		return out;
	}

	if( OrigConn && origctx ){
		if( StackTooDeep(OrigConn,url,out,rd) ){ /* v9.9.11 fix-140810a */
			return out;
		}
		ConnCopy(Conn,OrigConn);
		if( EmiActive(OrigConn) ){
			Conn->md_in = OrigConn->md_in;
		}
		ClntKeepAlive = 0;
		WillKeepAlive = 0;
		ToMyself = 0;
		Conn->sv_dflt = OrigConn->sv_dfltsav;
		bzero(&Conn->sv,sizeof(Conn->sv));
		ToS = ToSX = -1;
		/* maybe this is necessary...
		 * yes. these flags must be cleared not to activate
		 * WaitShutdown() to wait processes which are not the children
		 * of this URLget() when called by SSI/SHTML for "#include"
		 */
		Conn->xf_filters = 0;
		Conn->fi_builtin = 0;
		Conn->xf_clprocs = 0;
	}else{
		Conn->cx_magic = 0;
		ConnInit(Conn);
		Conn->from_myself = 1;
		if( lCOPYCLADDR() ) /* should be the default */
		if( OrigConn ){
			Conn->cl_peerAddr = OrigConn->cl_peerAddr;
			sv1log("URLget: copy the client addr [%s:%d]\n",
				Client_Host,Client_Port);
		}
	}
	ACT_SPECIALIST = 1;
	GatewayFlags |= (GW_DONT_SHUT | GW_DONT_FTOCL);

	if( OrigConn ){
		ClientSock = OrigConn->cl_sockFd;
		/*
		Conn->oc_isset = 1;
		Conn->oc_norewrite = OrigConn->oc_norewrite;
		strcpy(Conn->oc_proxy,OrigConn->oc_proxy);
		strcpy(Conn->oc_proto,OrigConn->oc_proto);
		*/
		Conn->mo_options = OrigConn->mo_optionsX;
		Conn->dg_urlcrc = OrigConn->dg_urlcrc;
		Conn->io_timeout = OrigConn->io_timeout;

		Conn->req_flags = OrigConn->req_flags;
		if( OrigConn->req_flags & QF_AUTH_FORW ){
			Conn->cl_auth = OrigConn->cl_auth;
		}
		strcpy(Conn->cl_expire,OrigConn->cl_expire);
	}

	Socketpair(io);
	FromC = io[0];
	ToC = dup(fileno(out));

	if( OrigConn != 0 && (OrigConn->req_flags & QF_URLGET_HEAD) ){
		rp = Sprintf(AVStr(req),"HEAD %s HTTP/1.0\r\n",url);
	}else
	rp = Sprintf(AVStr(req),"GET %s HTTP/1.0\r\n",url);

	/* v9.9.10 fix-140720b this is NG for forwarding and logging
	 * the original User-Agent at least for SSI #include
	rp = Sprintf(AVStr(rp),"User-Agent: DeleGate/%s\r\n",DELEGATE_ver());
	 */
	if( OrigConn && origctx && getUA(OrigConn) ){
		/* - should do appendVia() ?
		 * - should add Referer: of the base SHTML ?
		 * - sending original User-Agent is desirable to generate
		 *   customized data for the User-Agent at the "virtual=" server.
		 */
		rp = Sprintf(AVStr(rp),"User-Agent: %s\r\n",getUA(OrigConn));
	}else{
		/* should be "DeleGate/VER (include)" or so ? */
		rp = Sprintf(AVStr(rp),"User-Agent: DeleGate/%s\r\n",DELEGATE_ver());
	}

	if( reload )
		rp = Sprintf(AVStr(rp),"Pragma: no-cache\r\n");

	if( makeAuthorization(Conn,AVStr(genauth),0) ){
		sv1log("## GEN Authorization...\n");
		rp = Sprintf(AVStr(rp),"Authorization: %s\r\n",genauth);
	}
	else
	if( strneq(url,"file:",5) || URL_toMyself(Conn,url) )
	if( ClientAuthUser[0] ){
		/* to use ClientAuth in makeAuthorization() */
		ClientAuth.i_stat = AUTH_FORW;
		if( makeAuthorization(Conn,AVStr(genauth),0) ){
			sv1log("## RELAY Authorization[%s]\n",ClientAuthUser);
			rp = Sprintf(AVStr(rp),"Authorization: %s\r\n",genauth);
		}
	}
	if( strneq(url,"file:",5) ){
		/* bypass access control for reqest for SSI #include file: */
		IsMounted = 1;
	}

	if( isFullURL(url) && isHTTP(proto) /* v9.9.12 fix-140820g */
	 && (GatewayFlags & GW_SSI_INCLUDE) /* might be unconditionally */
	){
		sv1log("##SSI insert Host: %s\n",hostport);
		rp = Sprintf(AVStr(rp),"Host: %s\r\n",hostport);
		/* full-url should be partialized stripping http:://hostport */
		/* should do insert STLS=fsv for proto=https */
	}else
	if( CurEnv && OREQ_VHOST[0] ){
		/* to make absolute-URL in response for SSI #include http: */
		rp = Sprintf(AVStr(rp),"Host: %s\r\n",OREQ_VHOST);
	}
	strcpy(rp,"\r\n");

	if( OrigConn && origctx ){
		int curdepth = ConnDepth.cd_curdepth;
		ConnDepth.cd_curdepth += 1;
		if( OrigConn->co_depth.cd_peekdepth < curdepth ){
			OrigConn->co_depth.cd_peekdepth = curdepth;
		}
	}

	DDI_pushCbuf(Conn,req,strlen(req));
	service_http(Conn);

	if( OrigConn && origctx ){
		int peekdepth = ConnDepth.cd_peekdepth;
		ConnDepth.cd_curdepth -= 1;
		if( OrigConn->co_depth.cd_peekdepth < peekdepth ){
			OrigConn->co_depth.cd_peekdepth = peekdepth;
		}
		if( ConnDepth.cd_putlog ){
			daemonlog("F","%s\n",Conn->reject_reason);
		}
		OrigConn->co_depth.cd_overflow +=
			ConnDepth.cd_overflow; /* v9.9.12 fix-140814c */
	}

	fflush(out);
	Ftruncate(out,0,1);
	fseek(out,0,0);

	if( OrigConn ){
		if( EmiActive(Conn) ){
			OrigConn->md_in = Conn->md_in;
		}
	}

	if( fgets(resp,sizeof(resp),out) != NULL ){
		if( strncmp(resp,F_HTTPVER,F_HTTPVERLEN) == 0 ){
			int code;
			code = decomp_http_status(resp,&resx);
			/*
			if( code == 301 || code == 302 ){
			*/
			if( OrigConn && (OrigConn->req_flags & QF_URLGET_RAW) ){
				fseek(out,0,0);
			}else
			if( code == 301 || code == 302 || code == 303 ){
			  CStr(loc,1024);
			  if( 3 < ++rd ){
				sv1log("URLget(%d) too many redirection\n",rd);
				goto xERROR;
			  }else
			  if( fgetsHeaderField(out,"Location",AVStr(loc),sizeof(loc)) )
			  {
				const char *dp;
				FILE *rfp;
				int off;
				if( dp = strpbrk(loc,"\r\n") )
					truncVStr(dp);
				if( loc[0] == '/' ){
					CStr(xurl,URLSZ);
					sprintf(xurl,"%s://%s:%d%s",DST_PROTO,
						DST_HOST,DST_PORT,loc);
					strcpy(loc,xurl);
				}
				fflush(out);
				Ftruncate(out,0,0);
				fseek(out,0,0);
				sv1log("URLget(%d,%s)\n",rd,loc);
				rfp = fdopen(fileno(out),"r+");
				CTX_URLgetX(OrigConn,origctx,loc,reload,rfp,rd);
				off = ftell(rfp);
				fcloseFILE(rfp);
				fseek(out,off,0);
			  }
			}else
			if( OrigConn && (OrigConn->req_flags & QF_URLGET_THRU) ){
				fseek(out,0,0);
			}else
			if( code != 200 ){
		xERROR:
				fflush(out);
				Ftruncate(out,0,0);
				fseek(out,0,0);
				fgetc(out); /* set EOF to indicate error */
				sv1log("error: %s",resp);
				if( OrigConn && origctx ){
					putError(OrigConn,url,code,resp,out);
				}
			}else{
				while( fgets(resp,sizeof(resp),out) != NULL )
					if( resp[0] == '\r' || resp[0] == '\n' )
						break;
			}
		}else{
			fseek(out,0,0);
		}
	}

	close(io[0]);
	close(io[1]);

	return out;
}
FILE * CTX_URLget(Connection *OrigConn,int origctx,PCStr(url),int reload,FILE *out)
{
	return CTX_URLgetX(OrigConn,origctx,url,reload,out,0);
}
FILE * URLget(PCStr(url),int reload,FILE *out)
{
	return CTX_URLget(NULL,0,url,reload,out);
}
FILE * VA_URLget(Connection *Conn,VAddr *vaddr,PCStr(url),int reload,FILE *out){
	*Client_VAddr = *vaddr;
	Conn->cl_sockHOST = *vaddr;
	ClientSock = CLNT_NO_SOCK;
	GatewayFlags |= GW_GET_ERRRESP;
	Conn->from_myself = 1;
	return CTX_URLget(Conn,1,url,reload,out);
}

extern const char *TIMEFORM_RFC822;
void putFileInHTTP(FILE *tc,PCStr(path),PCStr(file))
{	FILE *fp;
	int size,mtime;
	CStr(sdate,1024);

	fp = fopen(path,"r");
	if( fp == NULL ){
		fprintf(tc,"HTTP/1.0 404 not found\r\n");
		return;
	}
	size = file_size(fileno(fp));
	mtime = file_mtime(fileno(fp));
	StrftimeGMT(AVStr(sdate),sizeof(sdate),TIMEFORM_RFC822,mtime,0);

	fprintf(tc,"HTTP/1.0 200 OK\r\n");
	fprintf(tc,"MIME-Version: 1.0\r\n");
	fprintf(tc,"Content-Type: application/octet-stream\r\n");
	fprintf(tc,"Content-Transfer-Encoding: base64\r\n");
	fprintf(tc,"Content-Length: %d\r\n",size);
	fprintf(tc,"Last-Modified: %s\r\n",sdate);
	fprintf(tc,"\r\n");
	MIME_to64(fp,tc);
	fclose(fp);
}

void HTTP_delayReject(Connection *Conn,PCStr(req),PCStr(stat),int self)
{	const char *method;
	const char *url;
	HttpRequest reqx;
	CStr(path,URLSZ);
	CStr(referer,URLSZ);
	CStr(shost,MaxHostNameLen);
	int sport;

	decomp_http_request(req,&reqx);
	method = reqx.hq_method;
	url = reqx.hq_url;

	path[0] = 0;
	decomp_absurl(url,VStrNULL,VStrNULL,AVStr(path),sizeof(path));
	HTTP_getRequestField(Conn,"Referer",AVStr(referer),sizeof(referer));

	self |= DO_DELEGATE || IsMounted || IAM_GATEWAY;
	sport = getClientHostPort(Conn,AVStr(shost));
	logReject(Conn,self,shost,sport);
	delayReject(Conn,self,method,DFLT_PROTO,shost,sport,path,referer,stat);
}
void HTTP_delayCantConn(Connection *Conn,PCStr(req),PCStr(stat),int self)
{	CStr(method,64);
	CStr(shost,MaxHostNameLen);
	int sport;

	wordScan(req,method);

	self |= DO_DELEGATE || IsMounted || IAM_GATEWAY;
	sport = getClientHostPort(Conn,AVStr(shost));
	delayReject(Conn,self,method,DFLT_PROTO,shost,sport,"","",stat);
}
