/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	http.h
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970708	extracted from httpd.c
//////////////////////////////////////////////////////////////////////#*/

#include "url.h"

#define OBUFSIZE	URLSZ
#define IBUFSIZE	URLSZ
#define SOCKBUFSIZE	URLSZ
#define RESP_LINEBUFSZ	(URLSZ*4)

#define MY_HTTPVER	"1.1"
#define MY_MIMEVER	"1.0"

#define ME_7bit		((char*)0)
#define ME_binary	"binary"

#define R_BEFORE_RESPONSE	-10000
#define R_EMPTY_RESPONSE	-10001
#define R_UNSATISFIED		-10002
#define R_UNSATISFIED_TEXT	-10003
#define R_NONTEXT_INTEXT	-10004
#define R_GENERATED		-10005
#define R_MOVED_LOOP		-10006
#define R_BROKEN_RESPONSE	-10007
#define R_PRIVATE		-10008
#define R_BAD_MD5		-10009
#define R_BAD_FORMAT		-10010
#define R_TRUNCATED		-10011 /* truncated by disconn. by client */

#define EMPTYBODY_SIZE		-2

/*
 * result status in the logfile
 */
#define CS_AUTHERR	'A'
#define CS_BADREQUEST	'B'	/* illegal request */
#define CS_CONNERR	'C'
#define CS_ERROR	'E'
#define CS_EOF  	'P'	/* abort on premature disconnection */
#define CS_REQTIMEOUT	'Q'	/* timeout in request */
#define CS_TIMEOUT	'T'	/* timeout while waiting response */

/* normal response */
#define CS_HITCACHE	'H'
#define CS_INTERNAL	'I'
#define CS_LOCAL	'L'	/* local file (or CGI,SSI) */
#define CS_MAKESHIFT	'M'	/* connection failed and make shift */
#define CS_NEW		'N'	/* got first (not found) */
#define CS_OBSOLETE	'O'	/* obsolete (modified) */
#define CS_RELOAD	'R'	/* reload (Pragma: no-cache) */
#define CS_STABLE	'S'	/* stable (not modified) */
#define CS_WITHOUTC	'W'	/* without cache */

typedef struct _HttpRequest {
	MStr(	hq_method,32);
	MStr(	hq_url,URLSZ);
	MStr(	hq_ver,32);
	int	hq_vno;
	int	hq_flags;
} HttpRequest;
#define HQF_ISPROXY	1

typedef struct {
	MStr(	hr_ver,256);		/* HTTP version */
	int	hr_rcode;		/* status code */
	MStr(	hr_reason,256);		/* reason */
	char	hr_isHTTP09;		/* before HTTP/1.0 */
} HttpResponse;

typedef struct {
	int	r_code;
	int	r_sav; /* if true, save the response message into r_msg[] */
	UTag	r_msg;
	int	r_len;
	FILE   *r_msgfp; /* if the response message is larger than r_msg */
} HtResp;

/* persistent during keep-alive with a client */
typedef struct {
	int	r_withNTHT;	/* NTLM over HTTP (RFC4559) */
	void   *r_utoken;	/* identifire of the client user */
	MStr(	r_user,128);	/* user and domain on Windows */
	MStr(	r_nego,512);	/* WWW-Authenticate: Negotiation value */
} HTTP_env0;

typedef struct {
	MStr(	r_oreqmsg,0x8000); /* original request message */
	int	r_oreqlen;
	int	r_oreqbodyoff;

	MStr(	r_oreq,URLSZ);	/* original request line */
	UTag	r_ohost;	/* original server host */
	int	r_oport;	/* original server port */
	MStr(	r_vhost,256);	/* original Host: field */
	MStr(	r_UserAgent,256);
       AuthInfo r_reqAuth;
	MStr(	r_svReqAtyp,16);

	int	r_badRequest;
	int	r_normalized;
	int	r_checkServ;
	int	r_waitServ;
	int	r_badServ;
	MStr(	r_badServResponse,128);
	MStr(	r_badServDetected,32);
	MStr(	r_req,URLSZ);	/* HTTP request possibly rewritten */
 HttpRequest	r_reqx;		/* decomposed r_req */

	MStr(	r_fields,0x8000);
  const	char   *r_lastFname;	/* cache for getRequestField */
  const	char   *r_lastFbody;	/* (pointers into f_fields) */

	UTag	r_acclangs;	/* merged list of Accept-Language for log */

	MStr(	r_clntIfmod,256); /* If-Mod-Since from the  client */
	int	r_clntIfmodClock; /* its value in int */

	int	r_flushhead;
	int	r_flushsmall;

	int	r_withCookie;
	MStr(	r_dgCookie,256); /* Proxy-Cookie */
	int	r_appletFilter;

	int	r_clntAccChunk;
	MStr(	r_httpConn,128);
	int	r_get_cache;
	MStr(	r_iconBase,256);	
	HtResp	r_resp;
	MStr(	r_resp_add,256);
	int	r_reqAsis;
	int	r_doUnzip;
	int	r_doZip;
	MStr(	r_accEnc,128); /* Accept-Encoding filed */

	int	r_NOJAVA;

  const char   *r_FTOCL; /* saved uncoditional FTOCL */
	UTag	r_o_buff; /* for stdio */
	UTag	r_i_buff;
	UTag	r_savConn;

	HTTP_env0 r_env0;
} HTTP_env00;
#define HTTP_env HTTP_env00

#define CurEnv		((HTTP_env*)Conn->cl_reqbuf)

#define OREQ_MSG	CurEnv->r_oreqmsg
/**/
#define OREQ_LEN	CurEnv->r_oreqlen
#define OREQ_BODYOFF	CurEnv->r_oreqbodyoff

#define OREQ		CurEnv->r_oreq
/**/
#define OREQ_HOST	CurEnv->r_ohost.ut_addr
/**/
#define OREQ_HOST_SIZ	CurEnv->r_ohost.ut_size
#define OREQ_PORT	CurEnv->r_oport
#define OREQ_VHOST	CurEnv->r_vhost
/**/
#define REQ_UA		CurEnv->r_UserAgent
#define REQ_AUTH	CurEnv->r_reqAuth
#define SVREQ_ATYP	CurEnv->r_svReqAtyp
/**/

#define REQ		CurEnv->r_req
/**/
#define REQ_FIELDS	CurEnv->r_fields
/**/
#define REQX		CurEnv->r_reqx
#define REQ_METHOD	CurEnv->r_reqx.hq_method
/**/
#define REQ_URL		CurEnv->r_reqx.hq_url
#define REQ_VER		CurEnv->r_reqx.hq_ver
#define REQ_VNO		CurEnv->r_reqx.hq_vno
#define REQ_FLAGS	CurEnv->r_reqx.hq_flags

#define BadRequest	CurEnv->r_badRequest
#define Normalized	CurEnv->r_normalized
#define CheckServ	CurEnv->r_checkServ
#define WaitServ	CurEnv->r_waitServ
#define BadServ		CurEnv->r_badServ
#define BadServResponse	CurEnv->r_badServResponse
#define BadServDetected	CurEnv->r_badServDetected

#define AcceptLanguages	CurEnv->r_acclangs.ut_addr
/**/

#define FlushHead	CurEnv->r_flushhead
#define FlushIfSmall	CurEnv->r_flushsmall

#define ClntIfMod	CurEnv->r_clntIfmod
/**/
#define ClntIfModClock	CurEnv->r_clntIfmodClock

#define withNTHT	CurEnv->r_env0.r_withNTHT
#define NTHT_utoken	CurEnv->r_env0.r_utoken
#define NTHT_user	CurEnv->r_env0.r_user
#define NTHT_nego	CurEnv->r_env0.r_nego

#define NTHT_REQNTLM	0x0001
#define NTHT_REQNEGO	0x0002
#define NTHT_REQ	0x0003
#define NTHT_CLNTKA	0x0004
#define NTHT_RESNTLM	0x0010
#define NTHT_RESNEGO	0x0020
#define NTHT_RES	0x0030
#define NTHT_SERVKA	0x0040
#define NTHT_START	0x0080
#define NTHT_REPEAT	0x0100
#define NTHT_CLAUTHOK	0x1000
#define NTHT_SVAUTHOK	0x2000
#define NTHT_CLBASIC	0x4000
#define NTHT_CLNTHT	0x8000
#define NTHT_REQRES	(NTHT_REQ|NTHT_RES)

int NTHT_accept(int asproxy,int tocl,int fromcl,PCStr(reql),PCStr(head),PVStr(user),void **utoken);
int NTHT_connect(int toproxy,int ts,int fs,PCStr(req),PCStr(head),PCStr(user),PCStr(pass),void *utoken,PCStr(chal));

#define withCookie	CurEnv->r_withCookie
#define appletFilter	CurEnv->r_appletFilter
#define proxyCookie	CurEnv->r_dgCookie

#define iconBase	CurEnv->r_iconBase
#define GET_CACHE	CurEnv->r_get_cache
#define ClntAccChunk	CurEnv->r_clntAccChunk
#define httpConn	CurEnv->r_httpConn
/**/

#define RespCode	CurEnv->r_resp.r_code
#define RESP_SAV	CurEnv->r_resp.r_sav
#define RESP_MSG	CurEnv->r_resp.r_msg.ut_addr
/**/
#define RESP_SIZ	CurEnv->r_resp.r_msg.ut_size
#define RESP_LEN	CurEnv->r_resp.r_len
#define RESP_MSGFP	CurEnv->r_resp.r_msgfp
#define RESP_ADD	CurEnv->r_resp_add
/**/
#define RESP_DoUNZIP	CurEnv->r_doUnzip
#define RESP_DoZIP	CurEnv->r_doZip
#define REQ_AccEnc	CurEnv->r_accEnc
#define REQ_ASIS	CurEnv->r_reqAsis

#define NOJAVA		CurEnv->r_NOJAVA
#define sav_FTOCL	CurEnv->r_FTOCL

#define F_HTTPVER	"HTTP/"
#define F_HTTPVERLEN	sizeof(F_HTTPVER)-1
#define F_DGVer		"DeleGate-Ver:"
#define F_ContType	"Content-Type:"
#define F_CtypeText	"Content-Type: text"
#define F_CtypePlain	"Content-Type: text/plain"
#define F_CtypeHTML	"Content-Type: text/html"
#define F_ContEncode	"Content-Encoding:"
#define F_ContMD5	"Content-MD5:"
#define F_TransEncode	"Transfer-Encoding:"
#define F_ContLeng	"Content-Length:"
#define F_ContRange	"Content-Range:"
#define F_ContDisp	"Content-Disposition:"
#define F_Range		"Range:"
#define F_Location	"Location:"
#define F_ContLocation	"Content-Location:"
#define F_SetProxy	"Set-Proxy:"
#define F_LastMod	"Last-Modified:"
#define F_Etag		"Etag:"
#define F_Server	"Server:"
#define F_Cookie	"Cookie:"
#define F_SetCookie	"Set-Cookie:"
#define F_Connection	"Connection:"
#define F_PConnection	"Proxy-Connection:"
#define F_Upgrade	"Upgrade:"
#define F_CacheControl	"Cache-Control:"
#define F_Pragma	"Pragma:"
#define F_KeepAlive	"Keep-Alive:"
#define F_Via		"Via:"
#define F_Vary		"Vary:"
#define F_AccEncode	"Accept-Encoding:"
#define F_Expires	"Expires:"
#define F_Authenticate	"WWW-Authenticate:"
#define F_PAuthenticate	"Proxy-Authenticate:"

#define STRH(field,fname) \
	(strncasecmp(field,fname,sizeof(fname)-1)==0?sizeof(fname)-1:0)

#define STRH_Connection(field) ( \
	  STRH(field,F_Connection) ? STRH(field,F_Connection) \
	: STRH(field,F_PConnection) )

extern int HTTP11_toserver;
extern int HTTP11_toclient;
extern int HTTP09_reject;
extern int HTTP_ignoreIf;
extern int HTTP_warnApplet;
extern int HTTP_rejectBadHeader;
extern int HTTP_CKA_MAXREQ;
extern int HTTP_CKA_PERCLIENT;
extern int HTTP_MAXHOPS;
extern int HTTP_MAX_REQLINE;
extern int HTTP_MAX_REQHEAD;
extern int HTTP_GW_MAX_REQLINE;
extern const char *HTTP_MAX_REQLINE_sym;
extern const char *HTTP_MAX_REQHEAD_sym;
extern const char *HTTP_GW_MAX_REQLINE_sym;
extern const char *HTTP_urlesc;

extern double HTTP_TOUT_QBODY;
extern double HTTP_WAIT_REQBODY;
extern double HTTP_TOUT_IN_REQBODY;
extern double HTTP_TOUT_BUFF_REQBODY;
extern double HTTP_TOUT_BUFF_RESBODY;
extern double HTTP_TOUT_CKA;
extern double HTTP_TOUT_CKA_MARGIN;
extern double HTTP_TOUT_CKA_RESPLINE;
extern double HTTP_TOUT_RESPLINE;
extern double HTTP_WAIT_BADSERV;

#define CMAP_APPROVER "Approver"
extern int modwatch_enable;
extern const char *modwatch_notify;
extern int modwatch_approver;

#define KH_REQ	1
#define KH_RES	2
#define KH_BOTH	3
#define KH_IN	0x10
#define KH_OUT	0x20
#define KH_IO	0x30

#define CACHE_ANY	0x0FFFFFFF
#define CACHE_NOLASTMOD	0x0001
#define CACHE_NOCACHE	0x0002
#define CACHE_302	0x0004
#define CACHE_COOKIE	0x0008
#define CACHE_404	0x0010 /* unknown */
#define CACHE_VARY	0x0020
#define CACHE_SHORT	0x4000 /* even if incomplete */
#define CACHE_ANYVER	0x8000
#define CACHE_LESSRELD	0x00010000
#define CACHE_WITHAUTH	0x80000000

/* Keep-Alive options */
extern int HTCKA_opts;
#define HTCKA_REQWITHLENG	0x00000001
#define HTCKA_RESPNOLENG	0x00000002
#define HTCKA_POST		0x00000010
#define HTCKA_POSTPIPELINE	0x00000020

extern int HTCFI_opts;
#define HTCFI_THRU_304		0x00000001
#define HTCFI_GEN_304		0x00000002

extern int HTTP_CKA_CFI;
#define HTTP_DELWRONGCONTLENG	0x00000001
#define HTTP_NOCHUNKED		0x00000002
#define HTTP_SUPPCHUNKED	0x00000004
#define HTTP_FLUSHCHUNK		0x00000008
#define HTTP_NOKEEPALIVE	0x00000010
#define HTTP_NOMETHODCHECK	0x00000020
#define HTTP_NOGZIP		0x00000040
#define HTTP_LINEBYLINE		0x00000080
#define HTTP_NOKEEPALIVEPROXY	0x00000100
#define HTTP_FLUSH_PIPELINE	0x00000200
#define HTTP_NODGC_ROUTE	0x00000400
#define HTTP_DOAUTH_BYSOURCE	0x00000800 /* emulate the bug in old ver. */
#define HTTP_DOAUTHCONV		0x00001000
#define HTTP_AUTHBASIC_NEVER_SV	0x00002000
#define HTTP_AUTHBASIC_DELAY_SV	0x00004000
#define HTTP_FORCEBASIC_CL	0x00008000
#define HTTP_THRUDIGEST_CL	0x00010000
#define HTTP_SESSION		0x00020000
#define HTTP_NOPIPELINE		0x00040000
#define HTTP_NODELAY		0x00080000
#define HTTP_NOFLUSHCHUNK	0x00100000
#define HTTP_TOUTPACKINTVL	0x00200000
#define HTTP_NOKEEPALIVE_STLS	0x00400000
#define HTTP_DOKEEPALIVE_STLS	0x00800000
#define HTTP_DONT_REWRITE_PX	0x01000000
#define HTTP_DO_REWRITE_PX	0x02000000
#define HTTP_ADDCONTLENG	0x04000000
#define HTTP_DOPOLL_REQBODY	0x08000000 /* postpone conn. to the server */
#define HTTP_POSTPONE_REQHEAD	0x40000000 /* adjust req. head after rew. */
#define HTTP_REW_RHEAD		0x10000000 /* rewriting by add/kill-rhead */
#define HTTP_OLDCACHE		0x20000000
#define HTTP_DUMPSTAT		0x80000000

int HTTP_doKeepAliveWithSTLS(Connection *Conn);
#define doKeepAliveWithSTLS(Conn) HTTP_doKeepAliveWithSTLS(Conn)
void  setHTTPenv(Connection *Conn,HTTP_env *he);
void  resetHTTPenv(Connection *Conn,HTTP_env *he);

/*-- REQUEST */
int   HTTP_reqIsHTTP(Connection *Conn,PCStr(req));
int   HTTP_methodWithBody(PCStr(method));
int   HTTP_reqWithHeader(Connection *Conn,PCStr(req));
int   decomp_http_request(PCStr(req),HttpRequest *reqx);
int   HTTP_decompRequest(Connection *Conn);
int   HTTP_allowMethod1(Connection *Conn,PCStr(req));
int   HTTP_allowMethods(Connection *Conn,PVStr(methods));
void  HTTP_setMethods(PCStr(methods));
int   HTTP_originalURLx(Connection *Conn,PVStr(url),int siz);
char *HTTP_originalRequest(Connection *Conn,PVStr(req));
char *HTTP_originalRequestField(Connection *Conn,PCStr(f),PVStr(b),int z);
int   HTTP_originalURLPath(Connection *Conn,PVStr(path));
int   urlPath(PCStr(url),PVStr(path));
const char *HTTP_outCharset(Connection *Conn);
void  HTTP_scanAcceptCharcode(Connection *Conn,PVStr(field));
void  HTTP_getHost(Connection *Conn,PCStr(request),PCStr(fields));
void  HTTP_setHost(Connection *Conn,PVStr(fields));
int   decomp_http_status(PCStr(stat),HttpResponse *resx);

int   fromProxyClient(PCStr(url));
int   NotREACHABLE(Connection *Conn,PCStr(proto),PCStr(host),int port);
void  HTTP_delayReject(Connection *Conn,PCStr(req),PCStr(stat),int self);
void  HTTP_delayCantConn(Connection *Conn,PCStr(req),PCStr(stat),int self);

/*-- GENERATE RESPONSE */
int HTML_put1sY(DGCTX,FILE *fp,PCStr(fmt),PCStr(val));
int HTML_put1dY(DGCTX,FILE *fp,PCStr(fmt),int iv);
#define HTML_put1s(fp,fmt,val) HTML_put1sY(Conn,fp,fmt,val)
#define HTML_put1d(fp,fmt,iv)  HTML_put1dY(Conn,fp,fmt,iv)
int   putHEAD(Connection *Conn,FILE *tc,int code,PCStr(reason),PCStr(server),PCStr(ctype),PCStr(ccode),FileSize csize,int mtime,int expire);
int   putHttpHeader1X(Connection *Conn,FILE *tc,int vno,PCStr(server),PCStr(type),PCStr(encoding),FileSize  size,int mtime,int expire,PCStr(status));
FileSize putHttpMssg(Connection *Conn,FILE *dst,FILE *src,PCStr(req),int vno,PCStr(serv),PCStr(ctype),PCStr(cenc),FileSize leng,int mtime,int exp,PCStr(stat));
int   HTTP_putHeader(Connection *Conn,FILE *tc,int vno,PCStr(type),FileSize size,int mtime);
int   putSignedMD5(FILE *tc,PCStr(cmd5),PCStr(options));
int   verifySignedMD5(PCStr(head),PCStr(cmd5),PCStr(options));
int   HTTP_putData(Connection *Conn,FILE *tc,int vno,PCStr(dataspec));
int   HTTP_putDeleGateHeader(Connection *Conn,FILE *tc,int iscache);
int   putUpgrade(Connection *Conn,FILE *tc);
int   putMovedTo(Connection *Conn,FILE *tc,PCStr(url));
int   putMovedToX(Connection *Conn,FILE *tc,int code,PCStr(url));
int   putUnknownMsg(Connection *Conn,FILE *tc,PCStr(req));
int   putHttpRejectmsg(Connection *Conn,FILE *tc,PCStr(proto),PCStr(server),int iport,PVStr(req));
int   putHttpNotModified(Connection *Conn,FILE *tc);
int   putChangeProxy(Connection *Conn,FILE *tc,PCStr(url),PCStr(proxy));
int   putNotAuthorized(Connection *Conn,FILE *tc,PCStr(req),int proxy,PCStr(realm),PCStr(mssg));
int   putFrogVer(Connection *Conn,FILE *tc);
int   putHttpNotModified(Connection *Conn,FILE *tc);
int   putHttpNotFound(Connection *Conn,FILE *tc,PCStr(mssg));
int   putHttpNotAvailable(Connection *Conn,FILE *tc,PCStr(mssg));
int   putConfigError(Connection *Conn,FILE *tc,PCStr(mssg));
int   putHttpCantConnmsg(Connection *Conn,FILE *tc,PCStr(proto),PCStr(server),int iport,PCStr(req));

/*-- KEEP ALIVE */
int   aliveServ(Connection *Conn);
int   putServ(Connection *Conn,int tsfd,int fsfd);
int   getServ(Connection *Conn);
void  delServ(Connection *Conn,int tsfd,int fsfd);
int   putKeepAlive(Connection *Conn,FILE *tc);
void  setKeepAlive(Connection *Conn,int timeout);
void  HTTP_clntClose(Connection *Conn,PCStr(fmt),...);
void  HTTP_modifyConnection(Connection *Conn,int rlength);
int   checkTobeKeptAlive(Connection *Conn,PCStr(where));

/*-- MOUNT */
int   MountMoved(Connection *Conn,FILE *tc);
void  MountReferer(Connection *Conn,PVStr(fields));
int   MountSpecialResponse(Connection *Conn,FILE *tc);
int   isMovedToAnotherServer(Connection *Conn,PCStr(line));
int   isMovedToSelf(Connection *Conn,PCStr(line));
void  url_absoluteS(Referer *referer,PCStr(line),PVStr(xline),PVStr(rem));
int   url_partializeS(Referer *referer,PCStr(line),PVStr(xline));
void  HTTP_baseURLrelative(Connection *Conn,PCStr(path),PVStr(url));
int   MountRequestURL(Connection *Conn,PVStr(ourl));
int   HTTP_setRetry(Connection *Conn,PCStr(req),int rcode);
char *extbase(Connection *Conn,PVStr(xpath),PCStr(pfmt),...);

/*-- AUTH */
int   auth_proxy_auth();
int   auth_origin_auth();
int   auth_proxy_pauth();
int   HTTP_authuserpass(Connection *Conn,PVStr(auth),int size);
int   HTTP_getAuthorization(Connection *Conn,int proxy,AuthInfo *ident,int decomp);
int   HTTP_getAuthorization2(Connection *Conn,AuthInfo *ident,int decomp);
int   HTTP_forgedAuthorization(Connection *Conn,PCStr(fields));
int   HTTP_proxyAuthorized(Connection *Conn,PCStr(req),PCStr(fields),int pauth,FILE *tc);
int   HTTP_decompAuth(PCStr(auth),PVStr(atype),int atsiz,PVStr(aval),int avsiz);
int   HTTP_decompAuthX(PCStr(auth),PVStr(atype),int atsiz,PVStr(aval),int avsiz,AuthInfo *ident);
int   askDigestAuth(Connection *Conn,int forced_realm,PCStr(realm),PVStr(digest));
void  refreshDigestNonce(Connection *Conn,FILE *tc);
void  resetDigestInCookie(Connection *Conn,PVStr(field));
void  rewriteReqBasicToDigest(Connection *Conn,PVStr(fields));
void  scanDigestParams(PCStr(cp),AuthInfo *ident,PVStr(aval),int avsiz);
void  setDigestInCookie(Connection *Conn,AuthInfo *seed,PVStr(field));
void  genAuthDigest(Connection *Conn,PCStr(fname),PVStr(reqauth),int rsize,AuthInfo *seed,PCStr(user),PCStr(pass));

/*-- CACHE */
int   HTTP_ContLengOk(FILE *cachefp);
int   HTTP_selfExpired(FILE *cachefp);
int   makeDistribution(Connection *Conn,FILE *cachefp,PCStr(cpath));
FILE *recvDistribution(Connection *Conn,PCStr(cpath),int *updated);
int   sendDistribution(Connection *Conn,FILE *cachefp,FILE *fs,FILE *tc,PCStr(buff),int leng);
void  stopDistribution(Connection *Conn,FILE *cachefp,PCStr(cpath));
void  detachFile(FILE *fp);
int   HTTP_genLastMod(PVStr(scdate),int size,FILE *cachefp,PCStr(cpath));
int   HTTP_getLastMod(PVStr(scdate),int size,FILE *cachefp,PCStr(cpath));

/*-- COOKIE */
int   genSessionCookie(Connection *Conn,PVStr(field));
int   getDigestInCookie(PVStr(fields),AuthInfo *seed);
void  MountCookieRequest(Connection *Conn,PCStr(request),PVStr(value));
void  MountCookieResponse(Connection *Conn,PCStr(request),PVStr(value));

/*-- HEADER FIELD EDITING */
int   makeForwarded(Connection *Conn,PVStr(forwarded));
int   makeFrom(Connection *Conn,PVStr(genfrom));
int   HTTP_genVia(Connection *Conn,int isreq,PVStr(via));
int   HTTP_genhead(Connection *Conn,PVStr(head),int what);
int   HTTP_head2kill(PCStr(head),int what);
int   HTTP_killhead(PVStr(head),int what);
void  HTTP_delRequestField(Connection *Conn,PCStr(fname));
void  HTTP_editResponseHeader(Connection *Conn,FILE *tc);

/*-- ROBOTS */
int   reqRobotsTxt(Connection *Conn);
int   putRobotsTxt(Connection *Conn,FILE *tc,FILE *afp,int ismsg);

/*-- LOGGING */
void  http_logplus(Connection *Conn,char type);
void  http_Log(Connection *Conn,int rcode,int rstat,PCStr(req),int size);

/*-- GATEWAY */
void  connected_to_proxy(Connection *Conn,PCStr(req),int clsock);
void  add_localheader(Connection *Conn,int proxy);
void  getProxyControlPart(Connection *Conn,PVStr(url));
void  makeProxyRequest(Connection *Conn);
int   httpfinger(Connection *Conn,int sv,PCStr(server),int iport,PCStr(path),int vno);
void  FTPHTTP_genPass(PVStr(pass));
int   HTTP_ACCEPT(Connection *Conn,PCStr(req),PCStr(head),FILE *fc,FILE *tc);
int   java_conv(PCStr(line),PVStr(xline),int uconvs);
void  doXECHO(FILE *tc,PCStr(msg));


/*-- CGI */
const char *URL_toMyself(Connection *Conn,PCStr(url));
FileSize HttpToMyself(Connection *Conn,PVStr(req),PCStr(head),FILE *fc,FILE *tc,int *stcodep);
int   form2v(PVStr(form),int maxargc,const char *argv[]);
int   HTTP_form2v(Connection *Conn,FILE *fc,int maxargc,const char *argv[]);

/* CacheFlags */
#define CACHE_DONTUSE	0x00000001
#define CACHE_DONTCARE	0x00000002
#define CACHE_ONLY	0x00000004
#define CACHE_RENAME	0x00000008

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2014 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	htfilter.h (HTML filter)
Author:		Yutaka Sato <y.sato@aist.go.jp>
Description:
History:
	970708	extracted from httpd.c
	140928	to be extracted from http.h (but failed on Windows)
//////////////////////////////////////////////////////////////////////#*/

typedef struct _Partf {
	int	p_Nput; /* number of parts put */
	int	p_NumParts; /* numbers of parts put (excluding STYLE) put */
	int	p_Isin;	/* isin xxx.html?part */
	int	p_IsinTag; /* in a tag in which no anchor generation (A and STYLE) */
	int	p_Incomment; /* v9.9.11 new-140724i, in <!-- comment --> */
	MStr(	p_Type,32);
	int	p_Asis;
	int	p_Indexing;
	int	p_BaseSet;
	MStr(	p_Base,256);
	MStr(	p_Title,256);
	MStr(	p_Meta,1024);
	MStr(	p_NoHrefGen,4*1024); /* comma separated list of words not to be hrefgen */
} Partf;

void  clearPartfilter(Partf *Pf);
int   Partfilter(Connection *Conn,Partf *Pf,PVStr(line),int size);
