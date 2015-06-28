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
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	httphead.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970708	extracted from httpd.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "ystring.h"
#include "credhy.h"
#include "delegate.h"
#include "filter.h"
#include "hostlist.h"
#include "file.h"
#include "auth.h"
#include "http.h"

#define FPRINTF		leng += Fprintf

extern int START_TIME1;

typedef struct {
  const char *m_name;
  const char *m_class;
} Method;
static Method validMethods[] = {
	{"OPTIONS",	"1.1"},	   /* RFC2616 9.2 */
	{"GET",		"1.1"},	   /* RFC2616 9.3 */
	{"HEAD",	"1.1"},	   /* RFC2616 9.4 */
	{"POST",	"1.1"},	   /* RFC2616 9.5 */
	{"PUT",		"1.1"},	   /* RFC2616 9.6 */
	{"DELETE",	"1.1"},	   /* RFC2616 9.7 */
	{"TRACE",	"1.1"},	   /* RFC2616 9.8 */
	{"CONNECT",	"1.1"},	   /* RFC2616 9.9 */
	{"PROPFIND",	"webdav"}, /* RFC2518 8.1 */
	{"PROPPATCH",	"webdav"}, /* RFC2518 8.2 */
	{"MKCOL",	"webdav"}, /* RFC2518 8.3 */
	{"COPY",	"webdav"}, /* RFC2518 8.8 */
	{"MOVE",	"webdav"}, /* RFC2518 8.9 */
	{"LOCK",	"webdav"}, /* RFC2518 8.10 */
	{"UNLOCK",	"webdav"}, /* RFC2518 8.11 */
	{"REPORT",	"webdav"}, /* RFC3253 3.6 */
	{"SEARCH",	"draft"},  /* HTTP/0.9 ? also in WebDAV,IIS,... */
	{"LINK",	"draft"},  /* HTTP/0.9 ? */
	{"UNLINK",	"draft"},  /* HTTP/0.9 ? */
	{"PATCH",	"?"},	   /* ? */
	{"X-CACHE-GET",	"delegate"},/* almost obsolete */
	{0}
};
static Method *allowMethodV;

/* TODO: HTTPCONF=methods:*,!M1,!M2" or "methods:!M1,!M2" should be supported.
 *       Should be declarable if a method has a {request/response} body or not
 */ 
static int allowAnyMethods;
static int acceptableRequest(PCStr(req))
{	int maj,min;

	if( allowAnyMethods )
	if( sscanf(req,"%*[_a-zA-Z] %*[a-zA-Z]://%*[^ ] HTTP/%d.%d",&maj,&min) == 2
	 || sscanf(req,"%*[_a-zA-Z] /%*[^ ] HTTP/%d.%d",&maj,&min) == 2
	 || sscanf(req,"%*[_a-zA-Z] / HTTP/%d.%d",&maj,&min) == 2
	 || sscanf(req,"%*[_a-zA-Z] * HTTP/%d.%d",&maj,&min) == 2
	)
			return 1;
	return 0;
}

const char *CTX_reqstr(Connection *Conn)
{
	if( Conn == NULL )
		return 0;
	if( CurEnv )
		return REQ_FIELDS;
	else	return 0;
}

const char *CTX_reqURL(Connection *Conn){ /* v10.0.0 new-140806b */
	if( Conn == NULL )
		return 0;
	if( CurEnv )
		return REQ_URL;
	else	return 0;
}

static int putMimeHeader(FILE *tc,PCStr(type),PCStr(encoding),FileSize size)
{	int leng = 0;

	FPRINTF(tc,"MIME-Version: %s\r\n",MY_MIMEVER);
	FPRINTF(tc,"Content-Type: %s\r\n",type);
	if( encoding != ME_7bit )
	FPRINTF(tc,"Content-Transfer-Encoding: %s\r\n",encoding);

	if( size == EMPTYBODY_SIZE ){
	FPRINTF(tc,"Content-Length: 0\r\n");
	}else
	if( 0 < size )
	FPRINTF(tc,"Content-Length: %lld\r\n",size);
	return leng;
}
static void makeDeleGateHeader(PVStr(head),int iscache)
{
	sprintf(head,"DeleGate-Ver: %s (delay=%d)",
		DELEGATE_ver(),ll2i(time(0)-START_TIME1));
	if( iscache )
		strcat(head," (from-cache)");
}
int HTTP_head2kill(PCStr(head),int what);
int HTTP_echoRequestHeader(Connection *Conn,FILE *tc);
int HTTP_putDeleGateHeader(Connection *Conn,FILE *tc,int iscache)
{	int leng = 0;
	CStr(head,256);

	makeDeleGateHeader(AVStr(head),iscache);
	if( !HTTP_head2kill(head,KH_OUT|KH_RES) )
	FPRINTF(tc,"%s\r\n",head);
	leng += HTTP_echoRequestHeader(Conn,tc);
	return leng;
}
int getMountOpt1(Connection *Conn,PCStr(onam),PVStr(oval),int size){
	if( Conn && MountOptions ){
		return getOpt1(MountOptions,onam,BVStr(oval));
	}
	return 0;
}
int getMountExpires(Connection *Conn,PVStr(date),int size){
	CStr(odate,64);
	CStr(mexpire,32);
	const char *mexp;
	int rel;
	int expire;
	int from;
	int disp;

	if( MountOptions == 0 )
		return 0;
	if( getOpt1(MountOptions,"expires",AVStr(mexpire)) == 0 )
		return 0;
	strcpy(odate,date);
	rel = 0;
	for( mexp = mexpire; *mexp; mexp++ ){
		if( *mexp == '+' || *mexp == '-' )
			rel = *mexp;
		else	break;
	}
	disp = scan_period(mexp,'s',0);

	if( date[0] )
		from = scanHTTPtime(date);
	else	from = time(0);

	switch( rel ){
		case '+': expire = from + disp; break;
		case '-': expire = from - disp; break;
		default:  expire = time(0) + disp; break;
	}

	StrftimeGMT(AVStr(date),size,TIMEFORM_RFC822,expire,0);
	Verbose("PUT Expires: %s [%s]\n",date,odate);
	return 1;
}

void HTTP_modifyConnection(Connection *Conn,int rlength);
int genSessionCookie(Connection *Conn,PVStr(field));
int putKeepAlive(Connection *Conn,FILE *tc);

int hextoStr(PCStr(hex),PVStr(bin),int siz);
const char *getEMCert(PCStr(emcert));
static scanListFunc scanopt(PCStr(opt),PVStr(opts),int *nenc){
	refQStr(tp,opts);
	CStr(md5,64);
	CStr(emcert,1024);
	CStr(sign,1024);
	unsigned int slen;
	int ok;
	const char *email;
	CStr(emailb,128);
	CStr(pass,128);

	if( opts[0] ){
		strcat(opts,",");
	}
	tp = opts+strlen(opts);
	strcpy(tp,opt);
	if( strstr(tp,"sign=pass:") || strstr(tp,"verify=pass:") ){
		tp = strchr(tp,':')+1;
		if( strncasecmp(tp,"MD5:",4) != 0 ){
			toMD5(tp,md5);
			sprintf(tp,"MD5:%s",md5);
			(*nenc) += 1;
		}
	}else
	if( strneq(opt,"sign=rsa",8) ){
		truncVStr(pass);
		if( opt[8] == 0 ){
			email = "anonymous-key";
		}else{
			tp = wordScanY(opt+9,emailb,"^:");
			email = emailb;
			if( *tp == ':' ){
				lineScan(tp+1,pass);
			}
		}
		sprintf(emcert,"%s.pem",email);

		slen = sizeof(sign);
		ok = SignRSA(emcert,getEMCert(emcert),pass,NULL,0,VStrNULL,NULL);
		if( ok == 0 ){
			fprintf(stderr,"# Can't set private-key: %s\n",emcert);
		}
	}else
	if( strneq(opt,"verify=rsa",10) ){
		if( opt[10] == 0 )
			email = "anonymous-cert";
		else	email = opt+11;
		slen = sizeof(sign);
		sprintf(emcert,"%s.pem",email);
		ok = VerifyRSA(emcert,getEMCert(emcert),NULL,0,NULL,0);
		if( ok == 0 ){
			fprintf(stderr,"# Can't set certificate: %s\n",emcert);
		}
	}
	
	return 0;
}
char *encryptMountPass(PCStr(a1)){
	const char *op;
	CStr(vURL,256);
	CStr(rURL,256);
	CStr(opts,256);
	CStr(mnt,1024);
	int nopt;
	int nenc;

	if( strcasestr(a1,"=pass:") == 0 )
	if( strcasestr(a1,"=rsa") == 0 )
		return 0;

	op = wordScan(a1,vURL); /* MOUNT=vURL */
	op = wordScan(op,rURL);
	while( isspace(*op) )
		op++;
	if( *op == 0 )
		return 0;

	nenc = 0;
	truncVStr(opts);
	scan_commaList(op,1,scanListCall scanopt,AVStr(opts),&nenc);
	if( nenc ){
		sprintf(mnt,"%s %s %s",vURL,rURL,opts);
		return stralloc(mnt);
	}
	return 0;
}

FILE *dgfopen(PCStr(what),PCStr(base),PCStr(rpath),PCStr(mode));
const char *getEMCert(PCStr(emcert)){
	const char *data;
	int len;
	CStr(url,1024);
	CStr(buf,8*1024);
	FILE *fp;
	const char *mp;

	sprintf(url,"builtin/config/%s",emcert);
	len = 0;
	if( data = getMssg(url,&len) )
		return data;

	if( (fp = dgfopen("EMCert","${ETCDIR}",emcert,"r"))
	 || (fp = dgfopen("EMCert","${ADMDIR}/dgca/emcerts",emcert,"r"))
	){
		len = fread(buf,1,sizeof(buf)-1,fp);
		fclose(fp);
		if( 0 < len ){
			setVStrEnd(buf,len);
			mp = stralloc(buf);
			return mp; /* should be freed ... */
		}
	}

	return 0;
}
int checkMD5(FILE *mfp,PCStr(url),PCStr(buf),int len){
	CStr(fv,128);

	if( buf == 0 || len < 0 ){
		daemonlog("F","Bad data for MD5: %X/%d %s\n",p2i(buf),len,url);
	}else
	if( fgetsHeaderField(mfp,"Content-MD5",AVStr(fv),sizeof(fv)) ){
		CStr(imd5,128);
		MD5 *md5;
		char digest[16];
		CStr(xs,128);

		wordScanY(fv,imd5,"^; \t\r\n");
		md5 = newMD5();
		addMD5(md5,buf,len);
		endMD5(md5,digest);
		MD5toa(digest,(char*)xs);
		if( strcaseeq(imd5,xs) ){
			return 0;
		}
		daemonlog("F","Inconsistent MD5: %s\n",url);
	}else{
		daemonlog("F","No MD5: %s\n",url);
	}
	return -1;
}
static int makeSignedMD5(PCStr(cmd5),PCStr(skey),PVStr(xs)){
	MD5 *md5;
	CStr(key,16);
	CStr(sign,16);
	int blen;

	blen = hextoStr(skey,AVStr(key),16);
	if( blen != 16 ){
		daemonlog("F","signedMD5: bad key: %s\n",skey);
		return -1;
	}
	md5 = newMD5();
	addMD5(md5,cmd5,16);
	addMD5(md5,key,16);
	endMD5(md5,sign);
	MD5toa(sign,(char*)xs);
	return 0;
}
int strtoB64(PCStr(str),int slen,PVStr(b64),int bsiz,int withnl);
int putSignedMD5(FILE *tc,PCStr(cmd5),PCStr(options)){
	int leng;
	CStr(xm,64);
	CStr(xs,64);
	const char *kp;
	CStr(rs,128);
	CStr(xrs,512);
	CStr(smd5,512);
	CStr(emcert,1024);

	strtoB64(cmd5,16,AVStr(xm),sizeof(xm),0);
	/*
	MD5toa(cmd5,xm);
	*/
	sprintf(smd5,"Content-MD5: %s",xm);

	if( options && (kp = strstr(options,"sign=pass:MD5:")) ){
		makeSignedMD5(cmd5,kp+14,AVStr(xs));
		Xsprintf(TVStr(smd5),"; sign=%s",xs);
	}
	if( options && (kp = strstr(options,"sign=rsa")) ){
		const char *email;
		CStr(emailb,128);
		CStr(pass,128);
		CStr(sig,128); /* 1024 bits sign in RSA */
		unsigned int slen;
		int ok;

		truncVStr(pass);
		if( kp[8] == ':' && kp[9] != 0 ){
			const char *tp;
			tp = wordScanY(kp+9,emailb,"^:");
			email = emailb;
			if( *tp == ':' ){
				lineScan(tp+1,pass);
			}
		}else{
			email = "anonymous-key";
		}
		sprintf(emcert,"%s.pem",email);
		slen = sizeof(sig);
		ok = SignRSA(emcert,getEMCert(emcert),pass,cmd5,16,AVStr(sig),&slen);
		strtoHex(sig,slen,AVStr(xrs),sizeof(xrs));
		Xsprintf(TVStr(smd5),"; sign=\"rsa::%s\"",xrs);
	}
	sv1log("##putMD5## %s\n",smd5);
	Xsprintf(TVStr(smd5),"\r\n");
	fputs(smd5,tc);
	leng = strlen(smd5);
	return leng;
}
int verifySignedMD5(PCStr(head),PCStr(cmd5),PCStr(options)){
	CStr(val,512);
	MD5 *md5;
	CStr(xs,64);
	CStr(xmd5,64);
	CStr(md,64);
	CStr(xsign,512);
	const char *kp;
	int rcode = 0;

	if( getFieldValue2(head,"Content-MD5",AVStr(val),sizeof(val)) == 0 ){
		return -1;
	}
	truncVStr(xmd5);
	truncVStr(xsign);
	Xsscanf(val,"%[^;]; sign=%[^;]",AVStr(xmd5),AVStr(xsign));

	str_from64(xmd5,strlen(xmd5),AVStr(md),sizeof(md));
	/*
	hextoStr(xmd5,AVStr(md),sizeof(md));
	*/
	if( cmd5 ){
		if( bcmp(cmd5,md,16) != 0 ){
			daemonlog("F","Content-MD5 error\n");
			return -2;
		}
		rcode |= 1;
	}else{
		cmd5 = md;
	}

	if( options && (kp = strstr(options,"verify=pass:MD5:")) ){
		makeSignedMD5(cmd5,kp+16,AVStr(xs));
		if( strcmp(xsign,xs) != 0 ){
			daemonlog("F","Content-MD5 sign error\n");
			return -3;
		}else{
			rcode |= 2;
		}
	}
	if( options && (kp = strstr(options,"verify=rsa")) ){
		CStr(xsig,512);
		CStr(sig,128);
		CStr(emcert,128);

		if( kp[10] != ':' )
			strcpy(emcert,"anonymous-cert.pem");
		else	sprintf(emcert,"%s.pem",kp+11);

		truncVStr(xsig);
		if( kp = strstr(val,"sign=\"rsa:") ){
			kp = wordScanY(kp+10,xsig,"^:; ");
			if( *kp == ':' ){
				/* sign=rsa:foo@bar:XXXX */
				wordScanY(kp+1,xsig,"^; ");
			}
		}
		if( xsig[0] ){
			int ok;
			int slen;
			slen = hextoStr(xsig,AVStr(sig),sizeof(sig));
			ok = VerifyRSA(emcert,getEMCert(emcert),cmd5,16,sig,slen);
			if( ok == 0 ){
				return -4;
			}
			Verbose("VERIFIED RSA %s\n",emcert);
			rcode |= 4;
		}else{
		}
	}
	return rcode;
}

int CTX_asproxy(Connection *Conn);
int putHEAD(Connection *Conn,FILE *tc,int code,PCStr(reason),PCStr(server),PCStr(ctype),PCStr(ccode),FileSize csize,int mtime,int expire)
{	int leng;
	CStr(date,128);
	CStr(serverb,128);
	int tobeclosed;
	int tobechunked;
	const char *myver;

	if( ctype == NULL ) ctype = "text/html";
	if( ccode == NULL ) ccode = ME_7bit;
	StrftimeGMT(AVStr(date),sizeof(date),TIMEFORM_RFC822,time(0),0);
	if( server == NULL ){
		sprintf(serverb,"DeleGate/%s",DELEGATE_ver());
		server = serverb;
	}

	tobeclosed = 0;
	tobechunked = 0;

	if( csize != EMPTYBODY_SIZE )
	if( csize <= 0 ){
		if( ClntAccChunk ){
			tobechunked = 1;
			/* Content-Length filed is not necessary */
		}else
		if( code == 304 /* || method == HEAD */ ){
			/* message is without body */
		}else{
			/* lacking necessary Content-Length info. to make
			 * connection be Keep-Alive
			 */
			tobeclosed = 1;
		}
	}

	myver = MY_HTTPVER;
	/* HTTP/1.1 response must not be closed without "Connection: close".
	 * Currenty this can occur for requests from HTTP/1.0 client
	 * without "Connection: keep-alive".
	 */
	if( !ClntAccChunk ) /* non-HTTP/1.1 client */
	if( !WillKeepAlive || tobeclosed )
	if( strcmp(myver,"1.0") != 0 )
		myver = "1.0";

	leng = 0;
	FPRINTF(tc,"HTTP/%s %d %s\r\n",myver,code,reason);
	leng += FPRINTF(tc,"Date: %s\r\n",date);
	leng += FPRINTF(tc,"Server: %s\r\n",server);
	leng += HTTP_putDeleGateHeader(Conn,tc,0);
	leng += putMimeHeader(tc,ctype,ccode,csize);
	if( genETag[0] ){
		leng += FPRINTF(tc,"ETag: %s\r\n",genETag);
		genETag[0] = 0;
	}
	if( addRespHeaders[0] ){
		leng += FPRINTF(tc,"%s",addRespHeaders);
	}
	if( Conn->mo_flags & MO_MD5_SET ){
		leng += putSignedMD5(tc,Conn->ht_qmd5,MountOptions);
	}

	/*
	if( HTTP_opts & HTTP_SESSION ){
	*/
	{
		CStr(head,256);
		if( genSessionCookie(Conn,AVStr(head)) )
			FPRINTF(tc,"%s",head);
	}

	if( mtime != -1 && mtime != 0 ){
		StrftimeGMT(AVStr(date),sizeof(date),TIMEFORM_RFC822,mtime,0);
		FPRINTF(tc,"Last-Modified: %s\r\n",date);
	}

	date[0] = 0;
	if( expire != -1 && expire != 0 ){
		StrftimeGMT(AVStr(date),sizeof(date),TIMEFORM_RFC822,expire,0);
		/*
		FPRINTF(tc,"Expires: %s\r\n",date);
		*/
	}
	getMountExpires(Conn,AVStr(date),sizeof(date));
	if( date[0] ){
		FPRINTF(tc,"Expires: %s\r\n",date);
	}

	if( code == 206 ){
		FPRINTF(tc,"Content-Range: bytes %lld-%lld/%lld\r\n",Conn->sv.p_range[0],Conn->sv.p_range[1],Conn->sv.p_range[2]);
	}
	if( code == 416 ){
		FPRINTF(tc,"Content-Range: bytes */%lld\r\n",Conn->sv.p_range[2]);
	}

	if( tobeclosed ){
		HTTP_clntClose(Conn,"U:unknown size internal response");
	}
	HTTP_modifyConnection(Conn,csize);
	leng += putKeepAlive(Conn,tc);

	if( tobechunked && WillKeepAlive && RespWithBody ){
		sv1log("## MUST USE CHNUNKED ENCODING: HTTP/%s %d %s ##\n",
			myver,code,reason);
		FPRINTF(tc,"Transfer-Encoding: chunked\r\n");
	}
	return leng;
}
int genHEADX(Connection *Conn,FILE *tc,int code,PCStr(reason),int cleng)
{	int leng;
	int expire;

	expire = -1;
	switch( code ){
	case 301:
		expire = time(0) + 60*60;
		break;
	case 302:
		expire = time(0) + 60;
		break;
	case 305:
	case 306:
		expire = time(0) + 60*60;
		break;
	}
	leng = putHEAD(Conn,tc,code,reason, NULL,NULL,NULL,cleng,-1,expire);
	return leng;
}

int putHttpHeader1X(Connection *Conn,FILE *tc,int vno,PCStr(server),PCStr(type),PCStr(encoding),FileSize  size,int mtime,int expire,PCStr(status))
{	int leng = 0;
	int code;
	const char *sp;
	CStr(reason,2048);

	if( vno < 100 )
		return 0;

	code = 200;
	strcpy(reason,"OK");
	if( status != NULL ){
		sp = scanint(status,&code);
		lineScan(sp,reason);
	}

leng = putHEAD(Conn,tc,code,reason,server,type,encoding,size,mtime,expire);

	if( Conn->fi_builtin == 0 ){ /* !withResponseFilter() */
		CStr(head,2048);
		head[0] = 0;
		if( HTTP_genhead(Conn,AVStr(head),KH_OUT|KH_RES) ){
			leng += strlen(head);
			fputs(head,tc);
		}
	}

	FPRINTF(tc,"\r\n");
	return leng;
}
int putHttpHeader1(Connection *Conn,FILE *tc,PCStr(server),PCStr(type),PCStr(encoding),FileSize size,int expire)
{
return
putHttpHeader1X(Conn,tc,100,server,type,encoding,size, -1,     expire,NULL);
}
int putHttpHeaderV(Connection *Conn,FILE *tc,int vno,PCStr(server),PCStr(type),PCStr(encoding),int size,int lastmod,int expire)
{
return
putHttpHeader1X(Conn,tc,vno,server,type,encoding,size,lastmod, expire,NULL);
}

int get_builtin_MADE_TIME();
int HTTP_putHeader(Connection *Conn,FILE *tc,int vno,PCStr(type),FileSize size,int mtime)
{	int lastmod;

	if( vno < 100 ){
		sv1log("No header put: client is HTTP %d.%d\n",
			vno/100,vno%100);
		return 0;
	}
	if( 0 < mtime )
		lastmod = mtime;
	else
	if( mtime == 0 )
		lastmod = get_builtin_MADE_TIME();
	else	lastmod = 0;

return
putHttpHeader1X(Conn,tc,vno,NULL,  type,ME_7bit, size, lastmod, 0,     NULL);
}


void setKeepAlive(Connection *Conn,int timeout)
{
	if( 1 < CKA_RemAlive )
		sprintf(httpConn,"keep-alive, timeout=%d, maxreq=%d",
			timeout,CKA_RemAlive);
	else	strcpy(httpConn,"close");
}
void HTTP_clntClose(Connection *Conn,PCStr(fmt),...)
{
	VARGS(16,fmt);
	WillKeepAlive = 0;
	sprintf(WhyClosed,fmt,VA16);
	Verbose("HCKA:[%d] %s\n",RequestSerno,WhyClosed);
}
int putKeepAlive(Connection *Conn,FILE *tc)
{	int leng;
	CStr(buff,256);

	if( leng = getKeepAlive(Conn,AVStr(buff)) )
		fputs(buff,tc);
	return leng;
}


int HTTP_doKeepAliveWithSTLS(Connection *Conn){
	if( HTTP_opts & HTTP_NOKEEPALIVE_STLS )
		return 0;

	/*
	if( HTTP_opts & HTTP_DOKEEPALIVE_STLS )
	*/
	if( ServerFlags & PF_MITM_ON )
	if( ClientFlags & PF_MITM_ON )
	if( (ClientFlags & PF_MITM_SPOT) == 0 )
	if( (Conn->xf_filters & (XF_FTOCL|XF_FFROMCL)) == 0 )
	{
		return 1;
	}
	if( ImMaster && (ClientFlags & (PF_MITM_DO/*|PF_SSL_ON*/)) ){
		sv1log("MITM: Keep-Alive in MASTER %X\n",ClientFlags);
		return 1;
	}

	if( Conn->xf_filters == XF_FCL )
	if( ClientFlags & (PF_STLS_ON|PF_SSL_ON) )
	{
		return 1;
	}

	return 0;
}

/*
 * 9.2.1 Connection:close might be sent in FTOCL or response filer
 * even when the main process has sent Connection:Keep-Alive or
 * HTTP/1.1, as in SHTML.
 * This situation should be cared by feeding back real Connection:
 * status sent to the client back to the main process...
 */
int checkTobeKeptAlive(Connection *Conn,PCStr(where)){
	if( WillKeepAlive )
	if( Conn->xf_filters & (XF_FTOCL|XF_FCL) )
	if( !HTTP_CKA_CFI )
	if( !doKeepAliveWithSTLS(Conn) ) 
	{
		HTTP_clntClose(Conn,"x:with-FTOCL/%s",where);
		return 1;
	}
	return 0;
}

int getKeepAlive(Connection *Conn,PVStr(KA))
{
	setVStrEnd(KA,0);
	if( Conn != NULL && ClntKeepAlive ){
		if( WillKeepAlive ){
			/* HTTP/1.1 does not require explicit keep-alive ... */
			sprintf(KA,"%s: %s\r\n",ConnFname,httpConn);
		}else	sprintf(KA,"%s: close\r\n",ConnFname);
		SentKeepAlive = WillKeepAlive;
		return strlen(KA);
	}else	return 0;
}

static char *getHost(PCStr(head),PVStr(host),int size)
{	const char *ohpp;
	CStr(ohpb,MaxHostNameLen);
	const char *hp;
	char hc;

	if( ohpp = findFieldValue(head,"Host") ){
		RFC822_valuescan(ohpp,AVStr(ohpb),sizeof(ohpb));
		for( hp = ohpb; hc = *hp; hp++ ){
			if( (hc & 0x80) || hc <= 0x20 ){
				sv1log("##ERROR: ignored malformed Host: %s\n",
					ohpb);
				return 0;
			}
		}
		wordscanX(ohpb,AVStr(host),size);
		return (char*)ohpp;
	}
	return 0;
}

int CTX_vhost(Connection *Conn,PVStr(host)){
	if( CurEnv && OREQ_VHOST[0] ){
		int port;
		port = scan_hostport(CLNT_PROTO,OREQ_VHOST,BVStr(host));
		return port;
	}
	return 0;
}
int getVserv(Connection *Conn,PCStr(head),PVStr(hostport)){
	if( GEN_VHOST[0] ){
		if( streq(GEN_VHOST,"-thru") ){
			getHost(head,BVStr(hostport),MaxHostNameLen);
		}else{
			strcpy(hostport,GEN_VHOST);
		}
		return 1;
	}else{
		HostPort(BVStr(hostport),DST_PROTO,DST_HOST,DST_PORT);
		return 0;
	}
}
int MOUNT_nvserv(PCStr(opts));
int getNvserv(Connection *Conn,PVStr(nvserv)){
	if( Conn )
	if( MOUNT_nvserv(MountOptions) ){
		if( CurEnv ){
			getVserv(Conn,REQ_FIELDS,BVStr(nvserv));
			return 1;
		}
	}
	return 0;
}

int getOpt1Rserv(Connection *Conn,PCStr(opts),PVStr(rserv));
int getOpt1Vserv(Connection *Conn,PCStr(opts),PVStr(vserv));

void replace_line(PVStr(oval),PCStr(val));
void HTTP_setHost(Connection *Conn,PVStr(fields))
{	refQStr(ohpp,fields); /**/
	CStr(ohpb,MaxHostNameLen);
	CStr(genhost,MaxHostNameLen);
	CStr(hostfield,MaxHostNameLen);

	if( GEN_VHOST[0] )
	{
		/* forwarding to a origin-server. it should be got with
		 * getOpt1Vserv() as in the case of forwarding to a PROXY
		if( MountOptions && OREQ_VHOST[0] ){
			getOpt1Vserv(Conn,MountOptions,AVStr(genhost));
		}else
		 */
		if( streq(GEN_VHOST,"-thru") ){
			genhost[0] = 0;
			getHost(fields,AVStr(genhost),sizeof(genhost));
		}else
		strcpy(genhost,GEN_VHOST);
	}
	else	HostPort(AVStr(genhost),DST_PROTO,DST_HOST,DST_PORT);

	if( (ohpp = getHost(fields,AVStr(ohpb),sizeof(ohpb))) == NULL ){
		sprintf(hostfield,"Host: %s\r\n",genhost);
		RFC822_addHeaderField(AVStr(fields),hostfield);
	}else{
		/* replace it ... */
		/* if the request is for proxy (DONT_REWRITE, with full-URL) or
		 * if the field may be rewritten by MOUNT.
		 * (PointCast2.X clients send request including "Host: proxy")
		 */
		if( DONT_REWRITE || DO_DELEGATE || IsMounted ){
			if( strcmp(genhost,ohpb) != 0 ){
				sv1log("XHost: (%d,%d,%d) %s <= %s\n",
					DONT_REWRITE,DO_DELEGATE,IsMounted,
					genhost,ohpb);
 if( strchr(genhost,'%') ){
	sv1log("## unescape host-name in Host: %s\n",genhost);
	nonxalpha_unescape(genhost,AVStr(genhost),0);
 }
				replace_line(AVStr(ohpp),genhost);
			}else	Verbose("Host: %s <= %s\n",genhost,ohpb);
		}
	}
	if( MountOptions && getOpt1Rserv(Conn,MountOptions,AVStr(genhost)) ){
		int port;
		IStr(host,256);
		sv1log("rserv=%s <= %s:%d\n",genhost,REAL_HOST,REAL_PORT);
		port = scan_hostport(DST_PROTO,genhost,AVStr(host));
		if( host[0] && !streq(host,"*") && !streq(host,"-") ){
			strcpy(REAL_HOST,host);
		}
		if( 0 < port ){
			REAL_PORT = port;
		}
	}
}
static void stripMyself(Connection *Conn,xPVStr(url));
static int save_VHOST(Connection *Conn,PCStr(url))
{	CStr(ohpb,MaxHostNameLen);
	CStr(myhost,MaxHostNameLen);
	int myport;
	IStr(urlb,URLSZ);

	OREQ_VHOST[0] = 0;

	if( GatewayFlags & GW_SSI_INCLUDE )
		/* restriction to avoid possible side effect */
	if( isFullURL(url) ){
		/* v9.9.11 fix-140726a, save vhost in OREQ_VHOST[] for a
		 * full-URL request directed to resource in this server.
		 * Full-URL request can occur via URLget() from SSI
		 * include by <!--#include virutal=URL -->
		 * OREQ_VHOST[] is necessary to do reverse URL rewriting
		 * (partializing) of MOUNT for response to be included.
		 */
		if( strncaseeq(url,"file://",7) ){
			url = "/"; /* just to pass the check below */
		}else
		{
			strcpy(urlb,url);
			stripMyself(Conn,AVStr(urlb));
			url = urlb;
		}
	}

	if( url[0] == '/' )
	if( getHost(OREQ_MSG,AVStr(ohpb),sizeof(ohpb)) )
	if( (myport = scan_Hostport1(ohpb,myhost)) || *myhost )
	if( !ImMaster || IsMyself(myhost) ) /* req. directed to myself */
	{
		if( myport == 0 )
			myport = serviceport(CLNT_PROTO);
		IsVhost = !Ismyself(Conn,CLNT_PROTO,myhost,myport);
		if( IsVhost && sizeof(OREQ_VHOST)/2-8 < strlen(myhost) ){
			sv1log("Truncated long virtual hostname: %s\n",myhost);
			setVStrEnd(myhost,sizeof(OREQ_VHOST)/2-8);
		}
		sprintf(OREQ_VHOST,"%s:%d",myhost,myport);
		return 1;
	}
	return 0;
}
void HTTP_getHost(Connection *Conn,PCStr(request),PCStr(fields))
{	const char *url;
	CStr(ohpb,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	int port;
	const char *myproto;

	if( getHost(fields,AVStr(ohpb),sizeof(ohpb)) ){
		myproto = CLNT_PROTO;
		port = scan_Hostport1p(myproto,ohpb,host);
		set_realsite(Conn,myproto,host,port);

		if( url = strpbrk(request," \t") ){
			while( *url == ' ' || *url == '\t' )
				url++;
			if( url[0] == '/' || url[0] == '*' )
				Verbose("Host: %s:%d\n",host,port);
		}
	}
}

/*
 * Replace "-.-" wich my real hostname.
 * The result will be sent to the server in Referer field.
 * The hostname of client's side socket should be used semantically, but
 * it might be hidden interface to the server. So instead use the hostname
 * of server's side socket.
 */
int getservsideNAME(Connection *Conn,PVStr(me));
static int substRealname(Connection *Conn,PVStr(url))
{	const char *proto;
	int plen;
	CStr(tmp,URLSZ);
	CStr(me,MaxHostNameLen);
	int port;

	proto = CLNT_PROTO;
	plen = strlen(proto);

	if( 0 <= ToS )
	if( strncmp(url,proto,plen) == 0 )
	if( strncmp(url+plen,"://-.-",6) == 0 ){
		lineScan(url+plen+6,tmp);
		getservsideNAME(Conn,AVStr(me));
		port = sockPort(ClientSock);
		if( port != serviceport(proto) )
			Xsprintf(TVStr(me),":%d",port);
		sprintf(url,"%s://%s%s",proto,me,tmp);
		return 1;
	}
	return 0;
}

int Isvhost(Connection *Conn,PCStr(host),int port)
{	CStr(vhost,246);
	int vport;

	vport = HTTP_ClientIF_H(Conn,AVStr(vhost));
	if( vport == port && strcasecmp(vhost,host) == 0 )
		return 1;
	return 0;
}

int CTX_moved_url_to(DGC*ctx,PCStr(myhostport),PCStr(method),PVStr(url));
const char *CTX_changeproxy_url(Connection*ctx,PCStr(clif),PCStr(method),PVStr(url),PVStr(proxy));

static int stripDeleGate(Connection *Conn,xPVStr(durl))
{	CStr(upath,URLSZ);
	CStr(mods,256);
	CStr(flags,256);
	const char *up;
	const char *proto;
	CStr(rproto,64);
	CStr(rhost,MaxHostNameLen);
	CStr(rhostport,MaxHostNameLen);
	CStr(mupath,URLSZ);
	int rport;
	int rewritten = 0;

	while( *durl == ' ' || *durl == '\t' )
		durl++;

	if( *durl == '0' || *durl == '\r' || *durl == '\n' )
		return 0;

	if( (up = URL_toMyself(Conn,durl)) == 0 )
		return 0;

	strcpy(upath,up);
	if( upath[0] == 0 )
		strcpy(upath,"/");

	proto = CLNT_PROTO;
	strcpy(rproto,proto);
	if( CTX_url_derefer(Conn,proto,AVStr(upath),AVStr(mods),AVStr(flags),AVStr(rproto),AVStr(rhost),&rport) ){
		HostPort(AVStr(rhostport),rproto,rhost,rport);
		sprintf(durl,"%s://%s%s",rproto,rhostport,upath);
		Verbose("STRIPPED: %s\n",durl);
		rewritten = 1;
	}else{
		decomp_absurl(durl,AVStr(rproto),AVStr(rhostport),VStrNULL,0);
		rport = scan_hostport(rproto,rhostport,AVStr(rhost));
	}


	if( !Ismyself(Conn,rproto,rhost,rport) )
	if( !Isvhost(Conn,rhost,rport) )
		return rewritten;

	strcpy(mupath,upath);
	/*
	 * send real URL with real host name in the Referer field to the server
	 * (ie. not in virtual URL on DeleGate) if the server is that in the
	 * Referer field, so that the server can recognize that the Referer
	 * field refers to itself.
	 */
	if( CTX_mount_url_to(Conn,Conn->cl_myhp,REQ_METHOD,AVStr(mupath)) ){
		decomp_absurl(mupath,AVStr(rproto),AVStr(rhostport),VStrNULL,0);
		rport = scan_hostport(rproto,rhostport,AVStr(rhost));
		if( rport != DST_PORT )
			return rewritten;
		if( strcmp(rproto,DST_PROTO) != 0 )
			return rewritten;
		if( hostcmp(rhost,DST_HOST) != 0 )
			return rewritten;
		strcpy(durl,mupath);
		Verbose("MOUNTED: %s\n",durl);
		rewritten = 1;
	}
	return rewritten;
}

int removeField1(PVStr(head),PCStr(field));
static const char *vmount_referer(Connection *Conn,PVStr(url));
int RefererMounts();
static int mount_referers(Connection *Conn,PVStr(fields)){
	refQStr(nam,fields);
	refQStr(val,fields);
	refQStr(nfp,fields);
	CStr(url,URLSZ);
	const char *opts;
	int nm = 0;

	for( nfp = fields; nfp && *nfp; ){
		if( (nam = findField(nfp,"Referer",pp2cpp(&val))) == 0 )
			break;
		RFC822_valuescan(val,AVStr(url),sizeof(url));
		if( opts = vmount_referer(Conn,AVStr(url)) ){
			nm++;
			sv1log("## MOUNT[%s] %s\n",opts,url);
			if( streq(url,"command:remove") ){
				removeField1(AVStr(fields),nam);
				continue;
			}
			replace_line(AVStr(val),url);
		}
		if( nfp = strchr(val,'\n') )
			nfp++;
	}
	return nm;
}
/*
 * Referer URL should be rewritten to the real URL when it is relayed
 * to the server of the URL, so that it can be recognized at the server.
 * This is neccearry to let work some "URL access counters" embedded in 
 * a html text, which use the Referer as the target of the counter.
 */
void MountReferer(Connection *Conn,PVStr(fields))
{	refQStr(val,fields); /**/
	CStr(url,URLSZ);

	if( val = findFieldValue(fields,"Referer") ){
		if( 0 < RefererMounts() ){
			mount_referers(Conn,BVStr(fields));
		}
		RFC822_valuescan(val,AVStr(url),sizeof(url));

		if( substRealname(Conn,AVStr(url)) ){
			replace_line(AVStr(val),url);
		}
		if( stripDeleGate(Conn,AVStr(url)) ){
			sv1log("rewritten Referer: %s\n",url);
			replace_line(AVStr(val),url);
		}
	}
}

/* strip redundant http://myHost:myPort/ for rewriting in MOUNT */
static void stripMyself(Connection *Conn,xPVStr(url))
{	CStr(uc,2);
	const char *up;
	const char *upath;

/*
if( MountOptions && isinList(MountOptions,"recursive") )
 {
sv1log("#### don't stripMyself(%s) %s\n",url,MountOptions);
return;
 }
*/

	if( url[0] != '/' )
	if( up = (char*)URL_toMyself(Conn,url) ){
		/* fix-140515b */ {
			IStr(proto,128);
			IStr(site,128);
			decomp_absurl(url,AVStr(proto),AVStr(site),VStrNULL,0);
			if( isMYSELF(site) ){
				strcpy(OREQ_VHOST,site);
			}
		}
		uc[0] = *up; uc[1] = 0;
		truncVStr(up);
		if( uc[0] )
			upath = up + 1;
		else	upath = "";
		sv1log("##stripped before MOUNT [%s]%s%s%s",url,uc,
			upath,strtailchr(upath)!='\n'?"\n":"");
		*(char*)up = uc[0]; /**/
		if( uc[0] != '/' )
			setVStrPtrInc(url,'/');
		ovstrcpy((char*)url,up);
	}
}
/*
 * using VHOST for pages in ToInternal is desirable
 * but not desirable if with forced DELEGATE or BASEURL parameter
 */

int forcedIF_HX(Connection *Conn,PCStr(vhostport),PVStr(host));
int forcedIF_HPX(Connection *Conn,PCStr(vhostport),PVStr(hostport));

#define VHost	(CurEnv&&OREQ_VHOST[0]?OREQ_VHOST:NULL)
#define forcedIF_HP(x,hp) forcedIF_HPX(x,VHost,hp)
#define forcedIF_H(x,h)   forcedIF_HX(x,VHost,h)

int HTTP_ClientIF_H(Connection *Conn,PVStr(host))
{
	int port;
	if( port = forcedIF_H(Conn,BVStr(host)) )
		return port;
	/*
	if( CurEnv && (DO_DELEGATE||IsMounted) && OREQ_VHOST[0] )
	*/
	if( CurEnv && (DO_DELEGATE||IsMounted||ToInternal) && OREQ_VHOST[0] )
		return scan_hostport(DFLT_PROTO,OREQ_VHOST,AVStr(host));
/*
	else
	if( BYNAME )
		return ClientIF_Hname(Conn,host);
	else	return ClientIF_H(Conn,BVStr(host));
*/
	else{
		return ClientIF_H(Conn,BVStr(host));
	}
}
void HTTP_ClientIF_HP(Connection *Conn,PVStr(hostport))
{
	if( forcedIF_HP(Conn,BVStr(hostport)) )
		return;

	/*
	if( CurEnv && (DO_DELEGATE||IsMounted) && OREQ_VHOST[0] )
	*/
	if( CurEnv && (DO_DELEGATE||IsMounted||ToInternal) && OREQ_VHOST[0] )
		strcpy(hostport,OREQ_VHOST);
/*
	else
	if( BYNAME )
		ClientIF_HPname(Conn,hostport);
*/
	else	ClientIF_HP(Conn,BVStr(hostport));
}

const char *baseURL(Connection *Conn);
static const char *HTTP_baseURL(Connection *Conn)
{
	CStr(hostport,MaxHostNameLen);
	if( forcedIF_HP(Conn,AVStr(hostport)) ){
		sprintf(Conn->dg_iconbase,"%s://%s",CLNT_PROTO,hostport);
		return Conn->dg_iconbase;
	}

	/*
	 * cl_baseurl is set when the DeleGate is invoked as a CGI program
	 * with SCRIPT_NAME which is the virtual URL of the root path of
	 * CGI-DeleGate in the client view.  It is not a full-URL but such
	 * a relative-URL without site part seems enough and desirable...
	 * When the parent HTTP server is also DeleGate, /-/builtin/icons/*
	 * of the parent can be used for efficiency, but maybe it shold be
	 * controlled in general way, maybe with some MOUNT extension ...
	 */
	if( Conn->cl_baseurl[0] )
		return Conn->cl_baseurl;

	/*
	if( CurEnv && (DO_DELEGATE||IsMounted) && OREQ_VHOST[0] ){
	*/
	if( CurEnv && (DO_DELEGATE||IsMounted||ToInternal) && OREQ_VHOST[0] ){
		sprintf(Conn->dg_iconbase,"%s://%s",CLNT_PROTO,OREQ_VHOST);
		return Conn->dg_iconbase;
	}else	return baseURL(Conn);
}
void HTTP_baseURLrelative(Connection *Conn,PCStr(path),PVStr(url))
{
	strcpy(url,HTTP_baseURL(Conn));
	if( strtailchr(url) != '/' && *path )
		strcat(url,"/");
	if( *path == '/' )
		path++;
	strcat(url,path);
}

static const char *vmount(Connection *Conn,PVStr(url))
{	const char *opts;
	CStr(xvhost,MaxHostNameLen);

	opts = NULL;
	if( OREQ_VHOST[0] ){
		xvhost[0] = '-';
		wordscanX(OREQ_VHOST,QVStr(xvhost+1,xvhost),sizeof(xvhost)-1);
		opts = CTX_mount_url_to(Conn,xvhost,REQ_METHOD,AVStr(url));

/* as in vmount_moved(), should return NULL when MOUNT for "Moved" is found.
 * mount_urlY() which returns Mtab entry if hit regardless of its type.
 */
	}
/*
if( opts && isinList(opts,"recursive") ){
sv1log("#### don't strip self: %s\n",url);
}else
*/
	stripMyself(Conn,AVStr(url));
	if( opts == NULL ){
		opts = CTX_mount_url_to(Conn,Conn->cl_myhp,REQ_METHOD,AVStr(url));
	}
	return opts;
}
/* v9.9.11 fix-140731c, MOUNT SSI vurl to file://localhost/rpath
 * regarding my virtual host name in OREQ_VHOST[]
 */
const char *MountSSIpath(Connection *Conn,PVStr(url)){
	const char *opts;
	stripMyself(Conn,AVStr(url));
	opts = vmount(Conn,BVStr(url));
	return opts;
}
const char *CTX_Client_Host(Connection *Conn){
	if( Conn && Client_Host[0] )
		return Client_Host;
	else	return "undefined_Client_Host";
}

int non_MOVED();
int vmount_fullmoved(Connection *Conn,PVStr(url)){
	IStr(furl,URLSZ);
	int rcode;
	sprintf(furl,"%s://%s%s",DST_PROTO,OREQ_VHOST,url);
	if( rcode = CTX_moved_url_to(Conn,OREQ_VHOST,REQ_METHOD,AVStr(furl)) ){
		strcpy(url,furl);
	}
	return rcode;
}
static int vmount_moved(Connection *Conn,PVStr(url))
{	CStr(xvhost,MaxHostNameLen);
	int rcode;

	rcode = 0;
	if( ServerFlags & PF_MITM_ON ){
		rcode = vmount_fullmoved(Conn,BVStr(url));
	}
	if( rcode == 0 )
	if( OREQ_VHOST[0] ){
		xvhost[0] = '-';
		wordscanX(OREQ_VHOST,QVStr(xvhost+1,xvhost),sizeof(xvhost)-1);
		rcode = CTX_moved_url_to(Conn,xvhost,REQ_METHOD,AVStr(url));
	}
	if( rcode == 0 ){
		rcode = CTX_moved_url_to(Conn,Conn->cl_myhp,REQ_METHOD,AVStr(url));
	}
	if( rcode == non_MOVED() ){
		/* matched non_MOVED */
		return 0;
	}
	return rcode;
}
const char *CTX_rewrite_referer(DGC*ctx,PCStr(myhp),PCStr(method),PVStr(url));
static const char *vmount_referer(Connection *Conn,PVStr(url)){
	const char *opts;
	IStr(proto,64);
	IStr(site,MaxHostNameLen);

	/*
	decomp_absurl(url,AVStr(proto),AVStr(site),VStrNULL,0);
	*/
	sprintf(site,"%s:%d",DST_HOST,DST_PORT);
	opts = CTX_rewrite_referer(Conn,site,REQ_METHOD,AVStr(url));
	if( opts == 0 ){
		stripMyself(Conn,AVStr(url));
		if( url[0] == '/' ){
			if( OREQ_VHOST[0] ){
			site[0] = '-';
			wordscanX(OREQ_VHOST,QVStr(site+1,site),sizeof(site)-1);
			}
			opts = CTX_rewrite_referer(Conn,site,REQ_METHOD,AVStr(url));
		}
	}
	return opts;
}
/*
 * Maybe this functionn is obsolete covered/generalized by
 * MountSpecialResponse() with rcode=xxx:
 *   moved --- rcode=302
 *   useproxy --- rcode=305
 */
int HTTP_originalURLx(Connection *Conn,PVStr(url),int siz);
int MountMoved(Connection *Conn,FILE *tc)
{	CStr(moved_url,URLSZ);
	CStr(proxy,128);
	int totalc;
	const char *query;
	CStr(me,128);
	CStr(realurl,URLSZ);
	int rcode;
	const char *req;
	CStr(req_url,URLSZ);

	req = OREQ;
	HTTP_originalURLx(Conn,AVStr(req_url),sizeof(req_url));
	nonxalpha_unescape(req_url,AVStr(moved_url),0);
	stripMyself(Conn,AVStr(moved_url));

	if( query = strstr(moved_url,"?-.-=") ){
		if( strncmp(moved_url,"/-_-",4) == 0 ){
			ClientIF_HP(Conn,AVStr(me));
			sprintf(realurl,"%s://%s/-_-%s",CLNT_PROTO,me,query+5);
		}else	strcpy(realurl,query+5);
		sv1log("REDIRECT %s -> %s\n",moved_url,realurl);
		totalc = putMovedTo(Conn,tc,realurl);
		http_Log(Conn,302,CS_INTERNAL,req,totalc);
		return 1;
	}

	save_VHOST(Conn,moved_url);
/*
	if( OREQ_VHOST[0]
	 && (rcode = CTX_moved_url_to(Conn,OREQ_VHOST,   REQ_METHOD,moved_url))
	 || (rcode = CTX_moved_url_to(Conn,Conn->cl_myhp,REQ_METHOD,moved_url))
	)
*/
	rcode = vmount_moved(Conn,AVStr(moved_url));
	if( rcode )
	if( !streq(moved_url,req_url) ){
		totalc = putMovedToX(Conn,tc,rcode,moved_url);
		http_Log(Conn,rcode,CS_INTERNAL,req,totalc);
		return 1;
	}

	/*
	 * check change-proxy based only on the real interface name
	 * but not on the virtual host name (seems enough).
	 */
	if( CTX_changeproxy_url(Conn,Conn->cl_myhp,REQ_METHOD,AVStr(moved_url),AVStr(proxy))){
		totalc = putChangeProxy(Conn,tc,moved_url,proxy);
		http_Log(Conn,305,CS_INTERNAL,req,totalc);
		sv1log("RETURNED 305 for: %s",req);
		HTTP_delayReject(Conn,req,"",1);
		return 1;
	}
	return 0;
}

int mount_lastforw();
void HTTP_reject(Connection *Conn,PCStr(why),PCStr(how));

int MountSpecialResponse(Connection *Conn,FILE *tc)
{	CStr(url,URLSZ);
	const char *rp;
	CStr(proto,256);
	CStr(host,MaxHostNameLen);
	const char *opts;
	int rcode,totalc,port;

	/*
	strcpy(url,REQ_URL);
	*/
	HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
	save_VHOST(Conn,url);
	stripMyself(Conn,AVStr(url));
	opts = vmount(Conn,AVStr(url));
/*
	if( save_VHOST(Conn,url) )
		opts = CTX_mount_url_to(Conn,OREQ_VHOST,REQ_METHOD,url);
	else	opts = CTX_mount_url_to(Conn,Conn->cl_myhp,REQ_METHOD,url);
*/

	if( opts ){
		if( isinList(opts,"forbidden") )
			opts = "rcode=403";
		else
		if( isinList(opts,"unknown") )
			opts = "rcode=404";
	}

	if( opts )
	if( rp = strstr(opts,"rcode=") )
	if( rcode = atoi(rp+6) ){
		port = ClientIF_H(Conn,AVStr(host));
		set_realserver(Conn,DFLT_PROTO,host,port);
		switch( rcode ){
		case 300:
		case 301:
		case 302:
		case 303:
			totalc = putMovedToX(Conn,tc,rcode,url);
			http_Log(Conn,rcode,CS_INTERNAL,OREQ,totalc);
			return 1;
		case 304:
			totalc = putHttpNotModified(Conn,tc);
			http_Log(Conn,rcode,CS_INTERNAL,OREQ,totalc);
			return 1;
		case 305:
		case 306:
			totalc = putChangeProxy(Conn,tc,url,"");
			http_Log(Conn,rcode,CS_INTERNAL,OREQ,totalc);
			return 1;
		case 403:
			{
			CStr(how,64);
			sprintf(how,"reject in MOUNT[%d]",mount_lastforw());
			HTTP_reject(Conn,"URL rejected",how);
			}
			totalc = putHttpRejectmsg(Conn,tc,"","",0,AVStr(OREQ));
			http_Log(Conn,rcode,CS_AUTHERR,OREQ,totalc);
			/* if( strchr(opts,"delay") ) HTTP_delayReject(); */
			return 1;
		case 404:
			totalc = putUnknownMsg(Conn,tc,OREQ);
			http_Log(Conn,rcode,CS_AUTHERR,OREQ,totalc);
			return 1;
		}
	}
	return 0;
}
int URL_withUpath(PCStr(url))
{	int len;

	if( strncasecmp(url,"file" ,len=4) == 0
	 || strncasecmp(url,"cgi"  ,len=3) == 0
	 || strncasecmp(url,"ftp"  ,len=3) == 0
	 || strncasecmp(url,"http" ,len=4) == 0
	 || strncasecmp(url,"https",len=5) == 0 )
	if( url[len] == ':' )
		return len;
	return 0;
}

const char *MountReqURL(Connection *Conn,PVStr(url)){
	const char *opts = 0;
	IStr(proto,64);
	IStr(site,MaxHostNameLen);
	IStr(up,URLSZ);
	IStr(ux,URLSZ);
	IStr(vhost,MaxHostNameLen);

	strcpy(site,"-");
	strcpy(up,"/");
	decomp_absurl(url,AVStr(proto),DVStr(site,1),DVStr(up,1),sizeof(up)-1);
	opts = CTX_mount_url_to(Conn,site,REQ_METHOD,AVStr(up));
	if( opts == 0 ){
		return NULL;
	}
	/*
	if( getOpt1(opts,"genvhost",AVStr(vhost)) ){
	*/
	if( getOpt1Vserv(Conn,opts,AVStr(vhost)) ){
		decomp_absurl(up,AVStr(proto),AVStr(site),AVStr(ux),sizeof(ux));
		sprintf(url,"%s://%s/%s",proto,vhost,ux);
	}else{
		strcpy(url,up);
	}
	return opts;
}

int url_serviceport(PCStr(url));
int MountRequestURL(Connection *Conn,PVStr(ourl))
{	CStr(xurl,URLSZ);
	const char *opts;

	Verbose("ImMaster? %d <%s://%s:%d> <%s://%s:%d/>\n",
		ImMaster,
		DFLT_PROTO,DFLT_HOST,DFLT_PORT,
		REAL_PROTO,REAL_HOST,REAL_PORT);

	if( ImMaster && !Ismyself(Conn,DFLT_PROTO,DFLT_HOST,DFLT_PORT)){
		Verbose("DON'T MOUNT (ImMaster) %s://%s:%d%s",
			DFLT_PROTO,DFLT_HOST,DFLT_PORT,ourl);
		return 0;
	}

	save_VHOST(Conn,ourl);
	stripMyself(Conn,AVStr(ourl));
	strcpy(xurl,ourl);

	/*
	opts = NULL;
	if( OREQ_VHOST[0] ){
		CStr(xvhost,512);
		xvhost[0] = '-';
		Xstrcpy(DVStr(xvhost,1),OREQ_VHOST);
		opts = CTX_mount_url_to(Conn,xvhost,REQ_METHOD,xurl);
	}
	stripMyself(Conn,xurl);
	if( opts == NULL )
		opts = CTX_mount_url_to(Conn,Conn->cl_myhp,REQ_METHOD,xurl);
	*/
	opts = vmount(Conn,AVStr(xurl));

	if( opts == NULL )
		return 0;

	/*
	 * don't rewrite /robots.txt for non-directory stile target servers
	 * even when root is MOUNTed ...
	 */
	if( strncmp(ourl,"/robots.txt",11) == 0 )
	if( streq(CLNT_PROTO,"http")||streq(CLNT_PROTO,"https") )
	if( URL_withUpath(xurl) == 0 )
		return 0;

	IsMounted = 1;
	strcpy(ourl,xurl);
	sv1log("REQUEST +M %s%s",ourl,strtailchr(ourl)!='\n'?"\n":"");
	eval_mountOptions(Conn,opts);
	{	const char *dp;
		CStr(urlesc,128);
		if( dp = strcasestr(opts,"urlesc=") ){
			wordscanY(dp+7,AVStr(urlesc),sizeof(urlesc),"^,");
			nonxalpha_unescape(urlesc,AVStr(urlesc),1);
			url_unescape(AVStr(ourl),AVStr(ourl),URLSZ,urlesc /*,""*/);
			url_escapeX(ourl,AVStr(ourl),URLSZ,urlesc," \t\r\n");
		}
	}
	setMountOptions(FL_ARG,Conn,opts);
	/*
	MountOptions = opts;
	*/
	if( xurl[0] == '/' ){
		/* not to clear no_dstcheck_proto set with PF_ADMIN_SW */
	}else
	Conn->no_dstcheck_proto = url_serviceport(xurl);
	return 1;
}

const char *CTX_Rstat(Connection *Conn){
	return Conn->Rstat;
}
int HTTP_setRetry(Connection *Conn,PCStr(req),int rcode){
	CStr(ourl,1024);
	CStr(eurl,1024);
	HttpRequest reqx;
	const char *opts;

	if( Conn->sv_retry != 0 )
		return 0;

	HTTP_originalURLPath(Conn,AVStr(ourl));
	strcpy(eurl,ourl);
	decomp_http_request(req,&reqx);
	sprintf(Conn->Rstat,"%d",rcode);

	/* maybe vmount() or MountRequestURL() should be used */
	if( opts = CTX_onerror_url_to(Conn,NULL,reqx.hq_method,AVStr(eurl)) ){
		if( strcmp(ourl,eurl) != 0 ){
			Conn->sv_retry = SV_RETRY_DO;
			strcpy(REQ_URL,eurl);
			IsMounted = 1;
			setMountOptions(FL_ARG,Conn,opts);
			/*
			MountOptions = opts;
			*/
			Verbose("To be RETRYed with [%s]\n",eurl);
			return 1;
		}
	}
	if( EccEnabled() )
	if( Conn->ccsv.ci_id ){
		if( rcode == 503 ){
			porting_dbg("-Ecc(%2d){%d}*%d/%d (%d) retry HTTP %d cl%d ##set-retry##",
				Conn->ccsv.ci_ix,Conn->ccsv.ci_id,
				Conn->ccsv.ci_reused,Conn->ccsv.ci_para,
				Conn->ccsv.ci_reusing,
				rcode,IsAlive(ClientSock)
			);
			HTTP_originalURLx(Conn,AVStr(REQ_URL),sizeof(REQ_URL));
			Conn->sv_retry = SV_RETRY_DO;
			return 2;
		}
	}
	return 0;
}


void replace_line(PVStr(oval),PCStr(val))
{	const char *tp;
	char tc;
	const char *sp;
	char sc;
	refQStr(dp,oval); /**/

	for( tp = oval; tc = *tp; tp++ )
		if( tc == ';' || tc == '\r' || tc == '\n' )
			break;
	cpyQStr(dp,oval);
	for( sp = val; sc = *sp; sp++ ){
		if( tp <= dp ){ /* become longer than the original */
			Strins(AVStr(dp),sp);
			dp = NULL;
			break;
		}
		setVStrPtrInc(dp,sc);
	}
	if( dp != NULL ){ /* when shorter than the original */
		for( sp = tp; sc = *sp; sp++ )
			setVStrPtrInc(dp,sc);
		setVStrEnd(dp,0);
	}
}
void del_param(PVStr(val))
{	const char *sp;
	const char *dp;

	for( sp = val; *sp; sp++ ){
		if( *sp == ';' ){
			sp++;
			if( *sp == ' ' )
				sp++;
		}
		if( *sp == '\r' || *sp == '\n' )
			break;
	}
	ovstrcpy((char*)val,sp);
}

static int getsetDomPath(PVStr(value),PVStr(domain),PVStr(path),int set)
{	refQStr(vp,value); /**/
	int domset,pathset;

	if( !set ){
		setVStrEnd(path,0);
		setVStrEnd(domain,0);
	}

	domset = pathset = 0;
	for( cpyQStr(vp,value); *vp; vp++ ){
		if( strncasecmp(vp,"DOMAIN=",7) == 0 ){
			if( set ){
			    IStr(odom,MaxHostNameLen);
			    valuescanX(vp+7,AVStr(odom),sizeof(odom));
			    if( odom[0] == '.' && strtailstrX(domain,odom,1) ){
				continue;
			    }
			}
			domset = 1;
			if( set )
				replace_line(QVStr(vp+7,value),domain);
				/*
				del_param(vp);
				*/
			else	paramscanX(vp+7,";",AVStr(domain),256);
		}else
		if( strncasecmp(vp,"PATH=",5) == 0 ){
			pathset = 1;
			if( set )
				replace_line(QVStr(vp+5,value),path);
			else	paramscanX(vp+5,";",AVStr(path),1024);
		}
	}
	return domset || pathset;
}
static void rewriteCookie(PVStr(value),PCStr(url))
{	const char *dp;
	CStr(proto,128);
	CStr(login,1024);
	CStr(path,1024);
	CStr(opath,1024);
	CStr(valb,256);

	decomp_absurl(url,AVStr(proto),AVStr(login),AVStr(path),sizeof(path));
	if( dp = strchr(login,':') )
		truncVStr(dp);
	sprintf(opath,"/%s",path);
	getsetDomPath(AVStr(value),AVStr(login),AVStr(opath),1);

	lineScan(value,valb);
	sv1log("rewriten-Cookie> %s\n",valb);
}
int HTTP_originalURLPath(Connection *Conn,PVStr(path));
void decryptCookie(Connection *Conn,PVStr(cookie));
void MountCookieRequest(Connection *Conn,PCStr(request),PVStr(value))
{	CStr(proto,128);
	CStr(login,1024);
	CStr(domain,1024);
	CStr(path,1024);
	const char *dp;
	CStr(opath,1024);
	CStr(url,URLSZ);
	CStr(valb,256);

	lineScan(value,valb);
	/*
	sv1log("Cookie: %s\n",valb);
	*/
	LSEC("Cookie: %s\n",valb);
	decryptCookie(Conn,BVStr(value));

#ifdef RWCOOKIEREQ
	HTTP_originalURLPath(Conn,opath);
	if( !getsetDomPath(value,domain,opath,0) )
		return;

	strcpy(url,opath);
	if( CTX_mount_url_to(Conn,Conn->cl_myhp,REQ_METHOD,url) )
		rewriteCookie(value,url);
#endif
}

int HTTP_getCookie(Connection *Conn,PCStr(name),PVStr(clcc),int csiz){
	refQStr(cp,OREQ_MSG);
	if( CurEnv == 0 || OREQ_MSG[0] == 0 )
		return 0;
	if( cp = findFieldValue(OREQ_MSG,"Cookie") ){
		setVStrEnd(clcc,0);
		getParamX(AVStr(cp),name,BVStr(clcc),csiz,0,1);
		return clcc[0];
	}
	return 0;
}

void encryptCookie(Connection *Conn,PVStr(cookie));
void MountCookieResponse(Connection *Conn,PCStr(request),PVStr(value))
{	CStr(dom,1024);
	CStr(login,1024);
	CStr(myhp,1024);
	CStr(opath,URLSZ);
	CStr(url,URLSZ);
	CStr(valb,256);

	/* fix-120313a suppress Set-Cookie rewriting by URICONV */{
		extern int URICONV_MOUNT;
		int mmask = URICONV_MOUNT;
		int HTML_attrTobeConv(PCStr(attr),PCStr(tag),int *uconvp);
		if( HTML_attrTobeConv("Set-Cookie","Header",&mmask) == 0 ){
			return;
		}
	}
	lineScan(value,valb);
	/*
	sv1log("Set-Cookie: %s\n",valb);
	*/
	LSEC("Set-Cookie: %s\n",valb);
	encryptCookie(Conn,AVStr(value));

	if( strcaseeq(DST_PROTO,"https") && strcaseeq(CLNT_PROTO,"http") )
	if( strcasestr(value,"Secure") )
	{
		if( delParam(AVStr(value),"Secure") ){
			sv1log("Removed Secure attribute ... %s\n",value);
		}
	}

	HTTP_originalURLPath(Conn,AVStr(opath));
	if( !getsetDomPath(AVStr(value),AVStr(dom),AVStr(opath),0) )
		return;

	HTTP_ClientIF_HP(Conn,AVStr(myhp));
	HostPort(AVStr(login),DST_PROTO,DST_HOST,DST_PORT);
	if( opath[0] == '/' )
		ovstrcpy(opath,opath+1);

	if( DO_DELEGATE ){
		sprintf(url,"%s://%s/-_-%s://%s/%s",
			CLNT_PROTO,myhp,DST_PROTO,login,opath);
		rewriteCookie(AVStr(value),url);
	}else
	if( CTX_mount_url_fromL(Conn,AVStr(url),DST_PROTO,login,opath,NULL,CLNT_PROTO,myhp) )
		rewriteCookie(AVStr(value),url);
}
const char *URL_toMyself(Connection *Conn,PCStr(url))
{	int len,port,ux;
	unsigned char uc;
	CStr(host,MaxHostNameLen);

	if( *url == '/' )
		return url;

	ux = 0;
	len = strlen(CLNT_PROTO);
	if( strncasecmp(&url[ux],CLNT_PROTO,len) != 0 )
		return 0;
	ux = len;
	if( url[ux++] != ':' ) return 0;
	if( url[ux++] != '/' ) return 0;
	if( url[ux++] != '/' ) return 0;

	port = scan_Hostport1p(CLNT_PROTO,&url[ux],host);
	if( !Ismyself(Conn,CLNT_PROTO,host,port) )
	if( !Isvhost(Conn,host,port) )
		return 0;

	for(; uc = url[ux]; ux++ )
		if( uc == '/' || uc == '?' || isspace(uc) )
			break;

	return &url[ux];
}
int HTTP_reqToMyself(Connection *Conn)
{	HttpRequest reqx;

	if( OREQ[0] ){
		decomp_http_request(OREQ,&reqx);
		return URL_toMyself(Conn,reqx.hq_url) != NULL;
	}
	return 0;
}
int url_deproxy(Connection *Conn,PVStr(req),PVStr(url),PVStr(Rproto),PVStr(Rhost),int *Rportp)
{	const char *dp;
	CStr(rproto,256);
	CStr(rsite,MaxHostNameLen);
	CStr(upath,URLSZ);
	CStr(rhost,MaxHostNameLen);
	int rport;

	if( url[0] == '/' )
		return 0;

	/*
	 * get "rproto","rsite" and strip them out from "url"
	 */
	if( 2 <= strip_urlhead(AVStr(url),AVStr(rproto),AVStr(rsite)) ){
		if( strcaseeq(rproto,"opher") ){
			/* might be generated in buggy Mosaic ;-) */
			sv1log("Repaired-PROTO: %s to gopher\n",rproto);
			strcpy(rproto,"gopher");
		}
	}else{
		scan_namebody(url,AVStr(rproto),sizeof(rproto),":",AVStr(upath),sizeof(upath),NULL);
		if( localPathProto(rproto) ){
			strcpy(rsite,"localhost");
			strcpy(url,upath);
		}else	return 0;
	}

	/*
	 * decompose "rsite" into "rhost" : "rport"
	 */
	rport = 0;
	if( dp = strchr(rsite,'@') ){
		refQStr(tp,rhost); /**/
		dp = paramscanX(rsite,"@",AVStr(rhost),sizeof(rhost));
		if( *rhost == 0 )
			strcpy(rhost,"(empty-username)");
		tp = rhost + strlen(rhost);
		dp = paramscanX(dp,":",AVStr(tp),sizeof(rhost)-(tp-rhost));
		if( *tp == '@' && tp[1] == 0 )
			Xstrcpy(QVStr(tp+1,rhost),"(empty-hostname)");
		if( *dp == ':' )
			rport = atoi(dp+1);
	}else{
		rport = scan_Hostport1(rsite,rhost);
	}
	if( rport == 0 )
		rport = serviceport(rproto);


	/*
	 * obsolete operations...
	 */
	if( url[0]==' ' && url[1]=='/' ){
		/* might be generated in buggy Mosaic ;-) */
		ovstrcpy((char*)url,url+1);
		sv1log("Repaired-URL: %s",req);
	}
	if( strcaseeq(rproto,"gopher") ){
		if( req[0] == '/' && req[1] != '\r' ){
			CStr(tmp,32);
			sprintf(tmp,"(:%c:)",req[1]);
			ovstrcpy((char*)req,req+2);
			Strins(AVStr(req),tmp);
		}
	}
	if( strcaseeq(rproto,CLNT_PROTO) ){
/*
if( MountOptions && isinList(MountOptions,"recursive") ){
sv1log("#### don't strip myself() %s\n",MountOptions);
}else
*/
		if( Ismyself(Conn,rproto,rhost,rport) ){
			set_realsite(Conn,rproto,rhost,rport);
			sv1log("##strip myself [%s:%d]\n",rhost,rport);
			ToMyself = 1;
			return 0;
		}
	}
	if( Rhost[0] != 0 ){
		sprintf(upath,"%s://%s:%d",Rproto,Rhost,*Rportp);
		Strins(AVStr(url),upath);
		strcpy(REMOTE_PROTO,Rproto);
		strcpy(REMOTE_HOST,Rhost);
		REMOTE_PORT = *Rportp;
		HostPort(AVStr(upath),"http",rhost,rport);
		scan_DELEGATE(Conn,upath);
		DONT_REWRITE = 0;
	}

	strcpy(Rproto,rproto);
	strcpy(Rhost,rhost);
	*Rportp = rport;

	if( localPathProto(rproto) )
		if( streq(rhost,"localhost") || rhost[0] == 0 )
			ToMyself = 1;

	return 1;
}

void makeVia(Connection *Conn,PVStr(via));
int NotifyPlatform(Connection *Conn,int isreq);
int HTTP_genVia(Connection *Conn,int isreq,PVStr(via))
{	CStr(host,MaxHostNameLen);
	CStr(uname,256);
	CStr(myid,256);

	makeVia(Conn,AVStr(host));
	if( *host == 0 ){
		setVStrEnd(via,0);
		return 0;
	}
	sprintf(myid,"DeleGate/%s",DELEGATE_ver());

	if( Uname(AVStr(uname)) == 0 )
	if( NotifyPlatform(Conn,isreq) )
		Xsprintf(TVStr(myid)," on %s",uname);
	sprintf(via,"%s %s (%s)",MY_HTTPVER,host,myid);
	return 1;
}
void FTPHTTP_genPass(PVStr(pass))
{
	sprintf(pass,"%s(FTP/HTTP-DeleGate/%s)",
		DELEGATE_ADMIN,DELEGATE_ver());
}

/*
int HTTP_selfExpired(FILE *cachefp)
*/
#define getFV(str,fld,buf) getFieldValue2(str,fld,AVStr(buf),sizeof(buf))
int HTTP_selfExpiredX(FILE *cachefp,PCStr(head))
{	int expired;
	const char *found;
	CStr(sdate,256);
	CStr(pragma,256);
	int expires,now;
	CStr(stat,32);
	int statcode;

	if( head == 0 )
	if( cachefp == NULL )
		return 0;

	expired = 0;
	if( head ){
		found = getFV(head,"Pragma",pragma);
	}else
	found = fgetsHeaderField(cachefp,"Pragma",AVStr(pragma),sizeof(pragma));
	if( found != NULL && strstr(pragma,"no-cache") ){
		sv1log("EXPIRES: Pragma: %s\n",pragma);
		return 1;
	}

	if( head ){
		found = getFV(head,"Expires",sdate);
	}else
	found = fgetsHeaderField(cachefp,"Expires",AVStr(sdate),sizeof(sdate));
	expires = 0;
	if( found != NULL ){
		now = time(0);
		expires = scanHTTPtime(sdate);
		if( expires <= now )
			expired = 1;
		sv1log("EXPIRES: %d > %d ? %s\n",now,expires,sdate);
	}

	if( expired )
		return expired;

	if( head ){
		sscanf(head,"%*s %d",&statcode);
	}else{
	stat[0] = 0;
	fgets(stat,sizeof(stat),cachefp);
	fseek(cachefp,0,0);
	statcode = 0;
	sscanf(stat,"%*s %d",&statcode);
	}

	if( (HTTP_cacheopt & CACHE_302) == 0 )
	if( expires == 0 && statcode == 302 ){
		/* regard 302 without Expires: as beeing expired */
		return 1;
	}

	return expired;
}
int HTTP_ContLengOk(FILE *cachefp)
{	CStr(Leng,128);
	int ok,off,leng,hsize,bsize;

	if( cachefp == NULL )
		return 0;

	ok = 0;
	off = ftell(cachefp);
	if( fgetsHeaderField(cachefp,"Content-Length",AVStr(Leng),sizeof(Leng)) ){
		leng = atoi(Leng);
		RFC821_skipheader(cachefp,NULL,NULL);
		hsize = ftell(cachefp);
		fseek(cachefp,0,2);
		bsize = ftell(cachefp) - hsize;
		if( bsize == leng )
			ok = 1;
		else	sv1log("#### wrong Content-Length: %d -> %d\n",
				leng,bsize);
	}
	fseek(cachefp,off,0);
	return ok;
}
int HTTP_getLastModInCache(PVStr(scdate),int size,FILE *cachefp,PCStr(cpath))
{	FILE *hfp;
	int off;
	const char *found;

	off = -1;

	if( cachefp ){
		off = ftell(cachefp);
		fseek(cachefp,0,0);
		hfp = cachefp;
	}else	hfp = fopen(cpath,"r");

	if( hfp != NULL ){
		found = fgetsHeaderField(hfp,"Last-Modified",AVStr(scdate),size);
		if( hfp == cachefp )
			fseek(cachefp,off,0);
		else	fclose(hfp);

		if( found != NULL ){
			Verbose("original Last-Modified: %s\n",scdate);
			return scanHTTPtime(scdate);
		}
	}
	return 0;
}
int HTTP_genLastMod(PVStr(scdate),int size,FILE *cachefp,PCStr(cpath))
{	int ncdate;

	if( cachefp )
		ncdate = file_mtime(fileno(cachefp));
	else	ncdate = File_mtime(cpath);

	StrftimeGMT(AVStr(scdate),size,TIMEFORM_RFC822,ncdate,0);
	sv1log("generated Last-Modified[%x]: %s\n",p2i(cachefp),scdate);
	return ncdate;
}
int HTTP_getLastMod(PVStr(scdate),int size,FILE *cachefp,PCStr(cpath))
{	int ncdate;

	if( ncdate = HTTP_getLastModInCache(AVStr(scdate),size,cachefp,cpath) )
		return ncdate;
	else	return HTTP_genLastMod(AVStr(scdate),size,cachefp,cpath);
}

#define MaxAuthFieldLen 4*1024

extern const char *HTTP_passesc;
int HTTP_decompAuthX(PCStr(auth),PVStr(atype),int atsiz,PVStr(aval),int avsiz,AuthInfo *ident);
int HTTP_decompAuth(PCStr(auth),PVStr(atype),int atsiz,PVStr(aval),int avsiz)
{
	return HTTP_decompAuthX(auth,BVStr(atype),atsiz,BVStr(aval),avsiz,NULL);
}

int HTTP_decompAuthX(PCStr(auth),PVStr(atype),int atsiz,PVStr(aval),int avsiz,AuthInfo *ident)
{	const char *cp;
	CStr(xaval,1024);
	/*
	CStr(authb,1024);
	*/
	CStr(authb,MaxAuthFieldLen);
	int nesc;

	setVStrEnd(aval,0);
	setVStrEnd(atype,0);
	RFC822_valuescan(auth,AVStr(authb),sizeof(authb));
	auth = authb;
	cp = wordscanX(auth,AVStr(atype),atsiz);
	if( ident )
		wordScan(atype,ident->i_atyp);
	if( *cp == 0 ){
		if( *atype == 0 )
			return 0;
		else	return 1;
	}
	if( strcasecmp(atype,"basic") == 0 ){
		wordscanX(cp,AVStr(xaval),sizeof(xaval));
		str_from64(xaval,strlen(xaval),AVStr(aval),avsiz);
		if( ident ){
			scan_field1(aval,
				AVStr(ident->i_user),sizeof(ident->i_user),
				AVStr(ident->i_pass),sizeof(ident->i_pass));
		}
		if( url_escapeX(aval,AVStr(aval),avsiz,"%S\"'<>","^:") ){
			wordscanY(aval,AVStr(xaval),sizeof(xaval),"^:");
			sv1log("WARNING: escaped Authorization [%s]\n",xaval);
		}
		if( HTTP_passesc )
		if( nesc = url_escapeX(aval,AVStr(aval),avsiz,HTTP_passesc,"") ){
			sv1log("WARNING: escaped Authorization (%d) by %s:%s\n",
				nesc,"HTTPCONF=passesc",HTTP_passesc);
		}
	}
	else
	if( strcaseeq(atype,"Digest") ){
		scanDigestParams(cp,ident,BVStr(aval),avsiz);
	}
	else
	if( strcaseeq(atype,"Negotiate")
	 || strcaseeq(atype,"NTLM")
	){
		if( ident ){
			if( ident->i_path ){
			strcpy(ident->i_path,cp);
			}
		}
	}
	else{
		return 1;
	}
	return 2;
}

int HTTP_auth2ident(Connection *Conn,PCStr(auth),AuthInfo *ident,int decomp){
	CStr(atype,128);
	/*
	CStr(dauth,1024);
	*/
	CStr(dauth,MaxAuthFieldLen);
	const char *dp;

	if( auth[0] == 0 )
		return 0;

	if( HTTP_decompAuthX(auth,AVStr(atype),sizeof(atype),AVStr(dauth),sizeof(dauth),ident) < 2 )
		return 0;

	scan_namebody(dauth,
		AVStr(ident->i_user),sizeof(ident->i_user),":",
		AVStr(ident->i_pass),sizeof(ident->i_pass),"\r\n");
	if( strcaseeq(atype,"Digest") ){
		wordScan(REQ_METHOD,ident->i_meth);
	}
	if( CurEnv && NTHT_user[0] ){
		strcpy(ident->i_user,NTHT_user);
	}
	if( decomp ){
		if( dp = strrchr(ident->i_user,'@') ){
			truncVStr(dp);
			wordScan(dp+1,ident->i_Host);
		}
	}
	return 1;
}

char *HTTP_originalRequestField(Connection *Conn,PCStr(fname),PVStr(buff),int bsize);
int HTTP_getAuthorizationX(Connection *Conn,int proxy,AuthInfo *ident,int decomp,PCStr(aauth));
int HTTP_getAuthorization(Connection *Conn,int proxy,AuthInfo *ident,int decomp)
{
	return HTTP_getAuthorizationX(Conn,proxy,ident,decomp,0);
}
int HTTP_getAuthorizationX(Connection *Conn,int proxy,AuthInfo *ident,int decomp,PCStr(aauth))
{	const char *field;
	/*
	CStr(auth,1024);
	*/
	CStr(auth,MaxAuthFieldLen);

	bzero(ident,sizeof(AuthInfo));
	if( decomp & 4 ){ /* getting Digest uri= or NTLM challenge */
		decomp &= ~ 4;
		if( STX_uri == 0 ){
			setQStr(STX_uri,malloc(MaxAuthFieldLen),MaxAuthFieldLen);
		}else{
		}
		cpyQStr(ident->i_path,STX_uri);
	}
	auth[0] = 0;
	if( proxy )
		field = "Proxy-Authorization";
	else	field = "Authorization";
	if( aauth ){
		strcpy(auth,aauth);
	}else
	if( decomp & 2 ){
		decomp &= ~2;
		HTTP_originalRequestField(Conn,field,AVStr(auth),sizeof(auth));
	}else
	HTTP_getRequestField(Conn,field,AVStr(auth),sizeof(auth));
	if( auth[0] == 0 )
		ident->i_error |= AUTH_ENOAUTH;
	if( HTTP_auth2ident(Conn,auth,ident,decomp) )
		return 1;

/*
	if( ClientAuth.i_stat == AUTH_SET ){
		*ident = ClientAuth;
	}
*/
	return 0;
}
int HTTP_getAuthorization2(Connection *Conn,AuthInfo *ident,int decomp)
{	int ratype;

	ratype = 0;
	if( HTTP_getAuthorization(Conn,0,ident,decomp) )
		ratype = 1;
	else
	if( HTTP_getAuthorization(Conn,1,ident,decomp) )
		ratype = 2;
	return ratype;
}
int HTTP_authuserpass(Connection *Conn,PVStr(auth),int size)
{	AuthInfo ident;
	int ratype;

	setVStrEnd(auth,0);
	if( ratype = HTTP_getAuthorization2(Conn,&ident,0) )
		sprintf(auth,"%s:%s",ident.i_user,ident.i_pass);
	return ratype;
}
int HTTP_forgedAuthorization(Connection *Conn,PCStr(fields))
{	const char *auth;
	CStr(atype,128);
	CStr(aval,256);
	const char *dp;
	CStr(host,MaxHostNameLen);

	auth = findFieldValue(fields,"Authorization");
	if( auth == 0 )
		return 0;

	HTTP_decompAuth(auth,AVStr(atype),sizeof(atype),AVStr(aval),sizeof(aval));

	if( dp = strrchr(aval,'/') ){
		gethostname(host,sizeof(host));
		if( strcmp(dp+1,host) == 0 ){
			sv1log("!!!! FORGED Authorization !!!!! [%s]\n",aval);
			return 1;
		}
	}

	return 0;
}
int HTTP_proxyAuthorized(Connection *Conn,PCStr(req),PCStr(fields),int pauth,FILE *tc)
{	AuthInfo ident;
	int vno,totalc;

	if( HTTP_getAuthorization(Conn,pauth,&ident,0) ){
		int rcode;
		if( rcode = doAuth(Conn,&ident) ){
			if( 0 < rcode ){
				ClientAuth = ident;
				if( service_permitted2(Conn,DST_PROTO,1) )
					return 1;
				ClientAuthUser[0] = 0;
			}
			return 0;
		}
	}
	if( HTTP_getAuthorization(Conn,pauth,&ident,1) ){
		MrefQStr(host,ident.i_Host); /**/
		const char *user; /**/
		const char *pass; /**/
		host = ident.i_Host;
		user = ident.i_user;
		pass = ident.i_pass;
		if( user[0] != 0 ){
			if( host[0] == 0 )
				strcpy(host,"localhost");
			ClientAuth = ident;
			if( service_permitted2(Conn,DST_PROTO,1) ){
				if( 0 <= Authenticate(Conn,host,user,pass,"/") )
					return 1;
			}
			ClientAuthUser[0] = 0;
		}
		sv1log("Not Authorized: user=[%s]@[%s]\n",user,host);
	}else	sv1log("No Authorization\n");
	return 0;
}


int ClientIfModClock(Connection *Conn)
{
	return	ClntIfModClock;
}

int HTTP_getreq(Connection *Conn,FILE *req){
	if( CurEnv ){
		fputs(REQ,req);
		fputs(REQ_FIELDS,req);
	}
	return 0;
}
char *HTTP_originalRequest(Connection *Conn,PVStr(req))
{
	if( OREQ[0] )
		paramscanX(OREQ,"",AVStr(req),URLSZ);
	else	setVStrEnd(req,0);
	return (char*)req;
}
int HTTP_originalURLx(Connection *Conn,PVStr(url),int siz)
{	HttpRequest reqx;

	if( OREQ[0] ){
		decomp_http_request(OREQ,&reqx);
		QStrncpy(url,reqx.hq_url,siz);
		return reqx.hq_vno;
	}else	return 0;
}
int HTTP_original_H(Connection *Conn,PVStr(host)){
	CStr(hp,MaxHostNameLen);
	int port = 0;

	truncVStr(host);
	if( CurEnv == 0 ){
		return 0;
	}
	if( OREQ[0] ){
		HTTP_originalRequestField(Conn,"Host",AVStr(hp),sizeof(hp));
		port = scan_hostport(CLNT_PROTO,hp,BVStr(host));
		return port;
	}
	return ClientIF_H(Conn,BVStr(host));
}
/* url-path part if exists, canonical with leading "/" */
int urlPath(PCStr(url),PVStr(path)){	
	strcpy(path,url);
	if( path[0] == '/' ){
		return 1;
	}
	strip_urlhead(AVStr(path),VStrNULL,VStrNULL);
	if( path[0] == '/' ){
		return 2;
	}
	clearVStr(path);
	return 0;
}
int HTTP_originalURLPath(Connection *Conn,PVStr(path))
{	CStr(url,URLSZ);

	if( HTTP_originalURLx(Conn,AVStr(url),sizeof(url)) ){
		if( url[0] != '/' )
			strip_urlhead(AVStr(url),VStrNULL,VStrNULL);

/*
		if( url[0] == '/' && url[1] != '/' ){
This originalURLPath() function is introduced in 2.8.14 just for NNTP/HTTP
(thus URLpath starting with "//" can be bad ?) which is removed at 2.8.19.
So this restriction seems be meaningless and harmful.
*/
		if( url[0] == '/' ){
			wordscanX(url,BVStr(path),1024);
			return 1;
		}
	}
	setVStrEnd(path,0);
	return 0;
}
int HTTP_originalURLmatch(Connection *Conn,PCStr(urlc))
{	const char *url;
	const char *up;
	int leng;

	if( OREQ[0] ){
		leng = strlen(urlc);
		if( url = strpbrk(OREQ," \t") ){
			while( *url == ' ' || *url == '\t' )
				url++;

			if( up = URL_toMyself(Conn,url) )
				url = up;
			if( up = URL_toMyself(Conn,urlc) )
				urlc = up;

			if( strncmp(url,urlc,leng) == 0 )
			if( url[leng] == 0 || strchr(" \t\r\n",url[leng]) )
				return 1;
		}
	}
	return 0;
}
static int getModifier(Connection *Conn,PVStr(mod))
{	
	if( mod )
		strcpy(mod,Modifier);
	return strlen(Modifier);
}
int HTTP_echoRequestHeader(Connection *Conn,FILE *tc)
{	const char *sp;
	char ch;
	int leng = 0;
	CStr(modifiers,512);

	if( !EchoRequest )
		return 0;
	if( !CurEnv )
		return 0;
	if( !HTTP_reqWithHeader(Conn,REQ) )
		return 0;

	fputs("X-Request-Original: ",tc);
	fputs(OREQ,tc);
	if( strstr(OREQ,"\n") == NULL )
		fputs("\r\n",tc);

	if( getModifier(Conn,AVStr(modifiers)) )
		fprintf(tc,"X-Modifier: %s\r\n",modifiers);

	fputs("X-Request: ",tc);
	fputs(REQ,tc);
	leng += strlen("X-Request: ") + strlen(REQ);

	sp = REQ_FIELDS;
	while( ch = *sp ){
		if( ch == '\r' || ch == '\n' )
			break;
		fputs("X-Request-",tc);
		leng += strlen("X-Request-");

		while( ch = *sp ){
			sp++;
			putc(ch,tc);
			leng++;
			if( ch == '\n' && !(*sp == ' ' || *sp == '\t') )
				break;
		}
	}
	return leng;
}
void originalHost(Connection *Conn,PVStr(host))
{
}
char *HTTP_originalRequestField(Connection *Conn,PCStr(fname),PVStr(buff),int bsize)
{	const char *ffname;
	const char *ffbody;

	setVStrEnd(buff,0);
	if( CurEnv ){
		if( ffname = findField(OREQ_MSG,fname,&ffbody) ){
			RFC822_valuescan(ffbody,AVStr(buff),bsize);
			return (char*)buff;
		}
	}
	return 0;
}
char *HTTP_getRequestField(Connection *Conn,PCStr(fname),PVStr(buff),int bsize)
{	const char *ffname;
	const char *ffbody;

	setVStrEnd(buff,0);
	if( CurEnv == 0 )
		return 0;

	if( strcmp(fname,"*") == 0 ){
		QStrncpy(buff,CurEnv->r_fields,bsize);
		return (char*)buff;
	}
	if( CurEnv->r_lastFname ){
		const char *lfname;
		int fnlen;
		lfname = CurEnv->r_lastFname;
		fnlen = strlen(fname);

		/* BUG: this header cache should be cleared when
		 * the header buffer is modified ...
		 */
		if( strncasecmp(lfname,fname,fnlen) == 0 )
		if( lfname[fnlen] == ':' && lfname[fnlen+1] == ' ' )
		if( &lfname[fnlen+2] == CurEnv->r_lastFbody ){
			linescanX(CurEnv->r_lastFbody,AVStr(buff),bsize);
			return (char*)buff;
		}
	}
	if( ffname = findField(CurEnv->r_fields,fname,&ffbody) ){
		RFC822_valuescan(ffbody,AVStr(buff),bsize);
		CurEnv->r_lastFname = (char*)ffname;
		CurEnv->r_lastFbody = (char*)ffbody;
		return (char*)buff;
	}
	return 0;
}
void HTTP_delRequestField(Connection *Conn,PCStr(fname))
{
	rmField(AVStr(REQ_FIELDS),fname);
	CurEnv->r_lastFname = NULL;
}
int HTTP_putRequest(Connection *Conn,FILE *fp)
{	int len = 0;

	if( CurEnv == 0 )
		return 0;

	len += strlen(CurEnv->r_req);
	fputs(CurEnv->r_req,fp);
	len += strlen(CurEnv->r_fields);
	fputs(CurEnv->r_fields,fp);
	return len;
}
void HTTP_scanAcceptCharcode(Connection *Conn,PVStr(field))
{	const char *value;
	const char *pp;
	const char *vp;
	const char *dp;
	CStr(code,256);
	CStr(buff,256);
	CStr(param,32);
	CStr(orgval,256);
	CStr(remmark,256);

	remmark[0] = 0;

	if( value = strchr(field,':') ){
		value++;
		while( *value == ' ' || *value == '\t' )
			value++;
		if( *value == 0 || *value == '\r' || *value == '\n' )
			return;
	}else	return;

	orgval[0] = 0;
	lineScan(value,orgval);

	while( pp = strstr(value,"(pragma=") ){
		strcat(remmark,"#"); /* indicate stuff removed */
		vp = pp + 8;
		if( strstr(vp,"thru)") == vp )
			RelayTHRU = 1;
		else
		if( strstr(vp,"no-cache)") == vp ){
			DontReadCache = 1;
			DontWriteCache = 1;
		}
		if( dp = strchr(pp,')') )
			ovstrcpy((char*)pp,dp+1);
		else	break;
	}

	if( (pp = strstr(value,"charcode="))
	 || (pp = strstr(value,"charset="))
	 || (pp = strstr(value,"charconv-")) ){
/*
		UTag *uv[3],ub[4];
*/
		UTag *uv[4],ub[3];
		CStr(del,4);
		strcat(remmark,"#"); /* indicate stuff removed */
		uvinit(uv,ub,3);
		uvfromsf(pp,0,"%[a-zA-Z]%[-=]%[-0-9a-zA-Z_/]",uv);
		Utos(uv[0],param);
		Utos(uv[1],del);
		Utos(uv[2],code);
		sv1log("HTTP %s%s%s\n",param,del,code);
		CCXcreate("*",code,CCX_TOCL);
		Conn->cl_setccx = 1;
		dp = pp+strlen(param)+strlen(del)+strlen(code);
		if( *dp == ';' )
			dp++;
		ovstrcpy((char*)pp,dp);
	}
	while( pp = strstr(value,"()") )
		ovstrcpy((char*)pp,pp+2);
	if( strncmp(value,"()",2) == 0 )
		value += 2;

	if( *value == 0 || *value == '\r' || *value == '\n' )
		setVStrEnd(field,0);

	if( AcceptLanguages ){
		Xassert(AVStr(AcceptLanguages),strtail(AcceptLanguages)+2+strlen(orgval)+strlen(remmark));
		if( AcceptLanguages[0] != 0 ) 
			strcat(AcceptLanguages,", ");
		strcat(AcceptLanguages,orgval);
		if( remmark[0] )
			strcat(AcceptLanguages,remmark);
	}
}

static scanListFunc add_method1(PCStr(method),Method *methodv,int mx)
{	int mi,del;
	const char *m1;

	if( methodv == NULL )
		return -1;

	if( *method == '-' ){
		method++;
		del = 1;
	}else	del = 0;
	for( mi = 0; mi < mx-1 && (m1 = methodv[mi].m_name); mi++ ){
		if( strcaseeq(method,m1) ){
			if( del ){
				for(;;mi++){
					methodv[mi] = methodv[mi+1];
					if( methodv[mi].m_name == NULL )
						break;
				}
			}
			goto EXIT;
		}
		if( del )
		if( strcaseeq(method,methodv[mi].m_class) ){
			methodv[mi].m_name = "-";
		}
	}
	if( !del ){
	    if( mi < mx-1 ){
		methodv[mi].m_name = method;
		methodv[mi].m_class = "";
		methodv[mi+1].m_name = 0;
	    }
	}
EXIT:
	return 0;
}
static int getMethods(Connection *Conn,Method *methodv,PVStr(methods))
{	int mi;
	const char *m1;
	refQStr(mp,methods); /**/

	if( methodv != NULL ){
		for( mi = 0; m1 = methodv[mi].m_name; mi++ ){
			if( mp != methods )
				setVStrPtrInc(mp,',');
			strcpy(mp,m1);
			mp += strlen(mp);
		}
	}
	XsetVStrEnd(AVStr(mp),0);
	return 0;
}
int HTTP_allowMethods(Connection *Conn,PVStr(methods))
{
	if( allowMethodV )
	return getMethods(Conn,allowMethodV,AVStr(methods));
	else
	return getMethods(Conn,validMethods,AVStr(methods));
}
void HTTP_setMethods(PCStr(methods))
{	CStr(methodb,1024);
	int mi;
	int mx = 64;

	if( strcmp(methods,"*") == 0 ){
		allowAnyMethods = 1;
		return;
	}

	allowMethodV = (Method*)StructAlloc(sizeof(Method)*mx);
	for( mi = 0; validMethods[mi].m_name; mi++ )
		allowMethodV[mi] = validMethods[mi];
	allowMethodV[mi].m_name = 0;

	if( methods[0] == '+' && methods[1] == ',' ){
		methods += 2;
	}else
	if( methods[0] == '+' && methods[1] == 0 ){
		methods += 1;
	}else
	if( methods[0] == '-' ){
	}else{
		allowMethodV[0].m_name = 0;
	}
	scan_commaList(methods,1,scanListCall add_method1,allowMethodV,mx);
	getMethods(NULL,allowMethodV,AVStr(methodb));
	sv1log("HTTPCONF=methods:%s\n",methodb);
}
static int isMethod(Method *methodv,PCStr(method))
{	int mi;
	const char *m1;
	const char *mp;
	char mc;

	for( mi = 0; m1 = methodv[mi].m_name; mi++ ){
		mp = method;
		while( *m1 && *mp == *m1 ){
			mp++;
			m1++;
		}
		if( *m1 == 0 ){
			mc = *mp;
			if( mc==0||mc==' '||mc=='\t'||mc=='\r'||mc=='\n' )
				return 1;
		}
	}
	return 0;
}
int HTTP_isMethod(PCStr(method))
{
	if( lHTTPACCEPT() && strneq(method,"ACCEPT",6) ){
		return 1;
	}
	if( allowMethodV && isMethod(allowMethodV,method) )
		return 1;
	else	return isMethod(validMethods,method);
}
int HTTP_allowMethod1(Connection *Conn,PCStr(req))
{	int ok;

	if( lHTTPACCEPT() && strneq(req,"ACCEPT",6) ){
		return 1;
	}
	if( allowMethodV )
		ok = isMethod(allowMethodV,req);
	else	ok = isMethod(validMethods,req);
	if( !ok ){
		if( acceptableRequest(req) )
			ok = 1;
	}
	return ok;
}

int HTTP_methodWithoutBody(PCStr(method))
{
	return strcasecmp(method,"GET")==0 || strcasecmp(method,"HEAD")==0;
}
int HTTP_methodWithBody(PCStr(method))
{
	return !HTTP_methodWithoutBody(method);
}
int HTTP_methodWithoutRespBody(PCStr(method))
{
	return strcasecmp(method,"HEAD")==0;
}

void resetHTTPenv(Connection *Conn,HTTP_env *he);
void setHTTPenv(Connection *Conn,HTTP_env *he)
{
	Conn->cl_reqbuf = (void*)he;
	if( he == NULL )
		return;
	Conn->cl_reqbufsize = sizeof(HTTP_env);

	resetHTTPenv(Conn,he);

	he->r_reqx.hq_method[0] = 0;
	he->r_httpConn[0] = 0;
	he->r_get_cache = 0;
	he->r_iconBase[0] = 0;
}
void resetHTTPenv(Connection *Conn,HTTP_env *he)
{
	he->r_oreqmsg[0] = 0;
	he->r_oreqlen = 0;
	he->r_oreqbodyoff = 0;
	he->r_oreq[0] = 0;
	setVStrEnd(he->r_ohost.ut_addr,0);
	he->r_oport = 0;
	he->r_vhost[0] = 0;

	he->r_req[0] = 0;
	he->r_reqx.hq_url[0] = 0;
	he->r_reqx.hq_ver[0] = 0;
	he->r_reqx.hq_vno = 0;

	he->r_fields[0] = 0;
	he->r_lastFname = 0;
	he->r_lastFbody = 0;

	setVStrEnd(he->r_acclangs.ut_addr,0);

	he->r_clntIfmod[0] = 0;
	he->r_clntIfmodClock = 0;

	he->r_flushhead = 0;
	he->r_flushsmall = 0;

	he->r_withCookie = 0;
	he->r_appletFilter = 0;
	he->r_dgCookie[0] = 0;
	he->r_clntAccChunk = 0;

	he->r_resp.r_code = 0;
	he->r_resp.r_sav = 0;
	setVStrEnd(he->r_resp.r_msg.ut_addr,0);
	he->r_resp.r_len = 0;
	he->r_resp.r_msgfp = 0;
	he->r_resp_add[0] = 0;
	he->r_doUnzip = 0;
	he->r_doZip = 0;
	he->r_reqAsis = 0;

	he->r_NOJAVA = 0;
}
int HTTP_decompRequest(Connection *Conn)
{
	REQ_VNO = decomp_http_request(REQ,&REQX);
	RespWithBody = !HTTP_methodWithoutRespBody(REQ_METHOD);
	strcpy(RequestMethod,REQ_METHOD);
	return REQ_VNO;
}
int decomp_http_request(PCStr(req),HttpRequest *reqx)
{	const char *dp;
	int vmaj,vmin;

	reqx->hq_method[0] = 0;
	reqx->hq_url[0] = 0;
	reqx->hq_ver[0] = 0;
	reqx->hq_vno = 0;
	reqx->hq_flags = 0;

	if( strpbrk(req," \t") == NULL )
		return 0;

	if( !HTTP_isMethod(req) )
	if( !acceptableRequest(req) )
		return 0;

	dp = wordScan(req,reqx->hq_method);
	dp = wordScan(dp,reqx->hq_url);
	if( reqx->hq_url[0] != '/' && reqx->hq_url[0] != '*' )
		reqx->hq_flags |= HQF_ISPROXY;

	vmaj = 0;
	vmin = 9;

	while( *dp == ' ' || *dp == '\t' )
		dp++;
	if( strncmp(dp,"HTTP/",5) == 0 )
		sscanf(dp+5,"%d.%d",&vmaj,&vmin);

	sprintf(reqx->hq_ver,"%d.%d",vmaj,vmin);
	reqx->hq_vno = vmaj*100 + vmin;
	return reqx->hq_vno;
}
int HTTP_reqIsHTTP(Connection *Conn,PCStr(req))
{	HttpRequest reqx;

	if( CurEnv == NULL || req != REQ )
		return HTTP_isMethod(req);
	else
	if( REQ_VNO != 0 )
		return REQ_VNO;
	else	return REQ_VNO = decomp_http_request(req,&reqx);
}
int HTTP_reqWithHeader(Connection *Conn,PCStr(req))
{	HttpRequest reqx;

	if( CurEnv == NULL || req != REQ )
		return 100 <= decomp_http_request(req,&reqx);
	else	return 100 <= HTTP_reqIsHTTP(Conn,REQ);
}

static void forwardUserinfo(Connection *Conn,PVStr(hostport))
{	const char *dp;
	CStr(user,64);
	CStr(pass,64);
	CStr(userpass,256);
	CStr(b64,256);
	CStr(auth,256);
	CStr(server,MaxHostNameLen);

	if( strchr(REAL_SITE,'@') == 0 )
		return;

	dp = wordscanY(REAL_SITE,AVStr(user),sizeof(user),"^:@");
	if( *user == 0 )
		return;

	sprintf(server,"%s@%s",user,hostport);
	strcpy(hostport,server);

	if( *dp == ':' ){
		wordscanY(dp+1,AVStr(pass),sizeof(pass),"^@");
		sprintf(userpass,"%s:%s",user,pass);
		str_to64(userpass,strlen(userpass),AVStr(b64),sizeof(b64),1);
		sprintf(auth,"Authorization: Basic %s\r\n",b64);
		RFC822_addHeaderField(AVStr(REQ_FIELDS),auth);
	}
}
void makeProxyRequest(Connection *Conn)
{	HttpRequest reqx;
	CStr(hostport,MaxHostNameLen);

	decomp_http_request(REQ,&reqx);
	if( reqx.hq_url[0] == '/' ){
		if( IsMounted && MountOptions
		/*
		 && getOpt1(MountOptions,"genvhost",AVStr(hostport)) ){
		*/
		 && getOpt1Vserv(Conn,MountOptions,AVStr(hostport)) ){
			/* forward with "proto://vhost" to the PROXY */
		}else
		if( lORIGDST() ){
			/* 9.9.6 for SERVER=http://odst.-:- */
			HTTP_ClientIF_HP(Conn,AVStr(hostport));
		}else
		HostPort(AVStr(hostport),DST_PROTO,DST_HOST,DST_PORT);
		forwardUserinfo(Conn,AVStr(hostport));
		sprintf(REQ,"%s %s://%s%s HTTP/%s\r\n",reqx.hq_method,
			DST_PROTO,hostport,reqx.hq_url,reqx.hq_ver);
		sv1log("#PROXY REQUEST = %s",REQ);
	}
}

int isMovedToSelf(Connection *Conn,PCStr(line))
{	CStr(base,URLSZ);
	CStr(movedto,URLSZ);

	lineScan(line,movedto);
	if( HTTP_originalURLx(Conn,AVStr(base),sizeof(base)) && strstr(base,":") ){
		if( streq(base,movedto) )
			return 1;

		/* should check IP-address and HOST-name matching ... */
	}
	return 0;
}
int isMovedToAnotherServer(Connection *Conn,PCStr(line))
{	CStr(movedto,URLSZ);
	CStr(proto,128);
	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	int port;

	lineScan(line,movedto);
	decomp_absurl(movedto,AVStr(proto),AVStr(hostport),VStrNULL,0);
	port = scan_Hostport1p(proto,hostport,host);

	if( strcasecmp(proto,DST_PROTO) == 0
	 && port == DST_PORT
	 && hostcmp(host,DST_HOST) == 0 )
		return 0;

	sv1log("Moved to another server [%s://%s:%d] -> [%s://%s:%d]\n",
		DST_PROTO,DST_HOST,DST_PORT,proto,host,port);
	return 1;
}

int HTTP_getICPurl(Connection *Conn,PVStr(url))
{	CStr(hostport,MaxHostNameLen);
	const char *upath;
	int ulen;

	if( strcmp(CLNT_PROTO,"http") != 0 )
		return -1;

	if( strncasecmp(REQ,"GET ",4) != 0
	 /* && strncasecmp(REQ,"HEAD ",5) != 0 */ )
	{
		return -1;
	}

	upath = strchr(REQ,' ');
	if( upath == NULL ){
		return -1;
	}
	if( 256 < strlen(upath) ){
		return -1;
	}
	if( strchr(REQ,'?') ){
		return -1;
	}

	upath++;
	if( *upath == '/' || strchr(" \t\r\n",*upath) ){
		upath++;
		HostPort(AVStr(hostport),DST_PROTO,DST_HOST,DST_PORT);
		sprintf(url,"%s://%s/",DST_PROTO,hostport);
		if( strchr(" \t\r\n",*upath) == NULL ){
			ulen = strlen(url);
			wordscanX(upath,QVStr(url+ulen,url),256);
		}
	}else{
		wordscanX(upath,AVStr(url),256);
	}
	return 0;
}

void HTTP_fprintmsgX(Connection *Conn,FILE *fp,PCStr(fmt),int opts);
void HTTP_fprintmsg(Connection *Conn,FILE *fp,PCStr(fmt))
{
	HTTP_fprintmsgX(Conn,fp,fmt,0);
}
void HTTP_fprintmsgX(Connection *Conn,FILE *fp,PCStr(fmt),int opts)
{	const char *mp;
	const char *np;
	CStr(line,1024);
	CStr(name,1024);
	CStr(type,1024);
	const char *msg;
	int fnlen;

	if( streq(fmt,"om") )
		msg = OREQ_MSG;
	else
	if( streq(fmt,"ol") )
		msg = OREQ;
	else	msg = "";

	for( mp = msg; *mp; mp = np ){
		lineScan(mp,line);
		if( strncasecmp(mp,"Proxy-Authorization:",fnlen=20)==0
		 || strncasecmp(mp,"Authorization:",      fnlen=14)==0 ){
			Xstrcpy(DVStr(line,fnlen)," ******");
		}
		if( opts ){
			CStr(xl,4*1024);
			if( encodeEntitiesXX(line,AVStr(xl),sizeof(xl),opts) ){
				strcpy(line,xl);
			}
		}
		HTML_put1s(fp,"%s\r\n",line);
		if( np = strchr(mp,'\n') )
			np++;
		else	break;
	}
}
void HTTP_editResponseHeader(Connection *Conn,FILE *tc)
{	const char *rhead;
	CStr(name,256);
	CStr(body,256);

	if( IsMounted && MountOptions ){
		if( rhead = strstr(MountOptions,"rhead=+") ){
			scan_namebody(rhead+7,AVStr(name),sizeof(name),":",AVStr(body),sizeof(body),",");
			fprintf(tc,"%s: %s\r\n",name,body);
		}
	}
}
int decomp_http_status(PCStr(stat),HttpResponse *resx)
{	const char *sp;
	int rcode;

	resx->hr_ver[0] = 0;
	resx->hr_reason[0] = 0;

	if( !STRH(stat,F_HTTPVER) ){
		rcode = 1200;
	}else{
		sp = wordScan(stat,resx->hr_ver);
		if( *sp == ' ' ) sp++;
		if( sp = scanint(sp,&rcode) ){
			lineScan(sp,resx->hr_reason);
			if( rcode <= 0 )
				rcode = R_BROKEN_RESPONSE;
		}else{
			sv1log("ERROR: BROKEN STATUS LINE: %s",stat);
			rcode = R_BROKEN_RESPONSE;
		}
	}
EXIT:
	resx->hr_rcode = rcode;
	return rcode;
}

int CTX_codeconv_get(Connection *Conn,PCStr(ctype),const char **xcharset, int *p2h);
const char *HTTP_outCharset(Connection *Conn)
{	const char *xcharset;

	xcharset = 0;
	if( CCXactive(CCX_TOCL) )
		xcharset = CCXcharset(CCX_TOCL);
	else	CTX_codeconv_get(Conn,NULL,&xcharset,NULL);
	return xcharset;
}

/* The following stuff is for Mozillas older than 3.0.
 * Either flushHead or Keep-Alive:close is necessary to let their Keep-Alive
 * work properly.
 * - Keep-Alive:close is preferable because their performance by Keep-Alive
 *   with flushHead isn't so good.
 * - But flushHead is preferable when RTT is long...
 */
void HTTP_modifyConnection(Connection *Conn,int rlength)
{
	if( FlushIfSmall )
	if( rlength < 1024 )
		HTTP_clntClose(Conn,"o:old Mozilla");

	if( WillKeepAlive )
	if( Conn->xf_filters & (XF_FCL|XF_FTOCL) )
	/*
	if( HTTP_CKA_CFI && xxx ){
	}else
	*/
		if( lDONTHT() && (Conn->xf_filters & XF_FTOCL) == 0 ){
			sv1log("----NTHT Keep-Alive (B)\n");
		}else
		if( doKeepAliveWithSTLS(Conn) ){
			Verbose("Keep-Avlie with TLS (B)\n");
		}else
		HTTP_clntClose(Conn,"x:external filter");
}

/*
 * Digest Authentication Scheme
 */
void scanDigestParams(PCStr(cp),AuthInfo *ident,PVStr(aval),int avsiz)
{	CStr(user,64);
	/*
	CStr(realm,64);
	*/
	CStr(realm,128);
	CStr(resp,64);
	/*
	CStr(uri,512);
	*/
	CStr(uri,MaxAuthFieldLen);
	CStr(nonce,64);
	CStr(opaque,64);
	CStr(xaval,1024);
	const char *av[16]; /**/
	const char *a1;
	const char *dp;
	CStr(name,64);
	/*
	CStr(val,64);
	*/
	/*
	CStr(val,512);
	*/
	CStr(val,MaxAuthFieldLen);
	CStr(qop,64);
	CStr(cnonce,64);
	CStr(nc,64);
	int ac,ai;
	int stale = 0;

	user[0] = realm[64] = resp[0] = uri[64] = 0;
	/*
	ac = list2vect(cp,',',elnumof(av),av);
	*/
	ac = list2vectX(cp,',',STR_OVWR|STR_QUOTE,elnumof(av),av);
	for( ai = 0; ai < ac; ai++ ){
		a1 = av[ai];
		while( isspace(*a1) )
			a1++;
		dp = wordscanY(a1,AVStr(name),sizeof(name),"^=");
		if( *dp != '=' ){
			continue;
		}
		dp++;
		if( *dp == '"' )
			wordscanY(dp+1,AVStr(val),sizeof(val),"^\"");
		else	wordScan(dp,val);
		syslog_DEBUG("%s=%s\n",name,val);

		if( strcaseeq(name,"username") )
			strcpy(user,val);
		else
		if( strcaseeq(name,"response") )
			strcpy(resp,val);
		else
		if( strcaseeq(name,"realm") )
			strcpy(realm,val);
		else
		if( strcaseeq(name,"uri") )
			strcpy(uri,val);
		else
		if( strcaseeq(name,"nonce") )
			strcpy(nonce,val);
		else
		if( strcaseeq(name,"opaque") )
			strcpy(opaque,val);
		else
		if( strcaseeq(name,"stale") )
			stale = strcaseeq(val,"true");
		else
		if( strcaseeq(name,"qop") )
			strcpy(qop,val);
		else
		if( strcaseeq(name,"cnonce") )
			strcpy(cnonce,val);
		else
		if( strcaseeq(name,"nc") )
			strcpy(nc,val);
		else
		if( strcaseeq(name,"algorithm") ){
			if( !strcaseeq(val,"MD5") ){
				syslog_ERROR("#### ERROR %s=%s\n",name,val);
			}
		}
		else{
			/*
			syslog_ERROR("Unused param: %s\n",name);
			*/
			syslog_ERROR("Digest Auth. unused %s=%s\n",name,val);
		}
	}
	if( aval ){
		sprintf(xaval,"%s:%s",user,resp);
		QStrncpy(aval,xaval,avsiz);
	}
	if( ident ){
		/*
		lineScan(uri,ident->i_path);
		*/
		if( ident->i_path ){
			strcpy(ident->i_path,uri);
		}
		lineScan(realm,ident->i_realm);
		lineScan(nonce,ident->i_nonce);
		lineScan(opaque,ident->i_opaque);
		lineScan(qop,ident->i_qop);
		lineScan(cnonce,ident->i_cnonce);
		lineScan(nc,ident->i_nc);
		if( stale )
			ident->i_error |= AUTH_ESTALE;
	}
}

/*
 * clients which seem not capable of Digest Authentication
 */
int UAwithoutDigest(Connection *Conn)
{	const char *dp;

	if( vercmp(REQ_VER,"1.1") < 0 )
		return 1;
	if( dp = strstr(REQ_UA,"Mozilla/") ){
		if( dp[8] <= '4' )
			return 1;
	}
	return 0;
}
const char *HTTP_DigestOpaque(Connection *Conn)
{
	if( CurEnv && REQ_AUTH.i_opaque[0] )
		return REQ_AUTH.i_opaque;
	return 0;
}
int askDigestAuthX(Connection *Conn,int forced_realm,PCStr(realm),PVStr(digest),PCStr(req),AuthInfo *ident);
int askDigestAuth(Connection *Conn,int forced_realm,PCStr(realm),PVStr(digest))
{
	return askDigestAuthX(Conn,forced_realm,realm,BVStr(digest),REQ_URL,&REQ_AUTH);
}
int askDigestAuthX(Connection *Conn,int forced_realm,PCStr(realm),PVStr(digest),PCStr(req),AuthInfo *ident)
{	CStr(yrealm,1024);
	CStr(opaque,128);
	CStr(nonce,1024);

	/*
	if( UAwithoutDigest(Conn) ) and not via Basic/Digest gateway...
		return 0;
	*/

	/*
	if( !genDigestResp(Conn,&REQ_AUTH,AVStr(yrealm),REQ_URL,AVStr(nonce)) )
	*/
	if( !genDigestResp(Conn,ident,AVStr(yrealm),req,AVStr(nonce)) )
		return 0;

	if( !forced_realm && *yrealm ){
		realm = yrealm;
		Verbose("REALM> %s\n",realm);
	}
	/*
	wordScan(REQ_AUTH.i_opaque,opaque);
	*/
	wordScan(ident->i_opaque,opaque);
	genSessionID(Conn,AVStr(opaque),1);

	sprintf(digest,"Realm=\"%s\", nonce=\"%s\", opaque=\"%s\"",
		realm,nonce,opaque);

	/*
	if( REQ_AUTH.i_error & AUTH_ESTALE )
	*/
	if( ident->i_error & AUTH_ESTALE )
		strcat(digest,", stale=true");

	strcat(digest,", qop=\"auth\""); /* RFC2617 */

	return 1;
}

void genAuthDigest(Connection *Conn,PCStr(fname),PVStr(reqauth),int rsize,AuthInfo *seed,PCStr(user),PCStr(pass))
{	MemFile MemF; 
	MemFile *SMemF = &MemF;
	CStr(digest,64);
	int qop_auth;

	digest[0] = 0;
	if( qop_auth = streq(seed->i_qop,"auth") ){
		/* cnonce and nc make no sence in gateway ? */
		sprintf(seed->i_cnonce,"%d",itime(0));
		sprintf(seed->i_nc,"%d",itime(0));
	}
	genDigestReq(seed,REQ_METHOD,REQ_URL,user,pass,
		seed->i_realm,seed->i_nonce,AVStr(digest));

	str_sopen(SMemF,"retryWithAuth",(char*)reqauth,rsize,0,"w");
	if( fname )
	str_sprintf(SMemF,"%s: ",fname);
	str_sprintf(SMemF,"Digest ");
	str_sprintf(SMemF,"username=\"%s\", realm=\"%s\", ",user,seed->i_realm);
	str_sprintf(SMemF,"nonce=\"%s\", uri=\"%s\", response=\"%s\", ",
		seed->i_nonce,REQ_URL,digest);
	str_sprintf(SMemF,"opaque=\"%s\"",seed->i_opaque);

	if( qop_auth )
	str_sprintf(SMemF,", qop=\"%s\", cnonce=\"%s\", nc=\"%s\"",
		"auth",seed->i_cnonce,seed->i_nc);

	str_sprintf(SMemF,"\r\n");
}
static void authBtoD(Connection *Conn,PVStr(fields),PCStr(fname),AuthInfo *seed)
{	AuthInfo clauth;
	CStr(auth,512);
	CStr(reqauth,512);
	CStr(atyp,64);
	CStr(up,128);

	if( getFieldValue2(fields,fname,AVStr(auth),sizeof(auth)) )
	if( HTTP_decompAuthX(auth,AVStr(atyp),sizeof(atyp),AVStr(up),sizeof(up),&clauth) )
	if( strcaseeq(atyp,"basic") ){
		if( seed->i_nonce[0] == 0 ){
			removeFields(AVStr(fields),fname,0);
		}else{
			genAuthDigest(Conn,NULL,AVStr(reqauth),sizeof(reqauth),seed,
				clauth.i_user,clauth.i_pass);
			replaceFieldValue(AVStr(fields),fname,reqauth);
			sv1log("rewriteREQUEST %s: Basic -> Digest\n",fname);
		}
	}
}
int getDigestInCookie(PVStr(fields),AuthInfo *seed);
void rewriteReqBasicToDigest(Connection *Conn,PVStr(fields))
{	CStr(cookie,512);
	AuthInfo seed;

	if( (HTTP_opts & HTTP_DOAUTHCONV) == 0 )
		return;

	getDigestInCookie(AVStr(fields),&seed);

	if( findFieldValue(fields,"Authorization") == 0
	 && findFieldValue(fields,"Proxy-Authorization") == 0 )
		return;

	/*
	 * if client does not echo Cookie, Digest Authorization cannot
	 * replace Basic Authorization.
	 * but Basic Authehtication should not be forwarded in this case.
	 */
	if( seed.i_nonce[0] == 0 ){
		if(HTTP_opts&(HTTP_AUTHBASIC_NEVER_SV|HTTP_AUTHBASIC_DELAY_SV)){
			sv1log("Don't forward Basic Authorization.\n");
		}else{
			return;
		}
	}

	authBtoD(Conn,AVStr(fields),"Authorization",&seed);
	authBtoD(Conn,AVStr(fields),"Proxy-Authorization",&seed);
}
static int doRefreshDigest = 0;
void refreshDigestNonce(Connection *Conn,FILE *tc)
/*
{	CStr(yrealm,64);
*/
{	CStr(yrealm,128);
	CStr(nonce,64);
	const char *fname;
	const char *realm;

	if( !doRefreshDigest )
		return;

	if( REQ_AUTH.i_stype != 0 )
	if( strcaseeq(REQ_AUTH.i_atyp,"Digest") )
	if( genDigestNonce(Conn,&REQ_AUTH,REQ_URL,AVStr(nonce)) ){
		if( REQ_AUTH.i_stype == AUTH_APROXY )
			fname = "Proxy-Authentication-Info";
		else	fname = "Authentication-Info";
		fprintf(tc,"%s: nextnonce=\"%s\"\r\n",fname,nonce);
	}
}

static const char *NonceParam = "Digest-Nonce";
/*
 * in response -- Set-Cookie:realm,nonce,opaque
 */
void setDigestInCookie(Connection *Conn,AuthInfo *seed,PVStr(field))
{	CStr(cookie,512);
	CStr(b64,512);
	CStr(setcookie,512);

	sprintf(cookie,"realm=\"%s\", nonce=\"%s\", opaque=\"%s\"",
		seed->i_realm,seed->i_nonce,seed->i_opaque);
	str_to64(cookie,strlen(cookie),AVStr(b64),sizeof(b64),1);
	strsubst(AVStr(b64),"\n","");
	sprintf(field,"Set-Cookie: %s=\"%s\"\r\n",NonceParam,b64);
}
void resetDigestInCookie(Connection *Conn,PVStr(field))
{
	sprintf(field,"Set-Cookie: %s=\"\"; Max-Age=0\r\n",NonceParam);
}
/*
 * in request -- Cookie:realm,nonce,opaque + Basic-user,pass -> Digest
 */
int getDigestInCookie(PVStr(fields),AuthInfo *seed)
{	CStr(nonce,512);
	CStr(dgv,512);

	if( seed )
		bzero(seed,sizeof(AuthInfo));
	if( extractParam(AVStr(fields),"Cookie",NonceParam,AVStr(nonce),sizeof(nonce),1) ){
		if( seed ){
			str_from64(nonce,strlen(nonce),AVStr(dgv),sizeof(dgv));
			scanDigestParams(dgv,seed,VStrNULL,0);
		}
		return 1;
	}
	return 0;
}
const char *DeleGateSId(PVStr(sn));
int decrypt_opaque(PCStr(opaque),PVStr(opqs));
int extractSessionCookie(Connection *Conn,PVStr(req)){
	CStr(sn,64);
	IStr(sc1,128);
	IStr(sc2,128);
	IStr(sd1,128);
	IStr(sd2,128);

	DeleGateSId(AVStr(sn));
	if( extractParam(BVStr(req),"Cookie",sn,AVStr(sc1),sizeof(sc1),1)==0 )
		return 0;
	if( sc1[0] ){
	    for(;;){
		clearVStr(sc2);
		extractParam(BVStr(req),"Cookie",sn,AVStr(sc2),sizeof(sc2),1);
		if( sc2[0] == 0 )
			break;
		decrypt_opaque(sc1,AVStr(sd1));
		decrypt_opaque(sc2,AVStr(sd2));
		if( lSECRET() ){
			sv1log("<<<< %s\n",sd1);
			sv1log(">>>> %s\n",sd2);
		}
		/* should select the newer ? */
		strcpy(sc1,sc2);
	    }
	}
	strcpy(ClientSession,sc1);
	return 1;
}
int genSessionCookie(Connection *Conn,PVStr(field))
{ 	CStr(next,64);
	CStr(sn,64);

	if( (HTTP_opts & HTTP_SESSION) == 0 ) /* no SessionCookie */
	if( AuthTimeout(Conn)==0 /* no timeout to be controlled by Cookie */
	  || CTX_asproxy(Conn)   /* Cookie is NG for timeout a proxy client */
	 || strcaseeq(ClientAuth.i_atyp,"Digest") /* Digest contains Cookie */
	)
	{
		return 0;
	}

	setVStrEnd(field,0);
	strcpy(next,ClientSession);
	genSessionID(Conn,AVStr(next),1);
	if( lSECRET() ){
		IStr(sd,128);
		decrypt_opaque(next,AVStr(sd));
		sv1log(">>>> %d %d/%d [%s] %s (%s)\n",AuthTimeout(Conn),
			ClientAuth.i_stat,ClientAuth.i_error,
			ClientAuth.i_atyp,next,sd);
	}
	if( AuthTimeout(Conn) && (ClientAuth.i_stat || ClientAuth.i_error) ){
	  /* don't cause multi re-authentications for each path on timeout */
	  sprintf(field,"Set-Cookie: %s=\"%s\"; Path=/;\r\n",
		DeleGateSId(AVStr(sn)),next);
	}else
	sprintf(field,"Set-Cookie: %s=\"%s\"\r\n",DeleGateSId(AVStr(sn)),next);
	return 1;
}

int DHTML_pringGenAuth(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),PCStr(value))
{	CStr(user,32);
	CStr(pass,64);

return 0;

	if( streq(arg,"genauth") ){
		return 1;
	}else
	if( streq(arg,"genuser") ){

		fprintf(fp,"AUTHTYPE[%s] stat[%X] err[%X]<BR>\r\n",
			REQ_AUTH.i_atyp,REQ_AUTH.i_stat,REQ_AUTH.i_error);

		if( REQ_AUTH.i_stat & AUTH_GEN ){
			sprintf(user,"%06X",0xFFFFFF&DH_rand32());
			genPass(Conn,"-dgauth.-crypt",user,AVStr(pass));
			fprintf(fp,"user:%s<BR>\r\npass:%s<BR>\r\n",user,pass);
		}
		return 1;
	}else
	return 0;
}
