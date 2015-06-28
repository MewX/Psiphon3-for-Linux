/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2014 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	httpd.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	941009	extracted from http.c
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "fpoll.h"
#include "file.h"
#include "proc.h"
#include "http.h"
#include "auth.h"

#define ME_7bit		((char*)0)
#define ME_binary	"binary"

static const char *home_page = "/-/";
static const char *ext_base = "/-/ext/";
static const char *admin_base = "/-/admin/";
static const char *cgi_base = "/-/cgi/";
static const char *builtin_base = "builtin:";
static const char *icon_base = "/-/builtin/icons/";
static const char *mssg_base = "/-/builtin/mssgs/";
static const char *conf_base = "/-/builtin/config/";
static const char *copy_base = "/-/COPYRIGHT";
static const char *dproxy_base = "/-/nonCERNproxy";
static const char *bench_base = "/-/bench?";
static const char *data_base = "/-/data:";
static const char *date_base = "/-/date";
#define icon_relative	(icon_base+3)
#define FPRINTF		leng += Fprintf

#define printConn	DHTML_printConn

int ClientIfModClock(Connection *Conn);	/* -1 if not specified */

int localPathProto(PCStr(proto))
{
	if( streq(proto,"file") ) return 1;
	if( streq(proto,"proc") ) return 1;
	if( streq(proto,"cgi" ) ) return 1;
	if( streq(proto,"cfi" ) ) return 1;
	return 0;
}
int isURN(PCStr(urn))
{
	if( strncmp(urn,"news:",  5) == 0 && urn[5] != '/' ) return 4;
	if( strncmp(urn,"mailto:",7) == 0 && urn[7] != '/' ) return 6;
	if( strncmp(urn,"data:",  5) == 0 && urn[5] != '/' ) return 4;
	if( strncmp(urn,"myfile:",7) == 0 && urn[8] != '/' ) return 6;
	if( strncmp(urn,"string:",7) == 0 && urn[7] != '/' ) return 6;
	if( strncmp(urn,"gendata:",8)== 0                  ) return 7;
	if( strncmp(urn,"builtin:",8)== 0 && urn[8] != '/' ) return 7;
	if( strncmp(urn,"command:",8)== 0 && urn[8] != '/' ) return 7;
	return 0;
}

static int toMyself(Connection *Conn)
{
	if( localPathProto(DST_PROTO) )
		if( strcmp(DST_HOST,"localhost") == 0 )
			return 1;
	return 0;
}

const char *HTTP_getIconBase(Connection *Conn)
{	CStr(base,1024);

	HTTP_baseURLrelative(Conn,icon_base,AVStr(base));
	wordScan(base,iconBase);
	return iconBase;
}
static int putFrogInline(Connection *Conn,FILE *tc,PCStr(align),int trans,int body)
{	const char *icon;
	CStr(iurl,1024);

	if( body )
		if( trans )
			icon = "ysato/frogTrans.gif";
		else	icon = "ysato/frog.gif";
	else	icon = "ysato/frogHead.gif";

	sprintf(iurl,"%s%s",HTTP_getIconBase(Conn),icon);
	return Fprintf(tc,"<IMG ALT=\"@_@\" ALIGN=%s BORDER=0 SRC=%s>",
		align,iurl);
}
int putDeleGateInline(Connection *Conn,FILE *tc,PCStr(align))
{
	return Fprintf(tc,"<IMG ALT=\"@_@\" ALIGN=%s SRC=%s%s>",
		align,HTTP_getIconBase(Conn),"ysato/DeleGateLogoTrans.gif");
}

char *getCERNiconBase(Connection *Conn,PVStr(base))
{
	sprintf(base,"%s%s",HTTP_getIconBase(Conn),"cern/");
	return (char*)base;
}

static void flushLinger(FILE *tc)
{
	fflush(tc);
	set_linger(fileno(tc),DELEGATE_LINGER);
}

const char *getIcon(PCStr(name),int *size);
int getBuiltinDataX(Connection *Conn,PCStr(what),PCStr(aurl),PVStr(buf),int size,int *date,PVStr(rurl));
void toMD5Y(const char *str,int len,char md5[]);

static int putIcon(Connection *Conn,FILE *tc,int vno,PCStr(icon))
{	const char *data;
	const char *ctype;
	int size;
	int date = 0;
	int leng = 0;

CStr(url,URLSZ);
CStr(rurl,URLSZ);
CStr(buf,URLSZ);
sprintf(url,"/-/%s",icon);
/*
size = getBuiltinData(Conn,"BuiltinData",url,AVStr(buf),sizeof(buf),AVStr(rurl));
*/
size = getBuiltinDataX(Conn,"BuiltinData",url,AVStr(buf),sizeof(buf),&date,AVStr(rurl));
if(0 < size ){
	data = buf;
}else{
	if( (data = getIcon(icon,&size)) == 0 )
		return 0;
}

	if( strstr(icon,".xbm") != 0 )
		ctype = "image/x-xbitmap";
	else
	if( strtailstr(icon,".ico") )
		ctype = "image/x-icon";
	else	ctype = "image/gif";
	/* mod-140504f
	leng += HTTP_putHeader(Conn,tc,vno,ctype,size,0);
	*/
	toMD5Y(data,size,(char*)genETag); /* new-140504g */
	leng += HTTP_putHeader(Conn,tc,vno,ctype,size,date);
	leng += fwrite(data,1,size,tc);
	flushLinger(tc);
	return leng;
}
int PutIcon(Connection *Conn,FILE *tc,int vno,PCStr(icon)){
	return putIcon(Conn,tc,vno,icon);
}
/**/
static scanListFunc put1(PCStr(name),PCStr(data),int size,PCStr(buf),PCStr(iconhp))
{	CStr(path,256);
	CStr(file,1024);
UTag *ut = (UTag*)buf;

	sprintf(path,"%s%s",home_page,name);
	sprintf(file,"<IMG SRC=%s%s> <A HREF=%s%s>%s</A> (%d bytes)<BR>\n",
		iconhp,path, iconhp,path, name,size);
	strcat(ut->ut_addr,file);
	return 0;
}
void scanIcons(PCStr(name),int (*func)(const void*,...),PCStr(arg1),PCStr(arg2));
static int putIconList(Connection *Conn,FILE *tc,int vno,PCStr(iconhp))
{	CStr(buf,0x10000);
	refQStr(bp,buf); /**/
	int leng;
	UTag ut; setQStr(ut.ut_addr,buf,sizeof(buf));

	buf[0] = 0;
	Xsprintf(TVStr(bp),"<TITLE> Built-in images </TITLE>");
	Xsprintf(TVStr(bp),"<H1> Images built into the DeleGate </H1>");
	Xsprintf(TVStr(bp),"<BODY bgcolor=#E0E0E0>\n");
	Xsprintf(TVStr(bp),"<MENU>\n");

	scanIcons(icon_relative,(int(*)(const void*,...))put1,(char*)&ut,iconhp);
	Xsprintf(TVStr(bp),"</MENU>\n");
	leng = strlen(buf);

	HTTP_putHeader(Conn,tc,vno,"text/html",leng,0);
	fputs(buf,tc);
	flushLinger(tc);
	return leng;
}

/*
FPRINTF(tc,"<LI> Display response header <ISINDEX>\n");
*/

static void getBodyMD5(Connection *Conn,FILE *fp){
	if( Conn->mo_flags & (MO_MD5_ADD|MO_MD5_SIGN) ){
		int off;
		off = ftell(fp);
		fMD5(fp,Conn->ht_qmd5);
		Conn->mo_flags |= MO_MD5_SET;
		fseek(fp,off,0);
	}
}

static int inUnknown;
static int putUnknownPage(Connection *Conn,FILE *tc,int vno,PCStr(req))
{	int hleng,cleng;
	FILE *tmp;
	CStr(mssg,0x10000);

	if( HTTP_setRetry(Conn,req,404) )
		return 0;

	if( inUnknown == getpid() ){
		hleng = fprintf(tc,"HTTP/1.0 404 recursive unknown\r\n\r\n");
		return hleng;
	}
	inUnknown = getpid();
	if( RequestFlags & QF_NO_DELAY ){
	}else
	if( strstr(req,"/favicon.ico") ){
		sv1log("DONT DELAY on unknown /favicon.ico\n");
	}else
	delayUnknown(Conn,1,req);

	tmp = TMPFILE("NotFound");
	putBuiltinHTML(Conn,tmp,"NotFound","404-notfound.dhtml","",NULL,NULL);
	putFrogVer(Conn,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	if( 0 < (cleng = fread(mssg,1,sizeof(mssg)-1,tmp)) )
		setVStrEnd(mssg,cleng);
	else	setVStrEnd(mssg,0);
	fclose(tmp);

	hleng = putHttpNotFound(Conn,tc,mssg);

	flushLinger(tc);
	inUnknown = 0;
	return hleng + cleng;
}
int putUnknownMsg(Connection *Conn,FILE *tc,PCStr(req))
{	int vno;
	HttpRequest reqx;
	vno = decomp_http_request(req,&reqx);
	return putUnknownPage(Conn,tc,vno,req);
}
static int putBench(Connection *Conn,FILE *tc,int vno,PCStr(what))
{	int bi;
	int isbin = 0;
	const char *ctype = "text/plain";
	FileSize leng;
	FileSize rem;
	IStr(buf,1024);
	int len1,wcc;
	int rcode;

	if( REQ_AUTH.i_stype==AUTH_AORIGIN && streq(REQ_AUTH.i_user,"bench") ){
	}else{
		leng = putNotAuthorized(Conn,tc,what,0,"bench","");
		return leng;
	}
	while( *what ){
		if( *what == 'b' ){
			ctype = "application/octet-stream";
			isbin = 1;
			what++;
		}else{
			break;
		}
	}
	if( strneq(what,"0x",2) )
		Xsscanf(what,"0x%llx",&leng);
	else	leng = kmxatoi(what);
	rem = leng;
	if( !isbin ){
		leng += 2;
	}
	HTTP_putHeader(Conn,tc,vno,ctype,leng,-1);
	if( isbin ){
		for( bi = 0; bi < elnumof(buf); bi++ ){
			setVStrElem(buf,bi,bi);
		}
	}else{
		for( bi = 0; bi < elnumof(buf); bi++ ){
			setVStrElem(buf,bi,"0123456789ABCDEF"[bi%16]);
		}
	}
	for(; 0 < rem; rem -= len1 ){
		if( 1024 < rem )
			len1 = 1024;
		else	len1 = rem;
		wcc = fwrite(buf,1,len1,tc);
		if( wcc < len1 ){
			break;
		}
	}
	if( !isbin ){
		fputs("\r\n",tc);
	}
	return leng;
}

#define	Cbuf	databuf[cbi%2]
int HTTP_putData(Connection *Conn,FILE *tc,int vno,PCStr(dataspec))
{	const char *dp;
	const char *data;
	CStr(ctype,64);
	CStr(encode,64);
	ACStr(databuf,2,0x8000); /**/
	int cbi,leng;

	if( !IsMounted ){
		data = "Not Available\n";
		leng = strlen(data);
		HTTP_putHeader(Conn,tc,vno,"text/plain",leng,-1);
		fwrite(data,1,leng,tc);
		return leng;
	}

	ctype[0] = encode[0] = 0;
	data = "";
	leng = 0;

	dp = strpbrk(dataspec,";,");
	if( dp == NULL || 64 <= (dp - dataspec) )
		goto EXIT;

	scan_namebody(dataspec,AVStr(ctype),sizeof(ctype),";",AVStr(encode),sizeof(encode),",");
	if( data = strchr(dataspec,',') ){
		cbi = 0;
		XStrncpy(ZVStr(Cbuf,sizeof(Cbuf)),data+1,sizeof(Cbuf));
		leng = strlen(Cbuf);
		data = Cbuf;

		if( strchr(data,'%') ){
			cbi++;
			nonxalpha_unescape(data,EVStr(Cbuf),1);
			leng = strlen(Cbuf);
			data = Cbuf;
		}
		if( strcasecmp(encode,"base64") == 0 ){
			cbi++;
			leng = str_from64(data,leng,EVStr(Cbuf),sizeof(Cbuf));
			data = Cbuf;
		}
	}
EXIT:
	if( vno != 0 ){
		if( ctype[0] == 0 )
			strcpy(ctype,"text/plain");
		HTTP_putHeader(Conn,tc,vno,ctype,leng,-1);
	}
	if( data )
		fwrite(data,1,leng,tc);
	return leng;
}

int HTTP_putDate(Connection *Conn,FILE *tc,int vno,PCStr(datespec)){
	CStr(dspec,128);
	CStr(tfmt,128);
	CStr(sdate,1024);
	CStr(resp,1024);
	int leng = 0;
	int fgmt = 0;

	if( *datespec == '?' )
		datespec++;
	if( strncaseeq(datespec,"zone=gmt&",9) ){
		datespec += 9;
		fgmt = 1;
	}
	if( strncaseeq(datespec,"zone=uts&",9) ){
		datespec += 9;
		fgmt = 1;
	}
	nonxalpha_unescape(datespec,AVStr(dspec),1);
	if( *dspec ){
		strcpy(tfmt,dspec);
		strsubst(AVStr(tfmt),"$","%");
	}else	strcpy(tfmt,"%Y%m%d%H%M%S");
	if( fgmt )
		StrftimeGMT(AVStr(sdate),sizeof(sdate),tfmt,time(0),0);
	else	StrftimeLocal(AVStr(sdate),sizeof(sdate),tfmt,time(0),0);
	sv1log("Date: [%s]->[%s]\n",tfmt,sdate);
	sprintf(resp,"%s\n",sdate);

	HTTP_putHeader(Conn,tc,vno,"text/plain",strlen(resp),-1);
	FPRINTF(tc,"%s",resp);
	return leng;
}
/*
 * 9.6.0 this is intended to return success to request to /favicon.ico
 * in HTTPS gateway to avoid repetitive retrial and delay which can caused
 * in the default or typical configurations as follows.
 *   SERVER=https
 *   -Pxxx (xxx != 443)
 *   REMITTABLE=...,https/443
 *   MOUNT="/favicon.ico builtin:... default,onerror=404,..."
 * It could be applied to more generic cases but is restricted for a while
 * for safety.
 */
static int setRetry(Connection *Conn,PCStr(req),PCStr(path)){
	/* could be more generic but restricted for safety */
	if( !streq(CLNT_PROTO,"https") )
		return 0;
	if( !streq(path,"/favicon.ico") )
		return 0;

	if( !service_permitted2(Conn,DST_PROTO,1) ){
		int port,pmok;

		port = REAL_PORT;
		REAL_PORT = 443;
		pmok = service_permitted2(Conn,DST_PROTO,1);
		REAL_PORT = port;
		if( !pmok ){
			return 0;
		}
	}
	if( HTTP_setRetry(Conn,req,404) ){
		return 1;
	}
	return 0;
}
extern char *DFLT_VHOST;

#define ISMYSELF(Conn) \
	(!Conn->co_nointernal && Ismyself(Conn,DST_PROTO,DST_HOST,DST_PORT))

int putRobotsTxt(Connection *Conn,FILE *tc,FILE *afp,int ismsg);
static int putBuiltinConfig(Connection *Conn,FILE *tc,int vno,PCStr(path));
static int putBuiltinMssg(Connection *Conn,FILE *tc,PCStr(path));
FileSize putLocal(Connection *Conn,int vno,PCStr(method),PVStr(req),PCStr(head),PVStr(url),FILE *fc,FILE *tc,int *stcodep);
int Isvhost(Connection *Conn,PCStr(host),int port);
int DHTML_putDeleGatePage(Connection *Conn,PCStr(req),FILE *tc,int vno);
int DHTML_putControl(Connection *Conn,PCStr(req),FILE *fc,FILE *tc,int vno,PVStr(command),int *stcodep);
int genHEADX(Connection *Conn,FILE *tc,int code,PCStr(reason),int cleng);

int ShutdownSocket(int fd);
int waitFilterThreadX(Connection *Conn);
static void waitFT_FL(Connection *Conn,FILE *tcx,FILE *tc,int leng,int L){
	int err;
	int fdx = fileno(tcx);
	int fd = fileno(tc);
	int sockx;
	int sock;

	sockx = SocketOf(fdx);
	ShutdownSocket(fdx);

	err = waitFilterThreadX(Conn);
	sock = SocketOf(fd);
	sv1tlog("----WinCE %s:%d waitFT(%d/%d %d/%d) %d\n",
		"httpd.c",L,sockx,fdx,sock,fd,err);
}
void waitFT_FLX(Connection *Conn,FILE *tcx,FILE *tc,int leng,FL_PAR){
	if( lSINGLEP() ){
		fflush(tcx);
		waitFT_FL(Conn,tcx,tc,leng,FL_L);
	}
}

int mapPort(Connection *Conn,int port,PVStr(mhost));
FileSize HttpToMyself(Connection *Conn,PVStr(req),PCStr(head),FILE *fc,FILE *tc,int *stcodep)
{	int vno;
	HttpRequest reqx;
	const char *method;
	MrefQStr(path,reqx.hq_url); /**/
	int nlen;
	FileSize leng = 0;
	int ismyself;
	int blen;

	if( GatewayFlags & GW_IN_CLALG ){
		Verbose("Not internal: in CLALG\n");
		return 0;
	}
	if( lORIGDST() && Origdst_Port )
	if( GatewayFlags & GW_WITH_ORIGDST )
	{
		sv1log("##NAT forwarding by ORIGDST [%s:%d] <= [%s:%d]\n",
			DFLT_HOST,DFLT_PORT,Origdst_Host,Origdst_Port);
		strcpy(REAL_HOST,DFLT_HOST);
		REAL_PORT = mapPort(Conn,DFLT_PORT,VStrNULL);
		return 0;
	}

	/*
	 * "ismyself" must be TRUE when the request is for internal data of
	 * this delegated on this host.  The problem is whether or not the
	 * request is for this delegated as an origin server.
	 * The problem occurs when "/" is accessed which is not MOUNTed,
	 * without MOUNT for "/", and when it is requested with virtual host
	 * with "Host: hostX" field and the hostX does not match with the
	 * name of my host.
	 * At least there are five cases to be considered.
	 *  1) acting as a MASTER DeleGate  -- to be forwarded
	 *  2) named with unknown (unmatch) hostname
	 *  3) accessed via NAT (unmatch address)
	 *  4) doing virtual hosting        -- to be forwarded ... MOUNTed
	 *  5) doing "transparent proxy"    -- to be forwarded ... resolvable
	 *
	 *  "IsVhost" is TRUE when it is accessed with "Host:virtual-hostname" 
	 *  "Isvhost()" is FALSE when it is MOUNTed even if IsVhost is TRUE
	 *  "ISMYSELF()" is FALSE when it is MOUNTed even if IsVhost is FALSE
	 */
	ismyself = ISMYSELF(Conn);
	if( ismyself == 0 && TelesockPort == DST_PORT ){
		int SvSock_withRIDENT(int sstype);
		extern int AccViaHTMUX;
		/* 9.9.0 accepted at remotehost (SockMux,HTACC,VSAP) */
		if( hostcmp(TelesockHost,DST_HOST) == 0 )
			ismyself = 1;
		else
		if( AccViaHTMUX && SvSock_withRIDENT(Conn->clif._portFlags) ){
			porting_dbg("--self %d:%d [%s][%s] HTMUX=%X Flags=%X",
				TelesockPort,DST_PORT,
				TelesockHost,DST_HOST,
				AccViaHTMUX,Conn->clif._portFlags);
			ismyself = 1;
		}
	}
	/* SO_ORIGINAL_DST should be cared */

	if( ismyself == 0 ){
		if( MountOptions ){
			/* explicitly MOUNTed to another server */
		}else
		if( do_RELAY(Conn,RELAY_VHOST) && IsResolvable(DST_HOST) ){
			/* probably called as a "transparent proxy" */
			/* possibly my host is named with unknown hostname */
		}else
		/* maybe accepted via NAT */
		ismyself = Isvhost(Conn,DST_HOST,DST_PORT)?2:0;
	}
/*
 fprintf(stderr,"ismyself:%d IsM=%d IsV=%d int=%d %s:%d isv=%d doR=%d res=%d\n",
ismyself,ISMYSELF(Conn),IsVhost,Conn->co_nointernal,DST_HOST,DST_PORT,
Isvhost(Conn,DST_HOST,DST_PORT),
do_RELAY(Conn,RELAY_VHOST),IsResolvable(DST_HOST));
*/

	if( ismyself )
		setToInternal();

	sv1log("checking delegate-internal: self=%d %s",ismyself,req);
	if( (vno = decomp_http_request(req,&reqx)) == 0 )
		return 0;
	method = reqx.hq_method;
	if( strncmp(path,ext_base,strlen(ext_base)) == 0 ){
		Conn->mo_flags |= MO_BI_EXTERN;
		strsubst(AVStr(path),ext_base,home_page);
	}

	if( ismyself ){
		CStr(upath,URLSZ);

		if( streq(path,"/") ){
			*stcodep = 302;
			if( IsAdmin ){
				return putMovedTo(Conn,tc,admin_base);
			}else
			if( do_RELAY(Conn,RELAY_DELEGATE) )
				return putMovedTo(Conn,tc,dproxy_base);
			else	return putMovedTo(Conn,tc,home_page);
		}
		if( strncmp(path,dproxy_base,nlen=strlen(dproxy_base)) == 0 
		 || strncmp(path,"/",nlen=strlen("/")) == 0 )
		if( path[nlen] == '?' ){
			CStr(durl,URLSZ);
			CStr(myhost,128);
			int myport;

			nlen++;
			nonxalpha_unescape(path+nlen,AVStr(upath),0);
			*stcodep = 302;
			if( DONT_REWRITE ){
				return putMovedTo(Conn,tc,upath);
			}else{
				myport = ClientIF_H(Conn,AVStr(myhost));
				CTX_url_rurlX(Conn,0,upath,AVStr(durl),CLNT_PROTO,myhost,myport,"",1);
				return putMovedTo(Conn,tc,durl);
			}
		}
		/* hard mount from dproxy_base to nonCERNproxy ... */
		if( strncmp(path,dproxy_base,nlen=strlen(dproxy_base)) == 0 ){
			strcpy(upath,path);
			strcpy(path,"/-/builtin/mssgs/nonCERNproxy.dhtml");
			strcat(path,upath+nlen);
		}
	}

	if( strncmp(path,data_base,strlen(data_base)) == 0 )
	{
		leng = HTTP_putData(Conn,tc,vno,path+strlen(data_base));
		if( 0 < leng )
			return leng;
		goto UNKNOWN;
	}

	if( streq(path,home_page) ){
		if( DONT_REWRITE ){
			leng = DHTML_putDeleGatePage(Conn,req,tc,vno);
			flushLinger(tc);
		}else{
			FILE *tcx;
			IsMounted = 1; /* IMG URL may be rewriten, so invoke
					* Content-Length correction in the
					* ResponseFilter process
					*/
			tcx = openHttpResponseFilter(Conn,tc);
			/* IsMounted should be restored here ? */
			leng = DHTML_putDeleGatePage(Conn,req,tcx,vno);
			flushLinger(tcx);
			if( isWindowsCE() ){
				waitFT_FL(Conn,tcx,tc,leng,__LINE__);
			}
			/*
			else
			if( lSINGLEP() ){
				dupclosed(fileno(tcx));
				waitFilterThreadX(Conn);
			}
			*/
			fclose(tcx);
			wait(0);
		}
		return leng;
	}
	if( strncmp(path,date_base,strlen(date_base)) == 0 ){
		leng = HTTP_putDate(Conn,tc,vno,path+strlen(date_base));
		if( 0 < leng )
			return leng;
		goto UNKNOWN;
	}

	blen = 0;
	if( strncmp(path,admin_base,blen=strlen(admin_base)) == 0
	 || strstr(path,"?-_-") ){
		leng = DHTML_putControl(Conn,req,fc,tc,vno,QVStr(path+blen,path),stcodep);
		flushLinger(tc);
		return leng;
	}

	nlen = strlen(builtin_base);
	if( strncmp(path,builtin_base,nlen) == 0 ){
		Strrplc(AVStr(path),nlen,"/-/builtin/");
	}

	nlen = strlen(mssg_base);
	if( strncmp(path,mssg_base,nlen) == 0 ){
		leng = putBuiltinMssg(Conn,tc,path+nlen);
		if( leng == 0 ){
			goto UNKNOWN;
		}
		return leng;
	}

	nlen = strlen(copy_base);
	if( strncmp(path,copy_base,nlen) == 0 ){
		leng = putBuiltinMssg(Conn,tc,"/-/../COPYRIGHT");
		if( leng == 0 ){
			goto UNKNOWN;
		}
		return leng;
	}

	nlen = strlen(conf_base);
	if( strncmp(path,conf_base,nlen) == 0 )
	if( strtailstr(path,".ico") )
/* as config data can include non-public info,it should be admin only.  */
	{
		leng = putBuiltinConfig(Conn,tc,vno,path+nlen);
		if( leng == 0 ){
			goto UNKNOWN;
		}
		return leng;
	}

	if( IsMounted )
	if( strheadstrX(path,"gendata:/-/ysh/",0) ){
		int putYshellData(Connection *Conn,FILE *fc,FILE *tc,PCStr(path));
		leng = putYshellData(Conn,fc,tc,path+8);
		return leng;
	}

	nlen = strlen(icon_base);
	if( strncmp(path,icon_base,nlen) == 0 ){
		CStr(icon,URLSZ);
		sprintf(icon,"%s%s",icon_relative,path+nlen);
		if( path[nlen] == 0 ){
			CStr(base,1024);
			HTTP_baseURLrelative(Conn,"",AVStr(base));
			leng = putIconList(Conn,tc,vno,base);
		}else	leng = putIcon(Conn,tc,vno,icon);

		if( 0 < leng ){
			IsInternal = 1;
			return leng;
		}
		if( ismyself || IsVhost ){
			goto UNKNOWN;
		}
	}else{
		if( strncmp(path,bench_base,strlen(bench_base)) == 0 ){
			return putBench(Conn,tc,vno,path+strlen(bench_base));
		}
		if( ismyself ){
			if( leng = putRobotsTxt(Conn,tc,NULL,0) )
				return leng;
			sv1log("ERROR: Unknown internal: %s",req);
			goto UNKNOWN;
		}
	}
	/* it could be inline images in the customized Forbidden message */
	{	CStr(opath,URLSZ);
		HTTP_originalURLPath(Conn,AVStr(opath));
		if( strncmp(opath,icon_base,nlen) == 0 )
		{
			Conn->from_myself = 1;
		}
	}

	if( leng = putLocal(Conn,vno,method,AVStr(req),head,AVStr(path),fc,tc,stcodep) )
	{
		httpStat = CS_LOCAL;
		return leng;
	}
	if( ismyself ){
		goto UNKNOWN;
	}

	if( IsVhost && IsMounted ){
		/* MOUNT="/p/* http://v/* vhost=-v */
		return 0;
	}

	/* V8.0.1 RELAY=novhost by default */
	if( IsVhost && do_RELAY(Conn,RELAY_VHOST) ){
		sv1log("forwarding by RELAY=vhost [%s:%d]\n",DST_HOST,DST_PORT);

	return 0;
	}
	if( strcaseeq(iSERVER_PROTO,"tunnel1") ){
		sv1log("forw. by SERVER=tunnel1 [%s:%d]\n",DST_HOST,DST_PORT);
		return 0;
	}

UNKNOWN:
	if( Conn->sv_retry == SV_RETRY_DO )
		return 0;

	if( setRetry(Conn,req,path) ){
		*stcodep = 404;
		return 0;
	}else
	if( !service_permitted(Conn,DST_PROTO) ){
		*stcodep = 403;
		leng = putHttpRejectmsg(Conn,tc,DST_PROTO,"-",0,BVStr(req));
		return leng;
	}

	sv1log("Unknown internal: [%s:%d] %s\n",DST_HOST,DST_PORT,path);
	*stcodep = 404;
	return putUnknownPage(Conn,tc,vno,req);
}

static int putDeleGateAnchor(Connection *Conn,FILE *tc)
{	CStr(url,1024);

	HTTP_baseURLrelative(Conn,home_page,AVStr(url));
	return Fprintf(tc,"<A HREF=%s>",url);
}

static int putBuiltinConfig(Connection *Conn,FILE *tc,int vno,PCStr(path))
{	int leng,cleng;
	CStr(url,URLSZ);
	CStr(rurl,URLSZ);
	CStr(buf,0x4000);
	FILE *tmp;
	const char *ctype;
	int ci,isbin;

	sprintf(url,"/-/builtin/config/%s",path);
	leng = getBuiltinData(Conn,"BuiltinData",url,AVStr(buf),sizeof(buf),AVStr(rurl));
	if( leng <= 0 )
		return 0;
	tmp = TMPFILE("BuiltinData");
	fwrite(buf,1,leng,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);

	isbin = 0;
	for( ci = 0; ci < leng; ci++ ){
		if( buf[ci] == 0 ){
			isbin = 1;
			break;
		}
	}
	if( isbin )
		ctype = "application/octet-stream";
	else	ctype = "text/plain";
	putHttpHeader1X(Conn,tc,vno,NULL,ctype,ME_7bit,cleng,-1,0,NULL);
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	return cleng;
}
static int putBuiltinMssg(Connection *Conn,FILE *tc,PCStr(path))
{	FILE *tmp;
	int leng,cleng;
	const char *ctype;

	tmp = TMPFILE("Builtin");
	leng = putBuiltinHTML(Conn,tmp,"builtin-mssg",path,NULL,(iFUNCP)printConn,NULL);
	if( leng <= 0 ){
		fclose(tmp);
		return 0;
	}
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	ctype = filename2ctype(path);
	if( ctype == NULL )
		ctype = "text/plain";
	putHttpHeader1(Conn,tc,NULL,ctype,ME_7bit,cleng,0);
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	return cleng;
}
int putChangeProxy(Connection *Conn,FILE *tc,PCStr(url),PCStr(proxy))
{	int leng,cleng;
	FILE *tmp;

	tmp = TMPFILE("ChangeProxy");
	putBuiltinHTML(Conn,tmp,"UseProxy-message",
		"305-useproxy.dhtml",NULL,(iFUNCP)printConn,NULL);
	putFrogVer(Conn,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	leng = genHEADX(Conn,tc,305,"Use Proxy",cleng);
	if( *proxy == 0 || strcasecmp(proxy,"direct") == 0 ){
		FPRINTF(tc,"Set-Proxy: DIRECT\r\n",url);
	}else{
		FPRINTF(tc,"Set-Proxy: SET; proxyURI=\"%s\"\r\n",proxy);
		FPRINTF(tc,"Location: %s\r\n",proxy);
	}
	FPRINTF(tc,"\r\n");
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	flushLinger(tc);
	return cleng;
}
int putUpgrade(Connection *Conn,FILE *tc){
	FILE *tmp;
	int cleng;

	tmp = TMPFILE("Upgrade");
	putBuiltinHTML(Conn,tmp,"Upgrade","426-upgrade.dhtml",NULL,
		(iFUNCP)printConn,NULL);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	fseek(tmp,0,0);

	fprintf(tc,"HTTP/1.1 426 Upgrade Required\r\n");
	fprintf(tc,"Upgrade: TLS/1.0, HTTP/1.1\r\n");
	fprintf(tc,"Connection: Upgrade\r\n");
	fprintf(tc,"Content-Type: text/html\r\n");
	fprintf(tc,"Content-Length: %d\r\n",cleng);
	fprintf(tc,"\r\n");

	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	return cleng;
}
int putMovedTo(Connection *Conn,FILE *tc,PCStr(url))
{
	return putMovedToX(Conn,tc,302,url);
}

static FILE *Tmp;
static FILE *TmpFILE(PCStr(what),PCStr(mode)){
	FILE *tmp;
	int fd;
	int isnew;

	if( lMULTIST() ){ /* on WindowsCE */
		tmp = TMPFILE(what);
		return tmp;
	}
	if( isnew = (Tmp == NULL) ){
		Tmp = TMPFILE(what);
	}
	fd = dup(fileno(Tmp));
	tmp = fdopen(fd,mode);
	if( !isnew ){
		fseek(tmp,0,0);
		Ftruncate(tmp,0,0);
	}
	return tmp;
}
int putMovedToX(Connection *Conn,FILE *tc,int code,PCStr(url))
{	int leng,cleng;
	const char *dp;
	CStr(myhp,MaxHostNameLen);
	CStr(fullurl,URLSZ);
	FILE *tmp;

	if( url[0] == '/' ){
		const char *proto;
		if( proto = Conn->my_vbase.u_proto ){
			HTTP_ClientIF_HP(Conn,AVStr(myhp));
			sprintf(fullurl,"%s://%s%s",proto,myhp,url);
		}else{
		HTTP_ClientIF_HP(Conn,AVStr(myhp));
		sprintf(fullurl,"%s://%s%s",CLNT_PROTO,myhp,url);
		}
		url = fullurl;
	}
	if( !URL_toMyself(Conn,url) ){
		HTTP_clntClose(Conn,"m:moved to another server");
		sv1log("Moved to another server [%s]\n",url);
	}

	/*
	tmp = TMPFILE("MovedTo");
	*/
	tmp = TmpFILE("MovedTo","w+");
	putBuiltinHTML(Conn,tmp,"Moved-message",
		"302-moved.dhtml",NULL,(iFUNCP)printConn,url);
	putFrogVer(Conn,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	leng = genHEADX(Conn,tc,code,"Moved",cleng);
	if( getenv("DG_useURI") ){
		if( strncmp(url,"http://",7) == 0 )
			if( dp = strchr(url+7,'/') )
				url = dp;
		FPRINTF(tc,"URI: <%s>\r\n",url);
		sv1log("####### URI: <%s>\r\n",url);
	}else{
		FPRINTF(tc,"Location: %s\r\n",url);
		sv1log("####### Location: %s\r\n",url);
	}
	FPRINTF(tc,"\r\n");

	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	flushLinger(tc);
	return cleng;
}
int putHttpNotModified(Connection *Conn,FILE *tc)
{	int leng;

	leng = genHEADX(Conn,tc,304,"Not modified",0);
	FPRINTF(tc,"\r\n");
	return leng;
}
int putHttpNotFound(Connection *Conn,FILE *tc,PCStr(mssg))
{	int leng,cleng;

	cleng = strlen(mssg);
	leng = genHEADX(Conn,tc,404,"Not found",cleng);
	fputs("\r\n",tc);
	if( RespWithBody ) fputs(mssg,tc);
	return cleng;
}
int putHttpNotAvailable(Connection *Conn,FILE *tc,PCStr(mssg))
{	int leng = 0;

	leng = genHEADX(Conn,tc,503,"Service Unavailable",0);
	FPRINTF(tc,"\r\n");
	return leng;
}

int putConfigError(Connection *Conn,FILE *tc,PCStr(msg))
{	int leng,cleng;
	FILE *tmp;

	tmp = TMPFILE("ConfigError");
	fprintf(tmp,"Configuration error in %s\r\n",msg);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	leng = genHEADX(Conn,tc,500,msg,cleng);
	FPRINTF(tc,"\r\n");
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	return leng;
}
int putNotAuthorized(Connection *Conn,FILE *tc,PCStr(req),int proxy,PCStr(realm),PCStr(mssg))
{	int leng,cleng;
	HttpRequest reqx;
	CStr(xrealm,1024);
	CStr(yrel,1024);
	int Mrealm = 0;
	const char *mid;
	const char *desc;
	FILE *tmp;
	int code;
	const char *fname;
	const char *reason;
	CStr(digest,1024);

	if( proxy ){
		code = 407;
		mid = "407-unauthproxy.dhtml";
		reason = "Proxy Authentication Required";
		fname = "Proxy-Authenticate";

		/* for CONNECT with Keep-Alive by MSIE */
		if( strstr(REQ_UA,"MSIE ") )
		HTTP_clntClose(Conn,"a:proxy authentication required");
	}else{
		code = 401;
		mid = "401-unauth.dhtml";
		reason = "Unauthorized";
		fname = "WWW-Authenticate";
	}
	Conn->from_myself = 1;
	tmp = TMPFILE("NotAuthorized");
	putBuiltinHTML(Conn,tmp,"NotAuth",mid,NULL,(iFUNCP)printConn,NULL);
	fputs(mssg,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	if( realm == NULL ){
		/*
		decomp_http_request(req,&reqx);
		sprintf(xrealm,"<%s>",reqx.hq_url);
		*/
		CStr(url,1024);
		const char *vbase;
		const char *dp;

		/* it is not MOUNTed when it is not authorized ... */
		if( MountOptions == 0 ){
			wordScan(REQ_URL,url);
			MountRequestURL(Conn,AVStr(url));
		}
		if( MountOptions && (dp = strchr(MO_Authorizer,'@')) ){
			if( REQ_AUTH.i_realm[0] && strstr(dp,REQ_AUTH.i_realm) )
				strcpy(xrealm,REQ_AUTH.i_realm);
			else
			wordscanY(dp+1,AVStr(xrealm),sizeof(xrealm),"^, ");
			Mrealm = 1;
		}else
		if( MountOptions
		&& (dp = strstr(MountOptions,"realm="))
		){
			wordscanY(dp+6,AVStr(xrealm),sizeof(xrealm),"^, ");
			Mrealm = 1;
		}else
		/*
		if( ClientFlags & PF_AS_PROXY ){
			lineScan("proxy",xrealm);
		}else
		*/
		if( REQ_AUTH.i_realm[0] ){
			lineScan(REQ_AUTH.i_realm,xrealm);
		}else
		if( proxy ){
			lineScan("proxy",xrealm);
		}else
		if( REQ_AUTH.i_error /* rejected by self AUTHORIZER */
		&& getMountAuthorizer(Conn,VStrNULL,0)==0/*not MountOption*/
		){
			sprintf(xrealm,"</>");
		}else
		if( MountOptions && (vbase = MountVbase(MountOptions)) )
			sprintf(xrealm,"<%s>",vbase);
		else	sprintf(xrealm,"</>");

		/* should add Host: value ? */
		realm = xrealm;
	}
	Verbose("REALM: %s\n",realm);
	realm = substDGDEF(Conn,realm,AVStr(yrel),sizeof(yrel),0,DGD_ESC_QUOTE);
	leng = genHEADX(Conn,tc,code,reason,cleng);

	if( askDigestAuth(Conn,Mrealm,realm,AVStr(digest)) )
	FPRINTF(tc,"%s: Digest %s\r\n",fname,digest);
	else
	FPRINTF(tc,"%s: Basic Realm=\"%s\"\r\n",fname,realm);
	FPRINTF(tc,"\r\n");

	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	Conn->statcode = code;
	return leng + cleng;
}

int putFrogForDeleGate(Connection *Conn,FILE *dst,PCStr(fmt),...);
int putFrogVer(Connection *Conn,FILE *tc)
{	int leng = 0;

	FPRINTF(tc,"<HR>\n");
	FPRINTF(tc,"<ADDRESS> Proxy HTTP Server %s \n", DELEGATE_Ver());
	leng += putFrogForDeleGate(Conn,tc,"");
	FPRINTF(tc,"</ADDRESS>\n");
	return leng;
}

int putHttpRejectmsg(Connection *Conn,FILE *tc,PCStr(proto),PCStr(server),int iport,PVStr(req))
{	int leng,cleng;
	int mleng;
	const char *mid;
	FILE *tmp;

	HTTP_originalRequest(Conn,AVStr(req));
	mid = "403-forbidden.dhtml";
	tmp = TMPFILE("Forbidden");
	Conn->from_myself = 1;
	putBuiltinHTML(Conn,tmp,"Forbidden-Message",mid,"",NULL,NULL);
	putFrogVer(Conn,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	leng = 0;
	if( HTTP_reqIsHTTP(Conn,req) ){
		leng = genHEADX(Conn,tc,403,"Forbidden",cleng);
		FPRINTF(tc,"\r\n");
	}
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	flushLinger(tc);

	Conn->statcode = 403;
	return leng + cleng;
}

int putHttpCantConnmsg(Connection *Conn,FILE *tc,PCStr(proto),PCStr(server),int iport,PCStr(req))
{	int leng,cleng;
	const char *mid;
	CStr(desc,1024);
	FILE *tmp;

	tmp = TMPFILE("CantConn");
	if( Conn->co_nonet ){
		mid = "502-offline.dhtml";
		sprintf(desc,"<B>Not in Cache</B>");
	}else{
		mid = "502-cantconnect.dhtml";
		sprintf(desc,"<B>Cannot Connect</B>");
	}
	putBuiltinHTML(Conn,tmp,"CantConn-Message",mid,desc,(iFUNCP)printConn,NULL);
	putFrogVer(Conn,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	getBodyMD5(Conn,tmp);

	leng = 0;
	if( HTTP_reqIsHTTP(Conn,req) ){
		leng = genHEADX(Conn,tc,502,"Cannot Connect",cleng);
		FPRINTF(tc,"\r\n");
	}
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);
	flushLinger(tc);
	return leng;
}

int httpfinger(Connection *Conn,int sv,PCStr(server),int iport,PCStr(path),int vno)
{	FILE *ts,*fs,*tc;
	CStr(resp,1024);
	int lines;
	int leng = 0;

	if( sv == -1 )
		return 0;
	ts = fdopen(dup(sv),"w");
	fs = fdopen(dup(sv),"r");
	tc = fdopen(dup(ToC),"w");

	if( *path == '/' )
		path++;
	if( *path == '?' )
		path++;

	fprintf(ts,"%s\r\n",path);
	fflush(ts);

	leng += HTTP_putHeader(Conn,tc,vno,"text/html",0,-1);
	FPRINTF(tc,"<TITLE> Finger on %s </TITLE>\n",server);
	FPRINTF(tc,"<H1> Finger on %s </H1>\n",server);
	FPRINTF(tc,"<ISINDEX>\n");
	FPRINTF(tc,"<PRE>\n");

	lines = 0;
	while( fgets(resp,sizeof(resp),fs) != NULL ){
		fputs(resp,tc);
		leng += strlen(resp);
		lines++;
	}
	FPRINTF(tc,"</PRE>\n");
	FPRINTF(tc,"<HR>\n");
	leng += putFrogForDeleGate(Conn,tc,"[%d lines]\n",lines);

	flushLinger(tc);
	fclose(ts);
	fclose(fs);
	fclose(tc);
	return leng;
}

int putFrogForDeleGate(Connection *Conn,FILE *dst,PCStr(fmt),...)
{	int leng = 0;
	VARGS(14,fmt);

	FPRINTF(dst,fmt,VA14);
	setToInternal();
	leng += putDeleGateAnchor(Conn,dst);
	leng += putFrogInline(Conn,dst,"BOTTOM",1,0);
	FPRINTF(dst,"V</A>\n");
	return leng;
}

static int off_limit(PCStr(url),PVStr(upath))
{	const char *rpath;
	CStr(apath,URLSZ);

	if( rpath = strstr(url,"://") ){
		rpath += 3;
		if( rpath = strchr(rpath,'/') ) /* skip server part */
			rpath += 1;
	}else
	if( rpath = strstr(url,":/") )
		rpath += 2;

	if( rpath ){
		CStr(drpath,URLSZ);
		if( nonxalpha_unescape(rpath,AVStr(drpath),1) )
			rpath = drpath;

		strcpy(apath,"-/-");
		while( *rpath == '/' )
			rpath++;
		chdir_cwd(AVStr(apath),rpath,0);
		if( strncmp(apath,"-/-",3) != 0 )
			return 1; /* intruded off limit by ".." */

		/* should copy &apath[2] ? */
		strcpy(upath,rpath);
	}

	return 0;
}
int upath_off_limit(PCStr(path),PVStr(npath)){
	int offl;

	truncVStr(npath);
	offl = off_limit(path,AVStr(npath));
	return offl;
}


/*
 * as a search script ?
 *
 *	/path/of/dir?ls-options
 *
 */
static char DIR_CGI[16] = "-dir.cgi";
static void dir_CGI(Connection *Conn,PCStr(path),PCStr(upath),FILE *fp)
{
}

static char DIR_HTML[16] = "-dir.html";

static const char *localOnly = "shtml";
static const char *http_search_script;
static const char *tab_indexurls[16] = {
	"welcome.dgp",
	"welcome.shtml",
	"welcome.html",
	"welcome.cgi",
	"index.dgp",
	"index.shtml",
	"index.html",
	"index.cgi",
	DIR_HTML,
	NULL
};
#define indexurls tab_indexurls

extern int HTTP_WARN_REQLINE;
const char *HTTP_MAX_REQHEAD_sym = "max-reqhead";
const char *HTTP_MAX_REQLINE_sym = "max-reqline";
const char *HTTP_GW_MAX_REQLINE_sym = "max-gw-reqline";
int HTTP_ftpXferlog;
extern int HTTP_CKA_CFI;
extern int HTTP_MAX_SSLTURNS;
const char *HTTP_urlesc;
const char *HTTP_passesc = "%%%C"; /* no default, escape control char. */
extern int HTTP_noXLocking;
extern const char *HTTP_accEncoding;
extern const char *HTTP_genEncoding;
extern int HTTP_MAX_BUFF_REQBODY;
extern int HTTP_MAX_RHPEEP;
extern int HTTP_MIN_CHUNKED;
extern int HTTP_MIN_GZIP_SIZE;
extern double HTTP_TOUT_PACKINTVL;
extern int url_unify_ports;
static const char *ProxyControlMARK;
extern int HTTP_TOUT_THREAD_PIPELINE;

static void settout(PCStr(what),PCStr(value),PCStr(conf))
{	double secs;
	int isecs;

	secs = Scan_period(value,'s',(double)0);
	isecs = (int)secs;
	if( streq(what,"tout-cka") )	    HTTP_TOUT_CKA = secs; else
	if( streq(what,"tout-ckamg") )	    HTTP_TOUT_CKA_MARGIN = secs; else
	if( streq(what,"tout-reqbody"))	    HTTP_TOUT_QBODY = secs; else
	if( streq(what,"tout-wait-badsv") ) HTTP_WAIT_BADSERV = secs; else
	if( streq(what,"tout-wait-reqbody"))HTTP_WAIT_REQBODY = secs; else
	if( streq(what,"tout-in-reqbody") ) HTTP_TOUT_IN_REQBODY = secs; else
	if( streq(what,"tout-buff-reqbody"))HTTP_TOUT_BUFF_REQBODY = secs; else
	if( streq(what,"tout-buff-resbody"))HTTP_TOUT_BUFF_RESBODY = secs; else
	if( streq(what,"tout-resp") )       HTTP_TOUT_RESPLINE = secs; else
	if( streq(what,"tout-threadp") )HTTP_TOUT_THREAD_PIPELINE = isecs; else
	if( streq(what,"tout-cka-resp") )   HTTP_TOUT_CKA_RESPLINE = secs; else
	if( streq(what,"tout-pack-intvl")){
					    HTTP_TOUT_PACKINTVL = secs;
		HTTP_opts |= HTTP_TOUTPACKINTVL;
	}else
	syslog_ERROR("ERROR: unknonw HTTPCONF=%s\n",conf);
}
extern int HTTP_MAX_PARAS;
static void setmax(PCStr(what),PCStr(value),PCStr(conf))
{	int maxi;

	maxi = kmxatoi(value);
	if( streq(what,"warn-reqline") ) HTTP_WARN_REQLINE = maxi; else
	if( streq(what,"max-hops") )	HTTP_MAXHOPS = maxi; else
	if( streq(what,"min-chunked") ) HTTP_MIN_CHUNKED = maxi; else
	if( streq(what,"min-gzip") )    HTTP_MIN_GZIP_SIZE = maxi; else
	if( streq(what,"max-ssl-turns") )    HTTP_MAX_SSLTURNS = maxi; else
	if( streq(what,"max-cka") )	HTTP_CKA_MAXREQ = maxi; else
	if( streq(what,"max-ckapch") )	HTTP_CKA_PERCLIENT = maxi; else
	if( streq(what,"max-buff-reqbody") ) HTTP_MAX_BUFF_REQBODY = maxi; else
	if( streq(what,"max-reshead-peep") ) HTTP_MAX_RHPEEP = maxi; else
	if( streq(what,"max-paras") )	HTTP_MAX_PARAS = maxi; else
	if( streq(what,HTTP_MAX_REQHEAD_sym) ) HTTP_MAX_REQHEAD = maxi; else
	if( streq(what,HTTP_MAX_REQLINE_sym) ) HTTP_MAX_REQLINE = maxi; else
	if( streq(what,HTTP_GW_MAX_REQLINE_sym) ) HTTP_GW_MAX_REQLINE = maxi;
	else
	syslog_ERROR("ERROR: unknown HTTPCONF=%s\n",conf);
}

typedef struct {
	int	 k_what;
	defQStr(k_pat);
	int	 k_len;
	int	 k_rem;
} KillPat;
static KillPat killpats[32]; /**/
static int killpatx;
static scanListFunc kill1(PCStr(pat),int what)
{	KillPat *kp;
	const char *dp;

	if( elnumof(killpats) <= killpatx ){
		return -1;
	}
	kp = &killpats[killpatx++];
	if( what & (KH_IN|KH_OUT) )
		kp->k_what = what;
	else	kp->k_what = what | KH_OUT;
	/*
	kp->k_what = what | (KH_IN|KH_OUT);
	*/
	setQStr(kp->k_pat,stralloc(pat),strlen(pat)+1);
	nonxalpha_unescape(kp->k_pat,ZVStr(kp->k_pat,strlen(kp->k_pat)+1),1);
	if( dp = strchr(kp->k_pat,'*') ){
		truncVStr(dp);
		kp->k_rem = 1;
	}
	kp->k_len = strlen(kp->k_pat);
	return 0;
}
static void addKill(PCStr(pat),int what)
{
	if( what & KH_RES ){
		HTTP_opts |= HTTP_REW_RHEAD;
	}
	scan_commaList(pat,0,scanListCall kill1,what);
}
int HTTP_head2kill(PCStr(head),int what)
{	int ki,killed;
	KillPat *kp;

	killed = 0;
	for( ki = 0; ki < killpatx; ki++ ){
		kp = &killpats[ki];
		if( (kp->k_what & what) == what )
		if( strncasecmp(head,kp->k_pat,kp->k_len) == 0 ){
			if( kp->k_rem || head[kp->k_len] == ':' ){
				killed++;
				break;
			}
		}
	}
	return killed;
}
int HTTP_killhead(PVStr(head),int what)
{	int killed;
	const char *hp; /* not "const" but fixed */
	const char *np;

	killed = 0;
	if( 0 < killpatx ){
		for( hp = head; hp && *hp; hp = np ){
			if( np = strpbrk(hp,"\r\n") ){
				while( *np == '\r' )
					np++;
				if( *np == '\n' )
					np++;
			}
			if( HTTP_head2kill(hp,what) ){
				killed++;
				ovstrcpy((char*)hp,np);
				np = hp;
			}
		}
	}
	return killed;
}

typedef struct {
	int	 g_what; /* request or response */
	int	 g_how;	 /* append or replace */
  const	char	*g_fmt;
} GenFormat;
static GenFormat genFormat[32]; /**/
static int genFormatX;
static void addGen(PCStr(fspec),int what,int how)
{	CStr(buf,256);
	refQStr(dp,buf); /**/
	GenFormat *gf;

	if( what & KH_RES ){
		HTTP_opts |= HTTP_REW_RHEAD;
	}
	lineScan(fspec,buf);
	if( dp = strchr(buf,':') ){
		if( dp[1] != 0 && dp[1] != ' ' )
			Strins(QVStr(&dp[1],buf)," ");
	}
	strcat(buf,"\r\n");
	if( elnumof(genFormat) <= genFormatX ){
		return;
	}
	gf = &genFormat[genFormatX++];
	if( what & (KH_IN|KH_OUT) )
		gf->g_what = what;
	else	gf->g_what = what | KH_OUT;
	/*
	gf->g_what = what | (KH_IN|KH_OUT);
	*/
	gf->g_fmt = stralloc(buf);
}

static void addf1(PVStr(head),PVStr(field))
{	refQStr(dp,field); /**/

	if( field[0] && strtailstr(field,"\r\n") == 0 ){
		dp = strtail(field);
		if( *dp != '\r' && *dp != '\n' )
			dp++;
		strcpy(dp,"\r\n");
	}
	RFC822_addHeaderField(AVStr(head),field);
}
static int genhead1(Connection *Conn,PVStr(head),PCStr(field))
{	CStr(fmt,512);
	CStr(buf,4096);
	char dc;

	dc = *field++;
	if( dc != ':' ) /* MOUNT="vURL rURL   add-[qr]head:x:y" */
	if( dc != '=' ) /* ProxyControl URL?_?add-[qr]head=x:y */
		return 0;

	if( dc == '=' )
		wordscanY(field,AVStr(fmt),sizeof(fmt),"^,+"); /* necessary ? */
	else	wordscanY(field,AVStr(fmt),sizeof(fmt),"^,");
	strfConnX(Conn,fmt,AVStr(buf),512);
	addf1(AVStr(head),AVStr(buf));
	return 1;
}
static int genheads(Connection *Conn,PVStr(head),int what,PCStr(list))
{	const char *mo;
	const char *ot;
	int gen = 0;

	if( (what & KH_REQ) && (mo=strstr(list,ot="add-qhead")) )
		gen += genhead1(Conn,AVStr(head),mo+strlen(ot));

	if( what & KH_OUT )
	if( (what & KH_RES) && (mo=strstr(list,ot="add-rhead")) )
		gen += genhead1(Conn,AVStr(head),mo+strlen(ot));

	if( what & KH_OUT )
	if( mo = strstr(list,ot="add-head") )
		gen += genhead1(Conn,AVStr(head),mo+strlen(ot));

	return gen;
}
int HTTP_genhead(Connection *Conn,PVStr(head),int what)
{	int fi,gen;
	GenFormat *gf;
	CStr(buf,4096);

	gen = 0;
	for( fi = 0; fi < genFormatX; fi++ ){
		gf = &genFormat[fi];
		if( (gf->g_what & what) == what ){
			strfConnX(Conn,gf->g_fmt,AVStr(buf),512);
			addf1(AVStr(head),AVStr(buf));
			gen++;
		}
	}
	if( MountOptions && strstr(MountOptions,"add-") != 0 ){
		gen += genheads(Conn,AVStr(head),what,MountOptions);
	}
	if( ProxyControls[0] && strstr(ProxyControls,"add-") != 0 ){
		gen += genheads(Conn,AVStr(head),what,ProxyControls);
	}
	/*
	if( strstr(ProxyControls,"replace-qhead") ){
		gen += genheads(Conn,AVStr(head),what,ProxyControls);
	}
	*/
	return gen;
}

int HTTP_flags;
static SStr(pathExt,32);
void setpathExt(Connection *Conn,PCStr(ext))
{
	xmem_push(pathExt,strlen(pathExt)+1,"pathExt",NULL);
	wordscanX(ext,MVStrSiz(pathExt));
}

/*
static scanListFunc setbugs(PCStr(value))
*/
static scanListFunc setbugs(PCStr(value),Connection *Conn)
{
	if( streq(value,"add-contleng") )
		HTTP_opts |= HTTP_ADDCONTLENG;
	else
	if( streq(value,"kill-contleng") )
		HTTP_opts |= HTTP_DELWRONGCONTLENG;
	else
	if( streq(value,"pass-contleng") )
		HTTP_opts &= ~HTTP_DELWRONGCONTLENG;
	else
	if( streq(value,"wait-reqbody") )
		HTTP_opts |= HTTP_DOPOLL_REQBODY;
	else
	if( streq(value,"postpone-reqhead") )
		HTTP_opts |= HTTP_POSTPONE_REQHEAD;
	else
	if( streq(value,"no-chunked") )
		HTTP_opts |= HTTP_NOCHUNKED;
	else
/*
	if( streq(value,"no-buff-for-ccx") )
		HTTP_opts |= HTTP_NOBUFF_FORCCX;
	else
*/
	if( streq(value,"less-chunked") )
		HTTP_opts |= HTTP_SUPPCHUNKED;
	else
	if( streq(value,"flush-chunk") )
		HTTP_opts |= HTTP_FLUSHCHUNK;
	else
	if( streq(value,"no-flush-chunk") )
		HTTP_opts |= HTTP_NOFLUSHCHUNK;
	else
	if( streq(value,"flush-pipeline") )
		HTTP_opts |= HTTP_FLUSH_PIPELINE;
	else
	if( streq(value,"no-keepalive") )
		HTTP_opts |= HTTP_NOKEEPALIVE;
	else
	if( streq(value,"do-keepalive-stls") )
		HTTP_opts |= HTTP_DOKEEPALIVE_STLS;
	else
	if( streq(value,"no-keepalive-stls") )
		HTTP_opts |= HTTP_NOKEEPALIVE_STLS;
	else
	if( streq(value,"no-keepalive-proxy") )
		HTTP_opts |= HTTP_NOKEEPALIVEPROXY;
	else
	if( streq(value,"do-keepalive-max") )
		HTCKA_opts = 0x0000FFFF;
	else
	if( streq(value,"do-keepalive-reqwithleng") )
		HTCKA_opts |= HTCKA_REQWITHLENG;
	else
	if( streq(value,"do-keepalive-respnoleng") )
		HTCKA_opts |= HTCKA_RESPNOLENG;
	else
	if( streq(value,"do-keepalive-post") )
		HTCKA_opts |= HTCKA_POST| HTCKA_REQWITHLENG| HTCKA_RESPNOLENG;
	else
	if( streq(value,"do-keepalive-post-pipeline") )
		HTCKA_opts |= HTCKA_POST| HTCKA_POSTPIPELINE|
			 HTCKA_REQWITHLENG| HTCKA_RESPNOLENG;
	else
	if( streq(value,"no-methodcheck") )
		HTTP_opts |= HTTP_NOMETHODCHECK;
	else
	if( streq(value,"do-gzip-stream") ){
		LOG_bugs |= ENBUG_GZIP_STREAM;
	}else
	if( streq(value,"no-gzip") )
		HTTP_opts |= HTTP_NOGZIP;
	else
	if( streq(value,"line-by-line") )
		HTTP_opts |= HTTP_LINEBYLINE;
	else
	if( streq(value,"do-authconv") )
	{
		HTTP_opts |= HTTP_DOAUTHCONV;
		LOG_type4 |= L_DONTHT;
	}
	else
	if( streq(value,"do-auth-sourceonly") )
		HTTP_opts |= HTTP_DOAUTH_BYSOURCE;
	else
	if( streq(value,"do-x-locking") )
		HTTP_noXLocking = 0;
	else
	if( streq(value,"thru-304") )
		HTCFI_opts |= HTCFI_THRU_304;
	else
	if( streq(value,"gen-304") )
		HTCFI_opts |= HTCFI_GEN_304;
	else
	if( streq(value,"do-oldcache") )
		HTTP_opts |= HTTP_OLDCACHE;
	else
	if( streq(value,"px-thruresp") )
		HTTP_opts |= HTTP_DONT_REWRITE_PX;
	else
	if( streq(value,"px-rewresp") )
		HTTP_opts |= HTTP_DO_REWRITE_PX;
	else
	if( streq(value,"no-cfi-delay") ){
		HTTP_flags |= PF_NO_CFI_DELAY;
	}else
	if( streq(value,"do-pre-filter") ){
		HTTP_flags |= PF_DO_PREFILTER;
	}

	return 0;
}

void setKillTags(PCStr(stags));
void HTTP_setModwatch(Connection *Conn,PCStr(spec));
int checkGzip(Connection *Conn);
void HTTP_setRespVers(PCStr(vers));
extern const char *URLinputEncoding;
extern int HTTP_CHUNKED_CLENG;

static void replaceH(PCStr(field),int what){
	CStr(nam,128);
	CStr(val,1024);
	scan_field1(field,AVStr(nam),sizeof(nam),AVStr(val),sizeof(val));
	addKill(nam,what);
	addGen(field,what,0);
}

void scan_HTTPCONF(Connection *Conn,PCStr(conf))
{	CStr(what,128);
	CStr(value,2048);

	what[0] = value[0] = 0;
	Xsscanf(conf,"%[^:]:%s",AVStr(what),AVStr(value));
	if( strncmp(what,"tout-",5) == 0 ){
		settout(what,value,conf);
	}else
	if( strncasecmp(what,"min-",4) == 0 ){
		setmax(what,value,conf);
	}else
	if( strncasecmp(what,"max-",4) == 0 ){
		setmax(what,value,conf);
	}else
	if( strncasecmp(what,"warn-",5) == 0 ){
		setmax(what,value,conf);
	}else
	if( strncasecmp(what,"kill-",5) == 0 ){
		strtolower(value,value);
		if( streq(what+5,"qhead") || streq(what+5,"head") ){
			if( isinList(value,"x-locking") )
				HTTP_noXLocking = 1;
		}
		if( streq(what+5,"xqhead")) addKill(value,KH_IO|KH_REQ); else
		if( streq(what+5,"xrhead")) addKill(value,KH_IO|KH_RES); else
		if( streq(what+5,"xhead") ) addKill(value,KH_IO|KH_BOTH); else
		if( streq(what+5,"iqhead")) addKill(value,KH_IN|KH_REQ); else
		if( streq(what+5,"irhead")) addKill(value,KH_IN|KH_RES); else
		if( streq(what+5,"ihead") ) addKill(value,KH_IN|KH_BOTH); else
		if( streq(what+5,"qhead") ) addKill(value,KH_REQ); else
		if( streq(what+5,"rhead") ) addKill(value,KH_RES); else
		if( streq(what+5,"head")  ) addKill(value,KH_BOTH); else
		if( streq(what+5,"tag") ) setKillTags(value);
	}else
	if( strncasecmp(what,"add-",4) == 0 ){
		if( streq(what+4,"iqhead")) addGen(value,KH_IN |KH_REQ,0); else
		if( streq(what+4,"irhead")) addGen(value,KH_IN |KH_RES,0); else
		if( streq(what+4,"ihead") ) addGen(value,KH_IN |KH_BOTH,0); else
		if( streq(what+4,"qhead") ) addGen(value,KH_OUT|KH_REQ,0); else
		if( streq(what+4,"rhead") ) addGen(value,KH_OUT|KH_RES,0); else
		if( streq(what+4,"head")  ) addGen(value,KH_OUT|KH_BOTH,0);
	}else
	if( strncasecmp(what,"replace-",8) == 0 ){
		if( streq(what+8,"iqhead")) replaceH(value,KH_IN |KH_REQ); else
		if( streq(what+8,"irhead")) replaceH(value,KH_IN |KH_RES); else
		if( streq(what+8,"ihead") ) replaceH(value,KH_IN |KH_BOTH); else
		if( streq(what+8,"qhead") ) replaceH(value,KH_OUT|KH_REQ); else
		if( streq(what+8,"rhead") ) replaceH(value,KH_OUT|KH_RES); else
		if( streq(what+8,"head")  ) replaceH(value,KH_OUT|KH_BOTH);
	}else
	/*
	if( strcaseeq(what,"thru-CONNECT") ){
		HTTP_opts |= HTTP_THRU_CONNECT;
	}else
	*/
	if( strcaseeq(what,"thru-type") ){
		extern const char *HTTP_thruType;
		const char *ttype = HTTP_thruType;
		if( strneq(value,"+,",2) && ttype ){
			ovstrcpy(value,value+1);
			Strins(AVStr(value),ttype);
		}
		HTTP_thruType = stralloc(value);
	}else
	if( strcaseeq(what,"ccx-url-ie") ){
		URLinputEncoding = stralloc(value);
	}else
	if( strcaseeq(what,"post-ccx-type") ){
		extern const char *HTTP_POSTccxType;
		if( strneq(value,"+,",2) ){
			/*
			strsubst(AVStr(value),"+",HTTP_POSTccxType);
			*/
			Strrplc(AVStr(value),1,HTTP_POSTccxType);
		}
		HTTP_POSTccxType = stralloc(value);
	}else
	if( strcaseeq(what,"thru-UA") ){
		extern char *HTTP_thruUA;
		HTTP_thruUA = stralloc(value);
	}else
	if( strcaseeq(what,"nvhost") ){
	}else
	if( strcaseeq(what,"nvserv") ){
		int MOUNT_setvhosts(int none,int all,int gen,int alias);
		int none=0,all=0,gen=0,alias=0;
		if( isinList(value,"gen")    ) gen = 1;
		if( isinList(value,"alias")  ) alias = 1;
		if( isinList(value,"auto")   ){ gen = alias = 1; }
		if( isinList(value,"noauto") ){ gen = alias = 0; }
		if( isinList(value,"none")   ){ gen = alias = 0; none = 1; }
		MOUNT_setvhosts(none,all,gen,alias);
	}else
	if( strcasecmp(what,"default-vhost") == 0 ){
		DFLT_VHOST = stralloc(value);
	}else
	if( strncasecmp(what,"acc-",4) == 0 ){
		if( streq(what+4,"encoding") ){
			HTTP_accEncoding = stralloc(value);
			if( strstr(value,"gzip") )
				checkGzip(Conn);
		}
	}else
	if( strncasecmp(what,"gen-",4) == 0 ){
		if( streq(what+4,"encoding") ){
			HTTP_genEncoding = stralloc(value);
			if( strstr(value,"gzip") )
				checkGzip(Conn);
		}
	}else
	if( streq(what,"cka-cfi") ){
		HTTP_CKA_CFI = 1;
	}else
	if( streq(what,"chunked-cleng") ){
		HTTP_CHUNKED_CLENG = atoi(value);
	}else
	if( streq(what,"methods") ){
		HTTP_setMethods(value);
	}else
	if( streq(what,"rvers") ){
		HTTP_setRespVers(value);
	}else
	if( streq(what,"search") ){
		http_search_script = stralloc(value);
		sv1log("HTTP SearchScript=%s\n",value);
	}else
	if( streq(what,"belocal") ){
		localOnly = stralloc(value);
	}else
	if( streq(what,"welcome") ){
		int wc,wi;
		const char *wv[16]; /**/

		wc = stoV(value,15,wv,',');
		for( wi = 0; wi < wc; wi++ ){
			Verbose("HTTP-Welcome[%d] %s\n",wi,wv[wi]);
			indexurls[wi] = stralloc(wv[wi]);
		}
		indexurls[wc] = NULL;
	}
	if( streq(what,"pathext") ){
		setpathExt(Conn,value);
	}
	else
	if( streq(what,"modwatch") || streq(what,"watchmod") ){
		HTTP_setModwatch(Conn,value);
	}
	else
	if( streq(what,"ver") ){
		if( strcmp(value,"1.0") == 0 )
		{
			HTTP11_toserver = 0;
			HTTP11_toclient = 0;
		}
	}
	else
	if( streq(what,"svver") ){
		if( strcmp(value,"1.0") == 0 )
			HTTP11_toserver = 0;
	}
	else
	if( streq(what,"clver") ){
		if( strcmp(value,"1.0") == 0 )
			HTTP11_toclient = 0;
		else
		if( strcmp(value,"0.9rej") == 0 )
			HTTP09_reject = 1;
	}
	else
	if( streq(what,"clauth") ){
		if( strcmp(value,"force-basic") == 0 )
			HTTP_opts |= HTTP_FORCEBASIC_CL;
		else
		if( strcmp(value,"thru-digest") == 0 )
			HTTP_opts |= HTTP_THRUDIGEST_CL;
	}
	else
	if( streq(what,"svauth") ){
		if( strcmp(value,"no-basic") == 0 )
			HTTP_opts |= HTTP_AUTHBASIC_NEVER_SV;
		else
		if( strcmp(value,"less-basic") == 0 )
			HTTP_opts |= HTTP_AUTHBASIC_DELAY_SV;
	}
	else
	if( streq(what,"session") ){
		HTTP_opts |= HTTP_SESSION;
	}
	else
	if( streq(what,"ignif") ){
		HTTP_ignoreIf = 1;
	}
	else
	if( streq(what,"applet") ){
		if( streq(value,"warn") )
			HTTP_warnApplet = 1;
	}
	else
	if( streq(what,"badhead") ){
		if( streq(value,"rej") )
			HTTP_rejectBadHeader = 1;
	}
	else
	if( streq(what,"urlesc") ){
		if( *value == 0 )
			strcpy(value,"<>");
		nonxalpha_unescape(value,AVStr(value),1);
		Strins(AVStr(value),"%%"); /* url is already encoded */
		HTTP_urlesc = stralloc(value);
	}
	else
	if( streq(what,"passesc") ){
		nonxalpha_unescape(value,AVStr(value),1);
		Strins(AVStr(value),"%%"); /* no default encoding */
		HTTP_passesc = stralloc(value);
	}
	else
	if( streq(what,"xferlog") ){
		if( streq(value,"ftp") )
			HTTP_ftpXferlog = 1;
	}
	else
	if( streq(what,"nolog") ){
		scan_CMAP2(Conn,"NOLOG",value);
	}
	else
	if( streq(what,"halfdup") ){
		HTTP_opts |= HTTP_NOPIPELINE;
	}
	else
	if( streq(what,"urlsearch") ){
		if( streq(value,"all") ) URL_SEARCH = URL_IN_ANY;
	}
	else
	if( streq(what,"urlunifyports") ){
		url_unify_ports = 1;
	}
	else
	if( streq(what,"proxycontrol") ){
		if( *value==0 || strcaseeq(value,"on")||strcaseeq(value,"yes") )
			ProxyControlMARK = "?_?";
		else
		if( strcaseeq(value,"off") || strcaseeq(value,"no") )
			ProxyControlMARK = 0;
		else	ProxyControlMARK = stralloc(value);
	}
	else
	if( streq(what,"dumpstat") ){
		HTTP_opts |= HTTP_DUMPSTAT;
	}
	else
	if( streq(what,"no-delay") ){
		HTTP_opts |= HTTP_NODELAY;
	}
	else
	if( streq(what,"no-cache") ){
		if( isinList(value,"no-cache") )
			HTTP_cacheopt &= ~CACHE_NOCACHE;
	}else
	if( streq(what,"cache") ){
		if( streq(value,"any") ){
			/*
			HTTP_cacheopt = 0xFFFFFFFF;
			*/
			HTTP_cacheopt = CACHE_ANY;
		}
		if( isinList(value,"nolastmod") )
			HTTP_cacheopt |= CACHE_NOLASTMOD;
		if( isinList(value,"302") )
			HTTP_cacheopt |= CACHE_302;
		if( isinList(value,"cookie") )
			HTTP_cacheopt |= CACHE_COOKIE;
		if( isinList(value,"vary") )
			HTTP_cacheopt |= CACHE_VARY;
		if( isinList(value,"less-reload") )
			HTTP_cacheopt |= CACHE_LESSRELD;
		if( isinList(value,"auth") )
			HTTP_cacheopt |= CACHE_WITHAUTH;
	}
	else
	if( streq(what,"nomenu") ){
		extern int HTTP_putmenu;
		HTTP_putmenu = 0;
	}
	else
	if( streq(what,"dgcroute") ){
		if( streq(value,"no") )
			HTTP_opts |= HTTP_NODGC_ROUTE;
	}else
	if( streq(what,"bugs") ){
		scan_commaList(value,0,scanListCall setbugs,Conn);
	}
	else
	if( strcaseeq(what,"cryptCookie") ){
		void setupCryptCookie(PCStr(value));
		setupCryptCookie(value);
	}
	else
	if( strcaseeq(what,"deleteCookie") ){
		void setupDeleteCookie(PCStr(value));
		setupDeleteCookie(value);
	}
}

/*
 * HTTPCONF="modwatch:notifyto,approver" equals to
 * HTTPCONF="modwatch:notifyto=${ADMIN},approver=*:.localnet"
 */
static scanListFunc modwatch1(PCStr(spec),Connection *Conn)
{	CStr(name,64);
	CStr(val,64);
	CStr(map,256);

	name[0] = val[0] = 0;
	Xsscanf(spec,"%[^=]=%s",AVStr(name),AVStr(val));
	sv1log("HTTPCONF=modwatch:%s=%s\n",name,val);
	if( strcmp(name,"notifyto") == 0 ){
		modwatch_notify = stralloc(val);
		/* should verify the address here ... */
	}else
	if( strcmp(name,"approver") == 0 ){
		modwatch_approver = 1;
		if( val[0] == 0 )
			sprintf(map,"approve:*:%s","*:.localnet");
		else	sprintf(map,"approve:*:%s",val);
		scan_CMAP2(Conn,CMAP_APPROVER,map);
	}
	return 0;
}
void HTTP_setModwatch(Connection *Conn,PCStr(spec))
{
	modwatch_enable = 1;
	scan_commaListL(spec,0,scanListCall modwatch1,Conn);
}


#define S_DATA	1
#define S_EXECI	2
#define S_EXECX	4
#define S_EXEC	(S_EXECI|S_EXECX)
#define S_XPATH	8

int isExecutableURL(PCStr(url))
{
	if( strtailchr(url) == '/' ) return 1;
	if( strchr(url,'?') ) return 2;
	if( strtailstr(url,".dgp") ) return 3;
	if( strtailstr(url,".cgi") ) return 4;
	if( strtailstr(url,".html") ) return 5;
	if( strtailstr(url,".shtml") ) return 6;
	if( strtailstr(url,".htm") ) return 7; /* v9.9.11 fix-140725a */
	return 0;
}

/*
 *  dir           -> dir-ext
 *  dir/          -> dir-ext/
 *  dir/path      -> dir/path-ext
 *  dir/path.type -> dir/path-ext.type
 */
char *getpathext(PCStr(path),PCStr(pathext),PVStr(xpath),int xsize)
{	const char *dp;
	const char *xp;
	CStr(ext,256);
	int len,siz;

	if( pathext[0] ){
		xp = path + strlen(path);
		if( path < xp ){
			dp = xp - 1;
			if( *dp == '/' )
				xp = dp;
			else
			for(; path <= dp; dp-- ){
				if( *dp == '/' ){
					xp = dp + strlen(dp);
					break;
				}
				if( *dp == '.' ){
					xp = dp;
					break;
				}
			}
		}
		linescanX(pathext,AVStr(ext),sizeof(ext));
		linescanX(xp,TVStr(ext),sizeof(ext)-strlen(ext));
		len = strlen(path) - strlen(xp);
		siz = xsize - strlen(ext);
		if( siz < len )
			len = siz;
		linescanX(path,AVStr(xpath),len+1);
		strcat(xpath,ext);
		return (char*)xpath;
	}
	return 0;
}
FILE *extfopen(PCStr(path),PCStr(mode))
{	CStr(xpath,URLSZ);
	FILE *fp;

	if( getpathext(path,pathExt,AVStr(xpath),sizeof(xpath)) ){
		if( fp = fopen(xpath,mode) ){
			sv1log("pathExt[%s] %s\n",pathExt,xpath);
			return fp;
		}
	}
	return fopen(path,mode);
}

int scanFTPxHTTP(Connection *Conn,PCStr(cmdopt),PVStr(cmd),PVStr(opt),PVStr(ctype));

FILE *ftp_localLIST(Connection *Conn,FILE *tc,PCStr(com),PCStr(arg),PVStr(path));
FILE *ftpxhttp(Connection *Conn,PCStr(base),PCStr(upath),PCStr(search),PCStr(ftpxcmd),PVStr(ipath),int *mtimep){
	IStr(cmd,64);
	IStr(opt,64);
	IStr(rpath,512);
	const char *dp;
	FILE *fp;

	strcpy(ipath,"/");
	chdir_cwd(AVStr(ipath),base,0);
	/*
	chdir_cwd(AVStr(rpath),upath,0);
	chdir_cwd(AVStr(ipath),rpath,0);
	*/

	sv1log("--FTPxHTTP [%s][%s] -> [%s]\n",base,upath,ipath);
	if( fileIsdir(ipath) ){
		if( ftpxcmd ){
			strcpy(cmd,ftpxcmd);
		}else{
			strcpy(cmd,"LIST");
		}
		if( search && (dp = strstr(search,"ftpxopt=")) ){
			Xsscanf(dp+8,"%s",AVStr(opt));
		}
		if( opt[0] == 0 && strcaseeq(cmd,"LIST") ){
			strcpy(opt,"-Ll");
		}
		fp = ftp_localLIST(Conn,NULL,cmd,opt,BVStr(ipath));
		if( fp ){
			fflush(fp);
			fseek(fp,0,0);
			*mtimep = File_mtime(ipath);
			return fp;
		}
	}
	return 0;
}
int ftpxhttpPOST(Connection *Conn,FILE *fc,FILE *tc,PCStr(method),PCStr(path),int *stcodep){
	FILE *fp;
	int rdy;
	int siz = -9;

	if( MountOptions && !isinListX(MountOptions,"rw","c") ){
		sv1log("#### FTPxHTTP without \"rw\" MountOption\n");
		*stcodep = 403;
		return -1;
	}
	rdy = fPollIn(fc,8*1000);
	if( fp = fopen(path,"w") ){
		siz = copyfile1(fc,fp);
		fclose(fp);
	}
	sv1log("#### FTPxHTTP POST [%s][%s] rdy=%d siz=%d\n",
		method,path,rdy,siz);
	*stcodep = 200;
	fprintf(tc,"HTTP/1.0 200 Ok POSTed\r\n");
	fprintf(tc,"Content-Length: 0\r\n");
	fprintf(tc,"\r\n");
	fflush(tc);
	return 1;
}

static void putDirPage(Connection *Conn,PCStr(path),PCStr(upath),FILE *fp);
static FILE *openIndex(Connection *Conn,PCStr(path),PCStr(upath),PVStr(ipath),int what,int *mtimep)
{	FILE *fp;
	int ii;
	const char *sp;
	char sc;
	refQStr(ip,ipath); /**/
	const char *file;
	const char *ext;

	*mtimep = -1;

	if( path[0] ){
		for( sp = path; sc = *sp; sp++ ){
			assertVStr(ipath,ip+1);
			setVStrPtrInc(ip,sc);
		}
		if( ip[-1] != '/' )
			setVStrPtrInc(ip,'/');
	}
	if( isinFTPxHTTP(Conn) ){
		if( fp = ftpxhttp(Conn,path,upath,"","",BVStr(ipath),mtimep) ){
			return fp;
		}
	}

	for( ii = 0; file = indexurls[ii]; ii++ ){
		if( streq(file,DIR_HTML) ){
			if( (what & S_EXECI) == 0 ) continue;
		}else
		/*
		if( strtailstr(file,".cgi")
		 || strtailstr(file,".dgp")
		 || strtailstr(file,".shtml")
		*/
		if( strtailstr(file,ext=".cgi")
		 || strtailstr(file,ext=".dgp")
		 || strtailstr(file,ext=".shtml")
		){
			if( (what & S_EXECX) == 0 ) continue;
			if( (what & S_XPATH) != 0 ){
				if( isinListX(localOnly,ext+1,"c") ){
					continue;
				}
			}
		}else{
			if( (what & S_DATA) == 0 ) continue;
		}

		strcpy(ip,file);
		if( strcmp(file,DIR_HTML) == 0 ){
			fp = TMPFILE("ls2html");
			putDirPage(Conn,path,upath,fp);
			fflush(fp);
			fseek(fp,0,0);
			*mtimep = File_mtime(path);
			return fp;
		}else{
			if( fp = extfopen(ipath,"r") )
				return fp;
		}
	}
	return NULL;
}

static void putDir(Connection *Conn,PCStr(dirpath),FILE *tmp,FILE *fp,PCStr(eol))
{	CStr(line,1024);
	CStr(file,2048);
	CStr(xfile,2048);
	CStr(iconbase,1024);
	const char *iconsrc;
	const char *iconalt;
	CStr(pfile,2048);
	CStr(xpfile,2048);
	CStr(path,1024);
	FileSize size;
	int time,isdir;
	CStr(atime,128);
	int rcode;
	int anchor;

	ServerFlags |= PF_DO_RESPBUFF; /* to adjust Content-Length after MOUNT */

	getCERNiconBase(Conn,AVStr(iconbase));
	while( fgets(line,sizeof(line),tmp) != NULL ){
		lineScan(line,file);
		strcpy(pfile,file);
		if( ClientFlags & PF_ADMIN_ON ){
		}else
		if( file[0] == '.' && file[1] != '.' )
			continue;

		strcpy(path,dirpath);
		if( strtailchr(path) != '/' )
			strcat(path,"/");
		strcat(path,file);
		rcode =
		File_stat(path,&size,&time,&isdir);
		StrftimeLocal(AVStr(atime),sizeof(atime),TIMEFORM_LS,time,0);
		fprintf(fp,"%8lld %s ",size,atime);

		if( isdir )
			strcat(file,"/");
		iconsrc = filename2icon(file,&iconalt);

/*
		nonxalpha_escapeX(file,AVStr(file),sizeof(file));
*/
		if( isWindowsCE() ){
			nonxalpha_escapeX(file,AVStr(xfile),sizeof(xfile));
		}else{
		URL_reescape(file,AVStr(xfile),0,0);
		strsubst(AVStr(xfile),":","%3A");
		}
		encodeEntitiesX(pfile,AVStr(xpfile),sizeof(xpfile));
		strsubst(AVStr(xpfile),"\r","^M");

		anchor = 0;
		if( (GatewayFlags & GW_NO_ANCHOR)
		 || rcode != 0
		 || streq(file,"./")
		){
			/* suppress anchor */
		}else{
			anchor = 1;
			if( ClientFlags & PF_ADMIN_ON )
			if( streq(xfile,"../") ){
				/* just to escape to be converted to
				 * absolute /path ... */
				strcpy(xfile,"%2E%2E");
			}
		}
		if( anchor ){
			fprintf(fp,"<A HREF=\"%s\">",xfile);
		}
		fprintf(fp,"<IMG ALT=\"[%s]\" BORDER=0 ALIGN=TOP SRC=\"%s%s\">",
			iconalt,iconbase,iconsrc);
		if( anchor )
			fprintf(fp," <B>%s</B></A>",xpfile);
		else	fprintf(fp," %s",xpfile);
		fprintf(fp,"%s",eol);
	}
}
static void putDirPage(Connection *Conn,PCStr(path),PCStr(upath),FILE *fp)
{	FILE *tmp;

	tmp = TMPFILE("dir2ls");

	if( ClientFlags & PF_ADMIN_ON ){
		const char *opt = "a";
		dir2ls(path,NULL,opt,CVStr("%N"),tmp);
		fflush(tmp);
		fseek(tmp,0,0);
		putDir(Conn,path,tmp,fp,"\r\n");
		fclose(tmp);
		return;
	}

	dir2ls(path,NULL,NULL,CVStr("%N"),tmp);
	fflush(tmp);
	fseek(tmp,0,0);

	if( isWindowsCE() /* and non-ASCII in the tmp file */ ){
		fprintf(fp,"<META HTTP-EQUIV=Content-Type CONTENT=\"%s\">\n",
			"text/html; charset=utf-8");
	}
	fprintf(fp,"<TITLE> Index of /%s </TITLE>\n",upath);
	fprintf(fp,"<B>/%s</B>\n",upath);
	fprintf(fp,"<PRE>\n",path);

	putDir(Conn,path,tmp,fp,"\r\n");

	fclose(tmp);
	fprintf(fp,"<HR>\n",path);
	fprintf(fp,"</PRE>\n",path);
}

int service_cgi(Connection *Conn)
{
	return 0;
}
int service_cfi(Connection *Conn)
{
	return 0;
}

/*
 * v9.9.11 fix-140727a fixed CGI MOUNT for with/without /extra/path
 *
 * MOUNT="/vpath/* cgi:/rpath/*"
 * - usually referred as /vpath/script.cgi?query
 * - it can be referred as /vpath/script.cgi/extra/path?query
 * - thus "/extra/path" part must be stripped to get the path of script.cgi
 * - to get the script name, this functuion searches the first point from
 *   the tail until no MOUNT matches or matches to different MOUNT
 * - but this became not work since DIRMATCH in MOUNT is introduced
 *   because "/vpath" without "/" at the tail matches with the MOUNT.
 * - so turned to use MountVbase() to get /vpath/ part of the MOUNT.
 */
const char *MountVbase(PCStr(opts));

static int strip_extrapath(Connection *Conn,PCStr(method),PVStr(surl),xPVStr(durl),PVStr(dupath),PVStr(extrapath))
{	CStr(durlbuf,URLSZ);
	CStr(search,URLSZ);
	CStr(surlb,URLSZ);
	CStr(durlb,URLSZ);
	const char *dp; /* not "const" but fixed */
	int script_namlen;
	const char *mopts;
	refQStr(ep,surlb);

	dp = strrchr(surl,'/');
	if( dp == 0 || dp == surl )
		return 0;

	if( durl == NULL )
		setPStr(durl,durlbuf,sizeof(durlbuf));

	strcpy(surlb,surl);
	if( dp = strchr(surlb,'?') ){
		strcpy(search,dp);
		truncVStr(dp);
	}else	search[0] = 0;

	strcpy(durlb,surlb);
	/*
	if( CTX_mount_url_to(Conn,NULL,method,AVStr(durlb)) == 0 )
	*/
	mopts = CTX_mount_url_to(Conn,NULL,method,AVStr(durlb));
	if( mopts == 0 ){
		/* no MOUNT for the script: this should not happen */
		return 0;
	}
	dp = surlb + strlen(MountVbase(mopts)); /* top of script-name */
	ep = strchr(dp,'/');
	if( ep == 0 ){
		/* no /extra/path after script-name */
		return 0;
	}
	setVStrEnd(ep,0);
	strcpy(durlb,surlb);
	CTX_mount_url_to(Conn,NULL,method,AVStr(durlb));
	strcpy(durl,durlb);

	/*
	for(;;){
		if( dp = strrchr(surlb,'/') )
			truncVStr(dp);
		else	break;

		strcpy(durlb,surlb);
		if( CTX_mount_url_to(Conn,NULL,method,AVStr(durlb))==0 || strstr(durl,durlb)==0 ){
			*(char*)dp = '/';
			break;
		}
		strcpy(durl,durlb);
	}
	*/
	if( script_namlen = strlen(surlb) ){
		strcpy(extrapath,surl+script_namlen);
		if( dp = strchr(extrapath,'?') )
			truncVStr(dp);
		decomp_absurl(durl,VStrNULL,VStrNULL,AVStr(dupath),1024);
		sv1log("### stripped CGI extra PATH [%s]=[/%s%s]+[%s]\n",
			surl,dupath,search,extrapath);
		Xstrcpy(DVStr(surl,script_namlen),search);
		strcat(durl,search);
		return 1;
	}
	return 0;
}

/*
 * check if the given path is a file-path which is in MOUNT
 */
static int on_limit(Connection *Conn,PCStr(path))
{	const char *mok;
	CStr(vurl,URLSZ);

	mok = CTX_mount_url_fromL(Conn,AVStr(vurl),"file","localhost",
		path[0]=='/'?path+1:path,
		NULL,"http","-");
	return mok != NULL;
}

/*
 * Test if the path name is composed of "/SCRIPT_NAME/PATH_INFO" where
 * /SCRIPT_NAME is a name of CGI script, including the case where there are
 * hidden CGIs as "/SCRIPT_NAME/{welcome,index}.{shtml,cgi}"
 */
static FILE *searchExecUpward(Connection *Conn,PCStr(script),PCStr(upath),PVStr(expath),char **pathp,const char **ctypep,PVStr(iexecpath),int *mtimep)
{	CStr(ipath,URLSZ);
	const char *dp;
	FILE *fp;
	int isdir;
	const char *xp;
	int mode = S_EXECX;

	if( RequestFlags & QF_FTPXHTTP ){
		return 0;
	}
	fp = NULL;
	strcpy(ipath,*pathp);
	while( dp = strrchr(ipath,'/') ){
		if( dp[1] ) mode |= S_XPATH;
		((char*)dp)[1] = 0;
		isdir = fileIsdir(ipath);

		if( !on_limit(Conn,ipath) )
			break;

		if( isdir )
		/*
		if( fp = openIndex(Conn,ipath,upath,AVStr(iexecpath),S_EXECX,mtimep) ){
		*/
		if( fp = openIndex(Conn,ipath,upath,AVStr(iexecpath),mode,mtimep) ){
			strcpy(expath,*pathp+(dp-ipath));
			if( xp = strtailstr(script,expath) )
				truncVStr(xp);
			*pathp = (char*)iexecpath;
			*ctypep = filename2ctype(iexecpath);
			break;
		}
		truncVStr(dp);

		if( !isdir )
		if( fp = extfopen(ipath,"r") )
		/* and if it is a DGP, SSI or CGI script file ... */
		{
			strcpy(expath,*pathp+(dp-ipath));
			if( xp = strtailstr(script,expath) )
				truncVStr(xp);
			strcpy(iexecpath,ipath);
			*pathp = (char*)iexecpath;
			*ctypep = filename2ctype(iexecpath);
			break;
		}
	}
	return fp;
}
void deltailslash(PCStr(fpath))
{	const char *tp;

	for( tp = fpath+strlen(fpath)-1; fpath < tp; ){
		if( *tp == '/' )
			*(char*)tp-- = 0; /* not "const" but fixed */
		else	break;
	}
}
int deldupslash(char path[])
{	const char *sp;
	char *dp; /**/
	int inpath;

	inpath = 1;
	for( sp = dp = path; *sp; sp++ ){
		if( inpath && sp[0] == '/' && sp[1] == '/' ){
			/* ignore redundant slash */
		}else{
			if( *sp == '?' )
				inpath = 0;
			if( sp == dp )
				dp++;
			else	*dp++ = *sp; /**/
		}
	}
	if( sp != dp ){
		*dp = 0;
		return sp - dp;
	}else	return 0;
}

void setPartfilter(Connection *Conn,PCStr(query));
static FileSize putData1(Connection *Conn,FILE *fp,FILE *tc,PCStr(req),int vno,PCStr(serv),PCStr(ctype),PCStr(cenc),FileSize size,int mtime,int exp,PCStr(stat));
void exec_delegate(Connection *Conn,PCStr(req),PCStr(head),PCStr(script),PCStr(expath),PCStr(path),FILE *pfp,FILE *fc,FILE *tc);
int exec_cgi(Connection *Conn,PCStr(req),PCStr(reqhead),PCStr(scriptpath),PCStr(datapath),PCStr(vurl),PCStr(vpath),PCStr(scripturl),PCStr(extpath),FILE *fc,FILE *tc,int *stcodep);
void cgi_makeEnv(PCStr(conninfo),PCStr(req),PCStr(head),PCStr(vurl),PCStr(vpath),PCStr(datapath),PCStr(scripturl),PCStr(extrapath),int mac,const char *av[],StrVec *Evp);
/*
int exec_metassi(Connection *ctx,const char *av[],const char *ev[],FILE *fc,FILE *tc,FILE *htfp);
*/
int exec_metassi(Connection *ctx,PCStr(path),const char *av[],const char *ev[],FILE *fc,FILE *tc,FILE *htfp);
int scan_SHTML(Connection *Conn,FILE *tc,FILE *fc,FILE *fp,PCStr(req),PCStr(head),PCStr(vurl),PCStr(ourl),PCStr(path),PCStr(script),PCStr(expath));

void HTTP_readReqBody(Connection *Conn,FILE *fc){
	IStr(buf,1024);
	int cleng = 0;
	int ready1,ready2 = 0;
	int timeout = 1;
	int remleng,gotleng,isbin;

	ready1 = ready_cc(fc);
	if( getFieldValue2(OREQ_MSG,"Content-Length",AVStr(buf),sizeof(buf)) ){
		cleng = atoi(buf);
		if( 0 < cleng ){
			ready2 = fPollIn(fc,1000);
		}
	}
	remleng = sizeof(OREQ_MSG) - OREQ_LEN;
	/*
	if( fgetsByBlock(QVStr(OREQ_MSG+OREQ_LEN,OREQ),remleng,fc,
	*/
	if( fgetsByBlock(DVStr(OREQ_MSG,OREQ_LEN),remleng,fc,
		0,timeout,0,0,cleng,&gotleng,&isbin) ){
		OREQ_LEN += gotleng;
	}
	Verbose("readReqBody: %d,%d %d/%d / %d/%d\n",ready1,ready2,
		gotleng,cleng,remleng,isizeof(OREQ_MSG));
}
const char *HTTP_originalReqBody(Connection *Conn){
	const char *ep;
	if( ep = strstr(OREQ_MSG,"\r\n\r\n") ){
		return ep + 4;
	}
	if( ep = strstr(OREQ_MSG,"\n\n") ){
		return ep + 2;
	}
	return "";
}

extern int DELEGATE_LastModified;
int tobeCharconv(Connection *Conn,PCStr(ctype),int lastmod,int clIfMod){
	if( CCXactive(CCX_TOCL) )
	if( !CCXguessing(CCX_TOCL) ){
	 	if( strheadstrX(ctype,"text/",1)
		 || strcasestr(ctype,"/xml")
		){
			return 1;
		}
	}
	return 0;
}

/* req and url should be "const" */
FileSize putLocal(Connection *Conn,int vno,PCStr(method),PVStr(req),PCStr(head),xPVStr(url),FILE *fc,FILE *tc,int *stcodep)
{	FILE *fp;
	const char *ctype = NULL;
	const char *encoding = ME_7bit;
	FileSize size = 0;
	int lastmod = 0;
	int mtime = -1;
	int expire = 0;
	CStr(server,MaxHostNameLen);
	FileSize leng;
	int notMod = 0;
	int CGIonly = 0;
	const char *mok;
	const char *myproto;
	CStr(dstproto,256);
	CStr(hostport,MaxHostNameLen);
	CStr(proto,1024);
	CStr(host,MaxHostNameLen);
	const char *pp;
	CStr(vurl,URLSZ);
	char *path; /**/
	CStr(upath,URLSZ);
	CStr(ourl,URLSZ);
	CStr(apath,URLSZ);
	CStr(dpath,URLSZ);
	const char *execpath;
	const char *datapath; /* path of script.exe and data.html */
	CStr(iexecpath,URLSZ);
	CStr(idatapath,URLSZ); /* index.html extended */
	const char *search;
	const char *Search;
	CStr(search_script,URLSZ);
	CStr(script,URLSZ);
	CStr(expath,URLSZ);
	CStr(nupath,URLSZ);
	CStr(texurl,URLSZ);
	CStr(texpath,URLSZ); /* translated expath */
	IStr(ftpxcmd,128);
	IStr(ftpxopt,128);
	IStr(ftpxctype,128);

	HTTP_originalURLPath(Conn,AVStr(ourl));
	expath[0] = 0;

	Search = http_search_script;
	if( MountOptions ){
		const char *dp;
		if( dp = strcasestr(MountOptions,"search:") ){
			search_script[0] = 0;
			Xsscanf(dp+7,"%[^, ]",AVStr(search_script));
			if( search_script[0] && strcmp(search_script,"-") != 0 )
				Search = search_script;
			else	Search = NULL;
		}
	}

	if( strcasecmp(DST_PROTO,"cgi") == 0){
		CGIonly = 1;
		if( strip_extrapath(Conn,REQ_METHOD,AVStr(ourl),VStrNULL,AVStr(nupath),AVStr(expath)) )
			setPStr(url,nupath,sizeof(nupath));
	}
	lineScan(ourl,script);
	if( search = strchr(script,'?') )
		truncVStr(search);

	if( streq(method,"POST") || streq(method,"PUT") ){
		CGIonly = 1;
		lineScan(ourl,expath);
		script[0] = 0;
	}

	strcpy(dstproto,DST_PROTO);
	if( localPathProto(dstproto) ){
		strcpy(proto,DST_PROTO);
		strcpy(host,DST_HOST);
		path = (char*)url;
	}else{
		path = file_hostpath(url,AVStr(proto),AVStr(host));
	}
	if( path == NULL )
		return 0;
	IsLocal = 1;

	if( search = strchr(url,'?') ){
		truncVStr(search); search++;
	}

	sprintf(server,"DeleGate/%s",DELEGATE_ver());
	set_realserver(Conn,proto,host,0);

	if( !service_permitted(Conn,proto) ){
		sv1log("REJECT 1\n");
		*stcodep = 403;
		return putHttpRejectmsg(Conn,tc,proto,server,0,AVStr(req));
	}
	if( !Conn->from_myself && !IsMounted ){
		sv1log("REJECT 2\n");
		*stcodep = 403;
		return putHttpRejectmsg(Conn,tc,proto,server,0,AVStr(req));
	}

	/*
	 * if the path is not in absolute form, then make it so ...
	 */
	Verbose("## PATH=[%s]\n",path);
	if( *path != '/' ){
		sprintf(apath,"/%s",path);
		path = apath;
	}
	lineScan(path,upath);

	HTTP_ClientIF_HP(Conn,AVStr(hostport));

	mok = 0;
	myproto = CLNT_PROTO;

	vurl[0] = 0;
	if( path[0] == '/' )
	mok = CTX_mount_url_fromL(Conn,AVStr(vurl),proto,host,path+1,NULL,myproto,hostport);
	if( !mok )
	mok = CTX_mount_url_fromL(Conn,AVStr(vurl),proto,host,path,  NULL,myproto,hostport);

	if( ClientFlags & PF_ADMIN_ON ){
	}else
	if( mok == 0 ){
		/* not likely to be in normal situation...  since this
		 * function is called when the requested URL is mounted.
		 */
		sv1log("REJECT 4 -- NOT MOUNTED[%s]\n",url);
		*stcodep = 403;
		return putHttpRejectmsg(Conn,tc,proto,server,0,AVStr(req));
	}

	Verbose("## URL=[%s]\n",vurl);

	if( localPathProto(dstproto) )
	if( off_limit(vurl,AVStr(upath)) ){
		sv1log("REJECT 3\n");
		*stcodep = 403;
		return putHttpRejectmsg(Conn,tc,proto,server,0,AVStr(req));
	}

	nonxalpha_unescape(path,AVStr(dpath),1);
	path = dpath;
	/*
	 * Duplicate slash like Q://RedHat is not accepted by Win95/98.
	 * It can be generated by a request URL like "//RedHat"
	 * for MOUNT="/* file:Q:/*"
	 * Stripping duplicate slash should have been done at the
	 * requested URL parsing phase, or it should be resolved to
	 * 302 MovedTo response...
	 */
	deldupslash(path);
	if( *path == '/' && isFullpath(path+1) ){
		path += 1;
		Verbose("## PATH=/[%s]\n",path);
	}

	Verbose("## UPATH=[%s]\n",upath);

	if( search ){
		scanFTPxHTTP(Conn,search,AVStr(ftpxcmd),AVStr(ftpxopt),AVStr(ftpxctype));
	}
	if( isinFTPxHTTP(Conn) ){
		RequestFlags |= QF_FTPXHTTP;
		RequestFlags |= QF_NO_DELAY; /* dir or file */
		RequestFlags |= QF_NO_REWRITE;
		if( D_EXPIRE[0] == 0 ){
			sprintf(D_EXPIRE,"8s");
		}
		if( RequestFlags & QF_FTP_COMSTOR ){
			leng = ftpxhttpPOST(Conn,fc,tc,method,path,stcodep);
			if( *stcodep == 403 ){
				return putHttpRejectmsg(Conn,tc,proto,
					server,0,AVStr(req));
			}
			return leng;
		}
		if( isinListX("STAT,MLST",ftpxcmd,"c") ){
			strcpy(apath,path);
			fp = ftp_localLIST(Conn,NULL,ftpxcmd,ftpxopt,AVStr(apath));
			if( fp ){
				fprintf(tc,"HTTP/1.0 200\r\n");
				fprintf(tc,"\r\n");
				leng = copyfile1(fp,tc);
				fclose(fp);
				return leng;
			}else{
				*stcodep = 404;
				RequestFlags |= QF_NO_DELAY;
				return putUnknownPage(Conn,tc,vno,req);
			}
		}
	}

	if( search && Search || CGIonly ){
		if( CGIonly )
			execpath = path;
		else	execpath = Search;
		if( strtailchr(execpath) == '/' ){
			if( fp = openIndex(Conn,execpath,upath,AVStr(iexecpath),S_EXEC,&mtime) ){
				execpath = iexecpath;
				fclose(fp);
			}
		}
		if( CGIonly ){
			if( expath[0] ){
				lineScan(expath,texurl);
				datapath = expath;
				if( CTX_mount_url_to(Conn,NULL,method,AVStr(texurl)) ){
					strcpy(texpath,"/");
					decomp_absurl(texurl,VStrNULL,VStrNULL,QVStr(texpath+1,texpath),sizeof(texpath)-1);
					datapath = texpath;
				}
			}else	datapath = execpath;
		}else{
			lineScan(ourl,expath);
			if( search = strchr(expath,'?') )
				truncVStr(search);
			datapath = path;
			script[0] = 0;
			sv1log("Search-Script: %s %s %s\n",execpath,datapath,expath);
		}
		if( strtailchr(datapath) == '/' ){
			if( fp = openIndex(Conn,datapath,upath,AVStr(idatapath),S_DATA,&mtime) ){
				datapath = idatapath;
				fclose(fp);
			}
		}
		if( !strtailstrX(execpath,".shtml",1) ){
		IsLocal = 0; /* some side effect might remain ... ? */
		leng = exec_cgi(Conn,req,head,execpath,datapath,vurl,ourl,script,expath,fc,tc,stcodep);
		return leng;
		}
	}

	fp = NULL;
	if( !fileIsdir(path) ){
		if( strtailchr(path) == '/' ){
			CStr(fpath,URLSZ);
			/* A plain file is refered as if it's a directory.
			 * It must be treated as "404 Not Found" or it may be
			 * a CGI SCRIPT_NAME postfixed with a PATH_INFO
			 */
			lineScan(path,fpath);
			deltailslash(fpath);

			if( strtailchr(vurl) == '/' )
			if( File_isreg(fpath) )
			if( !strtailstr(fpath,".cgi") )
			if( !strtailstr(fpath,".dgp") )
			if( !strtailstr(fpath,".shtml") )
			{
				deltailslash(vurl);
				*stcodep = 301;
				return putMovedToX(Conn,tc,301,vurl);
			}
		}else
		if( RequestFlags & QF_FTP_COMLIST ){
			sv1log("--FTPxHTTP LIST for plain file (%s)\n",ftpxcmd);
			*stcodep = 404;
			RequestFlags |= QF_NO_DELAY;
			return putUnknownPage(Conn,tc,vno,req);
		}else
			fp = extfopen(path,"r");
/* peep CACHE as if it's a normal page...
		if( fp != NULL && strstr(mok,"iscache") ){
			cachepath_to_url(path,vurl);
			*stcodep = 302;
			return putMovedTo(Conn,tc,vurl);
		}
*/
	}else
	if( (RequestFlags & QF_FTP_COMRETR) && (RequestFlags & QF_FTP_COMLIST) == 0 ){
		sv1log("--FTPxHTTP RETR for dir. (%s)\n",ftpxcmd);
		*stcodep = 404;
		RequestFlags |= QF_NO_DELAY;
		return putUnknownPage(Conn,tc,vno,req);
	}else
	if( strtailchr(path) != '/' ){
		strcat(vurl,"/");
		*stcodep = 301;
		if( RequestFlags & QF_FTPXHTTP ){
			if( search ){
				Xsprintf(TVStr(vurl),"?%s",search);
			}
		}
		return putMovedToX(Conn,tc,301,vurl);
	}

	if( leng = putRobotsTxt(Conn,tc,fp,0) ){
		if( fp != NULL )
			fclose(fp);
		return leng;
	}

	if( fp == NULL ){
		if( fp == NULL )
		/* search local welcome.html before upper welcome.cgi */
		if( fileIsdir(path) && strtailchr(path) == '/' ){
		    if( RequestFlags & QF_FTPXHTTP ){
			fp = ftpxhttp(Conn,path,upath,search,ftpxcmd,AVStr(idatapath),&mtime);
			path = idatapath;
			if( ftpxctype[0] ){
				ctype = ftpxctype;
			}
			sv1log("--FTPxHTTP [%s] ctype=%s\n",
				search?search:"",ctype);
		    }else{
			fp = openIndex(Conn,path,upath,AVStr(idatapath),S_EXEC|S_DATA,&mtime);
			if( fp != NULL ){
				path = idatapath;
				ctype = filename2ctype(idatapath);
			}
		    }
		}

		if( fp == NULL )
		if( strtailstr(path,".html") ){
			CStr(xpath,2048);
			strcpy(xpath,path);
			Xstrcpy(QVStr(strrchr(xpath,'.'),xpath),".shtml");
			if( fp = extfopen(xpath,"r") ){
				sv1log("redirect [%s] -> [%s]\n",path,xpath);
				/*
				Xstrcpy(HVStr(URLSZ,url) path,xpath);
				*/
				Xstrcpy(ZVStr(path,strlen(path)+2),xpath);
			}
		}

		if( fp == NULL )
		fp = searchExecUpward(Conn,script,upath,AVStr(expath),&path,&ctype,
			AVStr(iexecpath),&mtime);

		if( fp == NULL ){
			sv1log("Unknown local %s: %s\n",path,proto);
			/*
			delayUnknown(Conn,1,req);
			... this is done in putUnknownPage()
			*/
			*stcodep = 404;
			/*
			return putHttpNotFound(Conn,tc,
				"No such file or directory\r\n");
			*/
			return putUnknownPage(Conn,tc,vno,req);
		}
	}

	if( strtailstr(path,".dgp") ){
		int CTX_countdown(Connection *Conn,PCStr(why));
		void stopStickyServer(PCStr(why));
		exec_delegate(Conn,req,head,script,expath,path,fp,fc,tc);
		/* 9.9.5 should be longjump to execSpecialist() ? */
		CTX_countdown(Conn,"DGP");
		stopStickyServer("DGP");
		Finish(0);
		return 1;
	}

	if( strtailstrX(path,".cgi",1) ) /* if( executable ) */
	{
		leng = exec_cgi(Conn,req,head,path,path,vurl,ourl,script,expath,fc,tc,stcodep);
		if( 0 <= leng ){
			fclose(fp);
			IsLocal = 0; /* some side effect might remain ... ? */
			return leng;
		}
	}

	if( strtailstrX(path,".shtml",1) ){
		checkTobeKeptAlive(Conn,"beforeSHTML");
		HTTP_readReqBody(Conn,fc);

		leng = scan_SHTML(Conn,tc,fc,fp,req,head,vurl,ourl,path,script,expath);
		if( 0 <= leng ){
			fclose(fp);
			return leng;
		}
	}

	if( ctype == NULL )
		ctype = filename2ctype(path);
	if( ctype == NULL ){
		int ch;
		int ci;
		ctype = "text/plain";
		/*
		while( (ch = getc(fp)) != EOF )
			if( ch & 0x80 ){
		*/
		for( ci = 0; ci < 0x20000 && (ch = getc(fp)) != EOF; ci++ )
		{
			if( ch == 0 || (ch & 0x80) ){
				ctype = "application/octet-stream";
				encoding = ME_binary;
				break;
			}
		}
		if( ch == EOF )
			clearerr(fp);
		fseek(fp,0,0);
	}
	size = file_sizeX(fileno(fp));
	if( 0 < mtime )
		lastmod = mtime;
	else	lastmod = file_mtime(fileno(fp));

	{
	int clIfMod;
	clIfMod = ClientIfModClock(Conn);
	if( 0 < clIfMod ){
		if( lastmod <= clIfMod ){
			if( tobeCharconv(Conn,ctype,lastmod,clIfMod) ){
				sv1log("Not Modified but with CHARCODE: %s\n",path);
			}else{
			notMod = 1;
			sv1log("Not Modified: %s\n",path);
			}
		}
	}
	}

	if( !RelayTHRU )
	if( pp = strstr(path,".dhtml") )
	if( pp[6] == 0 ){
		const char *msg;
		FILE *tmp = TMPFILE("DHTML");

		msg = (char*)malloc(size+1);
		((char*)msg)[0] = 0;
		IGNRETP fread((char*)msg,1,size,fp); /**/
		((char*)msg)[size] = 0;
		leng = put_eval_dhtml(Conn,ourl,tmp,msg);
		free((char*)msg);
		fflush(tmp);
		fseek(tmp,0,0);
		size = file_size(fileno(tmp));
leng =
putData1(Conn,tmp, tc,req,vno,server,ctype,encoding,size,lastmod,expire,NULL);
		fclose(tmp);
/*
		return leng;
*/
	}

if( search ) /* don't clear ?_?partname=... */
	setPartfilter(Conn,search);

	if( strcasecmp(method,"HEAD") == 0 ){
		if( vno < 100 )
			vno = 100;
leng = 
putData1(Conn,NULL,tc,req,vno,server,ctype,encoding,size,lastmod,expire,NULL);
	}else
	if( notMod ){
leng = 
putData1(Conn,NULL,tc,req,vno,server,ctype,encoding,size,lastmod,expire,
"304 Not modified");
		*stcodep = 304;
	}else
	if( CCXactive(CCX_TOCL) || CTX_check_codeconv(Conn,1) ){
leng =
putData1(Conn,fp,  tc,req,vno,server,ctype,encoding,size,lastmod,expire,NULL);
	}else{
leng =
putData1(Conn,fp,  tc,req,vno,server,ctype,encoding,size,lastmod,expire,NULL);
	}
	fclose(fp);
	return leng;
}

int putMBOX(Connection *Conn,FILE *in,FILE *out);

static int relay_part(Connection *Conn,FILE *in,FILE *out,PCStr(range)){
	int ch,rcc,wcc;
	FileSize skip,len;
	CStr(line,1024);

	len = 0;
	skip = 0;
	if( fgets(line,sizeof(line),in) != NULL ){
		if( strncmp(line,"SKIP ",5) == 0 )
			Xsscanf(line+5,"%lld %lld",&skip,&len);
		else	fputs(line,out);
	}
	for(;;){
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		fputs(line,out);
		if( *line == '\r' || *line == '\n' )
			break;
	}
	wcc = 0;
	for( rcc = 0;; rcc++ ){
		if((ch = getc(in)) == EOF )
			break;
		if( rcc < skip )
			continue;
		if(putc(ch,out) == EOF)
			break;
		wcc++;
		if( len && len <= wcc )
			break;
	}
	sv1log("relay_part(%lld %lld) %d/%lld\n",skip,len,wcc,len);
	return wcc;
}

char *HTTP_getRequestField(Connection *Conn,PCStr(fn),PVStr(b),int bz);
#define reqPartFrom	Conn->cl.p_range[0]
#define reqPartTo	Conn->cl.p_range[1]
#define reqPARTIALtail	(reqPartFrom < 0 && 0 <= reqPartTo)

int scanHttpRange(Connection *Conn,PCStr(req),FileSize *from,FileSize *to){
	CStr(fnam,32);
	CStr(fval,128);

	fieldScan(req,fnam,fval);
	if( strncasecmp(fval,"bytes=",6) == 0 ){
		*from = *to = 0;
		Xsscanf(fval+6,"%lld-%lld",from,to);
		reqPartFrom = *from;
		reqPartTo   = *to;
		return 0;
	}
	return -1;
}

FILE *putPARTfilter(Connection *Conn,FILE *src,FILE *dst,FileSize *lengp){
	FileSize size,len,leng;
	FILE *dstx;

	size = file_sizeX(fileno(src));
	if( reqPARTIALtail ){
		/* bytes=-ddd */
		reqPartFrom = size + reqPartFrom;
	}
	if( 0 <= reqPartFrom && reqPartTo <= 0 ){
		/* bytes=ddd- */
		reqPartTo = size - 1;
	}
	if( size <= reqPartFrom || size <= reqPartTo ){
		CStr(b,128);
		if(HTTP_getRequestField(Conn,"If-Range",AVStr(b),sizeof(b))){
			return NULL;
		}
		*lengp = -1;
		gotPART_SIZE = size;
		return NULL;
	}

	gotPART_FROM = reqPART_FROM;
	if( reqPART_TO <= 0 || size <= reqPART_TO )
		gotPART_TO = size - 1;
	else	gotPART_TO = reqPART_TO;
	gotPART_SIZE = size;
	leng = gotPART_TO - gotPART_FROM + 1;

	dstx = openFilter(Conn,"RANGE",(iFUNCP)relay_part,dst,"");
	if( dstx != NULL ){
		dst = dstx;
		*lengp = leng;
		len = reqPART_TO - reqPART_FROM + 1;
		if( ftell(src) == 0 ){
			/* it's a regular file, seek it without skip reading */
			fseek(src,reqPART_FROM,0);
			Lseek(fileno(src),reqPART_FROM,0);
			fprintf(dst,"SKIP 0 %lld\r\n",len);
		}else{
			fprintf(dst,"SKIP %lld %lld\r\n",reqPART_FROM,len);
		}
	}
	return dstx;
}

static FileSize putData1(Connection *Conn,FILE *fp,FILE *tc,PCStr(req),int vno,PCStr(serv),PCStr(ctype),PCStr(cenc),FileSize size,int mtime,int exp,PCStr(stat))
{	FILE *tcx;
	FileSize leng;
	int rewrite;

	FILE *dstx = 0;
	CStr(statb,1024);
	if( reqPARTIAL || reqPARTIALtail )
	if( fp != NULL && strncasecmp(req,"HEAD ",5) != 0 ){
		size = 0;
		if( dstx = putPARTfilter(Conn,fp,tc,&size) ){
			if( stat && *stat ){
				int code;
				const char *dp;
				code = atoi(stat);
				dp = wordScan(stat,statb);
				lineScan(dp,statb);
				Strins(AVStr(statb),"206 ");
				stat = statb;
			}else{
				stat = "206 Partial";
			}
			tc = dstx;
		}
		if( size < 0 ){
			FILE *tmp;
			stat = "416 Not satisfiable";
			tmp = TMPFILE("RANGE");
			fprintf(tmp,"Range not satisfiable: %lld - %lld\n",reqPartFrom,reqPartTo);
			fflush(tmp);
			size = ftell(tmp);
			fseek(tmp,0,0);
			ctype = "text/html";
leng = putHttpMssg(Conn,tc,tmp,req,vno,serv,ctype,cenc,size,mtime,exp,stat);
			fclose(tmp);
			return leng;
		}
	}

	if( fp != NULL )
	if( Conn->dg_putpart[0] != 0 ){
		CStr(head,16);
		head[0] = 0;
		fgets(head,sizeof(head),fp);
		fseek(fp,0,0);
		if( strncmp(head,"From ",5) == 0 ){
			FILE *tmp = TMPFILE("putMBOX");
			size = putMBOX(Conn,fp,tmp);
			ctype = "text/html";

leng = putHttpMssg(Conn,tc,tmp,req,vno,serv,ctype,cenc,size,mtime,exp,stat);

			fclose(tmp);
			return leng;
		}
	}

	rewrite = strcmp(ctype,"text/html") == 0;
	if( rewrite && (RequestFlags & QF_NO_REWRITE) ){
		rewrite = 0;
	}
	if( rewrite == 0 ){
		if( strheadstrX(ctype,"text/",1) ){
			if( CCXactive(CCX_TOCL) ){
				/* it should be done without Filter
				 * just for CHARCODE=guess
				 */
				rewrite = 1;
			}
			/*
			if( with CHARMAP ... ){
			}
			*/
		}
	}

	if( rewrite ){
/*
possibly this was necessary to suppress some undesirable rewriting, but
it is harmful for necessary rewriting of, partializing icon URLs, or
reverse MOUNT of URLs in local HTML documents...
DONT_REWRITE = 1;
*/
		fflush(tc);
		tcx = openHttpResponseFilter(Conn,tc);
	}else	tcx = tc;

	leng = putHttpMssg(Conn,tcx,fp,req,vno,serv,ctype,cenc,size,mtime,exp,stat);
	if( rewrite ){
		if( isWindowsCE() ){
			waitFT_FL(Conn,tcx,tc,leng,__LINE__);
		}
		/*
		else{
			dupclosed(fileno(tcx));
			waitFilterThreadX(Conn);
		}
		*/
		fclose(tcx);
		wait(0);
	}
	if( dstx != NULL ){
		fclose(dstx);
		wait(0);
	}
	return leng;
}

int clearServ(Connection *Conn);
int finishThreadYY(int tgid);
/* 9.9.8 to mux. connections (for SSI #include) over a YYMUX */
int exec_metassiY(Connection *Conn,PCStr(path),const char *av[],const char *ev[],FILE *fc,FILE *tc,FILE *fp){
	int leng;
	int tgid;
	int gwf;

	if( getthreadgid(0) == 0 ){
		setthreadgid(getthreadid(),getthreadid());
		/* set thread-gid to sweep YYs by finishThreadYY() */
	}
	tgid = getthreadgid(0);
	gwf = GatewayFlags;
	GatewayFlags |= GW_IS_YYSHD; /* mux. connections in a single session */
	leng = exec_metassi(Conn,path,av,ev,fc,tc,fp);
	GatewayFlags = gwf;

	if( !lSINGLEP() ){
		/* should be done on the finishing of the server process? */
		clearServ(Conn);
		finishThreadYY(tgid); /* sweep YYMUX and resumptions */
	}
	return leng;
}

int scan_SHTML(Connection *Conn,FILE *tc,FILE *fc,FILE *fp,PCStr(req),PCStr(head),PCStr(vurl),PCStr(ourl),PCStr(path),PCStr(script),PCStr(expath))
{	CStr(conninfo,4096);
	const char *av[32]; /**/
	const char *ev[128]; /**/
	CStr(eb,4096);
	CStr(myhp,MaxHostNameLen);
	StrVec Env;
	FILE *tcx;
	int leng;

	randenv();
	make_conninfo(Conn,AVStr(conninfo));
	SVinit(&Env,"putLocal",ev,128,AVStr(eb),sizeof(eb));
	cgi_makeEnv(conninfo,req,head,vurl,ourl,path,script,expath,32,av,&Env);
	if( !HTTP_relayThru(Conn) )
	{
		/*
		Content-Length should be adjusted after conversion.
		ServerFlags |= PF_DO_RESPBUFF;
		*/
		tcx = openHttpResponseFilter(Conn,tc);
	}
	else	tcx = tc;
	/*
	leng = exec_metassi(Conn,path,av,ev,fc,tcx,fp);
	*/
	leng = exec_metassiY(Conn,path,av,ev,fc,tcx,fp);
	if( tcx != tc ){
		fclose(tcx);
		wait(0);
	}
	return leng;
}

int ssi_main(int ac,const char *av[],Connection *Conn){
	FILE *fc,*tc,*fp;
	int ai;
	const char *a1;
	CStr(req,256);
	CStr(head,256);
	CStr(vurl,256);
	CStr(ourl,256);
	CStr(path,256);
	CStr(script,256);
	CStr(exepath,256);
	HTTP_env he;

	bzero(Conn,sizeof(Connection));
	he.r_resp.r_msg = UTalloc(SB_CONN,1024,1);
	he.r_i_buff = UTalloc(SB_CONN,URLSZ,1);
	he.r_o_buff = UTalloc(SB_CONN,OBUFSIZE,1);
	he.r_savConn = UTalloc(SB_CONN,sizeof(Connection),8);
	he.r_acclangs = UTalloc(SB_CONN,1024,1);

	bzero(&he,sizeof(HTTP_env));
	Conn->cl_reqbuf = (void*)&he;
	Conn->cl_reqbufsize = sizeof(HTTP_env);
	DONT_REWRITE = 1;

	fc = stdin;
	tc = stdout;
	fp = 0;
	strcpy(req,"");
	strcpy(head,"");
	strcpy(vurl,"");
	strcpy(ourl,"");
	strcpy(path,"");
	strcpy(script,"");
	strcpy(exepath,"");
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' ){
		}else
		if( fp = fopen(a1,"r") ){
			strcpy(path,a1);
		}else{
			fprintf(stderr,"Cannot open: %s\n",a1);
			exit(1);
		}
	}
	if( fp == NULL ){
		exit(1);
	}
	scan_SHTML(Conn,tc,fc,fp,req,head,vurl,ourl,path,script,exepath);
	exit(0);
	return 0;
}

FileSize CCV_relay_textXX(Connection *Conn,FILE *in,FILE *out,FILE *dup,FileSize *wcc);
FileSize putHttpMssg(Connection *Conn,FILE *dst,FILE *src,PCStr(req),int vno,PCStr(serv),PCStr(ctype),PCStr(cenc),FileSize leng,int mtime,int exp,PCStr(stat))
{	int hlen;
	FileSize blen;
	FileSize wcc;
	const char *xcharset;
	CStr(xctype,256);

	if( Conn->fi_builtin == 0 /* codeconv will be done in the filter */
	 && strncasecmp(ctype,"text/",5) == 0 )
		xcharset = HTTP_outCharset(Conn);
	else	xcharset = 0;
	if( xcharset ){
		strcpy(xctype,ctype);
		replace_charset_value(AVStr(xctype),xcharset,1);
		ctype = xctype;
	}

	if( leng == 0 && 0 < mtime ){
		leng = EMPTYBODY_SIZE;
	}
	if( src != NULL ){
		getBodyMD5(Conn,src);
	}

	if( (unsigned int)0xFFFFFFFF <= leng ){
		HTTP_clntClose(Conn,"h:huge file larget than 4GB");
	}
	hlen = putHttpHeader1X(Conn,dst,vno,serv,ctype,cenc,leng,mtime,exp,stat);

	blen = 0;
	if( src != NULL && strncasecmp(req,"HEAD ",5) != 0 ){
		if( xcharset )
		{
			/* Connection:Keep-Alive must be closed if the
			 * output length differes from the Content-Length
			 */
			/*
			blen = CCV_relay_text(Conn,src,dst,NULL);
			*/
			blen = CCV_relay_textXX(Conn,src,dst,NULL,&wcc);
			if( 0 < wcc && wcc != leng ){
				fflush(dst);
				sv1log("CCV_relay_text: %lld/%lld/%lld, endHCKA:%d\n",
					wcc,blen,leng,CKA_RemAlive);
				CKA_RemAlive = 0;
			}
		}
		else	blen = copyfile1(src,dst);
	}

	/* return length including header length because some caller function
	 * needs non-zero value to judge the success...
	 */
	return hlen + blen;
}

/* Return true if the request is for "/robots.txt" from a client which
 * regards this DeleGate as an origin HTTP server.  In this case, the
 * original form of the request is like "GET /robots.txt HTTP/1.0".
 * In HTTP/1.1 or later, the existence of "Host: server" field might be
 * considered also ... ?
 */
static void norobot1(FILE *fp,PCStr(url),PCStr(proto),PCStr(user),PCStr(pass),PCStr(host),int port,PCStr(path),PCStr(opts))
{	int disable;
	int allow = 0;

	if( strstr(opts,"robots=ok") )
	{
		disable = 0;
		allow = 1;
	}
	else
	if( strstr(opts,"robots=no") )
	{
		disable = 1;
		allow = -1;
	}
	else
	if( streq(proto,"nntp") || streq(proto,"ftp") )
		disable = 1;
	else	disable = 0;

	if( disable )
	{
		sv1log("/robots.txt:Disallow %s #%s\n",url,opts);
		fprintf(fp,"Disallow: %s\r\n",url);
	}else
	if( allow ){
		/* explicitly allowed */
		sv1log("/robots.txt:%s %s #%s\n",
			0<allow?"allow":"disallow",url,opts);
		/*
		if( 0 < allow ){
			fprintf(fp,"Allow: %s\r\n",url);
		}
		*/
	}
}

int CTX_vhost(Connection *Conn,PVStr(host));
void CTX_scan_mtabX(DGC*ctx,PCStr(vhost),iFUNCP func,void *arg);

void DHTML_printNoRobots(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),PCStr(value))
{
	IStr(vhost,MaxHostNameLen);
	int vport;

	strcpy(vhost,"-");
	vport = CTX_vhost(Conn,DVStr(vhost,1));

	/* if( streq(arg,"mount") ) */
		if( vport ){
			Xsprintf(TVStr(vhost),":%d",vport);
			CTX_scan_mtabX(Conn,vhost,(iFUNCP)norobot1,fp);
		}else
		CTX_scan_mtab(Conn,(iFUNCP)norobot1,fp);
}
int HTTP_originalURLmatch(Connection *Conn,PCStr(urlc));
int reqRobotsTxt(Connection *Conn)
{
	return HTTP_originalURLmatch(Conn,"/robots.txt");
}
int mergeRobotsTxts(FILE *rtf1,FILE *rtf2,FILE *out);
int putRobotsTxt(Connection *Conn,FILE *tc,FILE *afp,int ismsg)
{	int leng,cleng;
	FILE *org,*gen,*tmp;
	CStr(line,1024);

	if( !reqRobotsTxt(Conn) )
		return 0;

	sv1log("#### Generate /robots.txt\n");
	if( afp == NULL ){
		tmp = TMPFILE("RobotsTxt");
		fprintf(tmp,"#### Generated by a proxy - %s\r\n",
			DELEGATE_version());
		putBuiltinHTML(Conn,tmp,"/robots.txt","robots.dhtml",
			NULL,(iFUNCP)printConn,NULL);
		fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);

		putHttpHeader1(Conn,tc,NULL,"text/plain",ME_7bit,cleng,0);
		if( RespWithBody ) copyfile1(tmp,tc);
		fclose(tmp);
		return cleng;
	}

	if( ismsg ){
		int rcode = 0;
		if( fgets(line,sizeof(line),afp) != NULL )
			sscanf(line,"%*s %d",&rcode);
		if( rcode != 200 )
			return putRobotsTxt(Conn,tc,NULL,ismsg);

		while( fgets(line,sizeof(line),afp) ){
			Verbose("SKIP HEADER %s",line);
			if( *line == '\r' || *line == '\n' )
				break;
		}
	}

	tmp = TMPFILE("RobotsTxt++");
	org = TMPFILE("RobotsTxt-1");
	copyfile1(afp,org);
	fflush(org);
	fseek(org,0,0);

	gen = TMPFILE("RobotsTxt-2");
	putBuiltinHTML(Conn,gen,"/robots.txt","robots.dhtml",
		NULL,(iFUNCP)printConn,NULL);
	fflush(gen);
	fseek(gen,0,0);

	leng = mergeRobotsTxts(org,gen,tmp);
	fflush(tmp); cleng = ftell(tmp); fseek(tmp,0,0);
	putHttpHeader1(Conn,tc,NULL,"text/plain",ME_7bit,cleng,0);
	if( RespWithBody ) copyfile1(tmp,tc);
	fclose(tmp);

	fclose(org);
	fclose(gen);
	return leng;
}

int mergeRobotsTxts(FILE *rtf1,FILE *rtf2,FILE *out)
{	int leng,len,tx,ti,out2;
	const char *rts[2]; /**/
	char ch;
	const char *sp;
	const char *np;
	const char *records[2][1024]; /**/
	CStr(fn,256);
	CStr(val,256);
	const char *rs1;
	const char *rs2;
	const char *wildua[2]; /**/
	int wildrec[2];
	CStr(msg,1024);

	len = 0; rts[0] = freadfile(rtf1,&len);
	len = 0; rts[1] = freadfile(rtf2,&len);

	for( ti = 0; ti < 2; ti++ ){
		tx = 0;
		records[ti][tx++] = rts[ti];
		wildrec[ti] = -1;
		wildua[ti] = 0;
		for( sp = rts[ti]; sp && *sp; sp = np ){
			if( wildua[ti] == NULL ){
				scan_field1(sp,AVStr(fn),sizeof(fn),AVStr(val),sizeof(val));
				if( strcasecmp(fn,"User-Agent") == 0 )
				if( strcmp(val,"*") == 0 ){
					wildua[ti] = (char*)sp;
					wildrec[ti] = tx - 1;;
				}
			}
			if( *sp == '\r' || *sp == '\n' )
				records[ti][tx++] = (char*)sp;
			if( np = strchr(sp,'\n') )
				np++;

			if( 1000 < tx ){
				sv1log("#### Too large /robots.txt\n");
				break;
			}
		}
		records[ti][tx++] = rts[ti] + strlen(rts[ti]);
		records[ti][tx] = 0;
	}

	leng = 0;
	for( tx = 0; (rs1 = records[0][tx]) && *rs1; tx++ ){
		leng += len = records[0][tx+1] - rs1;
		fwrite(rs1,1,len,out);
		if( 0 < len && rs1[len-1] != '\n' ){
			/* 9.9.1 the last line ended without NL */
			sv1log("#### Appended CRLF [%X]\n",rs1[len-1]);
			fwrite("\r\n",1,2,out);
			leng += 2;
		}
		if( tx == wildrec[0] && 0 <= (ti = wildrec[1]) ){
			sprintf(msg,"#### Appended by a proxy - %s\r\n",
				DELEGATE_version());
			leng += strlen(msg);
			fwrite(msg,1,strlen(msg),out);

			rs2 = records[1][ti];
			leng += len = wildua[1] - rs2;
			fwrite(rs2,1,len,out);

			fwrite("#",1,1,out);
			leng++;
			leng += len = records[1][ti+1] - wildua[1];
			fwrite(wildua[1],1,len,out);
		}
	}

	out2 = 0;
	for( ti = 0; (rs2 = records[1][ti]) && *rs2; ti++ )
	if( ti != wildrec[1] ){
		if( out2++ == 0 ){
			sprintf(msg,"\r\n");
			sprintf(msg,"#### Generated by a proxy - %s\r\n",
				DELEGATE_version());
			leng += strlen(msg);
			fwrite(msg,1,strlen(msg),out);
		}
		leng += len = records[1][ti+1] - rs2;
		fwrite(rs2,1,len,out);
	}
	return leng;
}

extern int DELEGATE_EXTOVW;
extern int BREAK_STICKY;
static int exec_loop;
static const char *exec_path;
int MAX_DGP_LOOP = 1;
void clear_mtab();
void DELEGATE_clearEnv();
void DELEGATE_configx(Connection *Conn,int force);

void exec_delegate(Connection *Conn,PCStr(req),PCStr(head),PCStr(script),PCStr(expath),PCStr(path),FILE *pfp,FILE *fc,FILE *tc)
{	CStr(buf,1024);
	CStr(ibuf,0x10000);
	refQStr(ibp,ibuf); /**/
	int rcc;
	Connection NewConnBuf, *NewConn = &NewConnBuf;

	if( MAX_DGP_LOOP < exec_loop
	 || exec_path != NULL && strcmp(exec_path,path) == 0){
		sv1log("## break DGP loop [%d] %s\n",exec_loop,path);
		Finish(0);
	}
	exec_loop++;
	exec_path = stralloc(path);

	sv1log("DeleGate[%s][%s][%s]\n",path,script,expath);
	if( *expath == 0 )
		expath = "/";
	sprintf(ibp,"%s %s HTTP/%s\r\n",REQ_METHOD,expath,REQ_VER);
	ibp += strlen(ibp);
	strcpy(ibp,head);
	ibp += strlen(ibp);
	while( 0 < (rcc = fgetBuffered(AVStr(ibp),1024,fc)) )
		ibp += rcc;
	XsetVStrEnd(AVStr(ibp),0);

	clear_mtab();

	DELEGATE_clearEnv();
	DELEGATE_EXTOVW = 1;

/* access control about source by RELIABLE is done in putLocal */
/* access control in this DeleGate must not be overwritten.
 * table for REMITTABLE,REACHABLE,RELIABLE,PERMIT should be able to
 * be pushed onto some "STACK"...
 * With such stack, REMITTABLE,REACHABLE,RELIABLE will be replaced
 * by "upper-level PERMIT"
 */
	load_script(NULL,NULL,path);
	DELEGATE_EXTOVW = 0;

	ConnCopy(NewConn,Conn);
	DELEGATE_configx(NewConn,1);
	DDI_pushCbuf(NewConn,ibuf,ibp-ibuf);

	Conn = NewConn;
	strcpy(DFLT_PROTO,"http");
	DFLT_HOST[0] = 0;
	DFLT_PORT = 0;
	ACT_SPECIALIST = 1;

	BREAK_STICKY = 1;
	DontKeepAlive = 1;
	execSpecialist(NewConn,fileno(fc),tc,-1);
}

void getProxyControlPart(Connection *Conn,PVStr(url))
{	const char *pxp;
	const char *pxe;
	CStr(pxc,1024);

	if( ProxyControlMARK == 0 || *ProxyControlMARK == 0 )
		return;

	if( pxp = strstr(url,ProxyControlMARK) ){
		wordScan(pxp+strlen(ProxyControlMARK),ProxyControls);
		pxe = wordScan(pxp+strlen(ProxyControlMARK),pxc);
		ovstrcpy((char*)pxp,pxe);
sv1log("#### PXC[%s]\n",pxc);
		if( strncmp(pxc,"partname=",9) == 0 ){
			setPartfilter(Conn,pxc+9);
		}
	}
}

int putMBOX(Connection *Conn,FILE *in,FILE *out)
{	int mn = 1;
	int mi;
	CStr(line,1024);
	CStr(xline,2048);
	CStr(param1,1024);
	CStr(params,1024);
	CStr(xparams,1024);
	refQStr(pp,params); /**/
	const char *sp;
	int size;
	CStr(style,32);
	CStr(returl,1024);
	CStr(fn,128);
	CStr(fv,1024);
	CStr(fvx,1024);
	CStr(From,128);
	CStr(To,128);
	CStr(Date,128);
	CStr(Subj,128);
	int topoff;

	style[0] = 0;
	returl[0] = 0;

	setVStrEnd(pp,0);
	for( sp = Conn->dg_putpart; *sp; ){
		sp = wordscanY(sp,AVStr(param1),sizeof(param1),"^&");
		if( strncmp(param1,"n=",2) == 0 ){
			mn = atoi(param1+2);
			continue;
		}else
		if( strncmp(param1,"sty=",4) == 0 ){
			wordScan(param1+4,style);
			continue;
		}else
		if( strncmp(param1,"ret=",4) == 0 ){
			wordScan(param1+4,returl);
		}
		if( params < pp )
			setVStrPtrInc(pp,'&');
		strcpy(pp,param1);
		pp += strlen(pp);
		if( *sp == '&' )
			sp++;
	}

	line[0] = 0;
	for( mi = 0; mi < mn; ){
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		if( strncmp(line,"From ",5) == 0 )
			mi++;
	}

sv1log("## MBOX mn=%d off=%d params[%s]\n",mn,ll2i(ftell(in)-strlen(line)),params);

	topoff = ftell(in);
	From[0] = 0;
	Subj[0] = 0;
	To[0] = 0;
	Date[0] = 0;
	for(;;){
		if( RFC822_fgetsHeaderField(AVStr(line),sizeof(line),in) == NULL )
			break;
		if( *line == '\r' || *line == '\n' )
			break;
		scan_field1(line,AVStr(fn),sizeof(fn),AVStr(fv),sizeof(fv));
		MIME_strHeaderDecode(fv,AVStr(fvx),sizeof(fvx));
		if( streq(fn,"From")   ) lineScan(fvx,From);
		if( streq(fn,"To")     ) lineScan(fvx,To);
		if( streq(fn,"Subject")) lineScan(fvx,Subj);
		if( streq(fn,"Date")   ) lineScan(fvx,Date);
		if( streq(fn,"Content-Type")   ){
			/* should get charset to be passed to output */
		}
	}

	strcpy(xparams,params);
	if( style[0] ){
		if( xparams[0] )
			strcat(xparams,"&");
		strcat(xparams,"sty=");
		strcat(xparams,style);
	}
	if( xparams[0] )
		strcat(xparams,"&");

	if(1 < mn)
	fprintf(out,"<A HREF=?%sn=%d>PREV</A>\r\n",xparams,mn-1);
	else
	fprintf(out,"PREV\r\n");
	fprintf(out,"<A HREF=?%sn=%d>NEXT</A>\r\n",xparams,mn+1);

	if( params[0] )
		strcat(params,"&");
	if( strcmp(style,"source") == 0 )
	fprintf(out,"<A HREF=?%sn=%d><small>HIDE_HEAD</small></A>\r\n",params,mn);
	else
	fprintf(out,"<A HREF=?%sn=%d&sty=source><small>SHOW_HEAD</small></A>\r\n",params,mn);

	if( returl[0] ){
	fprintf(out,"<A HREF=\"%s\">RETURN</A>",returl);
	}

	fprintf(out,"<HR>\n");
	encodeEntitiesX(From,AVStr(line),sizeof(line));
	fprintf(out,"From: %s<BR>\n",line);
	encodeEntitiesX(To,AVStr(line),sizeof(line));
	fprintf(out,"To: %s<BR>\n",line);
	encodeEntitiesX(Subj,AVStr(line),sizeof(line));
	fprintf(out,"Subject: %s<BR>\n",line);
	encodeEntitiesX(Date,AVStr(line),sizeof(line));
	fprintf(out,"Date: %s<BR>\n",line);
	fprintf(out,"<HR>\n");

	fprintf(out,"<PRE>\r\n");

	if( strcmp(style,"source") == 0 ){
	    fseek(in,topoff,0);
	    for(;;){
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		fputs(line,out);
		if( *line == '\r' || *line == '\n' )
			break;
	    }
	}

	for(;;){
		const char *cp;
		char ch;
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		if( strncmp(line,"From ",5) == 0 )
			break;

		CTX_line_codeconv(Conn,line,AVStr(xline),"text/plain");
		encodeEntitiesX(xline,AVStr(line),sizeof(line));
		fputs(line,out);
	}
	fprintf(out,"</PRE>\r\n");

	size = ftell(out);
	fflush(out);
	fseek(out,0,0);
	return size;
}
