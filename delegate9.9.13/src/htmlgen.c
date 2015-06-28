/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	htmlgen.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960126	extracted from httpd.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "delegate.h"
#include "ystring.h"
#include "file.h"
#include "url.h"

int HTML_put1sY(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val));
#define HTML_put1s(fp,fmt,val) HTML_put1sY(Conn,fp,fmt,val)
#define put1s	HTML_put1s
static void Nvclear(Connection *Conn);

typedef struct {
	int	 c_flags;
	int	 c_nflush;
	CCXP	 c_CCX;
	FILE	*c_fp;
	int	 c_peak;
	MStr(	 c_buf,1024);
	MStr(	 c_xb,2048);
} CCXFILE;

void CFinit(CCXFILE *CF,CCXP ccx,FILE *fp){
	CF->c_flags = 0;
	CF->c_nflush = 0;
	CF->c_fp = fp;
	CF->c_peak = 0;
	if( CCXactive(ccx) ){
		CF->c_CCX = ccx;
	}else{
		CF->c_CCX = 0;
	}
}
void CCXfflush(CCXFILE *CF){
	int ol;

	CF->c_nflush++;
	ol = CCXexec(CF->c_CCX,CF->c_buf,CF->c_peak,AVStr(CF->c_xb),sizeof(CF->c_xb));
	if( CF->c_flags )
		fprintf(stderr,"CCXflush %3d %d %d -> %d\n",
			CF->c_nflush,CF->c_peak!=ol,CF->c_peak,ol);
	if( CF->c_flags & 2 )
		fwrite(CF->c_buf,1,CF->c_peak,stderr);

	fwrite(CF->c_xb,1,ol,CF->c_fp);
	CF->c_peak = 0;
}
#define CCXflush(CF)	{ if( 0 < CF.c_peak ) CCXfflush(&CF); }
#define CCXfputs(CF,s)	{ \
	if( CF.c_fp ){ \
		if( CF.c_CCX == NULL ){ \
			fputs(s,CF.c_fp); \
		}else{ \
			int len = strlen(s); \
			if( sizeof(CF.c_buf) <= CF.c_peak + len ) \
				CCXflush(CF); \
			Xstrcpy(DVStr(CF.c_buf,CF.c_peak),s); \
			CF.c_peak += len; \
		} \
	} \
}
#define CCXfputc(CF,c)	{ \
	if( CF.c_fp ){ \
		if( CF.c_CCX == NULL ){ \
			putc(c,CF.c_fp); \
		}else{ \
			if( sizeof(CF.c_buf) <= CF.c_peak + 1 ) \
				CCXflush(CF); \
			setVStrElem(CF.c_buf,CF.c_peak,c); \
			CF.c_peak++; \
		} \
	} \
}

static int HDBG;

int HTTP_originalURLx(Connection *Conn,PVStr(url),int siz);
void HTTP_redirect_HTML0(Connection *Conn,PCStr(proto),PCStr(host),int port,PCStr(req),PCStr(src),PVStr(dst));
int putDeleGateInline(Connection *Conn,FILE *tc,PCStr(align));
int putFrogVer(Connection *Conn,FILE *tc);
void DHTML_printNoRobots(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),PCStr(value));
int DHTML_printMount(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(param));
int DHTML_printAuth(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),const void *value);
int DHTML_printAdmin(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(param));
int DHTML_pringGenAuth(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),PCStr(value));
void HTTP_fprintmsg(Connection *Conn,FILE *fp,PCStr(fmt));
const char *start_time();

static const char *home_page = "/-/";

static const char *msg_not_found = "\
<TITLE> Builtin Message %s Not Found </TITLE>\n\
Builtin message %s not found.\n\
";

typedef struct {
	int	 when;
  const	char	*url;
  const	char	*rurl;
	int	 size;
	int	 time;
	char	 data[1];
} Cache;

#define NUMCACHE	128
typedef struct {
	Cache  *he_caches[NUMCACHE]; /**/
	int	he_cachex;
} HtmlGenEnv;
static HtmlGenEnv *htmlGenEnv;
#define caches	htmlGenEnv->he_caches
#define cachex	htmlGenEnv->he_cachex
void minit_htmlgen()
{
	if( htmlGenEnv == 0 ){
		htmlGenEnv = NewStruct(HtmlGenEnv);
	}
}

static int putCacheX(PCStr(url),PCStr(rurl),PCStr(data),int size,int date);
static int putCache(PCStr(url),PCStr(rurl),PCStr(data),int size)
{
	int date = time(0);
	return putCacheX(url,rurl,data,size,date);
}
static int putCacheX(PCStr(url),PCStr(rurl),PCStr(data),int size,int date)
{	Cache *cp,*ocp;
	int cx;

	minit_htmlgen();

	if( elnumof(caches) <= cachex )
		return -1;

	for( cx = 0; cx < cachex; cx++ ){
	    ocp = caches[cx];
	    if( streq(url,ocp->url) )
	    if( streq(rurl,ocp->rurl) )
	    if( bcmp(data,ocp->data,size) == 0 )
	    {
		/* internal data will never be changed ... */
		ocp->when = MySeqNum();
		ocp->time = time(0);
		return cx;
	    }
	}

	cp = (Cache*)malloc(sizeof(Cache)+size-1);
	cp->when = MySeqNum();
	cp->url = stralloc(url);
	cp->rurl = stralloc(rurl);
	cp->size = size;
	/*
	cp->time = time(0);
	*/
	cp->time = date;
	bcopy(data,cp->data,size); /**/

	for( cx = 0; cx < cachex; cx++ ){
	    ocp = caches[cx];
	    if( streq(url,ocp->url) ){
		free((char*)ocp->url);
		free((char*)ocp->rurl);
		free(ocp);
		break;
	    }
	}
	caches[cx] = cp;
	if( cx == cachex )
		cachex++;
	else	sv1log("####[%d][reloaded] %s\n",cx,url);
	return cx;
}
void HTML_clearCache(PCStr(url)){
	int cx;
	Cache *cp;
	for( cx = 0; cx < cachex; cx++ ){
	    cp = caches[cx];
	    if( streq(url,cp->url) || streq(url,cp->rurl) ){
		cp->time = 0;
		break;
	    }
	}
}

static int getCacheX(PCStr(url),PVStr(rurl),PVStr(data),int size,int *date,int reload);
static int getCache(PCStr(url),PVStr(rurl),PVStr(data),int size,int reload)
{
	int date;
	return getCacheX(url,BVStr(rurl),BVStr(data),size,&date,reload);
}
static int getCacheX(PCStr(url),PVStr(rurl),PVStr(data),int size,int *date,int reload)
{	int cx,rcc;
	Cache *cp;

	minit_htmlgen();

	for( cx = 0; cx < cachex; cx++ ){
	    cp = caches[cx];
	    if( streq(url,cp->url) || streq(url,cp->rurl) ){
		if( cp->time == 0 ){
			break;
		}
		if( reload && cp->when != MySeqNum() ){
			sv1log("####[%d][to be reloaded] %s\n",cx,url);
			break;
		}
		if( size < cp->size )
			rcc = size;
		else	rcc = cp->size;
		strcpy(rurl,cp->rurl);
		*date = cp->time;
		Bcopy(cp->data,data,rcc);
		return rcc;
	    }
	}
	return -1;
}

int adecrypty(PCStr(key),int klen,PCStr(ins),int ilen,char out[]);
int getContentCRC(Connection *Conn,FILE *mfp){
	CStr(fv,128);
	CStr(crc,128);
	CStr(key,128);
	CStr(xcrc,128);
	int scrc = -1;

	if( fgetsHeaderField(mfp,"Content-CRC32",AVStr(fv),sizeof(fv)) == 0 )
		return -1;

	truncVStr(crc);
	truncVStr(key);
	Xsscanf(fv,"%[^;]; key=%s",AVStr(crc),AVStr(key));
	if( key[0] ){
		adecrypty(key,strlen(key),crc,strlen(crc),(char*)xcrc);
		sscanf(xcrc,"%X",&scrc);
	}else{
		sscanf(crc,"%X",&scrc);
	}
	return scrc;
}
int strCRC32(PCStr(str),int len);
int checkMD5(FILE *mfp,PCStr(url),PCStr(buf),int siz);
	const char *getMssgX(PCStr(name),int *size,int *date);
	int getBuiltinDataX(Connection *Conn,PCStr(what),PCStr(aurl),PVStr(buf),int size,int *date,PVStr(rurl));
int getBuiltinData(Connection *Conn,PCStr(what),PCStr(aurl),PVStr(buf),int size,PVStr(rurl))
{
	int date;
	return getBuiltinDataX(Conn,what,aurl,BVStr(buf),size,&date,BVStr(rurl));
}
int getBuiltinDataX(Connection *Conn,PCStr(what),PCStr(aurl),PVStr(buf),int size,int *date,PVStr(rurl))
{	int rcc;
	FILE *mfp;
	CStr(murl,1024);
	const char *iurl;
	const char *data;

	CStr(xurl,1024);
	const char *opts;
	int scrc = 0;
	int ucrc;

	*date = 0;
	if( Conn->mo_flags & MO_BI_EXTERN ){
		strcpy(xurl,aurl);
		strsubst(AVStr(xurl),"/-/","/-/ext/");
		aurl = xurl;
	}
	/*
	if( 0 <= (rcc = getCache(aurl,AVStr(rurl),BVStr(buf),size,DontReadCache)) ){
	*/
	if( 0 <= (rcc = getCacheX(aurl,AVStr(rurl),BVStr(buf),size,date,DontReadCache)) ){
		Verbose("####[reuse] %s\n",rurl);
		setVStrEnd(buf,rcc);
		return rcc;
	}

	setVStrEnd(rurl,0);
	strcpy(murl,aurl);
	opts =
	CTX_mount_url_to(Conn,NULL,"GET",AVStr(murl));

	ucrc = strCRC32(murl,strlen(murl));
	if( Conn->dg_urlcrc == ucrc ){
		sv1log("####[loop] %s\n",murl);
		clearVStr(buf);
		return 0;
	}
	if( strstr(murl,"://") != NULL ){
		mfp = (FILE*)TMPFILE("MountedBuiltinData");
		if( opts ){
			/* options as "verify=rsa" to be inherited to URLget()
			 * for all siblings referred with ${include:path}
			 */
			Conn->mo_optionsX = opts;
		}
		Conn->dg_urlcrc = ucrc;
		CTX_URLget(Conn,0,murl,0,mfp);
		Conn->dg_urlcrc = 0;
		alertVStr(buf,size);
		rcc = fread((char*)buf,1,QVSSize(buf,size),mfp);
		if( opts && isinList(opts,"verify=crc32") ){
			fseek(mfp,0,0);
			scrc = getContentCRC(Conn,mfp);
			if( scrc < 0 ){
				daemonlog("F","No CRC to verify: %s\n",murl);
				rcc = -1;
			}
		}
		if( Conn->mo_optionsX && strstr(Conn->mo_optionsX,"verify") ){
			fseek(mfp,0,0);
			if( checkMD5(mfp,murl,buf,rcc) != 0 ){
				rcc = -1;
			}
		}
		fclose(mfp);
		sv1log("%s (%d bytes) MOUNTED: %s\n",what,rcc,murl);
		if( 0 < rcc ){
			int crc;
			crc = strCRC32(buf,rcc);
			sv1log("####[loaded] crc=%X %s\n",crc,murl);
			/*
			sv1log("####[loaded] %s\n",murl);
			*/
			/*
			putCache(aurl,murl,buf,rcc);
			*/
			putCacheX(aurl,murl,buf,rcc,time(0));
			setVStrEnd(buf,rcc);
			strcpy(rurl,murl);
			return rcc;
		}
	}

	rcc = 0;
	if( strncmp(aurl,home_page,strlen(home_page)) == 0 ){
		iurl = aurl+strlen(home_page);
		/*
		if( data = getMssg(iurl,&rcc) ){
		*/
		if( data = getMssgX(iurl,&rcc,date) ){
			Verbose("####[builtin] %s\n",aurl);
			Bcopy(data,buf,rcc);
			setVStrEnd(buf,rcc);
			/*
			putCache(aurl,aurl,buf,rcc);
			*/
			putCacheX(aurl,aurl,buf,rcc,*date);
		}
	}
	return rcc;
}

int eval_DHTML(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(str),iFUNCP func,const void *farg,int *exitlevp);

int putBuiltinHTML0(Connection *Conn,FILE *tc,PCStr(what),PCStr(purl),PCStr(desc),iFUNCP func,const void *arg);
int putBuiltinHTML(Connection *Conn,FILE *tc,PCStr(what),PCStr(purl),PCStr(desc),iFUNCP func,const void *arg)
{	int leng;
	int ent1 = ENCODE_ENT1;
	const char *optX = Conn->mo_optionsX;

	leng = putBuiltinHTML0(Conn,tc,what,purl,desc,func,arg);
	ENCODE_ENT1 = ent1;
	/* undefine macros here ... */
	Nvclear(Conn);
	Conn->mo_optionsX = optX;
	return leng;
}
int putBuiltinHTML0(Connection *Conn,FILE *tc,PCStr(what),PCStr(purl),PCStr(desc),iFUNCP func,const void *arg)
{	int leng;
	/*
	CStr(buf1,8*1024);
	*/
	CStr(buf1,32*1024);
	const char *buf;
	defQStr(buf2); /*alloc*/
	CStr(murl,256);
	const char *curl;
	CStr(curlb,1024);
	int exitlev;
	const void *xarg;
setQStr(buf2,NULL,0);

	if( purl[0] == '/' || strstr(purl,"://") != 0 )
		curl = purl;
	else{
		sprintf(curlb,"%s%s%s",home_page,"builtin/mssgs/",purl);
		curl = curlb;
	}

	murl[0] = 0;
	leng = getBuiltinData(Conn,what,curl,AVStr(buf1),sizeof(buf1),AVStr(murl));

	if( leng == 0 ){
		if( desc == NULL )
		{
			if( tc ){
				sv1log("-- putBuiltinHTML: empty %s\n",purl);
				/* to avoid possible freeze by empty body */
				fprintf(tc,"\n");
			}
			return 0;
		}
		sprintf(buf1,msg_not_found,purl,purl);
		leng = strlen(buf1);
	}

	if( murl[0] && strcmp(murl,curl) != 0 && desc != NULL ){
		CStr(proto,64);
		CStr(server,MaxHostNameLen);
		int port;
		CStr(req,256);
		int dont_REWRITE;
		UrlX vb;
		defQStr(bp); /*alloc*//**/
		CStr(pmurl,256);

/*
		buf2 = (char*)malloc(sizeof(buf1));
*/
setQStr(buf2,(char*)malloc(sizeof(buf1)),sizeof(buf1));
		cpyQStr(bp,buf2);
		proto[0] = server[0] = 0;
		port = 0;
		Xsscanf(murl,"%[^:]://%[^:/]:%d",AVStr(proto),AVStr(server),&port);
		strcpy(req,"GET ");
		linescanX(murl,TVStr(req),sizeof(req)-strlen(req));

/*
sv1log("##### clear DONT_REWRITE:%d %s\n",DONT_REWRITE,murl);
DONT_REWRITE = 0;

must virtualize the URL of message itself and URLs contained in it
regardless of "DONT_REWRITE" (== true if working as a proxy)
*/
		if( dont_REWRITE = DONT_REWRITE ){
			CStr(base,128);
			DONT_REWRITE = 0;
			vb = Conn->my_vbase;
			sprintf(base,"%s://-.-",CLNT_PROTO);
			set_BASEURL(Conn,base);
		}
		setToInternal(); /* use Host: as BASEURL */

		/* Maybe this code is intended to cope with a customized page
		 * including links local to the page, like <IMG SRC=xxx.gif>
		 * To do so, it seems to intend to set the URL of the page
		 * in BASEURL, as the client-side virtual URL of the MOUNTed
		 * builtin page like "https://thishost/path" instead of the
		 * real URL like "http://localhost/path" or
		 * "file://localhost/path".
		 * But setting the virtual murl[], which is copied to curl[]
		 * to be used as the base URL of subsequent ${include:DHTML},
		 * will cause unnecessay remote access via the virtual URL.
		 *
		 * Anyway, this should be realized with reverse-MOUNT rather
		 * than using BASE tag.
		 * And why "desc" is used to switch this behavior is unknown.
		 *
		redirect_url(Conn,murl,AVStr(murl));
		bp = Sprintf(AVStr(bp),"<HEAD><BASE HREF=\"%s\"></HEAD>\n",murl);
		*/

		strcpy(pmurl,murl);
		strsubst(AVStr(pmurl)," ","%20");
		redirect_url(Conn,pmurl,AVStr(pmurl));
		bp = Sprintf(AVStr(bp),"<HEAD><BASE HREF=\"%s\"></HEAD>\n",pmurl);
		bp = Sprintf(AVStr(bp),"%s<HR>\n",desc);
		bp = Sprintf(AVStr(bp),"<!-- begin redirected %s -->\n\n",what);
		HTTP_redirect_HTML0(Conn,proto,server,port,req,buf1,AVStr(bp));
		bp += strlen(bp);
		bp = Sprintf(AVStr(bp),"\n<!-- end redirected %s -->\n",what);

		if( DONT_REWRITE = dont_REWRITE ){
			Conn->my_vbase = vb;
		}
		buf = buf2;
	}else	buf = buf1;

	if( murl[0] )
		curl = murl;
	exitlev = 0;

	if( func == NULL ){
		func = (iFUNCP)DHTML_printConn;
		/*
		arg = NULL;
		 arg might be omitted (not allocated on the stack)
		 when func==NULL
		*/
		xarg = NULL;
	}
	else	xarg = arg;

	/*
	leng = eval_DHTML(Conn,curl,tc,buf,func,arg,&exitlev);
	*/
	leng = eval_DHTML(Conn,curl,tc,buf,func,xarg,&exitlev);
	if( buf2 != 0 ){
		free((char*)buf2);
	}
	return leng;
}

static int put_host(Connection *Conn,FILE *fp,PCStr(what)){
	CStr(host,MaxHostNameLen);

	HTMLSRC_EXT = 1;
	if( streq(what,"W=MYSELF") ) gethostName(ClientSock,AVStr(host),PN_HOST); else
	if( streq(what,"W=CLIENT") ) getpeerName(ClientSock,AVStr(host),PN_HOST); else
	if( streq(what,"W=SERVER") ) sprintf(host,"%s",DST_HOST); else
		return -1;

	put1s(fp,"%s",host);
	return strlen(host);
}
static int put_hostport(Connection *Conn,FILE *fp,PCStr(what)){
	CStr(hp,512);

	HTMLSRC_EXT = 1;
	if( streq(what,"W=MYSELF") ){
		CStr(host,MaxHostNameLen);
		HTTP_ClientIF_HP(Conn,AVStr(hp));
		wordScanY(hp,host,"^:");
		if( VSA_strisaddr(host) ){
			ClientIF_HPname(Conn,AVStr(hp));
		}
	}else
	/*
	if( streq(what,"W=MYSELF") )gethostName(ClientSock,AVStr(hp),PN_HOSTPORT); else
	*/
	/*
	if( streq(what,"W=CLIENT") )getpeerName(ClientSock,AVStr(hp),PN_HOSTPORT); else
	*/
	if( streq(what,"W=CLIENT") ){
		sprintf(hp,"%s:%d",Client_Host,Client_Port);
	}else
	if( streq(what,"W=SERVER") ){
		if( REAL_HOST[0] )
			sprintf(hp,"%s:%d",REAL_HOST,REAL_PORT);
		else	sprintf(hp,"%s:%d",DFLT_HOST,DFLT_PORT);
	}
	else return -1;

	put1s(fp,"%s",hp);
	return strlen(hp);
}
static int put_protocol(Connection *Conn,FILE *fp,PCStr(what)){
	const char *proto;
	if( streq(what,"W=CLIENT") ) proto = "http"; else
	if( streq(what,"W=SERVER") ){
		if( REAL_PROTO[0] )
			proto = REAL_PROTO;
		else	proto = DFLT_PROTO;
	}
	else return -1;

	put1s(fp,"%s",proto);
	return strlen(proto);
}
static int put_logomark(Connection *Conn,FILE *fp,PCStr(align)){
	if( strncasecmp(align,"A=",2) == 0 )
		align += 2;
	else	align = "BOTTOM";
	return putDeleGateInline(Conn,fp,align);
}
static int put_frog_ver(Connection *Conn,FILE *fp,PCStr(form)){
	return putFrogVer(Conn,fp);
}
int put_manager(Connection *Conn,FILE *fp,PCStr(arg)){
	fputs(DELEGATE_ADMIN,fp);
	return strlen(DELEGATE_ADMIN);
}
static int put_icon(Connection *Conn,FILE *fp,PCStr(icon)){
	fprintf(fp,"<IMG SRC=%s>",icon);
	return 0;
}

typedef struct {
  const	char	*tag;
	int	(*dt_func)(Connection *Conn,FILE *fp,PCStr(arg));
} DTag;
static DTag dhtml_tags[] = {
	{"T=LOGOMARK",	put_logomark},
	{"T=FROG_VER",	put_frog_ver},
	{"T=HOSTPORT",	put_hostport},
	{"T=HOST",	put_host},
	{"T=PROTOCOL",	put_protocol},
	{"T=ADMIN",	put_manager},
	{"T=MANAGER",	put_manager},
	{"T=ICON",	put_icon},
	0
};

static const char *scanitem(PCStr(str))
{	const char *sp;
	int lev;

	lev = 1;
	for( sp = str; *sp; sp++ ){
		if( *sp == '{' )
			lev++;
		else
		if( *sp == '}' ){
			if( --lev == 0 )
				return sp;
		}
	}
	return NULL;
}

#define RESERVED_CH(c) (c=='$'||c=='{'||c=='?'||c==':'||c=='}'||c=='"'||c=='\\')

static const char *scanchr(PCStr(str),int chr,PVStr(dstr))
{	const char *sp;
	char ch;
	char nch;
	int lev;
	int lit;
	refQStr(dp,dstr); /**/

	if( dstr )
	setVStrEnd(dstr,0);
	lev = 0;
	lit = 0;
	for( sp = str; ch = *sp; sp++ ){
		if( dp )
		{
#if WITH_QVSTR
			if( dstrBASE+VStrSIZE(dstr) <= dp+1 )
				fprintf(stderr,"## %s:%d\n",dstrFILE,dstrLINE);
#endif
		assertVStr(dstr,dp+1);
		}
		if( ch == '"' && lit == 0 ){
			lit = 1;
		}else
		if( ch == '"' && lit == 1 ){
			lit = 0;
		}else
		if( ch == '{' )
			lev++;
		else
		if( ch == '}' )
			lev--;

		if( lit == 0 )
		if( ch == '\\' && (nch = sp[1]) && RESERVED_CH(nch) ){
		}else
		if( lev < 0 || lev == 0 && ch == chr ){
			if( dp )
			setVStrEnd(dp,0);
			return sp + 1;
		}

		if( dp )
		setVStrPtrInc(dp,ch);
	}
	if( dp )
	setVStrEnd(dp,0);
	return NULL;
}

static void scanatom(PCStr(itemexp),PVStr(name),PVStr(param))
{	const char *p;

	setVStrEnd(param,0);
	setVStrEnd(name,0);
	if( p = scanchr(itemexp,':',AVStr(name)) )
		scanchr(p,'\0',AVStr(param));
}

int HTML_scan1(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val)){
	int exitlev = 0;
	return eval_DHTML(Conn,"",fp,val,(iFUNCP)DHTML_printConn,NULL,&exitlev);
}
int HTML_ccxput1s(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val)){
	CStr(cb,16*1024);
	if( CCXactive(CCX_TOCL) ){
		CCXexec(CCX_TOCL,val,strlen(val),AVStr(cb),sizeof(cb));
		if( !streq(val,cb) ){
			val = cb;
		}
	}
	return put1s(fp,fmt,val);
}
int HTML_put1sX(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val)){
	const char *dp;
	if( (dp = strstr(val,"${")) && strstr(dp+2,"}") ){
		int exitlev = 0;
		return eval_DHTML(Conn,"",fp,val,(iFUNCP)DHTML_printConn,NULL,&exitlev);
	}else{
		return HTML_put1s(fp,fmt,val);
	}
}

/*
int HTML_put1s(FILE *fp,PCStr(fmt),PCStr(val))
*/
int HTML_put1sY(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(val))
{	CStr(buf,16*1024); /* for respmssg, must be solved by entEncodeToFile */

	if( val == 0 ){
		fprintf(stderr,"?? HTML_put1s(fp=%X,fmt=%X,val=NULL)\n",p2i(fp),p2i(fmt));
		sleep(3);
		return 0;
	}
	dumpstacksize("HTML_put1s","%s",fmt);
	if( fp != NULL ){
		if( ESCAPE_URL1 ){
			URL_reescape(val,AVStr(buf),1,0);
			if( HTMLSRC_EXT ){
				strsubst(AVStr(buf),"+AC","%2bAC");
				strsubst(AVStr(buf),"+AD","%2bAD");
				strsubst(AVStr(buf),"+AE","%2bAE");
			}
			val = buf;
		}else
		if( ENCODE_ENT1 ){
			encodeEntitiesX(val,AVStr(buf),sizeof(buf));
			if( HTMLSRC_EXT ){
				strsubst(AVStr(buf),"+AC","&#43;AC");
				strsubst(AVStr(buf),"+AD","&#43;AD");
				strsubst(AVStr(buf),"+AE","&#43;AE");
			}
/*
if(!streq(buf,val)){
fprintf(stderr,"%d<<< %s\n",ENCODE_ENT1,val);
fprintf(stderr,"%d>>> %s\n",ENCODE_ENT1,buf);
}
*/
			val = buf;
		}

/*
CStr(cb,16*1024);
if( CCXactive(CCX_TOCL) ){
	CCXexec(CCX_TOCL,val,strlen(val),AVStr(cb),sizeof(cb));
	if( !streq(val,cb) ){
		val = cb;
	}
}
*/
		if( fmt[0] == '%' && fmt[1] == 's' && fmt[2] == 0 )
			fputs(val,fp);
		else	fprintf(fp,fmt,val);
	}
	return val[0];
}

/*
int HTML_put1d(FILE *fp,PCStr(fmt),int iv)
*/
int HTML_put1dY(Connection *Conn,FILE *fp,PCStr(fmt),int iv)
{	CStr(buf,32);
	CStr(fmt1,8);

	if( fp != NULL ){
		if( fmt[0]=='%' && fmt[1]=='0' && isdigit(fmt[2]) ){
			sprintf(fmt1,"%%0%dd",atoi(&fmt[2]));
			sprintf(buf,fmt1,iv);
		}else	sprintf(buf,"%d",iv);
		put1s(fp,fmt,buf);
	}
	return iv;
}
#define HTML_put1d(fp,fmt,iv) HTML_put1dY(Conn,fp,fmt,iv)

/* convert xxx[yyy]=zzz to xxx=yyy */
void Form_conv_namevalue(int argc,const char *argv[]){
	int ai;
	const char *arg1;
	const char *dp;
	for( ai = 0; ai < argc; ai++ ){
		arg1 = argv[ai];
		if( dp = strpbrk(arg1,"[=") )
		if( *dp == '[' ){
			*(char*)dp = '=';
			if( dp = strchr(dp+1,']') )
				truncVStr(dp);
		}
	}
}

int HTML_conv(PCStr(type),PCStr(srctxt),PVStr(dsttxt));
static int call_func0(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(item),iFUNCP func,const void *arg);
static int call_func(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(item),iFUNCP func,const void *arg)
{
	int rcode;
	int Not;
	int Nil;

	if( Not = strneq(item,"NOT.",4) ){
		item += 4;
	}
	if( Nil = strneq(item,"NIL.",4) ){
		item += 4;
	}
	rcode = call_func0(Conn,curl,outfp,item,func,arg);
	if( Not ){
		rcode = rcode == 0; 
	}
	return rcode;
}
static int call_func0(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(item),iFUNCP func,const void *arg)
{	CStr(name,2*1024);
	const char *param;
	CStr(fmtb,128);
	refQStr(fmt,fmtb); /**/
	int fi;
	int rcode;
	int sent;

	if( item[0] == '=' ){
		fputs(item+1,outfp);
		return strlen(item+1);
	}

	param = scanchr(item,':',AVStr(name));
	if( streq(name,"include") || streq(name,"include.silent") ){
		CStr(ncurl,1024);
		CStr(what,128);
		const char *dp;
		int leng;

		/* mo_optionsX should be cleared if param is not under curl */
		sprintf(what,"eval:%s",param);
		strcpy(ncurl,curl);
		curl = ncurl;
		if( dp = strrchr(curl,'/') )
			truncVStr(dp);
		chdir_cwd(QVStr((char*)curl,ncurl),param,0); /* ncurl is not "const" */

		leng = putBuiltinHTML(Conn,outfp,what,curl,NULL,func,arg);
		if( leng <= 0 )
		if( streq(name,"include") )
			fprintf(outfp,"(cannot include %s, %s)",param,curl);
		return 0 < leng;
	}
	if( streq(name,"tag") ){
		CStr(tag,2048);
		CStr(tagn,64);
		const char *text;
		text = scanchr(param,':',AVStr(tag));
		wordScan(tag,tagn);
/*
 fprintf(stderr,"---- TAG {%s}{%s}\n",tag,text?text:"NULL");
*/
		if( text ){
			int leng = 0;
			leng += fprintf(outfp,"<");
			leng += HTML_put1sX(Conn,outfp,"%s",tag);
			leng += fprintf(outfp,">");
			//leng += HTML_put1sX(Conn,outfp,"%s",text);
			leng += HTML_scan1(Conn,outfp,"%s",text);
			leng += fprintf(outfp,"</%s>",tagn);
			return leng;
		}
	}
	if( streq(name,"type") ){
		CStr(ttype,128);
		const char *html;
		CStr(xh,1024);
		/* ${type:button,message,text:dhtml} for conversion */
		html = scanchr(param,':',AVStr(ttype));
/*
fprintf(stderr,"########## ${type:%s:%s}\n",ttype,html?html:"");
*/
		if( html ){
			/* convert the html according to the type */
			int xlev = 0;
			int leng;
			HTML_conv(ttype,html,AVStr(xh));
			if( CCXactive(CCX_TOCL) )
			CCXexec(CCX_TOCL,xh,strlen(xh),AVStr(xh),sizeof(xh));
			leng = eval_DHTML(Conn,curl,outfp,xh,func,arg,&xlev);
			return leng;
		}
	}

	/*
	 * Ex. ${checkbox:cbox:${cbox.on?checked} style="color:green"}
	 */
	if( streq(name,"checkbox") ){
		int leng = 0;
		CStr(bname,32);
		CStr(brems,1024);

		truncVStr(brems);
		scan_Listlist(param,':',AVStr(bname),AVStr(brems),
			VStrNULL,VStrNULL,VStrNULL);
		leng = fprintf(outfp,"<INPUT type=checkbox name=\"%s\" ",bname);
		leng += HTML_scan1(Conn,outfp,"%s",brems);
		leng += fprintf(outfp,">");
		return leng;
	}
	/*
	 * Ex. ${button:submit:com:df:Disk Free:style="color:green"}
	 */
	if( streq(name,"button") ){
		int leng = 0;
		CStr(btype,32);
		CStr(bname,32);
		CStr(bhval,256);
		CStr(bvval,256);
		CStr(brems,1024);

		truncVStr(bvval);
		truncVStr(brems);
		scan_Listlist(param,':',AVStr(btype),AVStr(bname),AVStr(bhval),
			AVStr(bvval),AVStr(brems));

		if( strcaseeq(btype,"text") ){
		leng = fprintf(outfp,"<INPUT type=%s name=\"%s\"",btype,bname);
			leng += fprintf(outfp,"\" value=\"");
			leng += HTML_scan1(Conn,outfp,"%s",bhval);
/*
			leng += HTML_scan1(Conn,outfp,"%s",bvval);
*/
			leng += fprintf(outfp,"\" ");
			leng += HTML_scan1(Conn,outfp,"%s",brems);
			leng += fprintf(outfp,">");
		}else
		/* to avoid the bugs of BUTTON implementation of MSIE */
		if( ServerFlags & PF_UA_MSIE ){
		leng = fprintf(outfp,"<INPUT type=%s name=\"%s[",btype,bname);
			leng += HTML_scan1(Conn,outfp,"%s",bhval);
			leng += fprintf(outfp,"]\" value=\"");
			leng += HTML_scan1(Conn,outfp,"%s",bvval);
			leng += fprintf(outfp,"\" ");
			leng += HTML_scan1(Conn,outfp,"%s",brems);
			leng += fprintf(outfp,">");
		}else{
		leng = fprintf(outfp,"<BUTTON type=%s name=\"%s\" value=\"",
				btype,bname);
			leng += HTML_scan1(Conn,outfp,"%s",bhval);
			leng += fprintf(outfp,"\" ");
			leng += HTML_scan1(Conn,outfp,"%s",brems);
			leng += fprintf(outfp,">");
			leng += HTML_scan1(Conn,outfp,"%s",bvval);
			leng += fprintf(outfp,"</BUTTON>");
		}
		return leng;
	}

	param = scanchr(item,'.',AVStr(name));
	if( param == 0 )
		param = "";

	if( name[0] == '%' ){
		fmt = fmtb;
		setVStrElem(fmt,0,'%');
		for( fi = 1; fi < sizeof(fmtb)-2; fi++ ){
			if( name[fi] < '0' || '9' < name[fi] )
				break;
		setVStrElem(fmt,fi,name[fi]);
		}
		setVStrElem(fmt,fi,'s');
		setVStrEnd(fmt,fi+1);
		ovstrcpy(name,name+fi);
	}else{
		fmt = "%s";
	}

	sent = 0;
	if( name[0] == '^' ){
		ESCAPE_URL1 = 1;
		ovstrcpy(name,name+1);
	}else
	if( name[0] == '~' ){
		if( 0 < ENCODE_ENT1 ){
			sent = ENCODE_ENT1;
			ENCODE_ENT1 = 0;
		}
		ovstrcpy(name,name+1);
	}else
	if( name[0] == '_' ){
		sent = -1;
		ENCODE_ENT1++;
		ovstrcpy(name,name+1);
	}
	/*
	}else	ENCODE_ENT1 = 0;
	*/

	rcode = (*func)(Conn,outfp,fmt,name,param,arg);

	/*
	ENCODE_ENT1 = 0;
	*/

/*
if( sent )
fprintf(stderr,"----- %d TO %d [%s.%s][%s]\n",ENCODE_ENT1,ENCODE_ENT1+sent,name,param,curl);
*/
	ENCODE_ENT1 += sent;
	ESCAPE_URL1 = 0;
	return rcode;
}

static void scancond(PCStr(condexp),PVStr(conds),PVStr(trues),PVStr(falses))
{	const char *p;

	setVStrEnd(falses,0);
	setVStrEnd(trues,0);
	setVStrEnd(conds,0);
	if( p = scanchr(condexp,'?',AVStr(conds)) )
	if( p = scanchr(p,':',AVStr(trues)) )
		scanchr(p,'\0',AVStr(falses));
}
static void scanexp2(PCStr(exp),int dch,PVStr(left),PVStr(right))
{	const char *p;

	setVStrEnd(right,0);
	setVStrEnd(left,0);
	if( p = scanchr(exp,dch,AVStr(left)) )
		scanchr(p,'\0',AVStr(right));
}
static int cond1(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(conds),iFUNCP func,const void *arg)
{	const char *dp;
	char dch;
	CStr(val1s,1024);
	CStr(val2s,1024);
	int val1,val2;

	/*
	if( dp = strpbrk(conds,"<=") ){
	*/
	if( dp = strpbrk(conds,"<=&|") ){
		dch = *dp;
		scanexp2(conds,dch,AVStr(val1s),AVStr(val2s));
		if( isdigits(val1s) )
			val1 = atoi(val1s);
		else	val1 = call_func(Conn,curl,NULL,val1s,func,arg);

		switch( dch ){
			case '&': if( val1 == 0 ) return 0; break;
			case '|': if( val1 != 0 ) return 1; break;
		}

		if( isdigits(val2s) )
			val2 = atoi(val2s);
		else	val2 = call_func(Conn,curl,NULL,val2s,func,arg);

		switch( dch ){
			case '<': return val1 < val2;
			case '=': return val1 == val2;
			case '&': return val1 && val2;
			case '|': return val1 || val2;
		}
		return 0;
	}else	return call_func(Conn,curl,NULL,conds,func,arg);
}

static int eval1(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(item),iFUNCP func,const void *arg,int *exitlevp)
{	const char *dp;
	CStr(conds,4096);
	CStr(trues,4096);
	CStr(falses,4096);

	/*
	if( dp = strchr(item,'?') ){
	*/
	if( dp = scanchr(item,'?',VStrNULL) ){
		scancond(item,AVStr(conds),AVStr(trues),AVStr(falses));
		if( cond1(Conn,curl,outfp,conds,func,arg) )
			return eval_DHTML(Conn,curl,outfp,trues,func,arg,exitlevp);
		else	return eval_DHTML(Conn,curl,outfp,falses,func,arg,exitlevp);
/*
		if( cond1(Conn,curl,outfp,conds,func,arg) )
			eval_DHTML(Conn,curl,outfp,trues,func,arg,exitlevp);
		else	eval_DHTML(Conn,curl,outfp,falses,func,arg,exitlevp);
		return 0;
*/
	}else{
		return call_func(Conn,curl,outfp,item,func,arg /*,exitlevp*/);
	}
}

typedef struct namvals {
	char	*namval;
 struct namvals *prev;
} NamVal;
#define Nvsp	Conn->html_namvals
#define Nvpush(namval) NvpushX(Conn,namval)
#define Nvpops(nvsp)   NvpopsX(Conn,nvsp)
#define Nvfind(nam)    NvfindX(Conn,nam)

static void NvpushX(Connection *Conn,PCStr(namval)){
	NamVal *nv;
	nv = (NamVal*)malloc(sizeof(NamVal));
	nv->namval = stralloc(namval);
	nv->prev = Nvsp;
	Nvsp = nv;
}
static void NvpopsX(Connection *Conn,NamVal *nvsp){
	NamVal *prev;
	while( Nvsp ){
		if( Nvsp == nvsp ){
			break;
		}
		prev = Nvsp->prev;
		free(Nvsp->namval);
		free(Nvsp);
		Nvsp = prev;
	}
}
static void Nvclear(Connection *Conn){
	if( Nvsp ){
		Nvpops(0);
	}
}
static const char *NvfindX(Connection *Conn,PCStr(nam)){
	NamVal *nv;
	int nlen = strlen(nam);

	for( nv = Nvsp; nv; nv = nv->prev ){
		if( nv->namval == 0 )
			continue;
		if( strncmp(nv->namval,nam,nlen) == 0 ){
			if( nv->namval[nlen] == 0 ){
				return nv->namval+nlen;
			}
			if( nv->namval[nlen] == '=' ){
				return nv->namval+nlen+1;
			}
		}
	}
	return 0;
}

static int HTML_SERNO;

int eval_DHTML(Connection *Conn,PCStr(curl),FILE *outfp,PCStr(str),iFUNCP func,const void *farg,int *exitlevp)
{	const char *sp;
	const char *dp;
	const char *ctag;
	int pch,ch;
	int leng = 0;
	int col;
	int tlen,len1;
	DTag *dt;
	const char *arg = "";
	CStr(argb,16*1024);
	NamVal *nvsp = Nvsp;
	int serno;
	CCXFILE CF;

	CFinit(&CF,CCX_TOCL,outfp);
/*
	CF.c_flags = 1;
*/

	serno = ++HTML_SERNO;
	col = 0;
	pch = 0;
	for( sp = str; ch = *sp; sp++ ){
		if( col == 0 && ch == '#' ){
			for( sp++; sp[1]; sp++ ){
				ch = *sp;
				if( ch == '\n' )
					break;
				if( ch == '\r' && sp[1] == '\n' ){
					sp++;
					break;
				}
			}
			continue;
		}
		col++;

		if( ch == '\\' && RESERVED_CH(sp[1]) ){
			ch = sp[1];
			sp += 1;
			goto PUT1;
		}else
		if( ch == '\\' && sp[1] == '\n' ){
			sp += 1;
			continue;
		}else
		if( ch == '\\' && sp[1] == '\r' && sp[2] == '\n' ){
			sp += 2;
			continue;
		}else
		if( ch == '$' && sp[1] == '{' ){
if(HDBG)fprintf(stderr,"-3- eval_DHTML ch=%X\n",ch);
		    if( strncmp(sp,"${exitfile}",11) == 0 ){
			*exitlevp = 100;
			break;
		    }else
		    if( strncmp(sp,"${exit}",7) == 0 ){
			*exitlevp = 1;
			break;
		    }else
		    if( strncmp(sp,"${NL}",5) == 0 ){
			ch = '\n';
			sp += 4;
		    }else
		    if( dp = scanitem(sp+2) ){
			truncVStr(dp);
			if( sp[2] == '+' ){ /* ${+name=value} -- push */
				Nvpush(sp+3);
			}else
			if( sp[2] == '?' ){ /* ${?name} -- refer */
				const char *vp;
				const char *mp;
				if( vp = Nvfind(sp+3) ){
					if( outfp ){
						if( strstr(vp,"${") == 0 ){
							CCXfputs(CF,vp);
/*
fputs(vp,outfp);
*/
						}else
						if( *vp == '=' ){
							vp++;
							CCXfputs(CF,vp);
/*
fputs(vp,outfp);
*/
						}else{
			mp = stralloc(vp);
			CCXflush(CF);
			eval_DHTML(Conn,curl,outfp,mp,func,arg,exitlevp);
if( lHTMLGENV() ){
  if( !streq(vp,mp) )
	fprintf(stderr,"--HTMLgen-- overwritten\n\t<<< %s\n\t>>> %s\n",vp,mp);
  else	fprintf(stderr,"--HTMLgen-- NOT overwritten\n<<< %s\n>>> %s\n",vp,mp);
}

			free((char*)mp);
						}
					}
				}
			}else
			if( func != NULL ){
				int leng1;
if(HDBG)fprintf(stderr,"-x- eval_DHTML ch=%X\n",ch);

				CCXflush(CF);
				leng1 =
				eval1(Conn,curl,outfp,sp+2,func,farg,exitlevp);
				leng += leng1; /*includes non output count ...*/

				if( 0 < *exitlevp ){
					*exitlevp -= 1;
					break;
				}
			}
			sp = dp;
			continue;
		    }
		}else
		if( ch == '<' && strncasecmp(sp+1,"X-D ",4) == 0 ){
		    ctag = sp+5;
		    if( dp = strchr(ctag,'>') ){
			int ti;
			const char *tag;
			for( ti = 0; tag = dhtml_tags[ti].tag; ti++ ){
				tlen = strlen(tag);
				if( strncasecmp(ctag,tag,tlen) == 0 ){
					arg = ctag+tlen;
					while( *arg == ' ' )
						*arg++;
			strncpy(argb,arg,dp-arg); setVStrEnd(argb,dp-arg);
					break;
				}
			}
			if( tag ){
				dt = &dhtml_tags[ti];
				/*
				ENCODE_ENT1 = 1;
				*/
				ENCODE_ENT1 += 1;

				CCXflush(CF);
				len1 = (*dt->dt_func)(Conn,outfp,argb);
				ENCODE_ENT1 -= 1;
				/*
				ENCODE_ENT1 = 0;
				*/
				if( 0 <= len1 ){
					leng += len1;
					sp = dp;
					continue;
				}
			}
		    }
		}
		if( ch == '\n' && pch != '\r' ){
			if( outfp == 0 ){
 fprintf(stderr,"-- A FP==0\n");
			}else
			CCXfputc(CF,'\r');
			/*
			putc('\r',outfp);
			*/
			leng += 1;
			col = 0;
		}
PUT1:
		if( outfp == 0 ){
 fprintf(stderr,"-- B FP==0 ch=%c\n",ch);
		}else
		CCXfputc(CF,ch);
		/*
		putc(ch,outfp);
		*/
		pch = ch;
		leng += 1;
	}
	CCXflush(CF);
	Nvpops(nvsp);
	return leng;
}


extern int DELEGATE_LastModified;
int get_builtin_MADE_TIME();
char GEN_MovedTo[1024];

int dhtml_eval(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(dhtml),PCStr(value),int *lnsp,PVStr(gendata)){
	CStr(arg0,128);
	CStr(arg1,1024);
	CStr(line,1024);
	int off,esiz,siz,lns;
	refQStr(op,gendata);

	Xsscanf(dhtml,"%[^.].%s",AVStr(arg0),AVStr(arg1));
	off = ftell(fp);
	DHTML_printConn(Conn,fp,fmt,arg0,arg1,value);
	esiz = ftell(fp);
	fflush(fp);
	fseek(fp,off,0);
	for( lns = 0; fgets(line,sizeof(line),fp) != NULL; lns++ ){
		if( gendata ){
			strcpy(op,line);
			op += strlen(op);
		}
	}
	fseek(fp,off,0);
	Ftruncate(fp,0,1);
	siz = esiz - off;
	if( lnsp ) *lnsp = lns;
	return siz;
}

char *extbase(Connection *Conn,PVStr(xpath),PCStr(fmt),...){
	VARGS(4,fmt);

	truncVStr(xpath);
	if( strncmp(fmt,"/-/",3) == 0 ){
		if( Conn->mo_flags & MO_BI_EXTERN ){
			strcpy(xpath,"/-/ext/");
		}else{
			strcpy(xpath,"/-/");
		}
		fmt += 3;
	}
	Xsprintf(TVStr(xpath),fmt,VA4);
	return (char*)xpath;
}

const char *DELEGATE_date();
const char *DELEGATE_licensee();
int DHTML_printNntpgw(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg));
int DHTML_printConn(Connection *Conn,FILE *fp,PCStr(fmt),PCStr(name),PCStr(arg),PCStr(value))
{	CStr(hostport,MaxHostNameLen);
	CStr(stime,128);
	CStr(url,URLSZ);
	CStr(arg0,128);
	CStr(arg1,1024);

	truncVStr(arg0);
	truncVStr(arg1);
	HTMLSRC_EXT = 0;

	if( streq(name,"no-robots") ){
		DHTML_printNoRobots(Conn,fp,fmt,name,arg,value);
	}else
	if( streq(name,"services") ){
		prservices(fp);
	}else
	if( streq(name,"mtab") ){
		return DHTML_printMount(Conn,fp,fmt,name,arg /*,value*/);
	}else
	if( streq(name,"OWNER") ){
		getUsername(getuid(),AVStr(url));
		put1s(fp,"%s",url);
	}else
	if( streq(name,"auth") ){
		return DHTML_printAuth(Conn,fp,fmt,name,arg,value);
	}else
	if( streq(name,"ibase") || streq(name,"abase") ){
		if( Conn->mo_flags & MO_BI_EXTERN ){
			put1s(fp,"%s","/-/ext/");
		}else{
			put1s(fp,"%s","/-/");
		}
		if( streq(name,"abase") ){
			put1s(fp,"%s","admin/");
		}
	}else
	if( streq(name,"nntpgw") ){
		CStr(n2,32);
		const char *a2;
		a2 = wordScanY(arg,n2,"^.");
		if( *a2 == '.' )
			a2++;
		else	a2 = "";
		return DHTML_printNntpgw(Conn,fp,fmt,n2,a2);
	}else
	if( streq(name,"admin") ){
		if( streq(arg,"isset") ){
			if( 0 < Conn->clif._adminPort )
				return 1;
			return 0 <= withAdminPort(NULL,NULL);
		}
		if( streq(arg,"port") ){
			int port;
			if( 0 < (port = Conn->clif._adminPort) ){
				HTTP_ClientIF_H(Conn,AVStr(hostport));
				fprintf(fp,"%s:%d",hostport,port);
			}else
			if( 0 <= withAdminPort(NULL,&port) ){
				HTTP_ClientIF_H(Conn,AVStr(hostport));
				fprintf(fp,"%s:%d",hostport,port);
			}else{
				HTTP_ClientIF_HP(Conn,AVStr(hostport));
				fputs(hostport,fp);
			}
			return port;
		}
		return DHTML_printAdmin(Conn,fp,fmt,name,arg /*,value*/);
	}else
	if( streq(name,"svstat") ){
		int getServStat(PCStr(proto),int *act);
		int port,act;
		Xsscanf(arg,"%[^.].%[^.\r\n]",AVStr(arg0),AVStr(arg1));
		port = getServStat(arg1,&act);
		if( streq(arg0,"port") ){
			fprintf(fp,"%d",port);
		}
		if( streq(arg0,"active") ){
			return act;
		}
		return 0;
	}else
	if( streq(name,"ioconf") ){
		if( streq(arg,"sock.sndbuf") ){
			fprintf(fp,"%d",SOCK_SNDBUF_MAX);
			return SOCK_SNDBUF_MAX;
		}
		if( streq(arg,"sock.sndmutex") ){
			return SOCK_SNDMUTEX;
		}
		if( streq(arg,"sock.sndnodelay") ){
			return SOCK_SNDNODELAY;
		}
		if( streq(arg,"sock.sndwait") ){
			fprintf(fp,"%d",SOCK_SNDWAIT);
			return SOCK_SNDWAIT;
		}
	}else
	if( streq(name,"genauth") ){
		return DHTML_pringGenAuth(Conn,fp,fmt,name,arg,value);
	}else
	if( streq(name,"client") ){
		if( streq(arg,"host") ){
			/* ClientSock might be overwritten by STLS=fcl */
			if( Client_Port && Client_Host[0] ){
				fputs(Client_Host,fp);
			}else{
			getpeerName(ClientSock,AVStr(hostport),PN_HOST);
			fputs(hostport,fp);
			}
		}else
		if( streq(arg,"ident") ){
			const char *ouser;
			AuthInfo ident;
			if( ouser = VA_getOriginatorIdent(Conn,&ident) )
				fputs(ouser,fp);
		}else
		if( streq(arg,"ifhp") ){
			ClientIF_HPname(Conn,AVStr(hostport));
			fputs(hostport,fp);
		}else
		if( streq(arg,"peersessions") ){
			fprintf(fp,"%d",Conn->cl_count);
		}else
		if( streq(arg,"requestserno") ){
			fprintf(fp,"%d",RequestSerno);
		}else
		if( streq(arg,"useragent") ){
			const char *dp;
			HTTP_getRequestField(Conn,"User-Agent",AVStr(url),sizeof(url));
			if( dp = strstr(url,"MSIE ") )
			if( dp != url ){
				strcpy(url,dp);
				if( dp = strrchr(url,')') )
					truncVStr(dp);
			}
			fputs(url,fp);
		}
	}else
	if( streq(name,"moved") ){ /* printMoved */
		if( streq(arg,"url") )
			if( value != NULL )
				fputs(value,fp);
	}else
	if( streq(name,"ver") ){
		fputs(DELEGATE_ver(),fp);
	}else
	if( streq(name,"verdate") ){
		if( streq(arg,"date") ){
			fprintf(fp,"%s",DELEGATE_date());
		}else
		fprintf(fp,"%s",DELEGATE_verdate());
	}else
	if( streq(name,"Version") ){
		fputs(DELEGATE_Version(),fp);
	}else
	if( streq(name,"copyright") ){
		fputs(DELEGATE_copyright(),fp);
	}else
	if( streq(name,"licensee") ){
		fputs(DELEGATE_licensee(),fp);
	}else
	if( streq(name,"license") ){
		if( streq(arg,"custody") )
			fputs("N/A",fp);
	}else
	if( streq(name,"homepage") ){
		fputs(DELEGATE_homepage(),fp);
	}else
	if( streq(name,"icon") ){
		if( streq(arg,"delegate") )
			fprintf(fp,"%s%s",HTTP_getIconBase(Conn),
				"ysato/DeleGateLogoTrans.gif");
		else
		if( streq(arg,"frog") )
			fprintf(fp,"%s%s",HTTP_getIconBase(Conn),
				"ysato/frog.gif");
		else
		if( streq(arg,"froghead") )
			fprintf(fp,"%s%s",HTTP_getIconBase(Conn),
				"ysato/frogHead.gif");
		else{
			fprintf(fp,"%sysato/%s.gif",HTTP_getIconBase(Conn),arg);
		}
	}else
	if( streq(name,"nowfmt") ){
		StrftimeLocal(AVStr(stime),sizeof(stime),arg,time(0),0);
		fputs(stime,fp);
	}else
	if( streq(name,"time") ){
		if( streq(arg,"now") ){
			StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,time(0),0);
			fputs(stime,fp);
		}else
		if( streq(arg,"sstart") ){
			CStr(stime,32);
			extern int START_TIME;
			rsctime(START_TIME,AVStr(stime));
			fputs(stime,fp);
		}else
		if( streq(arg,"start") )
			fputs(start_time(),fp);
		else
		if( streq(arg,"compiled") ){
			StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,
				get_builtin_MADE_TIME(),0);
			fputs(stime,fp);
		}else
		if( streq(arg,"configured") ){
			StrftimeLocal(AVStr(stime),sizeof(stime),TIMEFORM_HTTPD,DELEGATE_LastModified,0);
			fputs(stime,fp);
		}
	}else
	if( streq(name,"load") ){
		if( streq(arg,"total") )
			strfLoadStat(AVStr(url),128,"%L",time(NULL));
		else
		if( streq(arg,"recent") )
			strfLoadStat(AVStr(url),128,"%l",time(NULL));
		else	url[0] = 0;
		fputs(url,fp);
	}else
	if( streq(name,"num") ){
		if( streq(arg,"serno") )
			fprintf(fp,"%d",SERNO());
		else
		if( streq(arg,"peers") )
			fprintf(fp,"%d",alive_peers());
		else
		if( streq(arg,"served") )
			fprintf(fp,"%d",TOTAL_SERVED);
	}else
	if( streq(name,"clif") ){
		if( streq(arg,"addr") ){
			CStr(addr,64);
			ClientIF_addr(Conn,ClientSock,AVStr(addr));
			fputs(addr,fp);
		}else
		if( streq(arg,"isadm") ){
			return IsAdmin;
		}
		if( streq(arg,"withadm") ){
			return 0 < Conn->clif._adminPort;
		}
		if( streq(arg,"withssl") ){
			return ClientFlags & PF_SSL_ON;
		}
		if( streq(arg,"proto") ){
			if( fp ){
				fputs(CLNT_PROTO,fp);
			}
			return serviceport(CLNT_PROTO);
		}
	}else
	if( streq(name,"host") ){
		if( streq(arg,"clif") ){
			ClientIF_name(Conn,FromC,AVStr(hostport));
			fputs(hostport,fp);
		}
	}else
	if( streq(name,"hostport") ){
		HTMLSRC_EXT = 1;
		if( streq(arg,"client") ){
			strfConnX(Conn,"%h:%p",AVStr(hostport),sizeof(hostport));
			fputs(hostport,fp);
		}else
		if( streq(arg,"vhost") ){
			HTTP_ClientIF_HP(Conn,AVStr(hostport));
			fputs(hostport,fp);
		}else
		if( streq(arg,"clif") ){
			if( strneq(CLNT_PROTO,"http",4) ){
				HTTP_ClientIF_HP(Conn,AVStr(hostport));
			}else
			ClientIF_HPname(Conn,AVStr(hostport));
			fputs(hostport,fp);
		}
	}else
	if( streq(name,"request") ){
		HTMLSRC_EXT = 1;
		if( streq(arg,"mssg") )
			HTTP_fprintmsg(Conn,fp,"om");
		else
		if( streq(arg,"line") )
			HTTP_fprintmsg(Conn,fp,"ol");
		else
		if( streq(arg,"url") ){
			HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
			if( strncmp(url,"/-_-",4) == 0 )
				put1s(fp,"%s",url+4);
			else	put1s(fp,"%s",url);
		}
		else
		if( streq(arg,"urlbase") ){
			refQStr(up,url);
			HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
			if( up = strrchr(url,'/') )
				setVStrEnd(up,1);
		}else
		if( streq(arg,"reloading") ){
			if( ServerFlags & PF_UA_MSIE ){
				return 0;
			}
			return HttpReload;
		}
	}else
	if( streq(name,"server") ){
		const char *server;
		server = D_SERVER;
		HTMLSRC_EXT = 1;
		if( streq(arg,"iproto") )
			put1s(fp,"%s",iSERVER_PROTO);
		else
		if( streq(arg,"proto") )
			put1s(fp,"%s",DFLT_PROTO);
		else
		if( streq(arg,"name") )
			put1s(fp,"%s",server);
		else
		if( streq(arg,"host") )
			put1s(fp,"%s",DST_HOST);
		else
		if( streq(arg,"port") )
			fprintf(fp,"%d",DST_PORT);
		else
		if( streq(arg,"url") ){
			redirect_url(Conn,server,AVStr(url));
			put1s(fp,"%s",url);
		}
	}else
	if( streq(name,"mounted") ){
		return IsMounted;
	}else
	if( streq(name,"expire") )
		fprintf(fp,"%d",http_EXPIRE(Conn,""));
	else
	if( streq(name,"getccx") ){
		CStr(code,128);
		if( CTX_cur_codeconvCL(Conn,AVStr(code)) )
			return 1;
		else	return 0;
	}else
	if( streq(name,"setccx") ){
		CStr(code,128);
		CStr(stat,128);
		if( CTX_cur_codeconvCL(Conn,AVStr(code)) ){
			global_setCCX(Conn,AVStr(code),AVStr(stat));
			fprintf(fp,"\"%s\" %s",code,stat);
		}
	}else
	if( streq(name,"codeconv") ){
		CStr(cvenv,128);
		CTX_cur_codeconvCL(Conn,AVStr(cvenv));
		fprintf(fp,"%s",cvenv);
	}else
	if( streq(name,"ADMIN") )
		fprintf(fp,"%s",DELEGATE_ADMIN);
	else
	if( streq(name,"forbidden") ){
		if( streq(arg,"reason") ){
			fprintf(fp,"%s",Conn->reject_reason);
		}
	}else
	if( streq(name,"cantconn") ){
		if( streq(arg,"rejected") )
			return ConnError & CO_REJECTED;
		if( streq(arg,"unknown") )
			return ConnError & CO_CANTRESOLV;
		if( streq(arg,"timeout") )
			return ConnError & CO_TIMEOUT;
		if( streq(arg,"refused") )
			return ConnError & CO_REFUSED;
		if( streq(arg,"unreach") )
			return ConnError & CO_UNREACH;
		if( streq(arg,"noroute") )
			return ConnError & CO_NOROUTE;
		return 0;
	}
	else
	if( streq(name,"delegate") ){
		if( streq(arg,"icons") ){
			redirect_url(Conn,(char*)HTTP_getIconBase(Conn),AVStr(url));
			fputs(url,fp);
		}else
		if( streq(arg,"home") ){
			fputs(DELEGATE_homepage(),fp);
		}else
		if( streq(arg,"homeurl") ){
			redirect_url(Conn,DELEGATE_homepage(),AVStr(url));
			fputs(url,fp);
		}else
		if( streq(arg,"ftp") ){
			fputs(DELEGATE_Distribution(),fp);
		}else
		if( streq(arg,"ftpurl") ){
			redirect_url(Conn,DELEGATE_Distribution(),AVStr(url));
			fputs(url,fp);
		}
	}
	else
	if( strneq(name,"inc",3) && isdigit(name[3]) ){
		int val;
		int off;

		off = ftell(fp);
		Xsscanf(arg,"%[^.].%[^\n]",AVStr(arg0),AVStr(arg1));
		val = DHTML_printConn(Conn,fp,"%s",arg0,arg1,value);

		val += atoi(name+3);
		fseek(fp,off,0);
		HTML_put1d(fp,fmt,val);
		return val;
	}else
/*
	if( streq(name,"putlns") ){
		int off,li,lns;

		off = ftell(fp);
		Xsscanf(arg,"%[^.].%s",AVStr(arg0),AVStr(arg1));
		DHTML_printConn(Conn,fp,"%s",arg0,arg1,value);
		fflush(fp);
		fseek(fp,off,0);
		lns = 0;
		fscanf(fp,"%d",&lns);
		fseek(fp,off,0);
		Ftruncate(fp,0,1);

		for( li = 0; li < lns; li++ ){
			HTML_put1d(fp,fmt,li+1);
			HTML_put1s(fp,"%s","\n");
		}
	}else
*/
	if( streq(name,"lines") || streq(name,"bytes") ){
		int siz,lns;
		siz = dhtml_eval(Conn,fp,"%s",arg,value,&lns,VStrNULL);
		if( streq(name,"lines") )
			siz = lns;
		HTML_put1d(fp,fmt,siz);
		return siz;
	}else
	if( streq(name,"define") ){
		/*"${+Name=value}" */
		Nvpush(arg);
	}else
	if( streq(name,"refer") ){
		const char *vp;
		if( vp = Nvfind(arg) ){
			HTML_put1s(fp,"%s",vp);
		}
	}else
	if( streq(name,"ifndef") ){
		return Nvfind(arg) == 0;
	}else
	if( streq(name,"ifdef") ){
		return Nvfind(arg) != 0;
	}else
	if( streq(name,"not") ){
		int rv;
		truncVStr(arg0);
		truncVStr(arg1);
		Xsscanf(arg,"%[^.].%s",AVStr(arg0),AVStr(arg1));
		rv = DHTML_printConn(Conn,fp,"%s",arg0,arg1,value);
		return rv == 0;
	}else
	if( streq(name,"true") ){
		return 1;
	}else
	if( streq(name,"false") ){
		return 0;
	}else
	if( streq(name,"eval") ){
		int xlv = 0;
		eval_DHTML(Conn,"",fp,arg,(iFUNCP)DHTML_printConn,NULL,&xlv);
		return 1;
	}else
	if( streq(name,"evaleval") ){
		int lns,ret;
		int xlv = 0;
		CStr(script,1024);
		CStr(arg0,1024);
		CStr(arg1,1024);
		int off;
		int rcc;
		FILE *tmp = 0;

		if( fp == NULL ){ /* in condition */
			tmp = TMPFILE("EvalEval");
			fp = tmp;
		}
		off = ftell(fp);
		eval_DHTML(Conn,"",fp,arg,(iFUNCP)DHTML_printConn,NULL,&xlv);
		fflush(fp);
		fseek(fp,off,0);
		if( rcc = fread(script,1,sizeof(script)-1,fp) )
			setVStrEnd(script,rcc);
		else	setVStrEnd(script,0);
		fseek(fp,off,0);
		Ftruncate(fp,0,1);

		truncVStr(arg0);
		truncVStr(arg1);
		Xsscanf(script,"%[^.].%[^\377]",AVStr(arg0),AVStr(arg1));
		ret = DHTML_printConn(Conn,fp,fmt,arg0,arg1,value);
		if( tmp != NULL ){
			fclose(tmp);
		}
		return ret;
	}else
	if( streq(name,"movedto") ){
		int lns;
		CStr(buf,1024);
		Xstrcpy(FVStr(GEN_MovedTo),arg);
		dhtml_eval(Conn,fp,"%s",arg,value,&lns,FVStr(GEN_MovedTo));
		decodeEntitiesX(GEN_MovedTo,AVStr(buf),sizeof(buf),1);
		URL_reescape(buf,FVStr(GEN_MovedTo),1,0);
		return 1;
	}else
	if( streq(name,"setenent") ){
		ENCODE_ENT1 += 1;
		return 1;
	}else
	if( streq(name,"refresh") ){
		int sec;
		CStr(url,1024);
		CStr(xurl,1024);
		CStr(head,1024);
		truncVStr(url);
		Xsscanf(arg,"%d.%s",&sec,AVStr(url));

		if( 0 < sec ){
			if( sec < 10 ) sec = 10;
			sprintf(head,"Refresh: %d",sec);
			if( url[0] ){
				URL_reescape(url,FVStr(xurl),1,0);
				Xsprintf(TVStr(head),"; URL=%s",xurl);
			}
			Xsprintf(TVStr(head),"\r\n");
			strcat(addRespHeaders,head);
		}
	}else
	if( streq(name,"with") ){
		if( streq(arg,"rusage") ){
			if( isWindows() )
				return 0;
			else	return 1;
		}
		if( streq(arg,"sudo") ){
		}
	}
	return 0;
}
int put_eval_dhtml(Connection *Conn,PCStr(url),FILE *outfp,PCStr(instr))
{	int exitlev;

	exitlev = 0;
	return eval_DHTML(Conn,url,outfp,instr,(iFUNCP)DHTML_printConn,NULL,&exitlev);
}
