/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2005-2006 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	httpccx.c (character code conversion on HTTP)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
    TODO
	counter for mixed charset server:
	  SVCC=shift_JIS/12,euc-jp=/34,...
	see SVCC when without explicit charset and not obviousJP()
History:
	050714	extracted from http.c
//////////////////////////////////////////////////////////////////////#*/
#include "delegate.h"
#include "http.h"
#include "file.h"
#include "fpoll.h"


#define getFV(str,fld,buf)  getFieldValue2(str,fld,AVStr(buf),sizeof(buf))
int getParam(PVStr(params),PCStr(name),PVStr(val1),int siz,int del);
extern const char *TIMEFORM_COOKIE;

/*
 * SVCC is a hint for the charset of texts which is acceptable by
 * the server.  It is created from the charset of server's response.
 * It is sent from client in a Cookie in a request to indicate to
 * which charset a request to the server should be converted.
 */
#define DGC_SVCC "DeleGate-Control-SVCC"
#define NOCONV	"NoConv"
static char SVCCcookie[32]; /* SVCC sent from client in Cookie */
static int SVCCnoConv; /* SVCC=NoConv to disalbe CCX */
static char OutCharset[32];

void HTCCX_init(){
	SVCCcookie[0] = 0;
	SVCCnoConv = 0;
	OutCharset[0] = 0;
}

const char *CCXinputIsJP1(CCXP ccx);
void HTCCX_putSVCC(Connection *Conn,FILE *tc,int rcode,PCStr(head)){
	const char *xcharset;
	CStr(svcc,64);
	CStr(cenc,64);
	const char *gcharset = 0; /* guessed by look-ahead */
	int ccxerr = 0;

	if( CCXactive(CCX_TOCL) == 0 )
		return;

	svcc[0] = 0;
	if( InCharset[0] == 0 )
	{
		const char *xch;
		CStr(rcs,64); /* peeked charset */
		CStr(xhead,1024);
		CStr(tmp,4*1024);
		rcs[0] = 0;
		strcpy(xhead,head);
		extractParam(AVStr(xhead),"Content-Type","charset",AVStr(rcs),
			sizeof(rcs),0);
/*
CCXlog("{C} head charset[%s] In[%s]\n",rcs,InCharset);
*/
		if( getFV(head,"Content-Encoding",cenc)
		 && !strcaseeq(cenc,"identity")
		){	CStr(ctype,64);
			/* don't guess charset based on the encoded repr. */
			getFV(head,"Content-Type",ctype);
CCXlog("{C} ---- don't guess charset encoded[%s][%s]\n",cenc,ctype);
		}else
		if( rcs[0] == 0 ){
		/* should try scan_metahttp "HTTP-EQUIV Content-Type charset" */
		/*
		9.5.2 resp. mssg. into look-ahead buffer can be truncated
		at the boundary of Japanese Code so the convesion for it
		can leave pending input data (or error status possibly).
		Thus the CCX_TOCL used here for guessing / testing the input
		code should not be used for the real conversion.
		This problem has been since 9.0.3-pre13 (Jun2005) when
		the original setSVCC() was added into http.c.

		CCXexec(CCX_TOCL,head,strlen(head),AVStr(tmp),sizeof(tmp));
		xch = CCXident(CCX_TOCL); 
		*/
		int CCXpending(CCXP ccx);
		CStr(ccxb,64);

		CCXP ccx = (CCXP)ccxb;
		Bcopy(CCX_TOCL,ccxb,sizeof(ccxb));
		CCXexec(ccx,head,strlen(head),AVStr(tmp),sizeof(tmp));
		xch = CCXident(ccx);
		ccxerr = CCX_converror(ccx);

		if( ccxerr || CCXpending(ccx) ){
			sv1log("-- [%d] len=%d err=%d pending=%d %s\n",
				getpid(),istrlen(head),ccxerr,CCXpending(ccx),
				xch?xch:"");
			if( ccxerr ){
			fprintf(stderr,"-- [%d] len=%d err=%d pending=%d %s\n",
				getpid(),istrlen(head),ccxerr,CCXpending(ccx),
				xch?xch:"");
			fprintf(stderr,"-- %s://%s:%d%s\n%s\n",
				DST_PROTO,DST_HOST,DST_PORT,REQ_URL,head);
			}
		}

if( xch )
if( !strcaseeq(xch,"US-ASCII") )
		    if( ccxerr == 0
		     && !CCXguessing(CCX_TOCL)
		     && InCharset[0] == 0
		     && (SVCCcookie[0] == 0 || HttpReload)
		     ){
			gcharset = CCXinputIsJP1(ccx);

CCXlog("{C} ---- SVCC[%s]%d head guessed[%s][%s]\n",
				SVCCcookie,HttpReload,
				xch?xch:"?",gcharset?gcharset:"?");

		    }else{
CCXlog("{C} ---- [%s] head guessed[%s]\n",InCharset,xch?xch:"?");
		    }
		}
	}

	/*
	if( svcc[0] == 0 && InCharset[0] == 0 && CCX_converror(CCX_TOCL) == 0 )
	*/
	if( svcc[0] == 0 && InCharset[0] == 0 && ccxerr == 0 )
	if( !gcharset )
		return;

	/*
	if( CCX_converror(CCX_TOCL) ){
	*/
	if( ccxerr ){
		/* conversion is failed */
		CCXlog("{C} conv-error sv[%s] In[%s] SV[%s]\n",
			svcc,InCharset,SVCCcookie);
		if( InCharset[0] && !streq(InCharset,SVCCcookie) ){
			/* conv. req. by SVCC is not tried yet */
			xcharset = InCharset;
		}else{
			/*
			xcharset = NOCONV;
			*/
			xcharset = InCharset;
		}
	}else{
		xcharset = svcc;
		if( xcharset[0] == 0 )
			/* xcharset = CCXident(CCX_TOCL); */
			xcharset = InCharset;
		if( xcharset == 0 || *xcharset == 0 )
			xcharset = gcharset;
		if( xcharset == NULL )
			xcharset = "";
	}
	if( 300 <= rcode ){
		/* error message might in non-localized charset */
		CCXlog("{C} set SVCC[%s] cancelled by code=%d\n",
			xcharset,rcode);
		return;
	}
	if( !strcaseeq(xcharset,"US-ASCII") ){
		CStr(params,1024);
		CStr(path,1024);
		CStr(ex,64);
		int exp;
		/* the path should be the MOUNT point ... */
/*
		exp = time(0) + 10*60;
		StrftimeGMT(AVStr(ex),sizeof(ex),TIMEFORM_COOKIE,exp,0);
		sprintf(params,"%s=%s; Expires=%s",DGC_SVCC,xcharset,ex);
*/
/*
		sprintf(params,"%s=%s",DGC_SVCC,xcharset);
		fprintf(tc,"Set-Cookie: %s\r\n",params);
*/

		HTTP_originalURLPath(Conn,AVStr(path));
		if( *path ){
			const char *dp,*np;
			if( dp = strpbrk(path,"=+&%") )
				truncVStr(dp);
			if( dp = strchr(path,'?') )
				truncVStr(dp);
			else
			if( dp = strchr(path+1,'/') ){
				if( np = strchr(dp+1,'/') )
					truncVStr(np);
				else	truncVStr(dp);
			}
			else{
				if( path[0] == '/' )
					path[1] = 0;
			}
		}
		if( *path && strcmp(path,"/") != 0 ){
			sprintf(params,"%s=%s",DGC_SVCC,xcharset);
			fprintf(tc,"Set-Cookie: %s; Path=%s\r\n",params,path);
		}
		CCXlog("{C}*set SVCC[%s][%s]%s\n",xcharset,DST_HOST,path);

		exp = time(0) + 24*60*60;
		strcpy(path,"/");
		StrftimeGMT(AVStr(ex),sizeof(ex),TIMEFORM_COOKIE,exp,0);
		sprintf(params,"%s=%s; Expires=%s",DGC_SVCC,xcharset,ex);
		fprintf(tc,"Set-Cookie: %s; Path=%s\r\n",params,path);

		/*
		if( no Vary charset ){
			saveSVCCcache(Conn);
		}
		*/
	}
}

const char *URLinputEncoding = "ie,ei,ENCODING";
const char *parameq(PCStr(param),PCStr(name));
int isKnownCharset(PCStr(name));
int withInputEncoding(PVStr(url),PVStr(chset)){
	refQStr(up,url);
	const char *np;
	const char *ep;
	CStr(name,1024);
	IStr(cc,1024);

	if( up = strchr(url,'?') ){
		up++;
		while( *up ){
			np = wordScanY(up,name,"^=&");
			if( *np == '=' ){
				if( isinListX(URLinputEncoding,name,"") ){
					ep = wordScanY(np+1,cc,"^&");
					if( cc[0] ){
						if( isKnownCharset(cc) )
							strcpy(chset,cc);
						return 1;
					}
				}
			}
			for(; *up; up++ ){
				if( *up == '&' ){
					up++;
					break;
				}
			}
		}
	}
	return 0;
}

void HTCCX_getSVCC(Connection *Conn,PVStr(f)){
	IStr(qcc,128);
	CStr(cc,128);

	/*
	if( noSVCC ){
		return;
	}
	*/

	/*
	if( !CCXactive(CCX_TOCL) && !CCXactive(CCX_TOSV) ){
	*/
	if( !CCXactive(CCX_TOSV) )
	if( !CCXactive(CCX_TOCL) || CCXguessing(CCX_TOCL) ){
		/* SVCC is not hop-by-hop */
		return;
	}

	if( CurEnv ){
		withInputEncoding(AVStr(REQ_URL),AVStr(qcc));
		if( qcc[0] && SVCCcookie[0] == 0 ){
			Xstrcpy(FVStr(SVCCcookie),qcc);
		}
	}

	if( extractParam(AVStr(f),"Cookie",DGC_SVCC,AVStr(cc),sizeof(cc),1) ){
		if( cc[0] ){
			if( qcc[0] && isKnownCharset(qcc) ){
				sv1log("{C} SVCC[%s] < Query[%s]\n",cc,qcc);
				Xstrcpy(FVStr(SVCCcookie),qcc);
			}else
			Xstrcpy(FVStr(SVCCcookie),cc);
		}
	}
}

static int saveSVCCcache(Connection *Conn){
	return 0;
}
static int loadSVCCcache(Connection *Conn,PCStr(proto),PCStr(site),int port,PCStr(upath)){
	CStr(cpath,1024);
	CCXlog("----A {C} SVCC cache ? %s [%s][%s]%d[%s] cachedir=%X\n",REQ_URL,
		proto,site,port,upath,p2i(cachedir()));
	if( CTX_cache_path(Conn,proto,site,port,upath,AVStr(cpath)) == 0 )
		return 0;
	CCXlog("----B {C} SVCC cache ? %s [%s][%s]%d[%s] %s\n",REQ_URL,
		proto,site,port,upath,cpath);
	return 0;
}

static int noCCXTOSV(Connection *Conn){
	if( 2 <= HttpReload ){
		/* MSIE issues no-cache with POST of which body should be CCX */
		if( strcaseeq(RequestMethod,"POST") ){
			sv1log("{C} force SVCC on [%s] req. reload=%d\n",
				RequestMethod,HttpReload);
			return 0;
		}
		return 1;
	}
	return 0;
}
static void initCCXbySVCC(Connection *Conn,PCStr(proto),PCStr(site),int port,PCStr(upath)){
	const char *stat = "";

	if( CCXactive(CCX_TOSV) != 0 )
		return;

	if( SVCCcookie[0] == 0 ){
/*
CCXlog("---- {C} CCX_TOSV=%X CCX_TOCL=%X SVCC=[%s]\n",
CCXactive(CCX_TOSV),CCXactive(CCX_TOCL),SVCCcookie);
		if( CCXactive(CCX_TOCL) == 0
		 || loadSVCCcache(Conn,proto,site,port,upath) == 0 )
*/
			return;
	}

	/*
	if( 2 <= HttpReload ){
	*/
	if( noCCXTOSV(Conn) ){
		stat = "IGNORED";
	}else
	if( streq(SVCCcookie,NOCONV) ){
		SVCCnoConv = 1;
	}else{
		CCXcreate("*",SVCCcookie,CCX_TOSV);
		CCXtosv(CCX_TOSV,1);
		/* also it could be a hint for the input from server
		 * when it is ambiguous
		 * CCX_setincode(CCX_TOCL,SVCCcookie)
		 */
	}

	if( lCHARSET() )
	if( fileSeemsBinary(REQ_URL) <= 0 )
	{
		CStr(dom,32);
		refQStr(dp,dom);
		if( strncmp(REQ_URL,"http://",7) == 0 )
			FStrncpy(dom,REQ_URL+7);
		else	FStrncpy(dom,REQ_URL);
		if( dp = strchr(dom,'/') )
		if( dp = strchr(dp+1,'/') )
			setVStrEnd(dp,1);
		CCXlog("{C}*got SVCC[%s][%s]%s\n",SVCCcookie,dom,stat);
	}
}

static
void HTCCX_setInputCode(Connection *Conn,PCStr(where),CCXP ccx,PCStr(cset)){
	Xstrcpy(FVStr(InCharset),cset);
	CCXlog("{C} %s InCharset[%s] %d\n",where,InCharset,CCXwithJP(ccx));

	/* set the charset into CCX as the hint on input-charset */
	/*if( CCXwithJP(ccx) == 0 ) should be overridden HEAD < XML < META */
	if( cset[0] && CCXcharsetcmp(cset,"ISO-2022-JP") != 0 ){
		sv1log("{C} set CCX in-charset[%s] by %s\n",cset,where);
		CCX_setincode(ccx,cset);
	}
}

/* 9.6.1 fixed: it is broken in 9.2.4-pre12 by "IGNORED DUP setincode()" to
 * cope with broken HTML with multiple inconsistent META, but it is set
 * usually in HEAD (or XML) before META
 */
const char *CCX_incodeisset(CCXP ccx);
void CCX_clearincode(CCXP ccx);
static void clearInputCode(CCXP ccx,PCStr(cset),PCStr(text)){
	CStr(ccxb,64);
	CCXP gccx = (CCXP)ccxb;
	const char *ocset;
	const char *icset;
	int len;

	ocset = CCX_incodeisset(ccx);
	if( ocset == 0 || CCXcharsetcmp(ocset,cset) == 0 ){
		return;
	}
	CCXcreate("*","guess",gccx);
	CCX_setindflt(gccx,cset);
	len = strlen(text);
	CCXexec(gccx,text,len,ZVStr(text,len+1),len+1);
	if( CCXnonJP(gccx) == 0 )
	if( icset = CCXident(gccx) )
	if( CCXcharsetcmp(icset,cset) == 0 ){
		sv1log("{C} reset in-charset=%s[%s] <- %s\n",cset,icset,ocset);
		/* clear it before setincode() in thruCode() */
		CCX_clearincode(ccx);
	}
}

static int thruCode(Connection *Conn,PCStr(where),CCXP ccx,PCStr(cset)){
	const char *ccxout = 0;

	HTCCX_setInputCode(Conn,where,ccx,cset);

	/* don't erase charset=... if the charset is not changed */
	if( CCXactive(ccx) )
	if( CCXoutcharset(ccx,&ccxout) )
	if( ccxout != 0 && CCXcharsetcmp(ccxout,cset) == 0 ){
		sv1log("{C} thru chaset=%s in %s\n",cset,where);
		return 1;
	}

	if( CCXguessing(ccx) ){ /* CHARSET=guess */
		sv1log("{C} thru chaset=%s in %s (CHARSET=guess)\n",cset,where);
		Xstrcpy(FVStr(InCharset),cset);
		return 1;
	}

	if( CCX_inputIsJP(ccx) == 0 ){
		sv1log("{C} thru nonJP chaset=%s in %s\n",cset,where);
		return 1;
	}
	return 0;
}

void HTCCX_setReqSVCC(Connection *Conn,PCStr(proto),PCStr(site),int port,PCStr(upath)){
	if( HttpReload ){
		if( SVCCcookie[0] )
		if( fileSeemsBinary(REQ_URL) <= 0 )
		{
			CCXlog("{C} %sSVCC[%s] with reload-%d [%s]\n",
				2<=HttpReload?"(ignore)":"",
				SVCCcookie,HttpReload,REQ_URL);
		}
		/*
		if( 2 <= HttpReload ){
		*/
		if( noCCXTOSV(Conn) ){
			SVCCcookie[0] = 0;
			SVCCnoConv = 0;
		}
	}
	//if( SVCCcookie[0] )
	{
		initCCXbySVCC(Conn,proto,site,port,upath);
	}
}

int HTCCX_replaceCharset(Connection *Conn,PVStr(field),int fnlen,FILE *fp){
	const char *xcharset;
	CStr(ctype,64);
	CStr(chset,32);

	/*
	Xsscanf(field+fnlen," %[a-zA-Z0-9/-]",AVStr(ctype));
	*/
	Xsscanf(field+fnlen," %[a-zA-Z0-9/+-]",AVStr(ctype));
	if( !STRH(field,F_CtypeText)
	 && !streq(ctype,"application/x-javascript")
	 && !streq(ctype,"application/xml")
	 && !streq(ctype,"application/soap+xml")
	){
		return 0;
	}
	getParam(DVStr(field,fnlen),"charset",AVStr(chset),sizeof(chset),0);

	if( xcharset = HTTP_outCharset(Conn) )
	if( CCXactive(CCX_TOCL) )
	{
		if( chset[0] != 0 )
			HTCCX_setInputCode(Conn,"HEAD",CCX_TOCL,chset);

		if( chset[0] == 0 )
		if( file_isreg(fileno(fp)) )
		{
			int off;
			int rcc;
			char buff[4096];
			CStr(ob,4096);
			CStr(st,64);

			off = ftell(fp);
			rcc = fread(buff,1,sizeof(buff)-1,fp);
			fseek(fp,off,0);
			if( 0 < rcc ){
				buff[rcc] = 0;
				CCXexec(CCX_TOCL,buff,rcc,AVStr(ob),sizeof(ob));
			}
			CCXstats(CCX_TOCL,AVStr(st));
			CCXlog("{C} [%s] nonJP=%d %s\n",ctype,
				CCXnonJP(CCX_TOCL),st);
		}
		if( CCXnonJP(CCX_TOCL) ){
			CCXlog("{C} Head thru nonJP[%s] %s",chset,field);
		}else
		if( SVCCnoConv == 0 ){
			replace_charset(AVStr(field),xcharset);
			CCXlog("{C} Head replaced[%s] %s",chset,field);
			Xstrcpy(FVStr(OutCharset),xcharset);
			return 1;
		}
	}
	return 0;
}

int CCX_obviousJP(CCXP ccx);
int HTCCX_restoreCharset(Connection *Conn,PVStr(field),int fnlen,PCStr(where)){
	CStr(buf,128);
	CStr(ctype,64);
	CStr(cs,64);
	int nonJP = 0;

	if( Conn == NULL )
		return 0;

	Xsscanf(field+fnlen," %[a-zA-Z0-9/-]",AVStr(ctype));
	if( !STRH(field,F_CtypeText)
	 && !streq(ctype,"application/x-javascript")
	 && !streq(ctype,"application/xml")
	){
		return 0;
	}
	getParam(DVStr(field,fnlen),"charset",AVStr(cs),sizeof(cs),0);

	CCXstats(CCX_TOCL,AVStr(buf));
	CCXlog("{C} %s[%s] SVCC[%s] %s%s%s %s %s",where,InCharset,SVCCcookie,
		CCXactive(CCX_TOCL)?"A":"-",
		CCXwithJP(CCX_TOCL)?"J":"-",
		CCXnonJP(CCX_TOCL)?"?":"-",
		buf,field);

	if( CCXactive(CCX_TOCL) == 0 )
		return 0;

	if( CCXguessing(CCX_TOCL) ){
		/* setGuessedCharset() will be called after ... */
		return 0;
	}

	if( InCharset[0] == 0 )
	if( InLang[0] && !strcaseeq(InLang,"jp") )
	{
		if( CCX_obviousJP(CCX_TOCL) == 0 ){
			/*
			nonJP = 1;
			*/
			CCXlog("{C} nonJP Lang[%s] [%s]\n",InLang,InCharset);
		}
	}

	if( nonJP == 0 )
	if( CCXwithJP(CCX_TOCL) )
	if( CCXnonJP(CCX_TOCL) == 0 )
	{
		const char *outchset;
		if( OutCharset[0] != 0 )
			return 0;
		/* out-charset was not put in the header because
		 * unknown or non-JP charset name was given originally,
		 * but after then CCX charset was set by META and
		 * conversion was done.
		 */
		if( CCX_converror(CCX_TOCL) )
			return 0;
		/*
		if( CCXoutcharset(CCX_TOCL,&outchset) == 0 || outchset == 0 )
		*/
		if( (outchset = CCXcharset(CCX_TOCL)) == 0 )
			return 0;
		replace_charset(AVStr(field),outchset);
		CCXlog("{C} %s/Head replace[%s]<-[%s][%s] %s",
			where,outchset,cs,InCharset,field);
		/* for asahi-net */
		return 1;
	}

	/*
	strcpy(cs,"");
	*/
	if( InCharset[0] )
		replace_charset(AVStr(field),InCharset);
	else{
		getParam(DVStr(field,fnlen),"charset",AVStr(cs),sizeof(cs),1);
	}
	CCXlog("{C} %s[%s]<-[%s] restoreCharset %s",where,InCharset,cs,field);
	return 1;
}

int HTCCX_guessCharset(Connection *Conn,PCStr(ctype))
{ 
	if( strcasestr(ctype,"text/html") || strcasestr(ctype,"text/plain") )
	if( strcasestr(ctype,"charset=") == 0 )
	if( CCXactive(CCX_TOCL) )
	if( CCXguessing(CCX_TOCL) ) /* CHARSET=guess */
		return 1;
	return 0;
}

void HTCCX_setGuessedCharset(Connection *Conn,PVStr(line))
{	int fnlen;
	const char *xcharset;

	if( fnlen = STRH(line,F_ContType) )
	if( HTCCX_guessCharset(Conn,line+fnlen) ){
		if( xcharset = CCXident(CCX_TOCL) ){
			if( strcaseeq(xcharset,"US-ASCII") )
				xcharset = InCharset;
			if( *xcharset )
			if( !strcaseeq(xcharset,"US-ASCII") ){
				replace_charset(AVStr(line),xcharset);
				sv1log("{C} charset guessed:%s",line+fnlen);
			}
		}
	}
}

int CCXinURL(CCXP ccx,int inURL);
int HTCCX_reqURL(Connection *Conn,PCStr(url1),PVStr(url2));

void HTCCX_reqHead(Connection *Conn)
{	const char *method;
	const char *ver;
	HttpRequest reqx;
	CStr(url1,URLSZ);
	CStr(url2,URLSZ);

	if( CCXactive(CCX_TOSV) == 0 )
		return;

	decomp_http_request(REQ,&reqx);
	method = reqx.hq_method;
	strcpy(url1,reqx.hq_url);
	ver = reqx.hq_ver;
	

	if( HTCCX_reqURL(Conn,url1,AVStr(url2)) ){
		sprintf(url1,"%s %s HTTP/%s\r\n",method,url2,ver);
		sv1log("{C} applied char. conv. for request header (%d<-%d)\n",
			istrlen(url1),istrlen(REQ));
		CCXlog("{C} CCX_REQ [%s] (%d <- %d) %s\n",SVCCcookie,
			istrlen(url1),istrlen(REQ),url2);
		strcpy(REQ,url1);
		Verbose(">> %s",REQ);
	}
}

int URL_escape2B(PCStr(src),PVStr(dst));
int URL_unescape2B(PCStr(src),PVStr(dst));
void HTCCX_Qhead(Connection *Conn,PVStr(head)){
	CStr(ccxb,64);
	IStr(xhead,URLSZ);
	IStr(yhead,URLSZ);
	if( CCXactive(CCX_TOSV) == 0 )
		return;

	URL_unescape2B(head,AVStr(xhead));
	Bcopy(CCX_TOSV,ccxb,sizeof(ccxb));
	CCX_setincode((CCXP)ccxb,"utf-8"); /* output of TOCL */
	CCXexec((CCXP)ccxb,xhead,strlen(xhead),AVStr(yhead),sizeof(yhead));
	fprintf(stderr,"--REQ--CCX-Qhead-I %s",xhead);
	fprintf(stderr,"--REQ--CCX-Qhead-O %s",yhead);

	if( strcmp(xhead,yhead) != 0 ){
		URL_escape2B(yhead,AVStr(xhead));
		if( lCHARSET() ){
			sv1log("CCX-Qhead-I %s",head);
			sv1log("CCX-Qhead-O %s",xhead);
		}
		strcpy(head,xhead);
	}
}
void HTCCX_Rhead(Connection *Conn,PVStr(head)){
	CStr(ccxb,64);
	IStr(xhead,URLSZ);
	IStr(yhead,URLSZ);
	if( CCXactive(CCX_TOCL) == 0 )
		return;

	URL_unescape2B(head,AVStr(xhead));
	Bcopy(CCX_TOCL,ccxb,sizeof(ccxb));
	CCX_setincode((CCXP)ccxb,"Shift_JIS"); /* SVCC */
	CCXexec((CCXP)ccxb,xhead,strlen(xhead),AVStr(yhead),sizeof(yhead));
	fprintf(stderr,"--RESP--CCX-Rhead-I %s",xhead);
	fprintf(stderr,"--RESP--CCX-Rhead-O %s",yhead);

	if( strcmp(xhead,yhead) != 0 ){
		strcpy(head,yhead);
		/*
		URL_escape2B(yhead,AVStr(xhead));
		if( lCHARSET() ){
			sv1log("CCX-Rhead-I %s",head);
			sv1log("CCX-Rhead-O %s",xhead);
		}
		strcpy(head,xhead);
		*/
	}
}

int HTCCX_reqURL(Connection *Conn,PCStr(urli),PVStr(url2)){
	CStr(url1,URLSZ);
	refQStr(sp1,url1); /**/
	int oc;

	if( CCXactive(CCX_TOSV) == 0 )
		return 0;

	strcpy(url1,urli);
	if( sp1 = strchr(url1,'?') ){
		strcpy(url2,sp1+1);
		sprintf(sp1,"-_-_-%s",url2);
	}

	/* should do CCX_setincode(CHARSET-param) because the client is
	 * expected to send request string in the response CHARSET
	 * if the request is not in the CHARSET, then start without
	 * the hypothesis.
	 */

	if( strchr(REQ,'%') ){
		CCXlog("{C} CCX_REQ [%s] %s\n",SVCCcookie,url1);
	}
	URL_unescape(url1,AVStr(url2),0,1);
	/*
	nonxalpha_unescape(url1,AVStr(url2),0);
	*/
	CCXinURL(CCX_TOSV,1);
	oc = CCXexec(CCX_TOSV,url2,strlen(url2),AVStr(url1),sizeof(url1));
	CCXexec(CCX_TOSV,"",0,QVStr(url1+oc,url1),sizeof(url1)-oc);
	if( strchr(REQ,'%') ){
		CStr(st,128);
		CCXstats(CCX_TOSV,AVStr(st));
		CCXlog("{C} CCX_REQ convstat=%s\n",st);
	}
	CCXinURL(CCX_TOSV,0);

	if( strcmp(url1,url2) == 0 )
		return 0;

	if( strcmp(url1,url2) != 0 ){
		refQStr(sp2,url2);
		URL_reescape(url1,AVStr(url2),0,1);
		if( sp2 = strstr(url2,"-_-_-") )
			sprintf(sp2,"?%s",sp2+5);
	}
	return 1;
}

int CCXmime(CCXP ccx,PCStr(head),PCStr(body),PVStr(xbody),int xsiz){
	int oc;
	oc = CCXexec(ccx,body,strlen(body),BVStr(xbody),xsiz);
	return oc;
}

const char *HTTP_POSTccxType = "application/x-www-form-urlencoded";
/* "multipart/form-data,application/x-www-form-urlencoded"; */

int HTCCX_reqBodyWithConv(Connection *Conn,PCStr(req),PCStr(fields)){
	CStr(ctype,128);
	if( getFV(fields,"Content-Type",ctype) ){
	  if( CCXactive(CCX_TOSV) ){
		/*
	    if( streq(ctype,"application/x-www-form-urlencoded") ){
		*/
	    if( isinListX(HTTP_POSTccxType,ctype,"ch") ){
		return 1;
	    }
	  }
	}
	return 0;
}
int HTCCX_reqBody(Connection *Conn,FILE *ts,PCStr(req),PCStr(fields),PCStr(body),int blen){
	IStr(ctypef,128);
	CStr(ctype,128);
	CStr(cleng,32);
	defQStr(xbody);
	defQStr(ybody);
	defQStr(xfields);
	int bsiz;
	int hsiz;
	int oc;
	const char *cs;

	/*
	if( getFV(fields,"Content-Type",ctype) ){
	*/
	if( getFV(fields,"Content-Type",ctypef) ){
	  if( CCXactive(CCX_TOSV) ){
		wordScanY(ctypef,ctype,"^; ");
		/*
	    if( streq(ctype,"application/x-www-form-urlencoded") ){
		*/
	    if( isinListX(HTTP_POSTccxType,ctype,"ch") ){
		if( 1024*1024 < blen ){
			sv1log("## too large POST body for CCX: %d\n",blen);
			return 0;
		}
		/*
		bsiz = blen * 2;
		*/
		bsiz = blen * 4 + 1024;
		setQStr(xbody,malloc(bsiz),bsiz);
		setQStr(ybody,malloc(bsiz),bsiz);
	       if( streq(ctype,"application/x-www-form-urlencoded") ){
		sv1log("{C} --qbody--URLESC-I %s\n",body);
		URL_unescape(body,AVStr(xbody),1,1);
		oc = CCXexec(CCX_TOSV,xbody,strlen(xbody),AVStr(ybody),bsiz);
		CCXexec(CCX_TOSV,"",0,QVStr(ybody+oc,ybody),bsiz-oc);
		URL_reescape(ybody,AVStr(xbody),1,1);
		sv1log("{C} --qbody--URLESC-O %s\n",xbody);
	       }else
	       if( strheadstrX(ctype,"multipart/",1) ){
		oc = CCXmime(CCX_TOSV,fields,body,AVStr(xbody),bsiz);
	       }else{
		oc = CCXexec(CCX_TOSV,body,strlen(body),AVStr(xbody),bsiz);
	       }
		sprintf(cleng,"%d",istrlen(xbody));

		hsiz = strlen(fields) + 128;
		setQStr(xfields,malloc(hsiz),hsiz);
		strcpy(xfields,fields);
		replaceFieldValue(AVStr(xfields),"Content-Length",cleng);
		sv1log("{C} applied char. conv. for request body (%s<-%d)\n",
			cleng,blen);
		cs = CCXcharset(CCX_TOSV);
		if( cs == 0 )
			cs = "";
		sv1log("{C} CCX to[%s] from[%s]\n",cs,CCXident(CCX_TOSV));

		if( *cs )
		if( strstr(ctype,"text/")
		 || strstr(ctype,"/xml")
		 || strstr(ctype,"+xml")
		){
			defQStr(ctp);
			cpyQStr(ctp,xfields);
			if( ctp = findFieldValue(xfields,"Content-Type") )
        			replace_charset_value(AVStr(ctp),cs,0);
		}

		fputs(req,ts);
		fputs(xfields,ts);
		fputs(xbody,ts);

		sv1log("-- POST CCX for req. body (%s/%d <- %d)\n",cleng,bsiz,
			blen);
		return 1;
	    }
	  }
	}
	return 0;
}

int CCX_reqBody(Connection *Conn,PCStr(head),FILE *in,FILE *out,int len,int tout){
	int icc = 0;
	int wcc = 0;
	int occ;
	const char *rs;
	CStr(line,4*1024);
	CStr(xlin,16*1024);
	CStr(ylin,16*1024);
	int remleng;
	int gotleng;
	int isbin;
	int timeout;
	CCXP ccx = CCX_TOSV;
	IStr(ctype,128);

	if( !CCXactive(ccx) ){
		return 0;
	}
	getFV(head,"Content-Type",ctype);
	if( !isinListX(HTTP_POSTccxType,ctype,"ch") ){
		return 0;
	}
	if( strcasestr(ctype,"-urlencoded") ){
		CCXinURL(ccx,1);
	}

	remleng = len;
	timeout = tout * 1000;
	for(;;){
		if( remleng <= 0 ){
			timeout = 1;
		}
		if( 100 <= timeout ){
			if( fPollIn(in,100) == 0 )
				fflushTIMEOUT(out);
		}else{
			fflushTIMEOUT(out);
		}
		rs = fgetsByBlock(AVStr(line),sizeof(line),in,
			0,timeout,0,0,remleng,&gotleng,&isbin);
		if( rs == NULL ){
			break;
		}
		icc += strlen(line);
		remleng -= icc;
		URL_unescape(line,AVStr(xlin),0,1);
		if( lCHARSET() ){
			setVStrEnd(line,1024);
			sv1log("{C} --qbody--URLESC-i %s\n",line);
		}
		occ = CCXexec(ccx,xlin,strlen(xlin),AVStr(ylin),sizeof(ylin));
		URL_reescape(ylin,AVStr(xlin),0,1);
		fputs(xlin,out);
		if( lCHARSET() ){
			setVStrEnd(xlin,1024);
			sv1log("{C} --qbody--URLESC-o %s\n",xlin);
		}
		wcc += occ;
	}
	if( occ = CCXexec(ccx,"",0,AVStr(xlin),sizeof(xlin)) ){
		URL_reescape(xlin,AVStr(ylin),0,1);
		fputs(ylin,out);
		wcc += occ;
	}
	return wcc;
}

/*
	if( CCXactive(CCX_TOSV) == 0 )
	if( CCXactive(CCX_TOCL) != 0 ){
		int tobeccx = 0;
		const char *qp;
		char ch;
		for( qp = REQ_URL; ch = *qp; qp++ ){
			if( (ch & 0x80) || ch == '%' ){
				tobeccx = 1;
				break;
			}
		}
		CCXcreate("*",outcs,CCX_TOSV);
		CCXsetincode(CCX_TOSV,incs);
	}
*/

static const char *metahttp(Connection *Conn,PCStr(attr),PVStr(cont),PCStr(tagp),PVStr(contp),PCStr(nextp))
{	CStr(cset,64);
	int len;

	if( strcaseeq(attr,"Content-Language") ){
		strcpy(InLang,cont);
		return nextp;
	}

	if( strncaseeq(tagp,"<?xml",5) )
	if( strcaseeq(attr,"encoding") ){
		int olen;
		clearInputCode(CCX_TOCL,cont,nextp);
		if( thruCode(Conn,"?XML",CCX_TOCL,cont) )
			return nextp;
		olen = strlen(contp);
		getParam(BVStr(contp),"encoding",AVStr(cset),sizeof(cset),1);
		len = strlen(contp);
		sv1log("{C} removed charset in ?XML[%s][%s]\n",attr,cont);
		nextp = nextp - (olen-len);
		return nextp;
	}

	cset[0] = 0;
	if( strcaseeq(attr,"Content-Type") )
	if( len = erase_charset_param(AVStr(cont),AVStr(cset)) ){
		clearInputCode(CCX_TOCL,cset,nextp);
		if( thruCode(Conn,"META",CCX_TOCL,cset) )
			return nextp;
		len = erase_charset_param(AVStr(contp),AVStr(cset));
		sv1log("{C} removed charset in HTTP-EQUIV[%s][%s]\n",cont,cset);
		return nextp - len;
	}
	return nextp;
}

typedef const char *(*scanMetaFuncP)(Connection *Conn,PCStr(attr),PVStr(cont),PCStr(tagp),PVStr(contp),PCStr(nextp));
void scan_metahttp(Connection*ctx,PVStr(line),scanMetaFuncP func);
static int htmlconv(Connection *Conn,PCStr(ctype),PVStr(Cline));

int HTCCX_html(Connection *Conn,PCStr(ctype),int size,PVStr(Cline),PVStr(Nline)){
	if( SVCCnoConv )
		return 0;

/*
	htmlconv(Conn,ctype,BVStr(Cline));
*/
	if( strcasestr(ctype,"text") == 0 || strcasestr(ctype,"html") == 0 ){
		/* 9.9.4 non HTML, without META */
	}else
	scan_metahttp(Conn,BVStr(Cline),metahttp);
	if( CCXactive(CCX_TOCL) )
		CCXexec(CCX_TOCL,Cline,strlen(Cline),BVStr(Nline),size);
	else	CTX_line_codeconv(Conn,Cline,BVStr(Nline),ctype);
	return 1;
}


/*
 * 050718 extracted from delegated.c
 */
#include "param.h"
static int loadCCXmap(PCStr(map),int mi,int mn){
	CStr(url,1024);
	CStr(path,1024);
	FILE *tmp,*fp;
	int loaded = 0;

	sprintf(url,"%s/codemap/%s",DELEGATE_homepage(),map);
	fprintf(stderr,"---- %d/%d downloading %s ...\n",mi,mn,url);
	sprintf(path,"${LIBDIR}/codemap/%s",map);
	Substfile(path);
	if( 0 < File_size(path) ){
		fprintf(stderr,"---- ALREADY at %s (%dbytes)\n",path,
			File_size(path));
		return 0;
	}

	tmp = TMPFILE("CCXtab");
	if( tmp == NULL )
		return 0;

	URLget(url,0,tmp); /* global CHARSET should be disabled ... */
	if( !feof(tmp) && 0 < file_size(fileno(tmp)) ){
		if( fp = dirfopen("CCXMAP",AVStr(path),"w") ){
			copyfile1(tmp,fp);
			fclose(fp);
			fprintf(stderr,"---- INSTALLED at %s (%dbytes)\n",path,
				File_size(path));
			loaded = 1;
		}
		else{
			fprintf(stderr,"???? FAILED to create %s\n",path);
		}
	}
	else{
		fprintf(stderr,"???? FAILED to download %s\n",url);
	}
	fclose(tmp);
	return loaded;
}

int CCX_JUmapCache(PCStr(jumap),PVStr(bpath));
int get_builtin_MADE_TIME();
/*
void downloadCCXTabs(Connection *Conn)
*/
void downloadCCXTabs0(Connection *Conn)
{	const char *charset;
	int loaded = 0;

	if( DELEGATE_getEnv(P_CHARSET) || DELEGATE_getEnv(P_CHARCODE) )
	/*
	if( (charset = CCXcharset(CCX_TOCL)) && strcmp(charset,"UTF-8") == 0 ){
	*/
	/*
	if( CCXcharset(CCX_TOCL) && CCXoutJP(CCX_TOCL) ){
	*/
	if( CCXcharset(CCX_TOCL) && CCXoutJP(CCX_TOCL)
	 || (ConfigFlags & (CF_WITH_CCXTOSV|CF_WITH_CCXTOCL))
	){
		CStr(path,1024);
		if( 0 < CCX_JUmapCache(NULL,AVStr(path)) )
		if( get_builtin_MADE_TIME() <= File_mtime(path) )
		if( 0 < UCSinit() )
			return;

		fprintf(stderr,"**** downloading CHARSET tables ....\n");
		if( isWindowsCE() ){
			loaded += loadCCXmap("CP932.TXT",1,1);
		}else{
		loaded += loadCCXmap("JIS0208.TXT",1,5);
		loaded += loadCCXmap("JIS0212.TXT",2,5);
		loaded += loadCCXmap("SHIFTJIS.TXT",3,5);
		loaded += loadCCXmap("CP932.TXT",4,5);
		loaded += loadCCXmap("JAPANESE.TXT",5,5);
		}
		fprintf(stderr,"**** downloaded %d tables\n",loaded);
		UCSreset();
		if( 0 < UCSinit() ){
			fprintf(stderr,"**** cached at %s\n",path);
			File_touch(path,time(0));
		}else{
			fprintf(stderr,"**** ERROR in the tables...\n");
		}
	}
}
void downloadCCXTabs(Connection *Conn){
	if( !lISCHILD() ){
		downloadCCXTabs0(Conn);
	}
	if( DELEGATE_getEnv(P_CHARSET) || DELEGATE_getEnv(P_CHARCODE) ){
		/* 9.5.5 This is effective on Windows where fork() is not
		 * to inherit the initialized representation by UCSinit().
		 * It is necessary with "thread" to suppress the stack
		 * growth in the thread by on-demand UCSinit()
		 */
		UCSinit();
	}
}

typedef struct {
	char *s_src;
	char *s_dst;
} Subst;
static Subst subst[128];
static int substx;

static int htmlconv(Connection *Conn,PCStr(ctype),PVStr(line)){
	int i;
	if( substx == 0 ){
		FILE *fp;
		CStr(cline,1024);
		CStr(src,256);
		CStr(dst,256);
		const char *dp;
		if( fp = fopen("mlb.cnv","r") ){
			while( fgets(cline,sizeof(cline),fp) != NULL ){
				dp = wordScanY(cline,src,"^\t");
				if( *dp != '\t' )
					continue;
				while( *dp == '\t' )
					dp++;
				lineScan(dp,dst);
				if( *src && *dst ){
					subst[substx].s_src = stralloc(src);
					subst[substx].s_dst = stralloc(dst);
					substx++;
				}
			}
fprintf(stderr,"---- loaded %d\n",substx);
			fclose(fp);
		}else{
		}
	}
	for( i = 0; i < substx; i++ ){
		CStr(oline,0x10000);
		CStr(buf1,0x10000);
		CStr(buf2,0x10000);
		strcpy(oline,line);
		strsubst(BVStr(line),subst[i].s_src,subst[i].s_dst);

		if( strcmp(oline,line) != 0 ){
fprintf(stderr,"#A# [%s] %s %s\n",ctype,subst[i].s_src,REQ_URL);
if(strstr(line,"TINO"))
fprintf(stderr,"----------------------------------\n");
/*
fprintf(stderr,"#A# %s\n",line);
			URL_unescape(line,AVStr(buf1),0,1);
		CCXexec(CCX_TOCL,buf1,strlen(buf1),AVStr(buf2),sizeof(buf2));
			URL_reescape(buf2,AVStr(line),0,1);
fprintf(stderr,"#B# %s\n",line);
*/
		}
	}
	return 0;
}

int urlccx_main(int ac,const char *av[],Connection *Conn){
	int ai;
	const char *a1;
	const char *ics = "*";
	const char *ocs = "asis";
	IStr(txt,8*1024);
	IStr(xtxt,8*1024);
	refQStr(tp,txt);
	int rcc;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( *a1 == '-' ){
			if( a1[1] == '-' ){
				ics = a1+2;
			}else{
				ocs = a1+1;
				CCXcreate(ics,ocs,CCX_TOSV);
			}
		}else{
			if( txt < tp )
				setVStrPtrInc(tp,' ');
			strcpy(tp,a1);
		}
	}
	CCXinURL(CCX_TOSV,1);
	if( *txt == 0 ){
		rcc = fread((char*)txt,1,sizeof(txt)-1,stdin);
		if( 0 < rcc ){
			setVStrEnd(txt,rcc);
		}
	}
	if( *txt ){
		URL_unescape(txt,AVStr(xtxt),0,1);
		CCXexec(CCX_TOSV,xtxt,strlen(xtxt),AVStr(txt),sizeof(txt));
		URL_reescape(txt,AVStr(xtxt),0,1);
		strsubst(AVStr(xtxt),"%20"," ");
		strsubst(AVStr(xtxt),"%0A","\n");
		fprintf(stdout,"%s\n",xtxt);
	}
	return 0;
}

const char *COOKIE_CLCC = "DeleGate-Control-CLCC";
const char *HTTP_originalReqBody(Connection *Conn);
int HTTP_getCookie(DGC*ctx,PCStr(name),PVStr(clcc),int csiz);
int CCX_setindflt(CCXP ccx,PCStr(from));
void CTXsetCCX_TOCL(Connection *Conn,CCXP ccx,PCStr(ocs)){
	const char *ics = "*";
	IStr(clcc,128);

	CCXcreate(ics,ocs,ccx);
	if( HTTP_getCookie(Conn,COOKIE_CLCC,AVStr(clcc),sizeof(clcc)) ){
		if( lCHARSET() )
		sv1log("{C} new %s=%s\n",COOKIE_CLCC,clcc);
		CCX_setindflt(ccx,clcc);
	}
}
void HTCCX_setindflt(Connection *Conn){
	IStr(clcc,128);
	if( HTTP_getCookie(Conn,COOKIE_CLCC,AVStr(clcc),sizeof(clcc)) ){
		if( lCHARSET() ){
			sv1log("{C} set %s=%s\n",COOKIE_CLCC,clcc);
		}
		CCX_setindflt(CCX_TOCL,clcc);
	}
}

const char *HTTP_detectReqCharcode(Connection *Conn,PCStr(iqcharcode)){
	CStr(ccxb,128);
	CCXP ccx = (CCXP)ccxb;
	CStr(buf1,URLSZ);
	CStr(buf2,URLSZ);
	const char *cset;
	const char *body;

	if( iqcharcode && *iqcharcode ){
		CCXcreate("*","guess",ccx);
		CCX_setindflt(ccx,iqcharcode);
		if( lCHARSET() )
		sv1log("{C} set guess inchar-dflt[%s]\n",iqcharcode);
	}else{
	CTXsetCCX_TOCL(Conn,ccx,"guess");
	}

	lineScan(OREQ_MSG,buf1);
	URL_unescape(buf1,AVStr(buf2),0,1);
	CCXexec(ccx,buf2,strlen(buf2),AVStr(buf1),sizeof(buf1));
	CCXexec(ccx,"\n\n",2,AVStr(buf2),sizeof(buf2));

	body = HTTP_originalReqBody(Conn);
	URL_unescape(body,AVStr(buf2),0,1);
	CCXexec(ccx,buf2,strlen(buf2),AVStr(buf1),sizeof(buf1));
	CCXexec(ccx,"\n\n",2,AVStr(buf1),sizeof(buf1));

	cset = CCXident(ccx);
	if( cset ){
		return cset;
	}
	return "";
}
