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
Program:	cfi.c (Common Filter Interface)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960130	created
	960203	renamed from approxy (application protocol translation library)
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "config.h"
#include "ystring.h"
#include "fpoll.h"
#include "file.h"
#include "dglib.h"
#include <ctype.h>

int builtin_filter(DGC*ctx,PCStr(what),PCStr(filter),FILE *in,FILE *out,FILE *in1,FILE *out1);
void system_CGI(DGC*ctx,PCStr(conninfo),PCStr(oreq),PCStr(req),PVStr(head),PCStr(cgi),FILE *in,FILE *out);
int systemFilter(PCStr(command),FILE *in,FILE *out);
int HTTP_putMIMEmsg(DGC*Conn,FILE *in,FILE *out);
void genheadf(PCStr(fmt),PVStr(out),int siz);
UTag RFC822_readHeaderU(FILE *in,int seeEOR);

#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,ZVStr(buf,siz),siz)
#define getFV(str,fld,buf)             getFieldValue2(str,fld,AVStr(buf),sizeof(buf))
#define OPgetFV(spc,pre,fld,buf)  OPgetFieldValue(spc,pre,fld,AVStr(buf),sizeof(buf))
#define FTOCL_FIELD	"X-Request"

/*
 * ARGUMENTS
 *
 *	in	 input
 *	out	 output
 *	conninfo information about the client/server connection
 *	convspec specification of conversion
 *
 * RETURN value
 *
 *	-1 error
 *	 0 no translation
 *	 1 translated
 */
static int http_conv(DGC *ctx,FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec),PCStr(clproto),PVStr(statline),PVStr(head),int withbody);
int non_http_conv(DGC *ctx,FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec),PCStr(clproto));
void filter_msgs(DGC *ctx,int isresp,PCStr(clproto),FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec));

/*
 * read RFC822 header without buffering.
 */
static char *readHeader(FILE *in){
	int pch,ch;
	CStr(buf,MAX_MIMEHEAD);
	refQStr(bp,buf);
	char chb[1];
	char *test;

	pch = '\n';
	test = getenv("WIN_CFI_TEST");
	for(;;){
		if( test || 0 < ready_cc(in) ){
			if( (ch = getc(in)) == EOF )
				break;
		}else{
			if( read(fileno(in),chb,1) < 1 )
				break;
			ch = chb[0];
		}
		setVStrPtrInc(bp,ch);
		if( ch == '\n' && pch == '\n' )
			break;
		if( ch != '\r' )
			pch = ch;
	}
	setVStrPtrInc(bp,0);
	if( test ){
		sv1log("##CFI readHeader() -- isreg=%d ready_cc=%d\n",
			file_isreg(fileno(in)),ready_cc(in));
	}
	return stralloc(buf);
}

int cfi(DGC *ctx,int isresp,FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec))
{	CStr(statline,1024);
	defQStr(head); /*alloc*/
	FILE *tmp;
	CStr(clproto,64);
	int withhead;
	int withbody;
	int rcode;

	if( getFV(conninfo,"Client-Protocol",clproto) == 0 )
		strcpy(clproto,"http");

sv1log("## CFI/%s ##\n",clproto);

	if( strcaseeq(clproto,"nntp")
	 || strcaseeq(clproto,"smtp")
	 || strcaseeq(clproto,"pop") )
	{
		filter_msgs(ctx,isresp,clproto,in,out,conninfo,convspec);
		return 0;
	}

	/*
	if(!strcaseeq(clproto,"http") ){
	*/
	if( !strncaseeq(clproto,"http",4) ){
		if( non_http_conv(ctx,in,out,conninfo,convspec,clproto) ){
			sv1log("## NON-MIME-RELAY\n");
			return 1;
		}else{
			sv1log("## SIMPLE-RELAY\n");
			simple_relayf(in,out);
			return 0;
		}
	}

	/*
	 *	HTTP
	 */
	if( isWindows() ){
		/* suppress buffering HTTP body to let systemFilter() work... */
		setbuf(in,NULL);
	}
	withhead = 1;
	withbody = 1;
	if( isresp ){
		/*
		 *	Pass through non-HTTP stream
		 */

	    /* 9.6.3-pre1 for test */ {
		/* should use PollIns(in,out) to detect disconn. of out */
		int ifd = fileno(in);
		int ofd = fileno(out);
		int ni;
		for( ni = 0; ni < 20; ni++ ){
			if( 0 < fPollIn(in,3*1000) )
				break;
			porting_dbg("--CFI timeout? (%d/%d/%d,%d/%d/%d)",
				SocketOf(ifd),ifd,IsAlive(ifd),
				SocketOf(ofd),ofd,IsAlive(ofd)
			);
			if( file_isSOCKET(ifd) && !IsAlive(ifd) ){
				_exit(-1);
			}
			if( file_isSOCKET(ofd) && !IsAlive(ofd) ){
				_exit(-1);
			}
		}
		/*
		if( fPollIn(in,1000) <= 0 ){
			_exit(-1);
		}
		*/
	    }

		if( fPollIn(in,0) < 0 )
			exit(-1);
		if( fread(statline,1,5,in) <= 0 )
			return -1;

		if( strncmp(statline,"HTTP/",5) != 0 ){
			IGNRETP write(fileno(out),statline,5);
			simple_relayf(in,out);
			return 0;
		}
		/*
		 *	Read status line and response header
		 */
		if( Xfgets(DVStr(statline,5),sizeof(statline)-5,in) == NULL )
			return -1;

		if( sscanf(statline,"HTTP/%*s %d",&rcode) )
			if( rcode == 304 || rcode == 204 || rcode/100 == 1 ) 
				withbody = 0;
	}else{
		fgets(statline,sizeof(statline),in);
		if( strncmp(statline,"POST",4) != 0
		 && strncmp(statline,"PUT", 3) != 0 )
			withbody = 0;
		if( strstr(statline,"HTTP/") == NULL ){
			withhead = 0;
			withbody = 0;
		}
	}
	if( withhead ){
		if( isWindows() ){
			head = readHeader(in);
		}else
		head = RFC822_readHeader(in,0);
		if( isresp ){
			CStr(req,4096);
			if( getFV(head,"X-Request",req) )
				if( strncmp(req,"HEAD",4) == 0 )
					withbody = 0;
		}
	}else	head = stralloc("");
	if( isWindows() ){
		int ch = EOF;
		/* restart buffering ... */
		if( ready_cc(in) ){
			ch = getc(in);
		}
		in = fdopen(fileno(in),"r");
		if( ch != EOF ){
			ungetc(ch,in);
		}
	}
	setQStr(head,(char*)realloc((char*)head,
strlen(head)+2048),
strlen(head)+2048); /* make space for rewriting */

	/*
	 *	pass through if not to be filterd
	 */
	if( http_conv(ctx,in,out,conninfo,convspec,clproto,AVStr(statline),AVStr(head),withbody) == 0 ){
		fputs(statline,out);
		removeFields(AVStr(head),FTOCL_FIELD,1);
		fputs(head,out);
		simple_relayf(in,out);
		return 0;
	}
	return 1;
}

#define IsHttpResp(stat)	strneq(stat,"HTTP/",5)
#define IsHttpReqWithBody(req) (strneq(req,"POST ",5) || strneq(req,"PUT ",4))

/*
 * matching with CGI environment as:
 *   REQUEST_METHOD: POST
 *   SERVER_NAME: xxx.yyy
 *   PATH_INFO: /path/of/dir/
 */
static int isCGIENV(PCStr(name)){
	const char *np;
	char ch;
	int nus = 0;
	for( np = name; ch = *np; np++ ){
		if( ch == '_' ) nus++; else
		if( !isupper(ch) )
			return 0;
	}
	return nus;
}
static int matchEnviron(PCStr(spec)){
	const char *sp;
	char sc;
	const char *env;
	CStr(name,128);
	CStr(body,1024);

	for( sp = spec; sc = *sp; ){
		fieldScan(sp,name,body);
		if( 'A' <= name[0] && name[0] <= 'Z' )
		if( 'A' <= name[1] && name[1] <= 'Z' )
		if( isCGIENV(name) )
		{
			env = getenv(name);
			if( env == 0 )
				env = "";
			if( matchFields(spec,name,env) == 0 )
				return 0;
		}
		if( (sp = strchr(sp,'\n')) == 0 )
			break;
		sp++;
	}
	return 1;
}

/*
const char *searchSpec(PCStr(conninfo),PCStr(specs),PCStr(statline),PCStr(head))
*/
const char *CFI_searchSpec(PCStr(conninfo),PCStr(specs),PCStr(statline),PCStr(head),int silent)
{	CStr(ictype,1024);
	CStr(iagent,1024);
	CStr(iserver,1024);
	CStr(iencode,1024);
	CStr(request,2048);
	CStr(imethod,256);
	CStr(iurl,2048);
	CStr(iver,256);
	CStr(from,256);
	CStr(orequest,2048);
	CStr(iomethod,32);
	CStr(iourl,2048);
	CStr(rver,256);
	CStr(rstat,256);
	CStr(rcode,32);
	const char *dp;
	CStr(clhost,256);
	CStr(svhost,256);
	CStr(clproto,256);
	CStr(svproto,256);
	int top;
	const char *spec1;
	const char *np;
	const char *delp;
	char delc;

	orequest[0] = iourl[0] = 0;
	getFV(head,"X-Request-Original",orequest);
	dp = wordScan(orequest,iomethod);
	dp = wordScan(dp,iourl);

	request[0] = 0;
	if( !IsHttpResp(statline) )
		lineScan(statline,request);
	else
	getFV(head,"X-Request",request);
	dp = wordScan(request,imethod);
	dp = wordScan(dp,iurl);
	dp = wordScan(dp,iver);

	getFV(head,"X-Request-User-Agent",iagent);
	if( iagent[0] == 0 )
		getFV(head,"User-Agent",iagent);

	if( IsHttpResp(statline) ){
		dp = wordScan(statline,rver);
		dp = wordScan(dp,rcode);
	}else{
		rver[0] = 0;
		rcode[0] = 0;
	}

	getFV(head,"Server",iserver);
	getFV(head,"Content-Type",ictype);
	getFV(head,"Content-Encoding",iencode);
	getFV(conninfo,"Client-Host",clhost);
	getFV(conninfo,"Client-Protocol",clproto);
	getFV(conninfo,"Server-Host",svhost);
	getFV(conninfo,"Server-Protocol",svproto);

	getFV(head,"From",from);
	
	spec1 = (char*)specs; /* should be "const" */
	delp = 0;
	for( spec1 = (char*)specs; *spec1; spec1 = np ){ /* should be "const" */
		top = 1;
		if( delp ){ /* restore the delimiter char. */ *(char*)delp = delc; } /**/
		for( np = (char*)spec1; *np; np++ ){
			if( top ){
				if( *np == '.' && (np[1]=='\r' || np[1] == '\n')
				 || *np == '-' && np[1]=='-' && (np[2]=='\r'||np[2]=='\n')
				){
					if( *np == '-' )
						np += 2;
					else	np += 1;

					while( np[1] == '\r' || np[1] == '\n' )
						np++;
					delp = np;
					delc = *delp;
					*(char*)np++ = 0;
					break;
				}
			}
			top = (*np == '\n');
		}

		while( isspace(*spec1) )
			spec1++;
		if( *spec1 == 0 )
			continue;

		if( !silent )
		sv1vlog("////////////////////////////\n%s\n",spec1);

		if( !matchFields(spec1,"User-Agent",iagent) ) continue;
		if( !matchFields(spec1,"Server",iserver) ) continue;
		if( !matchFields(spec1,"Content-Type",ictype) ) continue;
		if( !matchFields(spec1,"Content-Encoding",iencode) ) continue;
		if( !matchFields(spec1,"Req-Method",imethod) ) continue;
		if( !matchFields(spec1,"Req-Url",iurl) ) continue;
		if( !matchFields(spec1,"Req-Version",iver) ) continue;
		if( !matchFields(spec1,"Req-Url-Orig",iourl) ) continue;

		if( !matchFields(spec1,"X-Request",request) ) continue;
		if( !matchFields(spec1,"X-Request-Method",imethod) ) continue;
		if( !matchFields(spec1,"X-Request-URL",iurl) ) continue;
		if( !matchFields(spec1,"X-Request-Ver",iver) ) continue;
		if( !matchFields(spec1,"X-Request-URL-Orig",iourl) ) continue;

		if( !matchFields(spec1,"Res-Version",rver) ) continue;
		if( !matchFields(spec1,"Res-Status",rstat) ) continue;

		if( !matchFields(spec1,"X-Status",rstat) ) continue;
		if( !matchFields(spec1,"X-Status-Ver",rver) ) continue;
		if( !matchFields(spec1,"X-Status-Code",rcode) ) continue;

		if( !matchFields(spec1,"Client-Host",clhost) ) continue;
		if( !matchFields(spec1,"Client-Protocol",clproto) ) continue;
		if( !matchFields(spec1,"Server-Host",svhost) ) continue;
		if( !matchFields(spec1,"Server-Protocol",svproto) ) continue;
		if( !matchFields(spec1,"From",from) ) continue;

		if( !matchEnviron(spec1) ) continue;

		if( !silent )
		sv1vlog("///////// MATCHED //////////\n");
		if( delp ){
			const char *sp1;
			sp1 = spec1;
			/* skip the heading in the first alternative */
			{
				if( strneq(sp1,"#!cfi",5) )
					sp1 += 5;
				while( isspace(*sp1) )
					sp1++;
			}
			spec1 = stralloc(sp1);
			/*
			spec1 = stralloc(spec1);
			*/
		}
		if( delp ){ /* restore the delimiter char. */ *(char*)delp = delc; } /**/
		return spec1;
	}
	return NULL;
}
#define searchSpec(ci,sp,st,head)	CFI_searchSpec(ci,sp,st,head,0)

static const char *OPgetFieldValue(PCStr(spec),PCStr(prefix),PCStr(fname),PVStr(value),int size)
{	const char *vp;
	CStr(field,256);

	sprintf(field,"%s/%s",prefix,fname);
	if( vp = getFieldValue(spec,field,value,size) )
		return vp;

	sprintf(field,"%s-%s",prefix,fname); /* obsolete ... */
	if( vp = getFieldValue(spec,field,value,size) )
		return vp;

	return NULL;
}

static void substitute(FILE *fp,PCStr(conninfo),PCStr(spec),PCStr(ftype),PCStr(fname),PCStr(statline),PCStr(head))
{	CStr(fvalue,1024);
	const char *sp;
	char sc;
	const char *hp;
	CStr(hname,1024);
	CStr(hvalue,1024);
	CStr(tmp,1024);

	OPgetFV(spec,ftype,fname,fvalue);
	for( sp = fvalue; sc = *sp; sp++ ){
		if( sc == '#' ){
			while( sp[1] && sp[1] != '\n' )
				sp++;
			continue;
		}else
		if( sc == '$' && sp[1] == '{' ){
			Xsscanf(sp,"${%[^}]",AVStr(hname));
			if( sp[2+strlen(hname)] == '}' ){
				if( strcasecmp(hname,"head") == 0 )
					fputs(head,fp);
				else
				if( strncasecmp(hname,"icon.",5) == 0 ){
					getFV(conninfo,"Client-IF-Host",tmp);
					fprintf(fp,"//%s/-/builtin/icons/ysato/%s",tmp,hname+5);
				}else
				if( strcasecmp(hname,"Req-Url-Orig") == 0 ){
					const char *url;
					const char *dp;

					getFV(head,"X-Request-Original",hvalue);
					url = tmp;
					dp = wordScan(hvalue,tmp);
					dp = wordScan(dp,tmp);
					if( strncmp(url,"/-_-",4) == 0 )
						url += 4;
					fputs(url,fp);
				}else
				if( getFV(conninfo,hname,hvalue) ){
					fputs(hvalue,fp);
				}else
				if( getFV(head,hname,hvalue) )
					fputs(hvalue,fp);
				else{
					fputc(sc,fp);
					continue;
				}
				sp += 2 + strlen(hname);
				continue;
			}
		}
		fputc(sc,fp);
	}
	if( *fvalue )
		fputs("\r\n\r\n",fp);
}

/*
 * read a messge to its logical end
 */
static int HTTP_getBody(PCStr(statline),PCStr(head),FILE *in,FILE *out)
{	CStr(cleng,128);
	int leng,rcc,ch,timeout;

	if( strncmp(statline,"POST ",5) != 0 )
		return 0;

	leng = 0;
	if( getFV(head,"Content-Length",cleng) )
		leng = atoi(cleng);

	ch = 0;
	rcc = 0;
	timeout = 3*1000;
	while( 0 < fPollIn(in,timeout) ){
		ch = getc(in);
		if( ch == EOF )
			break;
		putc(ch,out);
		rcc++;
		if( leng <= rcc )
			timeout = 100;
	}

	sv1log("## CFI-getBody[%d/%d] EOF=0x%X\n",rcc,leng,ch&0xFF);
	fflush(out);
	fseek(out,0,0);
	return 1;
}
void removeVaryCE(PVStr(head))
{	CStr(vary,64);

	if( getFieldValue2(head,"Vary",AVStr(vary),sizeof(vary)) ){
		if( strcaseeq(vary,"Accept-Encoding") )
			removeFields(AVStr(head),"Vary",0);
	}
}
void System(DGC *ctx,PCStr(command),FILE *in,FILE *out);
static int http_conv(DGC *ctx,FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec),PCStr(clproto),PVStr(statline),xPVStr(head),int withbody)
{	const char *spec;
	CStr(octype,1024);
	CStr(ochset,256);
	CStr(oetype,256);
	CStr(ostatus,256);
	CStr(oheader,1024);
	CStr(prefix,1024);
	CStr(postfix,1024);
	CStr(filter,1024);
	CStr(cgi,1024);
	FILE *intmp,*tmp;
	const char *xhead;
	int bodyoff;
	const char *ohead;
	const char *nhead;
	const char *savhead;
	CStr(enc,64);

	spec = searchSpec(conninfo,convspec,statline,head); /* should be "const" */
	if( spec == NULL )
	{
		/* seems never happen because spec includes the #!cfi line */
		return 0;
	}

	savhead = stralloc(head);

	/*
	 *	Rewrite Content-Type field
	 */
	if( OPgetFV(spec,"Output","Content-Type",octype) )
		replaceFieldValue(AVStr(head),"Content-Type",octype);

	if( OPgetFV(spec,"Output","Charset",ochset) )
		replace_charset(AVStr(head),ochset);

	if( OPgetFV(spec,"Output","Content-Encoding",oetype) )
		replaceFieldValue(AVStr(head),"Content-Encoding",oetype);

	if( strncmp(statline,"HTTP/",5) == 0 ){
		int code;
		CStr(ver,32);
		CStr(xstat,1024);
		strcpy(xstat,"X-Status: ");
		linescanX(statline,TVStr(xstat),sizeof(xstat));
		strcat(xstat,"\r\n");
		RFC822_addHeaderField(AVStr(head),xstat);

		wordScan(statline,ver);
		sscanf(statline,"%*s %d",&code);
		sprintf(xstat,"X-Status-Ver: %s\r\n",ver);
		RFC822_addHeaderField(AVStr(head),xstat);
		sprintf(xstat,"X-Status-Code: %d\r\n",code);
		RFC822_addHeaderField(AVStr(head),xstat);
	}

	filterFields(spec,AVStr(head));

	if( !IsHttpResp(statline) && IsHttpReqWithBody(statline) ){
		FILE *sin = in;
		in = TMPFILE("Request-Body");
		HTTP_getBody(statline,head,sin,in);
		fclose(sin);
	}
	if( getFieldValue2(head,"Content-Encoding",AVStr(enc),sizeof(enc)) ){
		FILE *sin = in;
		in = Gunzip(enc,in);
		if( in != sin ){
			removeFields(AVStr(head),"Content-Encoding",0);
			removeVaryCE(AVStr(head));
		}
	}

	tmp = TMPFILE("CFI-CONV");

	ohead = nhead = head;
	if( getFV(spec,"Header/Filter",filter)
	 || getFV(spec,"Header-Filter",filter)
	){
		FILE *htmp;
		int nhsize;
		CStr(line,1024);
		const char *crlf;
		CStr(crlfb,4);

		htmp = TMPFILE("CFI-Header/Filter");

		if( strncmp(statline,"HTTP/",5) == 0 )
			fprintf(htmp,"Status-Line: %s",statline);
		else
		if( statline[0] && strstr(statline,"HTTP/") ){
			fprintf(htmp,"Request-Line: %s",statline);
			syslog_DEBUG("Request-Line: %s",statline);
		}

		fputs(head,htmp); fflush(htmp); fseek(htmp,0,0);
		System(ctx,filter,htmp,tmp);
		fclose(htmp);
		fflush(tmp); fseek(tmp,0,0);
		nhsize = file_size(fileno(tmp));
		nhead = (char*)malloc(nhsize+2);
		IGNRETP fread((char*)nhead,1,nhsize,tmp); /**/
		((char*)nhead)[nhsize] = 0;
		fseek(tmp,0,0);
		Ftruncate(tmp,0,0);
		setPStr(head,(char*)nhead,nhsize+2);

		if( getFV(head,"Status-Line",line)
		 || getFV(head,"Request-Line",line) ){
			removeFields(AVStr(head),"Request-Line",0);
			removeFields(AVStr(head),"Status-Line",0);
			if( strstr(line,"HTTP/") ){
				if( crlf = strpbrk(statline,"\r\n") )
					strncpy(crlfb,crlf,sizeof(crlfb));
				strcpy(statline,line);
				if( crlf )
					strcat(statline,crlfb);
				syslog_ERROR(">>start-line: %s",statline);
			}
		}
	}

	intmp = NULL; 
	xhead = NULL;

	if( getFV(spec,"CGI",cgi) ){
		CStr(oreq,4096);
		CStr(req,4096);

		intmp = TMPFILE("CFI-CGI");
		getFV(head,"X-Request-Original",oreq);
		getFV(head,"X-Request",req);

		if( !IsHttpResp(statline) && !IsHttpReqWithBody(statline) )
			in = TMPFILE("Empty-Request-Body\n");

		system_CGI(ctx,conninfo,oreq,req,AVStr(head),cgi,in,intmp);
		fseek(intmp,0,0);
		if( IsHttpResp(statline) ){
			fgets(statline,1024,intmp);
		}else{
			CStr(stat,1024);
			fgets(stat,sizeof(stat),intmp);
			/* it should be the rewritten Request line ... */
		}
		xhead = RFC822_readHeader(intmp,0);
		setPStr(head,(char*)xhead,strlen(xhead)+1);
		in = intmp;
	}
	if( getFV(spec,"SSI",cgi) ){
		intmp = TMPFILE("CFI-SSI");
/*
		system_SSI(conninfo,in,intmp);
*/
		in = intmp;
	}

	if( OPgetFV(spec,"Output","Status",ostatus) )
		fprintf(tmp,"%s %s\r\n","HTTP/1.0",ostatus);
	else	fputs(statline,tmp);

	if( getFV(spec,"Output-Header",oheader) ){
		CStr(buf,1024);
		genheadf(oheader,AVStr(buf),sizeof(buf));
		fputs(buf,tmp);
		/*
		fputs(oheader,tmp);
		*/
		fputs("\r\n",tmp);
	}

	removeFields(AVStr(head),FTOCL_FIELD,1);
	removeFields(AVStr(head),"X-Status",1);
	if( *savhead == 0 && withbody ){
		/* v9.9.9 fix-140609c maybe "body" (for NNTP) */
	}else{
	fputs(head,tmp);
	}
	fflush(tmp);
	bodyoff = ftell(tmp);

	/*
	 *	Translate
	 */
	if( withbody ){
		int respTHRU = 0;
		FILE *stmp = tmp;
		CStr(opts,128);
		if( getFV(spec,"Options",opts) )
		if( isinListX(opts,"NoPerfection","cw") ){
			respTHRU = 1;
			sv1log("---- in NoPerfection BEGIN\n");
			Ftruncate(tmp,bodyoff,0);
			fseek(tmp,0,0);
			copyfile1(tmp,out);
			Ftruncate(tmp,0,0);
			tmp = out;
			/* if with Message-Filter, it must be invoked
			 * as a filter process connected with this process
			 * getting input from a pipe.
			 * On Windows, the output to socket should be done
			 * by DeleGate. So, this part for "withbody" should
			 * be spawned as a pipelined process.
			 */
		}

		if( getFV(spec,"Output-Prefix",prefix) )
			substitute(tmp,conninfo,spec,"Output","Prefix",statline,savhead);

		if( getFV(spec,"Filter",filter)
		 || getFV(spec,"Body-Filter",filter) )
		{	FILE *inbody;

			inbody = TMPFILE("CFI-MESSAGE-BODY");
			if( HTTP_getBody(statline,head,in,inbody) ){
				fclose(in);
				in = inbody;
			}
			System(ctx,filter,in,tmp);
		}
		else{
			if( HTTP_getBody(statline,head,in,tmp) ){
			}else{
				copyfile1(in,tmp);
			}
		}

		if( getFV(spec,"Output-Postfix",postfix) )
			substitute(tmp,conninfo,spec,"Output","Postfix",statline,savhead);
		if( respTHRU ){
			tmp = stmp;
			fflush(out);
			sv1log("---- in NoPerfection END\n");
			truncVStr(savhead);
		}
	}
	if( getFV(spec,"MIME-Filter",filter) ){
		FILE *inmsg;
		inmsg = TMPFILE("CFI-MIME-MESSAGE");
		fseek(tmp,0,0);
		if( statline[0] ){
			CStr(tmpstat,1024);
			if( fgets(tmpstat,sizeof(tmpstat),tmp) != NULL ){
				fputs(tmpstat,inmsg);
			}
		}
		System(ctx,filter,tmp,inmsg);
		fclose(tmp);
		tmp = inmsg;
	}
	if( getFV(spec,"Message-Filter",filter) ){
		FILE *inmsg;
		inmsg = TMPFILE("CFI-MESSAGE");
		fseek(tmp,0,0);
		System(ctx,filter,tmp,inmsg);
		fclose(tmp);
		tmp = inmsg;
	}

/*
	fflush(tmp);
	fseek(tmp,bodyoff,0);
	if( fgets(statline,SIZEOF(statline),tmp) != NULL ){
		if( strncmp(statline,"CFI/",4) == 0 ){
			const char *head;

			sv1log("CFI-CONTROL: %s\n",statline);
			if( head = RFC822_readHeader(tmp,0) ){
				sv1log("CFI-CONTROL: %s\n",head);
				free((char*)head);
			}
		}
	}
*/

	fseek(tmp,0,0);
	if( *savhead && withbody ) /* both head & body exist */
		HTTP_putMIMEmsg(NULL,tmp,out);
	else	copyfile1(tmp,out);
	fflush(out);
	fclose(tmp);
	if( intmp ){
		fclose(intmp);
		free((char*)xhead);
	}
	free((char*)savhead);
	return 1;
}

int non_http_conv(DGC *ctx,FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec),PCStr(clproto))
{	const char *spec;
	CStr(filter,1024);

	spec = searchSpec(conninfo,convspec,"",conninfo);
	if( spec == NULL )
		return 0;

	if( getFV(spec,"Filter",filter)
	 || getFV(spec,"Message-Filter",filter) )
		System(ctx,filter,in,out);
	else	simple_relayf(in,out);
	return 1;
}

void System(DGC *ctx,PCStr(command),FILE *in,FILE *out)
{
	if( 0 <= builtin_filter(ctx,NULL,command,in,out,NULL,NULL) )
		return;

	systemFilter(command,in,out);
}

int putMESSAGEline(FILE *fp,PCStr(type),PCStr(comment))
{
	return fprintf(fp,"--MESSAGE/%s %s\r\n",type,comment);
}
int getMESSAGEline(PCStr(line),PVStr(type),PVStr(comment))
{
	if( strncmp(line,"--MESSAGE/",10) == 0 )
		return Xsscanf(line,"--MESSAGE/%s %[^\r\n]",AVStr(type),AVStr(comment));
	else	return 0;
}

/*    FILTER_MSGS
 *	Filter a series of mesages which start with a line headed by
 *	  "--MESSAGE/line"
 *	  "--MESSAGE/head"
 *	  "--MESSAGE/body"
 *	  "--MESSAGE/mime"
 *	and end with a line
 *	  "." CRLF
 */

void filter_msgs(DGC *ctx,int isresp,PCStr(clproto),FILE *in,FILE *out,PCStr(conninfo),PCStr(convspec))
{	FILE *tmp;
	CStr(msgstat,1024);
	int nostat;
	CStr(statline,1024);
	CStr(type,128);
	CStr(comment,128);
	UTag Uhead; /* v9.9.9 fix-140605b */
	const char *head; /**/
	int body;
	const char *eoh;
	CStr(eohb,1024);
	CStr(endline,1024);

	tmp = TMPFILE("CFI-MESSAGES");

sv1log("## CFI/MSGS ##\n");

	for(;;){
		if( fPollIn(in,10) == 0 )
			fflush(out);
		if( fgets(msgstat,sizeof(msgstat),in) == NULL )
			break;

sv1log("CFI/MSGS ---- %s",msgstat);

		/*
		 *	out of scoope of the filter
		 */
		if( getMESSAGEline(msgstat,AVStr(type),AVStr(comment)) == 0 ){
			fputs(msgstat,out);
			continue;
		}

/*
 {
	CStr(filter,1024);
	if( getFV(convspec,"Control-Filter",filter) ){
	}
 }
*/

		/*
		 *	only status line
		 */
		if( strcmp(type,"line") == 0 ){
			fgets(statline,sizeof(statline),in);
			fputs(statline,out);
			continue;
		}

		/*
		 *	status line and [head][body].CRLF
		 */
		nostat = 0;
		/* if( !isresp ) */
		if( strcaseeq(clproto,"nntp") ){
			if( strncasecmp(comment,"POST",4) == 0 )
				nostat = 1;
		}else
		if( strcaseeq(clproto,"smtp") ){
			if( strncasecmp(comment,"DATA",4) == 0 )
				nostat = 1;
		}
		if( nostat )
			statline[0] = 0;
		else	fgets(statline,sizeof(statline),in);

		if( strcmp(type,"head") == 0 ){
			Uhead = RFC822_readHeaderU(in,1);
			body = 0;
		}else
		if( strcmp(type,"mime") == 0 ){
			Uhead = RFC822_readHeaderU(in,1);
			body = 1;
		}else
		if( strcmp(type,"body") == 0 ){
			/* v9.9.9 fix-140609b */
			Uhead = UTalloc(SB_CONN,MAX_MIMEHEAD,1);
			setVStrEnd(Uhead.ut_addr,0);
			body = 1;
		}else{
sv1log("CFI/MSG ---- unknown type: %s\n",type);
			exit(1);
		}
		head = Uhead.ut_addr;
		eoh = strSeekEOH(head);
		if( *eoh == '.' ){
			strcpy(eohb,eoh);
			truncVStr(eoh);
		}else	eohb[0] = 0;

		endline[0] = 0;
		fseek(tmp,0,0);
		if( body ){
			relayRESPBODY(in,tmp,AVStr(endline),sizeof(endline));
			fflush(tmp);
			/*
			Ftruncate(tmp,0,2);
			*/
			Ftruncate(tmp,0,1);
			fseek(tmp,0,0);
		}else{
			Ftruncate(tmp,0,0);
		}

		fflush(out); /* fix-140609d if buffered output remain, it
			* will be inherited by System()->system()->fork()
			* then flushed in the child process (maybe before
			* exec()) to make duplicated output.
			*/

		if( http_conv(ctx,tmp,out,conninfo,convspec,clproto,
			AVStr(statline),AVStr(Uhead.ut_addr),body) == 0 ){
			fputs(statline,out);
			fputs(head,out);
			simple_relayf(tmp,out);
		}
		/*
		 * this eohb+endline (maybe ".CRLF") must be suppressed if
		 * the status or command is rewritten not to include the body
		 * to be ended with ".CRLF"
		 * also the body filtered by the external command should be
		 * checked not to include such line.
		 * a possible solution is passing the endline to the filter
		 * command...
		 */
		fputs(eohb,out);
		fputs(endline,out);

		UTfree(&Uhead);
	}
}
