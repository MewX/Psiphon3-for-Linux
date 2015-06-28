/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	httplog.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950210	extracted from http.c
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "delegate.h"
#include "ystring.h"
#include "http.h"

const char *LOG_buffer(Logfile *logF);
const char *LOG_format(Logfile *logF);
Logfile *HTTP_PROTOLOG();
#define HTTPLOG	HTTP_PROTOLOG()
void LOG_write(Logfile *LogF,PCStr(str),int leng);
void clear_publiclog();
void publiclog(PCStr(sel),PCStr(fmt),...);
int CountUp(DGC*ctx,PCStr(proto),PCStr(host),int port,PCStr(upath));

void logurl_escapeX(PCStr(src),PVStr(dst),int siz);
void url_relative(PVStr(relurl),PCStr(absurl),PCStr(baseurl));
void http_publiclog(Connection *Conn,int rcode,PCStr(ctype),int rsize,int mtime,PCStr(request));

extern int LOG_center;
extern int HTTP_CKA_MAXREQ;

void http_logplus(Connection *Conn,char type)
{	Logfile *log;
	const char *buff; /* not "const" but fixed */
	int len;

	if( type == 0 )
		return;

	if( (log = HTTPLOG) == NULL )
		return;

	if( buff = LOG_buffer(log) ){
		len = strlen(buff);
		if( 2 < len && buff[len-1] == '\n' && buff[len-2] == '+' )
			((char*)buff)[len-2] = type;
	}
}

void http_log(Connection *Conn,PCStr(proto),PCStr(server),int iport,PCStr(req),int rcode,PCStr(ctype),FileSize rsize,int mtime,double ctime,double dtime)
{	Logfile *log;
	MemFile MemF;
	MemFile *SMemF = &MemF;
	CStr(clientlog,256);
	CStr(hostport,MaxHostNameLen);
	CStr(request,4*1024);
	const char *dp;
	CStr(com,1024);
	CStr(arg,4*1024);
	CStr(buff,8*1024);
	const char *fmt;
	const char *fp;
	char fc;
	CStr(fmtb,256);
	CStr(tmp,256);
	char cstat;

	if( lNOPROTOLOG() )
		return;

	if( 0 <= find_CMAP(Conn,"NOLOG",AVStr(buff)) ){
		sprintf(arg,"%d/%s",rcode,ctype);
		if( strmatch_list(arg,buff,"",NULL,NULL) )
			return;
	}

	if( (log = HTTPLOG) == NULL )
		return;
/*
 * logging for openFilter should be given up here...
 */

	fmt = LOG_format(log);
	if( fmt == NULL || strchr(fmt,'%') == NULL )
		fmt = "%C %D";

	makeClientLog(Conn,AVStr(clientlog));

	dp = wordScan(req,com);
	lineScan(dp,arg);

	str_sopen(SMemF,"http_log",request,sizeof(request),0,"w");
	str_sprintf(SMemF,"%s ",com);
	if( strcaseeq(com,"CONNECT") ){
		str_sprintf(SMemF,"%s://%s",proto,arg);
	}else
	if( isFullURL(arg) ){
		str_sprintf(SMemF,"%s",arg);
	}else
	if( rcode == 403 && strncmp(arg,"/-_-",3) == 0 ){
		str_sprintf(SMemF,"%s",arg);
	}else
	if( streq(proto,"file") || streq(server,"localhost") ){
		str_sprintf(SMemF,"%s",arg);
	}else{
		HostPort(AVStr(hostport),proto,server,iport);
		str_sprintf(SMemF,"%s://%s%s",proto,hostport,arg);
	}
	str_sputc(0,SMemF);
	if( strchr(request,'"') )
		strsubst(AVStr(request),"\"","%22");

	str_sopen(SMemF,"http_log",buff,sizeof(buff),0,"w");
	for( fp = fmt; fc = *fp; fp++ ){
		if( fc != '%' || fp[1] == 0 ){
			str_sputc(fc,SMemF);
			continue;
		}
		switch( fc = *++fp ){
		case '%': str_sputc('%',SMemF); break;
		case 'X':
			strcpy(tmp,fp+1);
			sprintf(fmtb,"X%%C \"%%r\" \"%%u\"%s",tmp);
			fp = fmtb;
			break;
		case 'c':
		case 'C':
		{	const char *form;
			CStr(date,128);
			int now,usec;

			now = Gettimeofday(&usec);
			if( fc == 'c' )
				form = TIMEFORM_HTTPDs;
			else	form = TIMEFORM_HTTPD;
			StrftimeLocal(AVStr(date),sizeof(date),form,now,usec);
			str_sprintf(SMemF,"%s [%s] \"%s\" %d %lld",clientlog,date,request,rcode,rsize);
			break;
		}
		case 'D':
			str_sprintf(SMemF,"%d*",Conn->sv_reusing);
			/*
			str_sprintf(SMemF,"%4.3f+%4.3f:%s%c",
			*/
			sprintf(tmp,"%4.3f+%4.3f:%s%c",
				ctime,dtime,
				httpStatX ? "R":"",
				httpStat ? httpStat:'-');
			str_sprintf(SMemF,"%s",tmp);
			if( 1 < HTTP_CKA_MAXREQ ){
				if( !ClntKeepAlive && RequestSerno == 0 )
					str_sprintf(SMemF,":0-");
				else	str_sprintf(SMemF,":%d+",RequestSerno);
				if( 0 < ServReqSerno )
					str_sprintf(SMemF,"%d",ServReqSerno);
			}
			break;

		case 'S':
			cstat = '?';
			if( ConnType     ) cstat = ConnType; else
			if( ServViaSocks ) cstat = 's'; else
			if( ServViaVSAP  ) cstat = 'v'; else
			if( ServViaCc    ) cstat = 'n'; else
			if( toMaster     ) cstat = 'm'; else
			if( toProxy      ) cstat = 'p'; else
			if( 0 <= ToS     ) cstat = 'd';
			str_sputc(cstat,SMemF);
			break;

		case 't':
			/* content-type */
			break;

		case 'r':
			HTTP_getRequestField(Conn,"Referer",AVStr(arg),sizeof(arg));
			if( strchr(arg,'"') ) strsubst(AVStr(arg),"\"","%22");
			str_sprintf(SMemF,"%s",arg);
			break;
		case 'u':
			HTTP_getRequestField(Conn,"User-Agent",AVStr(arg),sizeof(arg));
			if( strchr(arg,'"') ) strsubst(AVStr(arg),"\"","%22");
			str_sprintf(SMemF,"%s",arg);
			break;

		case 's':
			decrypt_opaque(ClientSession,AVStr(tmp));
			if( *tmp )
				str_sprintf(SMemF,"%s",tmp);
			else	str_sprintf(SMemF,"-",tmp);
			break;
		case 'A':
			if( CurEnv )
			if( fp[1] ){
				fc = *++fp;
				switch( fc ){
				  case 's':
				  case 'o':
					decrypt_opaque(REQ_AUTH.i_opaque,AVStr(tmp));
					if( *tmp )
						str_sprintf(SMemF,"%s",tmp);
					else	str_sprintf(SMemF,"-",tmp);
					break;
				  case 'n':
					str_sprintf(SMemF,"%s",REQ_AUTH.i_nonce);
					break;
				  case 'r':
					str_sprintf(SMemF,"%s",REQ_AUTH.i_realm);
					break;
				}
			}
			break;

		case '{':
			dp = wordscanY(fp+1,AVStr(tmp),sizeof(tmp),"^}");
			if( *dp == '}' ){
				fp = dp;
				HTTP_getRequestField(Conn,tmp,AVStr(arg),sizeof(arg));
				str_sprintf(SMemF,"%s",arg);
			}
			break;
		}
	}
	str_sputc('\n',SMemF);
	LOG_write(log,buff,str_stell(SMemF));

	if( 0 < LOG_center )
	if( 0 <= ToS || 0 < mtime )
		http_publiclog(Conn,rcode,ctype,rsize,mtime,request);
}

static int getReferer(Connection *Conn,PCStr(request),PCStr(url),PVStr(referer),PVStr(relurl))
{	const char *upath;

	setVStrEnd(relurl,0);
	setVStrEnd(referer,0);
/*if( HTTP_getRequestField(Conn,"Referer",AVStr(referer),ERR_sizeof(referer)) == 0 )*/
	if( HTTP_getRequestField(Conn,"Referer",AVStr(referer),1024) == 0 )
		return 0;

	if( upath = URL_toMyself(Conn,referer) ){
		/* strip http://myself/-_- */
		if( strncmp(upath,"/-_-",4) == 0 )
			strcpy(referer,upath+4);
	}
	if( strncmp(referer,"/-_-",4) == 0 )
		ovstrcpy((char*)referer,referer+4);

	url_relative(AVStr(relurl),referer,url);
	if( relurl[0] == 0 ) /* from the same server */
		strcpy(relurl,"=");
	else{
		CStr(rproto,256);
		CStr(rhostport,MaxHostNameLen);
		CStr(rhost,MaxHostNameLen);
		CStr(rlogmap,256);
		int rport;
		Connection ConnR;

		if( Xsscanf(relurl,"%[^:]://%[^/]",AVStr(rproto),AVStr(rhostport)) == 2 ){
			ConnR = *Conn;
			rport = scan_hostport(rproto,rhostport,AVStr(rhost));
			set_realserver(&ConnR,rproto,rhost,rport);
			find_CMAP(&ConnR,"sendlog",AVStr(rlogmap));
			Verbose("#### sendlog Referer map = [%s]\n",rlogmap);
			if( rlogmap[0] == 0 )
				strcpy(relurl,"-");
		}
	}
	return 1;
}

void http_publiclog(Connection *Conn,int rcode,PCStr(ctype),int rsize,int mtime,PCStr(request))
{	int code;
	CStr(url,4096);
	CStr(buf,4096);
	CStr(myhp,MaxHostNameLen);
	char proxytype;
	char statch;
	CStr(sdate,16);
	CStr(req,4096);
	const char *selector;
	CStr(logmap,1024);
	CStr(ctmajor,128);
	CStr(ctminor,128);
	CStr(sctype,32);
	CStr(referer,4096);
	CStr(relurl,4096);

	find_CMAP(Conn,"sendlog",AVStr(logmap));
	Verbose("#### sendlog map = [%s]\n",logmap);
	if( logmap[0] == 0 )
		return;

	code = (rcode % 1000) / 100;
	if( code == 2 || code == 3 ){
		selector = "xmit";
		wordScan(request,req);

		if( Xsscanf(ctype,"%[^/]/%s",AVStr(ctmajor),AVStr(ctminor)) == 2 )
			sprintf(sctype,"%c/%c",ctmajor[0],ctminor[0]);
		else	strcpy(sctype,"-/-");

		HTTP_originalURLx(Conn,AVStr(url),sizeof(url));
		Xstrcpy(DVStr(url,sizeof(url)-3-256),"\r\n");

		if( strncmp(url,"/-_-",4) == 0 ){
			proxytype = 'd';
			ovstrcpy(url,url+4);
		}else
		if( url[0] == '/' ){
			proxytype = '-';
			if( ImMaster )
				HostPort(AVStr(myhp),DST_PROTO,DST_HOST,DST_PORT);
			else	ClientIF_HP(Conn,AVStr(myhp));
			sprintf(buf,"http://%s%s",myhp,url);
			strcpy(url,buf);
		}else{
			proxytype = 'c';
		}
		statch = httpStat ? httpStat : '-';
		if( 0 < mtime )
			StrftimeGMT(AVStr(sdate),sizeof(sdate),TIMEFORM_YmdHMS,mtime,0);
		else	sprintf(sdate,"%012d",0);

		getReferer(Conn,request,url,AVStr(referer),AVStr(relurl));

		/*
		 * decode first, because it may be encoded in -_-URL case
		 */
		nonxalpha_unescape(url,AVStr(url),0);
		logurl_escapeX(url,AVStr(url),sizeof(url));

		clear_publiclog();
		publiclog("P","%s.%s %s \"%s %s\" %d %d %s %c%c \"%s\"\r\n",
			logmap,selector,sdate,
				req,url,rcode,rsize,
				sctype,proxytype,statch,relurl);
	}
}

void http_Log(Connection *Conn,int rcode,int rstat,PCStr(req),int size)
{	const char *proto;
	const char *host;
	int port;
	CStr(ctype,256);

	if( REAL_HOST[0] ){
		if( ToMyself && CLNT_PROTO[0] )
			proto = CLNT_PROTO;
		else	proto = REAL_PROTO;
		host = REAL_HOST;
		port = REAL_PORT;
	}else{
		if( CLNT_PROTO[0] )
			proto = CLNT_PROTO;
		else	proto = DFLT_PROTO;
		host = DFLT_HOST;
		port = DFLT_PORT;
	}
	httpStat = rstat;
	ctype[0] = 0;
	http_log(Conn,proto,host,port,req, rcode,ctype,size,0, 0.0,0.0);
}
