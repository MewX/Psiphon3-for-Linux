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
Program:	cgi.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960110	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include "ystring.h"
#include "delegate.h"
#include "fpoll.h"
#include "file.h"
#include "http.h"
#include "proc.h"
#include "log.h"
#include <ctype.h>
#include <errno.h>
#define MY_CGIVER	"1.1"

void closeOnExecServPorts(int set);
int scan_SHTML(Connection *Conn,FILE *tc,FILE *fc,FILE *fp,PCStr(req),PCStr(head),PCStr(vurl),PCStr(ourl),PCStr(path),PCStr(script),PCStr(expath));
FileSize file_copyTimeout(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary,int timeout);
char *fgetsLines(PVStr(line),int lsiz,FILE *in,int timeout);
char *fgetsLinesX(PVStr(line),int lsiz,FILE *in,int timeout,int *rccp,int *binp);

extern char **environ;
#if defined(__FreeBSD__)
#define safeputenv 1
#else
#define safeputenv (lMTSS_PUTENV()||tMTSS_PUTENV()) /* 9.9.4 MTSS force putenvs() "-Ete" */
#endif

#define getFieldValue(str,fld,buf,siz) getFieldValue2(str,fld,buf,siz)
#define getFV(str,fld,buf)             getFieldValue2(str,fld,AVStr(buf),sizeof(buf))


void addList(PVStr(list),int lsize,PCStr(elem))
{	refQStr(tp,list); /**/
	tp = strtail(list);

	if( list < tp ){
		linescanX(", ",AVStr(tp),lsize-(tp-list));
		tp += strlen(tp);
	}
	linescanX(elem,AVStr(tp),lsize-(tp-list));
}

static void cgi_head2env(PCStr(head),StrVec *Evp)
{	CStr(field,0x1000);
	CStr(accepts,2048);
	CStr(langs,256);
	const char *np;
	const char *fp;
	const char *vp; /* not "const" but fixed */

	accepts[0] = 0;
	langs[0] = 0;

	QStrncpy(field,head,sizeof(field)-2);
	strcat(field,"\r\n");
	fp = field;

	while( np = strpbrk(fp,"\r\n") ){
		truncVStr(np); np++;
		for( vp = fp; *vp; vp++ ){
			if( *vp == ' ' ){
				goto NEXTFIELD;
			}
			if( *vp == ':' ){
				truncVStr(vp); vp++;
				if( isspace(*vp) )
					vp++;
				break;
			}
			if( islower(*vp) )
				*(char*)vp = toupper(*vp); /**/
			else
			if( *vp == '-' )
				*(char*)vp = '_';
		}
		if( strcmp(fp,"ACCEPT_LANGUAGE") == 0 ){
			addList(AVStr(langs),sizeof(langs),vp);
		}else
		if( strcmp(fp,"ACCEPT") == 0 ){
			addList(AVStr(accepts),sizeof(accepts),vp);
		}else{
			SVaddEnvf(Evp,"HTTP_%s=%s",fp,vp);
		}
	NEXTFIELD:
		fp = np;
		while( *fp == '\r' || *fp == '\n' )
			fp++;
	}

	if( accepts[0] ){
		SVaddEnvf(Evp,"HTTP_ACCEPT=%s",accepts);
	}
	if( langs[0] ){
		SVaddEnvf(Evp,"HTTP_ACCEPT_LANGUAGE=%s",langs);
	}
}

static const char *cgienv;
int scan_CGIENV(Connection *Conn,PCStr(envlist))
{
	cgienv = StrAlloc(envlist);
	return 0;
}

void cgi_makeEnv(PCStr(conninfo),PCStr(req),PCStr(head),PCStr(vurl),PCStr(vpath),PCStr(datapath),PCStr(scripturl),PCStr(extrapath),int mac,const char *av[],StrVec *Evp)
{	const char *search;
	const char *dp;
	CStr(tmp,2048);
	int ac,ei;
	const char *es;
	const char *fp;
	const char *np;
	const char *vp;
	CStr(auth,1024);
	CStr(atype,128);
	CStr(auserpass,256);
	CStr(auser,256);
	CStr(method,128);
	const char *randenv;
	CStr(sv,MaxHostNameLen);

	randenv = 0;
	for( ei = 0; es = environ[ei]; ei++ ){
		if( strncmp(es,"RANDENV=",8) == 0 )
			randenv = es;
		else
		if( cgienv == NULL || strmatch_list(es,cgienv,"^=",NULL,NULL) ){
			if( Evp->sv_ecmax-1 <= Evp->sv_ec )
				syslog_ERROR("CGIENV OVERFLOW %d/%d\n",Evp->sv_ec,Evp->sv_ecmax);
			else	Evp->sv_ev[Evp->sv_ec++] = (char*)es;
		}
	}

	atype[0] = auser[0] = 0;
	if( getFV(head,"Authorization",auth) ){
		HTTP_decompAuth(auth,AVStr(atype),sizeof(atype),AVStr(auserpass),sizeof(auserpass));
		Xsscanf(auserpass,"%[^:]",AVStr(auser));
	}

	/* AUTH_TYPE */
	SVaddEnvf(Evp,"AUTH_TYPE=%s",atype);

	/* CONTENT_LENGTH */
	if( getFV(head,"Content-Length",tmp) == 0 )
		strcpy(tmp,"0");
	SVaddEnvf(Evp,"CONTENT_LENGTH=%d",atoi(tmp));

	/* CONTENT_TYPE */
	if( getFV(head,"Content-Type",tmp) == 0 )
		strcpy(tmp,"text/html");
	SVaddEnvf(Evp,"CONTENT_TYPE=%s",tmp);

	/* GATEWAY_INTERFACE */
	SVaddEnvf(Evp,"GATEWAY_INTERFACE=CGI/%s",MY_CGIVER);

	/* HTTP-* */
	cgi_head2env(head,Evp);

	/* PATH_INFO */
	es =
	SVaddEnvf(Evp,"PATH_INFO=%s",extrapath);
	if( es )
	if( search = strchr(es,'?') )
		truncVStr(search);

	/* PATH_TRANSLATED */
	SVaddEnvf(Evp,"PATH_TRANSLATED=%s",*extrapath?datapath:"");
	Verbose("PATH_TRANSLATED=%s\n",*extrapath?datapath:"");

	/* QUERY STRING */
	if( search = strchr(vpath,'?') ){
		truncVStr(search);
		search++;
	}
	SVaddEnvf(Evp,"QUERY_STRING=%s",search?search:"");

	/* REMOTE_ADDR */
	/* REMOTE_HOST */
	/* REMOTE_IDENT */
	/* REMOTE_USER */
	getFieldValue(conninfo,"Client-Addr",AVStr(tmp),sizeof(tmp));
	SVaddEnvf(Evp,"REMOTE_ADDR=%s",tmp);

	getFieldValue(conninfo,"Client-Host",AVStr(tmp),sizeof(tmp));
	SVaddEnvf(Evp,"REMOTE_HOST=%s",tmp);

	getFieldValue(conninfo,"Client-User-Ident",AVStr(tmp),sizeof(tmp));
	if( strcmp(tmp,"-") == 0 )
		tmp[0] = 0;
	SVaddEnvf(Evp,"REMOTE_IDENT=%s",tmp);

	SVaddEnvf(Evp,"REMOTE_USER=%s",auser);

	/* REQUEST_METHOD */
	wordScan(req,method);
	SVaddEnvf(Evp,"REQUEST_METHOD=%s",method);
	/* REQUEST_URL (extended for CFI) */
	SVaddEnvf(Evp,"REQUEST_URL=%s",vpath);
	SVaddEnvf(Evp,"REQUEST_URI=%s",vurl);

	/* SCRIPT_NAME */
	SVaddEnvf(Evp,"SCRIPT_NAME=%s",scripturl);

	/* SERVER_NAME */
	/* SERVER_PORT */
	/* SERVER_PROTOCOL */
	/* SERVER_SOFTWARE */
	{	CStr(svhp,MaxHostNameLen);
		CStr(svhost,MaxHostNameLen);
		int svport;

		svhost[0] = 0;
		if( getFV(head,"Host",svhp) ){
			svport = 80;
			Xsscanf(svhp,"%[^:]:%d",AVStr(svhost),&svport);
		}
		if( svhost[0] == 0 ){
			getFieldValue(conninfo,"Client-IF-Host",AVStr(svhp),sizeof(svhp));
			Xsscanf(svhp,"%[^:]:%d",AVStr(svhost),&svport);
			svport = scan_hostport("http",svhp,AVStr(svhost));
		}
		if( svhost[0] == 0 ){
			GetHostname(AVStr(svhost),sizeof(svhost));
			svport = SERVER_PORT();
		}

		SVaddEnvf(Evp,"SERVER_NAME=%s",svhost);
		SVaddEnvf(Evp,"SERVER_PORT=%d",svport);
		SVaddEnvf(Evp,"SERVER_PROTOCOL=HTTP/%s",MY_HTTPVER);
		SVaddEnvf(Evp,"SERVER_SOFTWARE=DeleGate/%s",
				DELEGATE_ver());
	}

	/* 9.2.4 to be used in SSLway for session cache ...
	 * a Cookie for SSLsession should be used.
	 */
	if( getFieldValue(conninfo,"Server-Host",AVStr(sv),sizeof(sv)) ){
		const char *sva;
		if( sva = gethostaddr(sv) )
		SVaddEnvf(Evp,"SERVER_ADDR=%s",sva);
		SVaddEnvf(Evp,"SERVER_HOST=%s",sv);
	}

	if( randenv )
		Evp->sv_ev[Evp->sv_ec++] = (char*)randenv;
	Evp->sv_ev[Evp->sv_ec] = 0;

	if( av != NULL ){
		ac = 0;
		if( search ){
			fp = SPrintf(&Evp->sv_MemF,"%s+",search);
			while( np = strchr(fp,'+') ){
				if( mac-1 <= ac ){
					break;
				}
				av[ac++] = (char*)fp;
				truncVStr(np);
				fp = np + 1;
			}
		}
		av[ac] = 0;
	}
/*
for( ei = 0; ei < ac; ei++ ) fprintf(stderr,"#### ARG[%2d] %s\n",ei,av[ei]);
for( ei = 0; ei < ec; ei++ ) fprintf(stderr,"#### ENV[%2d] %s\n",ei,ev[ei]);
*/
}

int getParam(PVStr(params),PCStr(name),PVStr(val),int siz,int del);
int CCX_lockoutcode(CCXP ccx);
int CCX_setindflt(CCXP ccx,PCStr(from));
/*
void HTCCX_setindflt(Connection *Conn,PVStr(ctype)){
	IStr(cset,128);
	if( CCXactive(CCX_TOCL) ){
		getParam(AVStr(ctype),"charset",AVStr(cset),sizeof(cset),0);
		if( cset[0] && !strcaseeq(cset,"ISO-2022-JP") ){
			CCX_setindflt(CCX_TOCL,cset);
		}
	}
}
*/
static void setcharcode(Connection *Conn,PCStr(field),PVStr(value)){
	IStr(ie,128);
	IStr(oe,128);

	if( strcaseeq(field,"Content-Type") ){
		getParam(AVStr(value),"charset",AVStr(ie),sizeof(ie),0);
		strcpy(oe,ie);
	}else
	if( strcaseeq(field,"CCX-Control") ){
		getParam(AVStr(value),"ie",AVStr(ie),sizeof(ie),0);
		getParam(AVStr(value),"oe",AVStr(oe),sizeof(oe),0);
		if( ie[0] == 0 && oe[0] == 0 ){
			strcpy(ie,value);
			strcpy(oe,value);
		}
	}
	if( strcaseeq(ie,"iso-2022-jp") )
		strcpy(ie,"");
	if( CCXactive(CCX_TOCL) ){
		if( ie[0] ) CCX_setindflt(CCX_TOCL,ie);
		if( oe[0] ) CCX_setoutcode(CCX_TOCL,oe);
	}else{
		CCXcreate("*",oe,CCX_TOCL);
		if( ie[0] ) CCX_setindflt(CCX_TOCL,ie);
	}
}

static int cgi_response(Connection *Conn,PCStr(req),PVStr(ihead),FILE *in,FILE *out,FILE **xout,int *stcodep)
{	CStr(ohead,0x10000);
	refQStr(hp,ohead); /**/
	CStr(ctype,1024);
	CStr(status,1024);
	int status_set;
	CStr(location,1024);
	CStr(mimever,1024);
	CStr(field,1024);
	CStr(value,1024);
	CStr(line,1024);
	const char *tp;
	int hleng,bleng,cleng,hcc;
	CStr(ostat,1024);
	const char *xcharset;
	int codeconv;
	int headonly;
	int putConnection;
	Connection ConnBuff;
	IStr(body,8*1024);
	int bodyL = -9;
	int bodyB = -9;

	if( Conn == NULL ){
		bzero(&ConnBuff,sizeof(Connection));
		Conn = &ConnBuff;
	}

	xcharset = HTTP_outCharset(Conn);
	if( xcharset && *xcharset ){
		/* CHARCODE=chset is specified, don't overwrite it */
		CCX_lockoutcode(CCX_TOCL);
	}

	if( getFieldValue2(ihead,"X-Status",AVStr(status),sizeof(status)) )
	{	HttpResponse Stat;
	 	if( 0 < decomp_http_status(status,&Stat) ){
			sprintf(status,"%d %s (filtered by CFI)",
				Stat.hr_rcode,Stat.hr_reason);
		sv1log("## default status: %s\n",status);
		}
	}
	else
	strcpy(status,"200 CGI-OK");
	location[0] = 0;
	status_set = 0;
	if( getFV(ihead,"Content-Type",ctype) )
		rmField(AVStr(ihead),"Content-Type");
	else	strcpy(ctype,"text/plain");
	strcpy(mimever,MY_MIMEVER);

	hcc = 0;
	cleng = -1;
	headonly = strncasecmp(req,"HEAD ",5) == 0;
	putConnection = 0;

	for(;;){
		if( fgets(line,sizeof(line),in) == NULL )
			break;
		hcc += strlen(line);

		if( tp = strpbrk(line,"\r\n") )
			truncVStr(tp);

		if( line[0] == 0 )
			break;

		if( strchr(line,':') == NULL )
		if( line[0] != ' ' && line[0] != '\t' )
			/* is folding supported in HTTP ? */
		{
			sv1log("NON header from CGI program? %s\n",line);
			break;
		}

		fieldScan(line,field,value);

		if( strcasecmp(field,"MIME-Version") == 0 ){
			lineScan(value,mimever);
			continue;
		}
		if( strcasecmp(field,"Status") == 0 ){
			lineScan(value,status);
			status_set = 1;
			continue;
		}
		if( strcasecmp(field,"Location") == 0 ){
			lineScan(value,location);
			continue;
		}
		if( strcasecmp(field,"Content-Type") == 0 ){
			lineScan(value,ctype);
			setcharcode(Conn,field,AVStr(value));
			xcharset = HTTP_outCharset(Conn);
			continue;
		}
		if( strcasecmp(field,"Content-Length") == 0 )
			cleng = atoi(value);

		if( strcaseeq(field,"CCX-Control") ){
			setcharcode(Conn,field,AVStr(value));
			xcharset = HTTP_outCharset(Conn);
			continue;
		}

		sprintf(hp,"%s\r\n",line);
		hp += strlen(hp);
	}
	if( hcc == 0 )
		return 0;

	sprintf(hp,"MIME-Version: %s\r\n",mimever);
	hp += strlen(hp);

	if( getFV(ihead,"Server",line) == NULL ){
		sprintf(hp,"Server: DeleGate/%s\r\n",DELEGATE_ver());
		hp += strlen(hp);
	}

	if( location[0] ){
		CStr(server,MaxHostNameLen);
		if( status_set == 0 )
		strcpy(status,"302 Moved (output of CGI)");
		if( location[0] == '/' ){
			if( Conn )
				ClientIF_HP(Conn,AVStr(server));
			else{
				sprintf(server,"%s:%s",
					getenv("SERVER_NAME"),
					getenv("SERVER_PORT"));
			}
			sprintf(hp,"Location: http://%s%s\r\n",server,location);
		}else	sprintf(hp,"Location: %s\r\n",location);
		hp += strlen(hp);
	}
	sprintf(ostat,"HTTP/%s %s\r\n",MY_HTTPVER,status);
	sprintf(hp,"Content-Type: %s\r\n",ctype);
	codeconv = strncasecmp(ctype,"text/",5) == 0 && xcharset != NULL;

	if( CCXactive(CCX_TOCL) ){
		const char *ocs;
		ocs = CCXcharset(CCX_TOCL);
		sv1log("{C} CGI CHARCODE ie=%s; oe=%s\n",
			CCX_getindflt(CCX_TOCL),ocs?ocs:"");
	}
	if( MountOptions && isinList(MountOptions,"CHARCODE=thru")
	){
		sv1log("##NoCCX(%s)%s\n",ctype,MountOptions?MountOptions:"");
		codeconv = 0;
	}
	if( codeconv == 0 && CCXguessing(CCX_TOCL) ){
		/* this should not be applied to non-text data... */
		const char *ics;
		/*
		fgetsLines(AVStr(body),sizeof(body)/4,in,3*1000);
		CCXexec(CCX_TOCL,body,strlen(body),AVStr(body),sizeof(body));
		*/
		fgetsLinesX(AVStr(body),sizeof(body)/4,in,3*1000,&bodyL,&bodyB);
		CCXexec(CCX_TOCL,body,bodyL,AVStr(body),sizeof(body));
		ics = CCXident(CCX_TOCL);
		if( ics && *ics ){
			sv1log("{C} CGI guessed charset=%s [%s]\n",ics,
				CCX_getindflt(CCX_TOCL));
			replace_charset(AVStr(hp),ics);
		}
	}
	if( codeconv )
		replace_charset(AVStr(hp),xcharset);
	hp += strlen(hp);

	if( atoi(status) == 304 )
		headonly = 1;

	if( stcodep )
		*stcodep = atoi(status);

	if( headonly
	 || 0 < cleng && file_size(fileno(in)) - ftell(in) == cleng ){
		if( Conn ){
			if( getKeepAlive(Conn,AVStr(hp)) ){
				putConnection = 1;
				hp += strlen(hp);
			}
		}
	}
	if( Conn ){
		if( !putConnection ){
			sprintf(hp,"Connection: close\r\n");
			hp += strlen(hp);
		}
	}

	strcpy(hp,ihead);
	hp += strlen(hp);
	strcpy(hp,"\r\n");

	/*
	if( strcaseeq(ctype,"text/shtml") ){
	*/
	if( strncasecmp(ctype,"text/shtml",10) == 0 ){
		if( xout != 0 ){
			*xout = TMPFILE("CGI -> SHTML");
			out = *xout;
		}
	}

	fputs(ostat,out);
	fputs(ohead,out);
	hleng = strlen(ostat) + strlen(ohead);

	if( headonly ){
		bleng = 0;
	}else{
		if( 0 < bodyL ){
			fwrite(body,1,bodyL,out);
		}
		/*
		if( body[0] ){
			fputs(body,out);
		}
		*/
		if( codeconv )
			bleng = CCV_relay_text(Conn,in,out,NULL);
		else
		if( 0 < cleng )
			bleng = copyfile1(in,out);
		else	bleng = simple_relayf(in,out);
	}

	if( xout && *xout ){ /* v9.9.12 fix-140815a, strange ... */
		/* this is a workaround to escape a very strange
		 * phenomena that the writable TMPFILE with buffered
		 * input is inherited to children and appended output
		 * on the automatic fflush() in exit() of the process;
		 * ...
		 * It is likely that the stream buffer for "rw" mode
		 * is not able to be distinguished for read or write.
		 */
		int ofd = dup(fileno(*xout));
		fclose(*xout);
		*xout = fdopen(ofd,"r");
	}

	return hleng+bleng;
}
static void putExecError(int tcd,PCStr(execpath))
{	FILE *tc;
	const char *env;
	int serrno = errno;

	/*
	sv1log("#### FAILED EXEC: %s\n",execpath);
	*/
	sv1log("#### FAILED EXEC: errno=%d %s\n",serrno,execpath);
	if( env = getenv("PATH") )
		sv1log("#### PATH=%s\n",env);

	tc = fdopen(tcd,"w");
	if( tc == NULL ){
		return;
	}
	if( serrno == ENOENT )
	{
	fprintf(tc,"Status: 404 not found\r\n");
	fprintf(tc,"Content-Type: text/plain\r\n");
	fprintf(tc,"\r\n");
	fprintf(tc,"Couldn't find the file.\r\n");
	}
	else
	{
	/*
	fprintf(tc,"Status: 500 cannot execute\r\n");
	*/
	fprintf(tc,"Status: 503 Service Unavailable\r\n");
	fprintf(tc,"Content-Type: text/plain\r\n");
	fprintf(tc,"\r\n");
	fprintf(tc,"the service is unavailable temporarily.\r\n");
	/*
	fprintf(tc,"Couldn't find or execute the CGI script.\r\n");
	*/
	}
	fflush(tc);
}
extern const char *BINSHELL;

int filterDGENV(char *ev[],char *nev[],int nec);
int execvpe(const char *path,char *av[],char *ev[]){
	IStr(xpath,1024);
	char *xev[1024];
	int rcode;

	fullpathCOM(path,"r",AVStr(xpath));
	filterDGENV(ev,xev,elnumof(xev));
	rcode = execve(xpath,av,xev);
	return rcode;
}
int SpawnvpeDirenv(const char *wh,const char *execpath,const char *av[],const char *ev[]){
	const char *nev[1024];
	int rcode = -1;

	return rcode;
}

int cgi_process(Connection *Conn,FILE *tc,PCStr(execpath),PCStr(workdir),const char *av[],const char *ev[],FILE *pfp[])
{	int toCGI[2],fromCGI[2];
	const char *const *savenv;
	CStr(savdir,1024);
	CStr(savfds,2);
	int pid;
	FILE *cfp;
	const char *cav[32]; /**/
	CStr(cab,1024);
	int cai;
	int ai;
	char *nev[1024];

	IGNRETZ pipe(toCGI);
	IGNRETZ pipe(fromCGI);
	setCloseOnExec(toCGI[1] /*,1*/);
	setCloseOnExec(fromCGI[0] /*,1*/);
	savenv = (char const*const*)environ;
	/*
	environ = (char**)ev;
	*/
	filterDGENV((char**)ev,nev,elnumof(nev));
	environ = nev;

	/*
	sv1log("chdir(%s)\n",workdir);
	*/
	IGNRETS getcwd(savdir,sizeof(savdir));
	sv1log("CGI chdir(%s) <- %s\n",workdir,savdir);
	IGNRETZ chdir(workdir);

	savfds[0] = dup(0); dup2(toCGI[0],0); close(toCGI[0]);
	savfds[1] = dup(1); dup2(fromCGI[1],1); close(fromCGI[1]);

	if( cfp = fopen(execpath,"r") ){
		CStr(line,64);
		CStr(shell,32);
		bzero(line,sizeof(line));
		IGNRETP fread(line,1,sizeof(line),cfp);
		wordscanX(line,AVStr(shell),sizeof(shell)-1);
		if( strncasecmp(line,"#!CGI-DeleGate",14) == 0 ){
/*
 * should pass access control parameters to control the access via CGI...
 */
			sprintf(cab,"+=%s",execpath);
			execpath = EXEC_PATH;
			cai = 0;
			cav[cai++] = (char*)execpath; 
			cav[cai++] = "-Fcgi";
			cav[cai++] = cab;
			cav[cai] = 0;
			av = cav;
		}
		if( strcmp(shell,"#!/bin/sh") == 0
		 && strcmp(BINSHELL,"/bin/sh") != 0 ){
			cai = 0;
			cav[cai++] = (char*)BINSHELL;
			cav[cai++] = (char*)execpath;
			for( ai = 1; av[ai]; ai++ ){
				if( 32-1 <= cai ){
					break;
				}
				cav[cai++] = av[ai];
			}
			cav[cai++] = 0;
			av = cav;
			execpath = BINSHELL;
		}
		fclose(cfp);
	}

	if( INHERENT_fork() ){
		if( (pid = Fork("CGI")) == 0 ){
		/* don't use Execvp() because it not returns even on error. */
			closeOnExecServPorts(1);
			execvp(execpath,(char**)av);
			/*
			execvpe(execpath,(char**)av,(char**)ev);
			*/
			putExecError(1,execpath);
			Finish(-1);
		}
	}else{
		extern int MIN_DGSPAWN_WAIT;
		int ws;
		int setwaitspawn(int ws);
		ws = setwaitspawn(MIN_DGSPAWN_WAIT-1);
		/* maybe the child is not DeleGate */
		closeOnExecServPorts(1);
		pid = SpawnvpDirenv("CGI",execpath,av);
		/*
		pid = SpawnvpeDirenv("CGI",execpath,av,ev);
		*/
		closeOnExecServPorts(0); /* is this necessary ? */
		setwaitspawn(ws);
	}
	if( pid == -1 ){
		putExecError(1,execpath); /* write to fromCGI[1] */
	} 

	dup2(savfds[0],0); close(savfds[0]);
	dup2(savfds[1],1); close(savfds[1]);
	environ = (char**)savenv;
	IGNRETZ chdir(savdir);
	pfp[1] = fdopen(toCGI[1],"w");
	pfp[0] = fdopen(fromCGI[0],"r");
	return pid;
}

int file_copyBuffered(FILE *in,FILE *out);
int checkChildAbort1(PCStr(where));
int CCX_reqBody(Connection *Conn,PCStr(qhead),FILE *in,FILE *out,int len,int tout);

extern double HTTP_TOUT_QBODY;
int exec_cgi(Connection *Conn,PCStr(req),PCStr(reqhead),PCStr(scriptpath),PCStr(datapath),PCStr(vurl),PCStr(vpath),PCStr(scripturl),PCStr(extpath),FILE *fc,FILE *tc,int *stcodep)
{
	FILE *pfp[2];
	CStr(oreq,2048);
	CStr(tmp,128);
	int leng;
	CStr(workdir,1024);
	const char *tp;
	const char *av[32]; /**/
	const char *ev[128]; /**/
	CStr(eb,0x10000);
	StrVec Env;
	CStr(conninfo,4096);
	int pid;
	FILE *xout;

	CStr(xvpath,4096);
	int HTCCX_reqURL(Connection *Conn,PCStr(url),PVStr(xvpath));

	if( !CCXactive(CCX_TOSV) ){
		/* might be no MOUNToption for CCX ... */
		scan_CCXTOSV(Conn);
	}
	if( HTCCX_reqURL(Conn,vpath,AVStr(xvpath)) ){
		sv1log("CGI vpath< %s\n",vpath);
		sv1log("CGI vpath> %s\n",xvpath);
		vpath = xvpath;
	}

	make_conninfo(Conn,AVStr(conninfo));
	strcpy(workdir,datapath);
	if( tp = strrchr(workdir,'/') )
		truncVStr(tp);
	av[0] = (char*)scriptpath;

	SVinit(&Env,"exec_cgi",ev,elnumof(ev)-1,AVStr(eb),sizeof(eb)); /* -1 for the entry of randenv */
	cgi_makeEnv(conninfo,req,reqhead,vurl,vpath,datapath,
		scripturl,extpath, 31,&av[1],&Env);
	pid = cgi_process(Conn,tc,scriptpath,workdir,av,ev,pfp);

	if( getFV(reqhead,"Content-Length",tmp) ){
		FileSize leng,wcc;
		int wcc2,isbinary,timeout,ch;

		Xsscanf(tmp,"%lld",&leng);
		timeout = (int)HTTP_TOUT_QBODY;
		wcc = CCX_reqBody(Conn,reqhead,fc,pfp[1],leng,timeout);
		if( wcc <= 0 && leng <= 0 ){
			/* 9.9.1 don't wait body when Content-Length:0 */
			wcc2 = 0;
			isbinary = 0;
		}else
		if( 0 < wcc ){
			wcc2 = 0;
			isbinary = 0;
		}else{
		wcc = file_copyTimeout(fc,pfp[1],NULL,leng,&isbinary,timeout);
		wcc2 = file_copyBuffered(fc,pfp[1]);
		}
		fflush(pfp[1]);
		sv1log("## Sent message body data to CGI [%lld+%d/%lld] %s\n",wcc,wcc2,leng,isbinary?"(BINARY)":"");
	}
	fclose(pfp[1]);
/*
	leng = cgi_response(Conn,req,"",pfp[0],tc,stcodep);
*/
	xout = 0;
	leng = cgi_response(Conn,req,CVStr(""),pfp[0],tc,&xout,stcodep);
	fclose(pfp[0]);

	if( 0 < pid ){
	    int xpid,start,ntry;

	    start = time(NULL);
	    {
	    /* give a chance to the process for finalization...
	     * this seems very effective.
	     * and use usleep_bypoll() which does not use SIGALRM
	     * (to make sleep work with -Tx option)
	     */
		usleep_bypoll(1000);
	    }
	    for( ntry = 0; ; ntry++ ){
		if( Kill(pid,0) < 0 ){
			/* maybe errno == ESRCH (no such process) */
			/* (for Windows) should check if it's a my child */
			break;
		}
		xpid = checkChildAbort1("CGI");
		if( xpid < 0 && errno == ECHILD ){
			break;
		}
		/*
		xpid = NoHangWait();
		*/
		sv1log("Wait*%d CGI-program exit: %d / %d (%d)\n",ntry,xpid,pid,
			ll2i(time(NULL)-start));
		if( xpid == pid )
			break;
		if( 10 < time(NULL)-start ){
			sv1log("KILL CGI-program to exit[%d]: %d\n",ntry,pid);
			Kill(pid,1);
			Kill(pid,9);
		}
		if( xpid <= 0 )
			usleep_bypoll(500*1000);
	    }
	}

	if( xout != 0 ){
		CStr(head,4096);
		refQStr(hp,head); /**/
		const char *xp;

		sv1log("## SHTML from CGI\n");
		fflush(xout);
		fseek(xout,0,0);

		xp = head + (sizeof(head)-1);
		for(; hp < xp; hp += strlen(hp) ){
			if( xp-hp < 1 )
				break;
			if( fgets(hp,xp-hp,xout) == NULL )
				break;
			if( *hp == '\r' || *hp == '\n' )
				break;
		}
		leng = scan_SHTML(Conn,tc,fc,xout,req,head,vurl,vpath,
			datapath,scripturl,extpath);
		fclose(xout);
	}

	return leng;
}

/* sleep without SIGALRM ... to avoid the effect of -Tx ? */
/*
void msleep_bypoll(int msec)
{	int waits[2];

	Socketpair(waits);
	PollIn(waits[0],msec);
	close(waits[0]);
	close(waits[1]);
}
*/

static void dump(PCStr(request))
{	int ei;
	const char *env;

	printf("Content-Type: text/html\r\n\r\n");
	printf("<H2>DeleGate as a CGI program</H2>\n");
	printf("<PRE>\r\n");
	printf("%s\r\n",request);
	for( ei = 0; env = environ[ei]; ei++ )
		printf("%s\r\n",env);
	printf("</PRE>\r\n");
	fflush(stdout);
}

int cgi_delegate(int ac,const char *av[],Connection *Conn)
{	char ei;
	CStr(request,4096);
	refQStr(rp,request); /**/
	const char *env;
	const char *method;
	const char *url;
	const char *ver;
	CStr(field,128);
	CStr(value,4096);
	const char *host;
	const char *port;
	const char *path;
	CStr(server,1024);
	CStr(mount,1024);
	CStr(delegate,1024);
	const char *leng;
	const char *type;
	const char *query;
	CStr(qext,1024);
	const char *chost;
	const char *caddr;
	const char *cuser;
	int fromHttpd[2],toHttpd[2];
	int wcc;

	method = getenv("REQUEST_METHOD");
	url = getenv("PATH_INFO");
	ver = getenv("SERVER_PROTOCOL");
	host = getenv("SERVER_NAME");
	port = getenv("SERVER_PORT");
	path = getenv("SCRIPT_NAME");
	query = getenv("QUERY_STRING");
	chost = getenv("REMOTE_HOST");
	caddr = getenv("REMOTE_ADDR");
	cuser = getenv("REMOTE_IDENT");

	Verbose("REQUEST_METHOD=%s\n",method?method:"(NULL)");
	Verbose("PATH_INFO=%s\n",url?url:"(NULL)");
	Verbose("SERVER_PROTOCOL=%s\n",ver?ver:"(NULL)");
	Verbose("SERVER_NAME=%s\n",host?host:"(NULL)");
	Verbose("SERVER_PORT=%s\n",port?port:"(NULL)");
	Verbose("SCRIPT_NAME=%s\n",path?path:"(NULL)");
	Verbose("QUERY_STRING=%s\n",query?query:"(NULL)");
	Verbose("REMOTE_HOST=%s\n",chost?chost:"(NULL)");
	Verbose("REMOTE_ADDR=%s\n",caddr?caddr:"(NULL)");
	Verbose("REMOTE_IDENT=%s\n",cuser?cuser:"(NULL)");

	if( method == 0 || host == 0 || port == 0 || path == 0 ){
		printf("Status: 500 CGI-DeleGate Error\r\n");
		return -1;
	}
	if( caddr == 0 || ver == 0 ){
		printf("Status: 500 CGI-DeleGate Error\r\n");
		return -1;
	}
	if( url == 0 ){
		printf("Status: 404 CGI-DeleGate Not Found\r\n");
		return -1;
	}

	/*
	 * CGI-DeleGate must be recognized as a directory as "xxx/"
	 * so that "yyy" in CGI-DeleGate is represented as "xxx/yyy"
	 */
	if( strtailchr(path) != '/' )
	if( url[0] == 0 ){
		CStr(urlb,1024);
		sprintf(urlb,"http://%s",host);
		if( atoi(port) != 80 )
		Xsprintf(TVStr(urlb),":%s",port);
		Xsprintf(TVStr(urlb),"%s/",path);
		printf("Status: 302 moved\r\n");
		printf("Location: %s\r\n",urlb);
		printf("\r\n");
		return 0;
	}
	if( url[0] == 0 )
		url = "/";

	sv1log("CGI-DeleGate accepted: %s@%s[%s]\n",
		cuser?cuser:"-",chost?chost:"",caddr?caddr:"");

	Conn->from_myself = 1;
	ACT_SPECIALIST = 1;
	if( chost && chost[0] )
		strcpy(CLNT_HOST,chost);
	else	strcpy(CLNT_HOST,caddr);

	sprintf(server,"%s://%s:%s%s","http",host,port,path);
	scan_SERVER(Conn,server);

/*
	sprintf(mount,"http://%s:%s%s",host,port,path);
	set_MOUNT(Conn,"/-","=","");
	set_MOUNT(Conn,"/*",mount,"");
*/

	sprintf(delegate,"%s:%s",host,port);
	scan_DELEGATE(Conn,delegate);
	/*
	 * This cl_baseurl must used as the base URLpath for any absolute
	 * URLs in the response message (including URLs of built-in icons)
	 * put from this CGI-DeleGate...
	 */
	if( Conn->cl_baseurl[0] == 0 )/* can be set manually by BASEURL */
		set_BASEURL(Conn,path);

	/*
	if( strtailchr(Conn->cl_baseurl) == '/' )
		Conn->cl_baseurl[strlen(Conn->cl_baseurl)-1] = 0;
	 * cl_baseurl is expected to be without trailing '/' but the
	 * original SCRIPT_NAME can be ended with "/" when the CGI script
	 * is named like ../welcome.cgi (the / should be erased in the
	 * parent DeleGate??)
	 */

	if( query && *query )
		sprintf(qext,"?%s",query);
	else	qext[0] = 0;

/* the response from this CGI-DeleGate must be in the version of the
 * client request, or must be converted to it by the caller HTTP server,
 * but it is not likely...
 */
if( strcmp(ver,"HTTP/1.1") == 0 ) ver = "HTTP/1.0";


	sprintf(rp,"%s %s%s %s\r\n",method,url,qext,ver?ver:"");
	rp += strlen(rp);

	for( ei = 0; env = environ[ei]; ei++ ){
		if( strncmp(env,"HTTP_",5) == 0 )
		if( Xsscanf(env+5,"%[^=]=%[^\n]",AVStr(field),AVStr(value)) == 2 ){
			const char *fp;

			for( fp = &field[1]; *fp; fp++ ){
				if( isupper(*fp) )
					*(char*)fp = tolower(*fp); /**/
				if( *fp == '_' )
					*(char*)fp = '-';
			}
			if( strcasecmp(field,"Accept") == 0 ){
			}
			sprintf(rp,"%s: %s\r\n",field,value);
			rp += strlen(rp);
		}
	}

	/* dump(request); */

	/*
	 * Generate a HTTP request message header from CGI environment and
	 * relay it to the HTTP-DeleGate (acting as CGI-program) as if the
	 * requeset was sent from a usual HTTP client. It seems necessary
	 * to be a process to relay the body of a request message which may
	 * exist (POST method for example)
	 */
	Socketpair(fromHttpd);
	if( Fork("CGI-DeleGate-To") == 0 ){
		fclose(stdout);
		fclose(stderr);
		close(fromHttpd[0]);

		if( type = getenv("CONTENT_TYPE") ){
			sprintf(rp,"Content-Type: %s\r\n",type);
			rp += strlen(rp);
		}
		if( leng = getenv("CONTENT_LENGTH") ){
			sprintf(rp,"Content-Length: %s\r\n",leng);
			rp += strlen(rp);
		}
		strcpy(rp,"\r\n");
		IGNRETP write(fromHttpd[1],request,strlen(request));
		wcc = simple_relayTimeout(fileno(stdin),fromHttpd[1],1000);
		sv1log("CGI-DeleGate-To: relayed request body %d+%d bytes\n",
			istrlen(request),wcc);
		Finish(0);
	}
	close(fromHttpd[1]);
	fclose(stdin);

	/*
	 * Relay a output from the HTTP-DeleGate to the server converting
	 * into the format of CGI output.
	 */
	Socketpair(toHttpd);
	if( Fork("CGI-DeleGate-From") == 0 ){
		CStr(stat,1024);
		const char *rcode;
		CStr(head1,4096);
		FILE *resp;
		int ch,hcc,bcc;

		close(toHttpd[1]);
		resp = fdopen(toHttpd[0],"r");
		fgets(stat,sizeof(stat),resp);
		hcc = strlen(stat);
		bcc = 0;

		if( strncmp(stat,"HTTP/",5) == 0 ){
		   if( rcode = strchr(stat,' ') ){
			fprintf(stdout,"Status: %s",rcode);
			while( fgets(head1,sizeof(head1),resp) != NULL ){
				hcc += strlen(head1);

				if( strncasecmp(head1,"Location:",9) == 0 ){
/* should be reverse MOUNTed ...?
 * but it seems to be done in CGI-DeleGate with scan_DELEGATE() + BASEURL...
 */
					fputs(head1,stdout);
				}else
				if( strncasecmp(head1,"Content-Type",12)==0
				 || strncasecmp(head1,"Last-Modified",13)==0
				){
					fputs(head1,stdout);
				}else
				if( head1[0] == '\r' || head1[0] == '\n' ){
					fputs(head1,stdout);
					break;
				}
			}
		    }
		}else	fputs(stat,stdout);
		while( 0 < ready_cc(resp) ){
			if( (ch = getc(resp)) == EOF )
				break;
			putc(ch,stdout);
			bcc++;
		}
		fflush(stdout);

		bcc += simple_relay(toHttpd[0],fileno(stdout));
		sv1log("CGI-DeleGate-From: relayed response %d+%d bytes\n",hcc,bcc);
		Finish(0);
	}
	close(toHttpd[0]);
	fclose(stderr);
	fclose(stdout);

	execGeneralist(Conn,fromHttpd[0],toHttpd[1],-1);
	close(fromHttpd[0]);
	close(toHttpd[1]);
	LOG_flushall();

	/*
	 * wait() post processes to exit() not to finish before filtered output
	 * from post process drained.
	 */
	wait(0);
	wait(0);
	return 0;
}

int form2v(PVStr(form),int maxargc,const char *argv[])
{	refQStr(sp,form); /**/
	const char *dp;
	int argc;

	/*
	for( argc = 0; argc < maxargc; argc++ ){
	*/
	for( argc = 0; argc < maxargc; ){
		if( maxargc-1 <= argc ){
			daemonlog("F","## TOO MANY PARAMS IN FORM %d\n",argc);
			break;
		}
		/*
		argv[argc] = sp;
		*/
		argv[argc++] = sp;
		if( dp = strchr(sp,'&') ){
			truncVStr(dp); dp++;
		}
		URL_unescape(sp,AVStr(sp),1,0);
		/*
		nonxalpha_unescape(sp,AVStr(sp),1);
		*/
		if( dp == 0 )
			break;
		sp = (char*)dp;
	}
	argv[argc] = 0;
	return argc;
}
int formdata2v(PCStr(ctype),PVStr(form),int maxargc,const char *argv[]){
	int argc = 0;
	CStr(line,256);
	CStr(boundary,256);
	int blen = 0;
	int where;
	const char *sp;
	const char *np;
	const char *pp;
	int fnlen;
	CStr(type,256);
	CStr(name,256);
	refQStr(fp,form);
	const char *bodyp;
	int enent = 0;

	truncVStr(boundary);
	if( pp = strcasestr(ctype,"boundary=") ){
		valuescanX(pp+9,AVStr(boundary),sizeof(boundary));
		blen = strlen(boundary);
	}

	sp = form;
	where = 0;
	bodyp = 0;
	for( sp = form; *sp; sp = np ){
		np = lineScan(sp,line);
		/*
		if( enent ){
			encodeEntities(line,AVStr(line),1);
		}
		*/
		if( strneq(line,"--",2) && strneq(line+2,boundary,blen) ){
			switch( where ){
				case 0: where = 1; /* header start */
					break;
				case 1: where = 0; /* header only end */
					setVStrPtrInc(fp,0);
					break;
				case 2:
				case 3: where = 1; /* body end */
					if( bodyp ){
						int bleng;
						const char *ep;
						ep = sp;
						if( bodyp+2 <= ep )
						if( strneq(ep-2,"\r\n",2) )
							ep -= 2;
						bleng = ep - bodyp;
						Bcopy(bodyp,fp,bleng);
						setVStrEnd(fp,bleng);
						fp += bleng + 1;
						bodyp = 0;
					}
					break;
			}
			truncVStr(sp);
			enent = 0;
		}
		if( where == 1 ){
			if( *line == 0 ){
				where = 2; /* body start */
			}
		}
		if( where == 1 ){
			if( fnlen = STRH(line,F_ContDisp) ){
				truncVStr(type);
				truncVStr(name);
				pp = wordScanY(line+fnlen,type,"^;");
				/*
				if( strcaseeq(type,"application/form-data") )
					enent = 1;
				*/
				if( *pp == ';' ){
					pp++;
					if( *pp == ' ' ) pp++;
					if( strncaseeq(pp,"name=",5) ){
				valuescanX(pp+5,AVStr(name),sizeof(name));
					}
					argv[argc++] = fp;
					sprintf(fp,"%s=",name);
					fp += strlen(fp);
				}
			}
		}
		if( *np == '\r' ) np++;
		if( *np == '\n' ) np++;
		if( where == 2 ){
			bodyp = np;
			where = 3;
		}
	}
	argv[argc] = 0;
	return argc;
}
int HTTP_form2v(Connection *Conn,FILE *fc,int maxargc,const char *argv[])
{	CStr(cLeng,1024);
	defQStr(form);
	int cleng,rcc;
	int argc,argi;
	CStr(ctyp,256);

	HTTP_getRequestField(Conn,"Content-Length",AVStr(cLeng),sizeof(cLeng));
	cleng = atoi(cLeng);
	setVStrEnd(ctyp,0);
	HTTP_originalRequestField(Conn,"Content-Type",AVStr(ctyp),sizeof(ctyp));

	argc = 0;
	/*
	form[0] = 0;
	*/
	if( 0 < cleng ){ /* && if Content-Type: x-form */
		/*
		if( sizeof(form) <= cleng ){
			daemonlog("F","## POST FORM TOO LARGE %d\n",cleng);
			cleng = sizeof(form) -1;
		}
		*/
		if( 0x10000 <= cleng ){
			daemonlog("F","## POST FORM TOO LARGE %d\n",cleng);
			cleng = 0x10000;
		}
		setQStr(form,(char*)malloc(cleng+1),cleng+1);
		rcc = fread((char*)form,1,QVSSize(form,cleng),fc);
		setVStrEnd(form,rcc);

		if( strncaseeq(ctyp,"multipart/form-data",19) ){
			argc = formdata2v(ctyp,AVStr(form),maxargc,argv);
		}else
		argc = form2v(AVStr(form),maxargc,argv);
	}
	argv[argc] = 0;
	return argc;
}

int clientHTTP(Connection *Conn)
{
	if( strcaseeq(CLNT_PROTO,"http") || strcaseeq(CLNT_PROTO,"https") )
		return CurEnv != 0;
	return 0;
}

typedef struct {
	StrVec	 e_Env;
  const	char	*e_ev[128]; /**/
	MStr(	 e_eb,0x10000);
} CgiEnv;
static const char **getCgiEnv(Connection *Conn,CgiEnv *E)
{	CStr(ci,4096);
	CStr(ourl,1024);

	if( !clientHTTP(Conn) )
	if( (ClientFlags & PF_STLS_DO) ){
		/* host-info. is necessary for SSL session cache in FCL */
		make_conninfo(Conn,AVStr(ci));
		SVinit(&E->e_Env,"substCGIENV",E->e_ev,elnumof(E->e_ev)-1,AVStr(E->e_eb),sizeof(E->e_eb));
		cgi_makeEnv(ci,"","","","","","","",0,NULL,&E->e_Env);
		return E->e_ev;
	}else{
		return (const char**)environ;
	}

	HTTP_originalURLx(Conn,AVStr(ourl),sizeof(ourl));
	make_conninfo(Conn,AVStr(ci));
	SVinit(&E->e_Env,"substCGIENV",E->e_ev,elnumof(E->e_ev)-1,AVStr(E->e_eb),sizeof(E->e_eb));
	cgi_makeEnv(ci,OREQ,OREQ_MSG,"",ourl,REQ_URL,"","",0,NULL,&E->e_Env);
	return E->e_ev;
}

const char **CFI_makeEnv(CgiEnv *Ev,PVStr(conninfo),Connection *Conn,PCStr(qhead),PCStr(rstat),PCStr(rhead)){
	CStr(ourl,1024);
	CStr(oupath,1024);
	const char *vu = "";
	const char *vup = "";
	const char *xp = ""; /* to be PATH_INFO */
	const char *dp = ""; /* to be PATH_TRNACLATED */
	const char *scp = ""; /* should be script path of CFI-script ? */

	make_conninfo(Conn,AVStr(conninfo));
	SVinit(&Ev->e_Env,"CFIsearch",Ev->e_ev,elnumof(Ev->e_ev)-1,AVStr(Ev->e_eb),sizeof(Ev->e_eb));

	/* these should be extracted from qhead */
	HTTP_originalURLx(Conn,AVStr(ourl),sizeof(ourl));
	/*
	HTTP_originalURLPath(Conn,AVStr(oupath));
	*/
	urlPath(ourl,AVStr(oupath));

	vu = ourl;
	vup = oupath;
	dp = REQ_URL;
	xp = oupath;

	cgi_makeEnv(conninfo,OREQ,OREQ_MSG,vu,vup,dp,scp,xp,0,NULL,&Ev->e_Env);
	return Ev->e_ev;
}
const char *CFI_searchSpec(PCStr(ci),PCStr(sp),PCStr(st),PCStr(he),int silent);
const char *CFI_searchSpecEnv(Connection *Conn,PCStr(sp),PCStr(rst),PCStr(rhead)){
	CgiEnv Ev;
	CStr(conninfo,2048);
	char **savenv;
	int silent;
	const char *sp1;

	savenv = environ;
	CFI_makeEnv(&Ev,AVStr(conninfo),Conn,OREQ_MSG,rst,rhead);
	environ = (char**)Ev.e_ev;
	silent = LOGLEVEL < 2;
	sp1 = CFI_searchSpec(conninfo,sp,rst,rhead,silent);
	environ = savenv;
	return sp1;
}

int substCGIENV(Connection *Conn,PCStr(name),PVStr(out),int size)
{	CgiEnv Ev;
	const char *const*evp;
	const char *e1;
	int ei,nlen,match;

	if( getenv("CFI_TYPE") ) /* running as a filter already with CGIENVs */
		evp = (char const*const*)environ;
	else	evp = getCgiEnv(Conn,&Ev);
	nlen = strlen(name);
	match = 0;
	for( ei = 0; e1 = evp[ei]; ei++ ){
		if( strncmp(name,e1,nlen) == 0 )
		if( e1[nlen] == '=' ){
			linescanX(e1+nlen+1,AVStr(out),size);
			match = 1;
		}
	}
	return match;
}
int isinv(const char *av[],PCStr(v1));
/* 9.9.4 MTSS -Ete putting new environ. vector using putenv() and unsetenv()
 * without directly rewriting the global *environ and environ[]
 */
int putenvs(PCStr(wh),const char **ev){
	int ei,ex,eo,en;
	const char *e1;
	IStr(name,128);
	int log = 0;

	for( eo = 0; environ[eo]; eo++ );
	for( ei = eo-1; 0 <= ei; ei-- ){
		if( (e1 = environ[ei]) == 0 ){
			break;
		}
		if( isinv(ev,e1) ){
			/* to be left as is */
		}else{
			paramscanX(e1,"=",AVStr(name),sizeof(name));
			if( getv((const char**)ev,name) ){
				/* to be overwritten */
				if( log ){
					sv1log("envR %s[%d] %s\n",wh,ei,e1);
				}
			}else{
				if( log ){
					sv1log("env- %s[%d] %s\n",wh,ei,e1);
				}
				unsetenv(name);
			}
		}
	}
	if( log ){
		for( ei = 0; e1 = ev[ei]; ei++ ){
			if( 1 < log ){
				if( isinv((const char**)environ,e1) ){
					sv1log("env= %s[%d] %s\n",wh,ei,e1);
				}else{
					sv1log("env+ %s[%d] %s\n",wh,ei,e1);
				}
			}
		}
	}
	for( ei = 0; e1 = ev[ei]; ei++ ){
		putenv(stralloc(e1));
	}
	en = ei;
	if( log ){
		sv1log("env# eo=%d en=%d\n",eo,en);
		if( 1 < log ){
			for( ei = 0; e1 = environ[ei]; ei++ ){
				ex = isinv(ev,e1)-1;
				sv1log("env#[%d][%d] %s\n",ex,ei,e1);
			}
		}
	}
	return 0;
}

void putCGIENV(Connection *Conn)
{	CgiEnv Ev;
	const char *const*ev;
	CStr(conninfo,2048);

	if( (GatewayFlags & GW_IS_CFI) && CurEnv != NULL ){
		ev = CFI_makeEnv(&Ev,AVStr(conninfo),Conn,OREQ_MSG,"","");
	}else
	ev = getCgiEnv(Conn,&Ev);
	if( ev != (char const*const*)environ )
	{
		if( safeputenv ){
			putenvs("putCGIENV",(const char**)ev);
		}else
		environ = (char**)dupv(ev,0);
	}
}
static char **savenv;
static char **tmpenv;
static int tmpSUM;

int strCRC32add(int crc,PCStr(str),int len);
int sumv(char *sv[]){
	int ei;
	int sum = 0;
	char *e1;

	for( ei = 0; e1 = sv[ei]; ei++ ){
		sum = strCRC32add(sum,(char*)&e1,sizeof(e1));
	}
	//fprintf(stderr,"--sumv(%X) = %X (%d)\n",sv,sum,ei);
	return sum;
}

void pushCGIENV(Connection *Conn,void *sevp)
{	char **ev;

	if( safeputenv ){
		ev = (char**)dupv((const char*const*)environ,0);
		*(char***)sevp = ev;
		putCGIENV(Conn);
		return;
	}
	ev = environ;
	putCGIENV(Conn);
	if( ev != environ )
	{
		if( savenv == 0 || ev != savenv ){
			if( savenv != 0 ){
				/* on CYGWIN+SSHd? */
				/* free(savenv); */
			}
			/* 9.6.0 the original *environ[] can be applied free()
			 * in a putenv() even if the **environ does not point
			 * to the area of the original *environ[] (on Linux)
			 * Thus saving and restore **environ value pointing to
			 * the original *environ[] will cause fatal error as
			 * SEGV using broken (overwritten) area as *environ[].
			 */
			savenv = (char**)dupv((const char*const*)ev,0);
			*(char***)sevp = savenv;
		}else{
		*(char***)sevp = ev;
		}
		tmpenv = environ;
		tmpSUM = sumv(environ);
	}
	else	*(char***)sevp = 0;
}
void popCGIENV(Connection *Conn,void *sevp)
{
	Verbose("--restore environ:%X %X/%X %X\n",
		p2i(environ),p2i(tmpenv),p2i(*(char***)sevp),p2i(savenv));

	if( *(char***)sevp && safeputenv ){
		putenvs("popCGIENV",*(const char***)sevp);
		freev(*(char***)sevp);
	}else
	if( *(char***)sevp && *(char***)sevp != environ ){
		if( *(char***)sevp != savenv ){
			daemonlog("F","--DON'T restore environ: %X != %X\n",
				p2i(*(char***)sevp),p2i(savenv));
		}else
		if( environ != tmpenv ){
			daemonlog("F","--DON'T free environ: %X != %X\n",
				p2i(environ),p2i(tmpenv));
		}else
		if( sumv(environ) != tmpSUM ){
			daemonlog("F","--DON'T free environ SUM: %X %X\n",
				tmpSUM,sumv(environ));
		}else{
		/*
		freev(environ);
			9.9.4 MTSS multi-thread signal safe environ[]
		*/
			char **oenviron = environ;
		environ = *(char***)sevp;
			freev(oenviron);
		}
	}
}

void System(DGC *ctx,PCStr(command),FILE *in,FILE *out);
void system_CGI(DGC *ctx,PCStr(conninfo),PCStr(oreq),PCStr(req),PVStr(head),PCStr(cgi),FILE *in,FILE *out)
{	const char *ev[128]; /**/
	CStr(eb,0x10000);
	FILE *tmp;
	const char *xhead;
	const char *dp;
	const char *url;
	const char *ourl;
	HttpRequest reqx,oreqx;
	const char *const *oenv;
	StrVec Env;

	xhead = stralloc(head);
	decomp_http_request(oreq,&oreqx);
	ourl = oreqx.hq_url;
	decomp_http_request(req,&reqx);
	url = reqx.hq_url;
	SVinit(&Env,"sysgem_CGI",ev,elnumof(ev)-1,AVStr(eb),sizeof(eb));
	cgi_makeEnv(conninfo,req,xhead,"",ourl,url,"","",0,NULL,&Env);

	oenv = (char const*const*)environ;
	environ = (char**)ev;

	tmp = TMPFILE("CFI-system_CGI");
	System(ctx,cgi,in,tmp);
	environ = (char**)oenv;
	fseek(tmp,0,0);
	if( dp = strstr(head,"\r\n\r\n") )
		((char*)dp)[2] = 0;
	if( dp = strstr(head,"\n\n") )
		((char*)dp)[1] = 0;
	cgi_response(NULL,req,AVStr(head),tmp,out,NULL,NULL);
	fclose(tmp);

	free((char*)xhead);
}
