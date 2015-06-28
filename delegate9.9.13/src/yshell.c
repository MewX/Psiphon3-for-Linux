/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Program:	yshell.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	080308	created
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include "ystring.h"
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE */
#include "delegate.h" /* Connection */
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "log.h"

void chdir_cwd(PVStr(cwd),PCStr(go),int userdir);
FILE *logUDPsockfp();
int LOGX_stats(PVStr(msg),int shortfmt);
void LOGX_stats2(PVStr(line));
void put_myconf(FILE *out);
int myid_mainX(int ac,const char *av[],FILE *idout);
int setDebugX(Connection *XConn,PCStr(arg),int force);
int captureLOG(Connection *Conn,FILE *tc,FILE *fc,int lns,int sec);
int dumpWhere(FILE *out,int flags);
int dumpScreen(FILE *fp);
FILE *ls_unix(FILE *fp,PCStr(opt),PVStr(fmt),PCStr(dir),FileStat *stp);
void iLOGdump1(FILE *lfp,int sig);
int cafe_mainX(int ac,const char *av[],FILE *out,FILE *log);
int cksum_main1(int ac,const char *av[],FILE *out,FILE *err);
int seltest(FILE *out);
int file_md5(FILE *fp,PVStr(md5));
int RFC821_skipbody(FILE *afp,FILE *out,xPVStr(line),int size);
int relayfX(Connection *Conn,RelayCtrl *relayCtrl,FILE *fc,FILE *tc,FILE *fs,FILE *ts);
int decomp_absurl(PCStr(url),PVStr(proto),PVStr(login),PVStr(upath),int ulen);
typedef int AUFunc(void *ctx,PCStr(base),PCStr(url));
int HTML_scanLinks(FILE *in,int optr,PCStr(abase),AUFunc aufunc,void *ctx);
int strCRC32(PCStr(str),int len);
int regdump_main(int ac,const char *av[],FILE *out,FILE *err);
void HTTP_readReqBody(Connection *Conn,FILE *fc);
const char *HTTP_originalReqBody(Connection *Conn);
const char *ControlPanelText();
int spinach(Connection *Conn,FILE *fc,FILE *tc);

#include "http.h"
int service_console(Connection *Conn);
int HTTP_getreq(Connection *Conn,FILE *req);
int HTTP_authok(Connection *Conn){
	int ok;
	if( CurEnv ){
		ok = REQ_AUTH.i_stype & (AUTH_APROXY|AUTH_AORIGIN);
		return ok;
	}
	return 0;
}
int putYshellData(Connection *Conn,FILE *fc,FILE *tc,PCStr(path)){
	int fromC = FromC;
	FILE *tmp;

	if( CurEnv && HTTP_methodWithBody(REQ_METHOD) ){
		HTTP_readReqBody(Conn,fc);
	}
	tmp = TMPFILE("Ysh/HTTP");
	FromC = fileno(tmp);
	HTTP_getreq(Conn,tmp);
	fflush(tmp);
	fseek(tmp,0,0);
	service_console(Conn);
	fclose(tmp);
	FromC = fromC;
	return 1;
}

#define LINESIZE 512
#define WORDSIZE 64

typedef struct {
	int  ysh_crc;
	int  ysh_created;
	int  ysh_nthlogin;
	int  ysh_lastlogin;
	int  ysh_lastlogout;
	MStr(ysh_cookie,LINESIZE); /* for HTTP session */
	MStr(ysh_prompt,LINESIZE); /* for Telent session */
	MStr(ysh_root,LINESIZE);
	MStr(ysh_cwd,LINESIZE);
	MStr(ysh_pushd,LINESIZE);
	int  ysh_capsec;
	int  ysh_caplns;
	MStr(ysh_rcwd,LINESIZE+1);
	int  ysh_remote;
	int  ysh_histN;
	int  ysh_histX;
	MStr(ysh_history,8*1024);
	MStr(ysh_histe,1);
} YshCtxPst;
typedef struct {
 Connection *ysh_Conn;
	int  ysh_authOk;
    AuthInfo ysh_ident;
       FILE *ysh_fc;
       FILE *ysh_tc;
	int  ysh_ishttp;
	MStr(ysh_method,WORDSIZE);
	MStr(ysh_reqver,WORDSIZE);
	MStr(ysh_req,LINESIZE);
	MStr(ysh_com,LINESIZE);
	MStr(ysh_args,LINESIZE);
	MStr(ysh_opts,LINESIZE);
	MStr(ysh_arg1,LINESIZE);
	MStr(ysh_arg2,LINESIZE);
 const char *ysh_argv[32];
	int  ysh_rcode;
	int  ysh_sock;
	int  ysh_lscrcs[128];
	int  ysh_lscrcsx;
	int  ysh_dogzip;
} YshCtxTmp;
typedef struct {
   YshCtxPst ysh_pst;
   YshCtxTmp ysh_tmp;
} YshCtx;

#define YshTmp	Ysh->ysh_tmp
#define Conn	YshTmp.ysh_Conn
#define AuthOk	YshTmp.ysh_authOk
#define Ident	YshTmp.ysh_ident
#define Fc	YshTmp.ysh_fc
#define Tc	YshTmp.ysh_tc
#define Ishttp	YshTmp.ysh_ishttp
#define Method	YshTmp.ysh_method
#define Reqver	YshTmp.ysh_reqver
#define Req	YshTmp.ysh_req
#define Com	YshTmp.ysh_com
#define Args	YshTmp.ysh_args
#define Opts	YshTmp.ysh_opts
#define Arg1	YshTmp.ysh_arg1
#define Arg2	YshTmp.ysh_arg2
#define Argv	YshTmp.ysh_argv
#define Rcode	YshTmp.ysh_rcode
#define Lscrcs	YshTmp.ysh_lscrcs
#define LscrcsX	YshTmp.ysh_lscrcsx
#define DoGZIP	YshTmp.ysh_dogzip

#define YshPst	Ysh->ysh_pst
#define Pstcrc	YshPst.ysh_crc
#define Created	YshPst.ysh_created
#define Numlog	YshPst.ysh_nthlogin
#define Lastli	YshPst.ysh_lastlogin
#define Lastlo	YshPst.ysh_lastlogout
#define Prompt	YshPst.ysh_prompt
#define Root	YshPst.ysh_root
#define Cwd	YshPst.ysh_cwd
#define Pushd	YshPst.ysh_pushd
#define Capsec	YshPst.ysh_capsec
#define Caplns	YshPst.ysh_caplns
#define Rcwd	YshPst.ysh_rcwd
#define Remote	YshPst.ysh_remote
#define HistN	YshPst.ysh_histN
#define HistX	YshPst.ysh_histX
#define History	YshPst.ysh_history

static void saveYshCtx(YshCtx *Ysh,FILE *cfp){
	fprintf(cfp,"Pstcrc: %X\r\n",Pstcrc);
	fprintf(cfp,"Created: %X\r\n",Created);
	fprintf(cfp,"Numlog: %X\r\n",Numlog);
	fprintf(cfp,"Lastli: %X\r\n",Lastli);
	fprintf(cfp,"Lastlo: %X\r\n",Lastlo);
	fprintf(cfp,"Prompt: %s\r\n",Prompt);
	fprintf(cfp,"Cwd: %s\r\n",Cwd);
	fprintf(cfp,"Pushd: %s\r\n",Pushd);
	fprintf(cfp,"Capsec: %X\r\n",Capsec);
	fprintf(cfp,"Caplns: %X\r\n",Caplns);
	fprintf(cfp,"Rcwd: %s\r\n",Rcwd);
	fprintf(cfp,"Remote: %X\r\n",Remote);
	fprintf(cfp,"HistN: %X\r\n",HistN);
	fprintf(cfp,"HistX: %X\r\n",HistX);
	fprintf(cfp,"History: \r\n%s",History);
}
static void loadYshCtx(YshCtx *Ysh,FILE *cfp){
	IStr(buf,LINESIZE);
	IStr(nam,LINESIZE);
	const char *val;
	int ival;
	refQStr(hp,History);
	int ci;

	for( ci = 0;; ci++ ){
		if( Fgets(AVStr(buf),sizeof(buf),cfp) == 0 ){
			break;
		}
		val = wordScanY(buf,nam,"^:");
		if( *val == ':' ) val++;
		if( *val == ' ' ) val++;
		ival = 0;
		sscanf(val,"%X",&ival);
		if( streq(nam,"Pstcrc") )   Pstcrc = ival;
		if( streq(nam,"Created") )  Created = ival;
		if( streq(nam,"Numlog") )   Numlog = ival;
		if( streq(nam,"Lastli") )   Lastli = ival;
		if( streq(nam,"Lastlo") )   Lastlo = ival;
		if( streq(nam,"Prompt") )   strcpy(Prompt,val);
		if( streq(nam,"Cwd") )      strcpy(Cwd,val);
		if( streq(nam,"Pushd") )    strcpy(Pushd,val);
		if( streq(nam,"Capsec") )   Capsec = ival;
		if( streq(nam,"Caplns") )   Caplns = ival;
		if( streq(nam,"Rcwd") )     strcpy(Rcwd,val);
		if( streq(nam,"Remote") )   Remote = ival;
		if( streq(nam,"HistN") )    HistN = ival;
		if( streq(nam,"HistX") )    HistX = ival;
		if( streq(nam,"History") ){
			IGNRETP fread(History,1,sizeof(History),cfp);
			break;
		}
	}
}

static FILE *_logMonFp;
FILE *logMonFp(){
	FILE *lfp;
	if( lfp = _logMonFp ){
		return lfp;
	}
	/*
	this can cause loop and freeze
		if( lfp = logUDPsockfp() ){
			return lfp;
		}
	*/
	return 0;
}
int setlogMonFp(FILE *fp){
	_logMonFp = fp;
	return 0;
}
static const char *helps[] = {
	"cd [path]",
	"cp [-p] srcpath dstpath",
	"ls [-t] [path]",
	"ln [-s] path newpath",
	"rm [path]",
	0
};
static void helpsh(YshCtx *Ysh){
	fprintf(Tc,"%s\r\n",DELEGATE_Ver());
	fprintf(Tc," cap       capture the output to LOGFILE and console\r\n");
	fprintf(Tc," opt -Opt  set option (ex. -vd)\r\n");
	fprintf(Tc," quit      quit\r\n");
	fprintf(Tc," stat      show status\r\n");
	fprintf(Tc," ver       show version and config.\r\n");
	fprintf(Tc," date      show current time\r\n");
	fprintf(Tc," time      show resouce usage\r\n");
	fprintf(Tc," ps        show running processes\r\n");
	fprintf(Tc," regdump   dump the registry\r\n");
	fprintf(Tc," cd pwd ls du find md5 cat tail\r\n");
	fprintf(Tc," rm ln cp mkdir rmdir touch\r\n");
	fflush(Tc);
}
void dumpsockets(FILE *out,PCStr(wh));
static void capturelog(YshCtx *Ysh){
	double Start = Time();

	if( isdigit(*Arg1) ){
		Capsec = atoi(Arg1);
	}
	if( 1 ){
		fprintf(Tc,"-- capture %d\r\n",Capsec);
		fprintf(Tc,"-- Started Log Moniter: hit RETURN to stop\r\n");
		fflush(Tc);
	}
	if( lSINGLEP() ){
		setNonblockingIO(fileno(Tc),1);
		setlogMonFp(Tc);
		fPollIn(Fc,Capsec*1000);
		setlogMonFp(0);
		setNonblockingIO(fileno(Tc),0);
	}else{
		captureLOG(Conn,Tc,Fc,Caplns,Capsec);
	}
	if( 1 ){
		IStr(stat,1024);
		IStr(stm,128);
		StrftimeLocal(AVStr(stm),sizeof(stm),"%H:%M:%S",time(0),0);
		fprintf(Tc,"-- Stopped Log Moniter %s (%.1f)\r\n",stm,
			Time()-Start);

		LOGX_stats2(AVStr(stat));
		fprintf(Tc,"%s\n",stat);
		LOGX_stats(AVStr(stat),0);
		fprintf(Tc,"%s\n",stat);
		dumpsockets(Tc,"capture");
		dumposf(Tc,"capture",0,0,0);
		fflush(Tc);
	}
	if( 0 < fPollIn(Fc,1) ){
		Fgets(AVStr(Req),LINESIZE,Fc);
	}
}
static void bench(YshCtx *Ysh){
	int bi;
	int ofd = fileno(Tc);
	int total = 0;
	int tsent = 0;
	double Start = Time();
	double Elps;
	double Now;
	IStr(buf,1000);
	int wcc;
	IStr(result,128);

	for( bi = 0; bi < sizeof(buf); bi++ ){
		setVStrElem(buf,bi,"123456789\n"[bi%10]);
	}
	fprintf(Tc,"sending bench mark data (10 seconds)... <BR><!--\r\n");
	fflush(Tc);
	setNonblockingIO(ofd,1);
	for( bi = 0; bi < 100*1000; bi++ ){
		Now = Time();
		if( 10 < Now - Start ){
			break;
		}
		if( PollOut(ofd,(int)((10-(Now-Start))*1000)) <= 0 ){
			break;
		}
		total += sizeof(buf);
		wcc = write(ofd,buf,sizeof(buf));
		if( wcc <= 0 ){
			break;
		}
		tsent += wcc;
		if( 10*1000*sizeof(buf) <= tsent ){
			break;
		}
	}
	setNonblockingIO(ofd,0);
	Elps = Time() - Start;
	fprintf(Tc,"\r\n-->\r\n");
	sprintf(result,"-- %d / %d / %d / %.2f",tsent,total,bi,Elps);
	sv1log("%s\n",result);
	fprintf(Tc,"<BR>%s\n",result);
	sprintf(result,"-- %.3fKB / sec. = %.3fMbps",tsent/Elps/1000,
		tsent*8/Elps/1000000);
	sv1log("%s\n",result);
	fprintf(Tc,"<BR>%s\n",result);
}
static void hputc(YshCtx *Ysh,char ch){
	((char*)History)[HistX++ % sizeof(History)] = ch;
}
#define hgetc(Ysh,hi) History[hi % sizeof(History)];

const char yitoad[] = "ahsjdkflgotnrmvi";
const char *yitox(PVStr(nums),int num){
	IStr(buf,16);
	int unum = (unsigned int)num;
	int bi;

	bi = sizeof(buf);
	--bi; setVStrEnd(buf,bi);
	for(;;){
		--bi; setVStrElem(buf,bi,yitoad[num&0xF]);
		if( (num >>= 4) == 0 )
			break;
	}
	strcpy(nums,buf+bi);
	return nums;
}
static void addhist(YshCtx *Ysh,PCStr(req)){
	IStr(nums,WORDSIZE);
	IStr(buf,WORDSIZE);
	const char *rp;
	int hi;
	char ch;
	char pch;

	yitox(AVStr(nums),HistN++);
	sprintf(buf,"%X %s ",itime(0),nums);
	for( rp = buf; ch = *rp; rp++ ){ hputc(Ysh,pch = ch); }
	for( rp = req; ch = *rp; rp++ ){ hputc(Ysh,pch = ch); }
	if( pch != '\n' ) hputc(Ysh,'\n');
}
static void gethist(YshCtx *Ysh){
	int hi,hx,hn;
	char ch;
	int act = 0;
	int pch;

	hx = HistX % sizeof(History);
	hn = 1;
	for( hi = hx+1; hi%sizeof(History) != hx; hi++ ){
		ch = hgetc(Ysh,hi);
		if( act ){
			putc(pch = ch,Tc);
		}
		if( ch == '\n' ){
			if( (hi+1)%sizeof(History) == hx ){
				break;
			}
			hn++;
			act = 1;
		}
	}
	if( pch != '\n' ) fprintf(Tc,"\n");
}
static void historysh(YshCtx *Ysh){
	if( strneq(Com,"history",2) ){
		if( streq(Arg1,"clear") ){
			HistX = 0;
			bzero(History,sizeof(History));
		}
		gethist(Ysh);
	}else
	if( strneq(Com,"prev",3) ){
	}else
	if( strneq(Com,"redo",3) ){
	}else
	if( strneq(Com,"last",2) ){
	}else
	if( streq(Com,"undo") ){
	}
	return;
}
int ps_unix(FILE *out);
static int statsh(YshCtx *Ysh){
	IStr(buf,LINESIZE);

	if( strcaseeq(Com,"date") ){
		StrftimeLocal(AVStr(buf),LINESIZE,"%Y/%m/%d %H:%M:%S %Z",
			time(0),0);
		fprintf(Tc,"%s\r\n",buf);
	}else
	if( strcaseeq(Com,"time") ){
		strfRusage(AVStr(buf),"%A",3,NULL);
		fprintf(Tc,"Total: %s\r\n",buf);
		strfRusage(AVStr(buf),"%A",1,NULL);
		fprintf(Tc,"Self: %s\r\n",buf);
		strfRusage(AVStr(buf),"%A",2,NULL);
		fprintf(Tc,"Child: %s\r\n",buf);
	}else
	if( strcaseeq(Com,"ps") ){
		ps_unix(Tc);
	}else{
		fprintf(Tc,"-- Unknown stat command\r\n");
		return -1;
	}
	return 0;
}
static int relays2(YshCtx *Ysh,int sock){
	FILE *fs;
	FILE *ts;
	RelayCtrl rc;

	fs = fdopen(sock,"r");
	ts = fdopen(sock,"w");
	bzero(&rc,sizeof(RelayCtrl));
	relayfX(Conn,&rc,Fc,Tc,fs,ts);
	fcloseFILE(ts);
	fclose(fs);
	return 0;
}
static int socketsh(YshCtx *Ysh){
	int sock;
	IStr(host,LINESIZE);
	int port;

	port = scan_hostportX("telnet",Arg1,AVStr(host),LINESIZE);
	if( streq(Com,"socket") ){
	}else
	if( streq(Com,"sockopt") ){
	}else
	if( streq(Com,"soconnect") ){
		sock = connectServer("Ysh","tcprelay",host,port);
		if( 0 <= sock ){
			relays2(Ysh,sock);
		}else{
		}
	}else
	if( streq(Com,"soaccept") ){
		sock = server_open("Ysh",AVStr(host),port,1);
		if( 0 <= sock ){
			int clsock;
			IStr(sockname,LINESIZE);
			clsock = ACCEPT1(sock,1,-1,10,AVStr(sockname));
			if( 0 <= clsock ){
				relays2(Ysh,clsock);
			}
			close(sock);
		}else{
		}
	}else
	if( streq(Com,"sojoin") ){
	}
	return 0;
}
static int abspath(YshCtx *Ysh,PVStr(apath),PCStr(rpath)){
	IStr(path,LINESIZE);
	const char *rp;

	strcpy(path,Cwd);
	chdir_cwd(AVStr(path),rpath,0);
	rp = path;
	if( *rp == '/' )
		rp++;
	if( strtailchr(Root) == '/' || *rp == 0 )
		sprintf(apath,"%s%s",Root,rp);
	else	sprintf(apath,"%s/%s",Root,rp);
	return 0;
}
static const char *relpath(YshCtx *Ysh,PCStr(apath)){
	int len;
	len = strlen(Root);
	if( strneq(apath,Root,len) ){
		if( apath[len] == '/' )
			return apath+len+1;
		else	return apath+len;
	}else{
		return apath;
	}
}
static int redirect(YshCtx *Ysh){
	if( strcaseeq(Com,"ipush") ){
	}else
	if( strcaseeq(Com,"ipop") ){
	}else
	if( strcaseeq(Com,"opush") ){
	}else
	if( strcaseeq(Com,"opop") ){
	}
	return 0;
}
static int aufunc(void *ysh,PCStr(base),PCStr(url)){
	YshCtx *Ysh = (YshCtx*)ysh;
	IStr(curl,LINESIZE);
	refQStr(dp,curl);
	int ci;
	int crc;

	if( strheadstrX(url,base,0) ){
		lineScan(url+strlen(base),curl);
		/*
		if( dp = strchr(curl,'/') ){
		*/
		if( dp = strrchr(curl,'/') ){
			setVStrEnd(dp,1);
		}
		if( curl[0] == 0 )
			return 0;
		crc = strCRC32(curl,strlen(curl));
		for( ci = 0; ci < elnumof(Lscrcs)-1; ci++ ){
			if( LscrcsX < ci )
				break;
			if( Lscrcs[ci] == 0 )
				break;
			if( Lscrcs[ci] == crc ){
				return 0;
			}
		}
		Lscrcs[ci] = crc;
		LscrcsX = ci;
		fprintf(Tc,"%s\r\n",curl);
	}else{
	}
	return 0;
}
static void dumphref(YshCtx *Ysh,PCStr(url),FILE *html){
	fprintf(Tc,"-- BASE:%s (%d)\r\n",url,file_size(fileno(html)));
	LscrcsX = 0;
	HTML_scanLinks(html,0,url,aufunc,Ysh);
}
static void download(YshCtx *Ysh){
	const char *dp;
	IStr(url,LINESIZE);
	IStr(lpath,LINESIZE);
	IStr(proto,LINESIZE);
	IStr(site,LINESIZE);
	IStr(upath,LINESIZE);
	FILE *fp;
	int reload;

	if( isFullURL(Arg1) ){
		strcpy(url,Arg1);
	}else{
		strcpy(url,Rcwd);
		chdir_cwd(AVStr(url),Arg1,0);
	}
	decomp_absurl(url,AVStr(proto),AVStr(site),AVStr(upath),LINESIZE);

	if( streq(Com,"rls") ){
		abspath(Ysh,AVStr(lpath),"#ysh.rls");
		strcat(url,"/");
	}else{
		if( *Arg2 != 0 ){
			abspath(Ysh,AVStr(lpath),Arg2);
		}else{
			if( dp = strrchr(upath,'/') )
			if( dp[1] ){
				abspath(Ysh,AVStr(lpath),dp+1);
			}
			if( lpath[0] == 0 ){
				abspath(Ysh,AVStr(lpath),"#ysh.got");
			}
		}
	}
	if( fp = fopen(lpath,"w+") ){
		reload = strstr(Opts,"-R") != 0;
		URLget(url,reload,fp);
		if( streq(Com,"rls") ){
			fseek(fp,0,0);
			if( streq(proto,"ftp") ){
				copyfile1(fp,Tc);
			}else{
				dumphref(Ysh,url,fp);
			}
		}
		fclose(fp);
	}else{
	}
}
extern char **environ;
static int envsh(YshCtx *Ysh){
	int ei;

	if( *Arg1 == 0 ){
		for( ei = 0; environ[ei]; ei++ ){
			fprintf(Tc,"%s\r\n",environ[ei]);
		}
	}else{
		refQStr(dp,Args);
		if( dp = strchr(Args,' ') ){
			setVStrElem(dp,0,'=');
		}
		fprintf(Tc,"%s\r\n",Args);
		putenv(stralloc(Args));
	}
	return 0;
}
static int ftpsh(YshCtx *Ysh){
	if( strcaseeq(Com,"rpwd") ){
		fprintf(Tc,"%s\r\n",Rcwd);
	}else
	if( strcaseeq(Com,"rcd") ){
		if( isFullURL(Arg1) ){
			strcpy(Rcwd,Arg1);
		}else{
			chdir_cwd(AVStr(Rcwd),Arg1,0);
		}
		fprintf(Tc,"%s\r\n",Rcwd);
	}else
	if( strcaseeq(Com,"rls") ){
		download(Ysh);
	}else
	if( strcaseeq(Com,"rget") ){
		download(Ysh);
	}else
	if( strcaseeq(Com,"rput") ){
	}
	return 0;
}
static int filesh(YshCtx *Ysh){
	IStr(path1,LINESIZE);
	IStr(path2,LINESIZE);
	IStr(buf,LINESIZE);
	IStr(md5,WORDSIZE);
	IStr(cwd,LINESIZE);
	FILE *fp1;
	FILE *fp2;

	errno = 0;
	Rcode = 0;
	if( streq(Com,"pwd") ){
		fprintf(Tc,"YSH/%s\r\n",Cwd);
	}else
	if( streq(Com,"cd") || streq(Com,"pushd") ){
		if( *Arg1 == 0 ){
			clearVStr(Cwd);
		}else{
			abspath(Ysh,AVStr(path1),Arg1);
			if( fileIsdir(path1) ){
				if( streq(Com,"pushd") ){
					strcpy(Pushd,Cwd);
				}
				strcpy(Cwd,relpath(Ysh,path1));
			}else{
				fprintf(Tc,"?? No such directory\r\n");
			}
		}
		fprintf(Tc,"YSH/%s\r\n",Cwd);
	}else
	if( streq(Com,"root") ){
		strcpy(path1,Root);
		chdir_cwd(AVStr(path1),Cwd,0);
		chdir_cwd(AVStr(path1),Arg1,0);
		if( isFullpath(path1) && fileIsdir(path1) ){
			strcpy(Root,path1);
			strcpy(Cwd,"");
			fprintf(Tc,"-- OK\r\n");
		}else{
			fprintf(Tc,"-- NG, Unknown directory\r\n");
		}
	}else
	if( streq(Com,"popd") ){
		strcpy(Cwd,Pushd);
		fprintf(Tc,"YSH/%s\r\n",Cwd);
	}else
	if( streq(Com,"ls") ){
		abspath(Ysh,AVStr(path1),Arg1);
		strcpy(buf,"%T%M%3L %10S %D %N");
		ls_unix(Tc,Opts,AVStr(buf),path1,NULL);
	}else
	if( streq(Com,"du") || streq(Com,"find") ){
		int ac = 0;
		Argv[ac++] = "find";
		sprintf(path1,"-root=%s",Root);
		Argv[ac++] = path1;
		if( streq(Com,"du") ){
			Argv[ac++] = "-du";
		}
		if( Opts[0] )
		ac += decomp_args(Argv+ac,elnumof(Argv)-ac,Opts,AVStr(buf));
		if( Args[0] )
		ac += decomp_args(Argv+ac,elnumof(Argv)-ac,Args,AVStr(buf));
		cafe_mainX(ac,Argv,Tc,stderr);
	}else
	if( streq(Com,"cksum") ){
		abspath(Ysh,AVStr(path1),Arg1);
		Argv[0] = Com;
		Argv[1] = path1;
		Argv[2] = 0;
		cksum_main1(2,Argv,Tc,Tc);
	}else
	if( streq(Com,"md5") ){
		if( *Arg1 == 0 ){
			Fgets(AVStr(buf),sizeof(buf),Fc);
			toMD5(buf,md5);
			fprintf(Tc,"%s\r\n",md5);
		}else{
			abspath(Ysh,AVStr(path1),Arg1);
			if( fp1 = fopen(path1,"r") ){
				file_md5(fp1,AVStr(buf));
				fclose(fp1);
				fprintf(Tc,"%s\r\n",buf);
			}else{
				fprintf(Tc,"?? Cannot read the file\r\n");
			}
		}
	}else
	if( streq(Com,"cat") || streq(Com,"tail") ){
		abspath(Ysh,AVStr(path1),Arg1);
		if( fp1 = fopen(path1,"r") ){
			if( streq(Com,"tail") ){
				fseek(fp1,1024,2);
			}
			copyfile1(fp1,Tc);
			fclose(fp1);
		}else{
			fprintf(Tc,"?? Cannot read the file\r\n");
		}
	}else
	if( streq(Com,"grep") ){
		abspath(Ysh,AVStr(path1),Arg1);
		if( fp1 = fopen(path1,"r") ){
			fclose(fp1);
		}else{
			fprintf(Tc,"?? Cannot read the file\r\n");
		}
	}else
	if( streq(Com,"ln") ){
		abspath(Ysh,AVStr(path1),Arg1);
		abspath(Ysh,AVStr(path2),Arg2);
		if( strstr(Opts,"-s") )
			Rcode = symlink(path1,path2);
		else	Rcode = link(path1,path2);
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( 0 ){
		/* modifiecation not allowed */
	}else
	if( streq(Com,"put") ){
		abspath(Ysh,AVStr(path1),Arg1);
		if( fp1 = fopen(path1,"w") ){
			RFC821_skipbody(Fc,fp1,AVStr(buf),LINESIZE);
			fclose(fp1);
		}else{
			fprintf(Tc,"?? Cannot create the file\r\n");
		}
	}else
	if( streq(Com,"add") ){
		abspath(Ysh,AVStr(path1),Arg1);
		if( fp1 = fopen(path1,"a") ){
			fclose(fp1);
		}else{
			fprintf(Tc,"?? Cannot add the file\r\n");
		}
	}else
	if( streq(Com,"touch") ){
		abspath(Ysh,AVStr(path1),Arg1);
		if( fp1 = fopen(path1,"a") ){
			fclose(fp1);
		}else{
			fprintf(Tc,"?? Cannot touch the file\r\n");
		}
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( streq(Com,"cp") ){
		abspath(Ysh,AVStr(path1),Arg1);
		abspath(Ysh,AVStr(path2),Arg2);
		if( fp1 = fopen(path1,"r") ){
			if( fp2 = fopen(path2,"w") ){
				copyfile1(fp1,fp2);
				if( strstr(Opts,"-p") ){
					File_copymod(path1,path2);
				}
				fclose(fp2);
			}else{
				fprintf(Tc,"?? Cannot write the file\r\n");
			}
			fclose(fp1);
		}else{
			fprintf(Tc,"?? No such file\r\n");
		}
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( streq(Com,"mv") ){
		abspath(Ysh,AVStr(path1),Arg1);
		abspath(Ysh,AVStr(path2),Arg2);
		Rcode = rename(path1,path2);
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( streq(Com,"rm") ){
		abspath(Ysh,AVStr(path1),Arg1);
		Rcode = unlink(path1);
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( streq(Com,"rmdir") ){
		abspath(Ysh,AVStr(path1),Arg1);
		Rcode = rmdir(path1);
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( streq(Com,"mkdir") ){
		abspath(Ysh,AVStr(path1),Arg1);
		Rcode = mkdir(path1,0700);
		fprintf(Tc,"%s: rcode = %d %d\r\n",Com,Rcode,errno);
	}else
	if( streq(Com,"expire") ){
	}else
	{
		fprintf(Tc,"-- Unknown file command\r\n");
		return -1;
	}
	return 0;
}

int CTX_withAuth(Connection *XConn);
int doAuth(Connection *XConn,AuthInfo *ident);
int authenticate_by_man(Connection *XConn,PVStr(comment),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident);

static int authenticate(YshCtx *Ysh,Connection *XConn,PVStr(comment),PCStr(user),PCStr(pass),PCStr(path),AuthInfo *ident){
	IStr(userb,WORDSIZE);
	IStr(passb,WORDSIZE);
	int witha = 0;

	clearVStr(comment);
	if( CTX_withAuth(XConn) == 0 ){
	}else{
		ident->i_stat = AUTH_TESTONLY;
		if( 0 <= doAuth(XConn,ident) ){
			AuthOk = 1;
			return AuthOk;
		}else{
			witha = 1;
		}
	}
	if( user == 0 ){
		if( !Ishttp ){
			fprintf(Tc,"Username: ");
			fflush(Tc);
			Fgets(AVStr(userb),sizeof(userb),Fc);
			fprintf(Tc,"Password: ");
			fflush(Tc);
			Fgets(AVStr(passb),sizeof(passb),Fc);
		}
		user = userb;
		pass = passb;
	}
	strcpy(ident->i_user,user);
	strcpy(ident->i_pass,pass);
	ident->i_stat = AUTH_GOT;
	if( witha ){
		if( 0 <= doAuth(XConn,ident) ){
			AuthOk = 1;
		}else{
			AuthOk = -1;
		}
	}else{
		if( !Ishttp ){
			fprintf(Tc,"-- Waiting approval by the admin...\r\n");
			fflush(Tc);
		}
		strcpy(comment,"/1h");
	AuthOk = authenticate_by_man(XConn,BVStr(comment),user,pass,path,ident);
	}
	return AuthOk;
}

int HTTP_decompAuthX(PCStr(auth),PVStr(aty),int asz,PVStr(ava),int avz,AuthInfo *ident);
int withDG_Zlib();
int withDGZlib();
int withZlib();
static int scanheader(YshCtx *Ysh){
	IStr(auth,LINESIZE);
	IStr(head,LINESIZE);
	const char *dp;
	CStr(aty,LINESIZE);
	CStr(ava,LINESIZE);
	IStr(buf,LINESIZE);

	for(;;){
		if( fgets(head,LINESIZE,Fc) == 0 )
			break;
		if( dp = strheadstrX(head,"Authorization:",0) ){
			lineScan(dp,auth);
		}
		if( strheadstrX(head,"Accept-Encoding:",1) ){
			if( strstr(head,"gzip") ){
				Verbose("-- Zlib=%d DGZlib=%d DG_Zlib=%d\n",
					withZlib(),withDGZlib(),withDG_Zlib());
				if( withZlib() ){
					DoGZIP = 1;
				}
			}
		}
		if( *head == '\r' || *head == '\n' )
			break;
	}
	if( HTTP_authok(Conn) ){
		AuthOk = 1;
		return 0;
	}
	if( auth[0] == 0 ){
		fprintf(Tc,"HTTP/1.1 401 Need Auth\r\n");
		fprintf(Tc,"WWW-Authenticate: basic realm=\"console\"\r\n");
		fprintf(Tc,"\r\n");
		fprintf(Tc,"Authentication Required.\r\n");
		return -1;
	}
	HTTP_decompAuthX(auth,AVStr(aty),sizeof(aty),AVStr(ava),sizeof(ava),&Ident);
	if( authenticate(Ysh,Conn,AVStr(buf),Ident.i_user,Ident.i_pass,"CONSOLE",&Ident) <= 0 ){
		fprintf(Tc,"HTTP/1.1 401 Bad Auth\r\n");
		fprintf(Tc,"WWW-Authenticate: basic realm=\"console\"\r\n");
		fprintf(Tc,"\r\n");
		fprintf(Tc,"Bad Authentication.\r\n");
		fprintf(Tc,"%s\r\n",buf);
		return -1;
	}
	return 0;
}
static int getYshRequest1(YshCtx *Ysh){
	IStr(hurl,LINESIZE);
	const char *dp;

	clearVStr(Req);
	if( Ishttp ){
		if( fPollIn(Fc,100) == 0 ){
			return EOF;
		}
	}else{
		if( fPollIn(Fc,100) == 0 ){
			if( Remote )
				fprintf(Tc,"@%s",Prompt);
			else	fprintf(Tc,"%s",Prompt);
			fflush(Tc);
			if( fPollIn(Fc,60*1000) <= 0 ){
				return EOF;
			}
		}
	}
	if( Fgets(AVStr(Req),LINESIZE,Fc) == 0 ){
		return EOF;
	}
	if( !HTTP_isMethod(Req) ){
		dp = wordscanX(Req,AVStr(Com),LINESIZE);
		dp = linescanX(dp,AVStr(Args),LINESIZE);
		Ishttp = 0;
		return 0;
	}else{
		Ishttp = 1;
	}
	scanheader(Ysh);
	if( AuthOk <= 0 ){
		return -1;
	}

	dp = wordScan(Req,Method);
	dp = wordScan(dp,hurl);
	if( strneq(hurl,"gendata:",8) ){
		ovstrcpy(hurl,hurl+8);
	}
	lineScan(dp,Reqver);
	URL_unescape(hurl,AVStr(Req),1,0);
	dp = wordscanX(Req,AVStr(Com),LINESIZE);
	linescanX(dp,AVStr(Args),LINESIZE);

	/*
	if( strneq(Req,"POST ",5) ){
		HTTP_readReqBody(Conn,Fc);
	}
	*/
	if( strneq(Com,"/-/ysh/",7) ){
		ovstrcpy((char*)Com,Com+7);
	}
	if( *Com == '/' ){
		ovstrcpy((char*)Com,Com+1);
	}
	fprintf(Tc,"HTTP/1.1 200 OK\r\n");
	fprintf(Tc,"Connection: Keep-Alive\r\n");
	if( 1 ){
		IStr(date,128);
		StrftimeGMT(AVStr(date),sizeof(date),TIMEFORM_RFC822,time(0),0);
		fprintf(Tc,"Last-Modified: %s\r\n",date);
	}
	if( strtailstr(Com,".bmp") ){
		IStr(lmt,128);
		StrftimeGMT(AVStr(lmt),sizeof(lmt),TIMEFORM_RFC822,time(0),0);
		fprintf(Tc,"Last-Modified: %s\r\n",lmt);
		fprintf(Tc,"Content-Type: image/bmp\r\n");
		if( DoGZIP ){
			fprintf(Tc,"Content-Encoding: gzip\r\n");
		}
	}else{
		/*
		fprintf(Tc,"Pragma: no-cache\r\n");
		*/
		if( strtailstr(Com,".html")
		 || strtailstr(Com,".shtml")
		 || strtailstr(Com,"/")
		 || strstr(Com,"screen/click")
		){
		fprintf(Tc,"Content-Type: text/html; charset=UTF-8\r\n");
		}else
		if( isWindowsCE() )
		fprintf(Tc,"Content-Type: text/plain; charset=UTF-8\r\n");
	}
	fprintf(Tc,"\r\n");
	return 0;
}
static int getYshRequest(YshCtx *Ysh){
	const char *ap;
	refQStr(op,Opts);

	if( getYshRequest1(Ysh) == EOF )
		return EOF; 
	ap = Args;
	if( *ap == '-' ){
		for( ; *ap == '-'; ){
			if( Opts < op ) setVStrPtrInc(op,' ');
			ap = wordScan(ap,op);
		}
		if( *ap == ' ' )
			ap++;
		ovstrcpy(Args,ap);
		ap = Args;
	}
	ap = wordscanX(ap,AVStr(Arg1),LINESIZE);
	ap = linescanX(ap,AVStr(Arg2),LINESIZE);
	return 0;
}
static const char *timefmt = "%y/%m/%d,%H:%M:%S";
int dumpHostCache(FILE *tc);

int setNonblockingFpTimeout(FILE *fp,int toms);
int gzipFilter(FILE *in,FILE *out);
static void gzipF(int tgid,FILE *pin,FILE *out){
	setthreadgid(0,tgid);
	gzipFilter(pin,out);
}
int YSH_SEND_TIMEOUT = 5*1000;
int YSH_THREAD_TIMEOUT = 10*1000;
FILE *gzipfout(FILE *out,FILE **pinp,int *tid){
	int pio[2];
	FILE *pout,*pin;
	int tgid;

	fflush(out); /* seems necessary to flush HTTP header on WinCE */
	pipeX(pio,0x8000);
	*pinp = pin = fdopen(pio[0],"r");
	pout = fdopen(pio[1],"w");
	if( isWindowsCE() ){
		setNonblockingFpTimeout(pout,YSH_SEND_TIMEOUT);
	}
	tgid = getthreadgid(0);
	*tid = thread_fork(0x80000,getthreadgid(0),"gzipFout",(IFUNCP)gzipF,tgid,pin,out);
	if( *tid == 0 ){
		syslog_ERROR("--gzipfout can't fork thread (%d)\n",errno);
		fclose(pout);
		fclose(pin);
		return 0;
	}
	syslog_ERROR("--gzipfout [%d]%X [%d]%X %X\n",
		pio[0],p2i(*pinp),pio[1],p2i(pout),*tid);
	return pout;
}

void putWinStatus(PCStr(fmt),...);
int askWinOKWTO(double dtx,PCStr(fmt),...);
int gzipfclose(FILE *pout,FILE *pin,int tid){
	int terr;
	setthread_FL(0,FL_ARG,"gzipfclose");
	fclose(pout);
	setthread_FL(0,FL_ARG,"gzipfclose");
	terr = thread_wait(tid,YSH_THREAD_TIMEOUT);
	setthread_FL(0,FL_ARG,"gzipfclose");
	if( terr != 0 ){
		dumpthreads("gzipfclose",0);
		sv1log("??? frozen gzip thread %X (%d)\n",PRTID(tid),terr);
		terr = thread_wait(tid,YSH_THREAD_TIMEOUT);
		sv1log(">>> frozen gzip thread %X (%d)\n",PRTID(tid),terr);
	}
	if( terr != 0 ){
		terr = thread_destroy(tid);
		/* don't wait killed (and erased) thread
		thread_kill(tid,9);
		terr = thread_wait(tid,YSH_THREAD_TIMEOUT);
		 */
		sv1log("!!! frozen gzip thread %X (%d)\n",PRTID(tid),terr);
		dumpthreads("gzipfclose",0);
		if( terr != 0 )
		askWinOKWTO(30,"!!! frozen gzip thread %X (%d)",PRTID(tid),terr);
	}
	if( terr == 0 ){
		fclose(pin);
	}else{
		/* should push pin and tid to be waited later */
		fclose(pin);
	}
	return terr;
}

int remoteWinSize(int *w,int *h);
int remoteWinCtrl(FILE *tc,PCStr(com),PCStr(arg),int width,int height,PCStr(query),PCStr(form),PVStr(stat));
int newSocket(PCStr(what),PCStr(opts));
static int conntest(FILE *tc,PVStr(stat)){
	int sock;
	int code;
	double St = Time();
	IStr(host,MaxHostNameLen);
	int port = 80;
	refQStr(sp,stat);
	FILE *ts;
	FILE *fs;
	IStr(resp,256);

	if( isWindowsCE() ){
		strcpy(host,"wince.delegate.org");
	}else{
		strcpy(host,"www.delegate.org");
	}
	sock = newSocket("conntest","");
	code = connectTimeout(sock,host,port,8000);
	if( sock < 0 ){
		sprintf(stat,"Connect Failed (%.2f) %s",Time()-St,host);
		return -1;
	}
	Rsprintf(sp,"Connected (%.2f) >>> %s\r\n",Time()-St,host);
	if( ts = fdopen(sock,"w") ){
		fprintf(ts,"GET /conntest/?ver=%s HTTP/1.0\r\n",DELEGATE_ver());
		fprintf(ts,"User-Agent: DeleGate\r\n");
		fprintf(ts,"\r\n");
		fflush(ts);
		if( fs = fdopen(dup(sock),"r") ){
			while( fgetsTimeout(AVStr(resp),sizeof(resp),fs,100) != NULL ){
				Rsprintf(sp,"%s",resp);
			}
			fclose(fs);
		}
		fclose(ts);
	}else{
		close(sock);
	}
	return 0;
}
static int dnstest(FILE *tc,PVStr(stat)){
	double St = Time();
	IStr(host,MaxHostNameLen);
	IStr(fqdn,MaxHostNameLen);
	int ia;

	/* log RES_DEBUG=-1 */
	if( isWindowsCE() ){
		strcpy(host,"wince.delegate.org");
	}else{
		strcpy(host,"www.delegate.org");
	}
	getFQDN(host,AVStr(fqdn));
	sprintf(stat,"%s %s (%.2fsec.)\n",host,fqdn,Time()-St);
	return 0;
}
typedef struct {
	int	wc_map_width;
	int	wc_map_height;
} WinCtx;
int rwinCtrl(WinCtx *Wx,FILE *tc,PCStr(com),PCStr(arg),PCStr(query),PCStr(form),PVStr(stat)){
	int rcode;
	if( strstr(form,"cmd=ConnTest") ){
		conntest(tc,BVStr(stat));
	}
	if( strstr(form,"cmd=DnsTest") ){
		dnstest(tc,BVStr(stat));
	}
	rcode = remoteWinCtrl(tc,com,arg,Wx->wc_map_width,Wx->wc_map_height,query,form,TVStr(stat));
	return rcode;
}
static void putWinHtml(YshCtx *Ysh,WinCtx *Wx,PCStr(stat)){
	FILE *fc = Fc;
	FILE *tc = Tc;
	const char *com = Com;
	const char *pp;
	IStr(hostname,MaxHostNameLen);
	IStr(clif,MaxHostNameLen);
	int sw_hsi = 0;
	int sw_hwt = 0;
	int sw_req = 0;
	int sw_one = 0;
	int cmd_reset = 0;
	int win_wid = 0;
	IStr(win_title,128);
	IStr(buf,128);

	if( CurEnv ){
		if( strcasestr(OREQ_MSG,"sw_hsi=on") ) sw_hsi = 1;
		if( strcasestr(OREQ_MSG,"sw_hwt=on") ) sw_hwt = 1;
		if( strcasestr(OREQ_MSG,"sw_req=on") ) sw_req = 1;
		if( strcasestr(OREQ_MSG,"sw_one=on") ) sw_one = 1;
		if( strcasestr(OREQ_MSG,"cmd=Reset") ) cmd_reset = 1;
		if( pp = strcasestr(OREQ_MSG,"win_wid=") ) sscanf(pp,"win_wid=%X",&win_wid);
		if( pp = strcasestr(OREQ_MSG,"win_title=") ){
			Xsscanf(pp,"win_title=%[^&]",AVStr(buf));
			URL_unescape(buf,AVStr(win_title),1,0);
		}
	}
	gethostname(hostname,sizeof(hostname));
	HTTP_ClientIF_HP(Conn,AVStr(clif));
	fprintf(tc,"<TITLE>%s / %s</TITLE>\r\n",hostname,clif);
	fprintf(tc,"<FORM METHOD=POST ACTION=.>\r\n");
	fprintf(tc,"<A HREF=.>Refresh</A>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Alt>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Home>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Prev>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Next>\r\n");
	fprintf(tc,"<BR>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Network>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Power>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Proxy>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Access>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Process>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Install>\r\n");
	fprintf(tc,"<BR>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=FontSize>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Small>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Minimize>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Normal>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Hide>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Show>\r\n");
	fprintf(tc,"&nbsp;&nbsp;\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Idle>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Active>\r\n");
	fprintf(tc,"<BR>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=DnsTest>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=ConnTest>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=DialUp>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=HangUp>\r\n");
	fprintf(tc,"<BR>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Reset>\r\n");
	fprintf(tc,"<INPUT type=checkbox name=sw_req %s>show request mssg.\r\n",
		cmd_reset==0&&sw_req?"checked":"");
	fprintf(tc,"<INPUT type=checkbox name=sw_hwt %s>hide window text\r\n",
		cmd_reset==0&&sw_hwt?"checked":"");
	fprintf(tc,"<INPUT type=checkbox name=sw_hsi %s>hide screen image\r\n",
		cmd_reset==0&&sw_hsi?"checked":"");
	fprintf(tc,"<BR>\r\n");
	fprintf(tc,"<INPUT type=submit name=cmd value=Refresh>\r\n");
	fprintf(tc,"<A HREF=scrdump.bmp>ScreenImage(BMP)</A><BR>\r\n");
	fprintf(tc,"<INPUT type=checkbox name=sw_one %s>\r\n",
		cmd_reset==0&&sw_one?"checked":"");
	if( pp = strstr(stat,"WINDOWID=") ){
		sscanf(pp,"WINDOWID=%X",&win_wid);
		if( pp = strstr(stat,"TITLE=") ){
			Xsscanf(pp,"TITLE=%[^;\r\n]",AVStr(win_title));
		}
	}
	if( win_wid ){
		fprintf(tc,"<INPUT type=text name=win_wid value=%X size=8 style=border:0>\r\n",win_wid);
		fprintf(tc,"<INPUT type=text name=win_title value=\"%s\" readonly>\r\n",win_title);
		fprintf(tc,"<INPUT type=text name=win_com size=30>\r\n");
	}
	if( pp = strstr(stat,"SCRSIZE=") ){
		int w = 0,h = 0;
		sscanf(pp,"SCRSIZE=%dx%d",&w,&h);
		if( 0 < w && w < Wx->wc_map_width 
		 || 0 < h && h < Wx->wc_map_height
		){
			Wx->wc_map_width = w;
			Wx->wc_map_height = h;
		}
	}
	fprintf(tc,"<INPUT type=hidden name=map_size value=%d,%d>\r\n",
		Wx->wc_map_width,Wx->wc_map_height);
	fprintf(tc,"<BR>\r\n");
	/*
	fprintf(tc,"<INPUT type=radio name=btn_mode value=single checked>single\r\n");
	fprintf(tc,"<INPUT type=radio name=btn_mode value=double>doble\r\n");
	fprintf(tc,"<INPUT type=radio name=btn_mode value=down>down\r\n");
	fprintf(tc,"<INPUT type=radio name=btn_mode value=up>up\r\n");
	fprintf(tc,"<BR>\r\n");
	*/

	if( sw_req ){
		if( CurEnv ){
			fprintf(tc,"<HR>\n");
			fprintf(tc,"<UL>\n");
			fprintf(tc,"<small><small><PRE>\n");
			fprintf(tc,"%s\n",OREQ_MSG);
			fprintf(tc,"</PRE></small></small>\n");
			fprintf(tc,"</UL>\n");
			fprintf(tc,"<HR>\n");
		}
	}
	if( sw_hwt == 0 ){
		if( *ControlPanelText() ){
			fprintf(tc,"<HR><PRE>\n");
			fprintf(tc,"%s",ControlPanelText());
			fprintf(tc,"</PRE><HR>\n");
		}
	}

	fprintf(tc,"<META HTTP-EQUIV=Set-Cookie CONTENT=sw_hsi=%s>\r\n",
		cmd_reset==0&&sw_hsi?"ON":"OFF");
	fprintf(tc,"<META HTTP-EQUIV=Set-Cookie CONTENT=sw_hwt=%s>\r\n",
		cmd_reset==0&&sw_hwt?"ON":"OFF");
	fprintf(tc,"<META HTTP-EQUIV=Set-Cookie CONTENT=sw_req=%s>\r\n",
		cmd_reset==0&&sw_req?"ON":"OFF");

	if( sw_hsi == 0 ){
		/*
		fprintf(tc,"<A HREF=/-/screen/click>\r\n");
		fprintf(tc,"<IMG BORDER=0 SRC=scrdump.bmp ISMAP width=%d height=%d>\r\n",
			Wx->wc_map_width,Wx->wc_map_height);
		fprintf(tc,"</A>\r\n");
		*/
		fprintf(tc,"<INPUT TYPE=IMAGE SRC=scrdump.bmp ISMAP width=%d height=%d>\r\n",
			Wx->wc_map_width,Wx->wc_map_height);
		fprintf(tc,"<HR>\r\n");
	}

	if( stat[0] ){
		fprintf(tc,"<KBD>\n",stat);
		fprintf(tc,"Stat: %s\n",stat);
		fprintf(tc,"</KBD>\n",stat);
	}
	fprintf(tc,"</FORM>\r\n");
}
static int service_console1(YshCtx *Ysh){
	IStr(buf,LINESIZE);
	int tty = 0;
	int qi;
	IStr(wstat,256);
	refQStr(query,Com);
	int rcode;

	WinCtx Wx = {640,480};
	WinCtx Ws;
	if( remoteWinSize(&Ws.wc_map_width,&Ws.wc_map_height) == 0 ){
		if( Ws.wc_map_width < Wx.wc_map_width ){
			Wx.wc_map_width = Ws.wc_map_width;
			Wx.wc_map_height = Ws.wc_map_height;
		}
	}

	if( fPollIn(Fc,300) == 0 ){
		fprintf(Tc,"-- DeleGate Console: enter help for help\r\n");
		if( Numlog ){
			StrftimeLocal(AVStr(buf),sizeof(buf),timefmt,Lastli,0);
			fprintf(Tc,"-- login(%d) last: %s ",Numlog,buf);
			StrftimeLocal(AVStr(buf),sizeof(buf),timefmt,Lastlo,0);
			fprintf(Tc,"- %s\r\n",buf);
		}
	}
	for( qi = 0; ; qi++ ){
		if( 0 < qi ){
			fflush(Tc);
		}
		if( getYshRequest(Ysh) == EOF ){
			break;
		}
		if( *Com == 0 ){
			if( Ishttp ){
				helpsh(Ysh);
				break;
			}else{
			}
		}
		sv1log("ysh: ls %s\n",Req);
		addhist(Ysh,Req);
		if( streq(Com,"quit")
		 || streq(Com,"exit")
		){
			fprintf(Tc,"-- DeleGate Console: Bye\r\n");
			break;
		}

		if( Ishttp ){
			if( query = strchr(Com,'?') ){
				setVStrPtrInc(query,0);
			}
		}
		if( !Ishttp ){
		    if( AuthOk <= 0 ){
			strcpy(DFLT_PROTO,"ysh");
			CTX_pushClientInfo(Conn);
	if( authenticate(Ysh,Conn,AVStr(buf),0,0,"CONSOLE",&Ident) <= 0 )
			{
				HL_popClientInfo();
				fprintf(Tc,"-- Forbidden (%s)\r\n",buf);
				return -1;
			}
			HL_popClientInfo();
			fprintf(Tc,"-- Approved (%s)\r\n",buf);
		    }
		}
		if( strneq(Com,"help",3) ){
			helpsh(Ysh);
			continue;
		}
		if( strneq(Com,"prompt",3) ){
			strcpy(Prompt,Args);
			continue;
		}
		if( streq(Com,"echo") ){
			if( Ishttp ){
			}else{
				if( *Arg1 == '$' ){
					const char *v1;
					if( v1 = getenv(Arg1+1) ){
						fprintf(Tc,"%s\r\n",v1);
					}
				}else
				fprintf(Tc,"%s\r\n",Args);
			}
			continue;
		}
		if( strneq(Com,"history",2)
		 || streq(Com,"prev")
		 || streq(Com,"next")
		 || streq(Com,"last")
		 || streq(Com,"redo")
		){
			historysh(Ysh);
			continue;
		}
		if( streq(Com,"sleep") ){
			if( fPollIn(Fc,1000*atoi(Arg1)) ){
				if( Fgets(AVStr(Req),LINESIZE,Fc) ){
				}
			}
			continue;
		}
		if( streq(Com,"date")
		 || streq(Com,"uptime")
		 || streq(Com,"time")
		 || streq(Com,"df")
		 || streq(Com,"mf")
		 || streq(Com,"ps")
		){
			statsh(Ysh);
			continue;
		}
		if( streq(Com,"ipush")
		 || streq(Com,"ipop")
		 || streq(Com,"opush")
		 || streq(Com,"opop")
		){
			redirect(Ysh);
			continue;
		}
		if( streq(Com,"remote") ){
			Remote = 1;
			fprintf(Tc,"rpwd = %s\r\n",Rcwd);
			continue;
		}
		if( streq(Com,"local") ){
			Remote = 0;
			fprintf(Tc,"pwd = YSH/%s\r\n",Cwd);
			continue;
		}
		if( Remote ){
			if( streq(Com,"pwd")
			 || streq(Com,"cd")
			 || streq(Com,"ls")
			 || streq(Com,"get")
			){
				Strins(AVStr(Com),"r");
			}else
			if( streq(Com,"lpwd")
			 || streq(Com,"lcd")
			 || streq(Com,"lls")
			 || streq(Com,"lget")
			){
				ovstrcpy(Com,Com+1);
			}
		}
		if( streq(Com,"rpwd") /* ftp or sftp */
		 || streq(Com,"rcd")
		 || streq(Com,"rls")
		 || streq(Com,"rget")
		 || streq(Com,"rput")
		 || streq(Com,"rcat")
		){
			ftpsh(Ysh);
			continue;
		}
		if( streq(Com,"setenv") ){
			envsh(Ysh);
			continue;
		}
		if( strneq(Com,"xterm",5) ){
			/* should set DISPLAY=:0.0 */
			rcode = system("xterm");
			continue;
		}
		if( streq(Com,"make")
		 || streq(Com,"cc")
		){
			continue;
		}
		if( streq(Com,"pwd")
		 || streq(Com,"root")
		 || streq(Com,"cd")
		 || streq(Com,"pushd")
		 || streq(Com,"popd")
		 || streq(Com,"ls")
		 || streq(Com,"cksum")
		 || streq(Com,"md5")
		 || streq(Com,"du")
		 || streq(Com,"find")
		 || streq(Com,"cat")
		 || streq(Com,"head")
		 || streq(Com,"tail")
		 || streq(Com,"grep")
		 || streq(Com,"mv")
		 || streq(Com,"rm")
		 || streq(Com,"cp")
		 || streq(Com,"touch")
		 || streq(Com,"ln")
		 || streq(Com,"mkdir")
		 || streq(Com,"rmdir")
		 || streq(Com,"expire")
		 || streq(Com,"gzip")
		 || streq(Com,"gunzip")
		 || streq(Com,"put")
		){
			filesh(Ysh);
			continue;
		}
		if( streq(Com,"regdump") ){
			regdump_main(0,0,Tc,Tc);
			continue;
		}
		if( strtailstr(Com,"screen/") ){
			const char *form;
			if( Ishttp && query != 0 ){
				form = query;
				if( *form ){
					rwinCtrl(&Wx,Tc,Com,Args,query,form,AVStr(wstat));
				}
			}else
			if( CurEnv && HTTP_methodWithBody(REQ_METHOD) ){
				form = HTTP_originalReqBody(Conn);
				if( *form ){
					rwinCtrl(&Wx,Tc,Com,Args,query,form,AVStr(wstat));
				}
			}
			putWinHtml(Ysh,&Wx,wstat);
			continue;
		}
		if( strstr(Com,"screen/") && strtailstr(Com,".html")
		 || streq(Com,"screen/click")
		){
			const char *form = "";
			if( CurEnv && HTTP_methodWithBody(REQ_METHOD) ){
				form = HTTP_originalReqBody(Conn);
			}
			rwinCtrl(&Wx,Tc,Com,Args,query,form,AVStr(wstat));
			putWinHtml(Ysh,&Wx,wstat);
			/* should be move to screen/ or Refresh: */
			continue;
		}
		if( strstr(Com,"scrdump.") ){
			if( DoGZIP ){
				FILE *gzfp;
				FILE *gzfpi;
				int gtid;
				gzfp = gzipfout(Tc,&gzfpi,&gtid);
				setthread_FL(0,FL_ARG,"dumpScreen");
				dumpScreen(gzfp);
				setthread_FL(0,FL_ARG,"dumpScreen");
				gzipfclose(gzfp,gzfpi,gtid);
				setthread_FL(0,FL_ARG,"dumpScreen");
			}else{
			dumpScreen(Tc);
			}
			break;
		}
		if( streq(Com,"regset") ){
			int setRegVal(FILE *tc,PCStr(name),PCStr(val));
			setRegVal(Tc,Arg1,Arg2);
			continue;
		}
		if( streq(Com,"socket")
		 || streq(Com,"sockopt")
		 || streq(Com,"soclose")
		 || streq(Com,"sobind")
		 || streq(Com,"soaccept")
		 || streq(Com,"soconnect")
		 || streq(Com,"sorelay")
		 || streq(Com,"sojoin")
		){
			socketsh(Ysh);
			continue;
		}
		if( strneq(Com,"where",3) ){
			dumpthreads("where",0);
			dumpWhere(Tc,0);
			continue;
		}
		if( strneq(Com,"version",3)
		 || streq(Com,"-Fver") ){
			Argv[0] = 0;
			myid_mainX(0,Argv,Tc);
			continue;
		}
		if( strneq(Com,"status",3) ){
			LOGX_stats(AVStr(buf),0);
			fprintf(Tc,"%s\r\n",buf);
			continue;
		}
		if( strneq(Com,"spinach",3) ){
			spinach(Conn,Fc,Tc);
			continue;
		}
		if( streq(Com,"load")
		 || streq(Com,"save")
		){
			/* configuration */
			continue;
		}
		if( streq(Com,"ilog") ){
			iLOGdump1(Tc,0);
			continue;
		}
		if( streq(Com,"acth") ){
			extern int AccThread;
			int oacth;
			oacth = AccThread;
			AccThread = !AccThread;
			fprintf(Tc,"AccThread = %d <- %d\r\n",AccThread,oacth);
			continue;
		}
		if( *Com == '-'
		 || strneq(Com,"option",3) && Opts[0] == '-' ){
			if( *Com == '-' )
				setDebugX(Conn,Com,1);
			else	setDebugX(Conn,Opts,1);
			fprintf(Tc,"-- opt %s\r\n",Com);
			fprintf(Tc,"Flags: %08X %08X %08X %08X %08X\r\n",
				LOG_type1,LOG_type2,LOG_type3,LOG_type4,
				LOG_bugs
			);
			continue;
		}
		if( strneq(Com,"capture",3) ){
			capturelog(Ysh);
			continue;
		}
		if( strneq(Com,"bench",2) ){
			bench(Ysh);
			continue;
		}
		if( strneq(Com,"seltest",7) ){
			seltest(Tc);
			continue;
		}
		if( strneq(Com,"hosts",5) ){
			if( strstr(Com,"sort") || strstr(Args,"sort") ){
				int SortCachedHosts();
				SortCachedHosts();
			}
			if( strstr(Com,"expire") || strstr(Args,"expire") ){
				int ox = HOSTS_expired;
				int nx = time(0);
				HOSTS_expired = nx;
				fprintf(Tc,"-- set HOSTS_expired = %X <- %X\n",
					nx,ox);
			}else
			dumpHostCache(Tc);
			continue;
		}
		if( strneq(Com,"alog",4) ){
			int putAbortLog(FILE *fp);
			putAbortLog(Tc);
			continue;
		}
		if( streq(Com,"") ){
			continue;
		}
		fprintf(Tc,"-- Unknown command\n");
	}
	return 0;
}
int console_main(int ac,const char *av[]){
	return 0;
}
static int checkport(Connection *XConn);
int ShutdownSocket(int sock);
int service_console(Connection *XConn){
	YshCtx *Ysh;
	FILE *cfp;
	int lastli = time(0);
	int off,crc;

	if( HTTP_authok(XConn) ){
	}else
	if( checkport(XConn) != 0 )
		return -1;
	if( !source_permittedX(XConn) ){
		return -1;
	}
	Ysh = (YshCtx*)malloc(sizeof(YshCtx));
	bzero(Ysh,sizeof(YshCtx));
	sprintf(Req,"%s/yshctx.txt",ADMDIR());
	cfp = fopen(Req,"r");
	crc = -1;
	off = sizeof(Pstcrc);
	if( cfp ){
		loadYshCtx(Ysh,cfp);
		fclose(cfp);
		crc = strCRC32(((char*)&YshPst)+off,sizeof(YshPst)-off);
		if( crc != Pstcrc ){
			daemonlog("F","Ysh: broken context? %X %X\n",
				crc,Pstcrc);
		}
	}
	if( Numlog == 0 ){
		bzero(Ysh,sizeof(YshCtx));
		addhist(Ysh,"");
		addhist(Ysh,"Initialized");
		strcpy(Prompt,"ysh> ");
		Capsec = 60;
		Caplns = 1000;
		Created = time(0);
	}
	strcpy(Root,DELEGATE_DGROOT);
	Conn = XConn;
	Fc = fdopen(FromC,"r");
	Tc = fdopen(ToC,"w");

	service_console1(Ysh);
	fflush(Tc);
	set_linger(fileno(Tc),5);
	ShutdownSocket(fileno(Tc));

	Lastli = lastli;
	Lastlo = time(0);
	Numlog++;
	Pstcrc = strCRC32(((char*)&YshPst)+off,sizeof(YshPst)-off);

	sprintf(Req,"%s/yshctx.txt",ADMDIR());
	cfp = fopen(Req,"w");
	if( cfp ){
		saveYshCtx(Ysh,cfp);
		fclose(cfp);
	}else{
	}

	if( lMULTIST() ){
		fcloseFILE(Tc);
		fcloseFILE(Fc);
	}else{
		fclose(Tc);
		fclose(Fc);
	}
	free(Ysh);
	return 0;
}


#undef Conn

static int checkport(Connection *Conn){
	IStr(path,1024);

	sprintf(path,"SERVER=%s -P%d/ysh %s:%d <= %s:%d",
		iSERVER_PROTO,
		Console_Port,CLIF_HOST,CLIF_PORT,Client_Host,Client_Port);
	sv1log("Ysh %s\n",path);
	if( !streq(iSERVER_PROTO,"console") )
	if( !streq(iSERVER_PROTO,"ysh") )
	if( CLIF_PORT != Console_Port ){
		daemonlog("F","Ysh forbidden on non-Console port: %s\n",path);
		return -1;
	}
	return 0;
}
