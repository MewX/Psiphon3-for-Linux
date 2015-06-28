/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	dget.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940206	extracted from urlfind.c
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include "ystring.h"
#include "url.h"
#include "delegate.h"
#include "filter.h"
#include "http.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"
#include "auth.h"
#include "credhy.h"
#include "vsignal.h"

extern int CHILD_SERNO;
extern int CHILD_SERNO_MULTI;
const char *DELEGATE_getEnv(PCStr(name));
char *fgetsTIMEOUT(xPVStr(b),int s,FILE *fp);

const char *strid_find(int tab,int hx,int id);
int connect2server(Connection *Conn,PCStr(proto),PCStr(host),int port);
FileSize CTX_file_copy(Connection *Conn,FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary);

void tar_scan(FILE *ifp,FILE *ofp,FILE *msg,PCStr(opts),PCStr(tarfile),const char *files[],PCStr(edits));

FILE *ftp_fopen(Connection *Conn,int put,int server,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),PVStr(resp),int rsize,int *isdirp,FILE *fsc);
FILE *ftp_fopen0(int put,int svsock,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),PVStr(resp),int rsize,int *isdirp);

static const char *usage = "\
Usage: urlfind URL\n\
    -- Find recursively in URL space.\n\
";
static const char *arg1spec = "\
Argument specification error:\n\
   The first argument should be URL as follows:\n\
      protocol://host\n\
      protocol://host:port\n\
      protocol://host/path\n\
      protocol://host:port/path\n\
";

typedef struct {
	int	de_NoCache;
	int	de_MaxAge;
	int	de_PutHead;
	int	de_PutBody;
	FILE   *de_putBodyFp;
	float	de_ResWait;
	int	de_KeepAlive;
	int	de_dontKeepAlive;
	MStr(	de_AccEncode,64);
	int	de_Decode;
	int	de_SendCookie;
	int	de_Interval;
	int	de_SendOnly;
	int	de_BeSilent;
	int	de_StatCodeOnly;
	int	de_Http11;
	int	de_Recursive;
	int	de_PrematureEOF;
	MStr(	de_MOptions,128);
	int	de_Verify;
	int	de_Vcode;
	int	de_URLgot;
	int	de_URLgetx;
	int	de_URLgotx;
  const char   *de_TarOpt;
  const	char   *de_TarFiles[2]; /**/
	MStr(	de_Host,MaxHostNameLen);
	MStr(	de_Headers,1024);
	int	de_noHost;
	int	de_toProxy;
	int	de_xcode;
	int	de_isChild;
	int	de_Sync[2];
	int	de_Npara;
	int	de_Pi;
	int	de_Nrepeat;
	MStr(	de_Sockname,128);
	MStr(	de_Servname,128);
} DgetEnv;
static DgetEnv *dgetEnv;
#define NoCache		dgetEnv->de_NoCache
#define MaxAge		dgetEnv->de_MaxAge
#define PutHead		dgetEnv->de_PutHead
#define PutBody		dgetEnv->de_PutBody
#define putBodyFp	dgetEnv->de_putBodyFp
#define ResWait		dgetEnv->de_ResWait
#define KeepAlive	dgetEnv->de_KeepAlive
#define dontKeepAlive	dgetEnv->de_dontKeepAlive
#define AccEncode	dgetEnv->de_AccEncode
#define Decode		dgetEnv->de_Decode
#define SendCookie	dgetEnv->de_SendCookie
#define Interval	dgetEnv->de_Interval
#define SendOnly	dgetEnv->de_SendOnly
#define BeSilent	dgetEnv->de_BeSilent
#define StatCodeOnly	dgetEnv->de_StatCodeOnly
#define Http11		dgetEnv->de_Http11
#define Recursive	dgetEnv->de_Recursive
#define PrematureEOF	dgetEnv->de_PrematureEOF
#define MOptions	dgetEnv->de_MOptions
#define Verify		dgetEnv->de_Verify
#define Vcode		dgetEnv->de_Vcode
#define URLgot		dgetEnv->de_URLgot
#define URLgetx		dgetEnv->de_URLgetx
#define URLgotx		dgetEnv->de_URLgotx
#define TarOpt		dgetEnv->de_TarOpt
#define TarFiles	dgetEnv->de_TarFiles
#define Host		dgetEnv->de_Host
/**/
#define Headers		dgetEnv->de_Headers
#define noHost		dgetEnv->de_noHost
#define ToProxy		dgetEnv->de_toProxy
#define Xcode		dgetEnv->de_xcode
#define isChild		dgetEnv->de_isChild
#define Sync		dgetEnv->de_Sync
#define Npara		dgetEnv->de_Npara
#define Pi		dgetEnv->de_Pi
#define Nrepeat		dgetEnv->de_Nrepeat
#define Sockname	dgetEnv->de_Sockname
#define Servname	dgetEnv->de_Servname

void minit_dget()
{
	if( dgetEnv == 0 )
		dgetEnv = NewStruct(DgetEnv);
}

static FileSize http1(Connection *XConn,int nr,FILE *ts,FILE *fs,PCStr(proto),PCStr(host),int port,PCStr(path),PVStr(result));

static void connect1(FILE *ts,FILE *fs,PCStr(site))
{	CStr(H,128);
	CStr(resp,128);
	int P;

	P = scan_hostport("https",site,AVStr(H));
	fprintf(ts,"CONNECT %s:%d HTTP/1.0\r\n\r\n",H,P);
	fflush(ts);
	while( fgets(resp,sizeof(resp),fs) != NULL ){
		fprintf(stderr,"%s",resp);
		if( *resp == '\r' || *resp == '\n' )
			break;
	}
}

static char HTTP_Auth[128];
static char HTTP_proxyAuth[128];
extern int CON_TIMEOUT;
static int Xcksum;
static int Xleng;
static int Xrepeat;

static FileSize recvfile1(Connection *Conn,FILE *fp){
	FileSize rcc = 0;
	FileSize prcc;
	int nrec = 0;
	int rc1;
	CStr(buf,0x10000);
	CStr(msg,128);
	double start,prev,now;
	double mean;
	int cksum = 0;
	int ri;

	start = prev = Time();
	prcc = 0;

	if( Xrepeat <= 1 ){
		if( Pi ) fprintf(stderr,"#%-2d ",Pi-1);
	fprintf(stderr,"%8s %7s %14s %9s\n","recv#","time","total-bytes","bytes/s");
	}
	setNonblockingIO(fileno(fp),1);
	for( nrec = 0; rc1 = freadTIMEOUT(AVStr(buf),1,sizeof(buf),fp); nrec++ ){
		EmiUpdateMD5(Conn,buf,rc1);

		for( ri = 0; ri < rc1; ri++ ){
			cksum ^= buf[ri];
		}
		now = Time();
		rcc += rc1;
		/*
		if( 2 <= now - prev ){
		*/
		if( 1 <= now - prev ){
			/*
			sprintf(msg,"%14lld %9d",rcc,
				(int)(rcc/(now<start?now-start:0.001)));
			*/
			if( start < now )
				mean = rcc / (now - start);
			else	mean = rcc / 0.001;
			sprintf(msg,"%14lld %9.0f",rcc,mean);

	if( Xrepeat <= 1 ){
				if( Pi ) fprintf(stderr,"#%-2d ",Pi-1);
			fprintf(stderr,"%8d %7.1f %s\n",nrec,now-start,msg);
	}
			prev = now;
			prcc = rcc;
		}
	}
	now = Time();
	/*
	sprintf(msg,"%14lld %9d",rcc,(int)(rcc/(now<start?now-start:0.001)));
	*/
	if( start < now )
		mean = rcc / (now - start);
	else	mean = rcc / 0.001;
	sprintf(msg,"%14lld %9.0f",rcc,mean);
	if( Xrepeat <= 1 ){
		if( Pi ) fprintf(stderr,"#%-2d ",Pi-1);
	fprintf(stderr,"%8d %7.1f %s\n",nrec,now-start,msg);
	}

	Xcksum = 0xFF & cksum;
	Xleng = rcc;
	return rcc;
}

#define SYNCH	"$"
static int waits(int nrepeat){
	double Start;
	CStr(buf,1024);
	FILE *lapi;
	int li,lo;
	int ci;

	Start = Time();
	close(Sync[0]);

	/* wait children to be ready */
	for( ci = 0; ci < Npara; ci++ ){
		if( PollIn(Sync[1],1000) <= 0 ){
			break;
		}
		if( read(Sync[1],buf,1) <= 0 ){
			break;
		}
		if( buf[0] != SYNCH[0] )
			break;
	}
	/* start children */
	IGNRETP write(Sync[1],"",1);

	lo = 0;
	lapi = fdopen(Sync[1],"r+");
	for( li = 1; fgets(buf,sizeof(buf),lapi); li++ ){
		double t1 = Time() - Start;
		if( buf[0] == '+' ){
			lo++;
			fprintf(stderr,"%7.2f %4d %5.2f %s",
				t1,lo,lo/t1,buf);
		}else{
			fprintf(stderr,"%s",buf);
		}
	}
	for(;;){
		int xpid;
		xpid = wait(0);
		if( xpid < 0 ){
			break;
		}
	}
	fprintf(stderr,"DONE %d/%d %.3fs %.3f/s\n",
		lo,(nrepeat*Npara),Time()-Start,
		lo/(Time()-Start));
	exit(0);
	return 0;
}
int dget_main1(int ac,const char *av[],Connection *Conn);
static int dget1(Connection *Conn,int cs,int sy,int ac,const char *av[],PCStr(args)){
	int ai,ax,ay;
	int nac;
	const char *nav[32];
	CStr(argb,1024);
	const char *arg;

	minit_dget();
	isChild = 1;
	Npara = 1;

	close(cs);
	IGNRETP write(sy,SYNCH,1);
	PollIn(sy,10*1000);
	Sync[0] = sy;
	Sync[1] = -1;

	nac = decomp_args(nav,elnumof(nav),args,AVStr(argb));
	for( ai = 0; ai < nac; ai++ ){
		arg = nav[ai];
		if( strneq(arg,"-p",2) ){
			Npara = atoi(arg+2);
		}else
		if( strneq(arg,"#p",2) ){
			Pi = atoi(arg+2);
			CHILD_SERNO = Pi;
		}
	}
	dget_main1(nac,nav,Conn);
	return 0;
}

int comp_args(PVStr(ab),int ac,const char *av[]);
int setDebugX(Connection *XConn,PCStr(arg),int force);

int dget_main(int ac,const char *av[],Connection *Conn){
	int ai;
	const char *arg;
	int nrepeat = 1;
	int ci;
	int nofork = !INHERENT_fork();

	minit_dget();
	if( ac < 2 ){
		fprintf(stderr,"Usage: %s [PROXY=host:port] [url] [-o]\r\n",
			av[0]);
		exit(0);
	}
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( arg[0] == '-' && isdigit(arg[1]) ){
			nrepeat = atoi(&arg[1]);
		}else
		if( strneq(arg,"-p",2) ){
			Npara = atoi(arg+2);
			Socketpair(Sync);
			set_linger(Sync[0],10);
		}else
		if( streq(arg,"-x") ){
			nofork = 1;
		}
	}
	if( 1 <= Npara && nofork ){
		IStr(args,1024);
		refQStr(ap,args);
		comp_args(AVStr(args),ac,av);
		ap = args + strlen(args);
		for( ci = 0; ci < Npara; ci++ ){
			sprintf(ap," #p%d",ci+1);
			execFunc(Conn,Sync[1],Sync[0],(iFUNCP)dget1,args);
		}
		waits(nrepeat);
	}else{
		dget_main1(ac,av,Conn);
	}
	return 0;
}

int decomp_siteX(PCStr(proto),PCStr(site),AuthInfo *ident);
FILE *ftp_fopen(Connection *Conn,int put,int server,PCStr(host),PCStr(user),PCStr(pass),PCStr(path),PVStr(resp),int rsize,int *isdirp,FILE *fsc);
int dput_main(int ac,const char *av[],Connection *Conn){
	int ai;
	const char *arg;
	const char *url = "";
	IStr(proto,32);
	IStr(site,256);
	IStr(path,1024);
	IStr(host,256);
	int port;
	AuthInfo ident;
	IStr(user,128);
	IStr(pass,128);
	IStr(resp,1024);
	int svsock;
	FILE *fs;
	FILE *fp;
	FILE *in = stdin;
	int isdir;
	int upsiz;
	double St1,St2;
	int rdy;

	if( ac < 2 ){
		fprintf(stderr,"Usage: %s [PROXY=host:port] [url]\r\n",
			av[0]);
		exit(0);
	}
	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( arg[0] == '-' ){
		}else{
			url = arg;
		}
	}
	decomp_absurl(url,AVStr(proto),AVStr(site),AVStr(path),sizeof(path));
	port = decomp_siteX(proto,site,&ident);
	strcpy(host,ident.i_Host);
	strcpy(user,ident.i_user);
	strcpy(pass,ident.i_pass);
	set_realserver(Conn,proto,host,port);
	Conn->from_myself = 1;
	svsock = connect_to_serv(Conn,FromC,ToC,0);
	fprintf(stderr,"----[%d] %s://%s:%d (%s)\n",
		svsock,DST_PROTO,DST_HOST,DST_PORT,user);
	if( svsock < 0 ){
		return -1;
	}
	fs = fdopen(svsock,"r");
	if( fs == NULL ){
		return -1;
	}
	if( streq(proto,"ftp") ){
		if( user[0] == 0 ){
			strcpy(user,"anonymous");
		}
		fp = ftp_fopen(Conn,1,svsock,host,user,pass,path,
			AVStr(resp),sizeof(resp),&isdir,fs);
		if( fp ){
			St1 = Time();
			upsiz = copyfile1(in,fp);
			fclose(fp);
			St2 = Time();
			rdy = PollIn(svsock,3*1000);
			fprintf(stderr,"----uploaded %d %s://%s:%d (%s)\n",
				upsiz,DST_PROTO,DST_HOST,DST_PORT,user);
		}else{
			fprintf(stderr,"----[%X] %s://%s:%d (%s)\n",
				p2i(fp),DST_PROTO,DST_HOST,DST_PORT,user);
		}
	}
	return 0;
}

static void sigPIPE(int sig){
	fprintf(stderr,"--[%d.%X] got SIGPIPE [%s]<-[%s]\n",
		getpid(),getthreadid(),Servname,Sockname);
	signal(SIGPIPE,sigPIPE);
}

static void insertNTHT(Connection *Conn,int withPROXY,PCStr(proto),PCStr(paddr),int pport,PCStr(upath)){
	IStr(req,256);
	IStr(head,4*1024);
	IStr(au,256);
	IStr(us,256);
	IStr(ps,256);
	int hcode;
	int rcc;

	get_MYAUTH(Conn,AVStr(au),"http",paddr,pport);
	if( withPROXY )
		sprintf(req,"HEAD %s://%s:%d%s HTTP/1.0\r\n",
			proto,paddr,pport,upath);
	else	sprintf(req,"HEAD /%s HTTP/1.0\r\n",upath);
	Xsscanf(au,"%[^:]:%s",AVStr(us),AVStr(ps));
	hcode = NTHT_connect(withPROXY,ToS,FromS,req,head,us,ps,0,"");
	fprintf(stderr,"----NTHT [%d] hcode=%d\n",FromS,hcode);
	while( 0 < PollIn(FromS,500) ){
		rcc = read(FromS,head,sizeof(head));
		if( rcc <= 0 )
			break;
		fprintf(stderr,"----NTHT %d\n",rcc);
		fwrite(head,1,rcc,stderr);
		/* should save WWW-Authenticate ... */
	}
	fprintf(stderr,"----NTHT [%d] hcode=%d DONE\n",FromS,hcode);
}

const char *scan_arg1(Connection *Conn,PCStr(ext_base),PCStr(arg));
int dget_main1(int ac,const char *av[],Connection *Conn){
	const char *proxy;
	CStr(phost,128);
	const char *paddr;
	CStr(paddrb,64);
	int pport;
	int ai,un,ux,nrepeat,nr;
	const char *arg;
	const char *urls[256]; /**/
	CStr(url,URLSZ);
	const char *dp;
	const char *u1;
	int svsock,num;
	FileSize total;
	CStr(date,128);
	double time0,Start,Time0,TTime,Max,Min;
	CStr(type,128);
	FILE *ts,*fs;
	FileSize leng;
	float intvl;
	CStr(proto,256);
	CStr(site,1024);
	CStr(upath,1024);
	CStr(noproxy,URLSZ);
	int withPROXY;
	int doNTHT = 0;
	double Prev;
	int prev;
	CStr(furl,4*1024);
	int viaSOCKS = 0;
	FILE *lap = stderr;
	int ppid = 0;
	int oKeepAlive = 0;
	int shutdown = 0;

	nrepeat = 1;
	proxy = NULL;
	un = 0;
	strcpy(proto,"http");
	signal(SIGPIPE,sigPIPE);

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];

		if( arg[0] == '-' && isdigit(arg[1]) ){
			nrepeat = atoi(&arg[1]);
			Xrepeat = nrepeat;
		}else
		if( strneq(arg,"-p",2) ){
		}else
		if( strneq(arg,"#p",2) ){
		}else
		if( strneq(arg,"-x",2) ){
		}else
		if( strncmp(arg,"-i",2) == 0 ){
			intvl = 0;
			sscanf(&arg[2],"%f",&intvl);
			Interval = (int)(intvl * 1000);
		}else
		if( strncmp(arg,"-w",2) == 0 ){
			sscanf(&arg[2],"%f",&ResWait);
		}else
		if( strncmp(arg,"-c",2) == 0 ){
			if( arg[2] == '0' ){
				MaxAge = atoi(arg+2)+1;
			}else
			NoCache = 1;
		}else
		if( strcmp(arg,"-h") == 0 ){
			PutHead = 1;
		}else
		if( strcmp(arg,"-o") == 0 ){
			PutBody = 1;
			putBodyFp = stdout;
		}else
		if( strcmp(arg,"-O") == 0 ){
			PutBody = 3;
			putBodyFp = stdout;
		}else
		if( strneq(arg,"-D",2) ){
			setDebugX(Conn,arg,1);
		}else
		if( strneq(arg,"--E",3) ){
			setDebugX(Conn,arg+1,1);
		}else
		if( strneq(arg,"-E",2) ){
			setDebugX(Conn,arg,1);
		}else
		if( strneq(arg,"-XD",3) ){
			Decode = 1;
		}else
		if( strneq(arg,"-XE",3) ){
			PrematureEOF = 1 + atoi(arg+3);
		}else
		if( strcmp(arg,"-r") == 0 ){
			Recursive = 1;
			URLgot = strid_create(0x10000);
		}else
		if( strncmp(arg,"-V",2) == 0 ){
			Verify = 1;
			if( strchr(arg+2,'@') ){
				sprintf(MOptions,"verify=rsa:%s",arg+2);
			}else{
				sprintf(MOptions,"verify=rsa");
				if( arg[2] ){
					CStr(md5,64);
					toMD5(arg+2,md5);
					Xsprintf(TVStr(MOptions),
						",verify=pass:MD5:%s",md5);
				}
			}
		}else
		if( strncmp(arg,"-tar",4) == 0 ){
			TarOpt = arg + 4;
			TarFiles[0] = "*";
			TarFiles[1] = 0;
		}else
		if( strncmp(arg,"-H",2) == 0 ){
			if( arg[2] == 0 )
			noHost = 1;
			else	strcpy(Host,arg+2);
		}else
		if( strncmp(arg,"-C",2) == 0 ){
			SendCookie = atoi(arg+2);
		}else
		if( strncmp(arg,"-add-head:",10) == 0 ){
			strcat(Headers,arg+10);
			strcat(Headers,"\r\n");
		}else
		if( strcmp(arg,"-K") == 0 ){
			dontKeepAlive = 1;
		}else
		if( strcmp(arg,"-k") == 0 ){
			KeepAlive = 1;
		}else
		if( strncmp(arg,"-e",2) == 0 ){
			wordScan(arg+2,AccEncode);
		}else
		if( strcmp(arg,"-so") == 0 ){
			SendOnly = 1;
		}else
		if( strcmp(arg,"-s") == 0 ){
			StatCodeOnly = 1;
		}else
		if( strcmp(arg,"-S") == 0 ){
			BeSilent = 1;
		}else
		if( strneq(arg,"-shutdown",9) ){
			shutdown = atoi(arg+9);
		}else
		if( strcmp(arg,"-v1.1") == 0 ){
			Http11 = 1;
			KeepAlive = 1;
			HTTP11_toserver = 3;
		}else
		if( strncmp(arg,"-u",2) == 0 ){
			int bsiz;
			bsiz = atoi(arg+2);
			setbuffer(stdout,NULL,bsiz);
		}else
		if( strneq(arg,"-f",2)
		){
			scan_arg1(Conn,"",arg);
		}else
		if( arg[0] == '-' ){
			fprintf(stderr,"Unknown option: %s\n",arg);
		}else
		if( strncmp(arg,"FSV=",4) == 0 ){
		}else
		if( strncmp(arg,"STLS=",5) == 0 ){
		}else
		if( strncmp(arg,"NTHT",4) == 0 ){
			doNTHT = 1;
		}else
		if( strncmp(arg,"MYAUTH=",7) == 0 ){
		}else
		if( strheadstrX(arg,"SSLTUNNEL=",0) ){
		}else
		if( strncmp(arg,"CONNECT=",8) == 0 ){
		}else
		if( strncmp(arg,"MASTER=",7) == 0 ){
		}else
		if( strncmp(arg,"YYMUX=",6) == 0 ){
		}else
		if( strncmp(arg,"MASTER=",7) == 0 ){
		}else
		if( strncmp(arg,"SOCKS=",6) == 0 ){
			viaSOCKS = 1;
		}else
		if( strncmp(arg,"PROXY=",6) == 0 ){
			ToProxy = 1;
			proxy = arg + 6;
		}else{
			if( elnumof(urls) <= un ){
				fprintf(stderr,"*** too many URLs (%d)\n",un);
			}else{
				urls[un++] = arg;
			}
		}
	}

	/*
	if( proxy == NULL )
		proxy = getenv("PROXY");
	*/
	proxy = DELEGATE_getEnv("PROXY");
	if( proxy != NULL )
		withPROXY = 1;
	else	withPROXY = 0;

/*
	if( proxy == NULL ){
		fprintf(stderr,
	"PROXY=host:port should be given by environment or parameger.\n");
		exit(1);
	}
*/
	if( proxy != NULL )
	if( Xsscanf(proxy,"%[^:]:%d",AVStr(phost),&pport) != 2 ){
		fprintf(stderr,"Illegal specification PROXY=%s\n",proxy);
		exit(2);
	}

	time0 = Time();

	if( 0 < Npara ){
		if( !isChild ){
			int pi;
			int me = getpid();
			for( pi = 0; pi < Npara; pi++ ){
				if( Fork("dget-para") == 0 ){
					ppid = getppid();
					Pi = pi + 1;
					CHILD_SERNO = Pi;
					close(Sync[1]);
					IGNRETP write(Sync[0],SYNCH,1);
					PollIn(Sync[0],10*1000);
					break;
				}
			}
			if( getpid() == me ){
				waits(nrepeat);
				return 0;
			}
		}
		lap = fdopen(Sync[0],"w+");
	}

	num = 0;
	total = 0;
	ts = fs = NULL;

	ux = 0;
	svsock = -1;

	TTime = Min = Max = 0;
	if( BeSilent ){
		CON_TIMEOUT = 1;
	}

	oKeepAlive = KeepAlive;
	for(;;){
		if( Recursive && URLgotx < URLgetx ){
			u1 = strid_find(URLgot,0,URLgotx);
			URLgotx++;
			fprintf(stderr,"-- %4d %s\n",URLgotx,u1);
			strcpy(url,u1);
		}else
		if( 0 < un ){
			if( un <= ux )
				break;
			strcpy(url,urls[ux++]);
		}else{
			if( fgets(url,sizeof(url),stdin) == NULL )
				break;
			if( dp = strpbrk(url,"\r\n") )
				truncVStr(dp);
			if( url[0] == '#' )
				continue;
		}
		strcpy(furl,url);
		if( !withPROXY ){
			decomp_absurl(url,AVStr(proto),AVStr(site),AVStr(upath),sizeof(upath));
			pport = scan_hostport(proto,site,AVStr(phost));
			if( pport == 0 ){
				fprintf(stderr,"? %s\n",url);
				exit(-1);
			}
			if( Host[0] == 0 )
			strcpy(Host,site);
			sprintf(noproxy,"%s:%d",phost,pport);
			proxy = noproxy;
			sprintf(url,"/%s",upath);
			if( !StatCodeOnly ){
				if( Npara ){
				fprintf(lap,"#%-2d [%d] ",Pi-1,getpid());
				}
			fprintf(lap,"%s [%s] %s\n",proto,noproxy,url);
				fflush(lap);
			}
		}
		if( doNTHT ){
		}else{
			if( streq(proto,"https") )
		get_MYAUTH(Conn,FVStr(HTTP_Auth),"https",phost,pport);
			else
		get_MYAUTH(Conn,FVStr(HTTP_Auth),"http",phost,pport);
		get_MYAUTH(Conn,FVStr(HTTP_proxyAuth),"http-proxy",phost,pport);
		}
		paddr = gethostaddr(phost);
		if( streq(proto,"https") ){ /* with SSLTUNNEL=... */
			/* to put CONNECT "name:port" rather than "add:port"
			 * it should be so with PROXY=...
			 */
			strcpy(paddrb,phost);
		}else
		if( viaSOCKS ){
			strcpy(paddrb,phost);
		}else
		if( paddr )
			strcpy(paddrb,paddr);
		else	strcpy(paddrb,phost);

		if( streq(proto,"https") && Host[0] ){ /* for SNI */
			static CStr(senv,128);
			CStr(env,128);
			refQStr(dp,env);
			sprintf(env,"SERVER_NAME=%s",Host);
			if( dp = strchr(env,':') )
				setVStrEnd(dp,0);
			if( !streq(senv,env) ){
				strcpy(senv,env);
				putenv(senv);
			}
		}

		Prev = Time();
		prev = -1;

		gethostintMin(phost); /* to enable retry on refuse */
		sethostcache_predef(phost,NULL,0,0);

		for( nr = 0; nr < nrepeat; nr++ ){
			if( 0 < nr && 0 < ppid )
			if( procIsAlive(ppid) == 0 ){
				syslog_ERROR("the parent[%d] dead\n",ppid);
				_exit(0);
			}
			type[0] = 0;
			Start = Time();
			num++;
			Nrepeat = nr+1;
			CHILD_SERNO_MULTI++;
			/*
			if( svsock < 0 )
				svsock = client_open("URLFIND",
					proto,phost,pport);
			*/
			paddr = paddrb;
			ToSX = -1;
			ServerSockX = -1;
			if( svsock < 0 ){
			if( paddr )
			svsock = connect2server(Conn,proto,paddr,pport);
			else
			svsock = connect2server(Conn,proto,phost,pport);
			}
			if( doNTHT && nr == 0 && streq(proto,"http") ){
				insertNTHT(Conn,withPROXY,proto,paddr,pport,upath);
			}
			if( GatewayPath ){
				free((char*)GatewayPath);
				GatewayPath = 0;
			}
			proc_title("dget %s",furl);

			strcpy(Sockname,"");
			if( svsock < 0 ){
				Xcode = 9;
				fprintf(lap,
				"cannot connect to PROXY=%s (%4.1fs) err=%d\n",
					proxy,Time()-Start,errno);
				if( BeSilent ){
					if( Time()-Start < CON_TIMEOUT )
						break;
				}else
				if( Interval == 0 )
					break;
				leng = 0;
			}else{
				int svs;
				if( 0 <= ServerSockX ){
					svs = ServerSockX;
				}else
				if( 0 <= ToSX )
					svs = ToSX;
				else	svs = svsock;
				gethostName(svs,AVStr(Sockname),"%A:%P");
				getpeerName(svs,AVStr(Servname),"%A:%P");

if( LOG_VERBOSE )
fprintf(stderr,"----dget-sock[%c][%d] SS[%d]SX[%d] TS[%d]TX[%d] %s <= %s\n",
ConnType?ConnType:' ',svs,ServerSock,ServerSockX,ToS,ToSX,Servname,Sockname);

				if( ServerFlags & PF_STLS_DO )
				if((ServerFlags & (PF_SSL_ON|PF_STLS_ON)) == 0){
					sv1log("##reset STLS %X\n",ServerFlags);
					ServerFlags &= ~PF_STLS_CHECKED;
					/* to insert implicit SSL */
				}

				if( streq(proto,"ftps") ){
					ServerFlags |= PF_SSL_IMPLICIT;
				}
				willSTLS_SV(Conn);

				if( ts == NULL ){
					ts = fdopen(svsock,"w");
					fs = fdopen(svsock,"r");
					if( ts == NULL | fs == NULL ){
		fprintf(stderr,"---- cannot open ts=%X fs=%X\n",p2i(ts),p2i(fs));
						break;
					}
				}
				if( strncmp(url,"https://",8) == 0 ){
					connect1(ts,fs,url+8);
				}
				if( PutBody & 2 ){
					CStr(path,1024);
					static int serno;
					if( putBodyFp && putBodyFp != stdout )
						fclose(putBodyFp);
					sprintf(path,"/tmp/dget-%d.%d",
						getpid(),serno++);
					putBodyFp = fopen(path,"w");
				}else{
					putBodyFp = stdout;
				}
				EmiSetupMD5(Conn,"dget");

/*
if( (proxy == NULL || proxy == noproxy) && strcmp(proto,"ftp") == 0 ){
*/
if( (proxy == NULL || proxy == noproxy)
 && (streq(proto,"ftp") || streq(proto,"ftps") || streq(proto,"ftpS")) ){
	FILE *dfp;
	CStr(resp,1024);
	int isdir;
	CStr(auth,128);
	const char *user;
	const char *pass;

	if( get_MYAUTH(Conn,AVStr(auth),"ftp",phost,pport) ){
		user = auth;
		if( pass = strchr(auth,':') ){
			truncVStr(pass); pass++;
		}else	pass = "";
	}else{
		user = "anonymous";
		pass = getADMIN();
	}


	/*
	if( streq(proto,"ftpS") ){
		ServerFlags |= PF_SSL_IMPLICIT;
		ServerFlags |= PF_STLS_SSL;
	}
	*/

	dfp = ftp_fopen(Conn,0,svsock,phost,
		user,pass,url,AVStr(resp),sizeof(resp),&isdir,NULL);

	if( streq(proto,"ftpS") && (ServerFlags & PF_SSL_ON) ){
		Connection dataConn;
		int FTP_dataSTLS_FSV(Connection *Conn,Connection *dataConn,int svdata);
		dataConn = *Conn;
		{	Connection *Conn = &dataConn;
			ServerFlags = 0;
			ClientFlags = 0;
			ToS = FromS = fileno(dfp);
		}
		ServerFlags |= PF_STLS_ON;
		FTP_dataSTLS_FSV(Conn,&dataConn,fileno(dfp));
	}

	/*
	dfp = ftp_fopen0(0,svsock,phost,
		user,pass,url,AVStr(resp),sizeof(resp),&isdir);
	*/
	strcpy(type,"application/octetstream");
	if( dfp != NULL ){
		if( TarOpt ){
			tar_scan(dfp,stdout,stderr,TarOpt,"-",TarFiles,NULL);
		}else
		if( PutBody )
			if( EmiActive(Conn) ){
			total += leng = CTX_file_copy(Conn,dfp,putBodyFp,0,0,0);
			}else
			total += leng = copyfile1(dfp,putBodyFp);
		else	total += leng = recvfile1(Conn,dfp);
		/*
		else	total += leng = copyfile1(dfp,fdopen(openNull(1),"w"));
		*/
	}else{
		total += leng = 0;
	}
	KeepAlive = 0;
}else
if( Recursive && !withPROXY ){
total += leng = http1(Conn,nr,ts,fs,"http",phost,pport,url,AVStr(type));
}else{
total += leng = http1(Conn,nr,ts,fs,"http","-",0,url,AVStr(type));
 }
				if( EmiActive(Conn) ){
					IStr(md5a,64);
					EmiFinishMD5(Conn,md5a,leng);
					EmiPrintMD5(Conn,AVStr(md5a));
					fprintf(stderr,"## MD5=%s leng=%lld\n",md5a,leng);
				}

				if( shutdown ){
 int ShutdownSocket(int sock);
 int rdy;
 double St = Time();
 fprintf(stderr,"----shutdown %d [%d]%d\n",
	shutdown,fileno(fs),IsAlive(fileno(fs)));
 ShutdownSocket(fileno(fs));
 rdy = PollIn(fileno(fs),shutdown);
 fprintf(stderr,"----shutdown %d [%d]%d rdy=%d (%.3f)\n",
	shutdown,fileno(fs),IsAlive(fileno(fs)),rdy,Time()-St);
				}
				if( !KeepAlive || oKeepAlive && feof(fs) ){
					if( oKeepAlive && feof(fs) ){
						fprintf(stderr,"###KeepAlive-EOS %d/%d\n",
							nr,nrepeat);
					}
					finishServYY(FL_ARG,Conn);
					fclose(ts); ts = NULL;
					fclose(fs); fs = NULL;
					if( !IsConnected(svsock,NULL) )
					waitFilterThread(Conn,1000,XF_ALL);
					svsock = -1;
					if( Conn->xf_filters ){
						int xpid;
						close_FSV(Conn);
						xpid = NoHangWait();
						while( 0 < xpid ){
							xpid = NoHangWait();
						}
					}
					if( Xcode == 7 ){
						break;
					}
					KeepAlive = oKeepAlive;
				}
			}
			Time0 = Time() - Start;
			if( Min == 0 || Time0 < Min )
				Min = Time0;
			if( Max == 0 || Max < Time0 )
				Max = Time0;
			TTime += Time0;

			if( 1 < nrepeat ){
			    double Now = Time();
			    int nd = nr + 1;
			    if( !BeSilent || 5 < (Now-Prev) ){
				if( Npara ) fprintf(lap,"+#%-2d ",Pi-1);
				fprintf(lap,
					"%7.2f %5.2f %d %6.2f/s %3d %6.2f/s",
					Now-time0,Now-Prev,
					nr-prev,(nr-prev)/(Now-Prev),
					nr+1,(nr+1)/(Now-time0)
				);
				if( 1 < Xrepeat ){
					fprintf(lap," %02X/%d",
						Xcksum,Xleng);
				}
				fprintf(lap,"\n");
				fflush(lap);
				Prev = Now;
				prev = nr;
			    }
			}
			if( 0 < Interval ){
				StrftimeLocal(AVStr(date),sizeof(date),"%m/%d %H:%M:%S",time(0),0);
				fprintf(lap,"%s %.3f (%lld)\n",date,Time0,
					leng);
				fflush(lap);
				msleep(Interval);
			}
		}
		StrftimeLocal(AVStr(date),sizeof(date),"%H:%M:%S",time(0),0);
		if( Npara ) fprintf(lap,"#%-2d ",Pi-1);
		fprintf(lap,"%s %3d: %s %s\n",date,num,url,type);
		fflush(lap);
	}
	if( Verify ){
		fprintf(lap,"Vrfy=%d ",Vcode);
	}

if( Npara ) fprintf(lap,"#%-2d ",Pi-1);
fprintf(lap,
"%d GET / %.3f seconds = %5.2f GET/second %lld bytes (%.3f/%.3f/%.3f)\n",
num,Time()-time0, num/(Time()-time0),total,
Min,TTime/nrepeat,Max);

	if( putBodyFp && putBodyFp != stdout )
		fclose(putBodyFp);
	fclose(lap);
	/*
	exit(0);
	return 0;
	*/
	exit(Xcode);
	return Xcode;
}

static void url1(PCStr(url),PCStr(base))
{	CStr(xurl,4096);
	const char *bp;
	const char *dp;
	int id;
/*
fprintf(stderr,"---- %s %s\n",base,url);
*/
	if( strncmp(url,"http:",5) == 0 )
	if( url[5] != '/' )
		url += 5;
	if( strncmp(url,"./",2) == 0 )
		url += 2;

	if( dp = strstr(url,"..") )
	if( dp[2] == 0 || dp[2] == '/' )
	if( dp == url || dp[-1] == '/' )
		return;

	xurl[0] = 0;
	if( strchr(url,':') == 0 ){
		strcpy(xurl,base);
		if( bp = strrchr(xurl,'/') )
			((char*)bp)[1] = 0;
	}

	strcat(xurl,url);
	if( dp = strchr(xurl,'#') )
		truncVStr(dp);

	if( strncmp(xurl,base,strlen(base)) != 0 )
		return;
	if( strcmp(xurl,base) == 0 )
		return;

	id = strid(URLgot,xurl,URLgetx);
	if( id == URLgetx ){
		URLgetx++;
		fprintf(stderr,"++ %4d %s\n",URLgetx,xurl);
	}
}

FileSize recvHTTPbodyX(Connection *Conn,int chunked,FILE *in,FILE *out);
static FileSize http1(Connection *XConn,int nr,FILE *ts,FILE *fs,PCStr(proto),PCStr(host),int port,PCStr(path),PVStr(result))
{	CStr(request,URLSZ);
	CStr(resp,URLSZ);
	CStr(xline,URLSZ);
	const char *url;
	double start;
	int code;
	CStr(type,256);
	FileSize leng;
	FileSize total = 0;
	int rcc;
	int keepalive;
	CStr(auth,256);
	CStr(authB64,256);
	const char *dp;
	Connection ConnBuf, *Conn = &ConnBuf;
	int chunked = 0;
	CStr(md5head,1024);
	CStr(md5d,16);
	MD5 *md5;

	if( Verify ){
		truncVStr(md5head);
		md5 = newMD5();
	}

/*
	sprintf(request,"GET %s HTTP/1.0\r\n\r\n",path[0]?path:"/");
*/
	if( Http11 )
		sprintf(request,"GET %s HTTP/1.1\r\n",path);
	else	sprintf(request,"GET %s HTTP/1.0\r\n",path);

	if( !noHost && Host[0] )
	Xsprintf(TVStr(request),"Host: %s\r\n",Host);
	else
	if( Http11 ){
		Xsprintf(TVStr(request),"Host: \r\n"); /* for apache ... */
	}
	Xsprintf(TVStr(request),"User-Agent: DeleGate/%s (dget)\r\n",
		DELEGATE_ver());
	if( Headers[0] ){
		Xstrcat(TVStr(request),Headers);
	}

	/*
	bzero(Conn,sizeof(Connection));
	*/
	ConnInit(Conn);
	if( XConn && EmiActive(XConn) ){
		Conn->md_in = XConn->md_in;
	}
	/*
	if( get_MYAUTH(Conn,AVStr(auth),"http",host,port) ){
	*/
	if( HTTP_Auth[0] ){
		strcpy(auth,HTTP_Auth);
		str_to64(auth,strlen(auth),AVStr(authB64),sizeof(authB64),1);
		if( dp = strpbrk(authB64,"\r\n") ) truncVStr(dp);
		Xsprintf(TVStr(request),"Authorization: Basic %s\r\n",authB64);
	}
	/*
	if( get_MYAUTH(Conn,AVStr(auth),"http-proxy",host,port) ){
	*/
	if( HTTP_proxyAuth[0] ){
		strcpy(auth,HTTP_proxyAuth);
		str_to64(auth,strlen(auth),AVStr(authB64),sizeof(authB64),1);
		if( dp = strpbrk(authB64,"\r\n") ) truncVStr(dp);
		Xsprintf(TVStr(request),"Proxy-Authorization: Basic %s\r\n",authB64);
	}

	if( NoCache )
		strcat(request,"Pragma: no-cache\r\n");
	if( 0 < MaxAge ){
		Xsprintf(TVStr(request),
			"Cache-Control: max-age=%d\r\n",MaxAge-1);
	}
	if( dontKeepAlive ){
		strcat(request,"Connection: close\r\n");
	}else
	if( KeepAlive ){
		if( ToProxy )
		strcat(request,"Proxy-Connection: Keep-Alive\r\n");
		else
		strcat(request,"Connection: keep-alive\r\n");
	}
	if( AccEncode[0] ){
		Xsprintf(TVStr(request),
			"Accept-Encoding: %s\r\n",AccEncode);
	}
	if( SendCookie ){
		int ci;
		refQStr(dp,request);/**/
		strcat(request,"Cookie:");
		dp = request + strlen(request);
		for( ci = 0; ci < SendCookie; ci++ ){
			if( &request[sizeof(request)-5] <= dp )
				break;
			setVStrPtrInc(dp," 123456789"[ci%10]);
		}
		strcpy(dp,"\r\n");
	}

 if( getenv("HEADSIZE") ){
	refQStr(p,request); /**/
	int size,i;
	size = atoi(getenv("HEADSIZE"));
	strcat(request,"X-Padding: ");
	p = request + strlen(request);
	for( i = 0; i < size; i++ ){
		if( &request[sizeof(request)-5] <= &p[i] )
			break;
		setVStrElem(p,i,'X');
	}
	setVStrEnd(p,i);
	strcat(request,"\r\n");
 }
	strcat(request,"\r\n");
	fputs(request,ts);
	fflush(ts);
/*
fprintf(stderr,"REQUEST-LEN: %d\n",strlen(request));
*/
	if( SendOnly )
		return 0;
	if( ResWait ){
		if( fPollIn(fs,(int)(ResWait*1000)) <= 0 ){
			fprintf(stderr,"Timeout: %f\n",ResWait);
			Xcode = 8;
			return 0;
		}
	}

	start = Time();
	if( fgetsTIMEOUT(AVStr(resp),sizeof(resp),fs) == NULL ){
		if( !BeSilent ){
		if( Npara )
		fprintf(stderr,"#%-2d [%d](%d)",Pi-1,getpid(),Nrepeat-1);
		fprintf(stderr,"[NULL] empty response (%3.2fs) %s\n",
			Time()-start,Sockname);
		}

syslog_ERROR("[NULL] empty response (%3.2fs) %s [%d] EOF=%d errno=%d\n",
	Time()-start,Sockname,fileno(fs),feof(fs),errno);

		sprintf(result,"[NULL]");
		Xcode = 7;
		goto xERR;
	}
	if( PutHead )
		fputs(resp,stdout);

	for(;;){
		fprintf(stderr,"dget-HTTP");
		fprintf(stderr,">>> %s",resp);
		if( !strneq(resp,"HTTP/1.1 100",12) ){
			break;
		}
		while( fgets(resp,sizeof(resp),fs) != NULL ){
fprintf(stderr,"SKIP>>> %s",resp);
			if( *resp == '\r' || *resp == '\n' ){
				fprintf(stderr,"dget-HTTP");
				fprintf(stderr,">>> %s",resp);
				break;
			}
		}
		fgets(resp,sizeof(resp),fs);
	}
	if( strncmp(resp,"HTTP/1.",7) != 0 ){
		fprintf(stderr,"[%d][NON-HTTP/1.0] %s\n",nr,resp);
		sprintf(result,"[%d][NON-HTTP/1.0]",nr);
		Xcode = 6;
		goto xERR;
	}
	sscanf(resp,"%*s %d",&code);
	if( StatCodeOnly ){
		printf("%d\n",code);
		exit(code);
	}
	if( 400 <= code ){
		Xcode = code / 100;
	}

	type[0] = 0;
	leng = 0;
	keepalive = 0;
	if( KeepAlive )
	if( strstr(resp,"HTTP/1.1") ){
		keepalive = 1;
	}

	while( fgets(resp,sizeof(resp),fs) != NULL ){
		const char *dp;

		if( PutHead )
			fputs(resp,stdout);
		if( dp = strpbrk(resp,"\r\n") )
			truncVStr(dp);
		if( dp == resp )
			break;

		if( strncasecmp("Transfer-Encoding:",resp,18) == 0 ){
			if( strstr(resp,"chunked") )
				chunked = 1;
		}else
		if( strncasecmp("Content-Type:",resp,12) == 0 )
			Xsscanf(resp,"%*s %[^; \t\r\n]",AVStr(type));
		else
		if( strncasecmp("Content-Length:",resp,13) == 0 )
			Xsscanf(resp,"%*s %lld",&leng);
		else
		if( strncasecmp("Proxy-Connection: keep-alive",resp,28) == 0
		 || strncasecmp(      "Connection: keep-alive",resp,22) == 0 )
		{
			keepalive = 1;
		}else
		if( strncasecmp("Proxy-Connection: close",resp,23) == 0
		 || strncasecmp(      "Connection: close",resp,17) == 0 )
		{
			keepalive = 0;
		}
		else
		if( strncasecmp("Content-MD5:",resp,12) == 0 ){
			strcpy(md5head,resp);
		}
	}
	if( PutHead ){
		fflush(stdout);
	}
	if( Verify ){
		if( (Vcode = verifySignedMD5(md5head,NULL,MOptions)) < 0 ){
			fprintf(stderr,"-- MD5-ERROR in header: %x\n",Vcode);
		}
	}
	sprintf(result,"[%d][%s][%lld]",code,type,leng);
	if( code == 304 ){
		return 0;
	}

	if( TarOpt ){
		tar_scan(fs,stdout,stderr,TarOpt,"-",TarFiles,NULL);
	}else
/*
	if( KeepAlive && keepalive && 0 < leng ){
*/
	/*
	if( keepalive ){
	*/
	if( keepalive && (0 < leng || chunked) ){
		FileSize ci;
		int ch;
		if( PrematureEOF ){
			ci = 0;
			while( 0 < (rcc = freadTIMEOUT(AVStr(resp),1,sizeof(resp),fs)) ){
				ci += rcc;
				if( PrematureEOF && PrematureEOF <= ci ){
					break;
				}
			}
			exit(0);
		}else
		if( chunked && PutBody ){
			ci = recvHTTPbodyX(Conn,chunked,fs,putBodyFp);
		}else
		if( chunked ){
			int pfd[2];
			FILE *fp;
			IGNRETZ pipe(pfd);
			if( Fork("dget-chunked") == 0 ){
				close(pfd[1]);
				fp = fdopen(pfd[0],"r");
				recvfile1(Conn,fp);
				_exit(0);
			}else{
				close(pfd[0]);
				fp = fdopen(pfd[1],"w");
				ci = recvHTTPbodyX(Conn,chunked,fs,fp);
				fclose(fp);
				wait(0);
			}
		}else
		for( ci = 0; ; ci++ ){
			if( ci == leng )
				fflush(stdout);
			if( leng <= ci && fPollIn(fs,1) <= 0 )
			{
				break;
			}
			if( (ch = getc(fs)) == EOF )
			{
				break;
			}
			if( EmiActive(Conn) ){
				char buf[1];
				buf[0] = ch;
				EmiUpdateMD5(Conn,buf,1);
			}
			if( PutBody )
			{
				putc(ch,putBodyFp);
			}
			if( READYCC(fs) <= 0 )
				fflush(stdout);
		}
		if( !BeSilent )
		fprintf(stderr,"dget-HTTP");
		fprintf(stderr,">>>> Response: %lld/%lld\n",ci,leng);
		/*
		const char *buf;
		buf = (char*)malloc(leng);
		total = fread (buf,1,leng,fs);
		if( PutBody )
			fwrite(buf,1,leng,putBodyFp);
		free(buf);
		*/
	}else
	if( Decode ){
		FILE *tmp1,*tmp2;
		int gunzipFilter(FILE*,FILE*);
		int elen,crc,ecrc;
		FILE *Gunzip(PCStr(enc),FILE *fs);

		tmp1 = TMPFILE("Decode");
		tmp2 = TMPFILE("Decode");
		elen = copyfile1(fs,tmp1);
		fflush(tmp1);
		fseek(tmp1,0,0);
		ecrc = fcrc32(tmp1);
		fseek(tmp1,0,0);
		leng = gunzipFilter(tmp1,tmp2);
		fflush(tmp2);
		fseek(tmp2,0,0);
		crc = fcrc32(tmp2);
		fclose(tmp2);
		fclose(tmp1);
		total = leng;
		Xcksum = ((0xFF & ecrc) << 8) | (0xFF & crc);
		Xleng = leng;
		syslog_ERROR("#%-2d Decode (%d/%X %d/%X)\n",Pi-1,
			elen,ecrc,(int)leng,crc);
	}else{
		if( Recursive && strcasecmp(type,"text/html") == 0 ){
			CStr(line,0x10000);
			const char *lp;
			CStr(xline,0x20000);
			const char *np;
			int remlen,leng,isbin;

	CStr(hostport,MaxHostNameLen);
	CStr(base,URLSZ);
	HostPort(AVStr(hostport),proto,host,port);
	sprintf(base,"%s://%s/%s",proto,hostport,path[0]=='/'?path+1:path);

			remlen = sizeof(line); 
			for(;;){
				lp = fgetsByBlock(AVStr(line),sizeof(line),fs,1,0,0,0,
					remlen,&leng,&isbin);
				if( lp == NULL )
					break;
/*
fprintf(stderr,"read %d bytes\n",strlen(line));
*/
				url_absolute("-.-",proto,host,port,"",line,AVStr(xline),VStrNULL);
				scan_url(xline,(iFUNCP)url1,base,(void*)"");
			}
		}else
		if( !Verify && !PutBody && !PrematureEOF ){
			total = recvfile1(Conn,fs);
		}else
		while( (rcc=freadTIMEOUT(AVStr(resp),1,sizeof(resp),fs)) != 0 ){
			total += rcc;
			if( Verify ){
				addMD5(md5,resp,rcc);
			}
			if( EmiActive(Conn) ){
				EmiUpdateMD5(Conn,resp,rcc);
			}
			if( PutBody )
			{
				fwrite(resp,1,rcc,putBodyFp);
				if( Http11 ){
					while( ready_cc(fs) ){
						putc(getc(fs),putBodyFp);
						total++;
					}
					fflush(putBodyFp);
				}
			}
			if( PrematureEOF && PrematureEOF <= total ){
				break;
			}
		}
	}
	if( PutBody ){
		fflush(putBodyFp);
	}
	if( Verify ){
		endMD5(md5,md5d);
		if( (Vcode |= verifySignedMD5(md5head,md5d,NULL)) < 0 ){
			fprintf(stderr,"-- MD5-ERROR in body: %x\n",Vcode);
		}
	}

	syslog_ERROR("total: %lld / %lld [%s]\n",total,leng,Sockname);
	if( 100000 < total )
		fprintf(stderr,"[%d] total: %lld / %lld [%s]\n",
			getpid(),total,leng,Sockname);


xERR:
	if( !keepalive )
		KeepAlive = 0;

	syslog_ERROR("+++ %.3f done len=%d [%d] EOF=%d threads=%d/%d\n",
		Time()-start,(int)total,fileno(fs),feof(fs),
		actthreads(),numthreads()
	);
	if( XConn && EmiActive(XConn) ){
		XConn->md_in = Conn->md_in;
	}
	return total;
}

int ENEWS_active(PCStr(spool),PCStr(artfmt),int *max,int *min);
int mirror_main(int ac,const char *av[],Connection *Conn){
	int serv;
	FILE *ts;
	FILE *fs;
	CStr(resp,1024);
	int di;
	double Start;
	int ano = 0;
	CStr(path,1024);
	FILE *afp;
	int dano = 0;
	int cnt,min,max;
	const char *a1;
	CStr(server,128);
	CStr(svhost,128);
	int svport;
	CStr(group,128);
	int ai;
	CStr(spool,1024);
	CStr(gpath,1024);
	int omin,omax,cdate,mdate;
	int verbose = 0;
	int nerr = 0;

	truncVStr(server);
	truncVStr(group);
	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( strneq(a1,"nntp://",7) ){
			Xsscanf(a1+7,"%[^/]/%[^/]/%d",AVStr(server),
				AVStr(group),&ano);
		}
		else
		if( strneq(a1,"--v",3) ){
			verbose = 1;
			if( a1[3] == 'v' )
				verbose = 2;
		}
		else{
			fprintf(stderr,"UNKNOWN arg[%d] %s\n",ai,a1);
		}
	}
	if( server[0] == 0 || group[0] == 0 ){
		fprintf(stderr,"command syntax error.\n");
		fprintf(stderr,"Usage: %s nntp://Server/Group\n",av[0]);
		exit(-1);
	}

	strcpy(gpath,group);
	strsubst(AVStr(gpath),".","/");
	omin = omax = -1;
	sprintf(spool,"nntp/%s/%s",server,gpath);
	if( ENEWS_active(spool,"*",&omax,&omin) ){
		if( 0 < omax ){
			ano = omax - 1;
		}
	}

	svport = 119;
	Xsscanf(server,"%[^:]:%d",AVStr(svhost),&svport);
	serv = OpenServer("Mirror","nntp",svhost,svport);
	if( serv < 0 ){
		fprintf(stderr,"cannot connect to server.\n");
		exit(-1);
	}
	if( verbose )
	fprintf(stderr,"connect to the server: %s:%d\n",svhost,svport);

	ts = fdopen(serv,"w");
	fs = fdopen(serv,"r");
	Fgets(AVStr(resp),sizeof(resp),fs);
	if( resp[0] != '2' ){
		fprintf(stderr,"rejected by server: %s\n",resp);
		exit(-1);
	}
	fprintf(ts,"GROUP %s\r\n",group); fflush(ts);
	Fgets(AVStr(resp),sizeof(resp),fs);
	if( resp[0] != '2' ){
		fprintf(stderr,"rejected by server: %s\n",resp);
		exit(-1);
	}
	if( 2 < verbose )
	fprintf(stderr,"GROUP %s << %s\n",group,resp);

	cnt = min = max = -1;
	sscanf(resp,"%*d %d %d %d",&cnt,&min,&max);
	Start = Time();
	if( ano+1 < min )
		ano = min - 1;

fprintf(ts,"ARTICLE %d\n",++ano); fflush(ts);
fprintf(ts,"ARTICLE %d\n",++ano); fflush(ts);
fprintf(ts,"ARTICLE %d\n",++ano); fflush(ts);

	for( di = 0;; di++ ){
		if( feof(fs) )
			break;
fprintf(ts,"ARTICLE %d\n",++ano); fflush(ts);
		if( fgets(resp,sizeof(resp),fs) == NULL )
			break;
		if( 1 < verbose ){
			fprintf(stderr,"-- ARTICLE %d ",ano);
			fprintf(stderr,"-- %s",resp);
		}

		if( *resp != '2' ){
			nerr++;
			if( max <= dano || max <= ano+3 ){
				if( verbose ){
					fprintf(stderr,"ERR*%d [%d %d %d] %s",
						nerr,max,dano,ano+3,resp);
				}
				if( 5 < nerr )
				break;
			}
			continue;
		}
		sscanf(resp,"%*d %d",&dano);

		sprintf(path,"%s/%03d/%02d",spool,dano/100,dano%100);
		afp = dirfopen("NNS",AVStr(path),"w+");

if( verbose )
//if( (ano % 100) == 0 )
fprintf(stderr,"---- %6d: %6.2f %s\n",di,Time()-Start,path);

		for(;;){
			if( fgets(resp,sizeof(resp),fs) == NULL )
				break;
			if( resp[0] == '.' )
			if( resp[1] == 0 || resp[1] == '\r' || resp[1] == '\n' )
				break;
			if( afp ){
				fputs(resp,afp);
			}
		}
		if( afp ){
			fclose(afp);
		}
	}

if( verbose )
fprintf(stderr,"---- %6d: %6.2f last=%d\n",di,Time()-Start,dano);

	fclose(ts);
	fclose(fs);
	return 0;
}
