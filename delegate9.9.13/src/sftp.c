/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2005-2006 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	sftp.c (ftp client to sftp server gateway)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	PROBLEM
		uploading huge file (STOR)
		 ... getting into local tmpfile is bad
History:
	050728	created
//////////////////////////////////////////////////////////////////////#*/
#include "vsocket.h"
#include "dglib.h"
#include "fpoll.h"
#include "proc.h"
#include "vsignal.h"

#include "log.h"
static int ErrorResp = 0;
#define DEBUG	(lGATEWAY()==0 && ErrorResp==0)?0:sv1log
#define Error	sv1log

#if defined(__KURO_BOX__)
#include <pty.h>
#define Forkpty(pty,name) forkpty(pty,name,NULL,NULL)
#else
int Forkpty(int *pty,char *name);
#endif
int Stty(int fd,const char *mode);

int CC_connect(PCStr(proto),PCStr(host),int port,PCStr(user));
int CC_accept(PCStr(proto),PCStr(host),int port,PCStr(user),int fromS);
int Mkfifo(PCStr(path),int mode);
char *fgetsTO(PVStr(b),int z,FILE *f,int t1,int t2);
FILE *fopenTO(PCStr(path),PCStr(mode),int timeout);
FileSize file_copy(FILE *src,FILE *dst,FILE *cache,FileSize bytes,int *binary);

/*
static int DATA_MAX = 10*1024*1024;
*/
static FileSize DATA_MAX = 10*1024*1024;
static const char *sftp_com = "sftp -oPort=%d %s@%s";
static int pid;
int SFTP_WITH_SEEK = 1;

static void putresp(FILE *tc,int code,PCStr(stat),...){
	CStr(resp,1024);
	refQStr(rp,resp);
	VARGS(8,stat);

	sprintf(rp,"%d ",code); rp += strlen(rp);
	sprintf(rp,stat,VA8);
	fprintf(tc,"%s\r\n",resp);
	fflush(tc);
	DEBUG("--SFTPGW >> %s\n",resp);
}
static void putsftp(FILE *ts,PCStr(fmt),...){
	CStr(com,1024);
	VARGS(8,fmt);

	sprintf(com,fmt,VA8);
	fprintf(ts,"%s\r\n",com);
	fflush(ts);
	DEBUG("--SFTP << %s\r\n",com);
}

/*
 * newer sftp forces ECHO unconditionally, thus the response for the
 * "ls ..." command includes "ls ..." before and "sftp> \r\n" after
 * the list data.
 */
static void relay_list(FILE *fs,int dsock,PCStr(scom)){
	CStr(res,1024);
	int tout;
	FILE *tc;

	int skipping = 0;
	int skipped = 0;
	double St = Time();
	int rdy;
	void (*sig)(int);
	rdy = fPollIn(fs,60*1000); /* 9.9.6 */
	if( 3 < Time()-St ){
		sv1log("--SFTP relay_list(%s) slow (%.1f) rdy=%d\n",
			scom,Time()-St,rdy);
	}
	sig = Vsignal(SIGPIPE,SIG_IGN);

	tout = 3*1000;
	tc = fdopen(dsock,"w");
	for(;;){
		if( fgetsTO(AVStr(res),sizeof(res),fs,tout,1) == NULL ){
			break;
		}
		if( strtailstr(res,"sftp> ") ){
			break;
		}
		if( *res == '\r' || *res == '\n'
		 || strheadstrX(res,"sftp> ",0)
		 || strheadstrX(res,scom,0)
		){
			continue;
		}
		/*
		fputs(res,tc);
		*/
		if( skipping ){
			skipped += strlen(res);
		}else
		if( fputs(res,tc) == EOF ){
			skipping = 1;
		}
	}
	fflush(tc);
	fcloseFILE(tc);
	Vsignal(SIGPIPE,sig);
}

static void relay_resp(FILE *fs,int dsock,int timeout,PVStr(resp),PCStr(com),int dolog){
	CStr(res,1024);
	FILE *fp;
	refQStr(rp,resp);
	refQStr(dp,res);
	int tout0;
	int tout;

	if( 0 < timeout )
		tout0 = tout = timeout;
	else	tout0 = tout = 3*1000;

	if( resp )
		setVStrEnd(resp,0);
	if( fPollIn(fs,tout) <= 0 ){
		DEBUG("--SFTP >> response timeout [%s]%d\n",com,tout);
		return;
	}
	if( 0 <= dsock )
		fp = fdopen(dsock,"w");
	else	fp = NULL;

	for(;;){
		if( 0 < fgetsBuffered(AVStr(res),sizeof(res),fs) ){
		}else
		if( fgetsTO(AVStr(res),sizeof(res),fs,tout,1) == NULL ){
			break;
		}
		if( *res == '@' ){
			dolog = 1;
			ErrorResp = 1;
		}
		if( dolog ){
			if( strchr(res,'\n') )
				DEBUG("--SFTP >>(%s) %s",com,res);
			else	DEBUG("--SFTP >>(%s/NO-NL)[%s]\n",com,res);
		}
		if( strtailstr(res,"sftp> ") ){
			if( rp ){
if( lGATEWAY() )
sv1log("####@@@@ resp[%s][%s]\n",res,resp);
				strcpy(rp,res);
				rp += strlen(rp);
			}
			if( fPollIn(fs,10) <= 0 )
				break;
		}
		if( dp = strpbrk(res,"\r\n") )
			strcpy(dp,"\r\n");
		if( fp != NULL )
			fputs(res,fp);
		if( streq(res,"\r\n") || streq(res,"\n") ){
			/* ignore empty lines */
		}else
		if( rp ){
			strcpy(rp,res);
			rp += strlen(rp);
		}
		if( resp && *resp == 0 ){
			tout = tout0;
		}else
		if( strtailstr(res,":")
		 || strtailstr(res,": ")
		 || strtailstr(res,"? ")
		){
			tout = 1;
		}else
		if( *res == '\r' || *res == '\n' )
			tout = 100;
		else	tout = tout0;
	}
	if( fp != NULL )
		fflush(fp);
	ErrorResp = 0;
}

static int sfsv_acsock;
static int sfsv_svsock;
static void closeAll(){
	int fi;
	int rcode;
	int lfd = curLogFd();
	for( fi = 3; fi < 256; fi++ ){
		if( fi == sfsv_acsock || fi == sfsv_svsock ){
			continue;
		}
		if( fi == lfd )
			continue;
		rcode = close(fi);
		/*
		if( rcode == 0 ) DEBUG("-- closed %d\n",fi);
		*/
	}
}

static int SftpPid;
static int SftpPty = -1;

static int SftpTid;
void tcp_relay2(int timeout,int s1,int d1,int s2,int d2);
int connect_to_sv(DGC*Conn,PCStr(proto),PCStr(host),int port);
int newSocket(PCStr(what),PCStr(opts));
int BindSocket(int sock,VSAddr *vsa,int port);

static int sftpsv1(int acsock,int svsock){
	IStr(sockname,256);
	int clsock;

	clsock = ACCEPT1(acsock,1,-1,0,AVStr(sockname));
	if( clsock < 0 ){
		return -1;
	}
	DEBUG("## relay [%d][%d]...\n",clsock,svsock);
	tcp_relay2(0,clsock,svsock,svsock,clsock);
	return 0;
}
static int sftpsv(int port,PCStr(host),PVStr(lhost)){
	int acsk,svsk,lport,lports;
	VSAddr vsa;

	lport = SERVER_PORT() + 1;
	lports = (lport<<16) | (lport+32);
	strcpy(lhost,"127.0.0.1");
	VSA_atosa(&vsa,0,lhost);
	acsk = newSocket("sftp","");
	if( BindSocket(acsk,&vsa,lports) != 0 ){
		BindSocket(acsk,&vsa,0);
	}
	lport = sockPort(acsk);
	listen(acsk,1);
	svsk = connect_to_sv(MainConn(),"sftp",host,port);
	sfsv_acsock = acsk;
	sfsv_svsock = svsk;
	SftpTid = thread_fork(0x80000,0,"sftpsv1",(IFUNCP)sftpsv1,acsk,svsk);
	sv1log("-Esf %d/%d %d/%d %X\n",lport,acsk,sockPort(svsk),svsk,SftpTid);
	return lport;
}

int dupLogFd();
void execsystem(PCStr(what),PCStr(pathcom));
/*
static int forkSftp(PCStr(host),int port,PCStr(user),PCStr(pass),int tf[2]){
*/
static int forkSftp(PCStr(host),int port,PCStr(user),PCStr(pass),int tf[2],PVStr(rresp)){
	CStr(com,1024);
	CStr(resp,0x10000);
	int pty;
	IStr(name,128);
	FILE *fs;
	FILE *ts;
	int to[2];
	int from[2];
	int rcode;
	int slog = LOG_type1;

	LOG_type1 &= ~L_CONSOLE; /* 9.9.8 suppress logging to pty by child */
	if( curLogFd() == fileno(stderr) ){
		dupLogFd(); /* 9.8.2 not to send log-output to pty */
	}
	if( lSFTP_FILTER() ){ /* 9.9.6 "-Esf" to apply SOCKS, SRCIF, ..*/
		IStr(lhost,MaxHostNameLen);
		int lport;
		lport = sftpsv(port,host,AVStr(lhost));
		port = lport;
		host = (const char*)lhost;
	}
	pid = Forkpty(&pty,(char*)name);
	if( 0 < pid ){
  int retrying = 0; /* fix-110921a for retrying auth. with sftp */
  IStr(prompt1,sizeof(resp));

		PollIn(pty,3*1000); /* wait a response from sftp */
		LOG_type1 = slog; /* LOG_type1 is on shared memory */

		SftpPid = pid;
		SftpPty = pty;
		DEBUG("--SFTP: pid=%d pty master %d %s\n",pid,pty,name);
		tf[0] = pty;
		tf[1] = pty;

		msleep(100);
		fs = fdopen(pty,"r");
		relay_resp(fs,-1,15*1000,AVStr(resp),"FORK-1",1);
		strcpy(prompt1,resp);

		if( strstr(resp,"Are you sure you want to continue") ){
			sprintf(com,"yes\n");
			IGNRETP write(pty,com,strlen(com));
			DEBUG("--SFTP: answered yes for...\n%s\n",resp);
			relay_resp(fs,-1,15*1000,AVStr(resp),"FORK-2",1);
		}

  for( retrying = 0; retrying < 10; retrying++ ){
		sprintf(com,"%s\r\n",pass);
		IGNRETP write(pty,com,strlen(com));
		DEBUG("--SFTP: sent the password...\n");
		relay_resp(fs,-1,15*1000,AVStr(resp),"FORK-3",1);

		if( strtailstr(resp,"Password:")
		 || strtailstr(resp,"Password: ")
		 || strtailstr(resp,"password: ")
		 || strstr(resp,"Enter passphrase for key")
		){
    if( retrying || strtailstr(prompt1,resp) != NULL ){ /* fix-110921a */
	DEBUG("--SFTP REPEAT %d %s\n",retrying,resp);
	clearVStr(resp);
	continue;
    }
			DEBUG("--SFTP %s\n",resp);
if( lGATEWAY() )
sv1log("####@@@@ KILL sftp pid=%d\n",pid);
			Kill(SftpPid,SIGTERM);
			strcpy(rresp,resp);
			return -1;
		}
    break;
  }

		sprintf(com,"progress\r\n");
		IGNRETP write(pty,com,strlen(com));
		relay_resp(fs,-1,5*1000,AVStr(resp),"FORK-4",1);

		return 0;
	}

	sprintf(com,"[%s]","sftp");
	Xsprintf(TVStr(com),sftp_com,port,user,host);
	DEBUG("--SFTP: %s\n",com);
if( lGATEWAY() )
sv1log("####@@@@ command %s\n",com);

	if( pid == 0 ){
		closeAll();
		Stty(0,"-echo");
		/*
		system("stty raw");
		*/
		/*
		rcode = system(com);
		printf("ssh exit(%d)\n",rcode);
		*/
		execsystem("sftp",com);
		printf("ssh exec(%s) failed\n",com);
		_exit(0);
	}

	IGNRETZ pipe(to);
	IGNRETZ pipe(from);
	if( Fork("Sftp") == 0 ){
		close(to[1]);
		dup2(to[0],0);
		close(from[0]);
		dup2(from[1],1);
		closeAll();
		rcode = system(com);
		printf("ssh exit(%d)\n",rcode);
		_exit(0);
	}
	close(to[0]);
	close(from[1]);
	tf[0] = from[0];
	tf[1] = to[1];
	fs = fdopen(from[0],"r");
	relay_resp(fs,-1,20*1000,AVStr(resp),"FORK-1",1);
	return 0;
}

static int frelayB(FILE *src,FILE *dst){
	CStr(buf,8*1024);
	int rcc,wcc;

	if( ready_cc(src) ){
		rcc = fgetsBuffered(AVStr(buf),sizeof(buf),src);
	}else{
		rcc = read(fileno(src),buf,sizeof(buf));
	}
	if( 0 < rcc ){
		wcc = fwrite(buf,1,rcc,dst);
		if( wcc != rcc ){
			sv1log("--SFTP frelayB failed %d / %d\n",wcc,rcc);
			return -1;
		}
	}
	return rcc;
}
int SFTP_DATA_TIMEOUT = 10;
/*
static int relay_fifo(FILE *fs,FILE *tc,PCStr(fifo),int dsock,PCStr(com)){
*/
static int relay_fifo(FILE *fs,FILE *tc,PCStr(fifo),int dsock,PCStr(com),PVStr(resp)){
	FILE *sfp;
	FILE *dfp;
	refQStr(rp,resp);
	/*
	int fv[2];
	*/
	FILE *fv[2];
	int rv[2];
	int nready;
	int done = 0;
	int leng = 0;

	truncVStr(resp);
	sfp = fopenTO(fifo,"r",1);
if( lGATEWAY() )
sv1log("----FIFO recv OPEN %X %s\n",p2i(sfp),fifo);
	DEBUG("--SFTP relay [%s] %X\n",fifo,p2i(sfp));
	if( sfp == NULL ){
		/*
		relay_resp(fs,-1,1,VStrNULL,"RESP-A",1);
		*/
		int rcode;
		rcode = unlink(fifo);
		sv1log("----FIFO unlink(%s)=%d\n",fifo,rcode);
		while( 0 < fPollIn(fs,10) ){
			relay_resp(fs,-1,1,AVStr(rp),com,1);
			rp += strlen(rp);
		}
		return -1;
	}

	/*
	fv[0] = fileno(fs);
	fv[1] = fileno(sfp);
	*/
	fv[0] = fs;
	fv[1] = sfp;
	dfp = 0;

	for(;;){
		/*
		nready = PollIns(1000,2,fv,rv);
		*/
		/*
		nready = fPollIns(1000,2,fv,rv);
		*/
		if( done ){
			/* FreeBSD-select() does not detect the EOF of FIFO ? */
			nready = fPollIns(1,2,fv,rv);
if( lGATEWAY() )
sv1log("####@@@@ FIFO done nready=%d poll=%d\n",nready,fPollIn(sfp,1));
			if( nready == 0 ){
				nready = 1;
				rv[0] = 0;
				rv[1] = 1;
			}
		}else
		nready = fPollIns(SFTP_DATA_TIMEOUT*1000,2,fv,rv);
		DEBUG("--SFTP poll [%s] %d[%d %d]\n",fifo,nready,rv[0],rv[1]);
		if( nready <= 0 ){
			DEBUG("--SFTP NO RESP-B\n");
			break;
		}else{
			if( 0 < rv[0] ){
				IStr(res,1024);
				/*
				relay_resp(fs,-1,1,VStrNULL,com,1);
				*/
				relay_resp(fs,-1,1,AVStr(res),com,1);
				strcpy(rp,res);
				rp += strlen(res);
				if( !strcasestr(res,"sftp>") && res[0] != 0 ){
					/* 9.6.1 not the prompt implying fin. */
					if( strtailchr(res) != '\n' )
						strcat(res,"\n");
					DEBUG("--SFTP relay: %s",res);
				}else
				{
				unlink(fifo); /* notify recv. completion */
				DEBUG("--SFTP recv. seems complete\n");
					done = 1;
				}
			}
			if( 0 < rv[1] ){
				if( dfp == NULL ){
					dfp = fdopen(dsock,"w");
					if( dfp ){
						putresp(tc,150,"Ok");
					}
				}
				if( dfp ){
					int bytes;
					bytes = frelayB(sfp,dfp);
if( lGATEWAY() )
DEBUG("####@@@@ bytes=%d errno=%d\n",bytes,errno);
					DEBUG("--SFTP %d downloaded\n",bytes);
					if( bytes <= 0 ){
					DEBUG("--SFTP EOF=%d\n",feof(sfp));
						break;
					}
					leng += bytes;
				}
				/*
				dfp = fdopen(dsock,"w");
				if( dfp ){
					int isbin;
					int bytes;
					DEBUG("--SFTP relay [%s]...\n",fifo);
					putresp(tc,150,"Ok");
					bytes=file_copy(sfp,dfp,NULL,0,&isbin);
					fcloseFILE(dfp);
					DEBUG("--SFTP bin=%d,%d downloaded\n",
						isbin,bytes);
				}
				break;
				*/
			}
		}
	}
	fclose(sfp);
	if( dfp )
		fcloseFILE(dfp);

if( lGATEWAY() )
sv1log("----FIFO recv DONE %d\n",leng);
	return leng;
	/*
	return 0;
	*/
}

int file_size(int fd);
int File_size(PCStr(path));
int File_is(PCStr(path));
FileSize File_sizeX(PCStr(path));
/*
int relayFile2Fifo(FILE *rfp,PCStr(regfile),PCStr(fifo)){
*/
int relayFile2Fifo(FILE *fs,FILE *rfp,PCStr(regfile),PCStr(fifo)){
	FILE *ffp;
	CStr(buf,8*1024);
	int siz,rem,rcc,rcc1;
	int start;
	int last = time(0);

	ffp = fopen(fifo,"w+");
if( lGATEWAY() )
sv1log("----FIFO relay OPEN %X %s\n",p2i(ffp),fifo);
	if( rfp == 0 || ffp == 0 )
		return -1;

	rcc = 0;
	start = time(0);
	for(;;){
		siz = File_size(regfile);
		if( siz < 0 ){
			break;
		}
		rem = siz - ftell(rfp);

		if( lVERB() )
		DEBUG("--SFTP-DATA rem[%d] = %d (%d - %d)\n",
			fileno(rfp),rem,iftell(rfp),File_size(regfile));

		if( 0 < rem ){
			rcc1 = fread(buf,1,sizeof(buf),rfp);
			if( rcc1 <= 0 )
				break;
			rcc += rcc1;
			fwrite(buf,1,rcc1,ffp);
			last = time(0);
		}else{
			if( !File_is(fifo) ){
				/* fifo is unlinked on recv. complete */
				break;
			}
			fflush(ffp);
			if( 10 < time(0)-start ){
				if( fPollIn(fs,1) == 0
				 //&& IsAlive(fileno(fifo))
				 && time(0)-last < SFTP_DATA_TIMEOUT ){
					/* no prompt for the next command yet */
				}else
				break;
			}
			msleep(100);
		}
	}
	fflush(ffp);
	fclose(ffp);
if( lGATEWAY() )
sv1log("####@@@@ FIFO relay DONE %d %s\n",rcc,fifo);
	return rcc;
}

const char *DELEGATE_getEnv(PCStr(env));
const char *getTMPDIR();
int fileIsdir(PCStr(path));
int mkdirRX(PCStr(dir));

unsigned int trand1(unsigned int max);
static FILE *getfile(PVStr(path),PCStr(mode),int fifo){
	const char *tmpdir;
	IStr(dgtmp,1024);
	CStr(npath,1024);
	int max = 64;
	FILE *fp;
	int fi;
	int fx;

	/*
	sprintf(path,"/tmp/sftpgw.%d.%d",getpid(),time(NULL));
	 */
	tmpdir = "/tmp";
	if( DELEGATE_getEnv("TMPDIR") )
	if( tmpdir = getTMPDIR() ){
		DEBUG("--SFTP TMPDIR=%s\n",tmpdir);
	}
	sprintf(dgtmp,"%s/dg-sftpgw",tmpdir);
	if( !fileIsdir(dgtmp) ){
		if( mkdirRX(dgtmp) != 0 ){
		}
	}
	sprintf(path,"%s/sftpgw-%d.%d",dgtmp,getpid(),itime(NULL));
	if( fifo ){
		if( Mkfifo(path,0600) != 0 ){
			DEBUG("--SFTP cant create FIFO: %s\n",path);
			return 0;
		}
		fp = NULL;
	}else{
		if( (fp = fopen(path,mode)) == 0 ){
			DEBUG("--SFTP cant create FILE: %s\n",path);
			return 0;
		}
	}
	fx = trand1(max);
	for( fi = 0; fi < max; fi++ ){
		/*
		sprintf(npath,"/tmp/sftpgw.%02x",fx);
		 */
		sprintf(npath,"%s/sftpgw-%02x",dgtmp,fx);
		if( rename(path,npath) == 0 ){
			DEBUG("--SFTP TEMP FILE: %s\n",npath);
			strcpy(path,npath);
			return fp;
		}
		fx = (fx + 1) % max;
	}
	DEBUG("--SFTP ERROR: can't rename %s\n",path);
	return fp;
}

const char *linehead(PCStr(str),PCStr(pat),int igncase){
	const char *sp,*np;
	for( sp = str; sp; sp = np ){
		if( strheadstrX(sp,pat,igncase) ){
			return sp;
		}
		if( np = strchr(sp,'\n') ){
			np++;
		}
	}
	return 0;
}
int scanresp(PCStr(sresp),PCStr(head),PVStr(value),int siz){
	const char *sp;
	if( sp = linehead(sresp,head,0) ){
		linescanX(sp+strlen(head),BVStr(value),siz);
		return 1;
	}
	return 0;
} 

static const char *BadPath = "No such file or directory";

static void PASV(FILE *tc,int *vsockp){
	VSAddr ba;
	int balen;
	CStr(mport,128);
	int vsock = -1;

	vsock = server_open("SftpGW",VStrNULL,0,1);
	if( 0 <= vsock ){
		balen = sizeof(ba);
		getsockname(vsock,(SAP)&ba,&balen);
#if defined(__CYGWIN__)
		if( VSA_addrisANY(&ba) ){
		    /*connection to 0.0.0.0 fails on CYGWIN?*/
		    VSA_atosa(&ba,VSA_port(&ba),"127.0.0.1");
		}
#endif
		VSA_prftp(&ba,AVStr(mport));
		putresp(tc,227,"Enterning Passive Mode (%s)",mport);
		*vsockp = vsock;
	}else{
		putresp(tc,500,"No");
	}
}
/*
 * 9.9.2 for huge file upload
 */
static int waitUploaded(PCStr(com),PVStr(sresp),FILE *fs,FILE *fc,FILE *tc,double Tout,int *vsockp){
	int tout,tout1,tout2,rem;
	FILE *fpv[2];
	int rdv[2];
	IStr(opt1,128);
	IStr(req,1024);
	double St;
	int nrdy;

	tout = (int)Tout;
	if( tout <= 0 ) tout = 1;
	sv1log("--SFTPGW uploading wait=%d\n",tout);
	tout1 = tout;
	if( 5 < tout1 ) tout1 = 5;
	if( getMountOpt1(MainConn(),"waitput",AVStr(opt1),sizeof(opt1)) ){
		tout2 = (int)(Scan_period(opt1,'s',0)*1000);
		sv1log("## waitput=%s %d\n",opt1,tout2);
		relay_resp(fs,-1,tout2,BVStr(sresp),com,1);
	}else
	relay_resp(fs,-1,tout1*1000,BVStr(sresp),com,1);
	if( strstr(sresp,"sftp>") ){
		putresp(tc,226,"Ok");
		return 1;
	}

	/* resp. to avoid client timeout */
	putresp(tc,226,"Ok (upload in progress ...)");
	fpv[0] = fs;
	fpv[1] = fc;
	rem = tout * 2 * 1000;
	if( getMountOpt1(MainConn(),"timeout",AVStr(opt1),sizeof(opt1)) ){
		tout2 = (int)(Scan_period(opt1,'s',0)*1000);
		sv1log("## timeout=%s %d\n",opt1,tout2);
		if( tout2 ){
			rem = tout2;
		}
	}
	for(;;){
		St = Time();
		nrdy = fPollIns(rem,2,fpv,rdv);
		if( nrdy <= 0 ){
			sv1log("##SFTPGW upload timeout...(%.1fs/%d) %d %d\n",
				Time()-St,rem,nrdy,errno);
			break;
		}
		if( rdv[0] ){
			break;
		}
		if( rdv[1] ){
			if( fgets(req,sizeof(req),fc) == 0 ){
				break;
			}
			if( strneq(req,"QUIT",4) ){
				sv1log("##SFTPGW aborted upload (QUIT)\n");
				fprintf(tc,"500 aborted upload\r\n");
				fflush(tc);
				break;
			}
			sv1log("##SFTPGW IGN-REQ %s",req);
			if( strneq(req,"PASV",4) ){
				PASV(tc,vsockp);
			}else{
				fprintf(tc,"450 upload in progress...\r\n");
			}
			fflush(tc);
		}
	}
	relay_resp(fs,-1,1000,BVStr(sresp),com,1);
	return 0;
}

static void SftpGW(PCStr(host),int port,int gw){
	int tofrom_sftp[2];
	FILE *fc;
	FILE *tc;
	FILE *ts;
	FILE *fs;
	int rcc;
	CStr(req,1024);
	CStr(com,1024);
	const unsigned char *ucom = (const unsigned char*)com;
	CStr(arg,1024);
	CStr(scom,1024);
	CStr(user,128);
	CStr(passMD5,128);
	CStr(md5,1024);
	CStr(logindir,1024);
	CStr(rnfr,512);
	CStr(res,1024);
	CStr(xcom,1024);
	const char *dp;
	int vsock = -1;
	int dsock = -1;
	CStr(fifo,1024);
	CStr(sresp,0x10000);
	CStr(path,1024);
	CStr(resp1,1024);
	int Ok;
	int Bad;
	int xpid;
	int nready;
	int nfc;
	FILE *fpv[2];
	int rdv[2];
	int ncc = 0;
	int leng;

	FileSize datamax = DATA_MAX;
	IStr(opt1,128);
	if( getMountOpt1(MainConn(),"datamax",AVStr(opt1),sizeof(opt1)) ){
		datamax = kmxatoi(opt1);
		sv1log("## datamax=%s 0x%llX\n",opt1,datamax);
	}

	DEBUG("--SFTPGW start\n");
	fc = fdopen(gw,"r");
	tc = fdopen(gw,"w");
	putresp(tc,220,"SFTP/FTP gateway ready.");
	fflush(tc);
	ts = NULL;
	fs = NULL;

	logindir[0] = 0;
	fpv[0] = fc;
	nfc = 1;
	for(;;){
		nready = fPollIns(0,nfc,fpv,rdv);
		if( nready == 0 && errno == EINTR ){
			DEBUG("--SFTPGW ignored EINTR\n");
			sleep(1);
			continue;
		}
		if( nready <= 0 ){
			break;
		}
		if( 1 < nfc && 0 < rdv[1] ){
			DEBUG("--SFTPGW EOF from server?\n");
			relay_resp(fs,-1,0,AVStr(sresp),"",1);
			break;
		}

		fflush(tc);
		if( fgets(req,sizeof(req),fc) == 0 )
			break;
		dp = wordScan(req,com);
		if( *dp == ' ' ){
			textScan(dp+1,arg);
		}else
		lineScan(dp,arg);
		if( strcaseeq(com,"PASS") )
			DEBUG("--SFTPGW << [%s][****]\n",com);
		else	DEBUG("--SFTPGW << [%s][%s]\n",com,arg);

		if( strcaseeq(com,"QUIT") ){
			putresp(tc,221,"Ok Bye.");
			fclose(fc);
			fclose(tc);
			fc = 0;
			tc = 0;
			if( fs == NULL ){
				DEBUG("--SFTPGW DONE (not started)\n");
				break;
			}
			gw = CC_accept("sftp",host,port,user,fileno(fs));
			if( 0 <= gw ){
				putsftp(ts,"cd .","");
				relay_resp(fs,-1,0,AVStr(sresp),"restart",1);
				if( sresp[0] == 0 ){
					sv1log("##sftp_CC NotAlive\n");
					break;
				}
				fc = fdopen(gw,"r");
				fpv[0] = fc;
				tc = fdopen(gw,"w");
				ncc++;
				DEBUG("--SFTPGW SFTPCC restart #%d\n",ncc);
				putresp(tc,220,"Ok (reusing)");
				continue;
			}
			DEBUG("--SFTPGW DONE\n");
			break;
		}else
		if( strcaseeq(com,"NOOP") ){
			putresp(tc,200,"Ok");
		}else
		if( strcaseeq(com,"USER") ){
			strcpy(user,arg);
			putresp(tc,331,"Send password or passphrase for '%s'",
				arg);
		}else
		if( strcaseeq(com,"PASS") ){
			if( ts != NULL ){
				toMD5(arg,md5);
				DEBUG("--SFTP reusing user[%s]pass[%s][%s]\n",
					user,passMD5,md5);
				if( !streq(md5,passMD5) ){
					putresp(tc,530,"No");
					continue;
				}else	putresp(tc,230,"Ok");
				putsftp(ts,"cd %s",logindir);
				relay_resp(fs,-1,0,AVStr(sresp),"restart",1);
				continue;
			}
			/*
			if( forkSftp(host,port,user,arg,tofrom_sftp) != 0 ){
			*/
			if( forkSftp(host,port,user,arg,tofrom_sftp,AVStr(sresp)) != 0 ){
				IStr(prompt,1024);
				lineScan(sresp,prompt);
				DEBUG("--SFTP login failed\n");
				/*
				putresp(tc,530,"No (Login failed)");
				*/
				putresp(tc,530,"No (Login failed:'%s')",prompt);
if( lGATEWAY() )
sv1log("####@@@@ LOGIN FAILURE\n");
continue; /* to return normal resp. for following commands... */
				break;
			}
			toMD5(arg,passMD5);
			fs = fdopen(tofrom_sftp[0],"r");
			ts = fdopen(tofrom_sftp[1],"w");
			fpv[1] = fs;
			nfc = 2;
			putresp(tc,230,"Ok");

			putsftp(ts,"pwd");
			relay_resp(fs,-1,0,AVStr(sresp),com,1);
			/*
			if( strneq(sresp,"Remote working directory: ",26) ){
				CStr(path,1024);
				lineScan(sresp+26,path);
			*/
			if( scanresp(sresp,"Remote working directory:",
			    AVStr(path),sizeof(path)) ){
				strcpy(logindir,path);
			}
		}else
		if( strcaseeq(com,"TYPE") ){
			putresp(tc,200,"Ok");
		}else
		if( strcaseeq(com,"PASV") ){
			PASV(tc,&vsock);
#if 0
			VSAddr ba;
			int balen;
			CStr(mport,128);
			vsock = server_open("SftpGW",VStrNULL,0,1);
			if( 0 <= vsock ){
				balen = sizeof(ba);
				getsockname(vsock,(SAP)&ba,&balen);
#if defined(__CYGWIN__)
				if( VSA_addrisANY(&ba) ){
				    /*connection to 0.0.0.0 fails on CYGWIN?*/
				    VSA_atosa(&ba,VSA_port(&ba),"127.0.0.1");
				}
#endif
				VSA_prftp(&ba,AVStr(mport));
			putresp(tc,227,"Enterning Passive Mode (%s)",mport);
			}else{
				putresp(tc,500,"No");
			}
#endif
		}else
		if( ts == NULL ){
			sv1log("Not Logged In: %s",req);
			putresp(tc,530,"Please login with USER and PASS.");
		}else
		if( strcaseeq(com,"PWD") ){
			putsftp(ts,"pwd");
			relay_resp(fs,-1,0,AVStr(sresp),com,1);
			/*
			if( strneq(sresp,"Remote working directory: ",26) ){
				CStr(path,1024);
				lineScan(sresp+26,path);
			*/
			if( scanresp(sresp,"Remote working directory:",
			    AVStr(path),sizeof(path)) ){
				putresp(tc,257,"\"%s\"",path);
			}else{
				putresp(tc,257,"\"/\"");
			}
		}else
		if( strcaseeq(com,"CWD") ){
			putsftp(ts,"cd %s",arg);
			relay_resp(fs,-1,0,AVStr(sresp),com,1);
			/*
			if( strneq(sresp,"Couldn't",8)
			 || strneq(sresp,"Can't",4) ){
			*/
			if( linehead(sresp,"Couldn't",0)
			 || linehead(sresp,"Can't",0) ){
				if( strstr(sresp,BadPath) )
					putresp(tc,550,BadPath);
				else
				putresp(tc,550,"No");
			}else	putresp(tc,250,"Ok");
		}else
		/*
		if( strcaseeq(com,"SIZE") ){
			putsftp(ts,"ls -ld %s",arg);
			relay_resp(fs,-1,0,AVStr(sresp),com,1);
			if( *sresp == '-' ){
				int sz = 0;
				sscanf(sresp,"%*s %*s %*s %*s %d",&sz);
				putresp(tc,213,"%d",sz);
			}else{
				putresp(tc,550,"Not a plain file");
			}
		}else
		*/
		if( strcaseeq(com,"STOR") ){
			if( vsock < 0 ){
				putresp(tc,500,"No");
				continue;
			}
			dsock = ACCEPT(vsock,1,-1,10);
			if( 0 <= dsock ){
				CStr(tmpf,1024);
				FILE *dfp;
				FILE *tmp;
				/*
				int bytes;
				*/
				FileSize Bytes;
				int isbin;
				double St;

				dfp = fdopen(dsock,"r");
				if( dfp == NULL ){
					putresp(tc,500,"No-1");
					continue;
				}
				tmp = getfile(AVStr(tmpf),"w",0);
				if( tmp == NULL ){
					putresp(tc,500,"No-2");
					fclose(dfp);
					continue;
				}
				putresp(tc,150,"Ok");
				St = Time();
				/*
				bytes = file_copy(dfp,tmp,NULL,DATA_MAX,&isbin);
				DEBUG("--SFTPGW bin=%d,%d bytes upload\n",
					isbin,bytes);
				*/
				Bytes = file_copy(dfp,tmp,NULL,datamax,&isbin);
				DEBUG("--SFTPGW bin=%d,%lld bytes upload\n",
					isbin,Bytes);
				fclose(tmp);
				fclose(dfp);

				DEBUG("--SFTPGW put %s (%lld %lld)\n",tmpf,
					Bytes,File_sizeX(tmpf));
				putsftp(ts,"put %s %s",tmpf,arg);
				/*
				relay_resp(fs,-1,15*1000,AVStr(sresp),com,1);
				*/
				relay_resp(fs,-1,5*1000,AVStr(sresp),com,1);

				if( strneq(sresp,"Uploading ",10)
				 && strstr(sresp,"sftp>") == 0 ){
					waitUploaded(com,AVStr(sresp),fs,fc,tc,
						Time()-St,&vsock);
				}else
				if( strncmp(sresp,"Could",5) == 0 )
					putresp(tc,550,"No");
				else	putresp(tc,226,"Ok");
				unlink(tmpf);
				dsock = -1;
			}else{
				putresp(tc,500,"accept error");
			}
			vsock = -1;
		}else
		if( strcaseeq(com,"RETR") ){
			if( vsock < 0 ){
				putresp(tc,500,"No");
				continue;
			}
			dsock = ACCEPT(vsock,1,-1,10);
			if( arg[0]==0 ||streq(arg,".") ||strtailstr(arg,"/") ){
				putresp(tc,550,"RETR for dir [%s]",arg);
				if( 0 <= dsock ){
					close(dsock);
					dsock = -1;
				}
			}else
			if( 0 <= dsock ){
				CStr(rpath,1024);
				FILE *rfp;
				int pid;

				truncVStr(rpath);
				getfile(AVStr(fifo),NULL,1);
				if( SFTP_WITH_SEEK ){
					/* newer sftp with output seeking */
					sprintf(rpath,"%sr",fifo);
					rfp = fopen(rpath,"w+");
					if( rfp ){
					  pid = Fork("SFTP-DATA");
					  if( pid == 0 ){
						/*
						relayFile2Fifo(rfp,rpath,fifo);
						*/
						relayFile2Fifo(fs,rfp,rpath,fifo);
						_exit(0);
					  }
					  else{
						fclose(rfp); /* 9.9.8 */
					  }
					}
					putsftp(ts,"get %s %s",arg,rpath);
				}else{
				putsftp(ts,"get %s %s",arg,fifo);
				}
				/*
				if( relay_fifo(fs,tc,fifo,dsock,com)==0 )
				*/
				leng = relay_fifo(fs,tc,fifo,dsock,com,AVStr(sresp));
				if( leng <= 0 ){
					sv1log("RETR ERROR: %s\n",sresp);
				}
				if( leng == 0 && strstr(sresp,BadPath) )
					putresp(tc,550,BadPath);
				else
				if( 0 < leng )
					putresp(tc,226,"Ok");
				else	putresp(tc,550,"No");
				relay_resp(fs,-1,1,AVStr(sresp),com,1);
				if( rpath[0] ){
					unlink(rpath);
					xpid = NoHangWait();
					DEBUG("--SFTP-DATA finished, pid=%d\n",
						xpid);
				}
				close(dsock);
				dsock = -1;
				unlink(fifo);
			}else{
				putresp(tc,500,"accept error");
			}
			if( 0 <= vsock ){
				close(vsock); /* 9.9.8 */
			}
			vsock = -1;
		}else
		if( strcaseeq(com,"NLST") || strcaseeq(com,"LIST") ){
			if( vsock < 0 ){
				putresp(tc,500,"No");
				continue;
			}
			dsock = ACCEPT(vsock,1,-1,10);
			if( 0 <= dsock ){
				putresp(tc,150,"Ok");
				if( arg[0] == '-' ){
					char *op;
					for( op = arg+1; *op; ){
						if( strchr(" \t\r\n",*op) )
							break;
						if( strchr("L",*op) ){
							ovstrcpy(op,op+1);
						}else	op++;
					}
				}
				/*
				if( streq(com,"NLST") || strstr(arg,"-l") )
					putsftp(ts,"ls %s",arg);
				else	putsftp(ts,"ls -l %s",arg);
				relay_resp(fs,dsock,0,VStrNULL,com,0);
				*/
				if( streq(com,"NLST") || strstr(arg,"-l") )
					sprintf(scom,"ls %s",arg);
				else	sprintf(scom,"ls -l %s",arg);
				putsftp(ts,"%s",scom);
				relay_list(fs,dsock,scom);
				close(dsock);
				dsock = -1;
				putresp(tc,226,"Ok");
			}else{
				putresp(tc,500,"accept error");
			}
			vsock = -1;
		}else
		if( ucom[0]==0xFF && ucom[1]==0xF4 /* IAC+IP */
		 && ucom[2]==0xF2 /* SYNC */
		 && strcaseeq(com+3,"ABOR") ){
			sv1log("--SFTPGW ABOR\n");
		}else
		if( strcaseeq(com,"RNFR") ){
			strcpy(rnfr,arg);
			putresp(tc,350,"Ok");
		}else
		if( strcaseeq(com,"RNTO") ){
			putsftp(ts,"rename %s %s",rnfr,arg);
			relay_resp(fs,-1,0,AVStr(sresp),com,1);
			if( dp = strstr(sresp,"Couldn't") ){
				lineScan(dp,resp1);
				putresp(tc,550,"No %s",resp1);
			}else	putresp(tc,250,"Ok");
		}else
		if( strcaseeq(com,"MKD") || strcaseeq(com,"RMD")
		 || strcaseeq(com,"DELE")
		){ 
			Bad = 550;
			if( strcaseeq(com,"MKD") ){
				Ok = 257;
				putsftp(ts,"mkdir %s",arg);
			}else
			if( strcaseeq(com,"RMD") ){
				Ok = 250;
				putsftp(ts,"rmdir %s",arg);
			}else{
				Ok = 250;
				putsftp(ts,"rm %s",arg);
			}
			relay_resp(fs,-1,0,AVStr(sresp),com,1);
			if( dp = strstr(sresp,"Couldn't") ){
				lineScan(dp,resp1);
				putresp(tc,Bad,"No %s",resp1);
			}else	putresp(tc,Ok,"Ok");
		}else
		{
			putresp(tc,502,"No not supported");
		}
	}
	if( fs != NULL && !feof(fs) ){
		putsftp(ts,"quit");
		relay_resp(fs,-1,0,AVStr(sresp),com,1);
	}
	xpid = NoHangWait();
	DEBUG("--SFTPGW finished, pid=%d\n",xpid);
}
static void sigTERM(int sig){
	int xpid;
	if( SftpPid ){
		if( 0 <= SftpPty ) close(SftpPty);
		msleep(10);
		Kill(SftpPid,SIGTERM);
		msleep(100);
		xpid = NoHangWait();
		sv1log("got SIGTERM/%d[%d] fin %d/%d\n",sig,SftpPid,SftpPty,
			xpid);
		SftpPty = -1;
		SftpPid = 0;
	}
	/* should salvage CC-socket ... */
	_Finish(0);
}
int sftpIsAlive(int fd){
	double St = Time();
	int rdy;
	int rcc;
	IStr(buf,128);
	refQStr(bp,buf);

	rdy = PollIn(fd,1000);
	sv1log("--rdy=%d alv=%d (%.3f)\n",rdy,IsAlive(fd),Time()-St);
	if( 0 < rdy ){
		rcc = recvPeekTIMEOUT(fd,AVStr(buf),sizeof(buf)-1);
		if( 0 < rcc ){
			setVStrEnd(buf,rcc);
			if( bp = strchr(buf,'\n') )
				clearVStr(bp);
		}
	}
	sv1log("---- SFTPCC Alive? [%d] rdy=%d rcc=%d alv=%d [%s]\n",
		fd,rdy,rcc,IsAlive(fd),0<rcc?buf:"");

	if( 0 < IsAlive(fd) ){
		return 1;
	}
	return 0;
}
int connectToSftp(const char *host,int port,const char *user,int fdc,int fdv[]){
	int socks[2];

	socks[1] = CC_connect("sftp",host,port,user);
	if( 0 <= socks[1] ){
		DEBUG("---- SFTPCC HIT[%d] %s@%s:%d\n",socks[1],user,host,port);
		if( !sftpIsAlive(socks[1]) ){
			close(socks[1]);
		}else
		return socks[1];
	}
	DEBUG("---- SFTPCC MISS %s@%s:%d\n",user,host,port);
	Socketpair(socks);
	if( Fork("SftpGW") == 0 ){
		int fi;
		for( fi = 0; fi < fdc; fi++ )
			close(fdv[fi]);
		close(socks[1]);
		closeServPorts();
		signal(SIGINT,sigTERM);
		signal(SIGTERM,sigTERM);
		SftpGW(host,port,socks[0]);
		_exit(0);
	}
	close(socks[0]);
	return socks[1];
}
