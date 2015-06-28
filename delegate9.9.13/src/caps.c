const char *SIGN_caps_c="{FILESIGN=caps.c:20141031194212+0900:e4a4048df60febb0:Author@DeleGate.ORG:RWKPTzv2hBaBCzPYzSPRSIHNo3FJPoEDX1rP+4jNypQKgmautsLYGkFVrnfDxWGbIG8lvH4tIKxkB7HvZSsUbYxh1xnqqp4bfHByo8Nh9SphmAlRkhozJGWihWhIrenwZborq5QKW2CAHq0ImLNhffu9nYOY/XxBoEvXW34tU6o=}";

/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2008 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	caps.c (capability contorol)
Author:		Yutaka Sato <ysato@delegate.org>
Description:

History:
	081020	created
	081021	extracted setup_exeid()  and beDaemon() from delegated.c
//////////////////////////////////////////////////////////////////////#*/

#include "file.h" /* 9.9.7 should be included first with -DSTAT64 */
#include <errno.h>
#include <sys/types.h>
/*
#include <sys/stat.h>
*/
#include <fcntl.h>
#include "delegate.h"
#include "vsignal.h"
#include "proc.h"
#include "log.h"
#include "auth.h"
#include "param.h"
#include "fpoll.h"
#include "credhy.h"
#include "config.h"

extern char **environ;
extern int LOG_initFd;
extern int WinServ;
static char REMOTE_ADDR[] = "REMOTE_ADDR";

int fromSSH();
void openServPorts();
int create_service(int ac,const char *av[],PCStr(port));
void ScanFileDefs(Connection *Conn);
int closeServPortsX(int clear);
int Send_file(int dpid,int fd,int closesrc,int inheritable);
void put_myconf(FILE *out);
void put_identification(FILE *out);
int askADMIN(FILE *out,FILE *in,PVStr(admin),int size);
int checkCACHEDIR(Connection *Conn);
int dumpCKeyParams(int mac,const char *av[],PVStr(abuf));
extern int RESOLV_UNKNOWN;
extern int SCRIPT_UNKNOWN;

void putWinStatus(PCStr(fmt),...);
extern int DGEXE_DATE;
extern int DGEXE_SIZE;
extern int DGEXE_MD532;
int exeMD5(FILE *fp,MD5 *md5,PVStr(amd5),int silent);
const char *getEXEsignMD5(PVStr(md5));
int sslway_dl();
#define substfile DELEGATE_substfile
#define substFile(f) substfile(AVStr(f),"",VStrNULL,VStrNULL,VStrNULL);

void setup_hostid(FILE *out,int verb);

#ifndef OPT_S /*{*/

void setup_exeid(Connection *Conn){
	CStr(path,1024);
	CStr(idpath,1024);
	FILE *fp;
	FILE *mfp;
	int ino;
	int len;
	CStr(sk,128);
	CStr(ei,1024);
	CStr(eei,1024);
	int silent = (InvokeStats & INV_ASFILTER);

	setup_hostid(NULL,0);

	strcpy(path,EXEC_PATH);
	if( !isFullpath(path) ){
		/* it might be in relative path in PATH,
		 * or not even in PATH,
		 * or not readble after setuid() ...
		*/
		fullpathCOM(EXEC_PATH,"r",AVStr(path));
	}
	DGEXE_DATE = File_mtime(path);
	DGEXE_SIZE = File_size(path);
	ino = File_ino(path);
	sprintf(sk,"%d.%d.%d.%s",DGEXE_DATE,DGEXE_SIZE,ino,path);

	sprintf(idpath,"${ADMDIR}/exeid/%08X",strCRC32(path,strlen(path)));
	substFile(idpath);
	if( mfp = dirfopen("exeid",AVStr(idpath),"r+") ){
	    int eino,date,size,crc;
	    eino = date = size = crc = 0;
	    if( file_mtime(fileno(mfp)) < DGEXE_DATE ){
		/* info. of old executable */
	    }else
	    if( fgets(eei,sizeof(eei),mfp) != NULL ){
		len = adecrypty(sk,strlen(sk),eei,strlen(eei),ei);
		if( 0 < len ){
			sscanf(ei,"%X %X %X %X\n",&eino,&date,&size,&crc);
			if( date == DGEXE_DATE && size == DGEXE_SIZE ){
				DGEXE_MD532 = crc;
			}
		}
		fseek(mfp,0,0);
	    }
	}else{
		mfp = dirfopen("exeid",AVStr(idpath),"w+");
	}

	if( sslway_dl() <= 0 ){
		putWinStatus("** No SSL library...");
	}else
	if( DGEXE_MD532 == 0 && mfp != NULL && (fp = fopen(path,"r")) ){
		double Start = Time();
		CStr(fmd5,64);
		CStr(bmd5,64);

		if( !silent )
		fprintf(stderr,"** checking the integrity of %s ...\n",path);
		putWinStatus("** Verifying the executable...");
		exeMD5(fp,NULL,AVStr(fmd5),silent);
		getEXEsignMD5(AVStr(bmd5));
		fclose(fp);
		if( strstr(fmd5,bmd5) != fmd5 ){
			int ign = 0;
			sv0log("-- checked integrity:ERROR (%.3f) %s %s\n",
				Time()-Start,fmd5,bmd5);
			fprintf(stderr,"FATAL: seems interpolated: %s\n",path);
			fprintf(stderr,"\
## Note: it might be an effect of some kind of optimization as 'prelink'.\r\n\
## If you are sure that there was not interpolation, repair it by updating\r\n\
## the checksum in the executable file as follows:\r\n");
			fprintf(stderr,"##   cp %s /tmp/dg\n",path);
			fprintf(stderr,"##   /tmp/dg -Fesign -w %s\n",path);
			/* if( the reason of fairue is the lacking of SSL */
			if( isWindowsCE() || lSINGLEP() && isWindows() ){
				int getAnswerYN(PCStr(msg),PVStr(ans),int siz);
				IStr(msg,1024);
				IStr(ans,32);
				sprintf(msg,"%s: %s\n%s\n%s\n",
					"Might be interpolated",path,
					fmd5,bmd5);
				getAnswerYN(msg,AVStr(ans),sizeof(ans));
				if( ans[0] == 'y' ){
					ign = 1;
				}
			}
			if( !ign )
			Finish(-1);
		}
		sv0log("-- checked integrity:OK (%.3f) %s\n",Time()-Start,bmd5);

		setVStrEnd(fmd5,8);
		sscanf(fmd5,"%X",&DGEXE_MD532);
		if( !silent )
		fprintf(stderr,"** checking DONE (took %.3f seconds)\n",
			Time()-Start);
		sprintf(ei,"%X %X %X %X %s",
			ino,DGEXE_DATE,DGEXE_SIZE,DGEXE_MD532,path);
		aencrypty(sk,strlen(sk),ei,strlen(ei),eei);
		fprintf(mfp,"%s\n",eei);
	}
	if( mfp ){
		fclose(mfp);
	}
}

void syncDaemon(int dmsync){
	void (*sigp)(int);

	if( 0 <= dmsync ){
		char dmstat = 0;
		if( RESOLV_UNKNOWN ) dmstat |= 1;
		if( SCRIPT_UNKNOWN ) dmstat |= 2;
		sigp = signal(SIGPIPE,SIG_IGN);
		if( PollIn(dmsync,10) ){
			/* to suppress SIGPIPE */
			sv1log("--beDaemon:[%d]%d parent=%d/%d\n",
				dmsync,IsAlive(dmsync),
				getppid(),procIsAlive(getppid()));
		}else{
			/* try to catch delayed SIGPIPE on SVR4? */
			int rdy1,wcc,err1;
			wcc =
		write(dmsync,&dmstat,1);
			err1 = errno;
			rdy1 = PollIn(dmsync,50);
			sv1log("--beDaemon:[%d]%d wcc=%d err=%d rdy=%d %d/%d\n",
				dmsync,IsAlive(dmsync),wcc,err1,rdy1,
				getppid(),procIsAlive(getppid()));
		}
		/*signal(SIGPIPE,sigPIPE);*/
		signal(SIGPIPE,sigp);
	}
	if( 0 <= dmsync ) close(dmsync);
}

int dump_hostidX(PVStr(out),int verb);
int beDaemon(Connection *Conn,const int isService,const double waitBG){
	const char *av[MAX_ARGC]; /**/
	CStr(port,PORTSSIZE);
	CStr(param,128);
	int ac,ai;
	const char *admin;
	CStr(admbuff,128);
	CStr(parambuff,128);
	CStr(logtype,32);
	CStr(logtype2,32);
	CStr(logtype3,32);
	const char *env;
	CStr(desc,32);
	CStr(ckeys,1024);
	IStr(hostid,256);

	if( !INHERENT_spawn() ){
		int dmsync[2];
		Socketpair(dmsync);
		if( Fork("daemon") != 0 )
		{
			close(dmsync[1]);
			/*
			PollIn(dmsync[0],3*1000);
			*/
			if( isatty(1) || fromSSH() ){
				int nready;
				char dmstat[1];
				nready = PollIn(dmsync[0],(int)(waitBG*1000));
				dmstat[0] = (char)-1;
				if( 0 < nready ){
					if( read(dmsync[0],dmstat,1) <= 0 ){
						dmstat[0] = (char)-2;
					}
				}
				sv1log("--beDaemon: ready=%d, stat=%d\n",
					nready,dmstat[0]);
			}
			sv1log("--beDaemon: going background ...\n");
			close(dmsync[0]);
			sv1log("--beDaemon: going background\n");
			_Finish(0);
		}
		close(dmsync[0]);

		setsid();
		if( isatty(0)
		 || fromSSH()
		){
			dup2(open("/dev/null",0),0);
		}
		return dmsync[1];
	}
	if( isService ){ /* it is running as a service */
		return -1;
	}

	ac = 0;	
	av[ac++] = EXEC_PATH;
	ac += copy_param(NULL,MAX_ARGC-ac-8,&av[ac],(const char**)environ);
	ac += copy_param("*+",MAX_ARGC-ac-8,&av[ac],&main_argv[1]);
	/*
	printServPort(AVStr(port),"",1);
	*/
	printServPort(AVStr(port),"",-1); /* -1 to get -Pxxx/admin */
	sprintf(param,"-P%s",port);
	av[ac++] = param;
	sprintf(logtype,"-L0x%x",LOG_type);
	av[ac++] = logtype;
	if( LOG_type2 || LOG_bugs ){
		sprintf(logtype2,"-L20x%X/%X",LOG_type2,LOG_bugs);
		av[ac++] = logtype2;
	}
	if( LOG_type3 || LOG_type4 ){
		sprintf(logtype3,"-L30x%X/%X",LOG_type3,LOG_type4);
		av[ac++] = logtype3;
	}
	if( EccEnabled() ){
		av[ac++] = "-Ecc";
	}
	for( ai = 0; ai < main_argc; ai++ ){
		if( elnumof(av)-2 <= ac ){
			fprintf(stderr,"too many arguments -- ignored\n");
			break;
		}
		if( streq(main_argv[ai],"-SERVICE") ){
			av[ac++] = "-SERVICE";
			break;
		}
		if( strncmp(main_argv[ai],"-W",2) == 0 ){
			av[ac++] = main_argv[ai];
		}
		if( strncmp(main_argv[ai],"-d",2) == 0 )
			av[ac++] = main_argv[ai];

		if( strncmp(main_argv[ai],"-n",2) == 0 ){
			av[ac++] = main_argv[ai];
		}
		if( strncmp(main_argv[ai],"-Q",2) == 0 ){
			av[ac++] = main_argv[ai];
		}
	}
	av[ac] = 0;
	if( env = getenv(REMOTE_ADDR) ){
		/* don't hold the file-descriptor for output to CGI */
		sv1log("---- DON'T SEND CGI OUTPUT TO THE SERVER: %s\n",env);
	}else
	/* stdout.log */{
		int xd;
		xd = Send_file(getpid(),fileno(stdout),0,1);
		sprintf(desc,"-IO%d",xd);
		av[ac++] = desc;
		av[ac] = 0;
	}

	if( !lQUIET() ){
	put_myconf(stdout);
	put_identification(stdout);
	putSRCsign(stdout);
	}
	admin = getADMIN1();
	fprintf(stderr,"DGROOT=%s\r\n",DELEGATE_DGROOT);
	fprintf(stderr,"ADMIN=%s\r\n",admin?admin:"");
	dump_hostidX(AVStr(hostid),0);
	fprintf(stderr,"HostID: %s\r\n",hostid);
	sv0log("HostID: %s\r\n",hostid);
	fflush(stderr);

	if( admin == NULL || *admin == 0 ){
		printf("CAUTION: ADMIN is not specified.\r\n");
		printf("You must declare your E-mail address.\r\n");

		admbuff[0] = 0;
		if( askADMIN(stdout,stdin,AVStr(admbuff),sizeof(admbuff)) != 0 )
			Finish(0);
		if( admbuff[0] == 0 ){
			printf("EXIT: You must declare ADMIN\r\n");
			Finish(0);
		}
		sprintf(parambuff,"ADMIN=%s",admbuff);
		av[ac++] = parambuff;
		av[ac] = NULL;
	}
	else
	if( getv(av,P_ADMIN) == NULL ){
		sprintf(parambuff,"%s=%s",P_ADMIN,admin);
		av[ac++] = parambuff;
		av[ac] = 0;
	}
	ScanFileDefs(Conn);
	if( checkCACHEDIR(Conn) != 0 )
		Finish(-1);

	WinServ = 1;
	dumpCKey(1);
	ac += dumpCKeyParams(elnumof(av)-ac,av+ac,AVStr(ckeys));

	sv0log("#### start a service...\n");
	if( 0 <= LOG_initFd ){
		lock_unlock(LOG_initFd);
	}

	fprintf(stderr,"... testing ports to be used [%s] ...\n",port);
	fflush(stderr);
	openServPorts();
	closeServPortsX(0);
	/*
	closeServPorts();
	*/

	if( create_service(ac,av,port) )
	{	int elp;

		/* wait the service process to finish initialization */
		sleep(1);
		lock_sharedTO(LOG_initFd,10*1000,&elp);
		lock_unlock(LOG_initFd);
		exit(0);
	}

	sv1log("#### DO NOT FORK TO BE DAEMON\n");
	return -1;
}

int setup_caps(FILE *out,PCStr(slkey),PCStr(admin),int test);
void scan_CAPSKEY(Connection *Conn,PCStr(capskey)){
	setup_caps(stderr,capskey,getADMIN1(),0);
}
void NOSRC_warn(PCStr(func),PCStr(fmt),...){
	IStr(msg,256);
	VARGS(8,fmt);

	sprintf(msg,"## %s: Not Available in the Source Distribution",func);
	porting_dbg("%s",msg);
	fprintf(stderr,"%s\r\n",msg);
}
void NOCAP_warn(PCStr(caps),PCStr(fmt),...){
	IStr(msg,256);
	VARGS(8,fmt);

	sprintf(msg,"## %s: CAPSKEY not available\r\n",caps);
	porting_dbg("%s",msg);
	fprintf(stderr,"%s",msg);
}

int dump_hostid(PVStr(out),int verb);
int dump_hostidX(PVStr(out),int verb){
	int rcode;

	rcode = dump_hostid(BVStr(out),verb);
#if defined(_MSC_VER) && !isWindowsCE()
	if( isWindows() ){
		Xsprintf(TVStr(out)," (tz=%d db=%d dl=%d)",
			_timezone/3600,_dstbias/3600,_daylight);
	}
#endif
	return rcode;
}
int hostid_main(int ac,const char *av[]){
	IStr(shid,256);
	FILE *out = stdout;
	int vs = 0;

	setup_hostid(NULL,0);

	if( LOG_VERBOSE ) vs = 1;
	if( lSILENT() ) vs = -1;
	dump_hostidX(AVStr(shid),vs);
	if( 0 <= vs )
		fprintf(out,"HostID: ");
	fprintf(out,"%s\n",shid);
	return 0;
}
#endif /*} OPT_S */

/* '"DIGEST-OFF"' */
        
