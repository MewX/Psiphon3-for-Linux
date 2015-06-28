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
Program:	syslog.c (RFC3164)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	951029	created
	060617	extended as a log broker
//////////////////////////////////////////////////////////////////////#*/
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "vsocket.h"
#include "dglib.h"
#include "file.h"
#include "log.h"
#include "yarg.h"
#include "fpoll.h"

void send_syslogX(PCStr(lclass),PCStr(log));
void openlogX(PCStr(ident),PCStr(logopt),int facility);
void syslogX(int priority,PCStr(fmt),...);

/*
 * SYSLOG=-vs,syslog://host:port
 * SYSLOG=-vH,file://dir/file.log
 *   -s emerg  alert  crit  err  warning  notice  into  debug 
 *   -f auth   cron  daemon ftp  mail news  user
 */
static const char *Severity[] = {
	"emerg",
	"alert",
	"crit",		/* critical */
	"err",
	"warning",
	"notice",
	"info",
	"debug",
	0,
};
static int sevn(PCStr(name)){
	int fi;
	const char *fn;
	for( fi = 0; fn = Severity[fi]; fi++ ){
		if( strneq(name,fn,strlen(fn)) ){
			return fi;
		}
	}
	return -1;
}
static const char *Facility[] = {
/* 0 */	"kern",
	"user",
	"mail",
/* 3 */	"daemon",
	"auth",
	"syslog",
	"lpr",
/* 7 */	"news",
/* 8 */	"uucp",
/* 9 */	"cron",
/*10 */	"authpriv",
/*11 */	"ftp",
	"netinfo",
/*13 */	"remoteauth",
/*14 */	"auth",
/*15 */	"cron",
/*16 */	"local0",
	"local1",
	"local2",
	"local3",
	"local4",
	"local5",
	"local6",
/*23 */	"local7",
	0
};
static int facn(PCStr(name)){
	int fi;
	const char *fn;
	for( fi = 0; fn = Facility[fi]; fi++ ){
		if( strneq(name,fn,strlen(fn)) ){
			return fi;
		}
	}
	return -1;
}

extern int SYSLOG_EMERG;
extern int SYSLOG_ALERT;
extern int SYSLOG_CRIT;
extern int SYSLOG_ERR;
extern int SYSLOG_WARNING;
extern int SYSLOG_NOTICE;
extern int SYSLOG_INFO;
extern int SYSLOG_DEBUG;

static int SYSLOG_DAEMON  = (3<<3);
extern int SYSLOG_PRIMASK;

int MAIN_argc;
const char **MAIN_argv;

#ifdef daVARGS      
#undef VARGS
#define VARGS daVARGS
#define LINESIZE 4096
#endif

void Syslog(int priority,PCStr(fmt),...)
{	int level;
	int se = errno;
	VARGS(14,fmt);

	level = priority & SYSLOG_PRIMASK;
	if( level <= SYSLOG_CRIT )
		sv1tlog(fmt,VA14);
	else
	if( level <= SYSLOG_INFO )
		sv1log(fmt,VA14);
	else	sv1vlog(fmt,VA14);
	errno = se;
}
int FMT_syslog_ERROR(PCStr(fmt),...)
{
	VARGS(14,fmt);
	Syslog(SYSLOG_ERR,fmt,VA14);
	return 0;
}
int FMT_syslog_DEBUG(PCStr(fmt),...)
{
	VARGS(14,fmt);
	Syslog(SYSLOG_DEBUG,fmt,VA14);
	return 0;
}

static void res_debug(PCStr(fmt),...)
{	CStr(msg,4096);
	VARGS(14,fmt);

	sprintf(msg,"{R} ");
	Xsprintf(TVStr(msg),fmt,VA14);
	sv1log("%s",msg);
}

extern iFUNCP RES_debugprinter;
iFUNCP DEBUG_printf = (iFUNCP)FMT_syslog_DEBUG;

void syslog_init(){
	RES_debugprinter = (iFUNCP)res_debug;
}


/*
int service_syslog(DGC*ctx)
{
*/
int service_syslog(DGC*ctx,int sock,int port){
	CStr(ib,0x10000);
	IStr(ibo,0x10000);
	int icc;
	CStr(froma,256);
	int fromp;
	int ni = 0;
	IStr(tstp,32);
	int rep = 0;

	for(;;){
		/*
		if( lFG() ){
		*/
		if( lFG() || curLogFp() ){
			if( PollIn(sock,200) == 0 ){
				if( curLogFp() ) fflush(curLogFp());
				fflush(stdout);
			}
		}
		icc = RecvFrom(sock,(char*)ib,sizeof(ib)-1,AVStr(froma),&fromp);
		if( 0 < icc ){
			setVStrEnd(ib,icc);
			if( strcmp(ib,ibo) == 0 ){
				rep++;
				continue;
			}
			if( 1 < rep ){
				if( curLogFp() )
				fprintf(curLogFp(),"(repeated %d times)\n",rep);
			}
			rep = 0;
			strcpy(ibo,ib);
			if( lVERB() ){
				sprintf(tstp,"%d ",++ni);
			}
			if( curLogFp() ){
				fprintf(curLogFp(),"%s%s:%d %s\n",tstp,froma,fromp,ib);
			}
			if( lFG() && !lCONSOLE() )
			printf("%s%s:%d %s\n",tstp,froma,fromp,ib);
		}
	}
	return 0;
}

#define SL_LOCAL	0x00000001
#define SL_ERROR	0x00000002
#define SL_NOPRI	0x00000010
#define SL_NOPID	0x00000020
#define SL_NOTIME	0x00000040
#define SL_NOHOST	0x00000080
#define SL_NONAME	0x00000100
#define SL_NOHEAD	0x00000800
#define SL_ADDNL	0x00001000
#define SL_SILENT	0x00002000
#define SL_TERSE	0x00004000
#define SL_NOACCLOG	0x00010000
#define SL_PRMSEC	0x00100000
#define SL_PRCSEC	0x00200000
#define SL_PRCLASS	0x10000000
int INHERENT_syslog();

typedef struct {
	DGC    *s_Conn;
	int	s_fd;
	FILE   *s_lfp;
	int	s_facn; /* facility number */
	int	s_sevn; /* severity level bias for LOG_DEBUG */
	int	s_flags;
	char   *s_hostport;
	char   *s_myhost;
	char   *s_myname;
} SysLog;

const char *LOG_myhost;
const char *LOG_myname = "DeleGate";
static SysLog LOG_syslogs[8];
static int LOG_syslogx;

static int makeHead(PVStr(msg),SysLog *SL,int pri,int pid){
	if( SL->s_flags & SL_NOHEAD ){
		setVStrEnd(msg,0);
		return 0;
	}
	if( LOG_myhost == 0 ){
		CStr(me,128);
		gethostname(me,sizeof(me));
		LOG_myhost = stralloc(me);
	}
	setVStrEnd(msg,0);
	if( (SL->s_flags & SL_NOPRI) == 0 ){
		int prix;
		if( pri == SYSLOG_DEBUG ){
			if( 0 < SL->s_sevn ){
				pri = SL->s_sevn;
			}
		}
		prix = (SL->s_facn << 3) | pri;
		Xsprintf(TVStr(msg),"<%d>",prix);
	}
	if( (SL->s_flags & SL_NOTIME) == 0 ){
		int sc,us;
		CStr(ts,128);
		/*
		StrftimeLocal(AVStr(ts),sizeof(ts),"%b %d %H:%M:%S",time(0),0);
		*/
		sc = Gettimeofday(&us);
		StrftimeLocal(AVStr(ts),sizeof(ts),"%b %d %H:%M:%S%.3s",sc,us);
		Xsprintf(TVStr(msg),"%s ",ts);
	}
	if( (SL->s_flags & SL_NOHOST) == 0 ){
		if( SL->s_myhost )
			Xsprintf(TVStr(msg),"%s ",SL->s_myhost);
		else	Xsprintf(TVStr(msg),"%s ",LOG_myhost);
	}
	if( (SL->s_flags & SL_NONAME) == 0 ){
		if( SL->s_myname )
			Xsprintf(TVStr(msg),"%s",SL->s_myname);
		else	Xsprintf(TVStr(msg),"%s",LOG_myname);
	}
	if( (SL->s_flags & SL_NOPID) == 0 ){
		if( lSINGLEP() ){
			Xsprintf(TVStr(msg),"[%04X]",TID);
		}else
		Xsprintf(TVStr(msg),"[%d]",pid);
	}
	Xsprintf(TVStr(msg),": ");
	return 1;
}

int open_syslog(SysLog *SL,PCStr(url))
{	CStr(hostport,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	int port;
	FILE *lfp = NULL;
	int lfd = -1;
	int flags = SL->s_flags;
	CStr(lhost,MaxHostNameLen);
	int lport;

	if( strncaseeq(url,"file:",5) ){
		if( lfp = fopen(url+5,"a") ){
			lfd = fileno(lfp);
			flags |= SL_ADDNL;
			goto logstart;
		}
		return -1;
	}
	if( isFullpath(url) || File_isreg(url) ){
		if( lfp = fopen(url,"a") ){
			lfd = fileno(lfp);
			flags |= SL_ADDNL;
			goto logstart;
		}
		return -1;
	}

	if( Xsscanf(url,"syslog://%s",AVStr(hostport)) <= 0 )
	{	CStr(file,256);
		if( 0 < Xsscanf(url,"syslog:%s",AVStr(file)) ){
			lfd = UDP_client_open("syslog","syslog",file,0);
			if( 0 <= lfd )
				goto logstart;
			return lfd;
		}
		return -1;
	}

	port = scan_hostport("syslog",hostport,AVStr(host));
	if( SRCIFfor(SL->s_Conn,"syslog",host,port,AVStr(lhost),&lport) ){
		lfd = UDP_client_open1("syslog","syslog",host,port,lhost,lport);
	}else
	lfd = UDP_client_open("syslog","syslog",host,port);

logstart:
	if( lfp != NULL ){
		lfd = fileno(lfp);
	}
	if( 0 <= lfd ){
		SL->s_lfp = lfp;
		SL->s_fd = lfd;
		SL->s_flags = flags;
		send_syslogX("F","server started\n");
	}
	return lfd;
}

void scan_SYSLOG(DGC*Conn,PCStr(conf)){
	const char *cp;
	SysLog *SL;

	if( elnumof(LOG_syslogs) <= LOG_syslogx ){
		fprintf(stderr,"-- TOO MANY SYSLOGS(%d+1) %s\n",
			LOG_syslogx,conf);
		return;
	}
	SL = &LOG_syslogs[LOG_syslogx];
	SL->s_facn = 3; /* daemon */
	SL->s_Conn = Conn;

	cp = conf;
	while( *cp == '-' ){
		switch( cp[1] ){
		  case 'v':
		    switch( cp[2] ){
			case 'c': SL->s_flags |= SL_PRCLASS; break;
			case 't': SL->s_flags |= SL_TERSE; break;
			case 's': SL->s_flags |= SL_SILENT; break;
			case 'S': SL->s_flags |= SL_NOACCLOG; break;
			case 'H': SL->s_flags |= SL_NOHEAD; break;
			case 'Q': SL->s_flags |= SL_NOPRI; break;
			case 'T': SL->s_flags |= SL_NOTIME; break;
			case 'D': SL->s_flags |= SL_NOHOST; break;
			case 'N': SL->s_flags |= SL_NONAME; break;
			case 'P': SL->s_flags |= SL_NOPID; break;
			case 'M': SL->s_flags |= SL_PRMSEC; break;
			case 'C': SL->s_flags |= SL_PRCSEC; break;
		    }
		    break;
		  case 's':
			SL->s_sevn = sevn(cp+2);
			if( SL->s_sevn < 0 && isdigit(cp[2]) )
				SL->s_sevn = atoi(cp+2);
			if( SL->s_sevn < 0 ){
				fprintf(stderr,"SYSLOG=-f%s Unknown Severity\n",
					cp+2);
				SL->s_flags |= SL_ERROR;
			}
			break;
		  case 'f':
			SL->s_facn = facn(cp+2);
			if( SL->s_facn < 0 && isdigit(cp[2]) )
				SL->s_facn = atoi(cp+2);
			if( SL->s_facn < 0 ){
				fprintf(stderr,"SYSLOG=-f%s Unknown Facility\n",
					cp+2);
				SL->s_flags |= SL_ERROR;
			}
			break;
		}
		for( cp++; *cp; cp++ ){
			if( *cp == ',' ){
				cp++;
				break;
			}
		}
	}

	if( SL->s_flags & SL_ERROR )
		return;

	if( *cp == 0 ){
		if( INHERENT_syslog() ){
			CStr(opts,128);
			strcpy(opts,"ndeay");
			if( (SL->s_flags & SL_NOPID) == 0 )
				strcat(opts,",pid");
			openlogX("DeleGate",opts,3);
			SL->s_flags |= SL_LOCAL;
			LOG_syslogx++;
			return;
		}
		if( 0 <= open_syslog(SL,"syslog:/dev/log")
		 || 0 <= open_syslog(SL,"syslog://localhost")
		){
			LOG_syslogx++;
		}
	}else{
		if( 0 <= open_syslog(SL,cp) ){
			LOG_syslogx++;
		}
	}
}

/*
void send_syslogX(PCStr(lclass),PCStr(log))
*/
int SUPPRESS_SYSLOG;
void send_syslogY(PCStr(lclass),PCStr(log))
{	const char *logp;
	const char *dp;
	const char *ep;
	CStr(head,256);
	CStr(msg,0x4000);
	int wcc,hlen;
	int pri;
	int pid = -1;
	int li;
	SysLog *SL;
	int mlen;
	int acclog = 0;

	if( SUPPRESS_SYSLOG )
		return;
	if( LOG_syslogx <= 0 )
		return;

	if( lclass && *lclass == *LS_ACCESS ){
		acclog = 1;
		pri = SYSLOG_NOTICE;
		logp = log;
	}else{
		acclog = 0;
		pri = SYSLOG_DEBUG;
		if( lclass && *lclass == *LS_FATAL )
			pri = SYSLOG_ERR;
		/*
		else
		if( lclass && *lclass == *LS_VERBOSE )
			pri = SYSLOG_DEBUG;
		else	pri = SYSLOG_INFO;
		*/

		logp = log;
		if( lMULTIST() ){
		}else
		if( (dp = strchr(log,'[')) && (pid = atoi(dp+1))
		 && (ep = strchr(dp+1,']'))
		){
			logp = ep+1;
			if( *logp == ' ' )
				logp++;
		}
	}

	for( li = 0; li < LOG_syslogx; li++ ){
		SL = &LOG_syslogs[li];
		if( acclog ){
			if( SL->s_flags & SL_NOACCLOG ){
				continue;
			}
		}else{
			if( SL->s_flags & SL_SILENT ){
				continue;
			}
			if( SL->s_flags & SL_TERSE ){
				if( lclass == 0
				 || *lclass == LS_DEBUG[0]
				 || *lclass == LS_USUAL[0]
				){
					continue;
				}
			}
		}

		if( pid <= 0 )
			pid = getpid();
		makeHead(AVStr(head),SL,pri,pid);

		if( SL->s_flags & SL_LOCAL ){
			if( pri == SYSLOG_DEBUG ){
				if( 0 < SL->s_sevn ){
					pri = SL->s_sevn;
				}
			}
			linescanX(logp,AVStr(msg),sizeof(msg));
			if( SL->s_flags & SL_PRCSEC )
			syslogX(pri,".%02d %s",((int)(Time()*100))%100,msg);
			else
			if( SL->s_flags & SL_PRMSEC )
			syslogX(pri,".%03d %s",((int)(Time()*1000))%1000,msg);
			else
			syslogX(pri,"%s",msg);
		}else
		if( SL->s_lfp ){
			if( SL->s_flags & SL_PRCLASS ){
				fprintf(SL->s_lfp,"%s",lclass?lclass:" ");
			}
			if( (SL->s_flags & SL_NOHEAD) == 0 ){
				fputs(head,SL->s_lfp);
				fputs(logp,SL->s_lfp);
			}else{
				fputs(log,SL->s_lfp);
			}
			fflush(SL->s_lfp);
			if( ferror(SL->s_lfp) ){
				/* should be disabled */
			}
		}else{
			strcpy(msg,head);
			hlen = strlen(msg);
			linescanX(logp,QVStr(msg+hlen,msg),sizeof(msg)-hlen);
			mlen = strlen(msg);
			wcc = write(SL->s_fd,msg,mlen);
			if( wcc < mlen ){
			  fprintf(stderr,"[%d] Failed SYSLOG: %d/%d errno=%d\n",
				getpid(),wcc,mlen,errno);
			}
		}
	}
}
static int inSyslog;
void send_syslogX(PCStr(lclass),PCStr(log)){
	if( inSyslog ){
		return;
	}
	inSyslog++;
	send_syslogY(lclass,log);
	inSyslog--;
}
