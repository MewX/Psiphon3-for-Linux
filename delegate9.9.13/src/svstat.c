/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	loadstat.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	991206	created
ToDo:
	- describe the total format of ps-title
	- display the server in keep-alive if exist
	- common symbol which indicates process status (Polling, *Running, ...)
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "file.h"
#include "dglib.h"
#include "log.h"
#include <stdio.h>
int clearCloseOnExec(int fd);
int printServPort(PVStr(port),PCStr(prefix),int whole);

extern const char *DHTML_ENC;
int HTML_conv(PCStr(ttype),PCStr(srctxt),PVStr(dsttxt));

#define ST_ACC	0
#define ST_DONE	1

const char *mainProcTitleFmt = "RPM=%L(%l)%?i[,IDLE=%is]%?c[,ACT=%c]";
const char *loadaveFmt = "%l";

int NUM_CHILDREN;
int NUM_PEERS;
int alive_peers(){ return NUM_PEERS; }
int START_TIME1;
int START_TIME;
int DELEGATE_LastModified;
int SERNO();
int NUM_HUPS;
int SVSTAT_FD = -1;
int DGEXE_DATE;
int DGEXE_SIZE;
int DGEXE_MD532;

/*
 * long range counter by hour, day, week, ...
 * and possibly dumped into persistent file and reload on restart...
 */


#define LSWIN	15	/* 1/4 minute */
#define LSSIZE	60	/* 15 minutes */
typedef struct {
	int	s_time;
	int	s_qmin; /* 1/4 minute */
	int	s_done;
} LoadStat;

#define SVSVER	((1<<8)|1)
typedef struct {
	int	le_Version;
	char	le_exeVer[4];
	int	le_exeDate;
	int	le_exeSize;
	int	le_exeCrc32;
	int	le_svPause; /* soft break,pause */

	/* MStr(le_svName,32); was here */

	int	le_svLastmod;
	int	le_svPid;
	int	le_svServed;
	int	le_svSerno;
	int	le_svHups;
	int	le_svActive;
	int	le_svTrace;
	int	le_svStarted;
	int	le_svUpdated;
	int	le_numUpdate;
	MStr(	le_svRusage,sizeof(long)*20);
	/* short le_chirdlen[128]; ... active children process list ... */

	int	le_TotalCount[2];
	int	le_TotalLast[2];
    LoadStat	le_loadStats[2][LSSIZE];
	MStr(	le_Stime,64);
	FILE   *le_loadStatFp;
	MStr(	le_reserved1,64);
	MStr(	le_svName,64);
	MStr(	le_reserved2,64);
} LoadStatEnv;

static LoadStatEnv *loadStatEnv;
#define svVersion	loadStatEnv->le_Version
#define exeVer		loadStatEnv->le_exeVer
#define exeDate		loadStatEnv->le_exeDate
#define exeSize		loadStatEnv->le_exeSize
#define exeCrc32	loadStatEnv->le_exeCrc32
#define svName		loadStatEnv->le_svName

#define svPid		loadStatEnv->le_svPid
#define svLastmod	loadStatEnv->le_svLastmod
#define svHups		loadStatEnv->le_svHups
#define svSerno		loadStatEnv->le_svSerno
#define svActive	loadStatEnv->le_svActive
#define svServed	loadStatEnv->le_svServed
#define svTrace		loadStatEnv->le_svTrace
#define svStarted	loadStatEnv->le_svStarted
#define svRusage	loadStatEnv->le_svRusage
#define svUpdated	loadStatEnv->le_svUpdated

#define numUpdate	loadStatEnv->le_numUpdate
#define loadStats	loadStatEnv->le_loadStats
#define TotalCount	loadStatEnv->le_TotalCount
#define TotalLast	loadStatEnv->le_TotalLast
#define Stime		loadStatEnv->le_Stime
/**/
#define loadStatFp	loadStatEnv->le_loadStatFp

void minit_loadstat()
{
	if( loadStatEnv == 0 )
	{
		loadStatEnv = NewStruct(LoadStatEnv);
		svVersion = SVSVER;
		svStarted = time(0);
		svPid = getpid();
	}
}
int getExeVer(PVStr(ver));
char *strfLoadStat(PVStr(str),int size,PCStr(fmt),int now);
FILE *fopenSvstats(PCStr(port),PCStr(mode));
const char *get_svname();

int put_svstat()
{	int fd,wcc;
	CStr(stat,128);

	minit_loadstat();
	if( loadStatFp == NULL ){
		if( svName[0] ){
			loadStatFp = fopenSvstats(svName,"w+");
/*
fprintf(stderr,"+++[%d]-- put svstat(%s)\n",getpid(),svName);
*/
		}
		if( loadStatFp == NULL ){
			loadStatFp = fopenSvstats(get_svname(),"w+");
/*
fprintf(stderr,"---[%d]-- put svstat(%s)\n",getpid(),svName);
*/
		}
		if( loadStatFp == NULL )
		loadStatFp = TMPFILE("LoadStat");
		fd = fileno(loadStatFp);
		clearCloseOnExec(fd);
	}
	if( loadStatFp && 0 <= (fd = fileno(loadStatFp)) ){
		SVSTAT_FD = fd;

		Lseek(fd,0,0);
		if( START_TIME ) svStarted = START_TIME;
		svLastmod = DELEGATE_LastModified;
		exeSize = DGEXE_SIZE;
		exeDate = DGEXE_DATE;
		getExeVer(FVStr(exeVer));
		exeCrc32 = DGEXE_MD532;
		svHups = NUM_HUPS;
		svSerno = SERNO();
		svActive = NUM_CHILDREN;
		svServed = TOTAL_SERVED;
		svUpdated = time(0);
		numUpdate += 1;
		if( 0 ){
			strfLoadStat(AVStr(stat),sizeof(stat),"%L %l",time(0));
			fprintf(stderr,"put_svstat #%d [%s]\n",numUpdate,stat);
		}
		strfRusage(AVStr(svRusage),"%B",3,NULL);
		wcc = write(fd,loadStatEnv,sizeof(LoadStatEnv));
if(0){
CStr(ru,256);
strfRusage(AVStr(ru),"%ss %uu",4,svRusage);
fprintf(stderr,"+++[%d] put #%d fd=%d wcc=%d %s\n",getpid(),numUpdate,fd,wcc,ru);
}

		return fd;
	}
	return -1;
}
int set_svtrace(int code){
	if( loadStatEnv ){
		svPid = getpid();
		svTrace = code;
		put_svstat();
		return 1;
	}
	return 0;
}
void get_svstat(int fd);
const char *get_svname(){
	if( svName[0] == 0 ){
		CStr(port,128);
		printServPort(AVStr(port),"",0);
		if( port[0] == 0 )
			strcpy(port,"0");
		sprintf(svName,"_%s_",port);
/*
fprintf(stderr,"---[%d]-- get svName(%s)\n",getpid(),svName);
*/
	}
	return svName;
}
int set_svname(PCStr(name)){
	minit_loadstat();
	if( *svName != 0 ){
		fprintf(stderr,"[%d] don't overwrite svName:%s [%s]\n",
			getpid(),name,svName);
		return -1;
	}
	strcpy(svName,name);
/*
fprintf(stderr,"----[%d]-- set svName:%s\n",getpid(),svName);
*/
	return 0;
}
int close_svstat(){
	int fd;
	if( loadStatFp ){
		fd = fileno(loadStatFp);
		fclose(loadStatFp);
		loadStatFp = 0;
		SVSTAT_FD = -1;
		return fd;
	}
	return -1;
}
int set_svstat(int fd){
	FILE *fp;

	minit_loadstat();
	if( loadStatFp ){
		return 0;
	}
	fp = fdopen(fd,"r+");

	if( fp != NULL ){
		loadStatFp = fp;
		clearCloseOnExec(fd);
		if( 0 < NUM_HUPS ){ /* on restart */
/*
fprintf(stderr,"------------- reuse on HUP:%d\n",NUM_HUPS);
*/
			get_svstat(fd);
		}
		put_svstat();
		return 1;
	}else{
		return -1;
	}
}
void get_svstat(int fd)
{	int rcc;

	if( fd < 0 ){
		return;
	}
	minit_loadstat();
	Lseek(fd,0,0);
	rcc = read(fd,loadStatEnv,sizeof(LoadStatEnv));
}

void putLoadStat(int what,int done)
{	int now,qmin,idx;
	LoadStat *lsp;

	now = time(NULL);
	qmin = now / LSWIN;
	idx = qmin % LSSIZE;
	lsp = &loadStats[what][idx];
	if( lsp->s_qmin != qmin ){
		lsp->s_time = now;
		lsp->s_qmin = qmin;
		lsp->s_done = 0;
	}
	lsp->s_done += done; 
	TotalCount[what] += done;
	TotalLast[what] = now;
}
double getLoadStat(int what,int now,int mrange)
{	int qmin,qmin0,idx,cur;
	LoadStat *lsp;
	double cum,elp;

	qmin = now / LSWIN;
	qmin0 = qmin - mrange*(60/LSWIN);
	cum = 0;
	cur = 0;
	for( idx = 0; idx < LSSIZE; idx++ ){
		lsp = &loadStats[what][idx];
		if( lsp->s_qmin == qmin ){
			elp = now - lsp->s_time;
			if( elp <= 0 )
				elp = 1;
			cum += lsp->s_done * (LSWIN/elp);
		}else
		if( qmin0 < lsp->s_qmin && lsp->s_qmin < qmin )
			cum += lsp->s_done;
	}
	return cum;
}

char *strfLoadStat(PVStr(str),int size,PCStr(fmt),int now)
{	const char *fp;
	char fc;
	refQStr(sp,str); /**/
	const char *sx;
	refQStr(pp,str); /**/
	const char *tp;
	CStr(subfmt,256);
	double load;
	int cond;
	int last,idle,elp,done;
	double loadv[4]; /**/
	refQStr(dp,str);
	CStr(Rfmt,32);

	sx = str + size - 1;
	cpyQStr(sp,str);
	fp = fmt;
	while( fc = *fp++ ){
		if( sx <= sp )
			break;

		if( fc != '%' ){
			setVStrPtrInc(sp,fc);
			setVStrEnd(sp,0);
			continue;
		}
		cond = 0;
		for(;;){
			switch( fc = *fp++ ){
				case 0: goto EXIT;
				case '?': cond = 1; continue;
			}
			break;
		}

		cpyQStr(pp,sp);
		switch( fc ){
			case '%':
				setVStrPtrInc(sp,fc);
				setVStrEnd(sp,0);
				break;
			case 'm':
				rsctime(svLastmod,AVStr(sp));
				sp += strlen(sp);
				break;
			case 'p':
				sprintf(sp,"%u",svPid);
				sp += strlen(sp);
				break;
			case 's':
				rsctime(svStarted,AVStr(sp));
				sp += strlen(sp);
				break;
			case 'u':
				rsctime(svUpdated,AVStr(sp));
				sp += strlen(sp);
				break;
			case 'f':
				sprintf(sp,"%d",svSerno);
				sp += strlen(sp);
				break;
			case 'a':
				sprintf(sp,"%d",svActive);
				sp += strlen(sp);
				break;
			case 'q':
				sprintf(sp,"%d",svServed);
				sp += strlen(sp);
				break;

			case 't':
				switch( svTrace ){
					case 0: sprintf(sp,"Unk"); break;
					case 1: sprintf(sp,"Ini"); break;
					case 2: sprintf(sp,"Run"); break;
					case 3: sprintf(sp,"Fin"); break;
					case 4: sprintf(sp,"Abo"); break;
					default:sprintf(sp,"Err-%d",svTrace);
				}
				HTML_conv("label",sp,AVStr(sp));
				sp += strlen(sp);
				break;
			case 'i':
				last = TotalLast[ST_ACC];
				if( last == 0 )
					last = svStarted;
/*
					last = START_TIME;
*/
				idle = now - last;
				if( 1 < idle )
					sp = Sprintf(AVStr(sp),"%d",idle);
				break;
			case 'c':
				if( 0 < NUM_CHILDREN )
					sp = Sprintf(AVStr(sp),"%d",NUM_CHILDREN);
				break;
			case 'l':
				loadv[0] = getLoadStat(ST_ACC,now,1);
				loadv[1] = getLoadStat(ST_ACC,now,5) / 5;
				loadv[2] = getLoadStat(ST_ACC,now,15) / 15;
				/*
				sp = Sprintf(AVStr(sp),"%3.1f %3.1f %3.1f",
				*/
				sprintf(sp,"%3.1f %3.1f %3.1f",
					loadv[0],loadv[1],loadv[2]);
				sp += strlen(sp);
				break;
			case 'L':
/*
				elp = now - START_TIME;
*/
				elp = now - svStarted;
				done = TotalCount[ST_ACC];
				if( elp <= 0 )
					elp = 1;
				loadv[0] = done / (elp/60.0);
				/*
				sp = Sprintf(AVStr(sp),"%4.2f",loadv[0]);
				*/
				sprintf(sp,"%4.2f",loadv[0]);
				sp += strlen(sp);
				break;
			case 'T':
				switch( *fp ){
				    case 'a':
					rsctime(TotalLast[ST_ACC],AVStr(sp));
					break;
				    default: continue;
				}
				break;
			case 'r':
				strfRusage(AVStr(sp),"%uu %ss %RR %SS",4,svRusage);
				sp += strlen(sp);
				break;
			case 'R':
				if( *fp == 0 )
					break;
				sprintf(Rfmt,"%%%c",*fp++);
				strfRusage(AVStr(sp),Rfmt,4,svRusage);
				sp += strlen(sp);
				break;
			case 'x':
				strcpy(sp,"");
				switch( *fp ){
				    case 'n':
					if( *svName ){
			encodeEntitiesY(svName,AVStr(sp),sizeof(sp),DHTML_ENC,0);
					}
					else	strcpy(sp,"%xn");
					break;
				    case 'v':
				    {
					CStr(pf,32);
					unsigned char px;
					px = exeVer[3];
					if( px == 0 || px == 0x80 ){
						truncVStr(pf);
					}else
					if( 0x80 & px ){
						sprintf(pf,"-fix%d",0x7F&px);
					}else	sprintf(pf,"-pre%d",px);
					sprintf(sp,"%d.%d.%d%s",exeVer[0],
						exeVer[1],exeVer[2],pf);
					/*
					sprintf(sp,"%d.%d.%d",exeVer[0],
						exeVer[1],exeVer[2]);
					if( exeVer[3] )
					Xsprintf(TVStr(sp),"-pre%d",exeVer[3]);
					*/
					break;
				    }
				    case 'c':
					sprintf(sp,"%d",exeCrc32);
					break;
				    case 'X':
					sprintf(sp,"%X",exeCrc32);
					break;
				    case 'd':
					rsctime(exeDate,AVStr(sp));
					break;
				    case 's':
					sprintf(sp,"%d",exeSize);
					break;
				    default: continue;
				}
				fp++;
				sp += strlen(sp);
				break;
		}
		if( svPid == 0 ){
			strcpy(pp,"-");
			sp = pp + strlen(pp);
		}
		if( cond ){
			fc = *fp++;
			if( fc == 0 )
				break;
			if( fc == '[' ){
				if( tp = strchr(fp,']') ){
					Bcopy(fp,subfmt,tp-fp);
					setVStrEnd(subfmt,tp-fp);
					fp = tp + 1;
				}else	break;
			}else{
				subfmt[0] = *fp++;
				subfmt[1] = 0;
			}
			if( pp < sp )
				sp = strfLoadStat(QVStr(pp,str),size-(sp-str),subfmt,now);
		}
	}
EXIT:
	return (char*)sp;
}
char *strfLoadStatX(PVStr(str),int size,PCStr(fmt),int now,int fd){
	LoadStatEnv *senv;
	LoadStatEnv env1;
	int rcc;
	const char *ret;

	bzero(&env1,sizeof(env1));
	if( fd < 0 ){
	}else{
		Lseek(fd,0,0);
		rcc = read(fd,(char*)&env1,sizeof(LoadStatEnv));
		if( rcc != sizeof(LoadStatEnv) || env1.le_Version != SVSVER ){
			fprintf(stderr,"--ERROR LoadStatX(%d) rcc=%d/%d/%d\n",
				fd,rcc,isizeof(LoadStatEnv),file_size(fd));
			bzero(&env1,sizeof(env1));
		}
	}
	senv = loadStatEnv;
	loadStatEnv = &env1;
	ret = strfLoadStat(BVStr(str),size,fmt,now);
	loadStatEnv = senv;
	return (char*)ret;
}
int getSvStats(int fd,int *pid,int *stime,int *utime){
	LoadStatEnv env1;
	int rcc;

	bzero(&env1,sizeof(env1));
	if( fd < 0 ){
		return -1;
	}else{
		Lseek(fd,0,0);
		rcc = read(fd,(char*)&env1,sizeof(LoadStatEnv));
		if( rcc != sizeof(LoadStatEnv) || env1.le_Version != SVSVER ){
			fprintf(stderr,"--ERROR SvStats(%d) rcc=%d/%d/%d\n",
				fd,rcc,isizeof(LoadStatEnv),file_size(fd));
			bzero(&env1,sizeof(env1));
			return -1;
		}
	}
	if( pid   ) *pid   = env1.le_svPid;
	if( stime ) *stime = env1.le_svStarted;
	if( utime ) *utime = env1.le_svUpdated;
	return 0;
}

const char *start_time()
{
	if( Stime[0] == 0 )
		StrftimeLocal(AVStr(Stime),sizeof(Stime),TIMEFORM_HTTPD,START_TIME,0);
	return Stime;
}
