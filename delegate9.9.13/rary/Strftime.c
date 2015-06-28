/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2008 National Institute of Advanced Industrial Science and Technology (AIST)
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
Content-Type:   program/C; charset=US-ASCII
Program:        ftime.c (portable strftime())
Author:         Yutaka Sato <ysato@etl.go.jp>
Description:
History:
        940719	created
	940727	introduced gmtoff() for portability
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "ystring.h"
#include "vsignal.h"
#include "ysignal.h"
#include "log.h"
#include <time.h>

#if !defined(__KURO_BOX__)
time_t timegm(struct tm *tm);
#endif
int Timegm(struct tm *tm);
int Timelocal(struct tm *tm);
long Gettimeofday(int *usec);

const char *TIMEFORM_mdHMS  = "%m/%d %H:%M:%S";
char TIMEFORM_mdHMS0[] = "%m/%d %H:%M:%S";
char TIMEFORM_mdHMSd[] = "%m/%d %H:%M:%S%.1s";
char TIMEFORM_mdHMSc[] = "%m/%d %H:%M:%S%.2s";
char TIMEFORM_mdHMSm[] = "%m/%d %H:%M:%S%.3s";
char TIMEFORM_mdHMS4[] = "%m/%d %H:%M:%S%.4s";
char TIMEFORM_mdHMS5[] = "%m/%d %H:%M:%S%.5s";
char TIMEFORM_mdHMS6[] = "%m/%d %H:%M:%S%.6s";
const char *TIMEFORM_HTTPD  = "%d/%b/%Y:%H:%M:%S %z";
const char *TIMEFORM_HTTPDs = "%d/%b/%Y:%H:%M:%S%.3s %z";
const char *TIMEFORM_GOPHER = "%Y%m%d%H%M%S";
const char *TIMEFORM_USENET = "%d %b %Y %H:%M:%S %z";
const char *TIMEFORM_RFC822 = "%a, %d %b %Y %H:%M:%S %z";
const char *TIMEFORM_RFC850 = "%A, %d-%b-%y %H:%M:%S %z";
const char *TIMEFORM_ANSI_C = "%a %b %d %H:%M:%S %Y";
const char *TIMEFORM_UXDATE = "%a %b %d %H:%M:%S %z %Y";
const char *TIMEFORM_ymdHMS = "%y %m %d %H %M %S";
const char *TIMEFORM_ymdHMSZ = "%y %m %d %H %M %S %Z";
const char *TIMEFORM_YmdHMS = "%Y%m%d%H%M%S";
const char *TIMEFORM_LS     = "%Y/%m/%d %H:%M:%S";
const char *TIMEFORM_SYSLOG = "%b %d %H:%M:%S";
const char *TIMEFORM_TAR    = "%b %e %H:%M %Y";
const char *TIMEFORM_COOKIE = "%a, %d-%b-%Y %H:%M:%S GMT";

const char *TIMEFORM_RFC0   = "%P%B %Y";
const char *TIMEFORM_RFC1   = "%P%d %B %Y";
const char *TIMEFORM_RFC2   = "%P%B %d, %Y";
const char *TIMEFORM_RFC3   = "%P%B %d %Y";
const char *TIMEFORM_RFC4   = "%d/%m/%y";

/*
 * inputs external representation of year and returns its internal value
 * for tm.tm_year which is defined as "year - 1900".
 *
 *   external        INTERPRETATION     internal        calculation
 *  -------------   ---------------    --------------  --------------------
 *  [   0 -   69] = ( 2000 - 2069 ) -> [ 100 -  169 ]  +100
 *  [  70 -   99] = ( 1970 - 1999 ) -> [  70 -   99 ]  as is
 *  [ 100 - 1899] = ( 2000 - 3799 ) -> [ 100 - 1899 ]  as is (for compati.)
 *  [1900 - 9999] = ( 1900 - 9999 ) -> [   0 - 8099 ]  -1900
 */
static int year2internal(int year)
{
	if( 0 <= year && year < 70 ){
		year += 100;
	}else
	if( 1900 <= year ){
		year -= 1900;
	}else{
	}
	return year;
}

static int cyear(int year)
{
	return year % 100;
}

/* MacOSX leaves time? relevant fd be opened after exec() */
char *ctimeX(const time_t *cl){
	char *ct;
	int fd;
	fd = nextFD();
	ct = ctime(cl);
	if( usedFD(fd) ){
		/*
		fprintf(stderr,"----usedFD(%d) in ctime()\n",fd);
		*/
	}
	return ct;
}

static struct tm *Gmtime(const time_t *clock);
static struct tm *Localtime(const time_t *clock);
int actthreads();
/* 9.9.4 MTSS localtime() is the main source of dead-lock on signal */
int selfLocaltime;

int ismainthread();
struct tm *gmtimeX(const time_t *clock){
	struct tm *tm;
	int nmask,smask;
	SSigMask sMask;

	/* 9.9.4 MTSS gmtime/localtime */
	if( lMTSS_NOSSIG() ){ /* "-Dts" */
		return gmtime(clock);
	}
	if( lMTSS_TMCONV() || selfLocaltime ){
		return Gmtime(clock);
	}
	if( !ismainthread() ){
		return Gmtime(clock);
	}
	setSSigMask(sMask);
	tm = gmtime(clock);
	resetSSigMask(sMask);
	return tm;
}
#define gmtime gmtimeX

const char *FL_F_Localtm;
int FL_L_Localtm;
int inLocaltm;
struct tm *localtimeX(const time_t *clock){
	SSigMask sMask;
	struct tm *tm;
	int nmask,smask;

	/*
	9.9.4 MTSS this sigmask is introduced in 9.6.3-pre4 to avoid
	spin_lock for mutex.  "actthreads()" is NG and should be
	"numthreads()" because auto. mutex for localtime/gmtime seems
	 to be persistently enabled after a thread is created.

	if( actthreads() == 0 ){
		return localtime(clock);
	}
	nmask = sigmask(SIGPIPE)|sigmask(SIGTERM)|sigmask(SIGINT);
	smask = sigblock(nmask);
	tm = localtime(clock);
	sigsetmask(smask);
	*/
	if( lMTSS_NOSSIG() ){
		return localtime(clock);
	}
	if( lMTSS_TMCONV() || selfLocaltime ){
		return Localtime(clock);
	}
	if( !ismainthread() ){
		return Localtime(clock);
	}
	setSSigMask(sMask);
	FL_F_Localtm = "localtime"; FL_L_Localtm = __LINE__;
	inLocaltm++;
	tm = localtime(clock);
	inLocaltm--;
	resetSSigMask(sMask);
	return tm;
}
#define localtime localtimeX

/*
 *	the return value of localtime(), struct tm in global area,
 *	should be saved befre Gmtoff()
 */
static long gmt_off;
static int gmt_off_got = 0;
long Gmt_off;
int GmtOff(){
	if( gmt_off_got )
		return gmt_off;
	else	return 0;
}
int Gmtoff(){
	struct tm *tm;
	time_t clock;
	int fd1 = -1;

	if( gmt_off_got )
		return gmt_off;

	clock = 24*3600;
	if( 1 ){
		fd1 = nextFD(); /* 9.9.8 for old MacOSX (Darwin 8.X) */
	}
	tm = localtime(&clock);
	if( 0 <= fd1 && usedFD(fd1) ){
		if( lFILEDESC() ){
			IStr(name,128);
			int fd2;
			fd2 = nextFD();
			Uname(AVStr(name));
			porting_dbg("##localtime[%d][%d] %s",fd1,fd2,name);
		}
	}
	gmt_off = Timegm(tm) - clock;
	Gmt_off = gmt_off;

	gmt_off_got = 1;
	return gmt_off;
}

static struct { defQStr(sgmtoff); } sgmtoff;
char *gmtoff(){
	time_t clock;
	int gmtoff;
	CStr(sctime,32);
	const char *satime;
	const char *env;
	CStr(envb,128);
	int off;

	if( sgmtoff.sgmtoff == NULL ){
		setQStr(sgmtoff.sgmtoff,(char*)StructAlloc(8),8); 
	}
	if( sgmtoff.sgmtoff[0] != 0 )
		return (char*)sgmtoff.sgmtoff;
	/*
	if( env = getenv("GMTOFF") ){
		if( *env == '+' ){
			off = atoi(env+1);
			if( 0 <= off && off <= 1200 ){
				sgmtoff.sgmtoff = env;
				return (char*)sgmtoff.sgmtoff;
			}
		}
	}
	*/
	strcpy(sgmtoff.sgmtoff,"+0000");

	clock = 24*3600;
	/*
	strcpy(sctime,ctime(&clock));
	*/
	strcpy(sctime,ctimeX(&clock));
	for( gmtoff = -12; gmtoff <= 12; gmtoff++ ){
		clock = 24*3600 + gmtoff*3600;
		satime = asctime(gmtime(&clock));
		if( strcmp(sctime,satime) == 0 ){
			sprintf(sgmtoff.sgmtoff,"%s%04d",
				0<=gmtoff?"+":"-",gmtoff*100);
			break;
		}
	}
	Gmt_off = gmtoff * 3600;
	/*
	sprintf(envb,"%s=%s","GMTOFF",sgmtoff.sgmtoff);
	putenv(stralloc(envb));
	*/
	return (char*)sgmtoff.sgmtoff;
}

static int NthWeek(struct tm *tm,int wday1)
{	int nth,off,sun1st,rem,remain;
	int yday;
	int wbase;

#ifdef XXXX
	if( 94 <= tm->tm_year && tm->tm_year <= 96 ) /* historical BUG */
		wbase = 1;
	else    wbase = 0;
#endif
	wbase = 0;

	yday = tm->tm_yday;
	rem = yday % 7;

	if( rem < tm->tm_wday )
		off = tm->tm_wday - rem;
	else	off = tm->tm_wday+7 - rem;

	sun1st = 7 - off;
	if( wday1 == 1 )
		sun1st++;
	sun1st = sun1st % 7;

	if( yday < sun1st )
		nth = wbase;
	else{
		remain = yday - sun1st + 1;
		nth = wbase + (remain/7) + (remain % 7 != 0 ? 1:0);
	}
	return nth;
}

static const char *Month[] =
{"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec",0};

static const char *Wdays[] =
{"Sun","Mon","Tue","Wed","Thu","Fri","Sat",0};

static const char *WDays[] =
{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",0};

static int montoi(PCStr(mon))
{	int i;
	const char *mo;

	for( i = 0; mo = Month[i]; i++ )
		if( strcmp(mo,mon) == 0 )
			return i;
	return -1;
}
static int Montoi(PCStr(mon))
{	int i;
	const char *mo;

	for( i = 0; mo = Month[i]; i++ )
		if( strncasecmp(mo,mon,3) == 0 )
			return i;
	return -1;
}
int wdaytoi(PCStr(wday))
{	int len,i;
	const char *wd;

	len = strlen(wday);
	if( len == 2 )
	for( i = 0; wd = Wdays[i]; i++ )
		if( strncasecmp(wd,wday,2) == 0 )
			return i;

	for( i = 0; wd = Wdays[i]; i++ )
		if( strcmp(wd,wday) == 0 )
			return i;
	for( i = 0; wd = WDays[i]; i++ )
		if( strcmp(wd,wday) == 0 )
			return i;
	return -1;
}

int TIME_NOW;
static char *lsDate(int clock,struct tm *tm,PVStr(lsdate))
{	int now;

	if( clock < 0 )
		clock = Timegm(tm);

	if( 0 < TIME_NOW )
		now = TIME_NOW;
	else	now = time(0);

	if( clock < now - (3600*24*31*6) )
		sprintf(lsdate,"%s %2d %5d",
			Month[tm->tm_mon],
			tm->tm_mday,
			tm->tm_year + 1900
		);
	else
		sprintf(lsdate,"%s %2d %02d:%02d",
			Month[tm->tm_mon],
			tm->tm_mday,
			tm->tm_hour,
			tm->tm_min
		);
	return (char*)lsdate;
}
char *rsctime(time_t clock,PVStr(lsdate))
{	struct tm *tm;

	tm = localtime(&clock);
	return lsDate(clock,tm,AVStr(lsdate));
}

long timeBaseDayLocal(time_t clock)
{	struct tm *tm;
	time_t base;

	tm = localtime(&clock);
	tm->tm_hour = 0;
	tm->tm_min = 0;
	tm->tm_sec = 0;
	base = Timelocal(tm);
	return base;
}

static char *sprint02d(xPVStr(d),int n)
{
/*
Year 2000 problem ? :-)
	if( 100 <= n )
		setVStrPtrInc(d,"0123456789"[(n/100)%10]);
*/
	setVStrPtrInc(d,"0123456789"[(n/10)%10]);
	setVStrPtrInc(d,"0123456789"[n%10]);
	setVStrEnd(d,0);
	return (char*)d;
}
static char *sprint1d(xPVStr(d),int n)
{
	setVStrPtrInc(d,"0123456789"[n%10]);
	setVStrEnd(d,0);
	return (char*)d;
}
static char *sprintstr(xPVStr(d),PCStr(s))
{	int ch;

	while( 1 ){
		ch = *s++;
		setVStrElem(d,0,ch);
		if( ch == 0 )
			break;
		d++;
	}
	return (char*)d;
}
#define Sprint02d(d,n) sprint02d(AVStr(d),n)
#define Sprint1d(d,n)  sprint1d(AVStr(d),n)
#define Sprintstr(d,s) sprintstr(AVStr(d),s)

static int Strftime0(PVStr(atime),int size,PCStr(fmt),struct tm *tm,int usecond,PCStr(zone))
{	const char *mon;
	const char *fp;
	refQStr(ap,atime); /**/
	const char *ax = &atime[size-1];
	CStr(fm1,16);
	CStr(buf,128);
	CStr(precision,16);

	if( tm->tm_mon < 0 || 12 <= tm->tm_mon ){
		fprintf(stderr,"----Strftime BAD month=%d\n",tm->tm_mon);
		tm->tm_mon = 0;
	}
	if( tm->tm_wday < 0 || 7 <= tm->tm_wday ){
		fprintf(stderr,"----Strftime BAD wday=%d\n",tm->tm_wday);
		tm->tm_mon = 0;
	}

	for( fp = fmt; *fp; fp++ ){
	    if( ax <= ap ){
		assertVStr(atime,ap);
	    }

	    if( *fp != '%' ){
		setVStrPtrInc(ap,*fp);
		continue;
	    }
	    fp++;

	    {	refQStr(pcp,precision); /**/
		const char *pcx = &precision[sizeof(precision)-1];
		while( *fp == '.' || isdigit(*fp) ){
			if( pcx <= pcp ){
				fprintf(stderr,"## Strftime ERROR: %s\n",fmt);
				break;
			}
			setVStrPtrInc(pcp,*fp++);
		}
		setVStrEnd(pcp,0);
	    }

	    switch( *fp ){
		default:  ap = Sprintstr(ap,"");	break;
		case '%': ap = Sprintstr(ap,"%");	break;

		case 'A': ap = Sprintstr(ap,WDays[tm->tm_wday]);break;
		case 'a': ap = Sprintstr(ap,Wdays[tm->tm_wday]);break;
		case 'b': ap = Sprintstr(ap,Month[tm->tm_mon]);	break;
		case 'z': ap = Sprintstr(ap,zone);		break;
		case 'L': ap = Sprintstr(ap,lsDate(-1,tm,AVStr(buf)));	break;

		case 'w': ap = Sprint1d(ap,tm->tm_wday);	break;
		case 'u': ap = Sprint1d(ap,(tm->tm_wday+6)%7+1);break;
		case 'd': ap = Sprint02d(ap,tm->tm_mday);	break;
		case 'e': sprintf(ap,"%2d",tm->tm_mday);
				ap += strlen(ap);		break;
		case 'm': ap = Sprint02d(ap,tm->tm_mon+1);	break;
		case 'H': ap = Sprint02d(ap,tm->tm_hour);	break;
		case 'M': ap = Sprint02d(ap,tm->tm_min);	break;
		/*
		case 'S': ap = Sprint02d(ap,tm->tm_sec);	break;
		*/
		case 'S': ap = Sprint02d(ap,tm->tm_sec);
			if( *precision == '.' )
				goto SUBSECS;
			break;
		case 'U': ap = Sprint02d(ap,NthWeek(tm,0));	break;
		case 'W': ap = Sprint02d(ap,NthWeek(tm,1));	break;
		case 'y': ap = Sprint02d(ap,cyear(tm->tm_year));break;

		case 'Y':
			sprintf(buf,"%d",tm->tm_year+1900);
			ap = Sprintstr(ap,buf);
			break;

		case 's':
			/* seconds since the Epoch */
			if( *precision != '.' && strchr(precision,'.') == 0 ){
				int uclock;
				uclock = timegm(tm);
				sprintf(fm1,"%%%sd",precision);
				sprintf(ap,fm1,uclock);
				ap += strlen(ap);
				break;
			}
		SUBSECS:
			truncVStr(buf);
			sprintf(fm1,"%%%sf",precision);
			sprintf(buf,fm1,usecond/1000000.0);
			if( strneq(buf,"1.0",3) ){
				/* 9.8.2 not go back to past with .00 */
				strcpy(buf,"0.999999999");
				setVStrEnd(buf,2+atoi(precision+1));
			}

if( 12 < strlen(buf) ){
fprintf(stderr,"## [%d] VStr? at %s:%d < %s:%d [%s][%s][%s][%d]%d[%f]%d\n",
getpid(),__FILE__,__LINE__,whStr(atime),
fmt,fm1,buf,usecond,isizeof(usecond),usecond/1000000.0,isizeof(1.0));
}
			ap = Sprintstr(ap,buf+1);
			break;
	    }
	}
	setVStrEnd(ap,0);
	return strlen(atime);
}

static struct tm *tmerr;
int StrftimeLocal(PVStr(atime),int size,PCStr(fmt),time_t clock,int usecond)
{	struct tm *tm;
	const char *zone;

	if( clock == -1 && usecond == -1 ){
		clock = Gettimeofday(&usecond);
	}
	zone = gmtoff(); /* *tm will be overwritten by side effect */
	tm = localtime(&clock);
	if( tm == NULL ){
		if( tmerr == NULL )
			tmerr = NewStruct(struct tm);
		tm = tmerr;
	}
	return Strftime0(BVStr(atime),size,fmt,tm,usecond,zone);
}
int StrftimeGMT(PVStr(atime),int size,PCStr(fmt),time_t clock,int usecond)
{	struct tm *tm;
	const char *zone;

	tm = gmtime(&clock);
	zone = "GMT";
	return Strftime0(BVStr(atime),size,fmt,tm,usecond,zone);
}
int StrfTimeLocal(PVStr(atime),int size,PCStr(fmt),double T){
	return StrftimeLocal(BVStr(atime),size,fmt,(time_t)T,
		((Int64)(T*1000000))%1000000);
}
int StrfTimeGMT(PVStr(atime),int size,PCStr(fmt),double T){
	return StrftimeGMT(BVStr(atime),size,fmt,(time_t)T,
		((Int64)(T*1000000))%1000000);
}

int scanftimeX(PVStr(stime),PCStr(fmt),int canon);
int scanftime(PCStr(stime),PCStr(fmt))
{
	return scanftimeX(CVStr((char*)stime),fmt,0);
}
int scanftimeX(PVStr(stime),PCStr(fmt),int canon)
{	int clock = -1;
	char ch;
	const char *fp;
	const char *sp;
	int year,mon,mday,hour,min,sec;
	CStr(sym,128);
	CStr(zone,128);
	int gmtoff;
	int localzone;
	struct tm tm;
	refQStr(yyp,stime); /**/
	int partial = 0;

	year = mon = mday = hour = min = sec = -1;
	zone[0] = 0;
	localzone = 0;
	yyp = 0;

	sp = stime;
	for( fp = fmt; ch = *fp; fp++ ){
	    /*fprintf(stderr,"[%s][%s]\n",fp,sp);*/

	    if( ch == ' ' || ch == '\t'  ){
		while( *sp == ' ' || *sp == '\t' )
			sp++;
		continue;
	    }
	    if( ch != '%' ){
		if( *sp != ch )
			goto EXIT;
		sp++;
		continue;
	    }
	    fp++;
	    switch( *fp ){
		case 'P': partial = 1; break;
		case '%': if(*sp != '%') goto EXIT; else sp++; break;
		case 'A': sp = awordscan(sp,sym); break;
		case 'a': sp = awordscan(sp,sym); break;
		case 'b': sp = awordscan(sp,sym); mon = montoi(sym); break;
		case 'B': sp = awordscan(sp,sym); mon = Montoi(sym); break;
		case 'd': if((sp = scanint(sp,&mday)) == NULL) goto EXIT; break;
		case 'm': if((sp = scanint(sp,&mon)) == NULL ) goto EXIT;
				mon -= 1; break;
		case 'z': sp = wordScan(sp,zone); break;
		case 'Z': sp = wordScan(sp,zone);
			if( strcmp(zone,"GMT") != 0 && strcmp(zone,"UTC") != 0 )
				localzone = 1;
			break;
		case 'H': if((sp = scanint(sp,&hour)) == NULL) goto EXIT; break;
		case 'M': if((sp = scanint(sp,&min) ) == NULL) goto EXIT; break;
		case 'S': if((sp = scanint(sp,&sec) ) == NULL) goto EXIT; break;
		case 'U': sp = awordscan(sp,sym); break;
		case 'W': sp = awordscan(sp,sym); break;
		case 'y':
		case 'Y':
			if( isdigit(*sp) && atoi(sp) < 200 )
				yyp = (char*)sp;
			if((sp = scanint(sp,&year)) == NULL) goto EXIT;
			if( partial ){
				if( *fp == 'Y' ){
					if( 1 <= year && year <= 31 ){
//fprintf(stderr,"---- year %d\n",year);
						year = -1;
						break;
					}
				}
			}
			year = year2internal(year);
			break;
	    }
	}
EXIT:
//fprintf(stderr,"----[%s] p=%d %d %d %d\n",fmt,partial,year,mon,mday);
	if( partial && 0 < year && 0 <= mon ){
		if( mday < 0 ) mday = 1;
		if( hour < 0 ) hour = 0;
		if( min < 0 ) min = 0;
		if( sec < 0 ) sec = 0;
	}else
	if( year<0 || mon<0 || mday<0 || hour<0 || min<0 || sec<0 )
		return -1;

	tm.tm_sec = sec;
	tm.tm_min = min;
	tm.tm_hour = hour;
	tm.tm_mday = mday;
	tm.tm_mon = mon;
	tm.tm_year = year;

	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = 0;
	/*tm.tm_zone = zone;*/
	/*tm.tm_gmtoff = 0;*/
	if( localzone )
		clock = Timelocal(&tm); 
	else	clock = Timegm(&tm);

	if( 0 <= clock && zone[0] ){
		int off;

		gmtoff = 0;
		if( zone[0] == '+' || zone[0] == '-' ){
			off = atoi(zone+1);
			gmtoff = 3600*(off/100) + 60*(off%100);
		}
		if( zone[0] == '+' ) clock -= gmtoff;
		if( zone[0] == '-' ) clock += gmtoff;
	}
	/*fprintf(stderr,"%d/%d/%d %d:%d:%d [%s] %d\n",
		year,mon+1,mday,hour,min,sec,zone,clock);*/

	if( canon && yyp ){
		sprintf(sym,"%d",1900+year);
		sp = scanint(yyp,&year);
		ovstrcpy((char*)yyp,sp);
		Strins(AVStr(yyp),sym);
		lineScan(stime,zone);
		/*
		syslog_ERROR("canon-Year %d -> %s [%s]\n",year,sym,zone);
		*/
		syslog_DEBUG("canon-Year %d -> %s [%s]\n",year,sym,zone);
	}
	return clock;
}

static char *scanint2(PCStr(s),int *num){
	char b[3];
	if( isdigit(s[0]) || isspace(s[0]) )
	if( isdigit(s[1]) ){
		b[0] = s[0];
		b[1] = s[1];
		b[2] = 0;
		*num = atoi(b);
		return (char*)s+2;
	}
	return NULL;
}
static char *scanint4(PCStr(s),int *num){
	char b[5];
	if( isdigit(s[0]) && isdigit(s[1]) && isdigit(s[2]) && isdigit(s[3]) ){
		b[0] = s[0];
		b[1] = s[1];
		b[2] = s[2];
		b[3] = s[3];
		b[4] = 0;
		*num = atoi(b);
		return (char*)s+4;
	}
	return NULL;
}
int scanftimeY(PCStr(stime),PCStr(fmt)){
	int clock = -1;
	char ch;
	const char *fp;
	const char *sp;
	int year,mon,mday,hour,min,sec;
	CStr(sym,128);
	CStr(zone,128);
	int gmtoff;
	int localzone;
	int zoff;
	struct tm tm;
	const char *yyp;
	time_t nowi;

	year = mon = mday = hour = min = sec = -1;
	zone[0] = 0;
	zoff = 0;
	localzone = 1;
	yyp = 0;

	sp = stime;
	for( fp = fmt; ch = *fp; fp++ ){
	    if( *sp == 0 ){
		break;
	    }
	    if( ch == ' ' || ch == '\t'  ){
		while( *sp == ' ' || *sp == '\t' )
			sp++;
		continue;
	    }
	    if( ch != '%' ){
		if( *sp != ch )
			goto EXIT;
		sp++;
		continue;
	    }
	    fp++;
	    switch( *fp ){
		case '%': if(*sp != '%') goto EXIT; else sp++; break;
		case 'A': sp = awordscan(sp,sym); break;
		case 'a': sp = awordscan(sp,sym); break;
		case 'b': sp = awordscan(sp,sym); mon = montoi(sym); break;
		case 'B': sp = awordscan(sp,sym); mon = Montoi(sym); break;
		case 'd': if((sp = scanint2(sp,&mday)) == NULL) goto EXIT; break;
		case 'm': if((sp = scanint2(sp,&mon)) == NULL ) goto EXIT;
				mon -= 1; break;
		case 'z':
		case 'Z':
			if( *sp == '+' || *sp == '-' ){
				int neg = *sp == '-';
				localzone = 1;
				sp = scanint4(sp+1,&zoff);
				if( neg ) zoff = -zoff;
			}else{
				sp = wordScan(sp,zone);
				if( streq(zone,"GMT") || streq(zone,"UTC") )
					localzone = 0;
			}
			break;
		case 'H': if((sp = scanint2(sp,&hour)) == NULL) goto EXIT; break;
		case 'M': if((sp = scanint2(sp,&min) ) == NULL) goto EXIT; break;
		case 'S': if((sp = scanint2(sp,&sec) ) == NULL) goto EXIT; break;
		case 'U': sp = awordscan(sp,sym); break;
		case 'W': sp = awordscan(sp,sym); break;
		case 'Y': if((sp = scanint4(sp,&year)) == NULL) goto EXIT;
			year = year2internal(year);
			break;
		case 'y':
			if( isdigit(*sp) && atoi(sp) < 200 )
				yyp = (char*)sp;
			if((sp = scanint2(sp,&year)) == NULL) goto EXIT;
			year = year2internal(year);
			break;
	    }
	}
EXIT:
	if( sp == NULL || *sp ){
		return -1;
	}
	nowi = time(0);
	if( localzone )
		tm = *localtime(&nowi);
	else	tm = *gmtime(&nowi);
fprintf(stderr,"-- MATCH [%s][%s]local=%d %d %02d:%02d:%02d\n",fmt,sp,localzone,mday,hour,min,sec);

	if( 0 <= hour){
		tm.tm_hour = hour;
		if( min < 0 ) tm.tm_min = 0;
		if( sec < 0 ) tm.tm_min = 0;
	}
	if( 0 <= min ){
		tm.tm_min = min;
		if( sec < 0 ) tm.tm_sec = 0;
	}
	if( 0 <= sec ){
		tm.tm_sec = sec;
	}
	if( 0 <= mday) tm.tm_mday = mday;
	if( 0 <= mon ) tm.tm_mon = mon;
	if( 0 <= year) tm.tm_year = year;
fprintf(stderr,">> MATCH [%s][%s]local=%d %d %02d:%02d:%02d\n",fmt,sp,localzone,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec);

	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = 0;
	/*tm.tm_zone = zone;*/
	/*tm.tm_gmtoff = 0;*/

	if( localzone )
		clock = Timelocal(&tm); 
	else	clock = Timegm(&tm);

/*
	if( 0 <= clock && zone[0] ){
		int off;

		gmtoff = 0;
		if( zone[0] == '+' || zone[0] == '-' ){
			off = atoi(zone+1);
			gmtoff = 3600*(off/100) + 60*(off%100);
		}
		if( zone[0] == '+' ) clock -= gmtoff;
		if( zone[0] == '-' ) clock += gmtoff;
	}
*/
	return clock;
}
int scanTime(PCStr(stime))
{	int itime;

	if( 0 <= (itime = scanftimeY(stime,"%M")) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,"%H:%M")) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,"%H:%M:%S")) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,TIMEFORM_mdHMS)) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,TIMEFORM_RFC822)) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,TIMEFORM_RFC850)) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,TIMEFORM_ANSI_C)) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,TIMEFORM_USENET)) ) return itime;
	if( 0 <= (itime = scanftimeY(stime,TIMEFORM_GOPHER)) ) return itime;
	return -1;
}

int scanYmdHMS_GMT(PCStr(stime))
{	char ch;
	struct tm tm;
	int v2v[8],vi;
	int clock;
	const char *sp;

	for( vi = 0; stime[vi*2]; vi++ ){
		if( stime[vi*2+1] == 0 )
			break;
		if( elnumof(v2v) <= vi ){
			break;
		}
		sp = (char*)stime; /* not read-only but "const" */
		ch = sp[vi*2+2];
		((char*)sp)[vi*2+2] = 0; /**/
		v2v[vi] = atoi(&stime[vi*2]);
		((char*)sp)[vi*2+2] = ch; /**/
	}
/*
syslog_ERROR("#### %d [%d][%d][%d][%d][%d][%d][%d]\n",
vi, v2v[0], v2v[1], v2v[2], v2v[3], v2v[4], v2v[5], v2v[6], v2v[7]);
*/
	if( vi != 7  )
		return -1;
	tm.tm_year = v2v[0]*100+v2v[1] - 1900;
	tm.tm_mon  = v2v[2] - 1;
	tm.tm_mday = v2v[3];
	tm.tm_hour = v2v[4];
	tm.tm_min  = v2v[5];
	tm.tm_sec  = v2v[6];

	clock = timegm(&tm);
	return clock;
}
int YMD_HMS_toi(PCStr(ymdhms))
{	CStr(ymdHMSZ,64);
	CStr(zone,16);
	int iymd,ihms,date;
	UTag *uv[4],ub[3];

	uvinit(uv,ub,3);
	uvfromsf(ymdhms,0,"%d %d %s",uv);
	iymd = utoi(uv[0]);
	ihms = utoi(uv[1]);
	Utos(uv[2],zone);
	if( !streq(zone,"GMT") && !streq(zone,"UTC") )
		zone[0] = 0;

	sprintf(ymdHMSZ,"%d %d %d %d %d %d%s%s",
		iymd/10000,(iymd/100)%100,iymd%100,
		ihms/10000,(ihms/100)%100,ihms%100,
		zone[0]?" ":"",zone);
	date = scanftime(ymdHMSZ,TIMEFORM_ymdHMSZ);
	return date;
}

static int xTimelocal(struct tm *Tx)
{	struct tm *Ty;
	time_t T1,T2;

	T1 = Timelocal(Tx);
	Ty = localtime(&T1);
	T2 = Timelocal(Ty);

	if( T2 != T1 )
		syslog_ERROR("## leapSec=%d (%d-%d)\n",xp2i(T1-T2),xp2i(T1),xp2i(T2));

	T1 = T1 + (T1 - T2);
	return T1;
}
int toclockGMT(int y,int m,int d,int H,int M,int S){
	struct tm tm;
	int clock;

	tm.tm_year = y;
	tm.tm_mon  = m - 1;
	tm.tm_mday = d;

	tm.tm_hour = H;
	tm.tm_min  = M;
	tm.tm_sec  = S;

	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = 0;
	/*tm.tm_gmtoff = 0;*/

	clock = Timegm(&tm);
	return clock;
}
int toclockLocal(int y,int m,int d,int H,int M,int S)
{	struct tm tm;
	int clock;

	tm.tm_year = y;
	tm.tm_mon  = m - 1;
	tm.tm_mday = d;

	tm.tm_hour = H;
	tm.tm_min  = M;
	tm.tm_sec  = S;

	tm.tm_wday = 0;
	tm.tm_yday = 0;
	tm.tm_isdst = 0;
	/*tm.tm_gmtoff = 0;*/

	/*
	clock = Timelocal(&tm);
	*/
	clock = xTimelocal(&tm);
	return clock;
}
int fromclockLocal(time_t clock,int *w,int *y,int *m,int *d,int *H,int *M,int *S)
{	struct tm *tm;

	if( (tm = localtime(&clock)) == NULL )
		return -1;

	*w = tm->tm_wday;

	*y = tm->tm_year;
	*m = tm->tm_mon + 1;
	*d = tm->tm_mday;

	*H = tm->tm_hour;
	*M = tm->tm_min;
	*S = tm->tm_sec;

	return 0;
}

int scanANSItime(PCStr(stime)){
	int itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_ANSI_C)) ) return itime;
	return -1;
}
int scanHTTPtime(PCStr(stime))
{	int itime;

	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC822)) ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC850)) ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_ANSI_C)) ) return itime;
	return -1;
}
int scanNNTPtime(PCStr(stime))
{	int itime;

	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC822)) ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC850)) ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_ANSI_C)) ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_USENET)) ) return itime;

	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC0))   ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC1))   ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC2))   ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC3))   ) return itime;
	if( 0 <= (itime = scanftime(stime,TIMEFORM_RFC4))   ) return itime;
	return -1;
}
int scanUNIXDATE(PCStr(stime))
{
	return scanftime(stime,TIMEFORM_UXDATE);
}
void canon_date(PVStr(stime))
{	int itime;
	refQStr(sp,stime); /**/

	for( cpyQStr(sp,stime); *sp == ' ' || *sp == '\t'; sp++ )
		;
	if( 0 <= scanftimeX(QVStr(sp,stime),TIMEFORM_RFC822,1) ) return;
	if( 0 <= scanftimeX(QVStr(sp,stime),TIMEFORM_RFC850,1) ) return;
	if( 0 <= scanftimeX(QVStr(sp,stime),TIMEFORM_ANSI_C,1) ) return;
	if( 0 <= scanftimeX(QVStr(sp,stime),TIMEFORM_USENET,1) ) return;
}
int scanUNIXFROMtime(PCStr(stime))
{	int itime;

	if( 0 <= (itime = scanftime(stime,TIMEFORM_ANSI_C)) )
		return itime - Gmtoff();
	else	return scanNNTPtime(stime);
}

char *scanLsDate(PCStr(str),PVStr(date))
{	const char *sp;
	CStr(mon,128);
	CStr(day,128);
	CStr(plus,128);
	int monlen,mi,len;
	int monx,dayx,plusx;

	while( *str == ' ' )
		str++;
	sp = wordScan(str,mon);
	monlen = strlen(mon);
	sp = wordScan(sp,day);
	sp = wordScan(sp,plus);

	for( mi = 0; mi < 12; mi++ ){
		if( strncmp(Month[mi],mon,monlen) == 0 ){
			if( 0 < atoi(day) ){
				len = sp - str;
				strncpy(date,str,len); setVStrEnd(date,len);
				return (char*)sp;
			}
			return NULL;
		}
	}

	monx = atoi(mon);
	dayx = atoi(day);
	plusx = atoi(plus);
	if( 1 <= monx && monx <= 12 && 1 <= dayx && dayx <= 31 ){
		if( strchr(plus,':') == 0 ){
			if( plusx < 1970 )
				return NULL;
			sprintf(plus,"%d",plusx);
		}
		sprintf(date,"%s %2d %5s",Month[monx-1],dayx,plus);
		return (char*)sp;
	}

	return NULL;
}
int LsDateClock(PCStr(date),time_t now)
{	CStr(smon,128);
	CStr(plus,128);
	int imday;
	struct tm tmnow,tm;
	int monnow,clock;
	UTag *uv[4],ub[3];

	tmnow = *gmtime(&now);
	tm = tmnow;
	monnow = tm.tm_mon;

	uvinit(uv,ub,3);
	if( uvfromsf(date,0,"%s %s %s",uv) != 3 )
		return -1;
	Utos(uv[0],smon);
	imday = utoi(uv[1]);
	Utos(uv[2],plus);

	if( (tm.tm_mon = montoi(smon)) < 0 )
		return -1;
	if( (tm.tm_mday = imday) < 0 )
		return -1;

	tm.tm_sec = 59;
	if( sscanf(plus,"%d:%d",&tm.tm_hour,&tm.tm_min) == 2 ){
		/*
		if( monnow < tm.tm_mon )
			tm.tm_year -= 1;
		*/
		clock = Timegm(&tm);
		if( now+31*24*3600 < clock ){
			tm.tm_year -= 1;
			clock = Timegm(&tm);
		}
	}else{
		tm.tm_year = year2internal(atoi(plus));
		tm.tm_hour = 23;
		tm.tm_min = 59;
	}
	clock = Timegm(&tm);
/* {
	CStr(buff,128);
	StrftimeGMT(AVStr(buff),128,TIMEFORM_RFC822,clock,0);
	fprintf(stderr,"#### [%-20s][%s]\n",date,buff);
} */
	return clock;
}

int tmcmp(struct tm *tm1,struct tm *tm2)
{
	if(tm1->tm_year != tm2->tm_year) return tm1->tm_year-tm2->tm_year;
	if(tm1->tm_mon  != tm2->tm_mon ) return tm1->tm_mon -tm2->tm_mon ;
	if(tm1->tm_mday != tm2->tm_mday) return tm1->tm_mday-tm2->tm_mday;
	if(tm1->tm_hour != tm2->tm_hour) return tm1->tm_hour-tm2->tm_hour;
	if(tm1->tm_min  != tm2->tm_min ) return tm1->tm_min -tm2->tm_min ;
	if(tm1->tm_sec  != tm2->tm_sec ) return tm1->tm_sec -tm2->tm_sec ;
	return 0;
}

static int yday_base[] = { 0,31,59,90,120,151,181,212,243,273,304,334,1000 };
int Timegm(struct tm *tm)
{	struct tm *tm0;
	int yoff,leapy,clock,yday;

	yoff = tm->tm_year - 70;
	yday = yday_base[tm->tm_mon] + (tm->tm_mday - 1);
	if( 1 < tm->tm_mon && (yoff-2) % 4 == 0 )
		yday += 1;

	clock = (
		 (
		  (
		   (
		    (yoff*365 + (yoff+1)/4 + yday) * 24
		   ) + tm->tm_hour
		  ) * 60
		 ) + tm->tm_min
		) * 60
		 + tm->tm_sec;
	return clock;
}
/*
 *	convert the "tm" time as if it is a local time, then detuct
 *	the Gmtoff()
 */
int Timelocal(struct tm *tm)
{	struct tm tms;

	tms = *tm;
	return Timegm(&tms) - Gmtoff();
}
static struct tm tmv[8];
static int tmx;
#undef gmtime
static struct tm *GmtimeX(unsigned int clock){
	int days,tdays,ydays;
	int yday,mday = 0;
	int yoff,mon = 0;
	struct tm *tm;

	tm = &tmv[tmx++ % elnumof(tmv)];
	tm->tm_sec = clock % 60;
	tm->tm_min = (clock / 60) % 60;
	tm->tm_hour = (clock / 3600) % 24;
	days = (clock / 3600) / 24;
	tdays = 0;
	for( yoff = 0; yoff < 70; yoff++ ){
		ydays = 365 + ((yoff-2) % 4 == 0);
		if( tdays+ydays < days ){
			tdays += ydays;
		}else{
			yday = days - tdays;
			for( mon = 0; mon < 12; mon++ ){
				if( yday < yday_base[mon+1] ){
					mday = yday - yday_base[mon];
					if( 1 < mon && (yoff-2)%4 == 0 )
						mday++;
					break;
				}
			}
			break;
		}
	}
	tm->tm_mon = mon;
	tm->tm_mday = mday + 1;
	tm->tm_year = 70+yoff;
	tm->tm_yday = yday;
	tm->tm_wday = (days +4 ) % 7;
	return tm;
}
static struct tm *Gmtime(const time_t *clock){
	return GmtimeX(*clock);
}
static struct tm *Localtime(const time_t *clock){
	return GmtimeX(*clock+Gmt_off);
}

void getTimestampY(PVStr(stime))
{
	StrfTimeLocal(BVStr(stime),64,"%Y/%m/%d-%H:%M:%S%.3s",Time());
}
void getTimestamp(PVStr(stime))
{	int now,usec;

	now = Gettimeofday(&usec);
	StrftimeLocal(BVStr(stime),64,"%m/%d-%H:%M:%S%.3s",now,usec);
/* StrftimeLocal(AVStr(stime),ERR_sizeof(stime),"%m/%d-%H:%M:%S%.3s",now,usec); */
}

/*
main(){
CStr(buf,64);
CStr(buf2,64);
int clock = time(0);
static struct tm tm1,tm2,*tm;
int i,nw,nnw;

nw = 0;
clock -= 24*60*60*280;
for(i = 0; i < 2000; i++)
{	CStr(buf,1024);

	tm = localtime(&clock);
	nnw = NthWeek(tm,1);
	if( nw != nnw ){
		strftime(buf,sizeof(buf),"%y/%m/%d(%w)",tm);
		printf("%2d: %-12s",nnw,buf);
	}
	nw = nnw;
	clock += 24*60*60;
}
exit();

StrftimeLocal(buf,32,TIMEFORM_RFC822,clock); printf("%s\n",buf);
StrftimeGMT(buf,32,TIMEFORM_RFC822,clock); printf("%s\n",buf);
sleep(1);
StrftimeGMT(buf2,32,TIMEFORM_RFC822,time(0)); printf("%s\n",buf2);

printf("%d\n",tmcmp(&tm1,&tm2));
printf("%d\n",tmcmp(&tm2,&tm1));

}
*/
/*
main(){
	CStr(date,1024);
	int now,t;

	now = time(0);

	StrftimeGMT(date,sizeof(date),TIMEFORM_RFC850,now);
	t = scanHTTPtime(date);
	printf("RFC850 %d %d %s\n",now,t,date);

	StrftimeGMT(date,sizeof(date),TIMEFORM_RFC822,now);
	t = scanHTTPtime(date);
	printf("RFC822 %d %d %s\n",now,t,date);

	StrftimeGMT(date,sizeof(date),TIMEFORM_ANSI_C,now);
	t = scanHTTPtime(date);
	printf("ANSI_C %d %d %s\n",now,t,date);
}
*/

/*
main()
{	unsigned long clock,clock1,clock2;
	struct tm *tm;
	CStr(fmt,64);
	CStr(date1,256);
	CStr(date2,256);

	strcpy(fmt,"%y/%m/%d W=%W");
	for( clock = 0; clock < 0xFFFFFFFF; clock += 60*60*24 ){
		tm = gmtime(&clock);
		clock1 = timegm(tm);
		clock2 = Timegm(tm);
		if( clock1 != clock2 ){
			printf("%8d %8d %8d %s",clock,clock1,clock2,ctime(&clock));
		}
		strftime(date1,sizeof(date1),fmt,tm);
		StrftimeGMT(date2,sizeof(date2),fmt,clock);
		if( strcmp(date1,date2) == 0 ){
			fprintf(stderr,"%10d [%s][%s]\r",clock,date1,date2);
			fflush(stderr);
		}else{
			fprintf(stdout,"%10d [%s][%s]\n",clock,date1,date2);
		}
	}
}
*/

/*
main()
{
	LsDateClock("Dec 22 01:46",time(0));
	LsDateClock("Dec 22 1996", time(0));
	LsDateClock("Apr 14 01:46",time(0));
	LsDateClock("Apr 14 1995", time(0));
	LsDateClock("Jan 22 19:55",time(0));
}
*/
