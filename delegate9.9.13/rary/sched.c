/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	sched.c (scheduler)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

   USAGE:
	void *sched;	// pointer to a scheduler
	char *cronspec;	// a scheduler rule
	long now;	// the current time
	long nexttime;	// the nearest future when some event will occur
	int (*callback)(arg);

	sched = sched_create();
			// create a scheduler and return the handle
	error = sched_append(sched,cronspec);
			// add a rule to the scheduler
	nexttime = sched_eval(sched,now,callback,arg)
			// actions to be activated by "now" are fired and
			// the time when to eval. next time is returned
	char *(*callback)(arg,cronspec,prevtime)
			// should return new cronspec ?
			// should return current process ID ?

   CRONSPEC:

   BASIC RULE
	EVENT [CONDITION] ACTION

	# comment

   TIME EVENT
	M H d m w action          // "cron" compatible rule
	@timespec action          // inherent rule
	Wday:y:m:d:H:M:S:action   // cannonical format

	  S [0-59]	seconds
	  M [0-59]	minutes
	  H [0-23]	hours
	  d [1-31]	days
	  m [1-12]	months
	  y [0-99]	year

	Each time-unit is a list of following values separated with ",".

	  N	on the unit-time N
	  *	on every unit-time
	  +M	after N unit-time exceeded from the previous activation time
	  N+M	on the unit-time N and succeeding every M unit-time
	  Wday	Sun | Mon | Tue | Wed | Thu | Fri | Sat

    ACTION
	compaible with inetd.conf
		action = uid:wait-status:command:
	CRON + INETD: CRONETD, INETCRON, ...
        chroot

        UID:ROOT:WAIT:COMMAND

    LABELED RULE
	label: RULE

    LOGGING-CONTROL
	(L|V)	record the log of executed actions

    OPTIONAL PREFIX
	(N)	discarded after N times repetition
	(-N)	maximum activation postpone [discarded if exceeded N]
	(+event)	activate after the "event" occured

    INTERNAL ACTIONS
	-exit                     // exit the server process
	-restart                  // restart the server process
	-sleep N                  // suspend the server for N seconds
	-expire -atime +N         // cache expiration
	-agelog
	-refresh URL              // reload (If-Modified)
	-fetch URL                // prefetch
		EXAMPLE:
		-fetch nntp://server/group1,group2,group3

		This rule can be generated automatically from DeleGate itself.

    EXTERNAL ACTIONS
	(owner=name) /path arg-list

    EXTERNAL EVENTS
	I/O selection
	acceptable port of servers socket itself

    INTERNAL EVENTS
	-initialization  -> private-MASTER ...
	-penalty sleep
	-thread scheduling
	-builtin (default) scheduler script
	-rules included by default

    SYNCRONIZATION
	wait until the action process exit, to avoid parallel
	multiple exection of action
	sleeping / polling in scheduler...

    EVENT,CONDTION,ACTION
	EVENT name
	CONDITION ... CFI?
	ACTION .. CGI?

    CONDITION
	number of parallel invocation of each action

    (autonomous proxy server)

    REMOTE ACTION
	action may be inported from remote user via some application
	protocol like HTTP... but there may be securiti problem.

History:
	970815	created
//////////////////////////////////////////////////////////////////////#*/
/*
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
*/
#include "ystring.h"
#include <ctype.h>
int toclockLocal(int y,int m,int d,int H,int M,int S);

int sched_DEBUG = 2;

/*
 * units of time
 */
#define CSEC	0	/* 1/100 second */
#define SEC	1	/* second */
#define MiN	2	/* minute */
#define HOUR	3	/* hour */
#define MDAY	4	/* day of month */
#define MON	5	/* month */
#define YEAR	6	/* year */
#define WDAY	7	/* day of week */

#define TUNITS	10

static struct {
  const	char   *ut_name;
	int	ut_min;
	int	ut_max;
} turange[TUNITS] = {
	{ "CSEC", 0, 99 },
	{ "SEC",  0, 59 },
	{ "MIN",  0, 59 },
	{ "HOUR", 0, 23 },
	{ "MDAY", 1, 31 },
	{ "MON",  1, 12 },
	{ "YEAR", 0, 128},
	{ "WDAY", 0,  6 },
};

typedef struct { unsigned int
	fmt:8,  /* time unit format {literal,EVERY,INC} */
	inc:8,  /* increment relative to the current time */
	base:8; /* the first time for inc. */
} Tunit;

/* special time unit value */
#define TMU_EVERY	(-1 & 0xFF)
#define TMU_INC 	(-2 & 0xFF)

#define _CLR(tfv)	(tfv[0].inc = 1)
#define _NTF(tfv)	((int)(tfv[0].inc)-1)
#define _FMT(tfv,ti)	(tfv[1+ti].fmt)
#define _INC(tfv,ti)	(tfv[1+ti].inc)

#define CNTF(ti)	_NTF(cep->c_tfv[ti])
#define CFMT(ti,tj)	_FMT(cep->c_tfv[ti],tj)
#define CINC(ti,tj)	_INC(cep->c_tfv[ti],tj)

typedef struct {
  const	char   *c_cronspec;	/* original time format specification text */
  const	char   *c_timespec;	/* normalized time format part of cronscpec */
	Tunit  *c_tfv[TUNITS];	/**//* time format vector (compiled timespec) */
	long	c_nexttime;	/* next activation time */
	long	c_prevtime;	/* previous activation time */
	int	c_prevcode;	/* previous exit code from the actiion */
	int	c_relative;	/* relative to the previous activation */
	int	c_mintime;	/* the mininum synthesizable time */
	int	c_maxtime;	/* the maximum synthesizable time */
  const	char   *c_event;
  const	char   *c_condition;
  const	char   *c_action;	/* what to do */
	int	c_maxcnt;	/* maximum activation count */
	int	c_cnt;		/* activation count */
} CronEnt;

typedef struct {
       CronEnt *st_cronvec;
	int	st_cronmax;
	int	st_numcron;
	int	st_nexttime;
} CronTab;

#define	CRONTAB	Cron->st_cronvec
#define NCRONS	Cron->st_numcron

CronTab *sched_create()
{	CronTab *Cron;
	int isize = 32;

	Cron = NewStruct(CronTab);
	Cron->st_cronmax = isize;
	Cron->st_cronvec = (CronEnt*)calloc(isize,sizeof(CronEnt));
	Cron->st_numcron = 0;
	Cron->st_nexttime = 0;
	return Cron;
}

static char *scan_timeform2(PCStr(cronspec),const char *tf[],PVStr(cronspecb))
{	const char *action;
	const char *tfx[TUNITS]; /**//* time format vector buffer */
	int ti;
	int nc;

	for( ti = 0; ti < 8; ti++ )
		tf[ti] = NULL;

	tf[CSEC] = "0";
	strcpy(cronspecb,cronspec);
	nc = stoV(cronspecb,8,tfx,':');
	if( 7 < nc ){
		/*
		 * min hour mday mon wday [action]
		 */
		tf[SEC] =tfx[6]; tf[MiN]=tfx[5]; tf[HOUR]=tfx[4];
		tf[MDAY]=tfx[3]; tf[MON]=tfx[2]; tf[YEAR]=tfx[1];
		tf[WDAY]=tfx[0];
		if( nc == 7 )
			action = "";
		else	action = tfx[7];
	}else{
		strcpy(cronspecb,cronspec);
		nc = stoV(cronspecb,6,tfx,' ');
		if( nc < 5 ){
 syslog_ERROR("SCHED ERROR %s ? USAGE=w:y:m:d:H:M:D:action\n",cronspec);
			return NULL;
		}
		/*
		 * wday:y:m:d:H:M:S[:action]
		 */
		tf[SEC] ="0";    tf[MiN]=tfx[0]; tf[HOUR]=tfx[1];
		tf[MDAY]=tfx[2]; tf[MON]=tfx[3]; tf[YEAR]="*";
		tf[WDAY]=tfx[4];
		if( nc == 5 )
			action = "";
		else	action = tfx[5];
	}
	return (char*)action;
}

static scanListFunc timeunit1(PCStr(tf1),CronEnt *cep,int ti,int mac,Tunit tuv1[])
{	int fmt,inc,idx;

	inc = 0;
	if( *tf1 == '+' ){
		fmt = TMU_INC;
		inc = atoi(&tf1[1]);
		if( inc == 0 )
			inc = 1;
		if( cep != NULL )
			cep->c_relative = 1;
	}else
	if( *tf1 == 0 || strcmp(tf1,"*") == 0 ){
		fmt = TMU_EVERY; /* every time */
		inc = 1;
	}else{
		if( ti == WDAY && !isdigit(*tf1) )
			fmt = wdaytoi(tf1);
		else	fmt = atoi(tf1);
		if( fmt < turange[ti].ut_min || turange[ti].ut_max < fmt )
			return -1;
	}
	if( mac <= tuv1[0].inc ){
		return -1;
	}
	idx = tuv1[0].inc++;
	tuv1[idx].fmt = fmt;
	tuv1[idx].inc = inc;
	return 0;
}
static Tunit *allocTunit(Tunit *tuv)
{	int size,tj;
	Tunit *ntuv;

	size = tuv[0].inc;
	ntuv = (Tunit*)calloc(size,sizeof(Tunit));
	for( tj = 0; tj < size; tj++ )
		ntuv[tj] = tuv[tj];
	return ntuv;
}
static scanListFunc tmform1(PCStr(tfm),Tunit tuv[][64])
{	int ti;

	switch( tfm[0] ){
		case 'C': ti = CSEC; break;
		case 'S': ti = SEC;  break;
		case 'M': ti = MiN;  break;
		case 'H': ti = HOUR; break;
		case 'd': ti = MDAY; break;
		case 'm': ti = WDAY; break;
		case 'y': ti = YEAR; break;
		default:
 syslog_ERROR("SCHED unknown %s\n",tfm);
			return -1;
	}
	timeunit1(tfm+1,NULL,ti,elnumof(tuv[ti]),tuv[ti]);
	return 0;
}
static void scan_timeform1(CronTab *Cron,PCStr(cronspec),PVStr(cronspecc))
{	const char *action;
	refQStr(sp,cronspecc); /**/
	const char *tp;
	Tunit tuv[TUNITS][64]; /**/
	int ti,tj,nfmt;
	CStr(cronspecb,1024);

	strcpy(cronspecb,cronspec);
	if( action = strpbrk(cronspecb,": \t") ){
		truncVStr(action); action++;
	}

	for( ti = 0; ti < 8; ti++ )
		_CLR(tuv[ti]);
	if( scan_commaList(cronspecb,0,scanListCall tmform1,tuv) != 0 )
		return;

	for( ti = WDAY; SEC <= ti; ti-- ){
		assertVStr(cronspecc,sp+10);
		nfmt = _NTF(tuv[ti]);
		if( nfmt == 0 ){
			setVStrPtrInc(sp,'*');
		}else
		if( _FMT(tuv[ti],0) == TMU_EVERY ){
			setVStrPtrInc(sp,'*');
		}else
		if( _FMT(tuv[ti],0) == TMU_INC ){
			setVStrPtrInc(sp,'+');
			sprintf(sp,"%d",_INC(tuv[ti],0));
			sp += strlen(sp);
		}else{
		    for( tj = 0; tj < nfmt; tj++ ){
			if( 0 < tj )
				setVStrPtrInc(sp,',');
			sprintf(sp,"%d",_FMT(tuv[ti],tj));
			sp += strlen(sp);
		    }
		}
		setVStrPtrInc(sp,':');
	}
	XsetVStrEnd(AVStr(sp),0);
	if( action )
		strcpy(sp,action);
	else	XsetVStrEnd(AVStr(sp),0);
}
static int lasttime(CronEnt *cep);
int sched_append(CronTab *Cron,PCStr(cronspec))
{	const char *tf[TUNITS];	/**//* time format vector */
	const char *action;
	int ci;
	int ti;
	CronEnt *cep;
	CStr(tmp,1024);
	CStr(cronspecb,1024);	/* time format data buffer */
	CStr(cronspecc,1024);
	Tunit tuv1[100]; /**/
	int rcode;

	for( ci = 0; ci < NCRONS; ci++ )
		if( strstr(cronspec,CRONTAB[ci].c_cronspec) )
			return 0;

	if( cronspec[0] == '@' ){
		scan_timeform1(Cron,cronspec+1,AVStr(cronspecc));
		cronspec = cronspecc;
	}

	action = scan_timeform2(cronspec,tf,AVStr(cronspecb));
	if( action == NULL )
		return -1;

	cep = &CRONTAB[ci];
	cep->c_action = stralloc(action);
	for( ti = 0; ti < 8; ti++ ){
		_CLR(tuv1);
		rcode = scan_commaList(tf[ti],0,scanListCall timeunit1,cep,ti,elnumof(tuv1),tuv1);
		if( rcode != 0 ){
 syslog_ERROR("SCHED ERROR range: %s -- %s[%d-%d]\n",
 cronspec,turange[ti].ut_name,turange[ti].ut_min,turange[ti].ut_max);
			return rcode;
		}
		cep->c_tfv[ti] = allocTunit(tuv1);
	}

	cep->c_maxtime = lasttime(cep);
	cep->c_cronspec = stralloc(cronspec);
	sprintf(tmp,"%s:%s:%s:%s:%s:%s:%s",
		tf[WDAY],tf[YEAR],tf[MON],tf[MDAY],tf[HOUR],tf[MiN],tf[SEC]);
	cep->c_timespec = stralloc(tmp);

 syslog_DEBUG("SCHED added [%d] %s -> %s %s\n",ci,cronspec,tmp,action);

	NCRONS++;
	return 0;
}


/*
 *	LASTTIME(timeformat)
 *	The lasttime which can be produced by the given time-format.
 */
static int lasttime(CronEnt *cep)
{	int ti,tj;
	int max;
	int tv[TUNITS];
	int tu;
	int last;

	for( ti = CSEC; ti <= YEAR; ti++ ){
		max = turange[ti].ut_min;
		for( tj = 0; tj < CNTF(ti); tj++ ){
			switch( tu = CFMT(ti,tj) ){
				case TMU_EVERY:
				case TMU_INC:
					max = turange[ti].ut_max;
					break;
				default:
					if( max < tu )
						max = tu;
					break;
			}
		}
		tv[ti] = max;
	}
	last = toclockLocal(tv[YEAR],tv[MON],tv[MDAY],
		tv[HOUR],tv[MiN],tv[SEC]);

	return last;
}

/*
 *	CALC_NEXTTIME()
 *	calculate the nearest future time for the given time format,
 *	that is, get the minimum value larger than given time "now".
 *
 */
static int vcmp(int *v1,int *v2,int n)
{	int i,d;

	for( i = n; 0 <= i; i-- )
		if( d = v1[i] - v2[i] )
			return d;
	return 0;
}

/*
 *    NEAREST1
 *	Get the nearest future in a time-unit.
 */
#define OUTRANGE	1000
static int nearest1(int xtu,int ti,CronEnt *cep,int *bt,int *ot)
{	int tu,bu;	
	int tj;
	int smaller,larger;

	larger = OUTRANGE;
	smaller = OUTRANGE;
	bu = bt[ti];

	for( tj = 0; tj < CNTF(ti); tj++ ){
		tu = CFMT(ti,tj);
		if( tu == bu && 0 < vcmp(ot,bt,ti-1) )
			return tu;
		if( bu < tu && tu < larger )
			larger = tu;
		if( tu < bu && tu < smaller )
			smaller = tu;
		/*printf("[%d] %3d %3d\n",tj,larger,smaller);*/
	}
	if( larger != OUTRANGE )
		return larger;
	if( smaller != OUTRANGE )
		return smaller;
	return xtu;
}
/*    NEARSETWDAYMDAY
 *	Calculate MDAY from WDAY if MDAY is free and WDAY is bound
 */
static int nearestWdayMday(CronEnt *cep,int bt[],int ot[])
{	int cwday,twday,nday;
	int min;
	int tj;

	min = 8;
	cwday = bt[WDAY];

	for( tj = 0; tj < CNTF(WDAY); tj++ ){
		twday = CFMT(WDAY,tj);
		if( cwday < twday || cwday == twday && 0 < vcmp(ot,bt,HOUR) )
			nday =     (twday - cwday);
		else	nday = 7 - (cwday - twday);
		if( nday < min )
			min = nday;
	}
	if( min == 8 )
		min = 0;
	return min;
}

/*
 *    RESET_LOWERORDER
 *	Reset lower order time-units when a higher order time-unit is 
 *	set with value different to the current time value.
 */
static void reset_lowerorder(int ti,CronEnt *cep,int bt[],int ot[],int carry[])
{	int tj;
	int tu;
	int lastcarry;

	lastcarry = -1;
	for( tj = ti-1; 0 <= tj; tj++ ){
		if( carry[tj] ){
			lastcarry = tj;
			break;
		}
	}

	for( tj = 0; tj < ti; tj++ ){
		tu = CFMT(tj,0);
		if( tu == TMU_EVERY )
			ot[tj] = turange[tj].ut_min;
		else
		if( tu == TMU_INC ){
			/* don't reset the time-value if the current rest is
			 * caused by the carry from this time-format itself.
			 */
			if( CFMT(ti,0) == TMU_INC || lastcarry != tj )
				ot[tj] = turange[tj].ut_min;
		}else	ot[tj] = tu; /* 1st, minimum value in the format */
	}
}

static void calc1(int ti,CronEnt *cep,int bt[],int ot[],int it[],int carry[])
{	int tu,inc,max,next;

	tu = CFMT(ti,0);
	if( tu == TMU_EVERY || tu == TMU_INC ){
		if( it[ti] == 0 && 0 < vcmp(ot,bt,ti-1) )
			ot[ti] = bt[ti];
		else{
			inc = CINC(ti,0);
			if( inc < it[ti] )
				inc = it[ti];

			next = bt[ti] + inc;
			max = turange[ti].ut_max;
			if( next <= max )
				ot[ti] = next;
			else	ot[ti] = next-max - 1 + turange[ti].ut_min;
		}
	}else{
		ot[ti] = nearest1(tu,ti,cep,bt,ot);
	}
	if( ot[ti] != bt[ti] ){
		carry[ti] = 1;
		reset_lowerorder(ti,cep,bt,ot,carry);
	}

	if( 3 <= sched_DEBUG ){
		int tj;
		for( tj = 0; tj <= ti; tj++ )
			printf("[%2d]",ot[tj]);
		printf(" %s\n",turange[ti].ut_name);
	}
}

#define TMFMT	"%w/%Y:%m:%d:%H:%M:%S"

static int calc_nexttime(CronEnt *cep,long now,long prev)
{	int *ft;   /* literal/template time (with translation instructions) */
	int bt[TUNITS];/* base time value (current time from "now") */
	int ot[TUNITS];/* output (result) time value */
	int pt[TUNITS];/* the time value of previous activation */
	int it[TUNITS];/* by Wday to Mday */
	int carry[TUNITS];
	int ti;
	long last,base,next;

	if( (last = cep->c_maxtime) < now ){
		CStr(ltime,64);
		StrftimeLocal(AVStr(ltime),sizeof(ltime),TMFMT,last,0);
 syslog_ERROR("SCHED exceed the last time %s %d < %d\n",ltime,ll2i(last),ll2i(now));
		return 0;
	}

	base = now;
	if( now < prev || prev && cep->c_relative )
		base = prev;

	bt[CSEC] = 0;
	fromclockLocal(base,
	&bt[WDAY],&bt[YEAR],&bt[MON],&bt[MDAY],&bt[HOUR],&bt[MiN],&bt[SEC]);

	for( ti = 0; ti <= WDAY; ti++ ){
		ot[ti] = 0;
		it[ti] = 0;
		carry[ti] = 0;
	}

	for( ti = CSEC; ti <= HOUR; ti++ )
		calc1(ti,cep,bt,ot,it,carry);

	if( CFMT(MDAY,0) == TMU_EVERY && CFMT(WDAY,0) != TMU_EVERY )
		it[MDAY] = nearestWdayMday(cep,bt,ot);

	for( ti = MDAY; ti <= YEAR; ti++ )
		calc1(ti,cep,bt,ot,it,carry);

	next = toclockLocal(ot[YEAR],ot[MON],ot[MDAY],
			ot[HOUR],ot[MiN],ot[SEC]);

	if( next == prev ){
 syslog_DEBUG("SCHED search T in %d <= T\n",ll2i(next));
		if( CFMT(SEC,0) == TMU_EVERY )
			next++;
		else	return calc_nexttime(cep,next+1,next+1);
	}else
	if( next <= now ){
		if( CFMT(SEC,0) == TMU_EVERY )
			next = now + 1;
		else	return calc_nexttime(cep,now,now);
	}

	cep->c_nexttime = next;
 if( 2 <= sched_DEBUG ){
	 CStr(btime,64);
	 CStr(ntime,64);
	 sprintf(btime,"%02d/%03d:%02d:%02d:%02d:%02d:%02d",
		bt[WDAY],bt[YEAR],bt[MON],bt[MDAY],bt[HOUR],bt[MiN],bt[SEC]);
	 StrftimeLocal(AVStr(ntime),sizeof(ntime),TMFMT,next,0);
 syslog_DEBUG("SCHED %s : %s -> %s = %d \"%s\"\n",
 btime,cep->c_timespec,ntime,ll2i(next),cep->c_action);
 }
	return cep->c_nexttime;
}

#define FARFUTURE	(((unsigned int)(-1))>>1)

/*
 *	SCHED_EVAL(cron,now,callback,arg)
 *
 *	Cause action which must be caused before now,
 *	calculate the next time to be called (rescheduled).
 *	Now is not necessary the real time.
 *
 */
int sched_eval(CronTab *Cron,long now,iFUNCP callback,void *arg)
{	int ci,next,nx1;
	CronEnt *cep;
	int xcode;
	int start;

	if( Cron == NULL )
		return -1;
	if( NCRONS == 0 )
		return -1;
	if( now < Cron->st_nexttime )
		return Cron->st_nexttime;

	start = time(0);
	for( ci = 0; ci < NCRONS; ci++ ){
		cep = &CRONTAB[ci];

		if( cep->c_nexttime )
		if( cep->c_nexttime <= now ){
 syslog_DEBUG("SCHED cause action [%s] %s\n",
 cep->c_timespec,cep->c_action);
			xcode = (*callback)(arg,cep->c_action,
				cep->c_prevtime,cep->c_prevcode);
			cep->c_prevtime = cep->c_nexttime;
			cep->c_prevcode = xcode;
			cep->c_nexttime = 0;
		}
	}
	now += (time(0) - start);

	next = FARFUTURE;
	for( ci = 0; ci < NCRONS; ci++ ){
		cep = &CRONTAB[ci];

		if( now < cep->c_nexttime )
			nx1 = cep->c_nexttime;
		else	nx1 = calc_nexttime(cep,now,cep->c_prevtime);
		if( now <= nx1 && nx1 < next )
			next = nx1;
	}

	if( next == FARFUTURE || next < now )
		return -1;

	Cron->st_nexttime = next;
	return next;
}


static int do_action(void *_,PCStr(action),long ptime,int pcode)
{
 syslog_DEBUG("ACTION: %s\n",action);
	IGNRETZ system(action);
	return 0;
}
int sched_main(int ac,const char *av[])
{	CStr(line,1024);
	CronTab *Cron;
	long next;
	int ai;
	const char *arg;
	int wait;
	FILE *cfp;

	Cron = sched_create();
	if( ac < 2 ){
		fprintf(stderr,"Usage: %s cronspec | /path/of/cronfile\r\n",
			av[0]);
		exit(1);
	}

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( arg[0] == '-' ){
			if( arg[1] == 'v' ){
				sched_DEBUG = atoi(&arg[2]);
				if( sched_DEBUG == 0 )
					sched_DEBUG = 2;
			}
		}else
		if( arg[0] == '/' ){
			cfp = fopen(arg,"r");
			if( cfp == NULL ){
				fprintf(stderr,"Cannot open: %s\r\n",arg);
				exit(1);
			}
			while( fgets(line,sizeof(line),cfp) != NULL )
				if( sched_append(Cron,line) != 0 )
					exit(1);
			fclose(cfp);
		}else{
			if( sched_append(Cron,arg) != 0 )
				exit(1);
		}
	}

	for(;;){
		next = sched_eval(Cron,time(NULL),(iFUNCP)do_action,(void*)0);
		wait = next - time(NULL);
		if( wait < 0 ){
			/* no more activation will occur */
			break;
		}
 if( 1 <= sched_DEBUG )
 syslog_DEBUG("SLEEP: %d seconds\n",wait);
		sleep(wait);
	}
	return 0;
}
