/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	timer.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950518	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "yarg.h"
#include "ystring.h"
#include "vsignal.h"
#include "proc.h"
#include "log.h"
void Usleep(int);

typedef struct {
  const	char	*what;
	int	intvl;
	vfuncp	func;
	vfuncp	osig;
	time_t	time;
	int	tid;  /* the thread to receive the SIGALRM */
	int	stid; /* original receiver thread of the SIGALRM */
} Timer;

typedef struct {
	Timer	te_timeStack[16]; /**/
	int	te_timeSp;
	int	te_func_start;
	jmp_buf	te_func_env;
} TimerEnv;
static TimerEnv *timerEnv;
#define timeStack	timerEnv->te_timeStack
#define timeSp		timerEnv->te_timeSp
#define func_start	timerEnv->te_func_start
#define func_env	timerEnv->te_func_env
void minit_timer()
{
	if( timerEnv == 0 )
		timerEnv = NewStruct(TimerEnv);
}

int DBG_TIMER = 0;
#define dprintf	(DBG_TIMER==0)?0:fprintf

static void sigALRM(int a)
{	Timer *tp;

	if( numthreads() ){
		/* 9.9.4 MTSS SIGALRM to be ignored in termination */
		if( gotsigTERM("SIGALRM ignored in termination") ){
			return;
		}
	}
	if( 0 < timeSp ){
		tp = &timeStack[timeSp-1];
dprintf(stderr,"!!sigALRM: %s\n",tp->what);
		if( actthreads() ){
			if( tp->tid != getthreadid() ){
				tp->stid = getthreadid();
				Vsignal(SIGALRM,sigALRM);
				thread_kill(tp->tid,SIGALRM);
				return;
			}
			if( tp->stid ){
				syslog_ERROR("[%X] SIGALRM forwarded from %X\n",
					getthreadid(),tp->stid);
			}
		}
		if( tp->func != NULL )
			(*tp->func)(a);
	}
}

void dumpTimer()
{	int pid,sp;

	pid = getpid();
	for( sp = 0; sp < timeSp; sp++ )
		dprintf(stderr,"[%d][%d] %s\n",pid,sp,timeStack[sp].what);
}

int pushTimer(PCStr(what),vfuncp func,int intvl)
{	Timer *tp;
	int sp;
	int oa;

	if( lMULTIST() ){
		return -1;
	}
	if( !WithSIGALRM )
		return timeSp;

	if( elnumof(timeStack) <= timeSp )
		return -1;

	sp = timeSp++;
	tp = &timeStack[sp];
	tp->tid = getthreadid();
	tp->stid = 0;
	tp->what = what;
	tp->func = func;
	tp->intvl = intvl;
	tp->osig = Vsignal(SIGALRM,sigALRM);
	if( oa = alarm(intvl) )
		tp->time = time(0) + oa;
	else	tp->time = 0;
dprintf(stderr,"++pushTimer: %s[%d] (%d)(%d)\n",tp->what,timeSp,intvl,oa);
	return sp;
}
void popTimer(int sp)
{	Timer *tp;
	int oa;

	if( lMULTIST() ){
		return;
	}
	if( !WithSIGALRM )
		return;
	if( sp < 0 )
		return;

	timeSp = sp;
	tp = &timeStack[sp];
	Vsignal(SIGALRM,tp->osig);
	if( oa = tp->time ){
dprintf(stderr,"--popTimer: %s[%d] --> %d\n",tp->what,timeSp,ll2i(oa-time(0)));
		alarm(oa - time(0));
	}else{
dprintf(stderr,"--popTimer: %s[%d] --> reset\n",tp->what,timeSp);
		alarm(0);
	}
}
void setTimer(int sp,int intvl)
{	Timer *tp;

	tp = &timeStack[sp];
	if( sp+1 == timeSp ){
dprintf(stderr,"==setTimer: %s[%d] == current (%d)\n",tp->what,sp,intvl);
		alarm(intvl);
	}else{
dprintf(stderr,"==setTimer: %s[%d] (%d)\n",tp->what,sp,intvl);
		if( intvl != 0 )
			tp->time = time(0) + intvl;
		else	tp->time = 0;
	}
}

/*
Sleep(sec)
{	int timer;

	timer = pushTimer("sleep",NULL,sec);
	sigpause(0);
	popTimer(timer);
}
*/

static void onTimeout(int sig)
{
	syslog_ERROR("## callFuncTimeout: SIGALRM after %ds\n",
		ll2i(time(NULL)-func_start));
	longjmp(func_env,-1);
}
void *callFuncTimeout(int sec,void *xcode,void *(*func)(void*,...),...)
{	void *rcode;
	int timer;
	void *osig;
	VARGS(4,func);

	minit_timer();
	func_start = time(NULL);
	timer = pushTimer("FuncTimeout",onTimeout,sec);
	if( setjmp(func_env) == 0 )
		rcode = (*func)(VA4);
	else	rcode = xcode;
	popTimer(timer);
	return rcode;
}

void msleep(int msec){
	int sec,usec;

	if( msec < 1000 ){
		Usleep(msec*1024);
		return;
	}

	if( sec = msec / 1000 )
		sleep(sec);

	if( usec = (msec % 1000)*1000 )
		Usleep(usec);
}
