/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2004 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	abort.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:

	extended abort() function to do notification and setting up
	for shutdown before dumping core and exit.

History:
	041206	extracted from shutter.c
//////////////////////////////////////////////////////////////////////#*/

/*
#include <signal.h>
*/
#define SIGQUIT 3
void exitFATAL(int sig);
int Kill(int,int);

#ifdef __cplusplus
extern "C" {
#endif
void _exit(int);
void sleep(int);
int getpid();
#ifdef __cplusplus
}
#endif

#if defined(FMT_CHECK)
#define putfLog(fmt,...) 0
#else
void putfLog(const char *fmt,...);
#endif
extern const char *suppressAbort;

void abort()
{
	if( suppressAbort ){
		/* 9.9.4 MTSS abort() called in fork() */
		putfLog("abort() -- %s",suppressAbort);
		_exit(0);
	}
	exitFATAL(SIGQUIT);
	sleep(1);
	Kill(getpid(),SIGQUIT);
	_exit(0);
}
