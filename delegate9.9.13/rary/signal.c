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
Program:	signal.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960616	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "vsignal.h"
int IsSolaris();

#if defined(SA_RESTART) || defined(sun)

#ifdef sun
/* an executalbe compiled on SunOS may be executed on Solaris,
 * therefore SA_RESTART given by preprocessor cannot be used.
 */
#undef SA_RESTART
#define SA_RESTART (IsSolaris() ? 4 : 0)
#endif

vfuncp BSDsignal(int sig,void (*func)(int))
{	int rcode;
	struct sigaction sa;
	void (*ofunc)(int);

	rcode = sigaction(SIGHUP,NULL,&sa);
	if( rcode != 0 )
		return (vfuncp)-1;

	ofunc = sa.sa_handler;
	sa.sa_handler = func;
	sa.sa_flags = SA_RESTART;
	rcode = sigaction(SIGHUP,&sa,NULL);

	syslog_DEBUG("#### SIGACTION(%d)=%d handler:%x mask:%x flags: %x\n",
		sig,rcode,xp2i(sa.sa_handler),sa.sa_mask,sa.sa_flags);

	if( rcode != 0 )
		return (vfuncp)-1;

	return ofunc;
}

#else
vfuncp BSDsignal(int sig,void (*func)(int))
{
	return Vsignal(sig,func);
}
#endif

const char *sigsym(int sig)
{
	switch( sig ){
		case SIGHUP:	return "HUP";
		case SIGINT:	return "INT";
		case SIGQUIT:	return "QUIT";
		case SIGILL:	return "ILL";

		case SIGFPE:	return "FPE";
		case SIGBUS:	return "BUS";
		case SIGSEGV:	return "SEGV";
		case SIGPIPE:	return "PIPE";

		case SIGKILL:	return "KILL";
		case SIGTERM:	return "TERM";

		case SIGTRAP:	return "TRAP";
		case SIGALRM:	return "ALRM";
		case SIGCHLD:	return "CHLD";
		case SIGEMT:	return "EMT";
		default:	return "???";
	}
}

static jmp_buf ps_env;
static void sigSEGV(int sig){
	longjmp(ps_env,-1);
}
int blockSEGVBUS(int (*func)(void*,...), void *a,void *b,void *c,void *d)
{	int rcode;

	vfuncp sSEGV,sBUS;
	sSEGV = Vsignal(SIGSEGV,sigSEGV);
	sBUS = Vsignal(SIGBUS,sigSEGV);

	if( setjmp(ps_env) == 0 )
		rcode = (*func)(a,b,c,d);
	else	rcode = -1;

	signal(SIGSEGV,sSEGV);
	signal(SIGBUS,sBUS);
	return rcode;
}
