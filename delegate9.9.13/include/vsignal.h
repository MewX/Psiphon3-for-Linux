#ifndef _VSIGNAL_H
#define _VSIGNAL_H

#include <setjmp.h>
#include <signal.h>
typedef void (*vfuncp)(int);

extern vfuncp BSDsignal(int,vfuncp);
/*
int pushTimer(PCStr(what),vfuncp func,int intvl);
*/
int pushTimer(const char *what,vfuncp func,int intvl);
void popTimer(int stackp);
extern const char *sigsym(int);

#ifndef SIGHUP
#define SIGHUP   -1
#endif

#ifndef SIGQUIT
#define SIGQUIT  -3
#endif

#ifndef SIGILL
#define SIGILL   -4
#endif

#ifndef SIGTRAP
#define SIGTRAP  -5
#endif

#ifndef SIGEMT
#define SIGEMT	 -7
#endif

#ifndef SIGFPE
#define SIGFPE	 -8
#endif

#ifndef SIGKILL
#define SIGKILL  -9
#endif

#ifndef SIGBUS
#define SIGBUS	-10
#endif

#ifndef SIGSEGV
#define SIGSEGV	-11
#endif

#ifdef _MSC_VER
#define SIGPIPE	SIGABRT
#else
#ifndef SIGPIPE
#define SIGPIPE -13
#endif
#endif

#ifndef SIGALRM
#define SIGALRM -14
#define WithSIGALRM	0
#else
#define WithSIGALRM	1
#endif

#ifndef SIGURG
#define SIGURG  -16
#endif

#ifndef SIGCHLD
#define SIGCHLD	-20
#endif

#ifndef SIGIO
#define SIGIO	-23
#endif

#ifndef SIGCONT
#define	SIGCONT	-24
#endif

#ifndef SIGXFSZ
#define	SIGXFSZ	-25
#endif

vfuncp Vsignal_FL(const char *F,int L,int sig,vfuncp func);
#define Vsignal(sig,func) Vsignal_FL(__FILE__,__LINE__,sig,func)
#define signal(sig,func) Vsignal_FL(__FILE__,__LINE__,sig,func)
void sigIGNORE(int sig);

#if defined(_MSC_VER) && 1400 <= _MSC_VER /* VC2005 or laters */
typedef void (*sigFunc)(int);
sigFunc winSignal(int sig,sigFunc func);
#undef signal
#define signal(s,f) winSignal(s,f)
#endif

#ifndef _SIGMASKINT_
#define _SIGMASKINT_
typedef unsigned int SigMaskInt;
#endif

#ifndef _FL_PAR_
#define _FL_PAR_
#define FL_PAR   const char *FL_F,int FL_L
#define FL_PAR_P FL_PAR,int pstm
#define FL_BAR   FL_F,FL_L
#define FL_BAR_P FL_BAR,pstm
#define FL_BAR_r FL_BAR,1
#define FL_BAR_s FL_BAR,0
#define FL_ARG   __FILE__,__LINE__
#define FL_ARG_r FL_ARG,1 /* resident */
#define FL_ARG_s FL_ARG,0 /* stacked */
#endif

#undef sigsetmask
#undef sigblock
#undef sigmask
SigMaskInt SigSetMask_FL(FL_PAR,SigMaskInt mask);
SigMaskInt SigBlock_FL(FL_PAR,SigMaskInt mask);
SigMaskInt SigMask_FL(FL_PAR,SigMaskInt sig);
#define sigsetmask(mask) SigSetMask_FL(FL_ARG,mask)
#define sigblock(mask)   SigBlock_FL(FL_ARG,mask)
#define sigmask(sig)     SigMask_FL(FL_ARG,sig)

#if defined(_MSC_VER) && !defined(sigjmp_buf)
#define sigjmp_buf jmp_buf
#endif
int SigSetJmp(FL_PAR,sigjmp_buf env,int savemask);
void SigLongJmp(FL_PAR,sigjmp_buf env,int val);
void LongJmp(FL_PAR,jmp_buf env,int val);
#define sigsetjmpX(env,sav) (SigSetJmp(FL_ARG,env,sav),sigsetjmp(env,sav))
#define siglongjmpX(env,val) (SigLongJmp(FL_ARG,env,val),siglongjmp(env,val))
#define longjmp(env,val) (LongJmp(FL_ARG,env,val),longjmp(env,val))

extern int selfLocaltime; /* use multi-thread signal safe localtime() */

#endif
