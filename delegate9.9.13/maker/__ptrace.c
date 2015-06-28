#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifdef PTRACE_TRACEME
#define ptTRACEME	PTRACE_TRACEME
#define ptCONTINUE	PTRACE_CONT
#ifndef PTRACE_KILL
#define PTRACE_KILL	PTRACE_EXIT
#endif
#define ptKILL		PTRACE_KILL
#define PTrace(o,p,a,d)	ptrace(o,p,(void*)a,d)
#endif

#ifdef PT_TRACE_ME
#define ptTRACEME	PT_TRACE_ME
#define ptCONTINUE	PT_CONTINUE
#define ptKILL		PT_KILL
#define PTrace(o,p,a,d)	ptrace(o,p,(void*)a,d)
#endif

#ifdef PT_SETTRC
#define ptTRACEME	PT_SETTRC
#define ptCONTINUE	PT_CONTIN
#define ptKILL		PT_EXIT
#define PTrace(o,p,a,d)	ptrace(o,p,(void*)a,d)
#endif

#ifndef ptTRACEME
#define ptTRACEME	0
#define ptCONTINUE	7
#define ptKILL		8
#define PTrace(o,p,a,d)	ptrace(o,p,a,d)
#endif

#ifndef WCOREDUMP
#define WCOREDUMP(stat)	-1
#endif

int INHERENT_ptrace(){ return 1; }

int ptraceTraceMe()
{
	return PTrace(ptTRACEME,0,0,0);
}
int ptraceContinue(int pid,int sig)
{
	return PTrace(ptCONTINUE,pid,1,sig);
}
int ptraceKill(int pid)
{
	return PTrace(ptKILL,pid,0,0);
}

int getWaitStopSig(int *statp)
{
	if( WIFSTOPPED(*statp) )
		return WSTOPSIG(*statp);
	else	return -1;
}
int getWaitExitSig(int *statp)
{
	if( WIFSIGNALED(*statp) )
		return WTERMSIG(*statp);
	else	return -1;
}
int getWaitExitCode(int *statp)
{
	if( WIFEXITED(*statp) )
		return WEXITSTATUS(*statp);
	else	return -1;
}
int getWaitExitCore(int *statp)
{
	return WCOREDUMP(*statp);
}
