#ifndef _PROC_H
#define _PROC_H

#ifndef _MSC_VER
#include <sys/types.h>
#include <sys/wait.h>
#endif
#ifdef _MSC_VER
#define getpgrp() 0
#define setpgid(p,g) -1
#endif

#ifndef MAX_THREADS
#define MAX_THREADS 64
#endif

int ptraceKill(int pid);
int ptraceContinue(int pid,int sig);
int getWaitStopSig(int *statp);
int getWaitExitSig(int *statp);
int getWaitExitCode(int *statp);
int getWaitExitCore(int *statp);

int Kill(int pid,int sig);
int KillTERM(int pid);
int Killpg(int pgrp,int sig);
int Fork(PCStr(what));
int ForkX(PCStr(what),int(*)(const char*,int));

typedef const char *const *ConstV;
int ExecveX(PCStr(where),PCStr(path),ConstV av,ConstV ev,int flag);
#define EXP_PATH    1 /* execvp() with PATH */
#define EXP_DGPATH  2 /* search by DeleGate's path */
#define EXP_NOENV   4 /* don't inherit DeleGate's environ */
#define EXP_NOFDS   8 /* don't inherit file descriptors [3-] */

int Execvp(PCStr(where),PCStr(path),const char *const av[]);
int Spawnvp(PCStr(what),PCStr(path),const char *const av[]);
void Exit(int code,PCStr(fmt),...);
int WaitX(int mode);
int NoHangWait();
int NoHangWaitX(int *sigp);
int NoHangWaitXX(int *sigp,int *statp);
int procIsAlive(int pid);
extern int InFinish;

int Getpid();
int uGetpid();
int setCloseOnExec(int fd);
int setCloseOnFork(PCStr(wh),int fd);
int setInheritHandle(int fd,int on);

#define MAINTHREADID	-2
int   thread_PollIn(int fd,int timeout);
int   thread_fork(int size,int gtid,PCStr(what),int (*func)(void*,...),...);
int   thread_wait(int tid,int timeout);
int   thread_destroy(int tid);
int   thread_priority(int pri);
int   thread_sigmask(PCStr(show),SigMaskInt nmask,SigMaskInt *omask);
int   thread_kill(int tid,int sig);
void  thread_exit(void *code);
void  thread_yield();
int   getthreadid();
int   getthreadix();
int   clearthreadsix();
int   mainthreadid();
int   ismainthread();
int   numthreads();
int   actthreads();
int   endthreads();
int   threadIsAlive(int tid);
int   dumpthreads(PCStr(wh),FILE *tc);

#if defined(_MSC_VER)
#if defined(UNDER_CE)
#define execve(p,a,e) -1
#endif
#endif
int Xexecve(FL_PAR,const char *path,char *av[],char *ev[]);
int filterDGENV(char *ev[],char *nev[],int nec);
int closeFds(Int64 inheritfds);

#endif /* _PROC_H */
