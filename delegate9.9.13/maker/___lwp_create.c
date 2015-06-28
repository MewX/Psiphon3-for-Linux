#if 0
#include "ystring.h"

#include <sys/lwp.h>
#define STKSIZE 0x20000

static void thread1(char *av[])
{	vFUNCP func;

	func = (vFUNCP)av[0];
	(*func)(av[1],av[2],av[3],av[4],av[5],av[6],av[7]);
	/*porting_dbg("thread_exit()");*/
	free(av);
	_lwp_exit();
	/*porting_dbg("thread_exit() failed.");*/
	exit(-1);
}

static lwpid_t thread_fork(int ssize,IFUNCP func,...)
{	ucontext_t *ctx;
	caddr_t stk;
        lwpid_t lwp;
        int err;
	char **av;
	int ai;
	VARGS(7,func);

	av = (char **)malloc(sizeof(void*)*8);
	av[0] = (char*)func;
	for( ai = 0; ai < 7; ai++ )
		av[1+ai] = va[ai];

	if( ssize == 0 )
		ssize = STKSIZE;

	ctx = (ucontext_t*)malloc(sizeof(ucontext_t));
	/*
	stk = (caddr_t)malloc(STKSIZE);
	*/
	stk = (caddr_t)malloc(ssize);
	_lwp_makecontext(ctx,(void(*)(void*))thread1,(void*)av,(void*)NULL,stk,ssize);
	err = _lwp_create(ctx,NULL,&lwp);
	/*porting_dbg("thread_fork() = %d",lwp);*/
	return lwp;
}

const char *WithThread = "_Lwp";
lwpid_t (*ThreadFork)(int,IFUNCP,...) = thread_fork;
int (*ThreadYield)() = 0;

static int thread_wait(int tid,int timeout){
        return -1;
}
int (*ThreadWait)(int,int) = (int(*)(int,int))thread_wait;
int (*ThreadId)() = 0;

int getThreadIds(FileSize *mtid,FileSize *ctid){ return 0; }
#endif
