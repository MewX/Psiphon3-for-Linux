#if 0
#include "ystring.h"

#include <lwp/lwp.h>
#include <lwp/stackdep.h>
#define STKSIZE 0x20000

static void thread1(char *av[])
{	vFUNCP func;

	func = (vFUNCP)av[0];
	(*func)(av[1],av[2],av[3],av[4],av[5],av[6],av[7]);
	/*porting_dbg("#### thread_exit()");*/
	free(av);
	lwp_destroy(SELF);
	porting_dbg("#### thread_exit() failed.");
	exit(-1);
}

static int init;

static caddr_t thread_fork(int ssize,IFUNCP func,...)
{	int err;
	char **av;
	thread_t *tid;
	stkalign_t *stack;
	int prio;
	int flags;
	int ai;
	VARGS(7,func);

	av = (char **)malloc(sizeof(void*)*8);
	av[0] = (char*)func;
	for( ai = 0; ai < 7; ai++ )
		av[1+ai] = va[ai];

	if( ssize == 0 )
		ssize = STKSIZE;

	prio = MINPRIO;
	flags = 0;
	if( init == 0 ){
		lwp_setstkcache(ssize,8);
		init = 1;
	}
	stack = lwp_newstk(ssize);
	err = lwp_create(&tid,thread1,prio,flags,stack,1,av);
	if( err )
		porting_dbg("#### lwp_create() failed: %d",err);
	return tid->thread_id;
}
static int thread_yield()
{
	return lwp_yield(SELF);
}

const char *WithThread = "Lwp";
caddr_t (*ThreadFork)() = thread_fork;
int (*ThreadYield)() = thread_yield;

static int thread_wait(int tid,int timeout){
        return -1;
}
int (*ThreadWait)(int,int) = (int(*)(int,int))thread_wait;
int (*ThreadId)() = 0;
int (*ThreadExit)(void *code) = 0;

int getThreadIds(FileSize *mtid,FileSize *ctid){ return 0; }
#endif
