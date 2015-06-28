#if 0
#include "ystring.h"

static void thread1(char *av[])
{	IFUNCP func;
	int rcode;

	func = (IFUNCP)(av[0]);
	rcode = (*func)(av[1],av[2],av[3],av[4]);
	porting_dbg("thread exit(%d)",rcode);
	_endthread(rcode);
}

static int thread_fork(int ssize,IFUNCP func,...)
{	int thid;
	int ai;
	void *av[8];
	VARGS(7,func);

	porting_dbg("thread fork(%d,%x) --> _beginthread()",ssize,func);

	av[0] = (void*)func;
	for( ai = 0; ai < 7; ai++ )
		av[1+ai] = va[ai];

	thid = _beginthread(thread1,ssize,av);
	porting_dbg("thread fork(%d,%x) = %d",ssize,func,thid);
	return thid;
}

const char *WithThread = "_BeginThread";
int (*ThreadFork)(int,IFUNCP,...) = thread_fork;
int (*ThreadYield)() = 0;
void WINthread(){}

static int thread_wait(int tid,int timeout){
	return -1;
}
int (*ThreadWait)(int,int) = (int(*)(int,int))thread_wait;
static int _getthreadid(){
	return GetCurrentThreadId();
}
int (*ThreadId)() = _getthreadid;

int getThreadIds(FileSize *mtid,FileSize *ctid){ return 0; }
#endif
