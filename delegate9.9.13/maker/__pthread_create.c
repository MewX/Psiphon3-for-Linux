#include "ystring.h"
#include "sysconf.h"
#include "log.h"
#if defined(__cplusplus) && !defined(DG_WITH_PTHREAD) && !defined(__CYGWIN__)
	// and if -lpthread is not confirmed to be available
	// then this module should not be included
	// (as in small installation of FreeBSD 4)
#else
#include <pthread.h>
#endif

#define STKSIZE 0x40000
int toTid(const void *tha,int add);
const void *toThd(int tid,int del,int *ser);

typedef struct {
	char *a_saddr;
	int   a_ssize;
  const char *a_name;
	char *a_argv[8];
	pthread_attr_t a_attr;
} ThreadArgs;
int thread_done(void *xcode);
int thread_start(const char *name,void *ta);

static void *thread2(ThreadArgs *ta)
{	vFUNCP func;
	char **av;
	int si;

	thread_start(ta->a_name,ta);
	av = ta->a_argv;
	func = (vFUNCP)av[0];
	(*func)(av[1],av[2],av[3],av[4],av[5],av[6],av[7]);
	if( ta->a_saddr ){
		for( si = 0; si < ta->a_ssize; si++ ){
			if( ta->a_saddr[si] ){
				break;
			}
		}
		syslog_ERROR("--## used %X / %X ##-- %X %X + %X\n",
			ta->a_ssize-si,ta->a_ssize,
			p2i(&ta),p2i(ta->a_saddr),si
		);
		//free(ta->a_saddr);
	}
	/*
	free(ta);
	*/
	thread_done(0);
	pthread_exit(0);
	porting_dbg("#### pthread_exit() failed.");
	exit(-1);
}
typedef void *(*thchFuncp)(void *thcharg);
void *thread_child(thchFuncp func,void *arg);
static void *thread1(ThreadArgs *ta){
	return thread_child((thchFuncp)thread2,ta);
}

pthread_t main_tid;
/*
static pthread_t thread_fork(int ssize,const char *name,IFUNCP func,...)
*/
static int thread_fork(int ssize,const char *name,IFUNCP func,...)
{	pthread_t thread;
	int tid;
	ThreadArgs *ta;
	int err;
	int ai;
	void  *sadr = 0;
	size_t ssiz = 0;
	VARGS(7,func);

	ta = (ThreadArgs*)malloc(sizeof(ThreadArgs));
	ta->a_name = name;
	ta->a_argv[0] = (char*)func;
	for( ai = 0; ai < 7; ai++ )
		ta->a_argv[1+ai] = va[ai];

	if( ssize == 0 )
		ssize = STKSIZE;
	ta->a_saddr = 0;
	ta->a_ssize = ssize;
	pthread_attr_init(&ta->a_attr);

	/*
	pthread_attr_getstacksize(&ta->a_attr,&ssiz);
	pthread_attr_getstackaddr(&ta->a_attr,&sadr);
	*/
	pthread_attr_setstacksize(&ta->a_attr,ssize);
#if 0
	if( 1 ){
		ta->a_saddr = (char*)calloc(ssize/8,8);
		pthread_attr_setstack(&ta->a_attr,ta->a_saddr,ta->a_ssize);
	}
#endif
	err = pthread_create(&thread,&ta->a_attr,(void*(*)(void*))thread1,ta);
	if( err )
		porting_dbg("#### pthread_create() failed: %d",err);
	else{
	/*
	pthread_attr_getstacksize(&attr,&ssiz);
	pthread_attr_getstackaddr(&attr,&sadr);
	fprintf(stderr,"#### thread %X: ssize=%d saddr=%X\n",thread,ssiz,sadr);
	*/
	}
	if( main_tid == 0 ){
		main_tid = pthread_self();
		main_tid = (pthread_t)toTid((void*)main_tid,1);
	}
	tid = toTid((void*)thread,2);
	if( lTHREADLOG() ){
		syslog_ERROR("thread_fork() = %X %llX\n",tid,(FileSize)thread);
	}
	return tid;
	/*
	return toTid((void*)thread,1);
	*/
	/*
	return thread;
	*/
}

int SIZEOF_tid_t = sizeof(pthread_t);
static void thread0(){
}
int getThreadIds(FileSize *mtid,FileSize *ctid){
	int err;
	pthread_t tid = 0;
	ThreadArgs tab,*ta = &tab;

	bzero(ta,sizeof(ThreadArgs));
	pthread_attr_init(&ta->a_attr);
	err = pthread_create(&tid,&ta->a_attr,(void*(*)(void*))thread0,ta);
	*mtid = (FileSize)pthread_self();
	*ctid = (FileSize)tid;
	return sizeof(pthread_t);
}
static int thread_yield()
{
	return 0;
}
/*
static int thread_wait(pthread_t tid,int timeout){
*/
static int _Thread_wait(int tid,int timeout){
	pthread_t tha;
	int ser;
	int err;

	ser = 0;
	tha = (pthread_t)toThd(tid,0,&ser);
	if( ((void*)tha) == ((void*)-1) ){
		/* 9.9.4 MTSS dangling thread-id to the handle value -1 */
		putfLog("SIG dangling thread-id %X %d",tid,ser);
		porting_dbg("##TW BAD tid=%X %llX %d",tid,(FileSize)tha,ser);
		err = -1;
	}else
	err = pthread_join(tha,NULL);
	if( err == 0 ){
		toThd(tid,1,&ser);
	}else{
	}
	return err;
}
static void thread_exit(void *code){
	thread_done(code);
	pthread_exit(code);
}

static int _getthreadid(){
	pthread_t tid;
	int tidi;
	tid = pthread_self();
	tidi = toTid((void*)tid,3);
	if( tidi != (long long int)tid ){
		return tidi;
	}
	return ((long long int)tid) & 0xFFFFFFFF;
}
int (*ThreadId)() = _getthreadid;

const char *WithThread = "PThread";
/*
pthread_t (*ThreadFork)(int,const char*,IFUNCP,...) = thread_fork;
int (*ThreadWait)(int,int) = (int(*)(int,int))_Thread_wait;
*/
int (*ThreadFork)(int,const char*,IFUNCP,...) = thread_fork;
int (*ThreadWait)(int,int) = _Thread_wait;
int (*ThreadYield)() = thread_yield;
void (*ThreadExit)(void *code) = thread_exit;

static int thread_priority(int pri){
	struct sched_param param;
	int policy;
	int gs,ss,op,np,opol;

	gs = pthread_getschedparam(pthread_self(),&policy,&param);
opol = policy;
	op = param.sched_priority;
	param.sched_priority = pri;
	ss = pthread_setschedparam(pthread_self(),policy,&param);
	pthread_getschedparam(pthread_self(),&policy,&param);
	np = param.sched_priority;

fprintf(stderr,"######## thpri[%d] %d -> %d -> %d [%d %d] pol[%d]->[%d]\n",
xp2i(pthread_self()),op,pri,np, gs,ss,
opol,
//SCHED_RR
SCHED_FIFO
);
/* PTHREAD_MIN_PRIORITY,PTHREAD_MAX_PRIORITY); */

	return 0;
}
int (*ThreadPriority)(int) = thread_priority;
