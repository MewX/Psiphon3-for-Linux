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
#include <signal.h>

/* no pthread_kill() on Solaris10 ? */

extern pthread_t main_tid;
/*
 * 64bits FedoraCore has 64bits pthread_t
 * but only the main-thread has an ID longer than sizeof(int)
 */
const void *toThd(int tid,int del,int *ser);

static int _Thread_kill(unsigned int tidi,int sig){
	pthread_t tid;
	/*
	tid = (pthread_t)tidi;
	*/
	int ser;
	tid = (pthread_t)toThd(tidi,0,&ser);
	if( sizeof(int) < sizeof(pthread_t) ){
		if( (long long int)tid == (((long long int)main_tid) & 0xFFFFFFFF) ){
			tid = main_tid;
		}
	}
	if( sig == 999 ){
		/* must do this because the thread to be killed cannot do it */
		int thread_doneX(int tid,void *xcode);
		thread_doneX(tidi,0);
		return pthread_cancel(tid);
	}
	return pthread_kill(tid,sig);
}
int (*ThreadKill)(int,int) = (int(*)(int,int))_Thread_kill;

static int thread_destroy(unsigned int tidi){
	return _Thread_kill(tidi,999);
}
int (*ThreadDestroy)(int) = (int(*)(int))thread_destroy;

static int thread_sigmask(const char *show,SigMaskInt nmaski,SigMaskInt *omaski){
	int how = 0;
	int mi;
	sigset_t nmask,omask;
	int rcode;

	sigemptyset(&nmask);
	for( mi = 1; mi < sizeof(nmaski)*8; mi++ ){
		if( nmaski & sigmask(mi) ){
			sigaddset(&nmask,mi);
		}
	}
	switch( *show ){
		case 'g': case 'G': how = SIG_UNBLOCK; sigemptyset(&nmask); break;
		case 'b': case 'B': how = SIG_BLOCK;  break;
		case 'u': case 'U': how = SIG_UNBLOCK; break;
		case 's': case 'S': how = SIG_SETMASK; break;
	}
	rcode = pthread_sigmask(how,&nmask,&omask);
	if( omaski ){
		*omaski = 0;
		for( mi = 1; mi < sizeof(*omaski)*8; mi++ ){
			if( sigismember(&omask,mi) ){
				*omaski |= sigmask(mi);
			}
		}
	}
	return rcode;
}
int (*ThreadSigmask)(const char *show,SigMaskInt nmaski,SigMaskInt *omaski) = thread_sigmask;
