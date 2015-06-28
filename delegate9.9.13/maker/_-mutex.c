/*
 * if with pthread
 */
#include "ystring.h"
#include "log.h"
#include "sysconf.h"
#if defined(__cplusplus) && !defined(DG_WITH_PTHREAD) && !defined(__CYGWIN__)
#else
#include <pthread.h>
#endif

const char *WithMutex = "pthread";
typedef struct {
	int xcs_ok;
	int xcs_pid;
	int xcs_count;
	unsigned char xcs_flags;
	unsigned char xcs_retry;
	unsigned short xcs_timeout;
	const char *xcs_wh;
	pthread_mutex_t xcs_cs;
} XCS;

int sizeofCSC(){
	return sizeof(XCS);
}

extern int cnt_errorCSC;
extern int cnt_retryCSC;
extern int cnt_enterCSC;
extern int cnt_leaveCSC;
extern int cnt_errCSCpid;
extern const char *enterCSC_F;
extern int enterCSC_L;

int statsCSC(void *acs,int *count,int *retry,int *timeout){
	XCS *xcs = (XCS*)acs;
	*count = xcs->xcs_count;
	*retry = xcs->xcs_retry;
	*timeout = xcs->xcs_timeout;
	return 0;
}
int debugCSC(void *acs,int on){
	XCS *xcs = (XCS*)acs;
	int oon = xcs->xcs_flags;
	xcs->xcs_flags = on;
	return oon;
}

int uGetpid();
int setupCSC(const char *wh,void *acs,int asz){
	XCS *xcs = (XCS*)acs;
	int pid;

	if( asz < sizeof(XCS) ){
		/* Uname -> minit_uname -> Xcalloc -> doLock_FL -> setupCSC
		Uname(AVStr(uname));
		*/
		fprintf(stderr,"----setupCSC: too small %d/%d\n",
			asz,isizeof(XCS));
		return -1;
	}
	/* getpid() is not unique in threads of a process on LinuxThreads */
	pid = uGetpid();
	if( xcs->xcs_ok ){
		if( xcs->xcs_pid == pid ){
		return 0;
		}
		cnt_errCSCpid++;
	}
	xcs->xcs_ok = 1;
	xcs->xcs_wh = wh;
	xcs->xcs_pid = pid;
	xcs->xcs_count = 0;
	xcs->xcs_retry = 0;
	xcs->xcs_timeout = 0;
	pthread_mutex_init(&xcs->xcs_cs,0);
        return 0;
}   
#undef fprintf
/*
int enterCSCX(void **acs,int timeout){
*/
int enterCSCX_FL(FL_PAR,void *acs,int timeout){
	int cum,rem,to1;
	XCS *xcs = (XCS*)acs;
	if( xcs->xcs_ok <= 0 ){
		return -1;
	}
	if( xcs->xcs_pid != uGetpid() ){
		/* should setup here? */
		cnt_errCSCpid += 0x100;
		xcs->xcs_ok = 0;
		return -1;
	}
	enterCSC_F = FL_F;
	enterCSC_L = FL_L;
	cnt_enterCSC++;
	xcs->xcs_count++;
	for( cum = 0; cum <= timeout; cum += to1 ){
		if( pthread_mutex_trylock(&xcs->xcs_cs) == 0 ){
			if( xcs->xcs_flags ){
				putfLog("--enterCSC(%s,%d) OK (%d)",
					xcs->xcs_wh,timeout,cum);
			}
			return 0;
		}
		if( xcs->xcs_flags ){
			putfLog("--enterCSC(%s,%d) WA (%d)",
				xcs->xcs_wh,timeout,cum);
		}
		cnt_retryCSC++;
		xcs->xcs_retry++;
		rem = timeout - cum;
		if( rem <= 0 ){
			break;
		}
		if(   10 <= rem && cum <=  100 ) to1 =  10; else
		if(  100 <= rem && cum <= 1000 ) to1 = 100; else
		if(  500 <= rem && cum <= 5000 ) to1 = 500; else
		if( 1000 <= rem )
			to1 = 1000;
		else	to1 = rem;
		/* this usleep() might be interrupted */
		usleep(to1*1000);
	}
	if( xcs->xcs_flags ){
		putfLog("--enterCSC(%s,%d) NG (%d)",
			xcs->xcs_wh,timeout,cum);
	}
	xcs->xcs_timeout++;
	cnt_errorCSC += 0x100;
	return -1;
}
/*
int enterCSC(void **acs){
*/
int enterCSC_FL(FL_PAR,void *acs){
	XCS *xcs = (XCS*)acs;
	if( xcs->xcs_ok <= 0 ){
		return -1;
	}
	if( xcs->xcs_pid != uGetpid() ){
		/* should setup here? */
		cnt_errCSCpid += 0x10000;
		xcs->xcs_ok = 0;
		return -1;
	}
	enterCSC_F = FL_F;
	enterCSC_L = FL_L;
	cnt_enterCSC++;
	xcs->xcs_count++;
	if( pthread_mutex_trylock(&xcs->xcs_cs) == 0 ){
		return 0;
	}
	if( pthread_mutex_lock(&xcs->xcs_cs) == 0 )
		return 0;
	cnt_errorCSC += 0x10000;
        return -1;
}
int leaveCSC_FL(FL_PAR,void *acs){
	XCS *xcs = (XCS*)acs;
	if( xcs->xcs_ok <= 0 ){
		return -1;
	}
	if( xcs->xcs_pid != uGetpid() ){
		/* should setup here? */
		cnt_errCSCpid += 0x1000000;
		xcs->xcs_ok = 0;
		return -1;
	}
	enterCSC_F = 0;
	enterCSC_L = 0;
	cnt_leaveCSC++;
	if( pthread_mutex_unlock(&xcs->xcs_cs) == 0 )
	{
		if( xcs->xcs_flags ){
			putfLog("--leaveCSC(%s) OK",xcs->xcs_wh);
		}
		return 0;
	}
	if( xcs->xcs_flags ){
		putfLog("--leaveCSC(%s) NG",xcs->xcs_wh);
	}
	xcs->xcs_timeout++;
	cnt_errorCSC += 0x1000000;
	return -1;
}
