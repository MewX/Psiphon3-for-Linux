#include "yselect.h" /* FD_SETSIZE */
#include <sys/time.h>
#include <sys/resource.h>

static int expand(const char *what,int op,int amax)
{	struct rlimit rl;
	int max = amax;
	int ocur;

	getrlimit(op,&rl);
	ocur = rl.rlim_cur;
	if( rl.rlim_cur < max ){
		if( rl.rlim_max < max )
			max = rl.rlim_max;
		rl.rlim_cur = max;
		rl.rlim_max = max;
		setrlimit(op,&rl);
		getrlimit(op,&rl);
	}
	/*
	porting_dbg("RLIMIT_%s = %d->%d/%d",what,ocur,rl.rlim_cur,rl.rlim_max);
	*/
	return rl.rlim_cur;
}

#ifdef RLIMIT_NOFILE
int expand_fdset(int amax)
{	struct rlimit rl;
	int max = amax;
	int ocur;

	getrlimit(RLIMIT_NOFILE,&rl);
	ocur = rl.rlim_cur;
	if( rl.rlim_cur < max ){
		if( rl.rlim_max < max )
			max = rl.rlim_max;
		rl.rlim_cur = max;
		rl.rlim_max = max;
		setrlimit(RLIMIT_NOFILE,&rl);
		getrlimit(RLIMIT_NOFILE,&rl);
	}
	return rl.rlim_cur;
}

#else

int expand_fdset(int amax)
{
	porting_dbg("FD_SETSIZE = %d",FD_SETSIZE);
	return FD_SETSIZE;
}
#endif

#ifdef RLIMIT_STACK
int expand_stack(int smax)
{
	return expand("STACK",RLIMIT_STACK,smax);
}
#else
int expand_stack(int smax)
{
	return -1;
}
#endif
