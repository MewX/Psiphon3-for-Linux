int SUBST_utimes = 1;
int INHERENT_utimes(){ return 0; }

#include <sys/types.h>
#include <utime.h>
int utime(char*,void*);

int utimes(char file[],struct timeval *tvp)
{	struct utimbuf times;

	if( tvp ){
		times.actime  = tvp[0].tv_sec;
		times.modtime = tvp[1].tv_sec;
		return utime(file,&times);
	}else	return utime(file,(void*)0);
}
