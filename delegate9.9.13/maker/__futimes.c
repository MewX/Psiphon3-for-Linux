#include <sys/types.h>
#include <sys/syscall.h> 
#ifndef SYS_futimes
futimes() is unavailable and might be a stab on Linux.
#endif

#include <sys/time.h>

int INHERENT_futimes(){ return 1; }
int Futimes(int fd,int as,int au,int ms,int mu){
	struct timeval tv[2];
	tv[0].tv_sec = as;
	tv[0].tv_usec = au;
	tv[1].tv_sec = ms;
	tv[1].tv_usec = mu;
	return futimes(fd,tv);
}
