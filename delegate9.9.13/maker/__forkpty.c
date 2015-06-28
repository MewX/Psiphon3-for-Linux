#include <stdio.h>

#ifdef __APPLE__
#include <util.h>
#else
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>
#if defined(__OpenBSD__) || defined(__NetBSD__)
#include <util.h>
#else
#include <libutil.h>
#endif
#endif

int _ForkptyX(int *pty,char *name,void *mode,void *size){
	int pid;
	pid = forkpty(pty,name,(struct termios*)mode,(struct winsize*)size);
	return pid;
}
int _Forkpty(int *pty,char *name){
	return _ForkptyX(pty,name,NULL,NULL);
}
