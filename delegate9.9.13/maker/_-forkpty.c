/* maybe in Linux */
#include <stdio.h>
#include <pty.h>
#include <utmp.h>
int _ForkptyX(int *pty,char *name,void *mode,void *size){
	int pid;
	pid = forkpty(pty,name,(struct termios*)mode,(struct winsize*)size);
	return pid;
}
int _Forkpty(int *pty,char *name){
	return _ForkptyX(pty,name,0,0);
}

