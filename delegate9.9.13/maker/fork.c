int SUBST_fork = 1;
int _INHERENT_fork(){ return 0; }
int INHERENT_fork(){ return 0; }

#include <stdio.h>
#include <stdlib.h>
int WAIT_WNOHANG = -1;

/*
int porting_dbg(const char *fmt,...);
int fork(){
	porting_dbg("*** fork() is not available.");
	exit(1);
	return -1;
}
*/
