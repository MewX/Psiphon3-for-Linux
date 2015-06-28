#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

int _spawnvp(int pmode,const char *path,const char *const argv[])
{	int pid;

	if( pid = fork() ){
		/*
		if( pmode == P_WAIT || pmode == P_WAITO )
			wait(0);
		*/
		return pid;
	}
	execvp(path,(char*const*const)argv);
	exit(-1);
	return -1;
}
