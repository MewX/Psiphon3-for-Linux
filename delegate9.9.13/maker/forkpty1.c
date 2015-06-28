/* maybe Solaris */
#include <stdlib.h> 
#include <string.h> 
#include <unistd.h> 
#include <fcntl.h> 
#include <sys/stropts.h> 

int _ForkptyX(int *amaster,char *name,void *mode,void *size){
	int msfd = -1;
	char *slname; 
	pid_t pid; 

	if( (msfd = open("/dev/ptmx",2)) < 0 ) goto EXIT;
	if( grantpt(msfd)  < 0 ) goto EXIT;
	if( unlockpt(msfd) < 0 ) goto EXIT;
	if( (slname = ptsname(msfd)) == NULL ) goto EXIT;
	if( (pid = fork()) < 0 ) goto EXIT;

	if( name ) strcpy(name,slname); 
	if( pid == 0 ){
		int slfd; 
		close(msfd); 
		setsid();
		slfd = open(slname,2); 
		if( ioctl(slfd,I_PUSH,"ptem") < 0
		 || ioctl(slfd,I_PUSH,"ldterm") < 0 ){
			return -1; 
		} 
		dup2(slfd,0); dup2(slfd,1); dup2(slfd,2); 
		close(slfd);
		if( amaster ) *amaster = -1;
		return 0;
	}else{
		/*
		ioctl(msfd,I_PUSH,"ptem"); // to enable tcsetattr() ...
		*/
		if( amaster ) *amaster = msfd; 
		return pid; 
	} 
EXIT:
	if( 0 <= msfd ) close(msfd);
	return -1;
}
int _Forkpty(int *amaster,char *name){
	return _ForkptyX(amaster,name,0,0);
}
