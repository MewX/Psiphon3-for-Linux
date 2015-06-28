#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
int porting_dbg(const char *fmt,...);
int getNullFd(const char *what);

int setferror(const char *F,int L,FILE *fp){
	int fd,sfd,nfd;

	sfd = nfd = -1;
	fd = fileno(fp);
	sfd = dup(fd);
	nfd = getNullFd("Setferror");
	dup2(nfd,fd);
	fputc(0,fp);
	fflush(fp);
	dup2(sfd,fd);
	close(sfd);
	porting_dbg("## Setferror(%X/%d,%d,%d)%X %s:%d",fp,fd,
		sfd,nfd,ferror(fp),F,L);
	return 0;
}
