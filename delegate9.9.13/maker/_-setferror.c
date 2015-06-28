#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
int getNullFd(const char *what);

int setferror(const char *F,int L,FILE *fp){
	int fd,sfd,nfd;

	sfd = nfd = -1;
	fd = fileno(fp);
#if defined(_IOERR)
	fp->_flag |= _IOERR;
#else
#if defined(_IO_ERR_SEEN)
	fp->_flags |= _IO_ERR_SEEN;
#else
#if defined(__SERR)
	fp->_flags |= __SERR;
#else
	sfd = dup(fd);
	nfd = getNullFd("Setferror");
	dup2(nfd,fd);
	fputc(0,fp);
	fflush(fp);
	dup2(sfd,fd);
	close(sfd);
#endif
#endif
#endif
	porting_dbg("## Setferror(%X/%d,%d,%d)%X %s:%d",p2i(fp),fd,
		sfd,nfd,ferror(fp),F,L);
	return 0;
}
