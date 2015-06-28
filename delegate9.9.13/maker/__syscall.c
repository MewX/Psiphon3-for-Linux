#include <sys/types.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>

int INHERENT_syscall(){ return 1; }
int pop_fd(int fd,int rw);
int top_fd(int fd,int rw);
int porting_dbg(const char *fmt,...);
int PollIn1(int fd,int timeout);
int get_writelimit(int,int);

static int inread;
static int inwrite;

#ifdef __cplusplus
extern "C" {
int syscall(int number, ...);
#endif

int read(int fd,void *buf,int siz)
{	int rcc;

	rcc = syscall(SYS_read,fd,buf,siz);
	inread++;
	if( rcc <= 0 ){
		if( 0 <= pop_fd(fd,0) ){
if( inread <= 1 ) porting_dbg("pop_fd read(%d)",fd);
			if( 0 < PollIn1(fd,100) ){
				rcc = syscall(SYS_read,fd,buf,siz);
			}else{
				rcc = -1;
				errno = EAGAIN;
			}
if( inread <= 1 ) porting_dbg("pop_fd read(%d) = %d",fd,rcc);
		}
	}
	inread--;
	return rcc;
}
int write(int fd,const void *buf,int siz)
{	int wcc;
	void (*osig)(int);

/*
	if( inwrite == 0 )
		siz = get_writelimit(fd,siz);
*/

	if( inwrite || top_fd(fd,1) < 0 )
		return syscall(SYS_write,fd,buf,siz);

	osig = signal(SIGPIPE,SIG_IGN);
	wcc = syscall(SYS_write,fd,buf,siz);
	signal(SIGPIPE,osig);

	if( wcc < 0 ){
		if( 0 <= pop_fd(fd,1) ){
			wcc = syscall(SYS_write,fd,buf,siz);
inwrite++;
if( inwrite <= 1 ) porting_dbg("pop_fd write(%d) = %d",fd,wcc);
inwrite--;
		}else{
			if( osig != SIG_IGN ){
				/* cuase SIGPIPE */
				wcc = syscall(SYS_write,fd,buf,siz);
			}
		}
	}
	return wcc;
}
#ifdef __cplusplus
}
#endif

/*
static int inclose;
close(fd){
	int rcode;
	rcode = syscall(SYS_close,fd);
inclose++;
if( inclose <= 1 ) porting_dbg("close(%d)=%d",fd,rcode);
inclose--;
	return rcode;
}
*/
