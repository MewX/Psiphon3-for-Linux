#include <sys/ioctl.h>
#include <fcntl.h>

#ifdef sun
#include <sys/termios.h>
#ifdef __cplusplus
extern "C" { int ioctl(int fildes, int request,...); }
#endif
#endif

int getwinsize(int fd,int *row,int *col){
	struct winsize ws;
	if( ioctl(fd,TIOCGWINSZ,&ws) == 0 ){
		if( row ) *row = ws.ws_row;
		if( col ) *col = ws.ws_col;
		return 0;
	}else{
		return -1;
	}
}
int setwinsize(int fd,int row,int col){
	struct winsize ws;
	ws.ws_row = row;
	ws.ws_col = col;
	if( ioctl(fd,TIOCSWINSZ,&ws) == 0 ){
		return 0;
	}else{
		return -1;
	}
}
