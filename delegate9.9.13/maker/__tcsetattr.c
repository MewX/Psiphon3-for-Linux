#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <errno.h>

const char *SttyType(){
	return "tcsetattr";
}
int isinListX(const char *list,const char *elem,const char *nocase);
int Stty(int fd,const char *mode){
	struct termios ta;
	errno = 0;
	if( tcgetattr(fd,&ta) != 0 ){
		return -2;
	}
	if( isinListX(mode,"-echo","c")  ) ta.c_lflag &= ~(ECHO|ECHONL);
	if( isinListX(mode,"echo","c")   ) ta.c_lflag |=  ECHO;
	if( isinListX(mode,"-icanon","c")) ta.c_lflag &= ~ICANON;
	if( isinListX(mode,"icanon","c") ) ta.c_lflag |=  ICANON;
	if( isinListX(mode,"echonl","c") ) ta.c_lflag |=  ECHONL;
	if( isinListX(mode,"icrnl","c")  ) ta.c_iflag |=  ICRNL;
	if( isinListX(mode,"igncr","c")  ) ta.c_iflag |=  IGNCR;
	if( isinListX(mode,"onlcr","c")  ) ta.c_oflag |=  ONLCR;
	if( isinListX(mode,"ocrnl","c")  ) ta.c_oflag |=  OCRNL;
	tcsetattr(fd,TCSANOW,&ta);
	return 0;
}
int Gtty(int fd,const char *mode){
	struct termios ta;
	errno = 0;
	if( tcgetattr(fd,&ta) != 0 ){
		return -2;
	}
	if( isinListX(mode,"all","c") ){
		return (ta.c_iflag << 16) | ta.c_lflag;
	}
	if( isinListX(mode,"iflags","c") ) return ta.c_iflag;
	if( isinListX(mode,"oflags","c") ) return ta.c_oflag;
	if( isinListX(mode,"lflags","c") ) return ta.c_lflag;
	if( isinListX(mode,"cflags","c") ) return ta.c_cflag;
	if( isinListX(mode,"echo","c") ){
		return ta.c_lflag & (ECHO|ECHONL);
	}
	return 0;
}
