#include <errno.h>
const char *SttyType(){
        return "none";
}
int Stty(int fd,const char *mode){
	errno = 0;
	return -1;
}
int Gtty(int fd,const char *mode){
	return -1;
}

