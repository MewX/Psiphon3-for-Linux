#include <sys/param.h>
#include <sys/stat.h>

int Mkfifo(const char *path,int mode){
	return mkfifo(path,mode);
}
