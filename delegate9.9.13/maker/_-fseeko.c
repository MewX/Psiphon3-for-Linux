#ifdef __osf__
OSF/1 does not have it, but -DNONCPLUS lets this file be compled successfully
#endif

#include "ystring.h"

int Fseeko(FILE *fp,FileSize off,int whence){
	return fseeko(fp,off,whence);
}
FileSize Ftello(FILE *fp){
	return ftello(fp);
}
