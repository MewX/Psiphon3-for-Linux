#include "ystring.h"

int Fseeko(FILE *fp,FileSize off,int whence){
	return fseek(fp,(int)off,whence);
}
FileSize Ftello(FILE *fp){
	return ftell(fp);
}
