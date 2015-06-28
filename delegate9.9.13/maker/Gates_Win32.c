#include "ystring.h"

int validateLicense(PCStr(path),PCStr(date)){
	fprintf(stderr,"---- ---- ---- NO LICENSE TO RUN AS A SERVICE\n");
	fprintf(stderr,"---- ---- ---- %s\n",path);
	return -1;
}
int putServiceArgs(PCStr(execpath),PCStr(servname),int ac,const char *av[]){
	validateLicense(execpath,__DATE__);
	return -1;
}
int getServiceArgsX(int argc,char *argv[],const char *av[],int an){
	validateLicense(argv[0],__DATE__);
	return -1;
}
int getImpKey(PCStr(exec),PVStr(ekey)){
	return -1;
}
int putImpKey(PCStr(exec),PCStr(ekey)){
	return -1;
}
