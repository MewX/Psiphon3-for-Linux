#include "ystring.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>

FileSize getSysctl(const char *name){
	int old4;
	FileSize old8;
	size_t olen,nlen;

	olen = sizeof(old4);
	old4 = 0;
	if( sysctlbyname(name,&old4,&olen,NULL,0) == 0 ){
		return ((FileSize)old4) & 0xFFFFFFFF;
	}
	if( errno == ENOMEM ){
		old8 = 0;
		olen = sizeof(old8);
		if( sysctlbyname(name,&old8,&olen,NULL,0) == 0 ){
			return old8;
		}
	}
	return -1;
}

/*
int main(int ac,char *av[]){
	int msize;
	getSysctl("hw.ncpu");
	getSysctl("hw.usermem");
	getSysctl("hw.memsize");
	return 0;
}
*/
