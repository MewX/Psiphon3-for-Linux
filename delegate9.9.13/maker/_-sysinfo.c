#if defined(__osf__)
/*
 * long sysinfo(int command,char *buf,long count);
 */
#include <sys/systeminfo.h>
#include "ystring.h"
FileSize getSysinfo(const char *name){
	char buf[256];
	if( sysinfo(SI_SYSNAME,buf,sizeof(buf)) != 0 ){
		return -1;
	}
	if( strcmp(name,"totalmem") == 0 ){
		return -1;
	}
	if( strcmp(name,"freemem") == 0 ){
		return -1;
	}
	return -1;
}
#endif
