#include <sys/sysinfo.h>
#include "ystring.h"

FileSize getSysinfo(const char *name){
	struct sysinfo info;
	if( sysinfo(&info) != 0 ){
		return -1;
	}
	if( strcmp(name,"totalmem") == 0 ){
		return ((FileSize)info.totalram) * info.mem_unit;
	}
	if( strcmp(name,"freemem") == 0 ){
		return ((FileSize)info.freeram) * info.mem_unit;
	}
	return -1;
}
