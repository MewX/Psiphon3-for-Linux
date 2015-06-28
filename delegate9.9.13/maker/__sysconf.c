#include "ystring.h"
#include <unistd.h>
/* Solaris */

FileSize getSysinfo(const char *name){
	if( strcmp(name,"totalmem") == 0 ){
		return ((FileSize)sysconf(_SC_PAGESIZE))
			* sysconf(_SC_PHYS_PAGES);
	}
	if( strcmp(name,"freemem") == 0 ){
		return ((FileSize)sysconf(_SC_PAGESIZE))
			* sysconf(_SC_AVPHYS_PAGES);
	}
	return -1;
}
