#include "ystring.h"

#if defined(__hpux)
#include <sys/param.h>
#include <sys/pstat.h>
FileSize getSysinfo(const char *name){
	struct pst_static pst;
	struct pst_static dyn;

	if( pstat_getstatic(&pst,sizeof(pst),1,0) != 0 ){
		return -1;
	}
	if( strcmp(name,"totalmem") == 0 ){
		return pst.page_size * pst.physical_memory;
	}

	if( pstat_getdynamic(&dyn,sizeof(dyn),1,0) != 0 ){
		return -1;
	}
	if( strcmp(name,"freemem") == 0 ){
		return pst.page_size * dyn.psd_free;
	}
	return -1;
}
#endif
