#include "ystring.h"
#if defined(__KURO_BOX__)
#define dlopen  __dlopen
#define dlsym   __dlsym
#define dlerror __dlerror
#define dlclose __dlclose
#endif
int porting_dbg(const char *fmt,...);

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
void *dlopen(const char *path,int mode){
	porting_dbg("dlopen(%s) not supported",path);
	return NULL;
}
void *dlsym(void *handle,const char *symbol){
	return NULL;
}
const char *dlerror(void){
	return "(dl NOT SUPPORTED)";
}
int dlclose(void *handle){
	return -1;
}
#ifdef __cplusplus
}
#endif
