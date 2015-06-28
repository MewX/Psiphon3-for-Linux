#include <stdlib.h>

#if defined(__APPLE__)
#ifdef __cplusplus
extern "C" {
#endif
int malloc_size(void *p);
#ifdef __cplusplus
}
#endif
#endif

int mallocSize(void *p){
	return malloc_size(p);
}
