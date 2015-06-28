/* old RedHat has sysctl() but without sysctlbyname() */
#include <sys/types.h>
int sysctlbyname(int *nm,unsigned int nml,void *op,size_t *ol,void *np,size_t nl){
	return -1;
}
