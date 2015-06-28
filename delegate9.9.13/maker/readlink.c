int SUBST_readlink = 1;

#include <errno.h>
int readlink(const char *path,char xpath[],int xplen)
{
	errno = EINVAL;
	return -1;
}
