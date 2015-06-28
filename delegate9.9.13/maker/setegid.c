int SUBST_setegid = 1;

#if defined(__hpux__)
#include <unistd.h>
#else
int setresgid(int,int,int);
#endif

int setegid(int gid)
{
	return setresgid(-1,gid,-1);
}
