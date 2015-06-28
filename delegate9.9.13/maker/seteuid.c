int SUBST_seteuid = 1;

#if defined(__hpux__)
#include <unistd.h>
#else
int setresuid(int,int,int);
#endif

int seteuid(int uid)
{
	return setresuid(-1,uid,-1);
}
