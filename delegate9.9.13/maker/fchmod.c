int SUBST_fchmod = 1;
int INHERENT_fchmod(){ return 0; }

#include <stdio.h>
int porting_dbg(const char *fmt,...);
int fchmod(int fd,int mode)
{
	porting_dbg("fchmod(%d,%x) not available.",fd,mode);
	return -1;
}

