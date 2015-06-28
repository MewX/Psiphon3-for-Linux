int SUBST_link = 1;
int INHERENT_link(){ return 0; }

#include <stdio.h>

int porting_dbg(const char *fmt,...);
int link(const char *path1,const char *path2)
{
	porting_dbg("*** link(%s,%s) is not available.",path1,path2);
	return -1;
}
