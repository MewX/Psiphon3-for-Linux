int SUBST_fchown = 1;
int INHERENT_fchown(){ return 0; }

#include <stdio.h>
int porting_dbg(const char *fmt,...);
int fchown(int fd,int uid,int gid)
{	int rcode;

	if( uid == 0 && gid == 0 )
		rcode = 0; 
	else	rcode = -1;
	porting_dbg("fchown(%d,%d,%d) = %d",fd,uid,gid,rcode);
	return rcode;
}
