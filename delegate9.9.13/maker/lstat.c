int SUBST_lstat = 1;
int INHERENT_lstat(){ return 0; }

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

int stat(const char *path, struct stat *st);
int porting_dbg(const char *fmt,...);

int lstat(const char *path,struct stat *st)
{	int rcode;

	rcode = stat(path,st);
	porting_dbg("*** lstat() = %d, substituted by stat().",path,rcode);
	return rcode;
}

int _stati64(const char *path, struct _stati64 *st);
__int64 lstati64(const char *path,struct _stati64 *st){
	int rcode;

	rcode = _stati64(path,st);
	porting_dbg("*** lstat() = %d, substituted by stat().",path,rcode);
	return rcode;
}
