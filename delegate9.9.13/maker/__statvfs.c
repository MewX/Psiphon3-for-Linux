#include <sys/types.h>
#include <sys/statvfs.h>
#include <string.h>

int Fstype(const char *path,char type[])
{	struct statvfs buf;

	if( statvfs(path,&buf) == 0 ){
		memcpy(type,buf.f_basetype,strlen(buf.f_basetype)+1);
		return 0;
	}
	*type = 0;
	return -1;
}
