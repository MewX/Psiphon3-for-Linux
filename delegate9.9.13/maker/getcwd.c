int SUBST_getcwd = 1;

#include <string.h>
#define MAXPATHLEN 1024
char *getwd(char*);

char *getcwd(char path[],int size)
{	char pathb[MAXPATHLEN];
	const char *rcode;

	if( size <= sizeof(pathb) )
		return getwd(path);
	else{
		rcode = getwd(pathb);
		strncpy(path,pathb,sizeof(pathb));
		return (char*)rcode;
	}
}
