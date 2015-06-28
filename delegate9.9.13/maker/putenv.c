int SUBST_putenv = 1; /* int putenv(char*); */

#include <stdio.h>
#include <string.h>

extern char **environ;
static char **my_environ;
void *malloc(int);
void free(void*);

int putenv(void *venv)
{	const char *env = (char*)venv;
	char name[256];
	int ei,len;
	const char *ep;
	const char **newe;

	sscanf(env,"%256[^=]",name);
	len = strlen(name);
	for( ei = 0; ep = environ[ei]; ei++ )
		if( strncmp(ep,name,len) == 0 ){
			environ[ei] = (char*)env;
			return 0;
		}

	newe = (const char**)malloc(sizeof(char*)*(ei+2));
	for( ei = 0; environ[ei]; ei++ )
		newe[ei] = (const char*)environ[ei];
	newe[ei] = env;
	newe[ei+1] = 0;
	if( environ == my_environ )
		free(environ);
	environ = my_environ = (char**)newe;
	return 0;
}
