#ifdef __cplusplus
extern "C" {
#endif
#ifndef RETYPE
#define RETYPE void
#endif

extern char **environ;
#include <string.h>
RETYPE unsetenv(const char *name){
	int ei = 0;
	int eo = 0;
	int el = 0;
	char *e1;

	el = strlen(name);
	eo = 0;
	for( ei = 0; e1 = environ[ei]; ei++ ){
		if( strncmp(e1,name,el) == 0 && e1[el] == '=' ){
			continue;
		}
		environ[eo++] = e1;
	}
	environ[eo] = 0;
}

#ifdef __cplusplus
}
#endif
