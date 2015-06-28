int SUBST_getwd = 1;

#define MAXPATHLEN 1024
char *getcwd(char*,int);

char *getwd(char path[])
{
	return getcwd(path,MAXPATHLEN);
}
