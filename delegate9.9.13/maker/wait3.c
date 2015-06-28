int SUBST_wait3 = 1;

int waitpid(int,int*,int);
int wait3(int *statusp,int options,void *rusage)
{
	return waitpid(-1, statusp, options);
}
