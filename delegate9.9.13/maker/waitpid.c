int SUBST_wiatpid = 1;

int wait4(int,int*,int,void*);
int waitpid(int pid,int *statp,int opts)
{
	return wait4(pid,statp,opts,(void*)0);
}
