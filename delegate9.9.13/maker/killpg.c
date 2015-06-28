int SUBST_killpg = 1;

int kill(int,int sig);
int killpg(int gid,int sig)
{
	return kill(-gid,sig);
}
