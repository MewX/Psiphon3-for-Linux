int SUBST_sigmask = 1;

int sigmask(int n)
{
	return 1 << ((n)-1);
}
