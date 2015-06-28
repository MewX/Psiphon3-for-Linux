int SUBST_symlink = 1;

int WITH_symlink(){ return 0; }
int symlink(const char *path1,const char *path2)
{
	return -1;
}
