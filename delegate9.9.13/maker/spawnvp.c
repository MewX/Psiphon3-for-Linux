int SUBST_spawnvp = 1;

int _spawnvp(int pmode,const char *path,const char *const argv[]);
int spawnvp(int pmode,const char *path,const char *const argv[])
{
	return _spawnvp(pmode,path,argv);
}
