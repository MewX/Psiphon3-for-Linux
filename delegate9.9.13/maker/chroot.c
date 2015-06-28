int SUBST_chroot = 1;

int porting_dbg(const char *fmt,...);
int chroot(const char *path)
{
	porting_dbg("chroot(%s) not supported",path);
	return -1;
}
