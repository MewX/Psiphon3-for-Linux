int SUBST_vfork = 1;

int fork();
int vfork(){
	return fork();
}
