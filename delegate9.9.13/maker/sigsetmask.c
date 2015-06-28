#include <signal.h>

#ifdef SIG_SETMASK
int SUBST_sigsetmask = 1; /* sigsetmask(int mask); */

static void int2set(int mask,sigset_t *setp)
{	int i;

	sigemptyset(setp);
	for(i = 0; i < sizeof(int)*8; i++)
		if( mask & (1 << i) )
			sigaddset(setp,i+1);
}
static int set2int(sigset_t *setp)
{	int mask,i;

	mask = 0;
	for(i = 0; i < sizeof(int)*8; i++)
		if( sigismember(setp,i+1) )
			mask |= (1 << i);
	return mask;
}

int sigsetmask(int mask)
{	sigset_t set,oset;

	int2set(mask,&set);
	oset = set;
	sigprocmask( SIG_SETMASK, &set, &oset);
	return set2int(&oset);
}
int sigblock(int mask)
{	sigset_t set,oset;

	int2set(mask,&set);
	oset = set;
	sigprocmask( SIG_BLOCK, &set, &oset);
	return set2int(&oset);
}
#else
static int dummy;
#endif
