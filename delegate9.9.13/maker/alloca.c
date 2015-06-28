#include <stdio.h>
#include "yalloca.h"
int porting_dbg(const char *fmt,...);

int alloca_call(AllocaArg *ap)
{	char buff[STACK1];
	int size;

	if( 0 < ap->s_count-- )
		return alloca_call(ap);
	else{
		if( ap->s_trace ){
			size = ap->s_sp0 - (char*)&ap;
			porting_dbg("%s (%4d) = %5d [%08lX - %08lX]",
			ap->s_what,ap->s_size,size,(char*)&ap,ap->s_sp0);
		}
		return (*ap->s_func)(ap->s_av[0],ap->s_av[1],
			ap->s_av[2],ap->s_av[3],ap->s_av[4],ap->s_av[5]);
	}
}
int INHERENT_alloca(){ return 0; }
