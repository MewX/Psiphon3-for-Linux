#include <stdio.h>
#include <stdlib.h>
#include "yalloca.h"
#include "ystring.h"

int alloca_call(AllocaArg *ap)
{	char *buff;
	int size;
	int rcode;
	void *bp;

	buff = (char*)alloca(ap->s_size * ap->s_unit);
	if( buff == NULL ){
		porting_dbg("#### FATAL: alloca_call() failed (no more stack)");
		exit(-1);
	}
	bp = addStrBuffer(ap->s_level,buff,ap->s_size*ap->s_unit);
	markStackBase(bp);

	if( ap->s_trace ){
		size = ap->s_sp0 - buff;
		porting_dbg("%s (%4d) = %5d [%08X - %08X]",
			ap->s_what,ap->s_size,size,p2i((char*)&ap),p2i(ap->s_sp0));
	}
	buff = 0;
	size = 0;
	rcode = (*ap->s_func)(ap->s_av[0],ap->s_av[1],ap->s_av[2],ap->s_av[3],
		ap->s_av[4],ap->s_av[5]);
	freeStrBuffer(ap->s_level,bp);
	return rcode;
}
int INHERENT_alloca(){ return 1; }
