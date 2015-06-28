#include <stdio.h>
#include "fpoll.h"

int ready_cc(FILE *fp)
{
	if( fp == NULL )
		return 0;
	else	return READYCC(fp);
}
int ready_CC(FILE *fp)
{	int rcc;

	rcc = READYCC(fp);
	if( 0 < rcc )
		return rcc;
	else	return 0;
}

