/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies, and
that the name of ETL not be used in advertising or publicity pertaining
to this material without the specific, prior written permission of an
authorized representative of ETL.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	bsort.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960531	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include <stdlib.h>

void Bsort(char base[],int nel,int width,int (*compar)(const char*,const char*))
{	int sx,dx,di,max;
	const char **srcp;
	defQStr(srcb); /*alloc*//**/

	srcp = (const char**)malloc(nel*sizeof(char*));
	setQStr(srcb,(char*)malloc(nel*width),nel*width);
	Bcopy(base,srcb,nel*width);

	for( sx = 0; sx < nel; sx++ )
		srcp[sx] = &srcb[sx*width];

	for( dx = 0; dx < nel; dx++ ){
		max = -1;
		for( di = 0; di < nel; di++ ){
			if( srcp[di] != 0L ){
				if( max == -1 )
					max = di;
				else
				if( 0 < (*compar)(srcp[max],srcp[di]) )
					max = di;
			}
		}
		bcopy(srcp[max],&base[dx*width],width);
		srcp[max] = 0L;
	}

	free(srcp);
	free((char*)srcb);
}
