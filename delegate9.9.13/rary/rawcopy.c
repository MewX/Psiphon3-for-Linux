/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999 Yutaka Sato
Copyright (c) 1999 Electrotechnical Laboratry (ETL), AIST, MITI

Permission to use, copy, and distribute this material for any purpose
and without fee is hereby granted, provided that the above copyright
notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	randstack.c (randomize stack base)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	020216	extracted from randstack.c and String.c
	041020	added BOUNDS_CHECKING_OFF
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"

#ifndef BOUNDS_CHECKING_OFF
#if defined(__GNUC__) && defined(__BOUNDS_CHECKING_ON)
extern int __bounds_debug_no_checking;
#define BOUNDS_CHECKING_OFF do { __bounds_debug_no_checking = 1;} while(0)
#define BOUNDS_CHECKING_ON  do { __bounds_debug_no_checking = 0;} while(0)
#endif
#endif
#ifndef BOUNDS_CHECKING_OFF
#define BOUNDS_CHECKING_OFF
#define BOUNDS_CHECKING_ON
#endif

void stackcopy(char *av[],int ac,char *asT,char *esT,char **areap,int *lengp,int *sizep)
{	const char *a0T;
	char *as;
	char *es;
	int ai,offs;
	int asiz;

	BOUNDS_CHECKING_OFF;
	if( ac <= 1 ){
		a0T = esT;
	}else{
		/* move ex-argv[1-] to the end of ex-environ area */
/*
		for( as = asT,es = esT; as && av[1] <= as; )
			*es-- = *as--;
		a0T = es + 1;
*/
		asiz = asT - av[1];
		as = asT - asiz;
		es = esT - asiz;
		Xmemmove(ZVStr(es,asiz+1),as,asiz+1);
		a0T = es;

		/* adjust ex-argv[1-] pointers */
		offs = esT - asT;
		for( ai = 1; ai < ac; ai++ )
			av[ai] += offs;

		/* clear ex-argv[1-] buffers (might be optional) */
		{
			for( ai = 1; ai < ac; ai++ )
				for( as = av[ai]; *as; as++ )
					*as = ' ';
		}
	}

	/*
	 * clear extended argv[0] area
	 */
	as = &av[0][strlen(av[0])]+1;
	memset(as,' ',a0T-as);
/*
	for( as = &av[0][strlen(av[0])]+1; as < a0T; as++ )
		*as = ' ';
*/

	if( areap ){
		*areap = av[0];
		*lengp = asT - av[0];
		*sizep = a0T - av[0];
	}
	BOUNDS_CHECKING_ON;
}

char *raw_Strncpy(PVStr(s1),PCStr(s2),int n)
{	refQStr(dp,s1); /**/

	BOUNDS_CHECKING_OFF;
	dp = s1;
	while( 1 < n-- ){
		int ch;
		ch = *s2++;
		setVStrPtrInc(dp,ch);
		if( ch == 0 )
			break;
	}
	setVStrEnd(dp,0);
	BOUNDS_CHECKING_ON;
	return (char*)s1;
}

void Strrplc(PVStr(str),int lendel,PCStr(ins))
{	int lenstr,lenins;

	BOUNDS_CHECKING_OFF;
	lenins = strlen(ins);
	lenstr = strlen(str);
	if( lendel != lenins ){
		Xmemmove(UVStr(str) str+lenins,str+lendel,lenstr-lendel+1);
	}
	if( lenins != 0 ){
		Xmemmove(UVStr(str) str,ins,lenins);
	}
	BOUNDS_CHECKING_ON;
}

void uvinit(UTag *tagv[],UTag tagvb[],int nelem)
{	int ui;

	BOUNDS_CHECKING_OFF;
	for( ui = 0; ui < nelem; ui++ ){
		tagv[ui] = &tagvb[ui];
		bzero(tagv[ui],sizeof(UTag));
	}
	tagv[ui] = 0;
	BOUNDS_CHECKING_ON;
}
