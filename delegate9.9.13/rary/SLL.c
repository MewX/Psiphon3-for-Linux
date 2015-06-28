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
Program:	SLL.c (Simple LL parser)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	940320	created
//////////////////////////////////////////////////////////////////////#*/

#include "ystring.h"
#include <stdio.h>
#include "SLL.h"
#define DEBUG 0
char SLL_OTHERWISE[] = {0};
#define OTHERWISE SLL_OTHERWISE

int SLLparse(int lev,SLLRule *prp,PCStr(srca),const char **nsrcp,putvFunc putv,PVStr(vala),int size,char **nvalp)
{
	SLLRule *crp;
	const char *src;
	int si;
	int glen;	/* read lenght */
	int ch;
	const char *type;
	const char *name;
	const char *gate;
	int flag;
	int match;
	refQStr(val,vala);
	int error;
	int slen,rsize;
	int nmatch;

	src = srca;
	flag = prp[0].r_flag;

	if( (flag & ISALT) != 0 )
		type = "ALT";
	else	type = "SEQ";

	name = prp[0].r_name;

if( DEBUG )
printf("%2d [%s] %-10s: %s\n", lev, type, name, src);

	nmatch = 0;
	for( si = 1; prp[si].r_name; si++ ){
		crp = &prp[si];

		if( crp->r_flag & CHARSET ){
			if( ch = *src ){
				glen = 1;
				match = strchr(crp->r_gate,ch) != 0;
			}else{
				glen = 0;
				match = 0;
			}
		}else{
			gate = crp->r_gate;
			glen = strlen(gate);
			if( gate == OTHERWISE ){
				if( (flag & ISALT) && 0 < nmatch )
					match = 0;
				else	match = 1;
			}else
			if( crp->r_flag & IGNCASE )
				match = strncasecmp(src,gate,glen) == 0;
			else	match = strncmp(src,gate,glen) == 0;
		}
		if( 0 < glen && match )
			nmatch++;

		if( match ){
			if( putv && (crp->r_flag & PUTGATE) ){
				(*putv)(crp->r_name,crp->r_gate,glen,QVStr(val,vala));
				val += strlen(val);
			}

			src += glen;

			if( crp->r_dest == SUCCESS )
				goto success;
			if( crp->r_dest == FAILURE ){
				error = 0;
				goto failure;
			}

			if( crp->r_dest == NEXT )
				continue;

			rsize = size - (val-vala);
			if( SLLparse(lev+1,crp->r_dest,src,nsrcp,
				putv,QVStr(val,vala),rsize,nvalp) == 0 )
			{
				val = *nvalp;
				if( putv &&(crp->r_flag & PUTVAL) ){
					slen = *nsrcp - src;
					if( rsize <= slen ){
						error = 4;
						goto failure;
					}
					(*putv)(crp->r_name,src,slen,QVStr(val,vala));
					val += strlen(val);
				}

				src = *nsrcp;
				if( flag & ISALT )
					goto success;

if( DEBUG )
if(prp[si+1].r_name) printf("%2d [%s] %-10sV %s\n", lev, type, name, src);

			}else{
				if( flag & ISSEQ )
				if( glen || !(crp->r_flag & xOPTIONAL) ){
					error = 1;
					goto failure;
				}
				src -= glen; /* back track the gate symbol */
			}
		}else{
			if( flag & ISSEQ )
				if( !(crp->r_flag & xOPTIONAL) ){
					error = 2;
					goto failure;
				}
		}
	}
	if( flag & ISALT ){
		error = 3;
		goto failure;
	}

success:
	*nsrcp = (char*)src;
	*nvalp = (char*)val;
	setVStrEnd(val,0);
	return 0;

failure:
	setVStrEnd(val,0);
	if( DEBUG )
		printf("FAILURE %d [%s]: %s\n",error,name,src);
	return -1;
}

void SLL_putval(PCStr(name),PCStr(val),int len,PVStr(out))
{	const char *sp;
	refQStr(vp,out);
	int vi;

	sp = name;
	while( *sp )
		setVStrPtrInc(vp,*sp++);
	setVStrPtrInc(vp,'=');

	sp = val;
	for( vi = 0; vi < len; vi++ )
		setVStrPtrInc(vp,*sp++);
	setVStrPtrInc(vp,'\n');
	setVStrEnd(vp,0);
}
