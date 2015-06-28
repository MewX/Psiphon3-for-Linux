/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997 Electrotechnical Laboratry (ETL), AIST, MITI

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
Program:	fcl.c (a template of FCL filter)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970208	created
//////////////////////////////////////////////////////////////////////#*/

#include <stdio.h>
#include "ystring.h"

/*
 *	bidirectional relay implemented using LWP of Solaris2.X
 */
#include <sys/lwp.h>
#define STKSIZE	0x10000

bdrelay(fromcl,tocl)
	vFUNCP fromcl,tocl;
{	vFUNCP func[2];
	ucontext_t *ctx[2];
	lwpid_t lwp[2];
	int error;
	int ti;
	lwpid_t lwp_done;

	func[0] = fromcl;
	func[1] = tocl;

	for( ti = 0; ti < 2; ti++ ){
		ctx[ti] = (ucontext_t*)malloc(sizeof(ucontext_t));
		_lwp_makecontext(ctx[ti],func[ti],(void*)NULL,(void*)NULL,
			(caddr_t)malloc(STKSIZE),STKSIZE);
		error = _lwp_create(ctx[ti],0,&lwp[ti]);
	}
	_lwp_wait(lwp[1],&lwp_done);
}


/*
 *	bidirectional tee using bdrelay()
 */
static void FFROMCL() /* 0 -> 1 */
{	int rcc;
	CStr(buf,512);

	while( 0 < (rcc = read(0,buf,sizeof(buf))) ){
		write(1,buf,rcc);
		write(2,buf,rcc);
	}
}
static void FTOCL() /* 1 -> 0 */
{	int rcc;
	CStr(buf,512);

	while( 0 < (rcc = read(1,buf,sizeof(buf))) ){
		write(0,buf,rcc);
		write(2,buf,rcc);
	}
}
main(){
	bdrelay(FFROMCL,FTOCL);
}
