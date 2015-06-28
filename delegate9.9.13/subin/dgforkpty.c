/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2010 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	dgforkpty.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	100117	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <errno.h>
#include "dgxauth.c"
#define DGFORKPTY
#include "../rary/netsh.c"

int dgforkpty_main(int ac,char *av[]);
int main(int ac,char *av[]){
	int rcode;
	dgxauth(ac,av);
	rcode = dgforkpty_main(ac,av);
	return rcode;
}

/* just to avoid error for caller-side in netsh.c */
int Socketpair_FL(FL_PAR,int sv[2]){
	fprintf(stderr,"---- dgforkpty: no socketpair() <= %s:%d\n",FL_BAR);
	return -1;
}
int spawnv_self1(int aac,const char *aav[]){
	fprintf(stderr,"---- dgforkpty: no spawnv_self1()\n");
	return -1;
}
