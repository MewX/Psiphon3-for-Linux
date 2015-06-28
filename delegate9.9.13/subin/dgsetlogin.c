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
	100131	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <errno.h>
#include "dgxauth.c"

int main(int ac,char *av[]){
	IStr(user,128);
	int rcode;

	dgxauth(ac,av);
	if( ac < 2 ){
		fprintf(stderr,"Usage: dgsetlogin username\n");
		return -1;
	}
	strcpy(user,av[1]);
	rcode = setlogin(user);
	fprintf(stderr,"--setlogin(%s)=%d, e%d\n",user,rcode,errno);
	return rcode;
}
