/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	pam.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	030814	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "dgxauth.c"

int pam_server(int ac,char *av[]);
int main(int ac,char *av[])
{
	dgxauth(ac,av);
	return randstack_call(1,(iFUNCP)pam_server,ac,av);
}
