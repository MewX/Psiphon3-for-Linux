/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for noncommercial and/or evaluation
purpose, copy this material for your own use, and distribute the copies
via publicly accessible on-line media, without fee, is hereby granted
provided that the above copyright notice and this permission notice
appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	dgdate.c (setting date)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	060924	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "dgxauth.c"

int date_main(int ac,const char *av[]);
int main(int ac,char *av[])
{
	dgxauth(ac,av);
	return randstack_call(1,(iFUNCP)date_main,ac,av);
}
