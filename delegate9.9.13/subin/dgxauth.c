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
Program:	dgxauth.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
	External commands under subin/ are executed under file owner's
	user-ID (root) and group-ID (Group).
	They must not be utilized by anyone (porcess) other than the
	owner (Group) of it.
	Therefore they are permitted to execute only if the real
	group-ID of the owner of the caller process equals to the Group
	which is set as the effective group-ID.
History:
	030117	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "ystring.h"
int randstack_call(int strg, iFUNCP func, ...);

static void dgxauth(int ac,char *av[])
{	int gid,egid;

	gid = getgid();
	egid = getegid();
	if( getuid() <= 0 ){
		/* allow super-user to use subin/* */
	}else
	if( egid != gid ){
		fprintf(stderr,"ERROR: gid=%d egid=%d (uid=%d %d)\n",
			gid,egid,getuid(),geteuid());
		exit(-1);
	}
}
