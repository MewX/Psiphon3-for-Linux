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
Program:	dgcpnod.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	031224	created
//////////////////////////////////////////////////////////////////////#*/
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include "dgxauth.c"

int main(int ac,char *av[])
{	const char *from;
	const char *to;
	struct stat st;
	int rcode;

	dgxauth(ac,av);
	if( ac < 3 ){
		fprintf(stderr,"Usage: %s path1 path2\n",av[0]);
		exit(-1);
	}
	from = av[1];
	to = av[2];
	if( stat(from,&st) != 0 ){
		perror(from);
		exit(-1);
	}
	rcode = mknod(to,st.st_mode,st.st_rdev);
	fprintf(stderr,"#### mknod(%s,%x,%x)\n",to,st.st_mode,ll2i(st.st_rdev));
	if( rcode != 0 ){
		perror(to);
		exit(-1);
	}
	chmod(to,st.st_mode);
	IGNRETZ chown(to,st.st_uid,st.st_gid);
	return 0;
}
