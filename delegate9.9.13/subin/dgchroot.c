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
Program:	dgchroot.c
Author:		Yutaka Sato <ysato@delegate.org>
Description:

History:
	030125	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <errno.h>
#include "dgxauth.c"

int main(int ac,char *av[])
{	int rcode;
	const char *root;
	const char *path;
	int ai;
	CStr(cwd,1024);
	CStr(env,1024+8);
	int pid = getpid();
	int verbose = 0;
	FILE *ilog = NULL;

	for( ai = 0; ai < ac; ai++ ){
		if( strncmp(av[ai],"-v",2) == 0 ){
			verbose = 1;
		}else
		if( strncmp(av[ai],"-II",3) == 0 ){
			int fd;
			fd = atoi(av[ai]+3);
			ilog = fdopen(fd,"a");
		}
	}

	dgxauth(ac,av);
	if( ac < 4 ){
		fprintf(stderr,"Usage: %s root path arg-list\n",av[0]);
		exit(-1);
	}
	root = av[1];
	path = av[2];

	IGNRETZ chdir(root);
	if( chroot(root) != 0 ){
		fprintf(stderr,"ERROR: could not do chroot(%s), errno=%d\n",
			root,errno);
		exit(-1);
	}

	if( verbose ){
		fprintf(stderr,"#[%d] chroot(%s)...OK\n",pid,root);
		if( ilog )
		fprintf(ilog,"#[%d] chroot(%s)...OK\n",pid,root);
	}

	seteuid(getuid());
	IGNRETZ chdir("/");

sleep(1); /* to avoid accidental tight loop ... */

	/* THE path MUST be renamed at relative one from new-root */
	fprintf(stderr,"#[%d] execv(%s)...\n",pid,path);
	if( verbose || ilog != NULL ){
		int ai;
		for( ai = 0; ai < ac; ai++ ){
			if( verbose ){
				if( ai == 3 )
				fprintf(stderr,"#[%d]\n",pid);
			fprintf(stderr,"#[%d] execv[%d] %s\n",pid,ai,av[ai]);
			}
			if( ilog )
			fprintf(ilog,"#[%d] execv[%d] %s\n",pid,ai,av[ai]);
		}
		if( ilog )
			fflush(ilog);
	}
	execv(path,&av[3]);

fprintf(stderr,"#### execv(%s) 3 ...\n",path);
	perror("chroot");
	truncVStr(cwd);
	IGNRETS getcwd(cwd,sizeof(cwd));
	fprintf(stderr,"ERROR: could not exec(%s) at %s, errno=%d\n",
		path,cwd,errno);
	for( ai = 3 ; ai < ac; ai++ )
		fprintf(stderr,"[%d] %s\n",ai-3,av[ai]);
	return -1;
}
