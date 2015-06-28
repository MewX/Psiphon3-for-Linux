#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/dir.h>
#include "yarg.h"

int scan_ino;

int Scandir(const char *dirpath,int(*func)(const char*,...),...)
{	struct direct **dirents,*dir1;
	int nent,ei;
	int rcode;

	VARGS(8,func);

	rcode = 0;
	dirents = NULL;
	if( 0 < (nent = scandir(dirpath,&dirents,NULL,NULL)) ){
		for( ei = 0; ei < nent; ei++ ){
			dir1 = dirents[ei];
			dir1->d_name[dir1->d_namlen] = 0;
			scan_ino = dir1->d_fileno;

			if( rcode = (*func)(dir1->d_name,VA8) )
				break;
		}
		free(dirents);
	}
	return rcode;
}
