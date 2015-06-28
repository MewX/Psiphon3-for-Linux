/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)
AIST-Product-ID: 2000-ETL-198715-01, H14PRO-049, H15PRO-165, H18PRO-443

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
Program:	lock.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970403	extracted from cache.c
	060808	moved from src/ to rary/
//////////////////////////////////////////////////////////////////////#*/
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "proc.h"
#include "file.h"
#include "log.h"

void msleep(int msec);
int SHlockB(int fd);
int SHlockNB(int fd);
int EXlockB(int fd);
int EXlockNB(int fd);
int UNlock(int fd);
int Fstype(PCStr(path),char type[]);
int File_device(PCStr(path));
int file_device(int fd);
int fileIsremote1(int fd);
int INHERENT_fchmod();
void *callFuncTimeout(int sec,void *xcode,void *(*func)(void*,...),...);

int lock_for_rd(PCStr(what),int nretry,PCStr(cpath),FILE *fp)
{	int rcode;
/*
double Start;
Start = Time();
*/
	errno = 0;
	if( SHlockB(fileno(fp)) == -1 ){
		syslog_ERROR("%s lock for read failed*%d (%d) %s\n",
			what,nretry,errno,cpath);
		rcode = -1;
	}else{
/*
daemonlog("E","[%3.2f][%s lock-shared] %s\n",Time()-Start,what,cpath);
*/
		rcode = 0;
	}
	return rcode;
}

int file_lock_wr(PCStr(what),FILE *fp)
{	int rcode;

	rcode = EXlockNB(fileno(fp));
	if( rcode == -1 )
	/* someone are reading or writing the file */
	{
		syslog_ERROR("%s lock for write failed (%d), retry..\n",
			what,errno);
		return -1;
	}else{
		syslog_DEBUG("%s locked for write [%d] %d\n",what,
			fileno(fp),rcode);
		return 0;
	}
}
int lock_exclusive(int fd)
{
	return EXlockB(fd);
}
int lock_exclusiveNB(int fd)
{
	return EXlockNB(fd);
}
int lock_shared(int fd)
{
	return SHlockB(fd);
}
int lock_sharedNB(int fd)
{
	return SHlockNB(fd);
}
int lock_unlock(int fd)
{
	return UNlock(fd);
}
int lock_free(int fd)
{
	return UNlock(fd);
}

static int LOCK_INTVL = 200;

static int never_locked(int errNo){
#ifdef EWOULDBLOCK
	if( errNo == EWOULDBLOCK )
		return 0;
	else	return 1;
#endif
#ifdef EBADF
	if( errNo == EBADF ) return 1;
#endif
#ifdef EINVAL
	if( errNo == EINVAL ) return 1;
#endif
#ifdef EOPNOTSUPP
	if( errNo == EOPNOTSUPP ) return 1;
#endif
	return 0;
}

typedef int (*iiFUNCP)(int);

static int lock_TO(int fd,iiFUNCP funcNB,iiFUNCP func,int timeout,int *elapsedp)
{	int elapsed,remain;
	long int rcode;
	int xtry;

	elapsed = 0;
	rcode = -1;

	for( xtry = 0;; xtry++ ){
		errno = 0;
		if( (*funcNB)(fd) == 0 ){
			rcode = 0;
			break;
		}
		if( never_locked(errno) ){
		/* Verbose("*** cannot lock [%d] errno=%d\n",fd,errno); */
			break;
		}

		remain = timeout - elapsed;
		if( remain <= 0 )
			break;

		if( isWindows() ){ /* no alarm() */
			int wait1;
			if( 3000 <= elapsed && 1000 <= remain )
				wait1 = 1000;
			else
			if( 1000 <= elapsed &&  500 <= remain )
				wait1 =  500;
			else
			if( remain < LOCK_INTVL )
				wait1 = remain;
			else	wait1 = LOCK_INTVL;
			msleep(wait1);
			elapsed += wait1;
		}else
		if( 2000 <= elapsed && 1000 <= remain ){
			double start;
			int elapse1;

			start = Time();
			rcode = (long int)callFuncTimeout(remain/1000,(void*)-1,(void*(*)(void*,...))func,fd);
			elapse1 = (int)((Time() - start) * 1000); 
/*{
static int n;
fprintf(stderr,"#### [%d] %5d sleeped %5d + %5d RCODE=%d\n",
getpid(),++n,elapsed,elapse1,rcode);
}*/

			elapsed += elapse1;
		}else{
			int wait1;

			if( remain < LOCK_INTVL )
				wait1 = remain;
			else	wait1 = LOCK_INTVL;
			msleep(wait1);
			elapsed += wait1;
		}
	}

	if( elapsedp != NULL )
		*elapsedp = elapsed;
	return rcode;
}
int lock_exclusiveTO(int fd,int timeout,int *elapsedp)
{
	return lock_TO(fd,(iiFUNCP)lock_exclusiveNB,(iiFUNCP)lock_exclusive,timeout,elapsedp);
}
int lock_sharedTO(int fd,int timeout,int *elapsedp)
{
	return lock_TO(fd,(iiFUNCP)lock_sharedNB,(iiFUNCP)lock_shared,timeout,elapsedp);
}

/* ################ */

int fileIsremote(PCStr(path),int fd)
{	int isremote,i;
	CStr(fstype,128);

	if( !INHERENT_fchmod() )
		return 0;

	/* may be on tmpfs on SunOS where st_ctime is not supported ... */
	if( strncmp(path,"/tmp/",5) == 0 )
		return 0;

	if( strncmp(path,"/net/",5) == 0 )
		return 1;
	if( strncmp(path,"/tmp_mnt/",9) == 0 )
		return 1;
	if( Fstype(path,fstype) == 0 ){
		if( strcmp(fstype,"nfs") == 0 )
			return 1;
		else	return 0;
	}

	if( fd < 0 )
		return -1;

	if( isatty(fd) )
		return 0;

	/* not only NFS but different type device also ... */
	if( File_device("/") != file_device(fd) )
		return 1;

/*
	if( lock_exclusive(fd,10*1000,NULL) != 0 )
*/
	if( lock_exclusiveTO(fd,10*1000,NULL) != 0 )
	{
		daemonlog("F","##SIG fileIsremote:lock err=%d %s\n",errno,path);
		return -1;
	}

	isremote = 0;
	for( i = 0; i < 5; i++ ){
		if( fileIsremote1(fd) != 0 ){
			isremote = 1;
			break;
		}
	}
	lock_unlock(fd);
	return isremote;
}
