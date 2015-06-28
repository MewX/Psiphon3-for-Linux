/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
Copyright (c) 2001-2006 National Institute of Advanced Industrial Science and Technology (AIST)

Permission to use this material for evaluation, copy this material for
your own use, and distribute the copies via publically accessible on-line
media, without fee, is hereby granted provided that the above copyright
notice and this permission notice appear in all copies.
AIST MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	CFI interface library
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	060809	extracted from windows.c
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"

int openNull(int);
int lock_exclusiveNB(int fd);
int lock_sharedNB(int fd);
int lock_unlock(int fd);
int CFI_SHARED_LOCKFD = -1;
int CFI_SHARED_LOCKPID = 0;
int CFI_SHARED_FD = -1;
static FILE *shlockfp;

void arg2env(PCStr(prefix),int logfd)
{	CStr(env,1024);
	CStr(tmp,1024);

	sprintf(env,"%sLOGFD=%d",prefix,logfd);
	putenv(stralloc(env));
}
void env2arg(PCStr(prefix))
{	CStr(name,1024);
	const char *env;

	sprintf(name,"%sLOGFD",prefix);
	if( env = getenv(name) )
	{	int lfd;

		if( *env == '-' ){
			lfd = openNull(1);
			dup2(lfd,fileno(stderr));
			close(lfd);
		}else
		dup2(atoi(env),fileno(stderr));
	}
}

FILE *CFI_fopenShared(PCStr(mode)){
	if( 0 <= CFI_SHARED_FD ){
		FILE *fp;
		int size;
		fp = fdopen(dup(CFI_SHARED_FD),mode);
		if( fp ){
			fseek(fp,0,2);
			size = ftell(fp);
			fseek(fp,0,0);
		}
		return fp;
	}
	return NULL;
}

void CFI_closeLock(){
	close(CFI_SHARED_LOCKFD);
	CFI_SHARED_LOCKFD = -1;
}
static int init_lock(){
	int pid = getpid();
	if( CFI_SHARED_LOCKFD < 0 || CFI_SHARED_LOCKPID != pid ){
		const char *env;
		FILE *fp;
		if( 0 <= CFI_SHARED_LOCKFD ){
			CFI_closeLock();
		}
		if( env = getenv("CFI_SHARED_LOCK") ){
			if( fp = fopen(env,"r+") ){
				CFI_SHARED_LOCKPID = pid;
				CFI_SHARED_LOCKFD = fileno(fp);
			}
		}
	}
	return CFI_SHARED_LOCKFD;
}
int CFI_exclusiveLock(){
	int stat;
	init_lock();
	if( CFI_SHARED_LOCKFD < 0 )
		return -1;
	stat = lock_exclusiveNB(CFI_SHARED_LOCKFD);
	return stat;
}
int CFI_sharedLock(){
	int stat;
	init_lock();
	if( CFI_SHARED_LOCKFD < 0 )
		return -1;
	stat = lock_sharedNB(CFI_SHARED_LOCKFD);
	return stat;
}
int CFI_unLock(){
	int stat;
	if( CFI_SHARED_LOCKFD < 0 )
		return -1;
	stat = lock_unlock(CFI_SHARED_LOCKFD);
	return stat;
}
FILE *CFI_LockFp(){
	init_lock();
	if( CFI_SHARED_LOCKFD < 0 )
		return 0;
	if( shlockfp ){
		if( fileno(shlockfp) == CFI_SHARED_LOCKFD )
			return shlockfp;
	}
	shlockfp = fdopen(CFI_SHARED_LOCKFD,"r");
	return shlockfp;
}

const char *CFI_FILTER_ID(){
	const char *env;
	if( env = getenv("CFI_FILTER_ID") ){
		return env;
	}
	return "";
}
int setCFIshared(){
	const char *env;
	if( env = getenv("CFI_SHARED_FD") ){
		CFI_SHARED_FD = atoi(env);
		return CFI_SHARED_FD;
	}
	return -1;
}
