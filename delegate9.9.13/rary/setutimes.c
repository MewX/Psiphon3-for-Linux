/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1997-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	setutimes.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970724	created
//////////////////////////////////////////////////////////////////////#*/
#include "file.h"
#include "vsocket.h" /* <sys/time.h> for timeval of utimes() */
#include <ctype.h>

int set_utimes(PCStr(path),int atime,int mtime)
{	FileStat st;
	struct timeval tv[2]; /**/

	if( stat(path,&st) != 0 )
		return -1;

	if( atime != 0 && atime != -1 )
		tv[0].tv_sec = atime;
	else	tv[0].tv_sec = st.st_atime;
	tv[0].tv_usec = 0;

	if( mtime != 0 && mtime != -1 )
		tv[1].tv_sec = mtime;
	else	tv[1].tv_sec = st.st_mtime;
	tv[1].tv_usec = 0;

	return utimes(path,tv);
}

int Futimes(int fd,int as,int au,int ms,int mu);
int INHERENT_futimes();
int set_futimes(int fd,int atime,int mtime){
	FileStat st;
	int as,au,ms,mu;
	int rcode;

	if( fstat(fd,&st) != 0 )
		return -1;

	if( atime != 0 && atime != -1 )
		as = atime;
	else	as = st.st_atime;
	au = 0;

	if( mtime != 0 && mtime != -1 )
		ms = mtime;
	else	ms = st.st_mtime;
	mu = 0;

	rcode = Futimes(fd,as,au,ms,mu);
	return rcode;
}

/*
 * futimes() is better in the performance and the time is that
 * of the host machine.
 * fturncate() sets the time which can be different with that
 * of the host machine if the file is on a network-file system.
 */
int file_touch(int fd){
	FileSize fsize;

	if( INHERENT_futimes() ){
		if( set_futimes(fd,-1,time(0)) == 0 ){
			return 0;
		}
	}
	if( 0 <= (fsize = file_size(fd)) )
	if( ftruncate(fd,fsize+1) == 0 )
	if( ftruncate(fd,fsize) == 0 )
		return 0;
	return -1;
}

/*
 * these casting to (off_t) seems to have been necessary when without
 * prototype (without including <unistd.h>)
 * maybe it is unnecssary after 8.10.0.  and it will be harmful where
 * (off_t < 4GB, non-BSD) and (4GB < FileSize, default after 9.2.2)
 * ftell()/fseek() is NG because it uses int and
 * should be replaced with ftello()/fseeko() or fgetpos()/fsetpos().
 */
FileSize Lseek(int fd,FileSize off,int wh);
int Ftruncate(FILE *fp,FileSize offset,int whence)
{	Fpos_t savoff;
	FileSize siz;
	int rcode;

	/*
	savoff = ftell(fp);
	fseek(fp,offset,whence);
	rcode = ftruncate(fileno(fp),(off_t)ftell(fp));
	fseek(fp,savoff,0);
	*/
	Fgetpos(fp,&savoff);
	fseek(fp,offset,whence);
	siz = Lseek(fileno(fp),offset,whence);
	if( siz <= 0xFFFFFFFF ){
		int fsiz = ftell(fp);
		if( siz != fsiz ){
			syslog_ERROR("## Ftruncate(%d,%lld,%d) %d %lld\n",
				fileno(fp),offset,whence,fsiz,siz);
			siz = fsiz;
		}
	}
	rcode = ftruncate(fileno(fp),siz);
	Fsetpos(fp,&savoff);
	return rcode;
}
FileSize Lseek(int fd,FileSize off,int wh)
{
	return lseek(fd,off,wh);
	/*
	return lseek(fd,(off_t)off,wh);
	*/
}
FileSize Ltell(int fd){
	FileSize off;
	off = lseek(fd,0,1);
	return off;
}
void ftouch(FILE *fp,int time)
{	int off;

	off = ftell(fp);
	fseek(fp,0,2);
	fwrite("",1,1,fp);
	fflush(fp);
	fseek(fp,-1,2);
	Ftruncate(fp,0,1);
	fseek(fp,off,0);
}
void File_touch(PCStr(path),int clock)
{	FILE *fp;

	if( fp = fopen(path,"a") ){
		ftouch(fp,clock);
		fclose(fp);
	}
}

int touch_main(int ac,const char *av[]){
	FileSize size = 0;
	int clock = -1;
	int fd = fileno(stdout);
	int orand = 0;
	int ai;
	const char *a1;
	FILE *fp;

	for( ai = 1; ai < ac; ai++ ){
		a1 = av[ai];
		if( a1[0] == '+' ){
			if( a1[1] == 0 )
				clock = time(0);
			else	clock = atoi(a1+1);
		}else
		if( a1[0] == '-' ){
			if( isdigit(a1[1]) ){
				size = kmxatoi(a1+1);
			}else
			switch( a1[1] ){
				case 'r': orand = 1; break;
			}
		}else{
			fp = fopen(a1,"r+");
			if( fp == NULL )
				fp = fopen(a1,"w");
			if( fp ){
				fd = fileno(fp);
			}
		}
	}
	if( 0 < size ){
		Lseek(fd,size-1,0);
		IGNRETP write(fd,"",1);
	}
	if( 0 < clock ){
		set_futimes(fd,-1,clock);
	}
	return 0;
}
