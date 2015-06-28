/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1999 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1999 Yutaka Sato

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	netzip.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:

  A filter to compress data transferred between two DeleGates.

  USAGE:
    remote-host> delegated -P8888 SERVER=tcprelay://news-server:119 \
                           FTOCL="netzip"
    local-host>  delegated -P8119 SERVER=tcprelay://remote-host:8888 \
                           FTOCL="netzip -d"

ToDo:
  + don't try compressing already compressed data like GIF or JPEG
  + be adaptable both for bi-directional and uni-directional filter
  + try to make larger packet by waiting input for certain timeout
  + non-blocking write toward receiver will be effective
  + adaptive algorithm to determine the data size to be compressed
  + consider difference between send/write, read/recv, OOB relay, ...
  + thread based implementation may be effective

History:
	990219	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include "ystring.h"
#include <sys/wait.h>

#define THRU		0
#define GNUZIP		1
#define COMPRESS	2

static int MIN_PACKSIZE = 1024;

char *gzip_path = "gzip";
char *gzip_av[] = {"gzip",0};
char *gunzip_av[] = {"gzip","-d",0};

typedef unsigned char UCHAR;

typedef struct {
	UCHAR	h_vern;
	UCHAR	h_type;
	UCHAR	h_seqn[2];
	UCHAR	h_leng[4];
} Head;

#define BtoI(b)   ((b[0] << 24)|(b[1] << 16)|(b[2]  <<8)|(b[3]))
#define ItoB(b,i) { b[0]=i>>24;  b[1]=i>>16;  b[2]=i>>8;  b[3]=i; }

static int itotal;
static int ototal;
static int npacks;
static char rembuf[0x10000];
static long remlen;

static void CHECKP(PCStr(fmt),...);
void fsetBinaryIO(int fd,int on);
int relay1(int decomp,int ifd,int ofd);

int main(int ac,char *av[])
{	int decomp,ai,gi,rcc;
	int ifd,ofd;

	decomp = 0;
	ifd = 0;
	ofd = 1;
	for( ai = 0; ai < ac; ai++ )
		if( strcmp(av[ai],"-d") == 0 )
			decomp = 1;

	/*
	 * negotiate if with bi-directional stream (socket)
	 */

	/*
	 * relay
	 */

	fsetBinaryIO(ifd,1);
	fsetBinaryIO(ofd,1);

	for( gi = 0;; gi++ ){
		rcc = relay1(decomp,ifd,ofd);
		if( rcc < 0 )
			break;
		if( rcc == 0 ){
sleep(1);
			break;
		}
	}
	CHECKP("\r\nDONE(%d)\r\n",gi);
	return 0;
}

static int ONE_LINE = 1;
static int mypid;
static void CHECKP(PCStr(fmt),...)
{	VARGS(8,fmt);

	if( mypid == 0 )
		mypid = getpid();
	if( *fmt == '\r' || !ONE_LINE ){
		fprintf(stderr,"\r[%d] ",mypid);
		if( *fmt == '\r' )
			fmt++;
	}
	fprintf(stderr,fmt,VA8);
	if( !ONE_LINE )
		fprintf(stderr,"\r\n");
	fflush(stderr);
}
static void ERROR(PCStr(fmt),...)
{	VARGS(8,fmt);

	fprintf(stderr,"\r\n!!");
	fprintf(stderr,fmt,VA8);
	fprintf(stderr,"!!\r\n");
	fflush(stderr);
}

int comp1(int decomp,PCStr(ibuf),int ilen,PVStr(obuf),int osiz);
int writes(int fd,PCStr(buf),int len);
int reads(int fd,PVStr(buf),int len);

int relay1(int decomp,int ifd,int ofd)
{	int plen,ilen,olen,rlen,rcc,nextlen,wlen;
	CStr(ibuf,0x10000);
	CStr(obuf,0x20000);
	const char *itop;
	defQStr(otop); /*alt*//**/
	Head *Ihp,*Ohp;

	Ihp = (Head*)ibuf;
	Ohp = (Head*)obuf;
	CHECKP("\r* ");

	if( decomp ){
		if( 0 < remlen ){
			bcopy(rembuf,ibuf,remlen);
			ilen = remlen;
			remlen = 0;
		}else{
ERROR("start-read[%d]",ifd);
			ilen = read(ifd,ibuf,0x4000);
ERROR("end-read[%d]",ilen);
if( ilen <= 0 )
	return 0;

		}
		rlen = sizeof(Head) - ilen;
		if( 0 < rlen ){
ERROR("READ-FLAGMENT-OF-HEADER[%d/%d]",rcc,ilen);
			rcc = reads(ifd,QVStr(ibuf+ilen,ibuf),rlen);
			ERROR("READ-FLAGMENT-OF-HEADER[%d/%d]",rcc,rlen);
			if( rcc <= 0 )
				return -1;
			ilen += rcc;
		}
		plen = BtoI(Ihp->h_leng);
	}else{
		ilen = read(ifd,ibuf,0x4000);
		plen = ilen;
	}
	if( ilen <= 0 ){
		CHECKP("EOF? read()=%d, errno=%d",ilen,errno);
		return ilen;
	}
	itotal += plen;
	CHECKP("[%6d ",plen);

	if( decomp ){
		nextlen = ilen - (sizeof(Head)+plen);
		if( 0 < nextlen ){
			bcopy(ibuf+sizeof(Head)+plen,rembuf,nextlen);
			remlen = nextlen;
			ilen = sizeof(Head)+plen;
		}
		rlen = plen - (ilen-sizeof(Head));
		if( 0 < rlen ){
			rcc = reads(ifd,QVStr(ibuf+ilen,ibuf),rlen);
			if( rcc != rlen ){
				ERROR("READ-FAILED[%d/%d]",rcc,rlen);
				return -1;
			}
			ilen += rcc;
		}

		ilen -= sizeof(Head);
		itop = ibuf + sizeof(Head);
		if( Ihp->h_type == THRU ){
			otop = (char*)itop;
			olen = ilen;
			CHECKP("== ");
			goto PUT;
		}
	}else{
		if( ilen < MIN_PACKSIZE ){
			Ohp->h_type = THRU;
			ItoB(Ohp->h_leng,ilen);
			bcopy(ibuf,obuf+sizeof(Head),ilen);
			otop = obuf;
			olen = sizeof(Head)+ilen;
			CHECKP("== ");
			goto PUT;
		}
		itop = ibuf;
	}

	CHECKP(">");
	otop = obuf + sizeof(Head);
	olen = comp1(decomp,itop,ilen,QVStr(otop,obuf),sizeof(obuf)-sizeof(Head));
	CHECKP("> ");

	if( decomp ){
	}else{
		Ohp->h_vern = 0;
		Ohp->h_type = GNUZIP;
		ItoB(Ohp->h_leng,olen);
		otop = obuf;
		olen += sizeof(Head);
	}
PUT:
	CHECKP(" %6d](%3d%%) ",olen,olen*100/plen);
	wlen = writes(ofd,otop,olen);
	if( wlen != olen )
		ERROR("WRITE-FAILED[%d/%d]",wlen,olen);
	npacks++;
	if( decomp )
		ototal += olen;
	else	ototal += olen - sizeof(Head);
	CHECKP("* [%8d >> %8d+%5d](%3d%%)",
		itotal,ototal,npacks*sizeof(Head),ototal*100/itotal);
	return ilen;
}
int writes(int fd,PCStr(buf),int len)
{	int off,wcc;

	for( off = 0; off < len; off += wcc ){
		wcc = write(fd,buf+off,len-off);
		if( wcc < 0 )
			break;
	}
	return off;
}
int reads(int fd,PVStr(buf),int len)
{	int off,rcc;

	for( off = 0; off < len; off += rcc ){
		rcc = read(fd,(char*)buf+off,len-off);
		if( rcc < 0 )
			break;
	}
	return off;
}

#ifdef __CYGWIN__
#include <process.h>
int comp1(int decomp,PCStr(ibuf),int ilen,PVStr(obuf),int osiz)
{	int tz[2],fz[2];
	int fd0,fd1,pid,olen,wlen,wpid,xstat;

	pipe(tz);
	pipe(fz);

	fcntl(tz[1],F_SETFD,1);
	fcntl(fz[0],F_SETFD,1);

	fd0 = dup(0); dup2(tz[0],0);
	fd1 = dup(1); dup2(fz[1],1);
	if( decomp )
		pid = spawnvp(_P_NOWAIT,gzip_path,gunzip_av);
	else	pid = spawnvp(_P_NOWAIT,gzip_path,gzip_av);
	dup2(fd0,0); close(fd0);
	dup2(fd1,1); close(fd1);

	wlen = writes(tz[1],ibuf,ilen);
	close(tz[1]);
	if( wlen != ilen )
		CHECKP("\r\n**(write failed[%d/%d]**\r\n",wlen,ilen);

	close(tz[0]);
	close(fz[1]);

	olen = read(fz[0],obuf,osiz);
	close(fz[0]);
	wpid = wait(&xstat);
	return olen;
}
#else
int comp1(int decomp,PCStr(ibuf),int ilen,PVStr(obuf),int osiz)
{	int tz[2],fz[2];
	int olen;

	pipe(tz);
	pipe(fz);
	if( fork() == 0 ){
		close(tz[1]); dup2(tz[0],0);
		close(fz[0]); dup2(fz[1],1);
		if( decomp )
			execvp(gzip_path,gunzip_av);
		else	execvp(gzip_path,gzip_av);
		exit(-1);
	}
	close(tz[0]);
	close(fz[1]);
	writes(tz[1],ibuf,ilen);
	close(tz[1]);
	olen = read(fz[0],(char*)obuf,osiz);
	close(fz[0]);
	wait(0);
	return olen;
}
#endif

void fsetBinaryIO(int fd,int on)
{	int oflags,flags,nflags,rcode;

#ifdef O_BINARY
	errno = 0;
	oflags = fcntl(fd,F_GETFL,0);
	if( on )
		flags = oflags |  O_BINARY;
	else	flags = oflags & ~O_BINARY;
	rcode = fcntl(fd,F_SETFL,flags);
	nflags = fcntl(fd,F_GETFL,0);

	CHECKP("SET-BINARY-IO(%d, %06x->%06x->%06x)=%d,errno=(%d)",
		fd,oflags,flags,nflags,rcode,errno);
#endif
}
