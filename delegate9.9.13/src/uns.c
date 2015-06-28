/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1996-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	unsock.c (AF_UNIX domain socket)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960604	extracted from distrib.c and inets.c
//////////////////////////////////////////////////////////////////////#*/
#include <errno.h>
#include <stdio.h>
#include "ystring.h"
#include "file.h"
#include "log.h"
#include "vsocket.h"
#include "dglib.h"

int IsOS2EMX();
void UnixSocketDir(PVStr(path));
int connectTO(int sock,SAP addr,int leng,int timeout);
void Myhostport(PVStr(myhp),int size);
int SocketPair(int d,int type,int protocol,int sv[2]);
int free_un(PCStr(what),PCStr(lpath),PVStr(spath),int size,int if_owner);

int AF_UNIX_DISABLE = 0;
int AF_UNIX_SOCKETPAIR_DISABLE = 0;
static int un_seqno;

#define errlog	sv1log
#define dbglog	LOGLEVEL<2?0:Verbose

#if defined(_SOCKADDR_LEN)/*OSF1*/ || defined(SUN_LEN)/*AIX*/
/* must set sockaddr_un.sun_len ? */
#else
#endif

int INET_Socketpair(int sv[])
{
	return SocketPair(AF_INET,SOCK_STREAM,0,sv);
}

#ifdef _MSC_VER
#define socketpair_FL(FL_PAR,d,t,p,sv) Xsocketpair_FL(FL_PAR,d,t,p,sv)
#else
#define socketpair_FL(FL_PAR,d,t,p,sv) socketpair(d,t,p,sv)
#endif

int Socketpair_FL(FL_PAR,int sv[])
{
	sv[0] = sv[1] = -1;

	if( !AF_UNIX_DISABLE || !AF_UNIX_SOCKETPAIR_DISABLE ){
		if( socketpair_FL(FL_BAR,AF_UNIX,SOCK_STREAM,0,sv) == 0 )
			return 0;
		AF_UNIX_DISABLE = 1;
		AF_UNIX_SOCKETPAIR_DISABLE = 1;
		dbglog("#### Socketpair(AF_UNIX) failed (%d)\n",errno);
	}

	if( 0 <= socketpair_FL(FL_BAR,AF_INET,SOCK_STREAM,0,sv) )
		return 0;

	if( AF_UNIX_SOCKETPAIR_DISABLE )
		return -1;
	else	return socketpair_FL(FL_BAR,AF_UNIX,SOCK_STREAM,0,sv);
}

int UDP_Socketpair_FL(FL_PAR,int sv[])
{
	/*
	some system (Solaris) don't support SOCK_DGRAM on AF_UNIX sockets
	return socketpair(AF_UNIX,SOCK_DGRAM,0,sv);
	*/
	/* MacOSX only supports socketpair(AF_UNIX) */
	if( !isWindows() )
	if( socketpair(AF_UNIX,SOCK_DGRAM,0,sv) == 0 )
		return 0;
	return socketpair_FL(FL_BAR,AF_INET,SOCK_DGRAM,0,sv);
}

int server_open_localhost(PCStr(what),PVStr(path),int nlisten)
{	int sock;
	FILE *sockfp;
	CStr(sockname,256);

	sock = server_open(what,CVStr("localhost"),0,nlisten);
	if( sock < 0 )
	sock = server_open(what,VStrNULL,0,nlisten);

	if( sock < 0 ){
		errlog("####LS cannot create local socket\n");
	}else{
		gethostName(sock,AVStr(sockname),"%A:%P");
		sockfp = dirfopen(what,AVStr(path),"w");
		if( sockfp == NULL ){
			errlog("####LS cannot create %s\n",path);
			close(sock);
			sock = -2;
		}else{
			if( lock_exclusiveTO(fileno(sockfp),3000,NULL) != 0 )
				errlog("####LS cannot lock %s\n",path);
			else{
				fprintf(sockfp,"%s\n",sockname);
/* DEBUG */{
CStr(myhp,MaxHostNameLen);
Myhostport(AVStr(myhp),sizeof(myhp));
fprintf(sockfp,"# %s\n",myhp);
fflush(sockfp);
}
				fflush(sockfp);
				lock_unlock(fileno(sockfp));
			dbglog("####LS bound local socket (%d) [%s] %s\n",
					sock,sockname,path);
			}
			fclose(sockfp);
		}
	}
	return sock;
}
int client_open_localhost(PCStr(what),PCStr(path),int timeout)
{	int sock;
	FILE *sockfp;
	CStr(sockname,MaxHostNameLen);
	CStr(host,MaxHostNameLen);
	int port;

	sockfp = fopen(path,"r");
	if( sockfp == NULL ){
		errlog("####LS cannot open %s\n",path);
		return -1;
	}
	if( lock_sharedNB(fileno(sockfp)) != 0 ){
		errlog("####LS cannot lock %s\n",path);
		fclose(sockfp);
		return -1;
	}

	sock = -1;
/*
	if( fscanf (sockfp,"%[^\r\n]",sockname) != 1 )
*/
	if( Fgets(AVStr(sockname),sizeof(sockname),sockfp) == NULL )
		errlog("####LS cannot read %s\n",path);
	else
	if( Xsscanf(sockname,"%[^:]:%d",AVStr(host),&port) != 2 )
		errlog("####LS cannot parse [%s] %s\n",sockname,path);
	else{
		sock = client_open(what,what,host,port);
		dbglog("####LS connected local socket (%d) [%s] %s\n",
			sock,sockname,path);
	}
	lock_unlock(fileno(sockfp));
	fclose(sockfp);
	return sock;
}

/**/
int server_open_un(PCStr(what),PVStr(path),int nlisten)
{	struct sockaddr_un una;
	int sock;
	int rcode;
	CStr(dir,1024);
	const char *dp;

	if( AF_UNIX_DISABLE )
		return server_open_localhost(what,AVStr(path),nlisten);

	if( sizeof(una.sun_path) <= strlen(path) ){
		errlog("#### bind_un: too long path: %s\n",path);
		return -1;
	}

	if( !IsOS2EMX() ){
		strcpy(dir,path);
		if( dp = strrpbrk(dir,"/\\") )
			truncVStr(dp);
		if( !fileIsdir(dir) ){
			mkdirRX(dir);
			if( !fileIsdir(dir) )
				errlog("bind_un: cannot mkdir %s\n",dir);
		}
	}

	if( nlisten < 0 )
		sock = socket(AF_UNIX,SOCK_DGRAM,0);
	else
	sock = socket(AF_UNIX,SOCK_STREAM,0);
	una.sun_family = AF_UNIX;
	Xstrcpy(EVStr(una.sun_path),path);

	rcode = bind(sock,(SAP)&una,sizeof(una));

	if( rcode == 0 ){
		if( 0 < nlisten ){
		rcode = listen(sock,nlisten);
		if( rcode != 0 )
			errlog("#### bind_un: cannot listen, errno=%d\n",errno);
		}
		return sock;
	}else{
		close(sock);
		return -1;
	}
}
int client_open_unX(PCStr(what),int sock,PCStr(path),int timeout);
int client_open_un(PCStr(what),PCStr(path),int timeout)
{
	return client_open_unX(what,-1,path,timeout);
}
int client_open_unX(PCStr(what),int sock,PCStr(path),int timeout)
{	struct sockaddr_un una;
	int rcode;

	if( AF_UNIX_DISABLE )
		return client_open_localhost(what,path,timeout);

	if( sizeof(una.sun_path) <= strlen(path) )
		return -1;

	if( sock < 0 )
	sock = socket(AF_UNIX,SOCK_STREAM,0);

	bzero(&una,sizeof(una));
	una.sun_family = AF_UNIX;
	Xstrcpy(EVStr(una.sun_path),path);

	errno = 0;
	rcode = connectTO(sock,(struct sockaddr*)&una,sizeof(una),timeout);

	if( rcode == 0 )
		return sock;
	else{
		dbglog("#### connect_un: cannot connect, errno=%d\n",errno);
		close(sock);
		return -1;
	}
}

static int put_link(PCStr(what),PVStr(lpath),PCStr(spath))
{	FILE *lfp,*vfp;
	CStr(xspath,2048);
	CStr(msg,2048);
	int eof;
	int rcode = -1;

	msg[0] = 0;
	if( (lfp = dirfopen(what,AVStr(lpath),"w")) == NULL ){
		strcpy(msg,"can't create");
		goto EXIT;
	}
	if( lock_exclusiveTO(fileno(lfp),1000,NULL) != 0 ){
		strcpy(msg,"locked out");
		fclose(lfp);
		goto EXIT;
	}

	eof = 0;
	eof |= fputs(spath,lfp) == EOF;
	eof |= fflush(lfp) == EOF;
	lock_unlock(fileno(lfp));
	eof |= fclose(lfp) == EOF;
	if( eof ){
		strcpy(msg,"write failed");
		goto EXIT;
	}
	if( (vfp = fopen(lpath,"r")) == NULL ){
		strcpy(msg,"can't verify open");
		goto EXIT;
	}

	if( fgets(xspath,sizeof(xspath),vfp) == NULL )
		strcpy(msg,"can't verify read");
	else
	if( strcmp(xspath,spath) != 0 )
		sprintf(msg,"snatched [%s]=>[%s]",spath,xspath);
	else{
		sprintf(msg,"[%s]",spath);
		rcode = 0;
	}
	fclose(vfp);
EXIT:
	if( rcode != 0 )
		errlog("#### put_link FAILED: %s %s\n",lpath,msg);
	else	dbglog("#### put_link %s %s\n",lpath,msg);
	return rcode;
}
static int get_link(PCStr(what),PCStr(lpath),PVStr(spath),int size,int ntry)
{	FILE *lfp = NULL;
	int xtry = 0;
	int opened = 0;

	setVStrEnd(spath,0);
	for(;;){
		if( lfp == NULL )
			lfp = fopen(lpath,"r");
		else{
			clearerr(lfp);
			fseek(lfp,0,0);
		}
		if( lfp != NULL ){
			opened++;
			if( lock_sharedNB(fileno(lfp)) != 0 )
				errlog("#### get_link: locked out %s\n",lpath);
			else{
				fgets(spath,size,lfp);
				lock_unlock(fileno(lfp));
			}
		}
		if( spath[0] || ntry <= ++xtry )
			break;
		msleep(100);
	}

	if( 1 < xtry )
	errlog("#### get_link [%d/%d] %x %s <%s>\n",opened,xtry,p2i(lfp),lpath,spath);

	if( lfp != NULL)
		fclose(lfp);
	if( spath[0] )
		return 0;
	else	return -1;
}

static int is_owner(PCStr(spath))
{	const char *dp;
	int ctime,owner;

	if( dp = strrchr(spath,'/') )
		dp++;
	else	dp = spath;
	if( sscanf(dp,"%d.%d",&ctime,&owner) == 2 )
		if( owner == getpid() )
			return 1;
	return 0;
}
int bind_un(PCStr(what),PVStr(lpath),int backlog,PVStr(spath),int size)
{	CStr(file,1024);
	CStr(stime,128);
	int pid;
	int sock;
	int xtry;

	if( free_un(what,lpath,AVStr(spath),size,0) == 0 )
		errlog("#### bind_un: salvaged %s <%s>\n",lpath,spath);

	UnixSocketDir(AVStr(spath));
	pid = getpid();
	Xsprintf(TVStr(spath),"%02d/",pid % 32);
	StrftimeLocal(AVStr(stime),sizeof(stime),"%m%d%H%M%S",time(0),0);
	Xsprintf(TVStr(spath),"%s.%05d.%02d",stime,pid,++un_seqno);

	errno = 0;
	for( xtry = 0; xtry++ < 10; ){
		sock = server_open_un(what,AVStr(spath),backlog);
		if( 0 <= sock )
			break;
		if( sock < -1 )
			break;
		msleep(100);
	}

	if( 1 < xtry || sock < 0 )
		errlog("#### bind_un: %d * bind() = %d, errno=%d, %s\n",
			xtry,sock,errno,spath);

	if( 0 <= sock ){
		if( 0 < File_size(lpath) )
			errlog("#### bind_un FAILED: snatched %s\n",lpath);
		else
		if( put_link(what,AVStr(lpath),spath) != 0 )
			errlog("#### bind_un FAILED: can't link %s\n",lpath);
		else{
			dbglog("#### bind_un: bound [%s] %s\n",spath,lpath);
			return sock;
		}
		close(sock);
	}

	unlink(spath);
	return -1;
}
int free_un(PCStr(what),PCStr(lpath),PVStr(spath),int size,int if_owner)
{	int rcode;
	int do_unlink;

	setVStrEnd(spath,0);
	rcode = 0;
	do_unlink = 1;

	if( get_link(what,lpath,AVStr(spath),size,1) == 0 ){
		if( if_owner && !is_owner(spath) ){
			do_unlink = 0;
			rcode = -1;
		}else
		if( unlink(spath) == 0 ){
			rcode = 0;
			dbglog("#### free_un: freed %s\n",spath);
		}else	rcode = -2;
	}else{
		/* another process may be locking the file to write */
		do_unlink = 0;
		rcode = -3;
	}

	if( do_unlink )
		unlink(lpath);

	return rcode;
}
int connect_un(PCStr(what),PCStr(lpath),int timeout)
{	CStr(spath,1024);
	FILE *lfp;
	int sock;

	if( get_link(what,lpath,AVStr(spath),sizeof(spath),20) == 0 ){
		sock = client_open_un(what,spath,timeout);
		if( 0 <= sock ){
			dbglog("#### connect_un: connected %s\n",spath);
			return sock;
		}
		errlog("#### connect_un: cannot connect(%d) %s\n",errno,spath);
		/*
		unlink(spath);
		unlink(lpath);
		*/
	}
	return -1;
}
