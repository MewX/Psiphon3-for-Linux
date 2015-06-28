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
Program:	distrib.c (cache data distributor)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	960501	created
//////////////////////////////////////////////////////////////////////#*/
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include "delegate.h"
#include "ystring.h"
#include "fpoll.h"
#include "proc.h"
#include "vsignal.h"
extern int CON_TIMEOUT;

int connect_un(PCStr(what),PCStr(lpath),int timeout);
int free_un(PCStr(what),PCStr(lpath),PVStr(spath),int size,int if_owner);
int bind_un(PCStr(what),PVStr(lpath),int backlog,PVStr(spath),int size);
void HTTP_clntClose(Connection *Conn,PCStr(fmt),...);

void detachFile(FILE *fp);
static void flushDistribution(Connection *Conn,FILE *cachefp,int eof);

#define errlog	sv1log
#define dbglog	Verbose

int makeDistribution(Connection *Conn,FILE *cachefp,PCStr(cpath))
{	int sock;
	CStr(lpath,4096);
	CStr(spath,1024);

	if( !INHERENT_fork() )
		return -1;
	if( actthreads() ){
		/* 9.6.1 fork() after thread_fork() seems to cause jamming */
		return -1;
	}

	sprintf(lpath,"%s#rdist",cpath);
	sock = bind_un("RESPDIST",AVStr(lpath),10,AVStr(spath),sizeof(spath));
	if( sock < 0 )
		sv1log("#### FAILED makeDistribution: (%d) %s\n",errno,lpath);
	else{
		dbglog("#### makeDistribution: [%d] %s\n",sock,lpath);
		Conn->ca_distsock_open = 1;
		Conn->ca_distsock = sock;
	}
	return sock;
}

FILE *recvDistribution(Connection *Conn,PCStr(cpath),int *updated)
{	CStr(lpath,4096);
	int start;
	int sock;
	FILE *fs;
	CStr(stat,4096);
	const char *dp;
	int timeout;

	*updated = 0;
	if( !INHERENT_fork() )
		return NULL;

	start = time(0);
	sprintf(lpath,"%s#rdist",cpath);

	/* the cache server may be the client that is using this delegated
	 * as a MASTER and is waiting the response from this delegated.
	 * Such a loop can be avoided by checking X-Locking in HTTP, but
	 * it is not so conclete and generic way...
	 */
	timeout = CON_TIMEOUT;
	sock = connect_un("RESPDIST1",lpath,timeout*1000);
	*updated = 0;

	if( sock < 0 ){
		errlog("#### can't open recvDistribution (%d) %d %s\n",
			ll2i(time(0)-start),errno,lpath);
		return NULL;
	}
	dbglog("#### connected recvDistribution: %s\n",lpath);
	if( timeout < 10 )
		timeout = 10;
	if( PollIn(sock,timeout*1000) <= 0 ){
		close(sock);
		errlog("#### timed out recvDistribution (%d) %s\n",
			ll2i(time(0)-start),lpath);
		return NULL;
	}
	fs = fdopen(sock,"r");
	if( fgets(stat,sizeof(stat),fs) == NULL )
		sprintf(stat,"500 connection closed(%d)",ll2i(time(0)-start));
	if( dp = strpbrk(stat,"\r\n") )
		truncVStr(dp);

	errlog("#### got recvDistribution(%d): %s %s\n",sock,stat,lpath);

	if( *stat == '2' )
	{
		ServerFlags |= PF_IS_DISTRIB;
		return fs;
	}
	else{
		*updated = 1;
		fclose(fs);
		sleep(1); /* wait stopDistribution() done ... X-0 */
		return NULL;
	}
}

static int nsigPIPE = 0;
static void sigPIPE(int sig)
{
	signal(SIGPIPE,SIG_IGN); /* sv1log may cause SIGPIPE ... */
	nsigPIPE++;
	sv1log("## got SIGPIPE [%d] in stopDistribution\n",nsigPIPE);
	signal(SIGPIPE,sigPIPE);

}
void stopDistribution(Connection *Conn,FILE *cachefp,PCStr(cpath))
{	CStr(lpath,4096);
	CStr(spath,1024);
	int rsock;
	int rcode;
	vfuncp sigpipe;

	if( !Conn->ca_distsock_open )
	{
		/* 9.9.3 sweep the socket left by "STOP sendDistribtion" */
		if( Conn->ca_distsock == -2 ){
			sv1log("## sweep socket(%s)\n",cpath);
			goto UnLink;
		}
		return;
	}

	if( 1 < Conn->ca_receptorN )
		errlog("#### stopDistribution: %d\n",Conn->ca_receptorN);
	else	dbglog("#### stopDistribution: %d\n",Conn->ca_receptorN);

	sigpipe = Vsignal(SIGPIPE,sigPIPE);
	flushDistribution(Conn,cachefp,1);
	Vsignal(SIGPIPE,sigpipe);

	/*
	while( 0 < PollIn(Conn->ca_distsock,100) ){
	*/
	while( 0 < PollIn(Conn->ca_distsock,1) ){
		rsock = ACCEPT(Conn->ca_distsock,1,-1,10);
		/*
		errlog("#### discard accepted Distribution [%d]->[%d]\n",
			Conn->ca_distsock,rsock);
		*/
		errlog("#### discard accepted Distribution [%d]->[%d] err=%d\n",
			Conn->ca_distsock,rsock,errno);
		if( rsock < 0 )
			break;
		close(rsock);
	}

UnLink:
	sprintf(lpath,"%s#rdist",cpath);
	rcode = free_un("RESPDIST",lpath,AVStr(spath),sizeof(spath),1);
	if( Conn->ca_distsock == -2 ){
		errlog("## swept free_un=%d %s <%s>\n",rcode,lpath,spath);
	}else
	if( rcode == 0 )
		dbglog("#### free_un=%d %s <%s>\n",rcode,lpath,spath);
	else	errlog("#### free_un=%d %s <%s>\n",rcode,lpath,spath);

	close(Conn->ca_distsock);
	Conn->ca_distsock = -1;
	Conn->ca_distsock_open = 0;
}

static int copy1(FILE *cachefp,int toC,int from,int doflush)
{	int savoff,leng,rcc,rcc1,wcc,wcc1;
	CStr(buff,4096);

	fflush(cachefp);
	savoff = ftell(cachefp);
	fseek(cachefp,from,0);
	leng = savoff - from;

	rcc = 0;
	wcc = 0;
	while( rcc < leng ){
		if( sizeof(buff) < leng - rcc )
			rcc1 = sizeof(buff);
		else	rcc1 = leng - rcc;
		rcc1 = fread(buff,1,rcc1,cachefp);
		if( rcc1 == 0 )
			break;
		rcc += rcc1;
		wcc1 = write(toC,buff,rcc1);
		if( 0 < wcc1 )
			wcc += wcc1;

		if( wcc1 != rcc1 ){
if( 2 <= LOGLEVEL )
Verbose("#### [%d] write incomplete Distribution %d / %d\n",toC,wcc1,rcc1);
			break;
		}
	}

if( 2 <= LOGLEVEL )
Verbose("#### [%d] Distribution %d / %d [%d-%d]\n",toC,wcc,leng,from,savoff);
	fseek(cachefp,savoff,0);
	return wcc;
}

static void flushDistribution(Connection *Conn,FILE *cachefp,int eof)
{	int rx;
	int wcc;
	int nput;
	/*
	int *receptors;
	*/
	short *receptors;
	int *putoff;
	int remain;
	int lastput;
	int idle;

	receptors = Conn->ca_receptors;
	putoff = Conn->ca_putoff;
	lastput = time(0);

	for(;;){
		nput = 0;
		for( rx = 0; rx < Conn->ca_receptorN; rx++ ){
			if( putoff[rx] == Conn->ca_curoff )
				continue;
			if( putoff[rx] < 0 ){
				continue;
			}
			nsigPIPE = 0;
			wcc = copy1(cachefp,receptors[rx],putoff[rx],1);
			if( 0 < wcc ){
				nput += wcc;
				putoff[rx] += wcc;
if( 2 <= LOGLEVEL )
Verbose("#### (%d)[%d] sendDistribution: caught up %d (%d/%d)\n",
	rx,receptors[rx], wcc,putoff[rx],Conn->ca_curoff);
			}else
			if( nsigPIPE ){
errlog("#### (%d)[%d] flushDistribution: caught SIGPIPE (%d)\n",
	rx,receptors[rx], putoff[rx]);
				if( 0 < putoff[rx] )
					putoff[rx] = -putoff[rx];
				else	putoff[rx] = -1;
			}
			else
			if( wcc <=0 && IsConnected(receptors[rx],NULL) == 0 ){
errlog("---- (%d)[%d] flushDistribution: disconnected (%d/%d)\n",
	rx,receptors[rx],putoff[rx],Conn->ca_curoff);
				if( 0 < putoff[rx] )
					putoff[rx] = -putoff[rx];
				else	putoff[rx] = -2;
			}
		}
		if( !eof )
			break;

		remain = 0;
		for( rx = 0; rx < Conn->ca_receptorN; rx++ ){
			if( receptors[rx] == -1 )
				continue;
			if( putoff[rx] == Conn->ca_curoff || putoff[rx] < 0 ){
errlog("#### (%d)[%d] closed Distribution: %d bytes\n",
	rx,receptors[rx], putoff[rx]);
				close(receptors[rx]);
				receptors[rx] = -1;
			}else	remain++;
		}
		if( remain == 0 )
			break;

		if( nput ){
			lastput = time(0);
		}else{
			idle = time(0) - lastput;
			if( 120 < idle ){
				errlog("#### timeout flushDistribution (%d)\n",
					remain);
				break;
			}
			if( idle )
				sleep(1);
			else	msleep(100);
			/* should be replaced with PollOuts() */
		}
	}
}

static void closeServer(Connection *Conn,FILE *fs,FILE *cachefp,int infd)
{	int rcc;

	dup2(infd,fileno(fs));
	close(infd);
	for( rcc = 0; 0 < ready_cc(fs); rcc++ )
		getc(fs);
	clearerr(fs);

	detachFile(cachefp);

	close(Conn->ca_distsock);
	Conn->ca_distsock = -1;
	Conn->ca_distsock_open = 0;
}

static int accept2(Connection *Conn,int rsock)
{	int rx;

	expsockbuf(rsock,0,0x20000);
	rx = Conn->ca_receptorN++;
	Conn->ca_receptors[rx] = rsock;
	errlog("#### (%d)[%d] accept cache Distribution request\n",rx,rsock);
	setNonblockingIO(rsock,1);
	if( 0 < DELEGATE_LINGER )
		set_linger(rsock,DELEGATE_LINGER);
	return rx;
}

static void accept1(Connection *Conn,int svsock,FILE *cachefp)
{	int rsock;
	int rx;
	CStr(msg,1024);
	int wcc;

	rsock = ACCEPT(svsock,1,-1,10);
	if( rsock < 0 )
		return;
	rx = accept2(Conn,rsock);
	sprintf(msg,"200 You are #%d\r\n",rx);
	IGNRETP write(rsock,msg,strlen(msg));
	wcc = copy1(cachefp,rsock,0,0);
	Conn->ca_putoff[rx] = wcc;
}

static void distrib(Connection *Conn,PCStr(buff),int leng)
{
/*
{	int *receptors;
*/
	short *receptors;
	int *putoff;
	int rx,wcc;

	receptors = Conn->ca_receptors;
	putoff = Conn->ca_putoff;

	for( rx = 0; rx < Conn->ca_receptorN; rx++ ){
		/* send to syncronized receivers only. other receivers will be
		 * syncronized (catch up) by flushDistirbution()
		 */
		if( putoff[rx] != Conn->ca_curoff )
			continue;

		wcc = write(receptors[rx],buff,leng);
		if( wcc != leng ){
if( 2 <= LOGLEVEL )
Verbose("#### (%d)[%d] sendDistribution incomplete: %d/%d/%d\n",
	rx,receptors[rx], wcc,leng,Conn->ca_curoff);
		}
		if( 0 < wcc )
			putoff[rx] += wcc;
	}
}

int sendDistribution(Connection *Conn,FILE *cachefp,FILE *fs,FILE *tc,PCStr(buff),int leng)
{	int timeout,fdv[2],rfdv[2];
	int off;
	double Start;
	int nready;

	if( cachefp == NULL || !Conn->ca_distsock_open )
		return 0;

	if( !INHERENT_fork() )
		return 0;

	if( actthreads() ){
		/* 9.6.3 response is in some encoding */
		sv1log("## STOP sendDistribution: ath=%d [%d/%d] %d\n",
			actthreads(),
			Conn->ca_distsock,Conn->ca_distsock_open,
			Conn->ca_receptorN
		);
		/* should unlink the socket */
		close(Conn->ca_distsock);
		/*
		Conn->ca_distsock = -1;
		*/
		Conn->ca_distsock = -2; /* to be swept */
		Conn->ca_distsock_open = 0;
		return 0;
	}

	ClientEOF &= ~CLEOF_NOACTCL;
	if( 0 < Conn->ca_receptorN ){
		int rx;
		int act = 0;
		for( rx = 0; rx < Conn->ca_receptorN; rx++ ){
			if( 0 <= Conn->ca_putoff[rx] ){
				act = 1;
				break;
			}
		}
		if( act == 0 ){
			sv1log("---- no active Distribution recveiver/%d\n",
				Conn->ca_receptorN);
			ClientEOF |= CLEOF_NOACTCL;
		}
	}

	distrib(Conn,buff,leng);

	off = Conn->ca_curoff;
	Conn->ca_curoff += leng;

	if( off == 0 || 0 < ready_cc(fs) && off/1024 == Conn->ca_curoff/1024 )
		return 0;

	flushDistribution(Conn,cachefp,0);

	fdv[0] = fileno(fs);
	fdv[1] = Conn->ca_distsock;

	/*
	 * wait a new parallel receiver of the data, or new data (or
	 * disconnection) from server.
	 * this is bad when Connection:Keep-Alive is used with the server
	 * because connection is not reset at the end of data.
	 */
	if( Time()-CONN_DONE <= 5 ){
		return 0;
	}
	if( 0 < ready_cc(fs) )
		timeout = 10;
	else	timeout = 1000;

	Start = Time();
	nready =
	PollIns(timeout,2,fdv,rfdv);
	if( 2 <= LOGLEVEL && nready == 0
	 || 3 <= LOGLEVEL && (1 < Time()-Start) ){
		sv1log("---- sendDistribution: ready=%d [%d][%d] %f/%d\n",
			nready,fileno(fs),fdv[1],Time()-Start,timeout);
	}
	if( rfdv[1] <= 0 )
		return 0;

	if( Conn->ca_receptorN == 0 ){
		int sio[2];

		fflush(tc);
		fflush(cachefp);

		Socketpair(sio);
		if( Fork("CacheDistributor") == 0 ){
			checkCloseOnTimeout(0);
			closeServer(Conn,fs,cachefp,sio[0]);
			close(sio[1]);
			ServerFlags |= PF_IS_DISTRIB;
			return 1;
		}else{
			int rx;
			detachFile(tc);
			ClientEOF = 1;
			ClientFlags |= PF_IS_DISTRIB;
			Vsignal(SIGPIPE,sigPIPE);
			close(sio[0]);
			rx = accept2(Conn,sio[1]);
			Conn->ca_putoff[rx] = ftell(cachefp);

HTTP_clntClose(Conn,"-:distributor");
/* close clsock ? */
			/* 9.6.3 to disable threads for gzip (wont happen) */
			LOG_type2 |= L_NOTHREAD;
		}
	}
	accept1(Conn,fdv[1],cachefp);
	return 2;
}

int dupclosed_FL(FL_PAR,int fd);
void detachFile(FILE *fp)
{	int fd,null;

	if( lSINGLEP() ){
		fprintf(stderr,"---ignored detachFile %X/%d\n",p2i(fp),fileno(fp));
		return;
	}

	if( actthreads() ){
		/* 9.9.4 the following can do close re-used fd by others */
		putfLog("detachFile(%X/%d)",p2i(fp),fileno(fp));
		dupclosed_FL(FL_ARG,fileno(fp));
		return;
	}
	fd = fileno(fp);
	close(fd);
	null = open("/dev/null",2);
	if( fd != null ){
		/* the fd below might be re-used by others already */
	dup2(null,fd);
	close(null);
	}
}
