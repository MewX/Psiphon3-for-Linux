/*
 *	@select.c: this file will be loaded in systems with select()
 */
#include "ystring.h"
#include "log.h"
#include <stdio.h>
#include "vsocket.h"
#include "yselect.h" /* FD_SETSIZE and FD_SET(),etc. */
/*void bzero(void *b, size_t length); *//* for FD_ZERO */

int connRESETbypeer(){ return -1; }
int connHUP(){ return -1; }
int PollIn_HUP(int on){ return -1; }

int file_ISSOCK(int fd);
int IsConnected(int sock,const char **reason);
int BrokenSocket(FL_PAR,int fd);

int PollOut(int fd,int timeout)
{	struct timeval tv;
	FdSet mask;
	int nready;
	int ofd = fd;
	FdSet xmask;
	int issock;
	int iscon;

	if( fd < 0 )
		return -1;
	fd = SocketOf(fd);

	if( timeout == TIMEOUT_IMM ){
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	}else
	if( timeout ){
		tv.tv_sec  = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}
	FD_ZERO(&mask);
	FD_SET(fd,&mask);

	if( lWINSOCK() ){
		issock = file_ISSOCK(ofd);
		iscon = IsConnected(ofd,0);
		xmask = mask;
	}
	nready = select(FD_SETSIZE,NULL,&mask,NULL,timeout?&tv:NULL);

	if( lWINSOCK() && nready < 0 ){
	  porting_dbg("-- %X PollOut(%d/%d/%d,%d)=%d %X/%X %X/%X %d/%d c%d/%d",
		TID,fd,SocketOf(ofd),ofd,timeout,nready,
		xp2i(&xmask),FD_ISSET(fd,&xmask),xp2i(&mask),FD_ISSET(fd,&mask),
		issock,file_ISSOCK(ofd),iscon,IsConnected(ofd,0));
	}
	if( nready <= 0 )
		return nready;
	return FD_ISSET(fd,&mask) ? 1 : 0;
}

int _gotOOB;

int PollIn1(int fd,int timeout)
{	struct timeval tv;
	FdSet Rmask,Xmask;
	int nready;
	int ofd = fd;

	if( fd < 0 )
		return -1;
	fd = SocketOf(fd);

	if( timeout == TIMEOUT_IMM ){
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	}else
	if( timeout ){
		tv.tv_sec  = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}

	_gotOOB = 0;
	FD_ZERO(&Rmask);
	FD_SET(fd,&Rmask);
	Xmask = Rmask;
	nready = select(FD_SETSIZE,&Rmask,NULL,&Xmask,timeout?&tv:NULL);
	if( nready <= 0 )
		return nready;
	if( FD_ISSET(fd,&Xmask) )
	{
		if( BrokenSocket(FL_ARG,ofd) ){
		}else
		_gotOOB = ofd+1;
	}
	return FD_ISSET(fd,&Rmask) ? 1 : 0;
}

int file_ISSOCK(int fd);
int getsocktype(int fd);

int PollIns(int timeout,int size,int *mask,int *rmask)
{	struct timeval tvbuf,*tv;
	int fi,fd,maxfd;
	FdSet Rmask,Xmask;
	int nready,rready;

	if( timeout == TIMEOUT_IMM ){
		tv = &tvbuf;
		tv->tv_sec  = 0;
		tv->tv_usec = 0;
	}else
	if( timeout ){
		tv = &tvbuf;
		tv->tv_sec  = timeout / 1000;
		tv->tv_usec = (timeout % 1000) * 1000;
	}else	tv = NULL;

	_gotOOB = 0;
	maxfd = -1;
	FD_ZERO(&Rmask);
	for(fi = 0; fi < size; fi++){
		fd = mask[fi];
		fd = SocketOf(fd);

		if( 0 <= fd ){
			FD_SET(fd,&Rmask);
			if( maxfd < fd )
				maxfd = fd;
		}
		rmask[fi] = 0;
	}
	Xmask = Rmask;
	nready = select(SELECT_WIDTH(maxfd),&Rmask,NULL,&Xmask,tv);
	if( nready < 0 && isWindows() ){
		for( fi = 0; fi < size; fi++ ){
			fd = mask[fi];
			if( SocketOf(fd) <= 0 )
			porting_dbg("PollIns(%d/%d) select(%d/%d) NOT SOCKET",
				fi,size,SocketOf(fd),fd);
		}
	}
	if( nready <= 0 )
		return nready;

	rready = 0;
	for(fi = 0; fi < size; fi++){
		int ofd = mask[fi];
		fd = mask[fi];
		fd = SocketOf(fd);

		if( 0 <= fd ){
/*
			if( FD_ISSET(fd,&Rmask) ){
*/
			if( FD_ISSET(fd,&Rmask) || FD_ISSET(fd,&Xmask) ){

 if( lPOLL() )
 fprintf(stderr,"----[%2d/%2d]%d,%d R:%X X:%X\n",fd,ofd,
	file_ISSOCK(fd),getsocktype(fd),
	FD_ISSET(fd,&Rmask),FD_ISSET(fd,&Xmask));

	/* Xmask seems to be set unconditionally for regular file ... */
				if( FD_ISSET(fd,&Xmask) ){
					/*
					if( !file_ISSOCK(fd) ){
					*/
					if( !file_ISSOCK(ofd) ){ /* 9.9.6 Win */
	/* Xmask is set on EOF of pipe on FreeBSD where pipe is not socket */
			syslog_ERROR("[%d/%d] select() detected EOF\n",fd,ofd);
					}else
					if( BrokenSocket(FL_ARG,ofd) ){
						/* 9.9.7 FreeBSD8 and CYGWIN */
			syslog_ERROR("[%d/%d] select() detected RST\n",fd,ofd);
					}else{
					_gotOOB = ofd+1;
			syslog_DEBUG("[%d/%d] select() detected OOB\n",fd,ofd);
					}
					if( FD_ISSET(fd,&Rmask) == 0 )
			syslog_ERROR("[%d/%d] OOB only\n",fd,ofd);
				}
				rready++;
				rmask[fi] = 1;
			}else	rmask[fi] = 0;
		}else	rmask[fi] = 0;
	}
	return rready;
}

int withOOB(int fd){
	FdSet Xmask;
	struct timeval tvbuf,*tv;
	int ready;

	if( fd < 0 ){
		syslog_ERROR("[%d] withOOB BAD-FD\n",fd);
		return 0;
	}
	fd = SocketOf(fd);
	tv = &tvbuf;
	FD_ZERO(&Xmask);
	FD_SET(fd,&Xmask);
	tv->tv_sec  = 0;
	tv->tv_usec = 0;
	ready = select(SELECT_WIDTH(fd),NULL,NULL,&Xmask,tv);
	syslog_DEBUG("[%d] withOOB ? %d %X\n",fd,ready,FD_ISSET(fd,&Xmask));
	if( 0 < ready ){
		if( FD_ISSET(fd,&Xmask) )
			return 1;
	}
	return 0;
}

int PollInsOuts(int timeout,int nfds,int fdv[],int ev[],int rev[])
{	fd_set rfds,wfds,xfds;
	int fi,fd,ev1,ev2;
	int ofd;
	int width;
	struct timeval tv;
	struct timeval *tvp;
	int nready;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&xfds);

	width = 0;
	for( fi = 0; fi < nfds; fi++ ){
		fd = fdv[fi];
		if( fd < 0 ){
			/* negative fd is not error but ignored in poll() */
			continue;
		}
		fd = SocketOf(fd);
		if( width < fd )
			width = fd;
		ev1 = ev[fi];
		if( ev1 & PS_IN  ) FD_SET(fd,&rfds);
		if( ev1 & PS_OUT ) FD_SET(fd,&wfds);
		if( ev1 & PS_PRI ) FD_SET(fd,&xfds);
	}
	/*
	if( timeout ){
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}
	nready = select(SELECT_WIDTH(width),&rfds,&wfds,&xfds,timeout?&tv:NULL);
	*/
	if( timeout == TIMEOUT_IMM ){
		tvp = &tv;
		tv.tv_sec  = 0;
		tv.tv_usec = 0;
	}else
	if( timeout < 0 ){ /* spec. of timeout of poll() */
		tvp = NULL;
	}else{
		tvp = &tv;
		tv.tv_sec = timeout / 1000;
		tv.tv_usec = (timeout % 1000) * 1000;
	}
	nready = select(SELECT_WIDTH(width),&rfds,&wfds,&xfds,tvp);
	for( fi = 0; fi < nfds; fi++ ){
		fd = fdv[fi];
		ofd = fd;
		if( fd < 0 ){
			rev[fi] = 0;
			continue;
		}
		fd = SocketOf(fd);
		ev2 = 0;
		if( FD_ISSET(fd,&rfds) ) ev2 |= PS_IN;
		if( FD_ISSET(fd,&wfds) ) ev2 |= PS_OUT;
		/*
		if( FD_ISSET(fd,&xfds) ) ev2 |= PS_PRI;
		*/
		if( FD_ISSET(fd,&xfds) ){
		    if( isWindowsCE() ){
			/* without MSG_PEEK, to set PS_PRI to show disconn. */
			ev2 |= PS_PRI;
		    }else
		    if( EccEnabled() && (ev1 & PS_OUT) ){
			/* to detect reset in non-blocking connect() */
			ev2 |= PS_PRI;
			porting_dbg("-- PollInsOut PRI [%d/%d] %X/%X",
				fd,ofd,ev2,ev1);
		    }else{
			char buf[1];
			int rcc;
			rcc = recv(fd,buf,1,MSG_PEEK|MSG_OOB);
			syslog_DEBUG("---- PollInOuts(%d)PRI OOB=%d\n",fd,rcc);
			if( 0 < rcc )
				ev2 |= PS_PRI;
		    }
		}
		rev[fi] = ev2;
	}
	return nready;
}
