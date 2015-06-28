/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1995-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	tcprelay.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950701	extracted from service.c and iotimeout.c and merged
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "vsocket.h"
#include "delegate.h"
#include "filter.h"
#include "fpoll.h"
#include "proc.h"
#include "file.h"
extern int dump_tcprelay;
extern int BREAK_STICKY;

int service_nbt(Connection *Conn)
{
	dump_tcprelay = 1;
	return relay_svcl(Conn,FromC,ToC,FromS,ToS);
}
void CTX_do_codeconv(Connection *Conn,PCStr(ccode),PCStr(src),PVStr(dst),PCStr(ctype));
int relay_svclX(Connection *Conn,int fromC,int toC,int fromS,int toS,int ins);
void CTX_relay_lines(Connection *Conn,int timeout,int flush,PCStr(C1),int S1,int D1,PCStr(C2),int S2,int D2);
int closeFilters(Connection *Conn,PCStr(what));

static int tcprelay1(int in,int out){
	IStr(buff,32*1024);
	int trcc = 0,nr = 0;
	int rcc,wcc;
	double St;

	for(;;){
		PollIn(in,0);
		rcc = read(in,buff,sizeof(buff));
		if( 0 < rcc ){
			nr++;
			trcc += rcc;
		}
		Verbose("[%04X][%2d <= %2d] rcc=%d %d/%d\n",TID,out,in,rcc,
			trcc,nr);
		if( rcc <= 0 ){
			break;
		}
		St = Time();
		wcc = write(out,buff,rcc);
		Verbose("[%04X][%2d <= %2d] rcc=%d wcc=%d (%.3f)\n",TID,
			out,in,rcc,wcc,Time()-St);
		if( wcc < rcc ){
			break;
		}
	}
	return 0;
}
int service_tcprelay2(Connection *Conn){
	int tid;
	expsockbuf(ToC,0,256*1024);
	tid = thread_fork(0,0,"tcprelay1",(IFUNCP)tcprelay1,FromC,ToS);
	tcprelay1(FromS,ToC);
	return 0;
}
int service_tcprelay(Connection *Conn)
{
	if( ToS < 0 && FromS < 0  ){
		if( isMYSELF(DST_HOST) ){
			ToS = fileno(stdout);
			FromS = fileno(stdin);
			if( file_isreg(FromS) ){
				fseek(stdin,0,0);
			}
			BREAK_STICKY = 1;
			/*
			ToS = dup(fileno(stdout));
			FromS = dup(fileno(stdin));
			sv1log("TCPRELAY for stdin,stdout [%d,%d] <- [%d,%d]\n",
				FromS,ToS,fileno(stdout),fileno(stdin));
			*/
		}else	return -1;
	}

	/*
	if( CTX_cur_codeconvCL(Conn,VStrNULL) ){
	*/
	if( CTX_cur_codeconvCL(Conn,VStrNULL) || CCXactive(CCX_TOSV)){
		CTX_check_codeconv(Conn,1);
		CTX_relay_lines(Conn,0,0,
			CCV_TOCL,FromS,ToC,
			CCV_TOSV,FromC,ToS /*,NULL*/);
	}else{
		relay_svclX(Conn,FromC,ToC,FromS,ToS,1);
	}
	close_FSV(Conn);
	close(ToS); ToS = -1;
	close(FromS); FromS = -1;

	/* 9.8.6 closing ToC is necessary to finish FTOCL */
	/* and to stop the leak of the descriptor for the pipe */
	closeFilters(Conn,"Tcprelay");

	/* 9.9.3 close TLS=fsv filter */
	waitFilterThread(Conn,100,XF_FSV);
	return 0;
}
extern int IO_TIMEOUT;
int in2sock(Connection *Conn,int infd,int *pidp);
void relays(int timeout,int sdc,int sdv[][2],int rccs[]);

int getpeerVSAddr(int sock,VSAddr *vsa);
int SOCKS_sendto0(int sock,PCStr(msg),int len,int flags,VSAddr *to,VSAddr *via,int isconn,int si);
int SOCKS_Recvfrom(int sock,PVStr(msg),int len,int flags,VSAddr *from,int *fromlen);

int relayUDPSOCKS(Connection *Conn,int toC,int fromC,int toS,int fromS){
	const char *aaddr;
	VSAddr to,via,rfrom;
	int timeout,nfd;
	int ifv[4],irv[4],ofv[4],ccv[4],nin[4];
	CStr(buf,8*1024);
	int rlen;
	int rcc,wcc;
	int isconn = 0;

	aaddr = gethostaddr(DST_HOST);
	if( aaddr == NULL ){
		return -1;
	}
	VSA_atosa(&to,DST_PORT,aaddr);

	bzero(&via,sizeof(VSAddr));
	VSA_aptosa(&via,Conn->sv.p_SOCKSADDR);
	if( getpeerVSAddr(toS,&via) == 0 ){
		CStr(peer,128);
		isconn = 1;
		getpeerName(toS,AVStr(peer),"%A:%P");
		Verbose("## connected [%s][%s]\n",peer,Conn->sv.p_SOCKSADDR);
	}else{
		Verbose("## cant get peer, using %s\n",Conn->sv.p_SOCKSADDR);
	}


	ifv[0] = fromC; ofv[0] = toS; ccv[0] = 0; nin[0] = 0;
	ifv[1] = fromS; ofv[1] = toC; ccv[1] = 0; nin[1] = 0;
	ifv[2] = Conn->sv.p_SOCKSCTL;
	timeout = IO_TIMEOUT * 1000;
	nfd = 3;

	for(;;){
		if( PollIns(timeout,nfd,ifv,irv) <= 0 ){
			break;
		}
		if( irv[0] ){
			rcc = read(ifv[0],buf,sizeof(buf));
			if( rcc <= 0 ){
				break;
			}
			wcc = SOCKS_sendto0(ofv[0],buf,rcc,0,&to,&via,isconn,0);
			ccv[0] += rcc;
			nin[0] += 1;
		}
		if( irv[1] ){
			rcc = SOCKS_Recvfrom(ifv[1],AVStr(buf),sizeof(buf),0,&rfrom,&rlen);
			wcc = write(ofv[1],buf,rcc);
			ccv[1] += rcc;
			nin[1] += 1;
		}
		if( irv[2] ){
			timeout = 1000;
			nfd = 2;
			sv1log("UDPSOCKS disconnected control: %d\n",ifv[2]);
		}
	}
	sv1log("relayUDPSOCKS [%d>%d]%d/%d [%d>%d]%d/%d\n",
		ifv[0],ofv[0],ccv[0],nin[0],
		ifv[1],ofv[1],ccv[1],nin[1]);
	return 0;
}

int relay_svclX(Connection *Conn,int fromC,int toC,int fromS,int toS,int ins)
{	int sdv[2][2];
	int cnt[2];
	int pid0,pid1;

	if( ins ){
		pid0 = pid1 = 0;
		if( !INHERENT_fork() )
		{
			/* Win32: no poll/select for consol */
			if( !file_ISSOCK(fromC) ){
				fromC = in2sock(Conn,fromC,&pid0); 
			}
			if( !file_ISSOCK(fromS) ){
				fromS = in2sock(Conn,fromS,&pid1); 
			}
		}
	}

	if( 0 <= Conn->sv.p_SOCKSCTL ){
		return relayUDPSOCKS(Conn,toC,fromC,toS,fromS);
	}

	sdv[0][0] = fromC; sdv[0][1] = toS;
	sdv[1][0] = fromS; sdv[1][1] = toC;
	relays(IO_TIMEOUT*1000,2,sdv,cnt);

	if( ins ){
		if( pid0 ) KillTERM(pid0);
		if( pid1 ) KillTERM(pid1);
	}
	return cnt[1];
}
int relay_svcl(Connection *Conn,int fromC,int toC,int fromS,int toS)
{
	return relay_svclX(Conn,fromC,toC,fromS,toS,0);
}
int relayf_svcl(Connection *Conn,FILE *fc,FILE *tc,FILE *fs,FILE *ts)
{	int cc;
	CStr(buf,512);

	while( 0 < (cc = fgetBuffered(AVStr(buf),sizeof(buf),fc)) )
		fputs(buf,ts);
	fflush(ts);
	while( 0 < (cc = fgetBuffered(AVStr(buf),sizeof(buf),fs)) )
		fputs(buf,tc);
	fflush(tc);
	return relay_svcl(Conn,fileno(fc),fileno(tc),fileno(fs),fileno(ts));
}

int simple_relayTimeout(int src,int dst,int timeout);
int simple_relayfTimeout(FILE *src,FILE *dst,int timeout);
int simple_relay(int src,int dst)
{
	return simple_relayTimeout(src,dst,IO_TIMEOUT*1000);
}
int simple_relayf(FILE *src,FILE *dst)
{
	return simple_relayfTimeout(src,dst,IO_TIMEOUT*1000);
}

void CTX_relay_lines(Connection *Conn,int timeout,int flush,PCStr(C1),int S1,int D1,PCStr(C2),int S2,int D2)
{	FILE *rfv[2]; /**/
	FILE *wfv[2]; /**/
	const char *ccv[2]; /**/
	char code;
	int wcv[2],rdv[2],nready;
	int fpc,fi;
	CStr(iline,1024);
	CStr(xline,4096);
	const char *oline;

	ccv[0] = C1; rfv[0] = fdopen(S1,"r"); wfv[0] = fdopen(D1,"w");
	ccv[1] = C2; rfv[1] = fdopen(S2,"r"); wfv[1] = fdopen(D2,"w");
	wcv[0] = wcv[1] = 0;
	fpc = 2;

	for(;;){
		nready = 0;
		for( fi = 0; fi < fpc; fi++ )
			if( 0 < ready_cc(rfv[fi]) )
				nready++;
		if( nready == 0 )
			for( fi = 0; fi < fpc; fi++ ){
				fflush(wfv[fi]);
				wcv[fi] = 0;
			}

		if( fPollIns(timeout,fpc,rfv,rdv) < 0 )
			break;

		for( fi = 0; fi < fpc; fi++ ){
		    if( 0 < rdv[fi] ){
			if( fgets(iline,sizeof(iline),rfv[fi]) == NULL )
				goto gotEOF;

			if( ccv[fi] == NULL )
				oline = iline;
			else
			if( ccv[fi] == CCV_TOSV && CCXactive(CCX_TOSV) ){
				CCXexec(CCX_TOSV,iline,strlen(iline),
					AVStr(xline),sizeof(xline));
				oline = xline;
			}
			else{
				CTX_do_codeconv(Conn,ccv[fi],iline,AVStr(xline),"text/plain");
				oline = xline;
			}

			if( fputs(oline,wfv[fi]) == EOF )
				goto gotEOF;

			wcv[fi] += strlen(oline);
			if( 0 < flush && flush < wcv[fi] ){
				fflush(wfv[fi]);
				wcv[fi] = 0;
			}
		    }
		}
	}
gotEOF:
	for( fi = 0; fi < fpc; fi++ ){
		fclose(rfv[fi]);
		fclose(wfv[fi]);
	}
}

static void in2sock1(Connection *Conn,int clsock,int svsock,int ac,char *av[],PCStr(arg))
{	CStr(buf,256);
	int rcc,wcc;

	/* must watch disconnection of svsock while reading ... */
	while( 0 < (rcc = read(0,buf,sizeof(buf))) ){
		if( buf[0] == 'D'-0x40 ) /* control-D dose not cause EOF */
			break;
		wcc = write(svsock,buf,rcc);
		if( wcc <= 0 )
			break;
	}
}
int in2sock(Connection *Conn,int infd,int *pidp)
{	int sock[2];

	Socketpair(sock);
	setCloseOnExecSocket(sock[0]);
	*pidp = execFunc(Conn,-1,sock[1],(iFUNCP)in2sock1,"");
	clearCloseOnExecSocket(sock[0]);
	close(sock[1]);
	return sock[0];
}

extern int enbugSelect;
int file_ISSOCK(int fd);
int shutdownWR(int fd);
int ShutdownSocketRDWR(int fd);
int ShutdownSocket(int sock);
int INET_Socketpair(int sv[]);
static int poll1(FILE *out,int fdv[2],int timeout,PCStr(wh)){
	int fd,rdv[2],rdy,rdys,issk,isco;
	IStr(host,128);

	fd = fdv[1];
	rdy = PollIn(fd,timeout);
	errno = 0;
	rdys = PollIns(timeout,2,fdv,rdv);
	issk = file_ISSOCK(fd);
	isco = IsConnected(fd,0);
	Uname(AVStr(host));
	fprintf(out,"[%s] rdy = %2d %2d (%d) issock=%d/%d OOB=%d e%d ... %s\n",
		host,rdy,rdys,rdv[1],issk,isco,gotOOB(-1),errno,wh);
	return 0;
}
int seltest(FILE *out){
	int sp0[2],sp1[2],fdv[2];

	enbugSelect = 1;
	INET_Socketpair(sp0);
	INET_Socketpair(sp1);
	fdv[0] = sp0[0];
	fdv[1] = sp1[0];

	poll1(out,fdv,1,"initial");
	close(sp1[1]);
	poll1(out,fdv,1,"after remote close");
	msleep(100);
	poll1(out,fdv,1,"after remote close-2");
	shutdownWR(sp1[0]);
	poll1(out,fdv,1,"after local shutdownWR");
	ShutdownSocketRDWR(sp1[0]);
	poll1(out,fdv,1,"after local ShutdownRDWR");
	return 0;
}
int seltest_main(int ac,const char *av[]){
	seltest(stdout);
	return 0;
}
