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
Program:	process.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970117	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "delegate.h"
#include "fpoll.h"
#include "param.h"
#include "file.h"
#include "proc.h"
#include "vsignal.h"

int inherent_fork(PCStr(F),int L);
#define INHERENT_fork() inherent_fork(__FILE__,__LINE__)

extern const char **main_argv;

int MountSerno(PCStr(opts));
const char *setMountOptions(FL_PAR,Connection *Conn,PCStr(opts));
typedef struct {
	int sa_mountserno;
	int sa_moptslen;
} SpawnArgs;

#define CLEAR(m) (Conn->m = 0)

static void clearConnPTR(Connection *Conn)
{
	CLEAR(sv_toServ);
	CLEAR(cl_user);
	/*
	CLEAR(cl_FromCbuff);
	*/
	STX_cb.cb_buff = 0;
	CLEAR(gw.p_auth);
	CLEAR(gw_path);
	CLEAR(sv_dflt.p_auth);
	CLEAR(ht_LockedByClient);
	/*
	UTfree(&D_REQUESTtag);
	*/
if( D_REQUESTtag.ut_addr ) sv1log("#### clearConnPTR: clearing D_REQUEST\n");
	UTclear(&D_REQUESTtag);

	bzero(&Conn->dg_fthread,sizeof(Conn->dg_fthread));
	bzero(&Conn->dg_sthread,sizeof(Conn->dg_sthread));
	bzero(ConnCSC,sizeof(ConnCSC));
}

extern int CHILD_SERNO;
extern int CHILD_SERNO_MULTI;
int callFilter(Connection *Conn,int ac,const char *av[])
{	int ein,eout,rcc;
	int tcc = 0;
	int fio[2];
	FILE *in,*out;
	const char *args;
	int sock;
	int rcode;
	SpawnArgs spawnArgs;

	iLog("--- callFilter(%X,%d,%X)",p2i(Conn),ac,p2i(av));
	/*
	sscanf(av[2],"%d/%d",&ein,&eout);
	in = fdopen(ein,"r");
	*/
	/*
	sscanf(av[2],"%d/%d/%d/%d",&fio[0],&fio[1],&ein,&eout);
	*/
	sscanf(av[2],"%d/%d/%d/%d %d/%d",&fio[0],&fio[1],&ein,&eout,
		&CHILD_SERNO,&CHILD_SERNO_MULTI);
	in = fdopen(fio[0],"r");
	close(fio[1]);

	rcc = fread(&spawnArgs,1,sizeof(spawnArgs),in);
	tcc += rcc;
	if( rcc != sizeof(spawnArgs) ){
		/* 9.9.4 MTSS the caller might exited with signal */
		fprintf(stderr,"[%d] --- callFilter sA rcc=%d/%d %d\n",
			getpid(),rcc,isizeof(spawnArgs),tcc);
		fflush(stderr);
		_exit(-1);
	}
	rcc = fread(Conn,1,sizeof(Connection),in);
	tcc += rcc;
	if( rcc != sizeof(Connection) ){
		fprintf(stderr,"[%d] --- callFilter Co rcc=%d/%d %d\n",
			getpid(),rcc,isizeof(Connection),tcc);
		fflush(stderr);
		_exit(-1);
	}

	iLog("--- callFilter %d %X %X %X+%d %X:%X %d:%d:%d %X %X",rcc,
		Conn->cx_magic,LOG_bugs,p2i(Conn->cl_reqbuf),Conn->cl_reqbufsize,
		p2i(&D_REQUESTtag),p2i(D_REQUESTtag.ut_addr),
		isizeof(int),isizeof(char*),isizeof(Connection),
		xp2i(clearConnPTR),xp2i(callFilter)
	);
	if( rcc != sizeof(Connection) ){
		void initABORT(int sig);
		bzero(Conn,sizeof(Conn)); /* dumped in initABORT() */
		initABORT(0);
		Finish(-1);
		return -1;
	}
	if( Conn->cl_reqbuf ){
		Conn->cl_reqbuf = (char*)malloc(Conn->cl_reqbufsize);
		iLog("--- qbuf=%X+%d",p2i(Conn->cl_reqbuf),Conn->cl_reqbufsize);
		rcc =
		fread(Conn->cl_reqbuf,1,Conn->cl_reqbufsize,in);
		tcc += rcc;
		if( rcc != Conn->cl_reqbufsize ){
			fprintf(stderr,"[%d] --- callFilter qb rcc=%d/%d %d\n",
				getpid(),rcc,Conn->cl_reqbufsize,tcc);
			fflush(stderr);
			_exit(-1);
		}
		iLog("--- qbuf rcc=%d/%d",rcc,Conn->cl_reqbufsize);
	}

	clearConnPTR(Conn);
	fdopenLogFile(Conn->fi_logfd);

	if( 0 < Conn->fi_arglen ){
		args = (char*)malloc(Conn->fi_arglen);
		rcc = fread((char*)args,1,Conn->fi_arglen,in);
		tcc += rcc;
		if( rcc != Conn->fi_arglen ){
			fprintf(stderr,"[%d] --- callFilter fa rcc=%d/%d %d\n",
				getpid(),rcc,Conn->fi_arglen,tcc);
			fflush(stderr);
			_exit(-1);
		}
	}else{
		args = NULL;
		rcc = 0;
	}
	iLog("--- callFilter args=%d/%d %X",rcc,Conn->fi_arglen,p2i(args));

	ClientSock = -1;
	if( Conn->fi_issock ){
		if( (sock = getclientsock()) < 0 )
		sock = Conn->fi_topeer;
		if( Conn->fi_dupclsock )
			ClientSock = sock;
	}else	sock = Conn->fi_topeer;

	if( spawnArgs.sa_mountserno ){
		IStr(opts,1024); /* opts[] can be empty */
		if( 0 < spawnArgs.sa_moptslen ){
			int len = sizeof(opts)-1;
			int occ;
			if( spawnArgs.sa_moptslen < len ){
				len = spawnArgs.sa_moptslen;
			}
			occ = fread(opts,1,len,in);
			if( 0 <= occ ){
				setVStrEnd(opts,occ);
			}
		}
		setMountOptions(FL_ARG,Conn,stralloc(opts));
	}

	fclose(in);
	if( Conn->fi_iomode & 1 ){
		close(eout);
		out = fdopen(sock,"w");
		in = fdopen(ein,"r");
	}else{
		in = fdopen(sock,"r");
		out = fdopen(eout,"w");
	}

	iLog("--- callFilter %X(%X,%X,%X,%d)",xp2i(Conn->fi_func),p2i(in),p2i(out),p2i(args),rcc);
	Verbose("## callFilter: %x[%d,%d]\n",xp2i(Conn->fi_func),fileno(in),fileno(out));
	rcode = (*Conn->fi_func)(Conn,in,out,args,rcc);
	Finish(rcode?1:0);
	return -1;
}

int spawnFilter(Connection *Conn,int iomode,int tofil[],int sock,iFUNCP func,PCStr(args))
{	CStr(ein,32);
	int ac;
	const char *av[256]; /**/
	CStr(epath,1024);
	CStr(logtype,64);
	CStr(logtype2,64);
	int fin; /* input at the filter side */
	int fout; /* output at the DeleGate side */
	int pid;
	int wcc;
	int wi;
	int fio[2]; /* a pipe to inherit Conn. */
	FILE *out;
	SpawnArgs spawnArgs;

	iLog("--- spawnFilter sock=%d func=%X args=%X",sock,xp2i(func),p2i(args));
	fin = tofil[0];
	fout = tofil[1];
	pipeX(fio,8*1024);
	out = fdopen(fio[1],"w");
	sprintf(ein,"%d/%d/%d/%d %d/%d",fio[0],fio[1],fin,fout,
		CHILD_SERNO,CHILD_SERNO_MULTI);
	/*
	sprintf(ein,"%d/%d/%d/%d",fio[0],fio[1],fin,fout);
	*/
	/*
	sprintf(ein,"%d/%d",fin,fout);
	*/

	sprintf(epath,"%s=%s",P_EXEC_PATH,EXEC_PATH);
	ac = 0;
	av[ac++] = /*DeleGate1*/ "DeleGate";
	av[ac++] = /*FuncFILTER*/ "(Filter)";
	av[ac++] = ein;
	av[ac++] = epath;

	/*
	sprintf(logtype,"-L0x%x",LOG_type);
	*/
	sprintf(logtype,"-L0x%x/%d",LOG_type,curLogFd());
	av[ac++] = logtype;
	if( LOG_type2 || LOG_bugs ){
		sprintf(logtype2,"-L20x%x/%x",LOG_type2,LOG_bugs);
		av[ac++] = logtype2;
	}
	ac += copy_param("f",elnumof(av)-ac,&av[ac],&main_argv[1]);
	av[ac] = NULL;

	Conn->fi_func = func;
	if( args == NULL )
		Conn->fi_arglen = 0;
	else	Conn->fi_arglen = strlen(args)+1;
	Conn->fi_iomode = iomode;
	Conn->fi_logfd  = curLogFd();

	if( file_isreg(sock) ){
		/* it might be TMPFILE() with CloseOnExec flag set */
		clearCloseOnExec(sock);
	}
	Conn->fi_topeer = sock;
	Conn->fi_dupclsock = 0;
	if( Conn->fi_issock = file_ISSOCK(sock) ){
		setclientsock(sock);
		if( sock == ClientSock
		 || SocketOf(sock) == SocketOf(ClientSock) )
			Conn->fi_dupclsock = 1;
			
	}

	/* might be emulating spawn() on Unix */
	sigsetmask(sigblock(0) & ~sigmask(SIGHUP) );

	pid = Spawnvp("openFilter",EXEC_PATH,av);
	Verbose("## spawnFilter: %d -> %d\n",getpid(),pid);
	if( pid <= 0 ){
		/* 9.6.3 don't freeze in fwrite() to the pipe ... */
		fclose(out);
		close(fio[0]);
		daemonlog("F","spawnFilter: FAILED %d\n",pid);
		porting_dbg("--FATAL: spawnFilter: FAILED spawn %d",pid);
		putpplog("--FATAL: spawnFilter: FAILED spawn %d\n",pid);
		return pid;
	}

/*
	wcc = write(fout,Conn,sizeof(Connection));
	if( Conn->cl_reqbuf )
		write(fout,Conn->cl_reqbuf,Conn->cl_reqbufsize);
	if( args != NULL )
		write(fout,args,strlen(args)+1);
*/
	close(fio[0]); /* close here to get EPIPE on write(fio[1]) */

	if( MountOptions ){
		spawnArgs.sa_mountserno = MountSerno(MountOptions);
		spawnArgs.sa_moptslen = strlen(MountOptions)+1;
	}else{
		spawnArgs.sa_mountserno = 0;
		spawnArgs.sa_moptslen = 0;
	}
	wcc = fwrite(&spawnArgs,1,sizeof(spawnArgs),out);
	wcc = fwrite(Conn,1,sizeof(Connection),out);
	if( Conn->cl_reqbuf )
		fwrite(Conn->cl_reqbuf,1,Conn->cl_reqbufsize,out);
	if( args != NULL )
		fwrite(args,1,strlen(args)+1,out);
	if( MountOptions && spawnArgs.sa_moptslen ){
		fwrite(MountOptions,1,spawnArgs.sa_moptslen,out);
		setMountOptions(FL_ARG,Conn,0);
	}
	fclose(out);

	/* If the iomode == READ then
	 * must wait till the client finish to read the written environment
	 * not to read it by myself.
	 * (in the case of FFROMCL, payload data may be ready, but cannot
	 *  identify whether or not it is env. data or payload data ...)
	 * If the iomode == WRITE and filter is direct system-command then
	 * must wait not to make buffered data be not passed to the filter.
	 */
	/*
	if( iomode == 0 || iomode != 0 && 0 < PollIn(fin,1) ){
		sv1log("## wait the filter finish reading enviroment\n");
		msleep(100);
	}
	*/

	return pid;
}

static int xproc(PCStr(what),int pid){
	fprintf(stderr,"----[%d] Fork(%s) detected exit of [%d]\n",
		getpid(),what,pid);
	return 0;
}

#if defined(__FreeBSD__)
#define THREADSAFE_FORK	0
#else
#define THREADSAFE_FORK	1
#endif
int threadSafeFork(){
	if( actthreads() == 0 )
		return 1;
	if( THREADSAFE_FORK ){
		return 1;
	}
	return 0;
}

int ShutdownSocket(int fd);
#define fth FTenv
static int threadFilter(Connection *Conn,PCStr(fname),iFUNCP func,FILE *ioin,FILE *out,PCStr(args)){
	int code;
	IStr(buf,1);
	int osock;

	setthreadgid(0,STX_tid);
	osock = ClientSock;
	//ClientSock = dup(ClientSock);
	Verbose("-- F openFilter: %s [%d][%d] [%d]>>[%d]\n",
		fname, osock,ClientSock, FromS,ToC);
	// write(fileno(ioin),"\n",1); /* for sync. of thread_fork */
	PollIn(fileno(ioin),1000);

	clearConnPTR(Conn);
	code = (*func)(Conn,ioin,out,args);
	Verbose("-- F openFilter: DONE %d\n",code);
	fflush(out);
	ShutdownSocket(fileno(ioin));
	/*
	close(fth.f_sync[1]);
	*/
	sv1log("-- F openFilter: EXIT(%d) %s\n",code,fname);
	return 0;
}
int waitFilterThreadX(Connection *Conn){
	int rdy,err;
	double St = Time();
	if( fth.f_tid ){
		/*
		rdy = PollIn(fth.f_sync[0],3*1000);
		*/
		err = thread_wait(fth.f_tid,10*1000);
		sv1log("--a--waitFilterThreadX: %X err=%d (%.3f)\n",
			fth.f_tid,err,Time()-St);
		/*
		sv1log("--a--waitFilterThreadX: rdy[%d]=%d %X err=%d\n",
			fth.f_sync[0],rdy,fth.f_tid,err);
		//fclose(fth.f_out);
		close(fth.f_sync[0]);
		*/
		fclose(fth.f_ioin);
		if( fth.f_Conn->cl.p_closed ){
			ClientEOF = 2 | fth.f_Conn->cl.p_closed;
		}
		if( fth.f_Conn->cl_tcCLOSED ){
			tcCLOSED = 2 | fth.f_Conn->cl_tcCLOSED;
		}
		sv1log("## [%d]%X threadF WAIT %X ClientEOF=%d/%d\n",
			STX_tix,TID,0xFFF&fth.f_tid,ClientEOF,tcCLOSED);

		free(fth.f_Conn);
		fth.f_Conn = 0;
		fth.f_tid = 0;
		fth.f_ptid = 0;
		return 0;
	}
	return -1;
}
static void relay(FILE *in,FILE *out){
	IStr(buf,1024);
	while( fgets(buf,sizeof(buf),in) ){
		fputs(buf,out);
	}
	fclose(in);
	//fcloseFILE(out);
}
FILE *openFilter(Connection *Conn,PCStr(fname),iFUNCP func,FILE *out,PCStr(args))
{	int pid;
	int toc[2];
	FILE *ioin;

	if( lSINGLEP() ){
		FILE *ioout;
		Connection *dupConn;
		extern int BREAK_STICKY;

		BREAK_STICKY = 1;
		Socketpair(toc);
		/*
		Socketpair(fth.f_sync);
		*/
		ioin = fdopen(toc[0],"r");
		ioout = fdopen(toc[1],"w");
		dupConn = (Connection*)malloc(sizeof(Connection));
		*dupConn = *Conn;
		fth.f_Conn = dupConn;
		fth.f_ioin = ioin;
		fth.f_ptid = STX_tid;
/*
		fth.f_tid = thread_fork(0x80000,STX_tid,"threadFilter",(IFUNCP)threadFilter,
*/
		fth.f_tid = thread_fork(0x100000,STX_tid,"threadFilter",(IFUNCP)threadFilter,
			dupConn,fname,func,ioin,out,args);
		return ioout;
	}
	/*
	pipe(toc);
	*/
	pipeX(toc,8*1024);
	/*
	if( INHERENT_fork() ){
	*/
	/*
	if( INHERENT_fork() && threadSafeFork() ){
	*/
	if( INHERENT_fork() && threadSafeFork() && !lEXECFILTER() ){
		/*
		if( Fork("openFilter") == 0 ){
		*/
		/*
		if( (pid = Fork("openFilter")) == 0 ){
		*/
		if( (pid = ForkX("openFilter",xproc)) == 0 ){
			close(toc[1]);
			ioin = fdopen(toc[0],"r");
			(*func)(Conn,ioin,out,args);
			Finish(0);
		}
	}else{
		fflush(out);
		pid = spawnFilter(Conn,1,toc,fileno(out),func,args);
	}
	Conn->fi_pid = pid;
	close(toc[0]);
	return fdopen(toc[1],"w");
}
