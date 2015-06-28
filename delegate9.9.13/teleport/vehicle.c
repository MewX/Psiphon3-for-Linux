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
Program:	vehicle.c (client Vehicle on the Teleport protocol)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	950622	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "teleport.h"

#define TP_INVITE	"INVITE"
#define TP_ROUTE	"ROUTE"
#define IMSIZE	(1024*8)

const char *MY_QZ = "3";

int FromTeleport;
int TELEPORT_TIMEOUT = 5;
int TELEPORT_BUFFERED = 1;

#define TPD_ERR	0
#define TPD_DBG	1
#define TPD_VRB	2

int TELEPORT_loglev = TPD_DBG;

#define LOG(lv)	(lv <= TELEPORT_loglev)
#define xERR	(!LOG(TPD_ERR)) ? 0 : sv1tlog
#define DBG	(!LOG(TPD_DBG)) ? 0 : sv1log
#define VRB	(!LOG(TPD_VRB)) ? 0 : sv1vlog

typedef struct {
  const	char   *a_path;
	int	a_io[2];
	int	a_onEOF;
	int	a_onCB;
	FILE   *a_froma;
	FILE   *a_toa;
	int	a_zomb;
	int	a_rcc;
	int	a_wcc;
	int	a_id;
	int	a_pid;
	int	a_origin;
	int	a_sentQZ;
} Agent;
typedef struct {
	Agent  *ve_agents[128];
	int	ve_nagents;
	int	ve_nalive;
	int	ve_agentID;
	MStr(	ve_teleHost,512);
	int	ve_telePort;

	int	ve_NOWAIT;
	int	ve_NOFLUSH;

	int	ve_PPVehicle; /* Point to Point Vehicle without Teleport */
	int	ve_dontTryTeleport;
	int	ve_TeleportPorts[64];
	int	ve_dontRetryConnect;
	jmp_buf	ve_jmpenv;
	Agent  *ve_writingAgent;

	int	ve_pcount;
	MStr(	ve_ppath,256);
} VehicleEnv;
static VehicleEnv *vehicleEnv;
#define agents		vehicleEnv->ve_agents
#define nagents		vehicleEnv->ve_nagents
#define nalive		vehicleEnv->ve_nalive
#define agentID		vehicleEnv->ve_agentID
#define teleHost	vehicleEnv->ve_teleHost
/**/
#define telePort	vehicleEnv->ve_telePort
#define NOWAIT		vehicleEnv->ve_NOWAIT
#define NOFLUSH		vehicleEnv->ve_NOFLUSH
#define PPVehicle	vehicleEnv->ve_PPVehicle
#define dontTryTeleport	vehicleEnv->ve_dontTryTeleport
#define TeleportPorts	vehicleEnv->ve_TeleportPorts
#define dontRetryConnect vehicleEnv->ve_dontRetryConnect
#define jmpenv		vehicleEnv->ve_jmpenv
#define writingAgent	vehicleEnv->ve_writingAgent
#define pcount		vehicleEnv->ve_pcount
#define Ppath		vehicleEnv->ve_ppath
/**/
static void minit_vehicle()
{
	if( vehicleEnv == 0 )
		vehicleEnv = NewStruct(VehicleEnv);
}

static void clearZomb(int kill)
{	int ax,aj,deleted;
	Agent *ap;

	aj = 0;
	deleted = 0;
	for( ax = 0; ax < nagents; ax++ ){
		ap = agents[ax];
		if( kill || ap->a_zomb ){
			DBG("{T}.DONE agent[%d] %di+%do\n",ap->a_id,ap->a_rcc,ap->a_wcc);
			fclose(ap->a_toa);
			fclose(ap->a_froma);
			free((char*)ap->a_path);
			free(ap);
			deleted++;
		}else{
			agents[aj++] = ap;
		}
	}
	nagents -= deleted;
}
static void closeTeleportSides(){
	int ax;
	Agent *ap;

	for( ax = 0; ax < nagents; ax++ ){
		ap = agents[ax];
		close(ap->a_io[1]);
	}
}

/*
 *	Spawn a new agent.
 *
 *	(1) If clsock is valid, spawn a <init> process to initialize the
 *	channel with the remote peer agent.  After the initialization,
 *	<init> closes the channel to the Backbone.  The backbone process
 *	detect the EOF, then starts bidirectional relay between
 *	the server beyand the clsock and the backbone.
 *
 *	(2) Otherwise, an agent is spawn as a proxy of the remote peer
 *	which is connected to the backbone.  The proxy is implemented
 *	with DeleGate which uses the socket to the backbone as a socket
 *	to a client.
 *
 *          client                 server
 *          DeleGate               DeleGate
 *             +---+                  |
 *          <init> +                  |
 *             +---+                  |
 *           agent                  agent
 *        -----+------- - - - --------+-----
 *          Teleport              Teleport
 *           teleport backbone process(es)
 *
 */
static void callbackDelegate(int ifd,int cbsock,PCStr(telehost),int teleport);
static int connectMyself(PCStr(telehost),int teleport);
static void callAgent(int telesock,int clsock);
static Agent *newAgent(PCStr(path),int svsock,int telesocks[],int clsock)
{	Agent *ap;
	CStr(newpath,256);
	register int pid;
	int cbsock;

	/* new agent for `path' */
	ap = (Agent*)calloc(sizeof(Agent),1);
	agents[nagents++] = ap;
	ap->a_id = ++agentID;

	if( path == NULL ){
		ap->a_origin = 1;
		sprintf(newpath,"");
	}else{
		sprintf(newpath,"%d!%s",ap->a_id,path);
	}
	DBG("{T}.SET(1) a_path=[%s]\n",newpath);
	ap->a_path = stralloc(newpath);

	ap->a_onEOF = -1;
	ap->a_onCB = -1;

	if( clsock < 0 ){
		clsock = connectMyself(teleHost,telePort);
		if( 0 <= clsock ){
			ap->a_io[0] = ap->a_io[1] = clsock;
			ap->a_froma = fdopen(clsock,"r");
			ap->a_toa = fdopen(clsock,"w");
			ap->a_pid = 0;

DBG("{T}.NEW DELEGATE AGENT#%d[%d](%d)(%d): %s\n",
ap->a_id,0,ap->a_io[1],clsock,ap->a_path);

			return ap;
		}
	}

	Socketpair(ap->a_io);
	cbsock = -1;
	if( clsock < 0 && NOFLUSH )
		cbsock = server_open("callbackDeleGate",VStrNULL,0,1);

	if( (pid = Fork("newAgent")) == 0 ){
		close(ap->a_io[1]);
		close(svsock);
		close(telesocks[0]);
		close(telesocks[1]);
		closeTeleportSides();

		FromTeleport = 1;
		if( 0 <= clsock ){
			/* <init> process */
			callAgent(ap->a_io[0],clsock);
		}else{
			callbackDelegate(ap->a_io[0],cbsock,teleHost,telePort);
		}
		exit(0);
	}

	nalive++;
	DBG("{T}.NEW AGENT#%d[%d](%d)(%d): %s\n",
		ap->a_id,pid,ap->a_io[1],clsock,ap->a_path);

	close(ap->a_io[0]);
	ap->a_froma = fdopen(ap->a_io[1],"r");
	ap->a_toa = fdopen(ap->a_io[1],"w");
	ap->a_pid = pid;

	if( 0 <= clsock ){
		ap->a_onEOF = clsock;
		ap->a_onCB = -1;
	}else{
		ap->a_onEOF = -1;
		ap->a_onCB = cbsock;
	}
	return ap;
}

static void replacesock(Agent *ap,int clsock)
{
	fclose(ap->a_froma);
	fclose(ap->a_toa);
	ap->a_io[1] = clsock;
	ap->a_froma = fdopen(clsock,"r");
	ap->a_toa = fdopen(clsock,"w");
}
static int onCallBack(Agent *ap)
{	int cbsock,clsock;

	if( 0 <= (cbsock = ap->a_onCB) ){
		if( 0 < PollIn(cbsock,1000) ){
			clsock = ACCEPT(cbsock,1,-1,10);
			close(cbsock);
			ap->a_onCB = -1;
			DBG("{T}.onCallBack[%d][%d]\n",cbsock,clsock);
			if( 0 <= clsock ){
				replacesock(ap,clsock);
				return 1;
			}
		}
		close(cbsock);
		ap->a_onCB = -1;
		DBG("{T}.noCallBack[%d]\n",cbsock);

	}
	return 0;
}
static int onEOF(Agent *ap)
{	int clsock;

	if( 0 <= (clsock = ap->a_onEOF) ){
		DBG("{T}.start on EOF\n");
		replacesock(ap,clsock);
		ap->a_onEOF = -1;
		return 1;
	}
	return 0;
}

static void pathReverse(PCStr(path),xPVStr(rpath))
{	CStr(buf,256);
	const char *bp;
	char ch;
	refQStr(rp,rpath);
	CStr(p1,256);
	CStr(p2,256);

	if( path[0] == '=' ){
		setVStrPtrInc(rpath,*path++);
		if( path[0] == '<' ){
			setVStrPtrInc(rpath,'>');
			path++;
		}else
		if( path[0] == '>' ){
			setVStrPtrInc(rpath,'<');
			path++;
		}
	}

	strcpy(buf,path);
	bp = &buf[strlen(buf)-1];
	cpyQStr(rp,rpath);

	while( buf < bp ){
		ch = *bp;
		if( ch == '!' || ch == '<' || ch == '>' ){
			if( Xsscanf(bp+1,"%[^/]/%s",AVStr(p1),AVStr(p2)) == 2 )
				sprintf(rp,"%s/%s",p2,p1);
			else	strcpy(rp,bp+1);
			rp += strlen(rp);
			if( ch == '<' ) ch = '>';
			if( ch == '>' ) ch = '<';
			setVStrPtrInc(rp,ch);
			truncVStr(bp);
		}
		bp--;
	}
	strcpy(rp,bp);
	/*VRB("PATH-REVERSE: [%s]->[%s]\n",path,rpath);*/
}
static Agent *findAgent(xPVStr(path),int svsock,int telesocks[],int *xnew)
{	int ax;
	int aid;
	Agent *ap;
	const char *pp;
	char direct;
	int unbound;
	unbound = (path[0] == '=') && (path[1] == '<') && (path[2] == '!');

	if( *path == '=' )
		path++;

	if( *path == '<' ){
		direct = '<';
		*path++;
	}else
	if( *path == '>' ){
		CStr(rpath,256);
		direct = '>';
		*path++;
		pathReverse(path,AVStr(rpath));
		setPStr(path,rpath,sizeof(rpath));
	}

	aid = atoi(path);
	if( aid != 0 ){
		for( ax = 0; ax < nagents; ax++ ){
			ap = agents[ax];
			if( ap->a_id == aid ){
				for( pp = path; *pp; pp++ )
					if( *pp == '<' || *pp == '>' )
						*(char*)pp = '!';
				if( ap->a_path[0] == 0 ){
DBG("{T}.SET(2) a_path=[%s]\n",path);
					ap->a_path = stralloc(path);
				}
				return ap;
			}
		}
		return NULL;
	}

	if( *path == '!' || *path == '>' || *path == '<' ) path++;
	if( *path == '>' || *path == '<' ) path++;
	for( pp = path; *pp; pp++ ) if( *pp == '<' ) *(char*)pp = '!';

	for( ax = 0; ax < nagents; ax++ ){
		ap = agents[ax];

		if( unbound ){
			if( pp = strchr(ap->a_path,'!') )
			if( streq(path,pp+1) ){
		DBG("{T}.UNBOUND #%d [%s][%s]\n",ap->a_id,path,ap->a_path);
				*xnew = 0;
				return ap;
			}
		}else
			if( streq(path,ap->a_path) ){
				*xnew = 0;
				return ap;
			}
	}
	*xnew = 1;
	return newAgent(path,svsock,telesocks,-1);
}

static int deWrite(int fd,PCStr(buf),int len)
{	int olen;
	CStr(obuf,0x4000);

	olen = QZdecode(fd,AVStr(obuf),buf,len);
	if( olen < 0 )
		return Write(fd,buf,len);
	else	return Write(fd,obuf,olen);
}
static int enRead(int fd,PCStr(prefix),PVStr(buf),int size)
{	int rcc;
	CStr(ibuf,IMSIZE);

	rcc = read(fd,(char*)ibuf,sizeof(ibuf));
	if( rcc <= 0 )
		return rcc;
	return QZencode(fd,prefix,AVStr(buf),ibuf,rcc);
}
static char *fromAgent(PCStr(prefix),PVStr(buf),int size,FILE *fp)
{
	if( enRead(fileno(fp),prefix,AVStr(buf),size) <= 0 )
		return NULL;
	else	return (char*)buf;
}
static int toAgent(FILE *fp,PCStr(buf),int len,int *olenp)
{	int olen;
	CStr(obuf,0x4000);

	*olenp = olen = QZdecode(fileno(fp),AVStr(obuf),buf,len);
	if( olen <= 0 ){
		DBG("toAgent(%x,%d -> %d)\n",p2i(fp),len,olen);
		return olen;
	}
	return fwrite(obuf,1,olen,fp);
/*
	return deWrite(fileno(fp),buf,len);
*/
}

static int Fflush(FILE *fp);
static scanListFunc invite1(PCStr(host),FILE *wfp)
{	CStr(msg,1024);

	sprintf(msg,"%s WhereIs/%s \r\n",TP_INVITE,host);
	fputs(msg,wfp);
	Fflush(wfp);
	DBG("PUT-Teleport: %s",msg);
	return 0;
}

static void sigPIPE(int sig)
{
	signal(SIGPIPE,sigPIPE);
	if( writingAgent )
		DBG("!!!!!!!! SIGPIPE on write to Agent !!!!!!!!\n");
	else{
		DBG("!!!!!!!! SIGPIPE on write to Teleport !!!!!!!!\n");
		longjmp(jmpenv,sig);
	}
}
static void resettty()
{
	if( fork() == 0 )
		execlp("stty","stty","echo",NULL);
	else	wait(0);
}
static void settty()
{
	if( isatty(0) ){
		if( fork() == 0 )
			execlp("stty","stty","-echo",NULL);
		else	wait(0);
		addBeforeExit("STTY-ECHO",(vFUNCP)resettty,0);
	}
}

/*
 *	Connect to the Teleport backbone at the specified host and returns
 *	the entrance to the backbone; a pair of sockets to the backbone.
 *
 *	When the host name is "private.vehicle", then given clsocks is
 *	used as the entrance of the backbone.  It is the case where
 *	this process is server side of a private Teleport connection.
 *
 */
static int connectTeleport(int clsocks[],PCStr(host),int port,PCStr(tunnel),int telesocks[])
{	int fd;
	int tio[2];
	CStr(ttype,64);
	CStr(tscript,1024);
	int clsock;
	CStr(helo,128);
	CStr(resp,256);

	if( tunnel ){
		Socketpair(tio);
		fieldScan(tunnel,ttype,tscript);
		if( Fork("Tunnel") == 0 ){
			close(tio[1]);
			dup2(tio[0],0);
			dup2(tio[0],1);

			shiobar(tscript);
			exit(0);
		}
		close(tio[0]);
		fd = tio[1];
		MY_QZ = "1";
		dontRetryConnect = 1;
 {
FILE *fp;
CStr(msg0,256);
fp = fdopen(dup(fd),"r");
setbuf(fp,NULL);
if( fgets(msg0,sizeof(msg0),fp) != NULL )
DBG("Remote Peer Says: %s",msg0);
fclose(fp);
 }
		telesocks[0] = tio[1];
		telesocks[1] = tio[1];
		return 0;
	}
	if( strcmp(host,"tty7") == 0 ){
		telesocks[0] = fileno(stdin);
		telesocks[1] = fileno(stdout);
		DBG(">>>>>>>> tty7/teleport\n");
		MY_QZ = "1";
		dontRetryConnect = 1;
		PPVehicle = 1;
		return 0;
	}

	if( strcmp(host,"private.vehicle") == 0 ){
		telesocks[0] = clsocks[0];
		telesocks[1] = clsocks[1];
		DBG(">>>>>>>> vehicle/teleport\n");
		MY_QZ = "3";
		dontRetryConnect = 1;
		NOFLUSH = 1;
		return 0;
	}

	clsock = client_open("Vehicle2/Teleport","teleport",host,port);
	if( clsock < 0 )
		return -1;

	sprintf(helo,"HELO\r\n");
	IGNRETP write(clsock,helo,strlen(helo));
	if( RecvLine(clsock,(char*)resp,sizeof(resp)) <= 0 )
		return -1;
	DBG("{T}.Teleport-SAYS: %s",resp);

	if( strstr(resp,"DeleGate") ){
		sprintf(helo,"TELEPORT DeleGate/%s\r\n",DELEGATE_ver());
		IGNRETP write(clsock,helo,strlen(helo));
		MY_QZ = "3";
		NOWAIT = 1;
	}

	telesocks[0] = clsock;
	telesocks[1] = clsock;
	return 0;
}
static void tracemsg(PCStr(who),PCStr(msg))
{	CStr(msghead,42);
	const char *np;
	char ch;

	if( TELEPORT_loglev < TPD_VRB )
		return;

	strncpy(msghead,msg,sizeof(msghead)-2); setVStrEnd(msghead,sizeof(msghead)-2);
	if( np = strpbrk(msghead,"\r\n") )
		truncVStr(np);
	for( np = msghead; ch = *np; np++ )
		if( ch < ' ' )
			*(char*)np = '?';
	VRB("{T}.%s %s\n",who,msghead);
}
static int Fflush(FILE *fp)
{
	VRB("## FLUSH(%d)\n",fileno(fp));
	return fflush(fp);
}
int bindTeleportVehicle(int tx,int clsocks[],PCStr(host),int port,PCStr(tunnel),PCStr(invites))
{	CStr(msg,0x4000);
	CStr(path,0x4000);
	CStr(head,0x4000);
	const char *bodyp;
	const char *body;
	register int pid;
	FILE *svfp,*rfp,*wfp;
	FILE *fpv[64];
	int fpc,cfpc,fpx;
	int rdv[64];
	int nready;
	int ax;
	int xnew;
	Agent *apv[64],*ap;
	int neof;
	int retry,wsecs,wtotal;
	int telesocks[2];
	CStr(resp,256);
	int svsock,clsock;

	minit_vehicle();
	svsock = server_open("teleport",VStrNULL,0,50);
	if( svsock < 0 ){
		xERR("{T}.TeleportVehicle can't open server socket.\n");
		return 0;
	}
	if( (pid = Fork("bindTeleportVehicle")) != 0 ){
		sockHostport(svsock,&TeleportPorts[tx]);
		close(svsock);
		xERR("{T}.TeleportPorts[%d]: %d\n",tx,TeleportPorts[tx]);
		if( strcmp(host,"tty7") == 0 ){
			/* "stty -echo" must be done in this parent process to
			 * make resetting "stty echo" is done in thie process
			 * too, because only ? this process control the
			 * control terminal...
			 */
			settty();
		}
		return pid;
	}

	dontTryTeleport = 1;
	svfp = fdopen(svsock,"r");
	rfp = NULL;
	wfp = NULL;
	while( setjmp(jmpenv) != 0 ){
		if( rfp == NULL ){
			xERR("!!!!!!!! Teleport setjmp ERROR !!!!!!!!\n");
			break;
		}
		clearZomb(1);
		if( rfp != NULL ) fclose(rfp);
		if( wfp != NULL ) fclose(wfp);
		if( dontRetryConnect )
			exit(0);
	}
	signal(SIGPIPE,sigPIPE);

	for( wtotal = 0; ; wtotal += wsecs ){
		if( connectTeleport(clsocks,host,port,tunnel,telesocks) == 0 )
			break;
		xERR("{T}.Teleport: %s:%d open failed.\n",host,port);

		if( strcmp(host,"tty7") == 0 )
			exit(0);

		if( wtotal <  30 ) wsecs =  3; else
		if( wtotal < 120 ) wsecs = 10; else
		if( wtotal < 600 ) wsecs = 30; else
			wsecs = 60;
		sleep(wsecs);
	}
	telePort = getpeerNAME(telesocks[0],AVStr(teleHost));
	DBG("{T}.Teleport: %s:%d [%s:%d] opened[%d/%d]\n",host,port,
		teleHost,telePort, telesocks[0],telesocks[1]);

	rfp = fdopen(telesocks[0],"r");
	wfp = fdopen(telesocks[1],"w");

	if( invites && invites[0] )
		scan_commaList(invites,0,scanListCall invite1,wfp);

	for(;;){
		fpc = 0;
		fpv[fpc++] = rfp;
		fpv[fpc++] = svfp;
		cfpc = fpc;

		for( ax = 0; ax < nagents; ax++ ){
			if( agents[ax]->a_froma ){
				apv[fpc] = agents[ax];
				fpv[fpc] = agents[ax]->a_froma;
				fpc++;
			}
		}

		nready = 0;
		if( TELEPORT_BUFFERED ){
			nready = fPollIns(3,fpc,fpv,rdv);
			if( nready == 0 ){
				Fflush(wfp);
				for( ax = 0; ax < nagents; ax++ )
					Fflush(agents[ax]->a_toa);
			}
		}

		if( nready == 0 ){
			int timeout;
			if( 5 <= nalive )
				timeout =  1*1000;
			else	timeout = 10*1000;
			nready = fPollIns(timeout,fpc,fpv,rdv);
		}

		if( nready < 0 ){
			DBG("Poll failed.\n");
			break;
		}
		if( nready == 0 || 10 < nalive ){
			int pid;
			while( 0 < (pid = NoHangWait()) ){
				nalive--;
				DBG("{T}.done[%d], %d remain.\n",pid,nalive);
			}
		}
		neof = 0;

		for( fpx = cfpc; fpx < fpc; fpx++ ){
		    ap = apv[fpx];
		    if( 0 < rdv[fpx] ){
			CStr(path,1024);
			CStr(xpath,1024);

			if( ap->a_path[0] == 0 ){
				sprintf(path,"=<!%d ",ap->a_id);
				strcpy(xpath,path);
			}else{
				sprintf(path,"=>%s ",ap->a_path);
				strcpy(xpath,path);

				if( ap->a_sentQZ == 0 ){
					ap->a_sentQZ = 1;
					Xsprintf(TVStr(xpath),"=Q%s",MY_QZ);
					/* this Qn may be repeated in the first block ... */
				}
			}
			if( fromAgent(xpath,AVStr(msg),sizeof(msg),fpv[fpx]) == NULL ){
				if( onEOF(ap) || onCallBack(ap) )
					continue;

DBG("{T}.GOT HARD-EOF local, INFORM remote of it: %s\n",path);

				fprintf(wfp,"%s ==\r\n",path);
				Fflush(wfp);
				ap->a_zomb = 1;
				neof++;
			}else{
				tracemsg("A>B",msg);
				VRB("CLIENT-SAY: %s",msg);
				fputs(msg,wfp);
				if( !TELEPORT_BUFFERED )
					Fflush(wfp);
				ap->a_rcc += strlen(msg);
			}
		    }else
		    if( rdv[fpx] < 0 ){
			xERR("!!!! poll result in error #%d !!!!\n",ap->a_id);
			ap->a_zomb = 1;
		    }
		}

		if( neof )
			clearZomb(0);

		if( 0 < rdv[1] ){
			clsock = ACCEPT(fileno(svfp),1,-1,0);
			if( 0 <= clsock )
				ap = newAgent(NULL,svsock,telesocks,clsock);
		}
		if( rdv[0] <= 0 )
			continue;

		setVStrEnd(msg,0);
		/*if( RecvLine(fileno(rfp),msg,sizeof(msg)) <= 0 )*/
		if( fgets(msg,sizeof(msg),rfp) == NULL ){
			xERR("{T}.!!!!!!!! EOF from backbone !!!!!!!!\n");
			longjmp(jmpenv,-1);
		}
		tracemsg("B>A",msg);

/*
		if( msg[0] == '=' )
			ovstrcpy(msg,msg+1);
		else{
			xERR("{T}.Teleport ERROR:[%d] %s\n",strlen(msg),msg);
		}
*/
 if( msg[0] != '=' )
 {
 fprintf(stderr,"DeleGate/Teleport: ?????? %s",msg);
 sleep(1);
 continue;
 }
		bodyp = wordScan(msg,path);
		body = wordScan(bodyp,head);

		ap = findAgent(AVStr(path),svsock,telesocks,&xnew);
		if( ap == NULL ){
			CStr(rpath,256);

/*
			if( head[0]=='=' && head[1]=='=' ){
				xERR("NO SUCH AGENT: [%s] (SOFT-EOF)\n",path);
				continue;
			}
			pathReverse(path,rpath);
			fprintf(wfp,"%s ==\r\n",rpath);
*/

			{
				if( strcmp(path,Ppath) == 0 ){
					if( ++pcount % 10 == 0 )
					xERR("NO SUCH AGENT: [%s] (%d)\n",path,pcount);
				}else{
					xERR("NO SUCH AGENT: [%s]\n",path);
					strcpy(Ppath,path);
					pcount = 1;
				}
			}
			continue;
		}
		if( head[0] == '=' && head[1] == '=' ){
			DBG("{T}.GOT SOFT-EOF to #%d from backbone.\n",ap->a_id);
			ap->a_zomb = 1;
			clearZomb(0);
			continue;
		}

if( strchr(msg,'\n') == 0 ){
	xERR("ERROR: WITHOUT NEWLINE\n");
	strcat(msg,"\n");
}

		if( strncmp("WhereIs/",head,7) == 0 ){
			DBG("put to Teleport: %s",msg);
			fprintf(wfp,"=>%s path=%s =0A=Q%s=QZ\r\n",
				ap->a_path,ap->a_path, MY_QZ);
			Fflush(wfp);
		}else
		{	int len,olen,wcc;

			if( *bodyp == ' ' )
				bodyp++;

			len = strlen(bodyp);
			writingAgent = ap;

			wcc = toAgent(ap->a_toa,bodyp,len,&olen);
			if( !TELEPORT_BUFFERED )
				Fflush(ap->a_toa);
			writingAgent = 0;
			ap->a_wcc += wcc;
			VRB("put to Agent[%d] %x[%d] (%d/%d): %s",
				ap->a_id,p2i(ap->a_toa),fileno(ap->a_toa),
				wcc,len,msg);

			if( wcc <= 0 ){
				DBG("write to Agent#%d Pid#%d failed: %d / %d\n",
					ap->a_id,ap->a_pid,wcc,olen);

				fprintf(wfp,"=>%s ==\r\n",ap->a_path);
				Fflush(wfp);
				ap->a_zomb = 1;
			}
		}
	}
	exit(0); return -1;
}

static int openTeleport(PCStr(host),int port,int closefd)
{	int telesock;
	int io[2];
	int rcc,rfdv[2];
	CStr(buf,0x4000);
	FILE *fpv[2];
	FILE *wfp;
	int qzput = 0;

	if( FromTeleport )
		return -1;

	telesock = client_open("Vehicle3/Teleport","teleport",host,port);
	if( telesock < 0 )
		return -1;

	Socketpair(io);
	if( Fork("openTeleport") == 0 ){
		close(closefd);
		close(io[1]);
		fpv[0] = fdopen(telesock,"r");
		fpv[1] = fdopen(io[0],"r");
		wfp = fdopen(telesock,"w");

		for(;;){
			if( fPollIns(0,2,fpv,rfdv) < 0 )
				break;
			if( 0 < rfdv[0] ){
				if( fgets(buf,sizeof(buf),fpv[0]) == NULL )
					break;
				rcc = strlen(buf);
				if( buf[0] == '=' && buf[1] == '=' ){
					DBG("{T}.GOT SOFT-EOF from remote\n");
					break;
				}
				DBG("GOT from remote: %s",buf);
				deWrite(io[0],buf,rcc);
			}else
			if( 0 < rfdv[1] ){
				rcc = enRead(io[0],NULL,AVStr(buf),sizeof(buf));
				if( rcc <= 0 ){ 
					DBG("SEND SOFT-EOF to remote.\n");
					Write(telesock,"==\r\n",4);
					break;
				}
				Write(telesock,buf,rcc);
/*
				if( qzput == 0 && strstr(buf,TP_ROUTE) ){
					qzput = 1;
					fprintf(wfp,"=Q%s=QZ\r\n",MY_QZ);
					Fflush(wfp);
					xERR("sent =Q%s after %s",MY_QZ,buf);
				}
*/
			}
		}
		exit(0);
	}
	close(telesock);
	close(io[0]);
	return io[1];
}

#define NOWAIT_EXT "/nowait"
static int bindVehicle(int telesock,PCStr(server));
int teleportOpen(int mx,PCStr(master),int mport,PCStr(target_server),int closefd)
{	const char *hp;
	int tsock,rcc;
	CStr(msg,1024);
	CStr(localhost,128);

	minit_vehicle();
	if( dontTryTeleport )
		return -1;

	if( 0 <= TeleportPorts[mx] ){
		strcpy(localhost,"localhost");
		GetHostname(AVStr(localhost),sizeof(localhost));
		tsock = client_open("teleport","teleport",localhost,
			TeleportPorts[mx]);

		if( 0 <= tsock ){
			DBG("{T}.Teleports[%d](%d): opened. trying %s ...\n",
				mx,tsock,target_server);

			sprintf(msg,"%s\r\n",target_server);
			Write(tsock,msg,strlen(msg));
			rcc = read(tsock,(char*)msg,sizeof(msg));
			if( 0 < rcc ){
				setVStrEnd(msg,rcc);
				DBG("{T}.Teleport[%d]: got: %s",tsock,msg);
				return tsock;
			}
		}
	}

	tsock = openTeleport(master,mport,closefd);
	if( 0 <= tsock ){
		if( 0 <= bindVehicle(tsock,target_server) )
			return tsock;
		else{
			dontTryTeleport = 1;
			close(tsock);
		}
	}
	return -1;
}
static void callAgent(int telesock,int clsock)
{	CStr(msg,1024);
	CStr(server,256);
	CStr(path,256);
	int sdv[2][2];
	int cnt[2];
	int rcc;
	FILE *ts,*fs,*tc,*fc;

	DBG("{T}.callAgent...\n");

	ts = fdopen(telesock,"w");
	fs = fdopen(telesock,"r");
	tc = fdopen(clsock,"w");
	fc = fdopen(clsock,"r");

/*
if( !PPVehicle )
*/
    {
	if( fgets(msg,sizeof(msg),fc) == NULL )
		return;
	wordScan(msg,server);
	DBG("{T}.FROM CLIENT: server=[%s] NOWAIT=%d\n",server,NOWAIT);

	if( !NOWAIT && strstr(server,NOWAIT_EXT) == NULL ){
		fprintf(ts,"WhereIs/%s \r\n",server);
		Fflush(ts);
		if( fgets(msg,sizeof(msg),fs) == NULL )
			return;
		DBG("FROM SERVER: %s",msg);
	}

	if( NOWAIT )
		fprintf(tc,"OK NOWAIT\r\n");
	else	fprintf(tc,"OK.\r\n");
	Fflush(tc);
    }

/*
	DBG("{T}.callAgent: START RELAY\n");
	sdv[0][0] = clsock;   sdv[0][1] = telesock;
	sdv[1][0] = telesock; sdv[1][1] = clsock;
	relays(0,2,sdv,cnt);
	DBG("{T}.callAgent: END RELAY\n");
*/
/*
	sscanf (msg,"path=%s",path);
	fprintf(ts,"ROUTE %s \r\n",path);
	Fflush(ts);
	if( fgets(msg,sizeof(msg),fs) == NULL )
		return;
	fprintf(stderr,"FROM SERVER: %s",msg);
*/
}

/*
 *  1. Connect to myself (as a Generalist-delegated) => s
 *  2. Send "CPORT clienthost:clientport" to s for access control
 *  3. Receive ACK from the Generalist
 *  4. Let the socket s be the socket of the agent
 *  5. Original header of DeleGate protocol including SERVER will follow ...
 *
 *  1. Connect to myself (as a Generalist-delegated)
 *  2. Send "CPORT localhost:port clienthost:clientport"
 *  3. Wait the SYNC from the Generalist
 *  4. Accept at the CPORT to get socket s
 *  5. Let socket s be the socket of the agent
 *
 *  These steps should be done here, before relaying inputs to the
 *  spawned agent, but it may take seconds?.
 *  (Teleport backbone will be blocked during until these steps finish)
 */

static int connectMyself(PCStr(telehost),int teleport)
{	int clsock,cbsock,cbport;
	CStr(myhost,128);
	CStr(cbmsg,128);
	CStr(ackmsg,128);
	int wcc;
	FILE *afp;

	clsock = connectToMyself("callbackDelegate1");

	if( 0 <= clsock ){
		getpeerName(clsock,AVStr(myhost),"%H:%P");
		sprintf(cbmsg,"CPORT %s:%d\r\n",telehost,teleport);
		IGNRETP write(clsock,cbmsg,strlen(cbmsg));
		if( PollIn(clsock,1*1000) <= 0 ){
			sv1log("{T}#### No resp. from callbackDeleGate %s\n",
				myhost);
			close(clsock);
			return -1;
		}
		afp = fdopen(dup(clsock),"r");
		setVStrEnd(ackmsg,0);
		fgets(ackmsg,sizeof(ackmsg),afp);
		fclose(afp);
		sv1log("%d CPORT[%s:%d] %s",clsock,telehost,teleport,ackmsg);
		if( atoi(ackmsg) == 200 )
			return clsock;
		else{
			close(clsock);
			return -1;
		}
/*
		cbsock = server_open("callbackDeleGate",NULL,0,1);
		cbport = sockPort(cbsock);
		sprintf(cbmsg,"CPORT %s:%d %s:%d\r\n",
			telehost,teleport,"localhost",cbport);
		wcc = write(clsock,cbmsg,strlen(cbmsg));
		close(clsock);
		clsock = ACCEPT(cbsock,1,-1,5);
		close(cbsock);
		return clsock;
*/
	}
	return -1;
}

static void callbackDelegate(int ifd,int cbsock,PCStr(telehost),int teleport) /* maybe unnecessary */
{	int clsock;
	CStr(host,256);
	int port;
	CStr(imsg,4096);
	refQStr(imp,imsg);
	FILE *ifp;
	FILE *ts;

	DBG("{T}.callbackDeleGate: NOWAIT=%d NOFLUSH=%d\n",NOWAIT,NOFLUSH);
	if( cbsock < 0 || !NOFLUSH ){
		callDelegate1(ifd,NULL,telehost,teleport);
		return;
	}

/*
	port = gethostNAME(cbsock,host);
	close(cbsock);
	strcpy(host,"127.0.0.1");

	ifp = fdopen(ifd,"r");
	for( imp = imsg; fgets(imp,1024,ifp) != NULL; imp += strlen(imp) )
		if( imp[0] == '\r' || imp[0] == '\n' )
			break;

	if( DELEGATE_PORT != 0 ){
		clsock = client_open("callbackDelegate","delegate",
			host,DELEGATE_PORT);

		if( 0 <= clsock ){
			fclose(ifp);
			ts = fdopen(clsock,"w");
			fprintf(ts,"CPORT %s:%d\r\nNOFLUSH\r\n%s",
				host,port,imsg);
			fclose(ts);
			return;
		}
	}
*/
ifp = NULL;
setVStrEnd(host,0);
port = 0;

	clsock = client_open("callbackDelegate","teleport",host,port);
if(ifp)
	fclose(ifp); /* invoke ACCEPT() */
	callDelegate1(clsock,imsg,telehost,teleport);
}

static int bindVehicle(int telesock,PCStr(server))
{	CStr(msg,1024);
	CStr(mpath,1024);
	const char *mp;
	int rcc;

	sprintf(msg,"WhereIs/%s \r\n",server,MY_QZ);
	if( Write(telesock,msg,strlen(msg)) < 0 )
		return -1;

	DBG("[%d] WAITING RESPONSE %s",telesock,msg);
	if( PollIn(telesock,TELEPORT_TIMEOUT*1000) <= 0 )
		return -1;

	rcc = RecvLine(telesock,(char*)msg,sizeof(msg));
	if( rcc <= 0 )
		return -1;

	setVStrEnd(msg,rcc);
	DBG("[%d] GOT RESPONSE: %s",telesock,msg);

	if( msg[0] == '=' && msg[1] == '>' ){
		wordScan(msg+1,mpath);
		setVStrElem(mpath,0,'<');
		for( mp = mpath+1; *mp; mp++ )
			if( *mp == '>' )
				*(char*)mp = '!';
		sprintf(msg,"%s %s \r\n",TP_ROUTE,mpath);
		Write(telesock,msg,strlen(msg));

		DBG("[%d] WAITING RESPONSE: %s",telesock,msg);
		if( PollIn(telesock,TELEPORT_TIMEOUT*1000) <= 0 )
			return -1;

		rcc = RecvLine(telesock,(char*)msg,sizeof(msg));
		setVStrEnd(msg,rcc);

		DBG("[%d] GOT RESPONSE: %s",telesock,msg);
		return 1;
	}
	return -1;
}
