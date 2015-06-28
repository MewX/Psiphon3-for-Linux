/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2006 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	sudo.c (a server for privileged actions)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
	BIND    ... BIND a port
	PAM     ... PAM authentication
	CHROOT  ... change root and execute
	CPNOD   ... copy a device node
	setdate

History:
	061022	created
//////////////////////////////////////////////////////////////////////#*/
#include "ystring.h"
#include "vsocket.h"
#include "fpoll.h"
#include "file.h"
#include "delegate.h"
#include "param.h"

#define SENDFD_OVERTCP 1

void unlinkOnExit(PCStr(path));
int newSocket(PCStr(what),PCStr(opts));
int sendFd(int sockfd,int fd,int pid);
int recvFd(int sockfd);
int bindSock(int sock,PCStr(portname),int af,xPVStr(hostname),int portnum,int nlisten);
int pam_auth1(PCStr(service),PCStr(user),PCStr(pass));
static int doBind(int clsock,PCStr(clhost),int clport,int tsock,PCStr(arg));
static int doPAM(int clsock,PCStr(clhost),int clport,int tosck,PCStr(arg));

int isUDPsock(int sock);
static int isPrivateSUDO = -1;
#define IamSUDO	(0 <= isPrivateSUDO)
extern char portSUDO[64];

int service_sudo(Connection *Conn,int svsock,int svport){
	int fc;
	int fv[2];
	int rv[2];
	CStr(req,1024);
	CStr(com,1024);
	CStr(arg,1024);
	CStr(a1,1024);
	CStr(a2,1024);
	CStr(a3,1024);
	const char *dp;
	CStr(resp,1024);
	int tsock = -1;
	int clsock;
	int isUDP;
	int rcc;
	int fd;
	CStr(local,MaxHostNameLen);
	CStr(remote,MaxHostNameLen);
	CStr(opts,MaxHostNameLen);
	CStr(clhost,128);
	int clport;

	gethostName(svsock,AVStr(local),"%A");
	sv1log("==SU START uid=%d/%d sock=%d port=%d udp=%d [%s]\n",
		getuid(),geteuid(),svsock,svport,isUDPsock(svsock),local);

	if( svport == 0 ){
		sprintf(local,"%s/sudo/port/P%s",DELEGATE_DGROOT,portSUDO);
		unlink(local);
		svsock = server_open_un("SUDO",AVStr(local),32);
		sv1log("==SU sock[%d] %s\n",svsock,local);
		if( svsock < 0 ){
			return -1;
		}
		if( geteuid() == 0 ){
			int omode = File_mod(local);
			/* set the owner of the socket to the one in OWNER */
			chmodShared(local);
			chmod(local,omode|0660);
		}
	}


	if( isUDP = isUDPsock(svsock) ){
	}else{
	}

	if( isUDP ){
		tsock = server_open_un("SUDO",AVStr(local),32);
		sv1log("---> tsock:%d [%s]\n",tsock,local);
	}else{
		tsock = svsock;
	}

	fc = 1;
	fv[0] = tsock;
	if( 0 <= isPrivateSUDO ){
		fc = 2;
		fv[1] = isPrivateSUDO;
	}

	for(;;){
		/*
		if( PollIn(tsock,0) <= 0 ){
			break;
		}
		*/
		if( PollIns(0,fc,fv,rv) <= 0 ){
			sv1log("==SU EXIT: poll error\n");
			break;
		}
		if( fc == 2 ){
			if( rv[1] ){
				sv1log("==SU EXIT: parent died\n");
				break;
			}
			if( rv[0] == 0 )
				continue;
		}

		clsock = tsock;
		if( !isUDP && !IsConnected(tsock,NULL) ){
			clsock = ACCEPT1(tsock,1,-1,10,AVStr(clhost));
			if( clsock < 0 ){
				msleep(100);
				continue;
			}
		}
		rcc = RecvFrom(clsock,req,sizeof(req)-1,AVStr(clhost),&clport);
		if( rcc <= 0 ){
			sv1log("==SU %d %d rcc=%d\n",tsock,clsock,rcc);
			if( clsock != tsock ){
				close(clsock);
				continue;
			}else{
				sv1log("==SU EXIT: read error\n");
				break;
			}
		}
		setVStrEnd(req,rcc);
		dp = wordScan(req,com);
		if( *dp == ' ' )
			textScan(dp+1,arg);
		else	lineScan(dp,arg);
		dp = wordScan(arg,a1);
		dp = wordScan(dp,a2);
		lineScan(dp,a3);
		sv1log("==SU Q[%s][%s]\n",com,arg);
		putLoadStat(ST_ACC,1);
		putLoadStat(ST_DONE,1);
		put_svstat();
		incRequestSerno(Conn);

		if( strcaseeq(com,"QUIT") ){
			if( isUDP ){
				continue;
			}else{
				sv1log("==SU EXIT: by QUIT command\n");
				break;
			}
		}
		if( strcaseeq(com,"PAM") ){
			doPAM(clsock,clhost,clport,tsock,arg);
			continue;
		}
		if( strcaseeq(com,"BIND") ){
			doBind(clsock,clhost,clport,tsock,arg);
			continue;
		}
/*
		if( strcaseeq(com,"STDERR") ){
			sv1log("==SU receiving @fd[%d]\n",usock);
			fd = recvFd(usock);
 fprintf(stderr,"---- STDERR %d -> %d\n",usock,fd);
			if( 0 <= fd ){
				dup2(fd,fileno(stderr));
 fprintf(stderr,"---- STDERR %d dup2\n",fd);
			}
		}
*/
	}
	return 0;
}
static int doBind(int clsock,PCStr(clhost),int clport,int tsock,PCStr(arg)){
	IStr(respudp,128);
	IStr(local,128);
	IStr(remote,128);
	IStr(opts,128);
	IStr(host,128);
	int port;
	int fd;
	int rsock;
	int cpid = -1;

	sv1log("==SU BIND %s...\n",arg);
	strcpy(local,"*");
	strcpy(remote,"*");
	strcpy(opts,"listen=32");

	Xsscanf(arg,"%s %s %s %s",AVStr(respudp),AVStr(local),
		AVStr(remote),AVStr(opts));

	if( isWindows() || SENDFD_OVERTCP ){
		rsock = clsock;
		sscanf(respudp,"pid=%d",&cpid);
	}else{
		rsock = UDP_client_open("BIND/sudo","sendfd",respudp,1);
		sv1log("==SU rsock=%d %s\n",rsock,respudp);
		if( rsock < 0 ){
			return -1;
		}
	}

	port = 0;
	Xsscanf(local,"%[^:]:%d",AVStr(host),&port);
	fd = newSocket("BIND/sudo","");
	bindSock(fd,"BIND/SUDO",-1,AVStr(host),port,32);
	sendFd(rsock,fd,cpid);
	if( isWindows() ){
	}else{
		close(rsock);
	}

	getpairName(fd,AVStr(local),AVStr(remote));
	close(fd);

	sv1log("==SU BOUND %d %s %s\n",fd,local,remote);
	/*
	SendTo(clsock,"OK\r\n",4,clhost,clport);
	*/
	IGNRETP write(clsock,"OK\r\n",4);
	sv1log("==SU returned OK\n");
	return 0;
}

static int respFd = -1;
static int respPid = 0;
static int getMyresp(PVStr(path)){
	int sock;
	int mypid = getpid();

	if( 0 <= respFd && respPid == mypid ){
		return respFd;
	}
	sprintf(path,"%s/sudoport/%d",DELEGATE_DGROOT,getpid());
	sock = server_open_un("SUDO",BVStr(path),-1);
	sv1log("==SU new-resp-sock %d %s\n",sock,path);
	if( 0 <= sock ){
		respFd = sock;
		respPid = mypid;
		sv1log("==SU ---- set unlinkOnExit %s\n",path);
		unlinkOnExit(path);
	}
	return respFd;
}
static int withoutSUDO = 0;
static int connectSudo(int *ts){
	CStr(path,1024);
	int tsock;

	if( withoutSUDO ){
		return -1;
	}
	sprintf(path,"%s/sudo/sudo/port/P%s",DELEGATE_DGROOT,portSUDO);
	tsock = client_open_un("SUDO",path,0);
	if( tsock < 0 ){
		sprintf(path,"%s/sudo/port/P%s",DELEGATE_DGROOT,portSUDO);
		tsock = client_open_un("SUDO",path,0);
	}
	*ts = tsock;
	if( tsock < 0 ){
		withoutSUDO = 1;
		sv1log("--SU NONE %s\n",path);
		return -1;
	}
	sv1log("--SU connected %d %s\n",tsock,path);
	return 0;
}

int enCreys(PCStr(opts),PCStr(pass),PCStr(data),PVStr(edata),int esize);
int deCreys(PCStr(opts),PCStr(pass),PCStr(data),PVStr(ddata),int dsize);
FileSize passSUDO;

int pamViaSudo(PCStr(service),PCStr(user),PCStr(pass),int *ok){
	int tsock;
	CStr(key,32);
	CStr(que,128);
	CStr(ans,128);
	CStr(epass,256);
	int rcc;
	const char *dp;

	if( IamSUDO ){
		return -1;
	}
	if( connectSudo(&tsock) != 0 )
		return -1;
	sprintf(key,"%lld",passSUDO);
	enCreys("",key,pass,AVStr(epass),sizeof(epass));
	sprintf(que,"PAM %s:%s:%s\r\n",service,user,epass);
	IGNRETP write(tsock,que,strlen(que));
	rcc = read(tsock,ans,sizeof(ans)-1);
	if( 0 < rcc )
		setVStrEnd(ans,rcc);
	else	setVStrEnd(ans,0);

	if( dp = strpbrk(que,"\r\n") ) *((char*)dp) = 0;
	if( dp = strpbrk(ans,"\r\n") ) *((char*)dp) = 0;
	sv1log("--SU Q[%s] A[%s]\n",que,ans);
	*ok = atoi(ans) == 1;
	return 0;
}
static int doPAM(int clsock,PCStr(clhost),int clport,int tosck,PCStr(arg)){
	int ok;
	CStr(key,32);
	IStr(dom,128);
	IStr(user,128);
	IStr(pass,128);
	IStr(epass,128);
	IStr(resp,128);

	Xsscanf(arg,"%[^:]:%[^:]:%[^\r\n]",AVStr(dom),
		AVStr(user),AVStr(epass));
	sprintf(key,"%lld",passSUDO);
	deCreys("",key,epass,AVStr(pass),sizeof(pass));
	ok = pam_auth1(dom,user,pass);
	sprintf(resp,"%d\r\n",ok);
	/*
	SendTo(clsock,resp,strlen(resp),clhost,clport);
	*/
	IGNRETP write(clsock,resp,strlen(resp));
	return 0;
}
int bindViaSudo(int sock,VSAddr *sap,int len){
	int tsock;
	CStr(msg,128);
	CStr(addrport,128);
	CStr(local,128);
	CStr(remote,128);
	int wcc;
	double Start = Time();
	int newfd;
	CStr(respudp,1024);
	int rsock;
	int fd;

	if( IamSUDO ){
		return -1;
	}
	if( connectSudo(&tsock) != 0 )
		return -1;
	if( isWindows() || SENDFD_OVERTCP ){
		rsock = tsock;
		sprintf(respudp,"pid=%d",getpid());
	}else{
		rsock = getMyresp(AVStr(respudp));
		if( rsock < 0 ){
			return -1;
		}
	}
	VSA_satoap(sap,AVStr(addrport));
	sv1log("--SU command BIND %s\n",addrport);
	sprintf(msg,"BIND %s %s\r\n",respudp,addrport);
	sv1log("--SU command BIND sockfd=%d ==> %d\n",sock,tsock);
	wcc = write(tsock,msg,strlen(msg));

	sv1log("--SU polling %d %d ...\n",tsock,rsock);
	if( PollIn(tsock,3*1000) <= 0 ){
		close(rsock);
		return -1;
	}
	sv1log("--SU poll done %d %d\n",tsock,rsock);

	if( tsock != rsock ){ /* Windows */
		if( PollIn(rsock,3*1000) <= 0 ){
			sv1log("--SU poll UDP timeout %d\n",rsock);
			close(rsock);
			return -1;
		}
	}

	fd = recvFd(rsock);
	sv1log("--SU recvFd rsock:%d ==> %d\n",rsock,fd);
	if( fd < 0 ){
		return -1;
	}
	getpairName(fd,AVStr(local),AVStr(remote));
	sv1log("--SU recvFd rsock:%d ==> %d [%s]\n",rsock,fd,local);
	close(tsock);

	sv1log("--SU [%s]=>[%s]\n",addrport,local);
	if( streq(addrport,local) ){
		sv1log("--SU DUP [%d]=>[%d]\n",fd,sock);
		dup2(fd,sock);
		close(fd);
		return 0;
	}else{
		close(fd);
		return -1;
	}
}

FileSize getRand64();
void startSUDO(Connection *Conn,int csock){
	CStr(port,128);

	if( csock < 0 ){
		return;
	}
	if( PollIn(csock,1) != 0 ){
		sv0log("--SU dead ?\n");
		return;
	}
	IGNRETP write(csock,portSUDO,sizeof(portSUDO));

	if( PollIn(csock,10*1000) <= 0 ){
		sv0log("--SU no response\n");
		return;
	}
	if( read(csock,&passSUDO,sizeof(passSUDO)) <= 0 ){
		sv0log("--SU EOF response\n");
		return;
	}
	sv0log("--SU started\n");
}
int forkSUDO(int ac,const char *av[],Connection *Conn,int csock){
	CStr(title,128);
	CStr(buf,1024);

	sprintf(title,"SUDO-%d",getppid());
	ProcTitle(Conn,"%s",title);

	if( PollIn(csock,30*1000) == 0 ){
		sv0log("--SU timeout to start\n");
		return -1;
	}
	if( read(csock,portSUDO,sizeof(portSUDO)) < sizeof(portSUDO) ){
		sv0log("--SU EOF on start\n");
		return -1;
	}
	sprintf(title,"SUDO-%s",portSUDO);
	ProcTitle(Conn,"%s",title);

	passSUDO = getRand64();
	IGNRETP write(csock,&passSUDO,sizeof(passSUDO));

	iLog("--- being SUDO server");
	isPrivateSUDO = csock;
	return 0;
}


int sudo_main(int ac,const char *av[],Connection *Conn){
	int ai;
	const char *arg;
	int sock;
	int sendfd = 0;
	int sockfd = fileno(stderr);
	const char *optpw = 0;
	IStr(local,128);
	IStr(remote,128);
	CStr(opts,128);
	IStr(host,128);
	int port = 0;

	if( ac <= 1 ){
		fprintf(stderr,"Usage: %s [host:port] [-a d:u:p] [-b h:p]\n",
			av[0]);
		return 0;
	}

	sprintf(host,"%s/sudo/sudo/port/P",DELEGATE_DGROOT);
	port = 1;

	for( ai = 1; ai < ac; ai++ ){
		arg = av[ai];
		if( streq(arg,"-a") ){
			if( ai+1 < ac ){
				arg = av[++ai];
				optpw = arg;
			}
		}else
		if( streq(arg,"-b") ){
			if( ai+1 < ac ){
				arg = av[++ai];
				sendfd = 1;
				sockfd = newSocket("BIND/test","");
				strcpy(opts,arg);
			}
		}else
		if( streq(arg,"-d") ){
			sendfd = 1;
		}else{
			Xsscanf(arg,"%[^:]:%d",AVStr(host),&port);
		}
	}

	set_realserver(Conn,"sudo",host,port);
	Conn->from_myself = 1;
	sock = connect_to_serv(Conn,0,1,0);
	if( sock < 0 ){
		sock = client_open_un("SUDO",host,32);
		if( sock < 0 ){
			fprintf(stderr,"---- cannot open '%s:%d'\n",host,port);
			return -1;
		}
	}

	if( optpw ){
		int wcc,rcc;
		CStr(msg,128);
		sprintf(msg,"PAM %s\r\n",optpw);
		wcc = write(sock,msg,strlen(msg));
		PollIn(sock,8*1000);
		rcc = read(sock,msg,sizeof(msg));
 fprintf(stderr,"---- %s\n",msg);
	}
	if( sendfd ){
		CStr(msg,128);
		int wcc;
		double Start = Time();

		if( sockfd == fileno(stderr) )
			sprintf(msg,"STDERR\r\n");
		else	sprintf(msg,"BIND %s\r\n",opts);
 fprintf(stderr,"---- command BIND sockfd=%d ==> %d\n",sockfd,sock);
		wcc = write(sock,msg,strlen(msg));
/*
 fprintf(stderr,"---- sending sockfd=%d ==> %d\n",sockfd,usock);
		wcc = sendFd(usock,sockfd,0);
*/

		PollIn(sock,8*1000);
		getpairName(sockfd,AVStr(local),AVStr(remote));

 fprintf(stderr,"---- SUDO %s SENT=%d [%.3f] sock=%d [%s][%s]\n",
 msg,wcc,Time()-Start,sockfd,local,remote);
	}
	return 0;
}


#define SU_DISABLE	1
typedef struct {
  const char	*c_name;
	int	 c_stats;
} Cap;
const char SU_setuid[]	= "setuid";
const char SU_setgid[]	= "setgid";
const char SU_chroot[]	= "chroot";
const char SU_bind[]	= "bind";
const char SU_pam[]	= "pam";
const char SU_chown[]	= "chown";
const char SU_cpnod[]	= "cpnod";
const char SU_settimeofday[] = "settimeofday";
static Cap sucaps[] = {
	{SU_bind	},
	{SU_chown	},
	{SU_cpnod	},
	{SU_chroot	},
	{SU_pam		},
	{SU_setgid	},
	{SU_settimeofday},
	{SU_setuid	},
	{0}
};
void lsSucaps(FILE *out){
	int ci;
	const char *name;
	for( ci = 0; name = sucaps[ci].c_name; ci++ )
		if( name ) fprintf(out,"%-15s ",name);
}
static Cap *findcap(PCStr(name)){
	int ci;
	Cap *cp;
	for( ci = 0; ci < elnumof(sucaps); ci++ ){
		cp = &sucaps[ci];
		if( streq(cp->c_name,name) )
			return cp;
	}
	return 0;
}

void enableFuncs(PCStr(func),int enable);
void setupSucaps(PCStr(caps)){
	CStr(cap1,128);
	const char *clist;
	const char *c1;
	int op;
	Cap *cap;
	int ci;

	if( *caps != '-' ){
		for( ci = 0; ci < elnumof(sucaps); ci++ )
			sucaps[ci].c_stats |= SU_DISABLE;
	}
	clist = caps;
	while( *clist ){
		clist = scan_ListElem1(clist,',',AVStr(cap1));
		c1 = cap1;
		op = 1;
		if( *c1 == '-' ){
			op = -1;
			c1++;
		}
		if( *c1 == 'F' ){
			enableFuncs(c1+1,2*op);
		}else
		if( cap = findcap(c1) ){
			if( 0 < op )
				cap->c_stats &= ~SU_DISABLE;
			else	cap->c_stats |=  SU_DISABLE;
		}else{
		}
	}
}
static scanListFunc sucap1(PCStr(cap)){
	if( findcap(cap) )
		return 0;
	fprintf(stderr,"Unknown capability: %s\n",cap);
	lsSucaps(stderr);
	fprintf(stderr,"\n");
	return -1;
}
int isSucap(PCStr(cap)){
	return sucap1(cap);
}
