/*////////////////////////////////////////////////////////////////////////
Copyright (c) 2003-2006 National Institute of Advanced Industrial Science and Technology (AIST)

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
Program:	pam.c (PAM interface)
Author:		Yutaka Sato <ysato@delegate.org>
Description:
History:
	030814	created
////////////////////////////////////////////////////////////////////////*/
#define PAM_NON_OPTIONAL

#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "vsocket.h"
#include "proc.h"
#include "log.h"
#include "ccenv.h" /* DG_LIB_pam */
#ifndef DG_LIB_pam
#define DG_LIB_pam 0
#endif

#include <sys/types.h>
#include <sys/stat.h>
#ifdef S_ISUID /* UNIX */
#include <grp.h> /* for initgroups() */
#endif

int fullpathSUCOM(PCStr(path),PCStr(mode),PVStr(xpath));
int INHERENT_fork();

#ifdef NONEMPTYARRAY
#define p_requestBASE	p_request
#define p_methodBASE	p_method
#define p_serviceBASE	p_service
#define p_userBASE	p_user
#define p_passBASE	p_pass
#endif

typedef struct {
	xMStr(	p_request,128);
	xMStr(	p_method,64);
	xMStr(	p_service,64);
	xMStr(	p_user,64);
	xMStr(	p_pass,64);
} PamReq;

#define PAM_OK		200
#define PAM_UNAUTH	401
#define PAM_FORBIDDEN	403
#define PAM_ESTABLISH_CRED	0x2

#define DEFAULT_PAMbaseurl "/-/pam/"
extern const char *PAMbaseurl;
extern const char *PAMurl;

/*
 * PAM server
 */
static void get_pamreq(FILE *qfp,PamReq *PQ)
{	int gotop = 0;
	CStr(line,128);
	CStr(serv,64);
	CStr(atype,32);
	CStr(xauth,128);
	CStr(auth,128);
	const char *dp;

	PQ->p_request[0] = 0;
	PQ->p_method[0] = 0;
	PQ->p_service[0] = 0;
	PQ->p_user[0] = 0;
	PQ->p_pass[0] = 0;

	while( fgets(line,sizeof(line),qfp) != NULL ){
		if( *line == '\r' || *line == '\n' )
			break;
		if( gotop == 0 ){
			linescanX(line,AVStr(PQ->p_request),sizeof(PQ->p_request));
			dp = wordscanX(line,AVStr(PQ->p_method),sizeof(PQ->p_method));
			wordScan(dp,serv);
			if( strncmp(serv,PAMbaseurl,strlen(PAMbaseurl)) == 0 )
				ovstrcpy(serv,serv+strlen(PAMbaseurl));
			dp = wordscanY(serv,
				AVStr(PQ->p_service),sizeof(PQ->p_service),"^/");
			if( *dp == '/' )
				wordscanX(dp+1,AVStr(PQ->p_method),sizeof(PQ->p_method));
			gotop = 1;
		}else
		if( strncasecmp(line,"Authorization:",14) == 0 ){
			dp = wordScan(line+14,atype);
			dp = wordScan(dp,xauth);
			str_from64(xauth,strlen(xauth),AVStr(auth),sizeof(auth));
			scan_field1(auth,AVStr(PQ->p_user),sizeof(PQ->p_user),
				AVStr(PQ->p_pass),sizeof(PQ->p_pass));
		}
	}
}
static void put_pamreq(FILE *qfp,PCStr(host),int port,PCStr(method),PCStr(service),PCStr(user),PCStr(pass))
{	CStr(auth,128);
	CStr(xauth,128);

	sprintf(auth,"%s:%s",user,pass);
	str_to64(auth,strlen(auth),AVStr(xauth),sizeof(xauth),1);

	if( PAMurl )
		fprintf(qfp,"GET %s HTTP/1.0\r\n",PAMurl);
	else	fprintf(qfp,"GET %s%s/%s HTTP/1.0\r\n",
			0<port?PAMbaseurl:"",service,method);
	if( 0 < port )
		fprintf(qfp,"Host: %s:%d\r\n",host,port);
	fprintf(qfp,"Authorization: Basic %s\r\n",xauth);
	fprintf(qfp,"\r\n");
	fflush(qfp);
}
static int get_pamresp(FILE *rfp,PVStr(rstat),int rsize)
{	int ok,rcode;

	ok = -1;
	if( fgets(rstat,rsize,rfp) != NULL ){
		rcode = 0;
		sscanf(rstat,"%*s %d",&rcode);
		if( rcode == PAM_OK )
			ok = 1;
		else	ok = 0;
	}
	return ok;
}
static int put_pamresp(FILE *rfp,int ok)
{	int rcode;

	if( 0 < ok )
		rcode = PAM_OK;
	else
	if( ok < 0 )
		rcode = PAM_FORBIDDEN;
	else	rcode = PAM_UNAUTH;
	fprintf(rfp,"HTTP/1.0 %d\r\n",rcode);
	fprintf(rfp,"\r\n");
	fprintf(rfp,"PAM-Expire: none\r\n");
	fflush(rfp);
	return rcode;
}

#ifndef PAM_BY_MAIN_ONLY

const char *PAMbaseurl = DEFAULT_PAMbaseurl;
const char *PAMurl;

/*
#include <security/pam_appl.h>
*/
typedef int (*iiFUNCP)(int,...);
struct pam_message {
	int	msg_style;
  const	char   *msg;
};
struct pam_response {
  const	char   *resp;
	int	resp_retcode;
};
struct pam_conv {
	iiFUNCP	conv;
	void   *appdata_ptr;
};
#define PAM_PROMPT_ECHO_OFF 1
#define PAM_SUCCESS 0

#if defined(__cplusplus)
extern "C" {
#endif
int pam_start(PCStr(service),PCStr(user),
               const struct pam_conv *conv, void **);
int pam_end(void *pamh, int pam_status);
int pam_authenticate(void *pamh, int flags);
/*
int pam_setcred(void *pamh, int flags);
int pam_open_session(void *pamh, int flags);
int pam_close_session(void *pamh, int flags);
int pam_putenv(void *pamh, const char *name_value);
const char *pam_strerror(void *pamh, int pam_error);
int pam_acct_mgmt(void *pamh, int flags);
*/
#if defined(__cplusplus)
}
#endif

int PAM_start(PCStr(service),PCStr(user),const struct pam_conv *conv, void **);
int PAM_end(void *pamh, int pam_status);
int PAM_authenticate(void *pamh, int flags);
static const char *gpass;
static int login_conv(int nmsg,struct pam_message **pmsg,struct pam_response **resp,PCStr(appdata))
{	int mi;

	for( mi = 0; mi < nmsg; mi++ ){
		switch( pmsg[mi]->msg_style ){
		case PAM_PROMPT_ECHO_OFF:
			resp[mi] = (struct pam_response*)calloc(1,sizeof(struct pam_response));
			resp[mi]->resp = strdup(gpass);
			break;
		default:
			break;
		}
	}
	return PAM_SUCCESS;
}
static struct pam_conv pam_conv = {(iiFUNCP)login_conv, NULL};
int scan_guid(PCStr(user_group),int *uidp,int *gidp);

int withPAM(){
	int stat = 0;
	void *pamh;

	if( pam_start("passwd","root",&pam_conv,&pamh) == PAM_SUCCESS ){
		stat |= 1;
		pam_end(pamh,PAM_SUCCESS);
	}
	if( PAM_start("passwd","root",&pam_conv,&pamh) == PAM_SUCCESS ){
		stat |= 2;
		PAM_end(pamh,PAM_SUCCESS);
	}
	return stat;
}
int xpam_start(PCStr(service),PCStr(user),const struct pam_conv *conv, void **pamhp){
	int rcode;
	if( DG_LIB_pam == 0 ){
		rcode = PAM_start(service,user,conv,pamhp);
	}else{
		rcode = pam_start(service,user,conv,pamhp);
		if( rcode == -1 && !lNOPAM_DYLIB() )
		rcode = PAM_start(service,user,conv,pamhp);
	}
	return rcode;
}
int xpam_end(void *pamh,int pam_status){
	int rcode;
	if( DG_LIB_pam == 0 ){
		rcode = PAM_end(pamh,pam_status);
	}else{
		rcode = pam_end(pamh,pam_status);
		if( rcode == -1 && !lNOPAM_DYLIB() )
		rcode = PAM_end(pamh,pam_status);
	}
	return rcode;
}
int xpam_authenticate(void *pamh,int flags){
	int rcode;

	if( DG_LIB_pam == 0 ){
		rcode = PAM_authenticate(pamh,flags);
	}else{
		rcode = pam_authenticate(pamh,flags);
		if( rcode == -1 && !lNOPAM_DYLIB() )
		rcode = PAM_authenticate(pamh,flags);
	}
	return rcode;
}

#ifndef PAM_NON_OPTIONAL
#define pam_start	PAM_start
#define pam_end		PAM_end
#define pam_authenticate PAM_authenticate
#else
#define pam_start	xpam_start
#define pam_end		xpam_end
#define pam_authenticate xpam_authenticate
#endif

int pam_auth1(PCStr(service),PCStr(user),PCStr(pass))
{	int status;
	void *pamh;

	/*
	if( pam_start(service,user,&pam_conv,&pamh) != PAM_SUCCESS ){
		syslog_ERROR("PAM: cannot start %s [%s]\n",service,user);
	*/
	pamh = NULL;
	status = pam_start(service,user,&pam_conv,&pamh);
	if( status != PAM_SUCCESS ){
		syslog_ERROR("PAM: cannot start %s [%s] error=%d\n",
			service,user,status);
		return -1;
	}
	gpass = pass;
	status = pam_authenticate(pamh,0);

/*
fprintf(stderr,"**-- pid=%d auth st=%d %s\n",getpid(),status,pam_strerror(pamh,status));
	if( status == PAM_SUCCESS ){
		int st,uid,gid;
		uid = gid = 0xFFFF;
		scan_guid(user,&uid,&gid);
		st = initgroups(user,gid);
fprintf(stderr,"---- IG = %d (user = %s) GID=%d\n",st,user,gid);
perror("INITGROUPS");
		st = pam_acct_mgmt(pamh,0);
fprintf(stderr,"---- ACCT = %d %s\n",st,pam_strerror(pamh,st));
		st = pam_setcred(pamh,PAM_ESTABLISH_CRED);
fprintf(stderr,"---- SETCRED = %d\n",st);
		st = pam_open_session(pamh,0);
fprintf(stderr,"---- SESSION = %d\n",st);
		st = pam_close_session(pamh,0);
fprintf(stderr,"---- SESSION = %d\n",st);
	}
*/

	pam_end(pamh,PAM_SUCCESS);
	syslog_ERROR("## pam_authenticate [%s][%s] = %d\n",service,user,status);

	if( status != PAM_SUCCESS ){
		return 0;
	}
	return 1;
}

int pam_server(int ac,char *av[])
{	int ok;
	PamReq PQ;

	get_pamreq(stdin,&PQ);
	ok = pam_auth1(PQ.p_service,PQ.p_user,PQ.p_pass);
	put_pamresp(stdout,ok);
	return ok;
}

#else /* PAM_BY_MAIN_ONLY */

static const char *ext_pam = "dgpam";
static const char *pam_path;
static int forkPAMserver(int sv[])
{	int ac,pid;
	const char *av[8]; /**/
	CStr(path,1024);
	int qpipe[2],rpipe[2];

	ac = 0;
	av[ac++] = "pam";
	av[ac] = 0;

	if( pam_path == 0 ){
		strcpy(path,ext_pam);
		if( fullpathSUCOM(ext_pam,"r",AVStr(path)) == 0 ){
			syslog_ERROR("## command not found: %s\n",ext_pam);
			return -1;
		}
		syslog_ERROR("## dgpam = %s\n",path);
		pam_path = stralloc(path);
	}

	IGNRETZ pipe(qpipe);
	IGNRETZ pipe(rpipe);
	if( (pid = fork()) == 0 ){
		close(qpipe[1]); dup2(qpipe[0],0); close(qpipe[0]);
		close(rpipe[0]); dup2(rpipe[1],1); close(rpipe[1]);
		Execvp("Pam",pam_path,av);
		exit(-1);
	}
	close(qpipe[0]);
	close(rpipe[1]);

	sv[0] = rpipe[0];
	sv[1] = qpipe[1];
	return pid;
}

static int openPAMserver(DGC*ctx,PCStr(host),int port,int sv[])
{	int sock,pid;
	CStr(local,256);
	CStr(remote,256);

	if( 0 < port ){
		sprintf(remote,"%s:%d",host,port);
		sock = VSocket(ctx,"CNCT/PAM",-1,AVStr(local),AVStr(remote),"proto=httpam,FSV");
		if( 0 <= sock ){
			sv[0] = sv[1] = sock;
			return 0;
		}
		return -1;
	}

	if( 0 < (pid = forkPAMserver(sv)) )
		return pid;

	return -1;
}

static int pam_auth1x(DGC*ctx,PCStr(host),int port,PCStr(service),PCStr(user),PCStr(pass))
{	int rcode,ok;
	int pamsv[2];
	FILE *qfp,*rfp;
	CStr(rstat,128);
	int pid;

	pid = openPAMserver(ctx,host,port,pamsv);
	if( pid < 0 ){
		return -1;
	}

	qfp = fdopen(pamsv[1],"w");
	rfp = fdopen(pamsv[0],"r");
	put_pamreq(qfp,host,port,"auth",service,user,pass);

	ok = get_pamresp(rfp,AVStr(rstat),sizeof(rstat));
	syslog_ERROR("## dgpam -a %s %s = %s",service,user,rstat);

	fclose(qfp);
	fclose(rfp);
	if( 0 < pid )
		wait(0);
	return ok;
}

int pam_service(DGC*ctx,int forbidden,PVStr(req),PVStr(user),int *stcodep)
{	int ok;
	PamReq PQ;

	if( forbidden ){
		ok = -1;
		bzero(&PQ,sizeof(PamReq));
		*stcodep = put_pamresp(stdout,ok);
	}else{
		get_pamreq(stdin,&PQ);
		ok = pam_auth1x(ctx,"-",0,PQ.p_service,PQ.p_user,PQ.p_pass);
		*stcodep = put_pamresp(stdout,ok);
	}
	strcpy(req,PQ.p_request);
	strcpy(user,PQ.p_user);
	return ok;
}

int pamViaSudo(PCStr(service),PCStr(user),PCStr(pass),int *ok);
int pam_checkPasswd(DGC*ctx,PCStr(host),int port,PCStr(service),PCStr(user),PCStr(pass))
{	int ok;
	int euid;

	ok = 0;
	euid = geteuid();

	if( pamViaSudo(service,user,pass,&ok) == 0 ){
		return ok;
	}

	/* ?? under non-superuser privilege,
	 * if password is correct for the user who own the porcess,
	 * PAM seems to return OK regardlessly of the username ??
	 */
	if( port == 0 )
	if( getUserId(user) == euid || euid == 0 ){
		ok = pam_auth1(service,user,pass);
	}
	if( port != 0 || !ok && euid != 0 && INHERENT_fork() ){
		ok = pam_auth1x(ctx,host,port,service,user,pass);
	}
	return ok;
}

#endif /* PAM_BY_MAIN_ONLY */
