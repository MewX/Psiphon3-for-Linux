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
Program:	editconf.c (DeleGate configuration editor)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	970117	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "file.h"
#include "proc.h"
#include "delegate.h"
#include "param.h"
#define LNSIZE	1024
const char *get_builtin_ADMINPASS();

static int getparam(PVStr(line),PCStr(param),FILE *in,FILE *out)
{	int len;
	const char *dp;

	if( *param == '-' )
		strcpy(line,param);
	else	sprintf(line,"%s=",param);
	len = strlen(line);

	fprintf(out,"%s",line);
	fflush(out);
	Xfgets(DVStr(line,len),LNSIZE-len,in);
	if( dp = strpbrk(line,"\r\n") )
		truncVStr(dp);
	if( line[len] )
		return 1;
	else	return 0;
}

#define GETPARAM(param)	getparam(AVStr(line),param,in,out)

int editconf(int ac,const char ***avp,FILE *in,FILE *out)
{	CStr(line,LNSIZE);
	static const char **nav;
	const char **av;
	CStr(arg1,128);
	int ac0,ai;

	if( nav == 0 )
		nav = (const char**)StructAlloc(128*sizeof(char*));

	ac0 = ac;
	av = *avp;
	for( ai = 0; ai < ac; ai++ )
		nav[ai] = av[ai];
	nav[ai] = NULL;

	fprintf(out,"Administrator's E-mail ## ADMIN=user@domain [%s]\n",
		getADMIN());
	if( GETPARAM("ADMIN") ) nav[ac++] = stralloc(line);

	fprintf(out,"Port of the DeleGate ## -P[hostName:]portNumber\n");
	if( GETPARAM("-P") ) nav[ac++] = stralloc(line);
	else{
#ifndef MAIN
		int sock,port;
		sock = server_open("-",VStrNULL,0,1);
		if( 1 < (port = sockPort(sock)) ){
			fprintf(out,"-P%d\n",port);
			sprintf(arg1,"-P%d/%d",port,sock);
			nav[ac++] = stralloc(arg1);
		}
#endif
	}

	fprintf(out,"Client's Protocol ## SERVER=protocol[://defaultServer/]\n");
	if( GETPARAM("SERVER") ) nav[ac++] = stralloc(line);

/*
	fprintf(out,"Upper DeleGate's port ## MASTER=hostName:portNumber\n");
	if( GETPARAM("MASTER") ) nav[ac++] = stralloc(line);
*/

	nav[ac++] = "-v";
	nav[ac] = NULL;

	fprintf(out,"--\n");
	for( ai = ac0; ai < ac; ai++ )
		fprintf(out,"%s\n",nav[ai]);

	*avp = nav;
	return ac;
}

#define getEnv(name) DELEGATE_getEnv(name)
#define getEnvADMIN()	(getEnv(P_ADMIN)?getEnv(P_ADMIN):getEnv(P_MANAGER))

const char *getADMIN1()
{	const char *env;

	if( env = getEnvADMIN() )
		return env;
	if( DELEGATE_ADMIN_DFLT[0] )
		return DELEGATE_ADMIN_DFLT;
	return NULL;
}
const char *getADMIN()
{	const char *admin;

	if( admin = getADMIN1() )
		return admin;
	else	return DELEGATE_ADMIN;
}

/*
 *	ADMINPASS=password:adminName:owner:host:capability:version
 */
#define APASS	0
#define ANAME	1
#define AOWNER	2
#define AHOST	3
#define ACAPS	4
#define AVERS	5

int checkADMINPASS(DGC*Conn,PCStr(passspec),PCStr(admin),PCStr(pass))
{	CStr(passb,1024);
	const char *passv[8]; /**/
	CStr(md5,64);
	int pi,pc;

	if( *passspec == 0 )
		return 0;
	strcpy(passb,passspec);
	for( pi = 0; pi < 8; pi++ )
		passv[pi] = "";
	pc = list2vect(passb,':',8,passv);

	if( *passv[APASS] ){
		if( pass == 0 || *pass == 0 ){
ERRMSG("ERROR! ADMINPASS=\"password-for-admin\" must be specified.\n");
			return -1;
		}
		toMD5(pass,md5);
		if( strcmp(md5,passv[APASS]) != 0 ){
ERRMSG("ERROR! bad ADMINPASS\n");
			return -1;
		}
	}
	if( *passv[AHOST] ){
		CStr(host,MaxHostNameLen);
		gethostname(host,sizeof(host));
		toMD5(host,md5);
		if( strcmp(md5,passv[AHOST]) != 0 ){
ERRMSG("ERROR! not allowed to run on this host.\n");
			return -1;
		}
	}

	return 0;
}
void checkADMIN(DGC*Conn,PCStr(proto))
{	const char *admin;
	CStr(owner,256);
	int xexplicit;
	const char *pass;

	xexplicit = getEnvADMIN() != 0;
	getUsername(getuid(),AVStr(owner));

	if( admin = getADMIN() )
		DELEGATE_ADMIN = admin;
	sv1log("ADMIN=%s protocol=%s%s\n",DELEGATE_ADMIN,proto,
		BORN_SPECIALIST?"(specialist)":"");

	if( DELEGATE_ADMIN[0] == 0 ){
ERRMSG("ERROR! ADMIN=\"your_mail_address\" must be specified.\n");
		svlog("EXIT: no ADMIN parameter given.\n");
		sleep(3);
		Finish(-1);
	}else
	if( !xexplicit ){
		if( isatty(2) )
		if( strncmp(DELEGATE_ADMIN,owner,strlen(owner)) != 0 ){
ERRMSG("WARNING! ADMIN=\"your_mail_address\" should be specified.\n");
ERRMSG("INFO: using ADMIN=%s given at compile time.\n",DELEGATE_ADMIN);
		}
	}

	if( pass = get_builtin_ADMINPASS() ){
		if( checkADMINPASS(Conn,pass,DELEGATE_ADMIN,
		getEnv(P_ADMINPASS)) != 0 ){
			sleep(3);
			Finish(-1);
		}
	}
}

void editconf1(int *acp,const char **avp[],FILE *in,FILE *out)
{	int ac;
	const char **av;

	ac = *acp;
	av = *avp;

	ac = editconf(ac,&av,in,out);
	if( ac < 2 )
		Finish(0);

	*acp = ac;
	*avp = av;
	main_argc = ac;
	main_argv = av;
}
int service_admin(Connection *Conn)
{	FILE *fc,*tc;
	int ai,nac;
	const char *arg;
	const char *nav[128]; /**/
	const char **navp;

	tc = fdopen(ToC,"w");
	fc = fdopen(FromC,"r");

	if( !service_permitted(Conn,"admin") ){
		fprintf(tc,"you have no permission to admin.\n");
		fflush(tc);
		return -1;
	}

	nac = 0;
	navp = nav;
	navp[nac++] = EXEC_PATH;
	for( ai = 1; ai < main_argc; ai++ ){
		if( elnumof(nav)-1 <= nac ){
			break;
		}
		arg = main_argv[ai];
		if( strncmp(arg,"SERVER=",7) == 0 ) continue;
		if( strncmp(arg,"-P",2) == 0 ) continue;
		if( strncmp(arg,"--",2) == 0 ) break;
		nav[nac++] = (char*)arg;
	}
	navp[nac] = 0;
	editconf1(&nac,&navp,fc,tc);

	fprintf(tc,"execute the server:\n");
	for( ai = 0; ai < nac; ai++ )
		fprintf(tc,"arg[%d] %s\n",ai,navp[ai]);
	closeServPorts();
	fclose(tc);
	fclose(fc);

	Execvp("ADMIN",EXEC_PATH,navp);
	return 0;
}

#ifdef MAIN
main(int ac,char *av[]){
{
	editconf(ac,(const char***)&av);
}
#endif


int askADMIN(FILE *out,FILE *in,PVStr(admin),int size)
{	const char *dp;
	CStr(yn,128);

	if( !isatty(fileno(in)) ){
		return -1;
	}

	for(;;){
		fprintf(out,"ADMIN=");
		fflush(out);
		if( fgets(admin,128,in) == NULL ){
			return -1;
		}
		if( dp = strpbrk(admin,"\r\n") )
			truncVStr(dp);
		for(;;){
			fprintf(out,"ADMIN=%s ... OK ?  [y] / n / x(abort): ",
				admin);
			fflush(out);
			if( fgets(yn,sizeof(yn),in) == NULL ){
				return -1;
			}
			switch( yn[0] ){
				case 'x':
					return -1;
				case 'y': case '\r': case '\n':
					goto GOT;
				case 'n':
					goto RETRY;
			}
		} RETRY:;
	} GOT:;
	return 0;
}

static const char *cached_cachedir;
static void cachedir_name(PVStr(dir),PVStr(sdir))
{
	strcpy(dir,DELEGATE_CACHEDIR);
	strsubstDirEnv(AVStr(dir),DELEGATE_DGROOT,DELEGATE_VARDIR);
	if( !isBoundpath(dir) ){
		strcpy(sdir,dir);
		sprintf(dir,"%s/%s",DELEGATE_VARDIR,sdir);
		strsubstDirEnv(AVStr(dir),DELEGATE_DGROOT,DELEGATE_VARDIR);
	}
	stripPATHexp(dir,AVStr(sdir));
}
const char *cachedirX(Connection *Conn);
const char *cachedir()
{
	return cachedirX(MainConn());
}
const char *cachedirX(Connection *Conn)
{	CStr(dir,1024);
	CStr(sdir,1024);

	if( cached_cachedir )
		return cached_cachedir;

	if( without_cache() )
		return 0;

	cachedir_name(AVStr(dir),AVStr(sdir));

	if( access_RWX(sdir) != 0 )
		return 0;

	Strdup((char**)&cached_cachedir,dir);
	return cached_cachedir;
}
char *getcachedir(PVStr(path),int size)
{	const char *cdir;

	if( (cdir = cachedir()) == NULL )
		return NULL;
	if( 0 <= Readlink(cdir,AVStr(path),size) )
		return (char*)path;
	else	return (char*)cdir;
}

static int isexpire(DGC*Conn,PCStr(cron1),int *isp)
{
	if( strstr(cron1,"expire") ){
		*isp = 1;
		return 1;
	}else	return 0;
}
static int withCRONexpire(DGC*Conn)
{	int is;

	if( getEnv(P_CRON) == NULL )
		return 0;
	is = 0;
	DELEGATE_scanEnv(Conn,P_CRON,(scanPFUNCP)isexpire,&is);
	return is;
}

void YesOrNo(FILE *out,FILE *in,PCStr(msg),PVStr(yn))
{	int xtry;

	setVStrEnd(yn,0);
	for( xtry = 0; xtry < 3; xtry++ ){
		fprintf(stderr,"%s ? [y] / n : ",msg);
		fflush(stderr);
		/*
		fgets(yn,128,stdin);
		*/
		tty_fgets(yn,128,stdin);
		switch( yn[0] ){
			case '\r':
			case '\n':
				strcpy(yn,"y");
			case 'y':
			case 'n':
				goto GOT;
		}
	} GOT:;
}

int checkCACHEDIR(DGC*Conn)
{	CStr(dir,1024);
	CStr(sdir,1024);
	CStr(test,1024);
	CStr(msg,1024);
	refQStr(mp,msg); /**/
	FILE *fp;
	CStr(yn,128);

	if( without_cache() )
		return 0;

	cachedir_name(AVStr(dir),AVStr(sdir));

	if( fileIsdir(sdir) && (access_RWX(sdir) == 0) ){
		sprintf(test,"%s/test-%d-%d",sdir,itime(0),getpid());
		if( fp = fopen(test,"w") ){
			fclose(fp);
			unlink(test);
		}else{
			sprintf(msg,
			"WARNING: Cache directory may not be accessible: %s",
				sdir);
			sv1log("%s\n",msg);
		}
		return 0;
	}

	sprintf(mp,"Cache directory ");
	mp += strlen(mp);
	if( fileIsdir(sdir) )
		sprintf(mp,"seems not RWX accessible: %s",sdir);
	else	sprintf(mp,"seems not exist: %s",sdir);

	if( getEnv(P_CACHE) )
	if( !File_is(sdir) ){
		if( mkdirRX(sdir) == 0 ){
			sv1log("#### CACHEDIR created: %s\n",sdir);
			return 0;
		}
	}

	if( getEnv(P_CACHEDIR) == NULL
	 && getEnv(P_CACHEFILE) == NULL
	 && getEnv(P_EXPIRE) == NULL
	 && !withCRONexpire(Conn)
	){
		svlog("#### CACHE DISABLED #### %s\n",msg);
		return 0;
	}

	if( !File_is(sdir) ){
		if( isatty(fileno(stderr)) && isatty(fileno(stdin)) ){
			fprintf(stderr,"#### %s\n",msg);
			YesOrNo(stderr,stdin,"#### Create Cachedir",AVStr(yn));
			if( yn[0] == 'y' )
			if( mkdirRX(sdir) == 0 ){
				fprintf(stderr,"#### Created: %s\n",sdir);
				sv1log("#### CACHEDIR created: %s\n",sdir);
				return 0;
			}
		}
	}

	svlog("ERROR: %s\n",msg);
	ERRMSG("EXIT: %s\r\n",msg);
	sleep(3);
	return -1;
}
