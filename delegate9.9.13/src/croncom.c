/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1994-2000 Yutaka Sato and ETL,AIST,MITI
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
Program:	croncom.c
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	981120	extracted from delegated.c (5.7.6)
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include "ystring.h"
#include "proc.h"
#include "file.h"
#include "delegate.h"
#include "param.h"

char *getcachedir(PVStr(path),int size);
void DELEGATE_execmain(PCStr(command));
typedef struct CronTab CTab;
int sched_eval(CTab *Cron,long now,iFUNCP callback,void *arg);
int sched_append(CTab *Cron,PCStr(cronspec));
CTab *sched_create();

typedef struct {
	int	ce_crons[256];
	int	ce_ncrons;
	int	ce_cronid;
	CTab	*ce_Cron;
} CronEnv;
static CronEnv *cronEnv;
#define crons	cronEnv[0].ce_crons
#define ncrons	cronEnv[0].ce_ncrons
#define cronid	cronEnv[0].ce_cronid
#define Cron	cronEnv[0].ce_Cron
void minit_cron()
{
	if( cronEnv == 0 )
		cronEnv = NewStruct(CronEnv);
}

int spawnv_self1(int aac,const char *aav[]);
int spawnv_self(int aac,const char *aav[])
{	int pid;

	if( 256 <= ncrons ){
		sv1log("#### too many cron children (%d)\n",ncrons);
		return 0;
	}

	pid = spawnv_self1(aac,aav);

	cronid++;
	crons[ncrons++] = pid;
	sv1log("CRON(%d) START [%s] cid=%d pid=%d\n",ncrons,aav[0],cronid,pid);
	return pid;
}
int spawnv_self1(int aac,const char *aav[])
{	int ai,ac;
	const char *av[128]; /**/
	int pid;

	ac = 0;
	av[ac++] = EXEC_PATH;
	for( ai = 0; ac < 127 && ai < aac; ai++ )
		av[ac++] = aav[ai];
	av[ac] = NULL;
	pid = SpawnvpDirenv("SpawnSelf",EXEC_PATH,av);
	return pid;
}
static int spawn_system(PCStr(command),int inherits)
{	int ac;
	const char *av[32]; /**/

	ac = 0;
	av[ac++] = "-Fsystem";
	av[ac++] = (char*)command;
	av[ac] = NULL;
	return spawnv_self(ac,av);
}
int DELEGATE_cronExit(int pid)
{	int pi,pj;

	for( pi = 0; pi < ncrons; pi++ ){
		if( crons[pi] == pid ){
			for( pj = pi; pj < ncrons-1; pj++ )
				crons[pj] = crons[pj+1];
			crons[pj] = 0;
			sv1log("CRON(%d) FINISH pid=%d\n",ncrons,pid);
			ncrons--;
			return pid;
		}
	}
	return 0;
}
static int internal_actions(PCStr(action),PCStr(act),PCStr(arg))
{	int pid;
	const char *av[32]; /**/
	ACStr(ab,8,128);
	int ac,ai,aj;

	pid = 0;
	if( act[0] == 0 ){
		ac = decomp_args(av,elnumof(av),arg,EVStr(ab[0]));
		pid = spawnv_self(ac,av);
	}else
	if( act[0] == 'F' ){
		Xsprintf(EVStr(ab[0]),"-%s",act);
		av[0] = ab[0];
		ac = 1 + decomp_args(&av[1],elnumof(av)-1,arg,EVStr(ab[1]));
		pid = spawnv_self(ac,av);
	}else
	if( strcmp(act,"exit") == 0 ){
		Finish(atoi(arg));
	}else
	if( strcmp(act,"suspend") == 0 ){
		int sec = atoi(arg);
		sv1log("sleeping %d...\n",sec);
		sleep(sec);
	}else
	if( strcmp(act,"restart") == 0 ){
		RESTART_NOW = 1;
	}else
	if( strcmp(act,"expire") == 0 ){
		CStr(period,32);
		CStr(log,1024);
		CStr(param,1024);
		const char *rem;
		const char *env;
		const char *cpath;
		CStr(cpathb,1024);

		if( (cpath = getcachedir(AVStr(cpathb),sizeof(cpathb))) == NULL )
			return 0;
		if( (env = DELEGATE_getEnv(P_EXPIRELOG)) == 0 )
			env = DELEGATE_EXPIRELOG;
		strcpy(log,env);
		DELEGATE_substfile(AVStr(log),"",VStrNULL,VStrNULL,VStrNULL);
		sprintf(param,"LOGFILE=%s",log);

		rem = arg;
		if( Isnumber(arg) )
			rem = wordScan(arg,period);
		else
		if( env = DELEGATE_getEnv(P_EXPIRE) )
			strcpy(period,env);
		else	strcpy(period,"+7d");

		ac = 0;
		av[ac++] = "-Fexpire";
		av[ac++] = (char*)cpath;
		av[ac++] = "-rm";
		av[ac++] = "-atime";
		av[ac++] = period;
		av[ac++] = "-sum";
		av[ac++] = "-ign";
		av[ac++] = param;
		ai = Xsscanf(rem,"%s %s %s %s %s",EVStr(ab[0]),EVStr(ab[1]),EVStr(ab[2]),EVStr(ab[3]),EVStr(ab[4]));
		for( aj = 0; aj < ai; aj++ ){
			av[ac++] = ab[aj];
		}
		av[ac] = NULL;
		pid = spawnv_self(ac,av);
	}else
	if( strcmp(act,"exec") == 0 ){
		DELEGATE_execmain(arg);
		Finish(-1);
	}else
	if( strcmp(act,"system") == 0 ){
		pid = spawn_system(arg,0);
	}
	return pid;
}

/*
 *  sched_action is called by sched_eval(), and returns the list of
 *  finished actions....
 */
void DELEGATE_sched_action(DGC*Conn,PCStr(action))
{	CStr(act,1024);
	CStr(arg,1024);
	int pid;

	act[0] = arg[0] = 0;
	Xsscanf(action,"%s %[^\r\n]",AVStr(act),AVStr(arg));

	if( act[0] == '-' ){
		internal_actions(action+1,act+1,arg);
	}else
	if( isFullpath(act) ){
		sv1log("SYSTEM-COMMAND: %s\n",action);
		pid = spawn_system(action,0);
	}else
	{
		sv1log("#### UNKNOWN ACTION: %s\n",action);
	}
}

int DELEGATE_sched_execute(int now,iFUNCP callback,void *Conn)
{	int next;

	next = sched_eval(Cron,now,callback,Conn);
	return next;
}
void scan_CRON(DGC*Conn,PCStr(cronspec))
{
	if( Cron == NULL )
		Cron = sched_create();
	sched_append(Cron,cronspec);
}

/*
 * CRONS -- per session scheduler
 */
static CTab *SubCron;
int DELEGATE_session_sched_execute(int now,iFUNCP callback,void *Conn)
{	int next;

	next = sched_eval(SubCron,now,callback,Conn);
	return next;
}
void scan_CRONS(DGC*Conn,PCStr(cronspec))
{
sv1log("#### SESSION SCHED[%s]\n",cronspec);
	if( SubCron == NULL )
		SubCron = sched_create();
	sched_append(SubCron,cronspec);
}
