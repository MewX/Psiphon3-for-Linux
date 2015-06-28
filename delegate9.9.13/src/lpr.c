/*////////////////////////////////////////////////////////////////////////
Copyright (c) 1998 Electrotechnical Laboratry (ETL), AIST, MITI
Copyright (c) 1998 Yutaka Sato

Permission to use, copy, modify, and distribute this material for any
purpose and without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.
ETL MAKES NO REPRESENTATIONS ABOUT THE ACCURACY OR SUITABILITY OF THIS
MATERIAL FOR ANY PURPOSE.  IT IS PROVIDED "AS IS", WITHOUT ANY EXPRESS
OR IMPLIED WARRANTIES.
/////////////////////////////////////////////////////////////////////////
Content-Type:	program/C; charset=US-ASCII
Program:	lpr.c (RFC1179)
Author:		Yutaka Sato <ysato@etl.go.jp>
Description:
History:
	981028	created
//////////////////////////////////////////////////////////////////////#*/
#include <stdio.h>
#include <stdlib.h>
#include "ystring.h"
#include "time.h"
#include "fpoll.h"
#include "file.h"
#include "dglib.h"

#define JC_PRINT	1
#define JC_RECEIVE	2
#define JC_SENDQSTATS	3
#define JC_SENDQSTATL	4
#define JC_REMOVEJOBS	5

/* JC_RECEIVE sub commands */
#define RJ_ABORT	1
#define RJ_CONTROL	2
#define RJ_DATA		3

/* control */
#define CF_CLASS	'C'
#define CF_HOSTNAME	'H'
#define CF_INDENT	'I'
#define CF_JOBNAME	'J'
#define CF_BANNER	'L'
#define CF_MAILTO	'M'
#define CF_FILENAME	'N'
#define CF_USERID	'P'
#define CF_SYMLINK	'S'
#define CF_TITLE	'T'
#define CF_UNLINK	'U'
#define CF_WIDTH	'W'

#define OK	0

#define DEFAULT_QUEUE	"AUTO"

typedef struct {
	int	l_off;
	int	l_data_off;
	int	l_data_siz;
	int	l_ctrl_off;
	int	l_ctrl_siz;
} LprJob;

static void relay_RECEIVE(LprJob *lpj,FILE *ts,FILE *fs,FILE *tc,FILE *fc)
{	CStr(req,1024);
	CStr(resp,1);
	char op;
	const char *buff;
	int size,rcc;
	FILE *ts_sav,*fs_sav;

	while( fgets(req,sizeof(req),fc) ){
		op = req[0];
		syslog_ERROR("C-S: < RECEIVE %02x %s",op,&req[1]);
		fputs(req,ts);
		fflush(ts);
		lpj->l_off += strlen(req);

		if( fs != NULL ){
			IGNRETP fread(resp,1,1,fs);
			syslog_ERROR("S-C: > RECEIVE %02x (%s)\n",resp[0],
				resp[0]==OK?"OK":"ERROR");
		}else{
			resp[0] = OK;
		}
		if( tc != NULL ){
			fwrite(resp,1,1,tc);
			fflush(tc);
		}

		if( op == RJ_CONTROL || op == RJ_DATA ){
			size = atoi(req+1);
			if( size == 0 ){
				rcc = copyfile1(fc,ts);
				fflush(ts);
				lpj->l_data_off = lpj->l_off;
				lpj->l_data_siz = rcc;
				lpj->l_off += rcc;

				if( fs != NULL )
					IGNRETP fread(resp,1,1,fs);
				else	resp[0] = OK;
				if( tc != NULL )
					fwrite(resp,1,1,tc);
				break;
			}
			rcc = size;
			buff = freadfile(fc,&rcc);
			if( rcc != size )
				break;

			if( op == RJ_CONTROL ){
				lpj->l_ctrl_off = lpj->l_off;
				lpj->l_ctrl_siz = rcc;
			}else{	
				lpj->l_data_off = lpj->l_off;
				lpj->l_data_siz = rcc;
			}
			fwrite(buff,1,size,ts);
			free((char*)buff);
			fflush(ts);
			lpj->l_off += rcc;

			IGNRETP fread(resp,1,1,fc);
			fwrite(resp,1,1,ts);
			fflush(ts);
			lpj->l_off += 1;

			if( fs != NULL )
				IGNRETP fread(resp,1,1,fs);
			else	resp[0] = OK;
			if( tc != NULL ){
				fwrite(resp,1,1,tc);
				fflush(tc);
			}
			syslog_ERROR("S-C: > RECEIVE DATA %02x %s\n",resp[0],
				resp[0]==OK?"OK":"ERROR");
		}
	}
}
static int relay_commands(LprJob *lpj,FILE *ts,FILE *fs,FILE *tc,FILE *fc)
{	CStr(req,1024);
	CStr(resp,0x8000);
	char op;
	char rcc;

	while( fgets(req,sizeof(req),fc) ){
		op = req[0];
		syslog_ERROR("C-S: < %02x %s",op,&req[1]);
		fputs(req,ts);
		fflush(ts);
		lpj->l_off += strlen(req);

		switch( op ){
			case JC_SENDQSTATS:
			case JC_SENDQSTATL:
				if( fs == NULL || tc == NULL )
					return op;
				rcc = copyfile1(fs,tc);
				fflush(tc);
				return 0;
		}

		if( fs != NULL )
			IGNRETP fread(resp,1,1,fs);
		else	resp[0] = 0;
		if( tc != NULL ){
			putc(resp[0],tc);
			fflush(tc);
		}
		syslog_ERROR("S-C: > %02x\n",resp[0]);

		if( resp[0] != OK )
			continue;

		if( op == JC_RECEIVE ){
			relay_RECEIVE(lpj,ts,fs,tc,fc);
			break;
		}
	}
	return 0;
}

int open_lpr(PCStr(host),int port,FILE **tsp,FILE **fsp);
int stat_lpr(PCStr(lphost),int lpport,PCStr(queue),PCStr(opt),PCStr(fname),PVStr(stat));

int service_lpr(DGC*Conn,int _1,int _2,int fromC,int toC,PCStr(svproto),PCStr(svhost),int svport,PCStr(svpath))
{	FILE *ts,*fs,*fc,*tc;
	CStr(req,1024);
	CStr(resp,0x8000);
	char op;
	int nowait;
	FILE *tmp;
	const char *host = svhost;
	int port = svport;
	LprJob lpj_buf, *lpj = &lpj_buf;

	nowait = getenv("LPR_NOWAIT") != NULL;
/*
if( withMount || filter_withCFI(Conn,X_FTOSV) )
	nowait = 1;
*/
	if( nowait )
		fc = fdopen(dup(fromC),"r");
	else	fc = fdopen(fromC,"r");
	tc = fdopen(toC,"w");

	bzero(lpj,sizeof(LprJob));
	op = 0;
	if( nowait ){
		tmp = TMPFILE("LPR");
		op = relay_commands(lpj,tmp,NULL,tc,fc);
		fclose(fc);
		fc = tmp;
		fflush(tmp);
		fseek(tmp,0,0);
		if( op == 0 ){
			syslog_ERROR("disconnect with the client.\n");
			fclose(tc);
			tc = NULL;
			closedups(0); /* maybe necessary for Win32 ? */
		}

		/* MOUNT host,port using CONTROL DATA */
		/* conver the data */
/*
{
int off,siz,rcc;
const char *buff;
sv1log("#### DATA:%d+%d CTRL:%d+%d SIZE=%d\n",
lpj->l_data_off, lpj->l_data_siz,
lpj->l_ctrl_off, lpj->l_ctrl_siz, lpj->l_off);
if( siz = lpj->l_data_siz ){
fseek(tmp,lpj->l_data_off,0);
buff = (char*)malloc(lpj->l_data_siz+1);
rcc = fread (buff,1,lpj->l_data_siz,tmp);
buff[rcc] = 0;
fprintf(stderr,"---\n%s---\n",buff);
free(buff);
fseek(tmp,0,0);
}
}
*/
	}
	if( open_lpr(host,port,&ts,&fs) != 0 ){
		syslog_ERROR("cannot connect to LPR %s:%d\n",host,port);
		resp[0] = (char)-1;
		IGNRETP write(toC,resp,1);
		return -1;
	}
	relay_commands(lpj,ts,fs,tc,fc);

	if( tc != NULL ){
		switch( op ){
			case JC_SENDQSTATS:
			case JC_SENDQSTATL:
			fprintf(tc,"#### NOWAIT MODE LPR-DeleGate/%s ####\r\n",
				DELEGATE_ver());
		}
		fclose(tc);
	}
	fclose(fc);

	set_linger(fileno(ts),30);
	fclose(ts);
	fclose(fs);
	return 0;
}

int open_lpr(PCStr(host),int port,FILE **tsp,FILE **fsp)
{	const char *lpr_host;
	int lpr_port;
	int sock;

	if( host && *host )
		lpr_host = host;
	else
	if( (lpr_host = getenv("PRINTER")) && *lpr_host )
		syslog_DEBUG("PRINTER=%s\n",lpr_host);
	else	lpr_host = "localhost";
	if( 0 < port )
		lpr_port = port;
	else	lpr_port = 515;

/* should try binding source port in range [721-731] */

	sock = client_open("LPR","lpr",lpr_host,lpr_port);
	if( sock < 0 ){
		syslog_ERROR("can't open %s:%d\n",lpr_host,lpr_port);
		return -1;
	}

	*tsp = fdopen(sock,"w");
	*fsp = fdopen(sock,"r");
	return 0;
}

static void getAgentInfo(DGC*Conn,PCStr(user),PVStr(orig_host),PVStr(orig_user))
{
	if( Conn ){
		strfConnX(Conn,"%h",AVStr(orig_host),64);
		strfConnX(Conn,"%u",AVStr(orig_user),64);
		if( streq(orig_user,"-") ){
			if( user && *user )
				strcpy(orig_user,user);
			else	strcpy(orig_user,"unknown");
		}
	}else{
		strcpy(orig_host,"unknown-host");
		strcpy(orig_user,"unknown-user");
	}
}
int send_lpr(DGC*Conn,PCStr(lphost),int lpport,PCStr(queue),FILE *dfp,int dlen,PCStr(user),PCStr(fname),PVStr(stat))
{	FILE *ts,*fs;
	CStr(job,64);
	CStr(resp,1024);
	int rcc;
	int jnum;
	CStr(src_files,64);
	int data_size,ctrl_size;
	CStr(data_name,64);
	CStr(ctrl_name,64);
	CStr(orig_host,64);
	CStr(orig_user,64);
	const char *pdata;
	CStr(ctrl_data,1024);
	refQStr(cfp,ctrl_data); /**/
	const char *fmt;

	if( queue == NULL || *queue == 0 )
		queue = DEFAULT_QUEUE;
	jnum = time(0) % 1000;

	data_size = dlen;
	pdata = freadfile(dfp,&data_size);
	if( fname )
		strcpy(src_files,fname);
	else	strcpy(src_files,"standard input");
	syslog_ERROR("Data Size: %d\n",data_size);

	fmt = "f";
	getAgentInfo(Conn,user,AVStr(orig_host),AVStr(orig_user));
	sprintf(data_name,"dfA%03d%s",jnum,orig_host);
	sprintf(ctrl_name,"cfA%03d%s",jnum,orig_host);

	sprintf(cfp,"%c%s\n",CF_HOSTNAME,orig_host); cfp += strlen(cfp);
	sprintf(cfp,"%c%s\n",CF_USERID,  orig_user); cfp += strlen(cfp);
	sprintf(cfp,"%c%s\n",CF_JOBNAME, src_files); cfp += strlen(cfp);
	sprintf(cfp,"%c%s\n",CF_CLASS,   orig_host); cfp += strlen(cfp);
	sprintf(cfp,"%c%s\n",CF_BANNER,  orig_user); cfp += strlen(cfp);
	sprintf(cfp,"%s%s\n",fmt,        data_name); cfp += strlen(cfp);
	sprintf(cfp,"%c%s\n",CF_UNLINK,  data_name); cfp += strlen(cfp);
	sprintf(cfp,"%c%s\n",CF_FILENAME,src_files); cfp += strlen(cfp);
	ctrl_size = strlen(ctrl_data);
	syslog_DEBUG("Control File:\n%s",ctrl_data);

	if( open_lpr(lphost,lpport,&ts,&fs) != 0 ){
		if( stat ) sprintf(stat,"can't connect to the LPR server\n");
		return -1;
	}

	fprintf(ts,"%c%s\n",JC_RECEIVE,queue);
	fflush(ts);
	rcc = fread(resp,1,1,fs);
	syslog_DEBUG("> %-10s %d code=%d\n","RECEIVE",rcc,resp[0]);

	fprintf(ts,"%c%d %s\n",RJ_DATA,data_size,data_name);
	fflush(ts);
	syslog_DEBUG("> %-10s %d %s\n","RJ_DATA",data_size,data_name);
	rcc = fread(resp,1,1,fs);
	syslog_DEBUG("< %-10s %d code=%d\n","RJ_DATA",rcc,resp[0]);
	fwrite(pdata,1,data_size,ts);
	free((char*)pdata);

	fflush(ts);
	fputc(0,ts);
	fflush(ts);
	rcc = fread(resp,1,1,fs);
	syslog_DEBUG("> %-10s %d code=%d\n","RJ_DATA",rcc,resp[0]);

	fprintf(ts,"%c%d %s\n",RJ_CONTROL,ctrl_size,ctrl_name);
	fflush(ts);
	syslog_DEBUG("< %-10s %d %s\n","RJ_CONTROL",ctrl_size,ctrl_name);
	rcc = fread(resp,1,1,fs);
	syslog_DEBUG("> %-10s %d code=%d\n","RJ_CONTROL",rcc,resp[0]);
	fputs(ctrl_data,ts);
	fflush(ts);
	fputc(0,ts);
	fflush(ts);
	rcc = fread(resp,1,1,fs);
	syslog_DEBUG("< %-10s %d code=%d\n","RJ_CONTROL",rcc,resp[0]);

	set_linger(fileno(ts),30);
	fclose(ts);
	fclose(fs);

	stat_lpr(lphost,lpport,queue,"","",AVStr(stat));
	return data_size;
}

int stat_lpr(PCStr(lphost),int lpport,PCStr(queue),PCStr(opt),PCStr(fname),PVStr(stat))
{	FILE *ts,*fs;
	CStr(resp,1024);

	if( open_lpr(lphost,lpport,&ts,&fs) != 0 ){
		if( stat ) sprintf(stat,"can't connect to the LPR server\n");
		return -1;
	}
	if( queue == NULL || *queue == 0 )
		queue = DEFAULT_QUEUE;

	if( strpbrk(opt,"l") )
		fprintf(ts,"%c%s\n",JC_SENDQSTATL,queue);
	else	fprintf(ts,"%c%s\n",JC_SENDQSTATS,queue);
	fflush(ts);

	if( stat ) setVStrEnd(stat,0);
	syslog_DEBUG("STATUS: \n");
	while( fgets(resp,sizeof(resp),fs) != NULL ){
		syslog_DEBUG("%s",resp);
		if( stat ) strcat(stat,resp);
	}
	fclose(ts);
	fclose(fs);
	return 0;
}
int rmjob_lpr(DGC*Conn,PCStr(lphost),int lpport,PCStr(queue),PCStr(user),PCStr(jobname),PVStr(stat))
{	FILE *ts,*fs;
	CStr(req,1024);
	CStr(resp,1024);
	CStr(orig_host,512);
	CStr(orig_user,512);

	if( open_lpr(lphost,lpport,&ts,&fs) != 0 ){
		return -1;
	}
	if( queue == NULL || *queue == 0 )
		queue = DEFAULT_QUEUE;
	getAgentInfo(Conn,user,AVStr(orig_host),AVStr(orig_user));

/*
sprintf(req,"%c%s %s %s%s\n",JC_REMOVEJOBS,queue,orig_user,jobname,orig_host);
*/
sprintf(req,"%c%s %s %s\n",JC_REMOVEJOBS,queue,orig_user,jobname);

	syslog_ERROR("C-S: < REMOVE %s",req+1);
	fputs(req,ts);
	fflush(ts);
	resp[0] = (char)-1;
	IGNRETP fread(resp,1,1,fs);
	syslog_ERROR("S-C: > REMOVE %02x\n",resp[0]);

	fclose(ts);
	fclose(fs);

	stat_lpr(lphost,lpport,queue,"","",AVStr(stat));
	return resp[0];
}

int lpr_main(int ac,const char *av[])
{
	return send_lpr(NULL,NULL,0,NULL,stdin,0,NULL,NULL,VStrNULL);
}
int lpq_main(int ac,const char *av[])
{	CStr(stat,4096);

	stat_lpr(NULL,0,NULL,"","",AVStr(stat));
	fputs(stat,stdout);
	return 0;
}
int lprm_main(int ac,const char *av[])
{
	return 0;
}
