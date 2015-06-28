#include <stdio.h>
#include "ystring.h"
#include "log.h"
LogControlSet(2);

int setVlog(PCStr(arg)){ return 0; }
int curLogFd(){
	return -1;
}
FILE *curLogFp(){
	return 0;
}
FILE *logMonFp(){
	return 0;
}

int NO_LOGGING;
int FMT_syslog_ERROR(PCStr(fmt), ...)
{	VARGS(16,fmt);

	if( NO_LOGGING ){
		return 0;
	}
	fprintf(stderr,fmt,VA16);
	return 0;
}
int FMT_daemonlog(PCStr(what),PCStr(fmt),...)
{	VARGS(16,fmt);
	fprintf(stderr,fmt,VA16);
	return 0;
}

int FMT_syslog_DEBUG(PCStr(fmt), ...)
{
	return 0;
}
int FMT_iLOGput(PCStr(fmt),...){
	return 0;
}

void Abort(int code,PCStr(fmt),...){
	abort();
}

int iLOGpos(PCStr(F),int L){
	return 0;
}
void putpplog(PCStr(fmt),...){
}
void closepplog(){
}
void putResTrace(PCStr(fmt),...){
}


int findopen_port(PCStr(wh),PVStr(host),int port,int nlisten){
	return -1;
}
#include "dgctx.h"
int CTX_closed(FL_PAR,PCStr(wh),DGC*ctx,int fd1,int fd2){
	return -1;
}
