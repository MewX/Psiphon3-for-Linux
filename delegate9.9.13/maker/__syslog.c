#include "ystring.h"
#include <syslog.h>

int SYSLOG_EMERG   = LOG_EMERG;
int SYSLOG_ALERT   = LOG_ALERT;
int SYSLOG_CRIT    = LOG_CRIT;
int SYSLOG_ERR     = LOG_ERR;
int SYSLOG_WARNING = LOG_WARNING;
int SYSLOG_NOTICE  = LOG_NOTICE;
int SYSLOG_INFO    = LOG_INFO;
int SYSLOG_DEBUG   = LOG_DEBUG;

#ifdef LOG_PRIMASK
int SYSLOG_PRIMASK = LOG_PRIMASK;
#else
int SYSLOG_PRIMASK = 0x7;
#endif

int INHERENT_syslog(){ return 1; }

void openlogX(PCStr(ident),PCStr(logopt),int facility){
	int opts = 0;
	if( isinListX(logopt,"ndelay","c") ) opts |= LOG_NDELAY;
	if( isinListX(logopt,"pid","c") ) opts |= LOG_PID;
	openlog(ident,opts,facility);
}

void syslogX(int priority,PCStr(fmt),...){
	VARGS(4,fmt);
	syslog(priority,fmt,VA4);
}
