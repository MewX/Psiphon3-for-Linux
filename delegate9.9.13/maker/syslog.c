int SYSLOG_EMERG   = 0;
int SYSLOG_ALERT   = 1;
int SYSLOG_CRIT    = 2;
int SYSLOG_ERR     = 3;
int SYSLOG_WARNING = 4;
int SYSLOG_NOTICE  = 5;
int SYSLOG_INFO    = 6;
int SYSLOG_DEBUG   = 7;
int SYSLOG_PRIMASK = 0x7;

#include "ystring.h"
int INHERENT_syslog(){ return 0; }
void openlogX(PCStr(ident),PCStr(logopt),int facility){
}
void syslogX(int priority,PCStr(fmt),...){
}
