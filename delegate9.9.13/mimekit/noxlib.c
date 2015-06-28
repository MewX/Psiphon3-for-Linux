#include "ystring.h"

void canon_date(PVStr(date)){}

int Ftruncate(FILE *fp,FileSize offset,int whence)
{	int savoff;
	int rcode;

	savoff = ftell(fp);
	fseek(fp,offset,whence);
	rcode = ftruncate(fileno(fp),(off_t)ftell(fp));
	fseek(fp,savoff,0);
}
int pendingcc(FILE *fp){ return 0; }
int pop_fd(int fd,int rw){ return -1; }
int getthreadid(){ return 0; }
int actthreads(){ return 0; }
int numthreads(){ return 0; }
int mallocSize(void *p){ return 0; }
int porting_dbg(const char *fmt,...){ return 0; }

/* 9.8.2 */
int setupCSC(PCStr(wh),void **cs,int sz){ return -1; }
/*
int enterCSC(void **cs){ return -1; }
int leaveCSC(void **cs){ return -1; }
*/
int setthread_FL(int tid,const char *F,int L,const char *st){ return 0; }
int doDeleteOnClose(int fd,int fh){ return -1; }
int inputReady(int fd,int *rs){ if( rs ) *rs = 1; return 1; }
int SocketOf(int sock){ return sock; }
int fd2handle(int fd){ return 0; }
double Time(){ return time(0); }

/* 9.9.0 */
#include "file.h"
int statXX(const char *p,FileStat *b){
	int rcode;
	rcode = Istat(p,b);
	return rcode;
}
void msleep(int msec){
	usleep(msec*1000);
}

/* 9.9.1 */
typedef struct _M17N *M17N;
int m17n_known_code(PCStr(name)){ return 0; }
M17N m17n_ccx_new(PCStr(icode),PCStr(ocode),void *buf,int siz){ return 0; }
int m17n_ccx_init(M17N m17n,PCStr(icode),const char *ocode){ return 0; }
int m17n_ccx_string(M17N m17n,PCStr(istr),int len,char *ostr,int siz){return 0;}
